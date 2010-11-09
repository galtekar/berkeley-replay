#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <syscall.h>
#include <signal.h>
#include <pthread.h>

#define __USE_GNU
#include <dlfcn.h>
#include <ucontext.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <arpa/inet.h>

#include "patterns.h"
#include "fast_logging.h"
#include "libc_pointers.h"
#include "log.h"
#include "sendlog.h"
#include "lwrap_sigs.h"
#include "util.h"
#include "cosched.h"
#include "lwrap.h"
#include "timers.h"
#include "finish.h"

#include "logreplay.h"
#include "tmalloc.h"
#include "misc.h"
#include "errops.h"
#include "hexops.h"
#include "dllops.h"
#include "gcc.h"

#define DEBUG 1
#include "debug.h"

/* Has a field pointing to the head of a linked list of process info as
 * well as other important info shared across processes. */
shared_info_t* _shared_info;

int log_kill(pid_t pid, int sig) {
	int ret;

	__CALL_LIBC(ret, kill, pid, sig);

	advance_vclock();

	if (!LOG( __KILL_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"kill\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_killpg(int pgrp, int sig) {
	int ret;

	__CALL_LIBC(ret, killpg, pgrp, sig);

	advance_vclock();

	if (!LOG( __KILLPG_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"killpg\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}


pid_t log_fork(void) {
	pid_t ret;
	volatile pthread_t* volatile child_thread_tid_p = NULL;

	advance_vclock();

	assert(_shared_info->free_head != NULL);

	child_thread_tid_p = mmap((void*)0x0, sizeof(pthread_t),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert(child_thread_tid_p != MAP_FAILED);
	assert(child_thread_tid_p != NULL);
	*child_thread_tid_p = 0;

	/* Call the libc fork function. Don't use the CALL_LIBC macro
	 * since that will result in two errno log entries being written,
	 * one for the parent and one for the child. */
	ret = __LIBC_PTR(fork)();

	/* WARNING (!!): Don't modify any shared data here.
	 * You are executing concurrently with the child, who IS modifying
	 * shared data. */

	if (ret) { /* Parent. */
		write_errno_log_entry(errno);

		/* WARNING (!!): Don't modify any shared data here.
		 * You are executing concurrently with the child, who IS modifying
		 * shared data. */

		/* Wait till the child reports his thread id. We need to
		 * know this since we need to log it. Unfortunately, there
		 * doesn't seem to be any convenient function I can invoke
		 * that returns the child's thread id. */
		while (*child_thread_tid_p == 0);

		/* NOTE: once we have the child's thread id, we know that
		 * the child has initialized and placed itself on the thread list. */


		/* Log the fork like any other system call event. */
		if (!LOG( __FORK_PAT, ret,
						*child_thread_tid_p, _shared_info->vclock )) {
			fatal("can't communicate with logger process on fork()\n");
		}

		tfree((void*)child_thread_tid_p);

	} else { /* Child. */

		/**************** BEGIN UNPROTECTED CODE ******************/
		/* This code is not protected, but runs concurrently only
		 * with the parent process. When this code segment finishes,
		 * it will raise a signal to the parent by setting the
		 * child_thread_tid_p flag (which also conveys this thread's
		 * thread id). We do this so that this child process can
		 * initialize itself before this wrapper finishes. Without
		 * doing this, the parent process could run, terminate, and
		 * close the connection to the logger--all before this child
		 * process has had a chance to run. When this child process
		 * does try to run, it will get a ``fatal: broken pipe''
		 * error since it cannot connect to the logger. Thus, we try
		 * to avoid such a situation. */

		/* Allocate a proc info from the free list and update the free
		 * list. */
		assert(_shared_info->free_head != NULL);
		_my_tinfo = _shared_info->free_head;
		_shared_info->free_head = _shared_info->free_head->next;

		memset(_my_tinfo, 0x0, sizeof(thread_info_t));
		_my_tinfo->log_mode_id.pid = syscall(SYS_getpid);
		_my_tinfo->log_mode_id.tid = (*__LIBC_PTR(pthread_self))();
		assert(_my_tinfo->log_mode_id.pid != 0);
		assert(_my_tinfo->log_mode_id.tid != 0);

		/* Hookup to the head of the process list. */
		_shared_info->head->prev = _my_tinfo;
		_my_tinfo->next = _shared_info->head;
		_my_tinfo->prev = NULL;
		_shared_info->head = _my_tinfo;

		_shared_info->num_procs++;
		_shared_info->num_threads++;
		_shared_info->num_active_threads++;

		/* Release the lock, and thus, allow the parent to continue. This
		 * must be last thing we do in this unprotected region. */
		assert(_my_tinfo->log_mode_id.tid != 0);
		*child_thread_tid_p = _my_tinfo->log_mode_id.tid;

		/***************** END UNPROTECTED CODE (!) *****************/

		/* WARNING (!!): Don't modify any shared data here. */

		ACQUIRE_SCHED_LOCK();

		/* NOTE: It's okay to modify shared data here. */

		ASSERT_SCHED_INVARIANTS();

		/* Pretend as if the child was just born spontaneously. Don't
		 * log its birth event (i.e., the fork). */
		DEBUG_MSG(3, "Child with pid=%d is born.\n", syscall(SYS_getpid));

		/* By unsetting this variable, we get exclusive access
		 * to the CPU while taking the checkpoint. That is, if
		 * drop_checkpoint() or any of its sub functions makes
		 * a system call, we won't get switched out, since 
		 * INVOKE_COSCHEDULER() will do nothing when this var
		 * is 0. */
		_private_info.done_with_init = 0;

		install_signal_handlers();

		_private_info.orig_pid = syscall(SYS_getpid);
		_private_info.orig_ppid = syscall(SYS_getppid);
		assert(_private_info.orig_pid != 0);
		assert(_private_info.orig_ppid != 0);

		start_logging();

		_private_info.done_with_init = 1;

		/* Observe that the above code is similar to that of log_main()
		 * in main.c. */

		/* RECOVERY PATH! */
	}

	/* CAREFUL (!) : Make sure you DO NOT drop a checkpoint before forking.
	 * If you do, then you will fork a new process during replay, which is
	 * undesirable. */

	/* Don't rotate the logs here! We don't expect fork to be called
	 * frequently, also note that this is on the recovery path (!!!). */

	return ret;
}

pid_t log_wait(int *status) {
	pid_t ret;

	__ASYNC_CALL(ret, wait, status);

	advance_vclock();

	/* Log the join before we awaken another thread so that the log
	 * entry for the join appears immediately after the thread id entry. */
	if (!LOG(__WAIT_PAT, ret,
					status ? *status : 0, _shared_info->vclock)) {
		fatal("can't communicate with logger process on wait\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

pid_t log_waitpid(pid_t pid, int* status, int options) {
	pid_t ret;

	__ASYNC_CALL(ret, waitpid, pid, status, options);

	advance_vclock();

	/* Log the join before we awaken another thread so that the log
	 * entry for the join appears immediately after the thread id entry. */
	if (!LOG(__WAITPID_PAT, ret,
					status ? *status : 0, _shared_info->vclock)) {
		fatal("can't communicate with logger process on waitpid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_system(const char* string) {
	int ret;

	/* We don't want the child process to use liblog. */
	unsetenv("LD_PRELOAD");

	__CALL_LIBC(ret, system, string);

	advance_vclock();

	/* Log the fork like any other system call event. */
	if (!LOG( __SYSTEM_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on system()\n");
	}

	return ret;
}

void NORETURN log_abort() {

	advance_vclock();

	/* Log the fork like any other system call event. */
	if (!LOG( __ABORT_PAT,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on abort()\n");
	}

	exit(-1);
}

char* log_getenv(const char *name)
{
	char * ret;

	assert( __LIBC_PTR(getenv) != NULL );

	__CALL_LIBC(ret, getenv, name );

	advance_vclock();

	/* Log the fork like any other system call event. */
	if (!LOG( __LOG_GETENV_PAT,
					(ret?ret:"(null)"),
					name,  _shared_info->vclock )) {
		fatal("can't communicate with logger process on abort()\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setfsuid(uid_t fsuid) {
	int ret;

	__CALL_LIBC(ret, setfsuid, fsuid);

	advance_vclock();

	if (!LOG( __SETFSUID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setfsuid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setuid(uid_t uid) {
	int ret;

	__CALL_LIBC(ret, setuid, uid);

	advance_vclock();

	if (!LOG( __SETUID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setuid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

pid_t log_setsid(void) {
	pid_t ret;

	__CALL_LIBC(ret, setsid);

	advance_vclock();

	if (!LOG( __SETSID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setsid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setpgid(pid_t pid, pid_t pgid) {
	int ret;

	__CALL_LIBC(ret, setpgid, pid, pgid);

	advance_vclock();

	if (!LOG( __SETPGID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setpgid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setgid(gid_t gid) {
	int ret;

	__CALL_LIBC(ret, setgid, gid);

	advance_vclock();

	if (!LOG( __SETGID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setgid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setfsgid(uid_t fsgid) {
	int ret;

	__CALL_LIBC(ret, setfsgid, fsgid);

	advance_vclock();

	if (!LOG( __SETFSGID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setfsgid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setreuid(uid_t ruid, uid_t euid) {
	int ret;

	__CALL_LIBC(ret, setreuid, ruid, euid);

	advance_vclock();

	if (!LOG( __SETREUID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setreuid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setregid(gid_t rgid, gid_t egid) {
	int ret;

	__CALL_LIBC(ret, setregid, rgid, egid);

	advance_vclock();

	if (!LOG( __SETREGID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setregid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setpgrp(void) {
	int ret;

	__CALL_LIBC(ret, setpgrp);

	advance_vclock();

	if (!LOG( __SETPGRP_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setpgrp\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}


int log_tcsetpgrp(int fd, pid_t pgrp) {
	int ret;

	__CALL_LIBC(ret, tcsetpgrp, fd, pgrp);

	advance_vclock();

	if (!LOG( __TCSETPGRP_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"tcsetpgrp\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

pid_t log_tcgetpgrp(int fd) {
	int ret;

	__CALL_LIBC(ret, tcgetpgrp, fd);

	advance_vclock();

	if (!LOG( __TCGETPGRP_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"tcgetpgrp\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_isatty(int desc) {
	int ret;

	__CALL_LIBC(ret, isatty, desc);

	advance_vclock();

	if (!LOG( __ISATTY_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"isatty\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

gid_t log_getgid(void) {
	gid_t ret;

	__CALL_LIBC(ret, getgid);

	advance_vclock();

	if (!LOG( __GETGID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getgid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

gid_t log_getegid(void) {
	gid_t ret;

	__CALL_LIBC(ret, getegid);

	advance_vclock();

	if (!LOG( __GETEGID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getegid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

uid_t log_getuid(void) {
	uid_t ret;

	__CALL_LIBC(ret, getuid);

	advance_vclock();

	if (!LOG( __GETUID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getuid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

uid_t log_geteuid(void) {
	uid_t ret;

	__CALL_LIBC(ret, geteuid);

	advance_vclock();

	if (!LOG( __GETEUID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"geteuid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_execl(const char *path, const char *arg, va_list ap) {
	int ret;

	/* Pretend like this process is going to die. */
	liblog_finish();
	printf("done with liblog_finish\n");

	/* Assume that exec succeeds. */
	ret = __LIBC_PTR(execl)(path, arg, NULL);

	assert(0);

	return ret;
}

int log_execvp(const char *file, char *const argv[]) {
	int ret;

	/* Pretend like this process is going to die. */
	liblog_finish();
	printf("done with liblog_finish\n");

	/* Assume that exec succeeds. */
	ret = __LIBC_PTR(execvp)(file, argv);

	assert(0);

	return ret;
}

