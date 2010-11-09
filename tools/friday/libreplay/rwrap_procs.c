#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <syscall.h>
#include <signal.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "logreplay.h"
#include "replay.h"
#include "misc.h"
#include "patterns.h"
#include "gcc.h"
#include "util.h"
#include "errops.h"
#include "libc_pointers.h"

#define DEBUG 0

pid_t replay_fork(void) {
	pid_t log_mode_pid, replay_mode_pid;
	pthread_t log_mode_tid;
	thread_info_t* parent_tinfo;

	

	if( ! LOG_TO_BUF() ||
			(sscanf( libreplay_io_buf, __FORK_PAT, &log_mode_pid,
					 &log_mode_tid, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore fork\n" );
	}

	/* Keep a pointer into the paren't condition variable so that
	 * the child can singnal it once it has performed intialization. */
	parent_tinfo = _my_tinfo;

	__INTERNAL_CALL_LIBC_2(replay_mode_pid, fork);

	if (replay_mode_pid) {	/* Parent. */
	  	hook_for_gdb( LL_HOOK_FORK, &replay_mode_pid);

		/* Yield the CPU to the newly created process, thereby giving it a
		 * chance to run a little, and then put itself on the signal wait
		 * queue for future notification. */
		SCHED_WAIT();
	} else { /* Child. */

		assert(replay_mode_pid == 0);

		/* Once we have the lock, we know that all threads are waiting for a
		 * signal. This is because wait() atomically releases and listens
		 * for the signal. */
		ACQUIRE_SCHED_LOCK();

		/* Allocate a proc info from the free list and update the free
		 * list. Each process should have a proc info, which is also
		 * a node in a linked list of proc infos stored in shared
		 * memory. */
		assert(_shared_info->free_head != NULL);
		_my_tinfo = _shared_info->free_head;
		_shared_info->free_head = _shared_info->free_head->next;

		/* Initialize the proc info node. */
		memset(_my_tinfo, 0x0, sizeof(thread_info_t));
		_my_tinfo->log_mode_id.pid = log_mode_pid;
		_my_tinfo->log_mode_id.tid = log_mode_tid;
		_my_tinfo->replay_mode_id.pid = syscall(SYS_getpid);
		_my_tinfo->replay_mode_id.tid = (*__LIBC_PTR(pthread_self))();
		_my_tinfo->num_rotations = -1;
		_my_tinfo->log_file = NULL;
		my_cond_init(&_my_tinfo->cond);

		/* Hookup the proc info node to the head of process list. */
		_shared_info->head->prev = _my_tinfo;
		_my_tinfo->next = _shared_info->head;
		_my_tinfo->prev = NULL;
		_shared_info->head = _my_tinfo;

		_shared_info->num_procs++;
		_shared_info->num_threads++;
		_shared_info->num_active_threads++;

		if( DEBUG ) lprintf("Child with pid=%d is born.\n",
				syscall(SYS_getpid));
		_private_info.orig_ppid = _private_info.orig_pid;
		_private_info.orig_pid = 0;
		_private_info.is_ckpt_master = FALSE;

		/* Hand the CPU back to the parent and wait until someone gives
		 * us the CPU. We do this because the parent may have more
		 * log entries in its quantum. */
		SCHED_SIGNAL(parent_tinfo);
		SCHED_WAIT();
	}

	/* Observe how the TRAP is the last instruction before the return.
	 * To keep things consistent, make sure you place TRAPs at the end
	 * of all wrapper functions. */
	TRAP();

	/* The child should always get a retval of 0. */
	return replay_mode_pid ? log_mode_pid : 0;
}

pid_t replay_wait(int *status) {
	pid_t ret;
	int stat_val;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __WAIT_PAT, &ret,
					&stat_val, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore wait\n" );
	}

	if (status) {
		*status = stat_val;
	}

	TRAP();

	return ret;
}

pid_t replay_waitpid(pid_t pid, int* status, int options) {
	pid_t ret;
	int stat_val;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __WAITPID_PAT, &ret,
					&stat_val, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore waitpid\n" );
	}

	if (status) {
		*status = stat_val;
	}

	TRAP();

	return ret;
}

int replay_kill(pid_t pid, int sig) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __KILL_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore kill\n" );
	}

	TRAP();

	return ret;
}

int replay_killpg(int pgrp, int sig) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __KILLPG_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore killpg\n" );
	}

	TRAP();

	return ret;
}

int replay_system(char* string) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SYSTEM_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore system\n" );
	}

	TRAP();

	return ret;
}

void NORETURN replay_abort() {
	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __ABORT_PAT,
					&_shared_info->vclock ) != 1) ) {
		stop_replay( "could not restore abort\n" );
	}

	exit(-1);

	TRAP();
}

char* replay_getenv(const char *name)
{
	static char ret_buf[LOG_BUF_SIZE];
	char * ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __REPLAY_GETENV_PAT,
					ret_buf, &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getenv\n" );
	}
	if( strcmp( ret_buf, "(null)" ) == 0 ) {
		ret = NULL;
	} else {
		ret = ret_buf;
	}
	TRAP();
	return ret;
}

int replay_execl(const char *path, const char *arg, va_list ap) {
	/* TODO: gdb should intercept this call and start the new
	 * executable. */
	assert(0);

	return 0;
}

int replay_execvp(const char *file, char *const argv[]) {
	assert(0);

	return 0;
}
