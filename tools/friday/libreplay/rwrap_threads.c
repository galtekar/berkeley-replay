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
#include "tmalloc.h"

#include "libc_pointers.h"

#define DEBUG 0

typedef struct covert_arg {
	void*  (*orig_start_routine)(void*);
	thread_id_t orig_id;
	thread_info_t* parent_tinfo;
	void* arg;
} covert_arg_t;

static void remove_thread_from_list(thread_info_t* t) {
	assert(t != NULL);

	/* The thread is now dead (logically, but not oficially quite yet). 
	 * Remove it from our list of thread infos. */
	if (t->prev || t->next) {
		if (t->prev) t->prev->next = t->next;
		if (t->next) t->next->prev = t->prev;

		if (_shared_info->head == t) 
			_shared_info->head = t->next;
	} else {
		/* The main application thread should always be in the list,
		 * and thus we should never reach here. */
		assert(0);
	}
}

static void thread_exit_cleanup() {
	ASSERT_SCHED_INVARIANTS();
	_shared_info->num_threads--;
	_shared_info->num_active_threads--;

	/* The thread is now dead (logically, but not oficially quite yet). 
	 * Mark it as dead. It will be removed from our list of thread 
	 * once the app invokes pthread_join. */
	_my_tinfo->state = EXIT;

	/* Unfortunately, it died while holding the lock. Signal
	 * the next thread in the log and then release the lock. */
	_my_tinfo->state = EXIT;
	LOG_TO_BUF();
}

static void* covert_start_routine(void* arg) {
	void* ret;
	covert_arg_t carg = *((covert_arg_t*)arg);

	tfree(arg);

	/* Once we have the lock, we know that all threads are waiting for a
	 * signal. This is because wait() atomically releases and listens
	 * for the signal. */
	ACQUIRE_SCHED_LOCK();

	/* Allocate a thread info from the free list and update the
	 * free list. */
	assert(_shared_info->free_head != NULL);
	_my_tinfo = _shared_info->free_head;
	_shared_info->free_head = _shared_info->free_head->next;

	/* Attach this thread's info onto the global thread linked list. */
	assert(_shared_info->head != NULL); 
	memset(_my_tinfo, 0x0, sizeof(thread_info_t));
	_my_tinfo->log_mode_id.pid = carg.orig_id.pid;
	_my_tinfo->log_mode_id.tid = carg.orig_id.tid;
	_my_tinfo->replay_mode_id.pid = syscall(SYS_getpid);
	_my_tinfo->replay_mode_id.tid = (*__LIBC_PTR(pthread_self))();
	my_cond_init(&_my_tinfo->cond);

	/* Hook the node to the linked list. */
	_shared_info->head->prev = _my_tinfo;
	_my_tinfo->next = _shared_info->head;
	_my_tinfo->prev = NULL;

	/* Add it to the front of our global list of threads. */
	_shared_info->head = _my_tinfo;

	_shared_info->num_threads++;
	_shared_info->num_active_threads++;
	ASSERT_SCHED_INVARIANTS();

	/* Signal the parent thread and then wait your turn. */
	SCHED_SIGNAL(carg.parent_tinfo);	
	SCHED_WAIT();

	ret = carg.orig_start_routine(carg.arg);

	thread_exit_cleanup();

	return ret;
}

int replay_pthread_create(pthread_t  *  thread, pthread_attr_t * attr, void *
		(*start_routine)(void *), void * arg) {

	int ret;
	pthread_t orig_tid;
	pid_t orig_pid;
	covert_arg_t* cargp = NULL;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __PTHREAD_CREATE_PAT,
					&ret, &orig_pid, &orig_tid, &_shared_info->vclock) != 4)) {
		stop_replay( "could not restore pthread_create\n" );
	}

	/* Allocate cargp on the heap to avoid race conditions with
	 * back-to-back calls to pthread_create. */
	cargp = tmalloc(sizeof(covert_arg_t));
	*(void **)(&cargp->orig_start_routine) = start_routine;
	cargp->arg = arg;
	cargp->orig_id.tid = orig_tid;
	cargp->orig_id.pid = orig_pid;
	cargp->parent_tinfo = _my_tinfo;

	/* Spawn a new thread. */
	/* Call the real ptread_create function with our interposed startup
	 * routine. Our routine will handoff control to the user-specified
	 * routine once it has performed some basic initialization (see above). */
	__INTERNAL_CALL_LIBC_2(ret, pthread_create, thread, attr,
			&covert_start_routine, cargp);

	/* Yield the CPU to the newly created thread, thereby giving it a
	 * chance to acquire the lock, run a little, and then put itself
	 * on the signal wait queue for future notification. If we don't
	 * do this, then the newly created thread will be stuck in the
	 * lock acquire in covert_start_routine() until all existing
	 * threads are done. And that's not very fair. */
	SCHED_WAIT();

	TRAP();

	return ret;
}

int replay_pthread_join(pthread_t th, void **thread_return) {
	int ret;
	thread_id_t orig_id;
	thread_info_t* t = _shared_info->head;

	

	/* There should always be at least one thread running. */
	assert(_shared_info->num_threads >= 1);

	/* It's important that we read the log entry before we release the
	 * lock, since this after we do so, we are no longer guaranteed that
	 * this is the only active thread. */
	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __PTHREAD_JOIN_PAT,
					&ret, (long int*)&orig_id.pid, &orig_id.tid, 
					&_shared_info->vclock) != 4)) {
		stop_replay( "could not restore pthread_join\n" );
	}

	/* Find the replay mode id of the thread, since that is the real
	 * thread identifier. pthrad_join will hang if we simply use the
	 * original identifier as found in the log file. */
	while (t != NULL) {
		if (orig_id.pid == t->log_mode_id.pid &&
				orig_id.tid == t->log_mode_id.tid) {

			/* We've found it. */

			break;
		}

		t = t->next;
	}

	/* We should definitely find the thread in the list, even if it
	 * has already terminated (e.g., made a call to pthread_exit()). This
	 * is because the thread is not removed from the list until after
	 * pthread_join is called on it (see code below). */
	assert(t != NULL);

	printf("h1\n");
	__INTERNAL_CALL_LIBC_2(ret, pthread_join, 
			t->replay_mode_id.tid, thread_return);
	printf("h2\n");

	/* Delete the threadinfo for this thread now that pthread_join 
	 * has freed all of its resources. */
	/* ASSUMPTION: the app will not call pthread_join on this thread again. */
	remove_thread_from_list(t);

	return ret;
}

void replay_pthread_exit(void* retval) {
	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __PTHREAD_EXIT_PAT,
					&_shared_info->vclock) != 1)) {
		stop_replay( "could not restore pthread_exit\n" );
	}

	thread_exit_cleanup();

	__INTERNAL_CALL_LIBC_1(pthread_exit, retval);
}
