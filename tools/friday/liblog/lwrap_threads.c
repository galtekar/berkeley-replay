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
#include "cosched.h"
#include "util.h"
#include "lwrap.h"
#include "timers.h"

#include "logreplay.h"
#include "tmalloc.h"
#include "misc.h"
#include "errops.h"
#include "hexops.h"
#include "gcc.h"

#define DEBUG 0

/* The current thread's thread info. */
__thread thread_info_t* _my_tinfo = NULL;
__thread int is_in_libc = 0;

typedef struct covert_arg {
	void*  (*orig_start_routine)(void*);
	void* arg;
} covert_arg_t;

void HIDDEN save_thread_kernel_context() {
	/* Checkpoint TLS segment info. */
	_my_tinfo->tls.entry_number = 6;
	/* the ``6'' is  magic: see linux/include/asm-i386/segment.h */
	if (syscall(SYS_get_thread_area, &_my_tinfo->tls) < 0) {
		fatal("cannot get TLS segment info\n");
	}

	/* Checkpoint the thread register (i.e., %gs). It holds the index
	 * of this thread's TLS segment descriptor in the thread's LDT. */
	asm("movw %%gs,%w0" : "=q" (_my_tinfo->gs));

	/* %gs is a 16-bit register, so make sure the upper 2 bytes are
	 * not garbage. */
	_my_tinfo->gs &= 0xffff;
}

/* Removes the thread from the thread linked list and releases the
 * lock for good. */
static void thread_exit_cleanup() {
	_shared_info->num_threads--;
	_shared_info->num_active_threads--;

	/* The thread is now dead (logically, but not oficially quite yet). 
	 * Remove it from our list of thread infos. */
	if (_my_tinfo->prev || _my_tinfo->next) {
		if (_my_tinfo->prev) { 
			_my_tinfo->prev->next = _my_tinfo->next;
		}
		if (_my_tinfo->next) { 
			_my_tinfo->next->prev = _my_tinfo->prev;
		}

		/* Update the head of the list if necessary. */
		if (_shared_info->head == _my_tinfo) { 
			_shared_info->head = _my_tinfo->next;
		}
	} else {
		/* The main application thread should always be in the list,
		 * and thus we should never reach here. */
		assert(0);
	}

	ASSERT_SCHED_INVARIANTS();

	/* Since this thread is on its way out, release the scheduler lock
	 * so that other threads can run. Without relasing the lock, there
	 * would be deadlock. */
	RELEASE_SCHED_LOCK();
}

/* This is the function that we interpose between pthread_create and
 * the thread startup routine specified by pthread_create. */
static void* covert_start_routine(void* arg) {
	void* ret;
	covert_arg_t carg = *((covert_arg_t*)arg);

	/* Free the memory log_pthread_create allocated for this carg. */
	tfree(arg);

	/* WARNING: This thread may be concurrently executing with another 
	 * thread at this point. Avoid accessing shared data here! */

	/* Once we have the lock, we know that someone is waiting for a
	 * signal. This is because wait() atomically releases and listens
	 * for the signal. */
	ACQUIRE_SCHED_LOCK();
	/* NOTE: the above mutex lock helps us avoid the race condition
	 * where a thread performs a signal before other threads have a 
	 * chance to call wait. The result would be that the signal would
	 * be lost and deadlock will most-likely ensue. */


	/* Allocate a thread info from the free list and update 
	 * the free list. */
	assert(_shared_info->free_head != NULL);
	_my_tinfo = _shared_info->free_head;
	_shared_info->free_head = _shared_info->free_head->next;

	/* Fill in the thread's info, and attach it to the global list
	 * of threads. */
	assert(_shared_info->head != NULL); 
	memset(_my_tinfo, 0x0, sizeof(thread_info_t));
	_my_tinfo->log_mode_id.pid = syscall(SYS_getpid);
	_my_tinfo->log_mode_id.tid = (*__LIBC_PTR(pthread_self))();
	_my_tinfo->next = _shared_info->head;
	_my_tinfo->prev = NULL;

	/* Add it to the front of our global list of threads. */
	_shared_info->head->prev = _my_tinfo;
	_shared_info->head = _my_tinfo;

	/* Perform important scheduler bookkeeping. */
	_shared_info->num_threads++;
	_shared_info->num_active_threads++;

	ASSERT_SCHED_INVARIANTS();

	/* Save this thread's TLS segment info so that we can restore
	 * it upon checkpoint recovery. This needs to be done only once,
	 * since the segment descriptor will not change in the thread's
	 * lifetime. */
	save_thread_kernel_context();

	/* Invoke the programmer-supplied thread start routine. */
	ret = (*carg.orig_start_routine)(carg.arg);

	thread_exit_cleanup();

	return ret;
}

int log_pthread_create(pthread_t  *  thread, const pthread_attr_t * attr, void *
		(*start_routine)(void *), void * arg) {
	int ret;

	covert_arg_t* cargp = NULL;
	static int count = 0;

	/* Allocate a carg on the heap so that each invocation of pthread_create
	 * gets one. This avoids the race where back to back pthread_creates
	 * overwrite the previous carg vefore it is read. */
	cargp = tmalloc(sizeof(covert_arg_t));
	cargp->arg = arg;
	*(void **)(&cargp->orig_start_routine) = start_routine;

	/* Call the real ptread_create function with our interposed startup
	 * routine. Our routine will handoff control to the user-specified
	 * routine once it has performed some basic initialization (see above). */
	__CALL_LIBC(ret, pthread_create, thread, attr, 
			&covert_start_routine, cargp);

	advance_vclock();

	if (!LOG(__PTHREAD_CREATE_PAT, ret,
					_my_tinfo->log_mode_id.pid, *thread, 
					_shared_info->vclock)) {
		fatal("can't communicate with logger process on pthread_create\n");
	}

	count++;

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_pthread_join(pthread_t th, void **thread_return) {
	int ret;

	__ASYNC_CALL(ret, pthread_join, th, thread_return);

	advance_vclock();

	/* Log the join before we awaken another thread so that the log
	 * entry for the join appears immediately after the thread id entry. */
	if (!LOG(__PTHREAD_JOIN_PAT, ret,
					syscall(SYS_getpid), th, _shared_info->vclock)) {
		fatal("can't communicate with logger process on pthread_join\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

void log_pthread_exit(void *retval) {

	advance_vclock();

	/* Log the join before we awaken another thread so that the log
	 * entry for the join appears immediately after the thread id entry. */
	if (!LOG(__PTHREAD_EXIT_PAT, _shared_info->vclock)) {
		fatal("can't communicate with logger process on pthread_exit\n");
	}

	thread_exit_cleanup();

	//lprintf("[%lu]: EXITING\n", pthread_self());

	/* Clearly, the call to pthread_exit must be the very last thing. */
	__CALL_LIBC_1(pthread_exit, retval);

	assert(0);
}

/* Locking operations. These are independent of shared memory
 * implementation and thus work with both BSD and SysV shared memory. */
int log_pthread_mutex_lock(pthread_mutex_t* mutex) {
	int ret;

	/* EXPLANATION: Why does using __ASYNC_CALL on pthread_mutex_lock 
	 * not deadlock? The reason is that by the time __ASYNC_CALL 
	 * makes the call to pthread_mutex_lock, it has already released the 
	 * scheduler locks. This means that other processes are free to grab 
	 * it and run. This implies that the lock we are trying to acquire 
	 * will eventually be unlocked by one of the other threads. So there 
	 * is no deadlock. */
	__ASYNC_CALL(ret, pthread_mutex_lock, mutex);

#define LOG_MUTEX 0

#if LOG_MUTEX
	/* Log the locking operation and outcome, since it is a nondeterministic
	 * event in the event of lock competition. */
	advance_vclock();

	if (!LOG(__PTHREAD_MUTEX_LOCK_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on pthread_mutex_lock\n");
	} 

#endif

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_pthread_mutex_unlock(pthread_mutex_t* mutex) {
	int ret;

	/* Release the lock. */

	__CALL_LIBC(ret, pthread_mutex_unlock, mutex);

#if LOG_MUTEX
	/* Log the unlocking operation and outcome, since it is a nondeterministic
	 * event in the event of lock competition. */
	advance_vclock();

	if (!LOG(__PTHREAD_MUTEX_UNLOCK_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on pthread_mutex_unlock\n");
	} 
#endif

	POST_WRAPPER_CLEANUP();

	return ret;
}
