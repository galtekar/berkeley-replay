#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <syscall.h>

#include "logreplay.h"
#include "errops.h"

#include "libc_pointers.h"
#include "gcc.h"
#include "misc.h"

#define DEBUG 0

/* This variable is a hook for gdb to tell whether the application is
 * in the lock-released code segment in my_cond_wait.
 * We need this hook when we attach to child processes at startup.
 */
static int holding_locks = TRUE;

void HIDDEN my_barrier_init(my_barrier_t *b) {

	assert(b != NULL);

	memset(b, 0x0, sizeof(my_barrier_t));

	pthread_mutex_init(&b->mutex, NULL);
	my_cond_init(&b->cond);
}

void HIDDEN my_barrier_wait(my_barrier_t *b, int num_threads) {
	/* A num_threads barrier. If b resides in inter-process
	 * shared memory, then threads from different processes
	 * can use it to synchronize. */

	assert(b != NULL);

	(*__LIBC_PTR(pthread_mutex_lock))(&b->mutex);
	if (++b->count == num_threads) {
		b->count = 0;
		my_cond_broadcast(&b->cond);
	}
	else {
		my_cond_wait(&b->cond, &b->mutex);
	}

	(*__LIBC_PTR(pthread_mutex_unlock))(&b->mutex);
}

void HIDDEN my_cond_init(my_cond_t* pcv) {

	assert(pcv != NULL);

	memset(pcv, 0x0, sizeof(my_cond_t));
	pthread_mutex_init(&pcv->lock, NULL);
}

void HIDDEN my_cond_wait(my_cond_t* pcv, pthread_mutex_t* mut) {
	int val, seq;
	unsigned int* futex;

	assert(pcv != NULL);
	assert(mut != NULL);

	if( DEBUG ) lprintf( "entering my_cond_wait(%p,%p)\n", &pcv->lock, mut );
	/* If the unlock and the suspend is atomic, and if other
	 * processes acquire this lock (MUT) before sending a signal, then
	 * we are guaranteed that we will receive that signal. */
	VERIFY_LIBC_POINTERS();

	(*__LIBC_PTR(pthread_mutex_lock))(&pcv->lock);

	(*__LIBC_PTR(pthread_mutex_unlock))(mut);

	/* We have one more waiter on this condition variable. */
	pcv->total_seq++;
	val = seq = pcv->wakeup_seq;

	futex = &pcv->wakeup_seq;

	do {
		(*__LIBC_PTR(pthread_mutex_unlock))(&pcv->lock);

		holding_locks = FALSE;
		// Give replay console a chance to switch to a new gdb
		// process before this one blocks.
		hook_for_gdb( LL_HOOK_WAIT, NULL );

		/* Wait until the value has changed (or there may be no waiting
		 * if the value has already changed, which is possible). */
		holding_locks = TRUE;
		syscall(SYS_futex, futex, FUTEX_WAIT, val, NULL);

		(*__LIBC_PTR(pthread_mutex_lock))(&pcv->lock);

		/* Are we eligible for wakeup? */
		val = pcv->wakeup_seq;
	} while(val == seq || pcv->woken_seq == val);

	/* One more process woken up. */
	pcv->woken_seq++;

	(*__LIBC_PTR(pthread_mutex_unlock))(&pcv->lock);

	(*__LIBC_PTR(pthread_mutex_lock))(mut);
	if( DEBUG ) lprintf( "leaving my_cond_wait(%p,%p)\n", &pcv->lock, mut );
}

/* Wrapper for my_cond_signal()
   Exists only as a convenient place for GDB to read the
   replay_mode_id of the signalled thread. */
void HIDDEN my_cond_signal_wrapper(my_cond_t* pcv, thread_id_t replay_mode_id ) {
  if( DEBUG ) lprintf( "cond_signalling: %d %lu\n", replay_mode_id.pid, replay_mode_id.tid);
  
  if( replay_mode_id.pid != _my_tinfo->replay_mode_id.pid ) {
    // Going to switch processes, not just threads.
    hook_for_gdb( LL_HOOK_SIGNAL, &(replay_mode_id.pid) );
  }
  // Now call through:
  my_cond_signal(pcv);
  return; 	// Leave this comment for gdb.
}

void HIDDEN my_cond_signal(my_cond_t* pcv) {
	unsigned int* futex;

	assert(pcv != NULL);

	/* By acquiring the lock associated with the condition variable,
	 * we are guaranteed the condition variable is waiting for a signal,
	 * assuming we are sending the signal after acquiring MUT. */
	if( DEBUG ) lprintf( "entering my_cond_signal(%p)\n", &pcv->lock );
	(*__LIBC_PTR(pthread_mutex_lock))(&pcv->lock);

	/* Is there anyone waiting on this condition variable? */
	if (pcv->total_seq > pcv->wakeup_seq) {
		futex = &pcv->wakeup_seq;
		pcv->wakeup_seq++;
		syscall(SYS_futex, futex, FUTEX_WAKE, 1, NULL);
	}

	(*__LIBC_PTR(pthread_mutex_unlock))(&pcv->lock);
	if( DEBUG ) lprintf( "leaving my_cond_signal(%p)\n", &pcv->lock );
}

void HIDDEN my_cond_broadcast(my_cond_t* pcv) {
	unsigned int* futex;

	assert(pcv != NULL);

	(*__LIBC_PTR(pthread_mutex_lock))(&pcv->lock);

	if (pcv->total_seq > pcv->wakeup_seq) {
		pcv->wakeup_seq = pcv->total_seq;

		(*__LIBC_PTR(pthread_mutex_unlock))(&pcv->lock);

		futex = &pcv->wakeup_seq;

		/* Wake-up all the threads in the system waiting on this
		 * condition variable. */
		syscall(SYS_futex, futex, FUTEX_WAKE, INT_MAX, NULL);

		return;
	}

	(*__LIBC_PTR(pthread_mutex_unlock))(&pcv->lock);
}
