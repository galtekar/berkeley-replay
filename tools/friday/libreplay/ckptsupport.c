#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ckpt.h>
#include <assert.h>
#include <syscall.h>
#include <pthread.h>
#include <ckpt.h>

#include "libc_pointers.h"
#include "clock.h"
#include "errops.h"
#include "misc.h"
#include "gcc.h"

#include "util.h"

#define DEBUG 1
#include "debug.h"

static void have_everyone_drop_a_checkpoint() {
	int n = 0, i = 0;
	pid_t already_processed_pids[MAX_PROCS];

	thread_info_t* t = _shared_info->head;

	assert(_private_info.is_replay);
	assert(t != NULL); /* Should be at least 1 thread there. */

	ASSERT_SCHED_INVARIANTS();

	/* Skip the master process (i.e., this process). */
	assert(_my_tinfo != NULL);
	already_processed_pids[0] = _my_tinfo->replay_mode_id.pid;
	n = 1;

	/* Walk the thread list and for each unique process found, signal
	 * it to take a checkpoint. */
	while (t != NULL) {
		assert(n <= MAX_PROCS);

		/* BUG: What if the target process has already terminated? */

		/* If this process has already been signalled, skip. */
		for (i = 0; i < n; i++) {
			if (already_processed_pids[i] == t->replay_mode_id.pid) {
				/* Gasp (!). A goto. */
				goto next;
			}
		}

		__LIBC_PTR(kill)(t->log_mode_id.pid, SIGUSR1);

		already_processed_pids[n] = t->replay_mode_id.pid;
		n++;

next:
		t = t->next;
	}

	/* Before writing the checkpoint, mark that this is the process
	 * that initiated the checkpoint. We'll need this during replay
	 * to skip doing a longjmp on this thread, since we know it is
	 * in a safe spot (at the end of handle_switch_event()). */
	_private_info.is_ckpt_master = 1;

	/* Dump a checkpoint. */
	__START_CKPT_TIMER(_drop_checkpoint);
	if (!libreplay_drop_checkpoint(_shared_info->vclock)) {
		__STOP_CKPT_TIMER(_drop_checkpoint);
		_private_info.is_ckpt_master = 0;

		/* Wait until all processes have dropped a checkpoint. We
		 * don't want this proc to modify shared state before
		 * others have had a chance to take a checkpoint, since that
		 * would result in inconsistent state on recovery. */
		my_barrier_wait(&_shared_info->proc_ckpt_barrier,
				_shared_info->num_procs);

	} else {
		__STOP_CKPT_TIMER(_drop_checkpoint);
		/* We are recovering (i.e., in replay mode). */
		assert(_private_info.is_replay == LIBREPLAY_CHECKPOINT);

		DEBUG_MSG(2, "Recovering. is_replay=%d\n", _private_info.is_replay);
	}

	/* RECOVERY PATH. Don't put any liblog specific code here (!!). */

	DEBUG_MSG(2, "Recovery line.\n");
}

void HIDDEN drop_ckpt_if_time() {
	uint64_t now_us = 0;

	assert(_private_info.is_replay);

	/* This should've been set by the overlord wrapper. */
	assert(overlord_should_call_through == 1);

	now_us = get_sys_micros();

	/* Check CHECKPOINT_PERIOD_US time has passed. If so,
	 * then rotate the log. Observe that the checkpoint timestamp
	 * is stored in shared memory. This prevents the situation
	 * where one thread takes a checkpoint, and then another
	 * thread is scheduled in and then makes another checkpoint
	 * before the next interval has arrived. */
	if (((now_us - _shared_info->last_ckpt_us ) >=
				_private_info.ckpt_period_us)) {


		/* Note the checkpoint time so that we know when to take the
		 * next checkpoint. We may not dump a checkpoint if there is
		 * one already taking place. If that's the case, mark the
		 * time anyway, to avoid excessive checkpointing. */
		_shared_info->last_ckpt_us += _private_info.ckpt_period_us;

		if (!_shared_info->is_ckpt_in_progress) {
			/* Ensure that no process initiates a checkpoint operation while one
			 * is taking place. This is possible if the time it takes to write
			 * the checkpoint exceeds CHECKPOINT_PERIOD_US. */
			_shared_info->is_ckpt_in_progress = 1;
			DEBUG_MSG(2, "Initiating a replay checkpoint.\n");
			have_everyone_drop_a_checkpoint();
			_shared_info->is_ckpt_in_progress = 0;
		} else {
			/* We shouldn't be here, since the serialized thread order
			 * makes it impossible for multiple processes to intiate
			 * checkpoints at the same time. This implies that the
			 * is_ckpt_in_progress flag is just for debugging purposes. */
			assert(0);
		}
	}

	/* Taking the checkpoint might've altered errno, since libckpt makes
	 * several libc calls. Restore it to the correct value to be safe,
	 * since applications depend on the correct errno value being present. */
	errno = _my_tinfo->e_val;
}
