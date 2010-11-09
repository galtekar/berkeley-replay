#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include "libc_pointers.h"
#include "errops.h"

#include "sendlog.h"
#include "lwrap_sigs.h"
#include "start.h"

#define DEBUG 1

#include "debug.h"

/* We expect this function to be called during logging and replay. */
static void proc_exit_cleanup() {
	/* The assert should come before we decrement the number
	 * of threads/procs. This is because the invariants don't
	 * hold after the last processes exits. */
	ASSERT_SCHED_INVARIANTS();

	_shared_info->num_threads--;
	_shared_info->num_active_threads--;
	_shared_info->num_procs--;

	/* The process is now dead (logically, but not oficially quite yet).
	 * Remove it from out list of proc infos and add it to the free list. */
	if (_my_tinfo->prev || _my_tinfo->next) {
		if (_my_tinfo->prev) _my_tinfo->prev->next = _my_tinfo->next;
		if (_my_tinfo->next) _my_tinfo->next->prev = _my_tinfo->prev;

		/* Update the head of the list if necessary. */
		if (_shared_info->head == _my_tinfo)
			_shared_info->head = _my_tinfo->next;

		/* Add this element to the free list. */
		_my_tinfo->next = _shared_info->free_head;
		_shared_info->free_head = _my_tinfo;

	} else {
		/* The last thread is exiting. */
	}

	if (_shared_info->num_threads == 0) {
		/* Output an empty file in the current directory to signal
		 * that the last thread has exited. Our automatic test script
		 * (test/run_tests) uses this to as a signal to run diff on 
		 * logged and replay mode outputs. */
		char filename[256];
		int fd;

		/* We write the file to the /tmp/ since the app might've
		 * invoked chdir() and changed the working directory. We need
		 * a predictable place to put the done-with file. */
		snprintf(filename, sizeof(filename), "/tmp/done.with.%s.%d",
			_private_info.is_replay ? "replay" : "log",
			_private_info.orig_pgid);
		fd = (*__LIBC_PTR(creat))(filename, 0600);
		(*__LIBC_PTR(close))(fd);
	}

	if (_private_info.is_replay) {
		/* Do nothing since we are in replay mode. replay_finish()
		 * in libreplay/replay.c should take care of correct handoff. */
	} else {

		/* Log all signals before terminating the connection to
		 * the logger. */
		LOG_AND_DELIVER_QUEUED_SIGNALS();

		/* If this is the last process to die, then close the
		 * connection to the logger, and perform other cleanup
		 * operations. */
		if (_shared_info->num_procs == 0) {
			DEBUG_MSG(2, "Sending log close message.\n");

			/* Tell the logger to close the log. */
			send_log_close_msg("closed", _shared_info->vclock);

			/* Close the connection to the log server. */
			(*__LIBC_PTR(close))(_private_info.socket_fd);

			_private_info.socket_fd = -1;

			/* Print out timings from microbenchmark measurements. */
			if ((*__LIBC_PTR(getenv))("LIBLOG_MICROBENCHMARKS")) {
				print_timing_stats();
			}
		}

		/* Make sure to relinquish our hold on the CPU since we are about
		 * to die. Deadlock is a bad thing. */
		RELEASE_SCHED_LOCK();
	}
}

/*
 * This function will be automatically called upon program termination,
 * for both logging and replay. We expect this to be called before
 * all other destructors. */
__attribute__((destructor)) void liblog_finish() {

	DEBUG_MSG(2, "Exiting\n");
	DEBUG_MSG(2, "Calling log_finish\n");

	/* Set this variable so that any subsequently called destructors
	 * will use tfree rather than free. This is required since
	 * their corresponding constructors were called before liblog's
	 * constructor and therefore they used tmalloc. Thus we must free
	 * that memory with tfree rather than free. */
	is_in_library++;
	assert(is_in_library > 0);

	/* We use this flag in LOG_AND_DELIVER_QUEUED_SIGNALS to avoid
	 * calling exit() if we are already on our way out. This ensures
	 * that the connection to the logger is closed and the
	 * microbenchmarks are printed out. */
	_private_info.about_to_exit = 1;

	/* The confusing parent shouldn't call proc_exit_cleanup() since it
	 * hasn't setup any state yet. */
	if (!__ll_is_confusing_parent) {
		/* Let other threads know that we are about to die and relinquish our
		 * hold on the CPU. */
		proc_exit_cleanup();
	} else {
		DEBUG_MSG(2, "skipping cleanup\n");
	}

	DEBUG_MSG(2, "Ending log_finish\n");

	/* Set this flag to true to prevent any subsequently invoked library
	 * calls from being logged. For example, C++ apps will typically
	 * invoke fflush() after the destructors have finished--we assume that
	 * these are deterministic and thus don't want them to be logged. Also
	 * make sure setting this flag is that last thing we do, and in particular,
	 * it comes afer the call to proc_exit_cleanup(), since that function
	 * invokes LOG_AND_DELIVER_QUEUED_SIGNALS, which in turn may need to
	 * send log entries to the logger. */
	_private_info.done_with_execution = 1;
}
