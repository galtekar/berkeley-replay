#ifndef COSCHED_H
#define COSCHED_H

#include <pthread.h>
#include <sched.h>

#include "util.h"
#include "patterns.h"
#include "log.h"

/* Interface to the log-mode cooperative scheduler (cosched). */


#if USE_FAST_LOGGING

/* This the fast version. It simply writes pids and tid into shared memory
 * and lets the logger do the logging at some later time. */
#define LOG_CONTEXT_SWITCH() { \
	/* Writes out a log entry for a process or thread context switch. */ \
	if (_private_info.done_with_init) { \
		/* If we switch to a different thread, then log the thread
		 * we are switching to. */ \
		if (_shared_info->prev_id.pid != _my_tinfo->log_mode_id.pid || \
			_shared_info->prev_id.tid != _my_tinfo->log_mode_id.tid) { \
			\
			advance_vclock(); \
			GET_SHM_CHUNK(ctx_switch); \
			e->id = _my_tinfo->log_mode_id; \
		} \
		\
		_shared_info->prev_id = _my_tinfo->log_mode_id; \
	} \
}

#else

#define LOG_CONTEXT_SWITCH() { \
	/* Writes out a log entry for a process or thread context switch. */ \
	if (_private_info.done_with_init) { \
		/* If we switch to a different process or thread, then log the thread
		 * we are switching to. */ \
		if (_shared_info->prev_id.pid != _my_tinfo->log_mode_id.pid || \
			_shared_info->prev_id.tid != _my_tinfo->log_mode_id.tid) { \
			if (!LOG("<switch pid=%d tid=%lu/>\n", _my_tinfo->log_mode_id.pid, _my_tinfo->log_mode_id.tid)) { \
				fatal("can't communicate with logger process after thread handoff\n"); \
			} \
			\
		} else { \
			/*MSG_TO_LOGGER("<debug tid=%lu/>\n", _my_tinfo->log_mode_id.tid);*/ \
		} \
		_shared_info->prev_id = _my_tinfo->log_mode_id; \
	} \
}

#endif


/* This function is invoked by each wrapper in overlord.c. This must
 * be macro since we must ensure that the setjmp is called in the 
 * same stack frame as that of the wrapper. This allows us to resume
 * execution outside of the log-mode wrapper function. */
#define INVOKE_COSCHEDULER() { \
	\
	/* Invoke the coscheduler only if we are in logging mode. Don't
	 * invoke it if liblog is not done with its initialization
	 * (see main.c). The latter clause is necessary since before
	 * initialization, the scheduler locks haven't been initialized
	 * yet. Finally don't invoke it if we are already within a libc
	 * function (for example, pthread_create calls mmap() but we don't
	 * want to perform a handoff on that call to mmap(). Thus, we
	 * perform handoff only at the top-level libc call. We do this
	 * mainly because it makes it easier to reason about the code. */ \
	/*if (!_private_info.is_replay && _private_info.done_with_init &&  \
			!is_in_libc ) { */ \
	if (!_private_info.is_replay && _private_info.done_with_init) { \
		/* No need to perform any handoff when there is at most 1 thread
		 * in the ready queue, since the others are blocking and can't
		 * make use of the CPU anyway. */ \
		if (setjmp(_my_tinfo->context)) { \
			/* REPLAY MODE: The context is being restored (i.e., longjmp()
			 * has been invoked). */ \
			\
			/* We don't need to restore the thread pointer here, since we
			 * assume that it has already been restored by the thread
			 * restore covert function. */ \
			\
			/* In fact, put all recovery code in libreplay, since 
			 * modifying liblog might invalidate existing checkpoints. */ \
			\
		} else { \
			/* LOG MODE: The context is being saved. */ \
			\
			/* Always release the sched lock so that others
			 * may have a chance to run. You can't rely on
			 * num_active_threads to tell you if there are
			 * others waiting because a thread increments that
			 * variable only after a thread acquires the 
			 * sched lock. So it is simpler just to always
			 * release and then reqacuire the lock. */ \
			if (_shared_info->num_active_threads > 1 || 1) { \
				\
				/* Let another thread have a turn. */ \
				RELEASE_SCHED_LOCK(); \
				\
				/* Sched_yield doesn't guarantee that the next-in-line 
				 * proc will be switched in next. So it's not really 
				 * necessary. In fact, it may hurt performance if it 
				 * picks a thread that doesn't choose one of our
				 * application's threads. Also, it's an expensive call
				 * to make on the critical path. */ \
/*sched_yield();*/ \
				\
				/* Acquire the lock only in log mode. In replay mode,
				 * we also use signal/wait in addition to locking. */ \
				ACQUIRE_SCHED_LOCK(); \
				\
			}  \
			\
			/* Context switches should be logged as long there is more than
			 * one thread in the system. This is because we must clearly
			 * distinguish log entries from different threads, even if 
			 * only one is currently active. Note that the
			 * LOG_CONTEXT_SWITCH macro will ouput a context switch entry
			 * only if the previously scheduled process differs from this
			 * one. */ \
			LOG_CONTEXT_SWITCH(); \
		} \
		/* NOTE: Don't place any code after this position. We don't
		 * want it to get executed during replay, after we do the
		 * longjmp(). */ \
	} \
}

#endif
