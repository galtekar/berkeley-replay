#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ckpt.h>
#include <assert.h>
#include <syscall.h>
#include <pthread.h>

#include "libc_pointers.h"
#include "patterns.h"
#include "log.h"
#include "sendlog.h"
#include "logger.h"
#include "fast_logging.h"

#include "clock.h"
#include "errops.h"
#include "misc.h"
#include "gcc.h"

#define DEBUG 1
#include "debug.h"

#define LOGGER_ROTATE() { \
	__START_CKPT_TIMER(_logger_rotate); \
	_shared_info->is_ckpt_in_progress = 1; \
	logger_rotate(); \
	_shared_info->is_ckpt_in_progress = 0; \
	__STOP_CKPT_TIMER(_logger_rotate); \
}

extern in_addr_t __liblog_get_addr(void); /* hosts.c */

/**************************************************
 * Log Handling Functions
 **************************************************/

HIDDEN __thread int __ll_last_errno = 0;

/* Logging details for application process. */
private_info_t _private_info;

/* A constructor for struct logged_process_info. */
static void init_process_info(char *log_prefix,
		uint64_t log_epoch, uint64_t vclock, int is_replay, pid_t pid,
		pid_t pgid, char* path, char* tag, char* ckpt_period_us) {

	assert(_shared_info != NULL);

	_shared_info->vclock = vclock;
	_shared_info->log_vclock_id = vclock;
	_shared_info->last_clock = 0;
	_private_info.log_epoch = log_epoch;

	strncpy( _private_info.log_prefix, log_prefix, PATH_MAX );
	memset( _private_info.log_name, 0, PATH_MAX );

	_private_info.is_replay = is_replay;
	_private_info.is_ckpt_master = 0;

	_private_info.ckpt_period_us = ckpt_period_us ?
		strtoll(ckpt_period_us, NULL, 10) : CHECKPOINT_PERIOD_US;

	/* Initialize process state. */
	_private_info.orig_pid = pid; /* Original process id. */

	_private_info.orig_pgid = pgid;


	/* Intialize the path and tag values, which should be given to us
	 * from the environment, although we don't assume that. */

	/* If no path is specified, then the current working directory of
	 * of the app will be the path. */
	strncpy(_private_info.log_path, path ? path :
		(*__LIBC_PTR(getcwd))(path, sizeof(_private_info.log_path)), PATH_MAX);

	/* Append the process id to the specified tag, so that each process's
	 * tag will be unique. */
	{
		struct in_addr ia;

		ia.s_addr = __liblog_get_addr();
		#if 0
		snprintf(_private_info.tag_str, sizeof(_private_info.tag_str), "%s#%d",
				tag ? tag : inet_ntoa(ia), pgid);
		#else
		snprintf(_private_info.tag_str, sizeof(_private_info.tag_str), "%s",
				tag ? tag : inet_ntoa(ia));
		#endif
	}

	memset(&_private_info.orig_handlers, 0x0, 
		sizeof(_private_info.orig_handlers));

	DEBUG_MSG(2, "LOGGER_DIR=%s\n", _private_info.log_path);
	DEBUG_MSG(2, "LOGGER_TAG=%s\n", _private_info.tag_str);
	DEBUG_MSG(2, "LOGGER_ROTATE_PERIOD_US=%ld\n", _private_info.ckpt_period_us);
}


/* Tell the logger to create a new log. If this is not the first time
 * it received a new log message, it interprets the new log message
 * as a log rotation message. */
static int new_log( uint64_t vclock )
{
	assert(!_private_info.is_replay);

	/* entry_numn keeps count of the current entry in the log and
	 * therefore, it must be reset everytime we rotate logs. */
	_shared_info->entry_num = 0;

	/* Save the vlock id of the current log file. This helps us identify
	 * what log file we are on during replay. */
	_shared_info->log_vclock_id = vclock;

	send_new_log_msg(vclock);

#if USE_FAST_LOGGING
	/* Detach from the current segment, if we already have one. */
	if (_private_info.shmpos != NULL) {
		if ((*__LIBC_PTR(shmdt))((void*)_private_info.shmpos) != 0) {
			perror("shmdt");
			fatal("can't detach from the old shared memory segment\n");
		}
	}

	DEBUG_MSG(3, "detached segment at shmpos=0x%x\n", _private_info.shmpos);

	/* Attach to the shared memory segment (to which we will write out
	 * log entries). */
	assert(_shared_info->shmid != -1);
	if ((_private_info.shmpos = (int*)(*__LIBC_PTR(shmat))(_shared_info->shmid,
					(void *) 0, 0)) == (void*)-1) {
		perror("shmat");
		fatal("can't attach to segment shmid=%d\n", _shared_info->shmid);
	}

	DEBUG_MSG(3, "attaching new segment %d to 0x%x\n", _shared_info->shmid,
			_private_info.shmpos);

	/* The first word of the shared memory segment contains the
	 * the number of used bytes in that segment (i.e., the 
	 * next unused position to which we may write), denoted by
	 * _private_info.shmpos. */
	assert(_private_info.shmpos != NULL);
	*_private_info.shmpos = 0; /* 0, since nothing has been written yet. */

	/* Everything after the first word is log entries. */
	_private_info.shmdata = (char*)_private_info.shmpos + sizeof(int);
	assert(_private_info.shmdata != NULL);

	/* Tell libckpt to ignore this shared memory segment, since we
	 * use it to keep log entries that needn't be checkpointed
	 * (because they go in the log). That is, we want libckpt
	 * to checkpoint only those shared memory segments allocated by
	 * the __application__, and not those allocated by liblog. */
	ckpt_mask_region((void*)_private_info.shmpos,
			_shared_info->shmsize);

	assert(*_private_info.shmpos == 0);
#endif


	return 1;
}

/* Drops a checkpoint of current application state. The checkpoint
 * file will have VCLOCK as a unique identifier to distinguish it
 * from the set of checkpoints taken earlier by the same application. */
int HIDDEN liblog_drop_checkpoint( uint64_t vclock ) {
	char ckpt_filename[PATH_MAX];
	char base_name[PATH_MAX];
	int is_recovering;

	/* Put the name of the checkpoint file together. */
	construct_ckpt_filename_base(_private_info.log_path,
			_private_info.log_prefix,
			_private_info.tag_str, _private_info.orig_pid,
			_private_info.orig_pgid, _private_info.log_epoch,
			vclock, base_name, sizeof(base_name));

	if (_private_info.is_ckpt_master) {
		snprintf(ckpt_filename, PATH_MAX, "%s.ckpt.master", base_name);
	} else {
		snprintf(ckpt_filename, PATH_MAX, "%s.ckpt", base_name);
	}

	/* Switch to replay mode before taking the checkpoint, and then
	 * switch back if we are still in log mode. Then, upon checkpoint
	 * recovery, the replay flag would already be set. This allows
	 * us to tell if we are in replay mode or not even if post_replay_handler()
	 * hasn't been called yet. */
	_private_info.is_replay = LIBLOG_CHECKPOINT;

	/* Only one process (the checkpoint master) needs to save 
	 * shared memory segments. */
	is_recovering = ckpt_ckpt(ckpt_filename,
			_private_info.is_ckpt_master ? 0 : IGNORE_SHAREDMEM);

	DEBUG_MSG(2, "Recovery line. is_replay=%d\n",
			is_recovering);

	/* If we aren't recovering, we must still be in log mode. */
	_private_info.is_replay = is_recovering ? _private_info.is_replay : 0;

	/* RECOVERY PATH. DON'T PUT ANY LIBLOG SPECIFIC CODE HERE (!!). */

	/* RECOVERY LINE. When recovering from the checkpoint, execution will
	 * resume here. Actually, execution will resume somewhere in ckpt_ckpt(),
	 * but as far we care, we can say that it resumes here. */

	return is_recovering;
}

/* Closes the current log and opens a new one. When logging, writes a
 * new checkpoint. We can't make this static since it is called by logger.c
 * when taking the initial checkpoint. */
static int logger_rotate( )
{
	int ret, n = 0, i = 0;
	pid_t already_processed_pids[MAX_PROCS];

	thread_info_t* t = _shared_info->head;

	assert(!_private_info.is_replay);
	assert(t != NULL); /* Should be at least 1 thread there. */

	/* Now close the current log and open the next. We must
	 * do this before we drop the checkpoint, since if new_log
	 * is executed on recovery, then it will spit out errors. */
	ret = new_log( _shared_info->vclock );

	ASSERT_SCHED_INVARIANTS();

	/* Skip the master process (i.e., this process). */
	assert(_my_tinfo != NULL);
	already_processed_pids[0] = _my_tinfo->log_mode_id.pid;
	n = 1;

	/* Walk the thread list and for each unique process found, signal
	 * it to take a checkpoint. */
	while (t != NULL) {
		assert(n <= MAX_PROCS);

		/* If this process has already been signalled, skip. */
		for (i = 0; i < n; i++) {
			if (already_processed_pids[i] == t->log_mode_id.pid) {
				/* Gasp (!). A goto. */
				goto next;
			}
		}

		__LIBC_PTR(kill)(t->log_mode_id.pid, SIGUSR1);

		already_processed_pids[n] = t->log_mode_id.pid;
		n++;

next:
		t = t->next;
	}

	/* Before writing the checkpoint, mark that this is the process
	 * that initiated the checkpoint. We'll need this during replay
	 * to skip doing a longjmp on this thread, since we know it is
	 * in a safe spot (at the end of some wrapper function, via
	 * rotate_log_if_time()). */
	_private_info.is_ckpt_master = 1;

	/* Write a new checkpoint. We must do this AFTER signalling
	 * the other processes. Otherwise, we will get stuck in the
	 * barrier in the checkpoint signal handler. */
	__START_CKPT_TIMER(_drop_checkpoint);
	if (!liblog_drop_checkpoint(_shared_info->vclock)) {
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
		assert(_private_info.is_replay == LIBLOG_CHECKPOINT);

		DEBUG_MSG(2, "Recovering. is_replay=%d\n", _private_info.is_replay);
	}

	/* RECOVERY PATH. Don't put any liblog specific code here (!!). */

	DEBUG_MSG(2, "Recovery line.\n");

	return ret;
}

/* Rotate the logs, if and only if it is time to do so. The amount
 * of time we wait is *approximately controlled* by CHECKPOINT_PERIOD_US.
 * The reason is that we only check time on system calls. This approximation
 * should be good enough however, if we assume that system calls occur
 * frequently and are uniformly distributed. */
void HIDDEN rotate_log_if_time() {
	uint64_t now_us = 0;

	assert(!_private_info.is_replay);

	/* BUG: This variable should really be called
	 * _private_info.is_within_liblog. */
	assert( _private_info.done_with_init == 1 );

	/* Turn off context switching. */
	_private_info.done_with_init = 0;

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
			LOGGER_ROTATE();
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

	_private_info.done_with_init = 1;

	/* RECOVERY PATH. Don't put any liblog specific code here (!!). */
}

int HIDDEN buf_to_shmem(const char* format, ...) {
	va_list args;
	logentry_header_t* hdrp;
	char* strp;
	int strlen, max_entry_len;

	/* This function should be called only during logging. */
	assert(!_private_info.is_replay);

	if (_private_info.done_with_execution) {
		/* If liblog has terminated already, then some library is
		 * probably making a system call. Don't log it. */
		return 1;
	}

	max_entry_len = sizeof(logentry_header_t) + LOG_BUF_SIZE;

	if (*_private_info.shmpos + max_entry_len >= 
			(_shared_info->shmsize - sizeof(long))) {
		/* We've run out of space in the shared memory segment.
		 * Thus, we need to ask the logger to flush the contents
		 * of the segment to disk. */

		/* Detach from the old shared segment. */
		if ((*__LIBC_PTR(shmdt))((void*)_private_info.shmpos) != 0) {
			fatal("can't detach from the old shared memory segment\n");
		}

		send_log_flush_msg(_shared_info->vclock);

		/* Reattach to the new shared segment as specified in the ack 
		 * for the log flush message. */
		if ((_private_info.shmpos = 
					(int*)(*__LIBC_PTR(shmat))(_shared_info->shmid,
												 (void *) 0, 0)) == (void*)-1) {
			fatal("can't attach to new shared segment handed out by log server\n");
		}

		_private_info.shmdata = (char*)_private_info.shmpos + sizeof(int);
		*_private_info.shmpos = 0;
	}

	assert(_private_info.shmpos != NULL);
	assert(_private_info.shmdata != NULL);
	hdrp = (logentry_header_t*)&_private_info.shmdata[*_private_info.shmpos];
	strp = (char*)&_private_info.shmdata[*(_private_info.shmpos) + 
		sizeof(logentry_header_t)];

	va_start(args, format);
	strlen = vsnprintf(strp, LOG_BUF_SIZE, format, args);
	va_end(args);

	/* Some of our wrappers may return more than LOG_BUF_SIZE data,
	 * believe it or not. */
	if (strlen >= LOG_BUF_SIZE) {
		/* Log string was truncated. */
		fatal("Log string was truncated. LOG_BUF_SIZE too small?\n");
	}

	assert(strlen >= 0);
	assert(strlen < LOG_BUF_SIZE); /* The output shouldn't be truncated. */

	hdrp->id = __ll_string_id; /* 0 is the ID for string entries. */
	hdrp->size = strlen + 1;
	hdrp->vclock = _shared_info->vclock;

	/* Advance the shared memory position. */
	*_private_info.shmpos += sizeof(logentry_header_t) + hdrp->size;

	_shared_info->total_events++;
	_shared_info->entry_num++;

	return 1;
}

/* Advances _private_info.vclock by the number of microseconds elapsed
 * on the local clock since the last call.  Also updates
 * _private_info.local_clock. */
void HIDDEN advance_vclock() {
	uint64_t last_clock = _shared_info->last_clock;
	assert(_shared_info != NULL);

	_shared_info->last_clock = get_cpu_micros();

	if( last_clock == 0 ) {	// uninitialized; use system time.
		_shared_info->vclock = _private_info.log_epoch;
	} else {	// Advance with CPU clock rate
		/* The plus 1 is to make sure that vclock is strictly increasing.
		 * This property is assumed by the log server, which flushes
		 * shared memory log entries in order based on their vclock
		 * timestamps. */
		_shared_info->vclock += (_shared_info->last_clock - last_clock) + 1;
	}

	return;
}


/* Initialize private and shared date, and connect to the log
 * server. */
void HIDDEN start_logging() {
	char prefix_str[256];
	const int IS_REPLAY = 0;
	uint64_t epoch;
	struct in_addr ia;
	char buf[1024];
	extern void save_thread_kernel_context();

	assert(!_private_info.is_replay);

	/* Get the name of the invoked binary. This is the prefix string
	 * for all checkpoints and logs we dump from now on. */
	get_prefix_str(prefix_str);

	assert ((*__LIBC_PTR(getcwd))(buf, sizeof(buf)) != NULL);
	if( 0 != strcmp((*__LIBC_PTR(getenv))("PWD"), buf) ) {
		// The wrapper script changed the directory. Move back.
		assert( 0 == (*__LIBC_PTR(chdir))(getenv("PWD")) );
	}

	epoch = get_sys_micros();

	/* Save the thread LDT entry at startup rather than on every wrapper
	 * call (as we used to do). This works because the thread LDT entry 
	 * will not change during execution. */
	save_thread_kernel_context();

	/* Connect to the logger, start a new log and take a checkpoint, if
	 * this is the main process. Otherwise, if this is a child process,
	 * then simply take a new checkpoint. */
	if (_private_info.orig_ppid == syscall(SYS_getpid)) {
		/* Child process (i.e., application) -------------------------. */
		init_process_info(prefix_str, epoch,
				0 /* no vclock */, IS_REPLAY /* == 0, since we are
														  in logging mode now */, syscall(SYS_getpid) /* libc
																														 getpid() seems to be caching the paren't pid! That's
																														 why we aren't using it. */, syscall(SYS_getpgrp),

				/* BUG: What if the process group changes? */
				(*__LIBC_PTR(getenv))("LOGGER_DIR"), (*__LIBC_PTR(getenv))("LOGGER_TAG"),
				(*__LIBC_PTR(getenv))("LOGGER_ROTATE_PERIOD_US"));

		_private_info.logger_port = (*__LIBC_PTR(getenv))("LOGGER_PORT") ?
			atoi((*__LIBC_PTR(getenv))("LOGGER_PORT")) : DEFAULT_LOGGER_PORT;

		/* Assume logger is running on the same host for now. */
		_private_info.logger_addr = ntohl(__liblog_get_addr());

		ia.s_addr = htonl(_private_info.logger_addr);

		DEBUG_MSG(2, "Logging to server at %s:%d.\n", inet_ntoa(ia),
				_private_info.logger_port);

		/* In addition to connecting to the logger, this function also
		 * retrieves important info from the logger (e.g., id of the
		 * shared memory segment. */
		_private_info.socket_fd = connect_to_logger(_private_info.logger_addr,
				_private_info.logger_port);

		advance_vclock();	/* Sets vclock first time. */

		/* Mark the current time, since we are about to perform
		 * a checkpoint. */
		_shared_info->last_ckpt_us = get_sys_micros();

		/* First ``rotate'' writes initial checkpoint and signals logger. */
		LOGGER_ROTATE();

		/* RECOVERY PATH (!!). */

	} else {
		/* This is a child process. No initialization needs to be done
		 * here. */
	}

	/* RECOVERY PATH (!!). */
	assert(is_in_library == 1);
}

/* Writes an errno log entry. */
void HIDDEN write_errno_log_entry(int val) {

	/* We must save the current value of errno so it can be restored
	 * later. We do this because errno may be trampled by some of
	 * the work we do in the log wrappers. */
	_my_tinfo->e_val = val;

	/* Log the errno value only if it is different than the previous
	 * value. */
	if (val != __ll_last_errno) {
		__ll_last_errno = val;

		advance_vclock();

#if USE_FAST_LOGGING
		/* Careful: errno might be a macro and might expand to something
		 * wierd. _errno shouldn't be one and is therefore safe to use. */
		GET_SHM_CHUNK(_errno);
		e->eval = val;
#else
		if (!LOG(__ERRNO_PAT, val)) {
			fatal("can't communicate with logger process on "
					"errno\n");
		}
#endif
	}
}
