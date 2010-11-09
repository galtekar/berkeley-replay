#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <syscall.h>
#include <setjmp.h>
#include <pthread.h>

#include <linux/unistd.h>
#include <asm/ldt.h>

#include <sys/mman.h>
#include <ckpt.h>

#define __USE_GNU
#include <ucontext.h>
#include <sys/ucontext.h>

#include "libc_pointers.h"
#include "errops.h"
#include "logreplay.h"
#include "patterns.h"
#include "tmalloc.h"
#include "hexops.h"
#include "syncops.h"
#include "misc.h"

#include "replay.h"
#include "util.h"
#include "gcc.h"

#include "ckptsupport.h"
#include "rwrap_sigs.h"

#define DEBUG 1
#include "debug.h"


#define __CALL_LIBZ_1(f, ...) \
	is_in_libc++; \
	__libreplay_##f(__VA_ARGS__); \
	is_in_libc--;

#define __CALL_LIBZ_2(r, f, ...) \
	is_in_libc++; \
	r = __libreplay_##f(__VA_ARGS__); \
	is_in_libc--;

#define WAIT_FOR_GDB 1
#define DO_REPLAY_CHECKPOINTING 0

struct tailhead head;

void* page_start_addr = NULL;

/* Staging area for log entries read from the lo.g */
HIDDEN char libreplay_io_buf[LOG_BUF_SIZE];	

/* Open a log for replay. */
void HIDDEN replay_open_log(char* filename, uint64_t vclock, int should_read_header) {

	char *start_tag = "<log>\n";
	char *timestamp_pat = "<start vc=\"%llu\">\n";

	memset(libreplay_io_buf, 0x0, LOG_BUF_SIZE);

	/* Open the file for reading, not writing. Doh! This was the
	 * root of the bug that caused subsequent calls to gzgets to fail. */
	DEBUG_MSG(2, "replay_open_log: opening logfile %s\n", filename);
	hook_for_gdb( LL_HOOK_NEXT_LOG, filename );
	
	_my_tinfo->log_file = __LIBC_PTR(fopen)(filename, "r");
	if (_my_tinfo->log_file == NULL) {
		fatal("replay_open_log: could not open log file \"%s\"\n",
				filename);
	}

	/* Read the header only if this proc is first to perform the
	 * rotation. Otherwise, skip it, since we know cur_pos was reset
	 * and the header has already been read by the first guy. */
	if (should_read_header) {
		/* Check the header - both the first and second line count as
		 * only one entry. */
		if( !log_to_buf(libreplay_io_buf, sizeof(libreplay_io_buf))      // First line
				|| strncmp( libreplay_io_buf, start_tag, strlen(start_tag) )
				|| !log_to_buf(libreplay_io_buf, sizeof(libreplay_io_buf))    // Second line
				|| (sscanf(libreplay_io_buf, timestamp_pat, &_shared_info->log_vclock_id) != 1)
				|| (vclock != _shared_info->log_vclock_id)) {
			fatal("replay_open_log: error reading log header\n");
		}
	}
}

/* Close a log, presumably after replay. */
void HIDDEN replay_close_log() {

	if (_my_tinfo->log_file) {
		__LIBC_PTR(fclose)(_my_tinfo->log_file);
	}
}

/* Move to the next log file during replay. If UPDATE_SHARED is nonzero,
 * then the shared rotation count will be incremented and the shared cur
 * position will be reset. */
static void replay_rotate_log(int64_t vclock, int update_shared) {
	char filename[PATH_MAX];
	char base_name[PATH_MAX];

	/* Close the currently open log file. */
	replay_close_log();

	/* Construct the filename of the next log. */
	construct_log_filename_base(_private_info.log_path, _private_info.log_prefix,
			_private_info.tag_str, _private_info.orig_pgid,
			_private_info.log_epoch, vclock, base_name, sizeof(base_name));
	snprintf(filename, sizeof(filename), "%s.log.xml", base_name);
	strncpy(_private_info.log_name, filename,
		sizeof(_private_info.log_name) );
	
	/* Reset shared variables before calling replay_open_log, since
	 * that function advances the log position, and we don't want to
	 * reset after lines have been read. */
	if (update_shared) {
		/* We need to reset the current position everytime we rotate. */
		_shared_info->cur_pos = 0;

		/* Update the shared vclock so that other processes can use it to
		 * open the same log file that we are opening. Recall that each
		 * process much open the log file, due to problems with zlib
		 * that preclude us from having a shared instance of the log file. */
		_shared_info->log_vclock_id = vclock;

		/* Update the shared rotation number so that other processes,
		 * upon comparing their local rotation number to the shared one,
		 * will see that they need to rotate their logs based on the
		 * shared vclock. */
		_shared_info->num_rotations++;
	}

	/* NOTE: We could have done _my_tinfo.num_rotations++, but that
	 * assumes that a process can be at most 1 rotation behind another
	 * process, and that's not true, since a process may perform multiple
	 * rotations before handing control back to this process. */
	assert(_my_tinfo->num_rotations <= _shared_info->num_rotations);
	/* NOTE: The assert uses ``<='' since both variables can be equal
	 * when we resume from a multi-process intermediate checkpoint. */
	_my_tinfo->num_rotations = _shared_info->num_rotations;

	replay_open_log(filename, vclock, update_shared);
}

static void replay_init_log(int64_t vclock, int should_read_header) {
	char filename[PATH_MAX];
	char base_name[PATH_MAX];

	/* Close the currently open log file. */
	replay_close_log();

	/* Construct the filename of the next log. */
	construct_log_filename_base(_private_info.log_path, _private_info.log_prefix,
			_private_info.tag_str, _private_info.orig_pgid,
			_private_info.log_epoch, vclock, base_name, sizeof(base_name));
	snprintf(filename, sizeof(filename), "%s.log.xml", base_name);
	strncpy(_private_info.log_name, filename,
		sizeof(_private_info.log_name) );
	
	/* NOTE: We could have done _my_tinfo.num_rotations++, but that
	 * assumes that a process can be at most 1 rotation behind another
	 * process, and that's not true, since a process may perform multiple
	 * rotations before handing control back to this process. */
	assert(_my_tinfo->num_rotations <= _shared_info->num_rotations);
	/* NOTE: The assert uses ``<='' since both variables can be equal
	 * when we resume from a multi-process intermediate checkpoint. */

	replay_open_log(filename, vclock, should_read_header);
}


/* Reads the next entry from the specified file into buf for size bytes. */
static void read_next_log_entry(char* buf, int size) {
	long prev_pos;
	long cur_pos;
	char* ret_buf;
	int ret;

	DEBUG_MSG(4, "_shared_info->cur_pos=%d size=%d\n", _shared_info->cur_pos, size);

	/* If our local rotation count equals the global rotation count, then
	 * we are reading from the correct log file. But if it's not, then
	 * we need to rotate to the most recent log file. */
	assert(_my_tinfo->num_rotations <= _shared_info->num_rotations);
	if (_my_tinfo->num_rotations < _shared_info->num_rotations) {
		DEBUG_MSG(4, "rotate catchup: local_num_rots=%d global_num_rots=%d\n",
				_my_tinfo->num_rotations, _shared_info->num_rotations);
		replay_rotate_log(_shared_info->log_vclock_id, 0);
		assert(_my_tinfo->num_rotations == _shared_info->num_rotations);
	}

	/* Move to the current position in the log, which may have
	 * been modified by another process. */
	ret = __LIBC_PTR(fseek)(_my_tinfo->log_file, _shared_info->cur_pos, SEEK_SET);
	if( ret == -1 ) {
		lprintf("Seemingly unnecessary rotation caused by\n");
		replay_rotate_log( _shared_info->log_vclock_id, 0);
		ret = __LIBC_PTR(fseek)(_my_tinfo->log_file, _shared_info->cur_pos, SEEK_SET);
		DEBUG_MSG(4, "After positioning log cur_pos: %ld\n", cur_pos );
		if( ret == -1 ) {
			fatal("problem reading next entry in the log file (entry %d, offset %d)\n",
					_shared_info->entry_num, _shared_info->cur_pos);
		}
	}
	assert(ret != -1);

	cur_pos = __LIBC_PTR(ftell)(_my_tinfo->log_file);
	assert(cur_pos == _shared_info->cur_pos);
	prev_pos = cur_pos;

	ret_buf = __LIBC_PTR(fgets)(buf, size, _my_tinfo->log_file);
	if( NULL == ret_buf) {
		fatal("problem reading next entry in the log file (entry %d, offset %d)\n",
				_shared_info->entry_num, _shared_info->cur_pos);
	}


	/* Make the new position within the log available in shared
	 * memory. This is to let other processes know where they should
	 * be in the log. */
	_shared_info->cur_pos = __LIBC_PTR(ftell)(_my_tinfo->log_file);
	assert(_shared_info->cur_pos > prev_pos);

	DEBUG_MSG(4, "next entry: %s (entry %d, prev_pos %d, cur_pos %d)\n", buf,
				_shared_info->entry_num, prev_pos, _shared_info->cur_pos);

	/* Keep track of how many total log entries we have processed so far. */
	_shared_info->total_events++;

	/* Keep track of how many entries from the current log we have processed
	 * so far. */
	_shared_info->entry_num++;
}

#if 0
/* This is usefull for lookahead purposes. */
static void go_to_previous_log_entry() {
	gzseek(_private_info.log_file, prev_pos, SEEK_SET);
}
#endif

static void handle_log_end_event(char* buf) {
	char *rotate_pat = "<end why=\"rotate\" vc=\"%llu\"/>\n";
	char *closed_pat = "<end why=\"closed\" vc=\"%llu\"/>\n";

	int64_t vclock;

	/* During replay, we want to transparently rotate to the next log. */
	/* Have we reached the end of the log? If so, we need to rotate to
	 * the next log file. */
	if (sscanf( buf, rotate_pat, &vclock /* vclock of next log */) == 1) {
		/* Move to the next log. */
		replay_rotate_log(vclock, 1);

	} else {
		/* The only other possibility is that this is a log close event.
		 * In this case, we must release our locks so that other threads
		 * and processes can get at the CPU. */
		if (sscanf( buf, closed_pat, &vclock) != 1) {
			fatal("abnormal end log event: %s\n", buf);
		}

		RELEASE_SCHED_LOCK();
	}
}

static void handle_signal_event(char* buf) {
	/* Process all the signals. */
	char entry_hex_str[(sizeof(struct signal_entry) * 2) + 1];
	int signum;
	void* pc;
	int64_t vc;
	struct signal_entry * se;

	sscanf(buf, __SIGNAL_PAT, &signum,
			(unsigned int*) &pc,
			entry_hex_str, &vc);

	//printf("SIGNAL %d 0x%x %llu %s\n", signum, pc, vc, entry_hex_str);
	/* Add the signal to the queue, and we will deliver it on
	 * the next ``system call''. */
	/* Enqueue the signal for later delivery. */
	se = (struct signal_entry*)tmalloc(sizeof(struct signal_entry));
	/* Decode the entry back into binary. */
	hex_decode(entry_hex_str, se, sizeof(struct signal_entry));

	TAILQ_INSERT_TAIL(&head, se, entries);

	/* Immediately deliver the queued signal. */
	deliver_queued_signals();
}

static void handle_errno_event(char* buf) {

	/* Store the errno val in a temporary, thread-local location.
	 * This value should be copied into the real errno by the
	 * replay wrapper. And this should be the very last thing
	 * done in order to avoid clobbering. */
	if (sscanf(buf, __ERRNO_PAT, &_my_tinfo->e_val) != 1) {
		fatal("error scanning errno entry\n");
	}
}

static void handle_switch_event(char* buf) {
	char *thread_pat = "<switch pid=%d tid=%lu/>\n";
	thread_id_t log_mode_id;
	thread_info_t* t = _shared_info->head;

	if (sscanf(buf, thread_pat, &log_mode_id.pid, &log_mode_id.tid) != 2) {
		fatal("error scanning switch entry\n");
	}

	/* Find the condition variable associated with the thread. We do
	 * this by walking the thread list and finding the thread with
	 * log mode id specified by the log entry. */
	while (t != NULL) {
		if (t->log_mode_id.pid == log_mode_id.pid &&
			t->log_mode_id.tid == log_mode_id.tid) {

			/* We've found it! */
			break;
		}

		t = t->next;
	}

	assert(t != NULL);

	DEBUG_MSG(4, "handle_switch_event: state=%d, t=(%d,%u), me=(%d,%u)\n", _my_tinfo->state, t->replay_mode_id.pid, t->replay_mode_id.tid, syscall(SYS_getpid),
			__LIBC_PTR(pthread_self)());

	switch (_my_tinfo->state) {
		case EXIT:
			/* There should not be any more log entries for this thread since
			 * it is about to exit (and thus has already made its last wrapper
			 * call). */

			/* The guy that's next in line shouln't be you, since you are
			 * about to exit, and therefore you shouldn't have any more
			 * log entries to process. */
			assert(t->replay_mode_id.pid != syscall(SYS_getpid) ||
				t->replay_mode_id.tid != __LIBC_PTR(pthread_self)());

			/* Allow the other threads to use the CPU, and then let go of the
			 * lock, rather than wait, since you are about to die and won't
			 * need the lock again. */
			DEBUG_MSG(3, "handle_switch_event: exiting.\n"); 
			SCHED_SIGNAL(t);
			RELEASE_SCHED_LOCK();
			hook_for_gdb( LL_HOOK_THREAD_EXIT, NULL );
			break;

		case HANDOFF:
			/* Relinquish control to the corresponding thread only if
			 * that thread is not this thread (i.e., a different thread
			 * on the same process or is in some other process). */
			if (t->replay_mode_id.pid != syscall(SYS_getpid) ||
				t->replay_mode_id.tid != __LIBC_PTR(pthread_self)()) {

				/* Replay checkpoint/recovery support. This setjmp()
				 * is used for the same purpose as the setjmp() in
				 * liblog/cosched.h. */
				if (!setjmp(_my_tinfo->context)) {
					/* If we are here, then this thread is not recovering from
					 * a checkpoint. */

					/* Allow the other thread to use the CPU, and then wait until
					 * some thread signals your turn. */
					DEBUG_MSG(4, "handle_switch_event: handing off.\n"); 
					SCHED_SIGNAL(t);
					SCHED_WAIT();
				} else {
					/* Recovering from checkpoint. This thread should be the
					 * only one running at this point. It should now proceed
					 * to the next system call and process it. */
				}
			} else {
				/* Do nothing. */
			}

			break;
		default:
			assert(0);
			break;
	}
}

/* Reads the next line from _private_info.log_file into _private_info.io_buf[]
 * Updates _private_info.entry_num. Returns TRUE if successful, else FALSE. */
int HIDDEN log_to_buf(char* buf, size_t buf_size) {
	const int MAX_CMD_STR_LEN = 128;
	char cmd_str[MAX_CMD_STR_LEN];
	int count = 0;

#if DO_REPLAY_CHECKPOINTING
	DEBUG_MSG(5, "log_to_buf(): calling drop_ckpt_if_time().\n");
	/* If we are done recovering and have completed initialization,
	 * try and drop a replay checkpoint. */
	if (_private_info.done_with_init && _private_info.is_replay ==
			LIBLOG_CHECKPOINT) {
		drop_ckpt_if_time(); 
	}
#endif


	read_next_log_entry(buf, buf_size);

	/* IMPORTANT: update statistics before making the call to new_log below
	 * in order to count the current line. */

	/* Is it an asynchronous event (e.g., a signal or shared memory
	 * write made by another process)? If so, call the appropriate
	 * handler to process it. */
	while(1) {
		count++;
		if (sscanf(buf, "<%s ", cmd_str) != 1) {
			fatal("can't recognize the command string: %s\n", buf);
		}

		if (strcmp(cmd_str, "end") == 0) {
			handle_log_end_event(buf);

		} else if (strcmp(cmd_str, "signal") == 0) {
			handle_signal_event(buf);

		} else if (strcmp(cmd_str, "switch") == 0) {
			/* Context switch event. */
			handle_switch_event(buf);

			/* If the thread is on it's way out, then don't process
			 * anymore log entries. Return immediately. */
			if (_my_tinfo->state == EXIT) {
				return 1;
			}
		} else if (strcmp(cmd_str, "errno") == 0) {
			handle_errno_event(buf);

		} else if (strcmp(cmd_str, "debug") == 0) {
			/* Ignore the entry. */

		} else {
			return 1; /* It should be a wrapper entry. */
		}

		read_next_log_entry(buf, buf_size);
	}

	assert(0);
}


/* Only the checkpoint master should call this function. */
void restore_processes() {
	int n = 0, i = 0;
	pid_t already_processed_pids[MAX_PROCS];
	thread_info_t* t;

	assert(_shared_info != NULL);
	t = _shared_info->head;
	assert(t != NULL);

	assert(_private_info.is_ckpt_master);

	init_libc_pointers();

	VERIFY_LIBC_POINTERS();

	/* The checkpoint master should have the process since he
	 * dropped the checkpoint. lock. __status = 1 in locked state. */
	ASSERT_SCHED_LOCK_IS_LOCKED();

	/* For each process in the process list, fork a process and
	 * have it call ckpt_restart() on the appropriate checkpoint file
	 * to reinstante itself. */

	/* Skip yourself since you already exist. */
	assert(_my_tinfo != NULL);
	already_processed_pids[0] = _my_tinfo->log_mode_id.pid;
	n = 1;

	while (t != NULL) {
		for (i = 0; i < n; i++) {
			if (already_processed_pids[i] == t->log_mode_id.pid) {
				/* Gasp (!). A goto. What foul language is this? */
				goto next;
			}
		}

		already_processed_pids[n] = t->log_mode_id.pid;
		n++;

		/* Invoke the fork() system call directly rather than going through
		 * the libc call since pthread_create might zero out the TLS
		 * segment if you do the latter. */
		if (!(syscall(SYS_fork))) {
			char ckpt_filename[PATH_MAX];
			char base_name[PATH_MAX];

			/* Child. Slave process. */
			construct_ckpt_filename_base(_private_info.log_path,
					_private_info.log_prefix,
					_private_info.tag_str, t->log_mode_id.pid,
					_private_info.orig_pgid, _private_info.log_epoch,
					_shared_info->vclock, base_name, sizeof(base_name));

			snprintf(ckpt_filename, PATH_MAX,
					"%s.ckpt", base_name);
			DEBUG_MSG(2, "reinstating process ckpt=%s num_procs=%d (%d)\n",
					ckpt_filename, _shared_info->num_procs, t->log_mode_id.pid);

			/* NOTE: Only the checkpoint master (i.e., the parent) has
			 * the shared memory regions, and therefore is the only one
			 * that should restore them. Slaves should not. */
			ckpt_restart(ckpt_filename);

			assert(0);
			break;
		} else {
			/* Parent. Master checkpoint process. */

			/* Wait for the recently created child to bootstrap itself
			 * and wake us again (it does that by invoking SCHED_SIGNAL()
			 * and then SCHED_WAIT() in start_replay()). */
			SCHED_WAIT();
		}

next:
		t = t->next;
	}

	/* At this point, all existing processes are in
	 * start_replay():my_cond_wait() waiting for the goahead. */
}

typedef struct covert_arg {
	thread_info_t *child_tinfo; /* child thread's tinfo */
	thread_info_t *parent_tinfo; /* parent thread's tinfo */
	struct linux_ldt tls;
	char* thread_area_data;
} covert_arg_t;

static void* covert_thread_restore_routine(void* arg) {
	assert(arg);

	covert_arg_t carg = *((covert_arg_t*)arg);

	tfree(arg);

	VERIFY_LIBC_POINTERS();

	/* Once we have the lock, we know that all threads are waiting for a
	 * signal. This is because wait() atomically releases and listens
	 * for the signal. */
	ACQUIRE_SCHED_LOCK();

	/* Note that we can't rely on _my_tinfo being correct since
	 * we haven't restored the thread pointer (i.e., %gs) yet.
	 * That's why we are relying on the main thread to give us a
	 * pointer to our own _my_tinfo. */

	/* Restore the TLS segment descriptor in this thread's LDT.
	 * This must be done so that all TLS data (including those
	 * used by liblog/libreplay/etc.) can be addressed by the same
	 * pointers we used during logging. */
	if (syscall(SYS_set_thread_area, &carg.child_tinfo->tls) < 0) {
		perror("set_thread_area");
		fatal("can't restore TLS info\n");
	}

	/* The %gs segment register is actually an index into the TLS
	 * segment descriptor stored in this thread's LDT. We've already
	 * restored the descriptor, so this code finished the job by
	 * restoring the index. */
	asm("movw %w0,%%gs" :: "q" (carg.child_tinfo->gs));

	/* _my_tinfo should be at the same location as it was during
	 * logging. */
	assert(_my_tinfo == carg.child_tinfo);

	/* Record the replay-mode pid for this thread so that other
	 * threads can find it in the thread list and signal it when
	 * necessary. */
	_my_tinfo->replay_mode_id.pid = syscall(SYS_getpid);
	_my_tinfo->replay_mode_id.tid = __LIBC_PTR(pthread_self)();
	my_cond_init(&_my_tinfo->cond);

	/* Wait until we are given the CPU. If the thread pointer was
	 * successfully restored, our _my_tinfo TLS variable should
	 * be correct. */

	/* Signal the restoring thread (i.e., the thread that created this
	 * child thread). */
	SCHED_SIGNAL(carg.parent_tinfo);

	/* Wait until the log tells us that it's our turn to go. Why
	 * do we need to do this? Because when the checkpoint was taken,
	 * the slave threads were waiting for their turn and we want the
	 * same behavior during replay. */
	SCHED_WAIT();

	/* Jump to where we executed our last thread setjmp. Should be
	 * within some overlord wrapper (see liblog/cosched.h). */
	longjmp(_my_tinfo->context, 1);

	/* We should never reach here. */
	assert(0);

	return NULL;
}

/* Restores each thread in the thread list. We don't make any assumptions
 * about the location of the thread invoking the function within the
 * thread list. */
static void restore_threads() {
	static int thread_count = 0;
	thread_info_t* t;
	covert_arg_t* cargp = NULL;

	assert(_shared_info != NULL);
	t = _shared_info->head;
	assert(t != NULL);

	VERIFY_LIBC_POINTERS();

	ASSERT_SCHED_LOCK_IS_LOCKED();

	/* For each thread in the thread list that belongs to the same
	 * process, spawn a corresponding thread.
	 * Process the entire list, wrap around if needed, and stop when we
	 * get back to the currently executing thread. */
	while (t) {
		pthread_t thread;

		/* We don't need to restore the currently executing thread since
		 * that is already done by libckpt. Also, don't restore threads
		 * in other processes. */
		if (t == _my_tinfo || t->log_mode_id.pid != _my_tinfo->log_mode_id.pid) {
			goto next;
		}

		/* Allocate cargp on the heap to avoid race conditions with
		 * back-to-back calls to pthread_create. */
		cargp = tmalloc(sizeof(covert_arg_t));
		cargp->child_tinfo = t;
		cargp->parent_tinfo = _my_tinfo;

		__LIBC_PTR(pthread_create)(&thread, NULL, &covert_thread_restore_routine,
								 (void*)cargp);
		thread_count++;

		/* Wait until the child thread signals us, after which we
		 * create the next child thread. This gurantees that, once
		 * we are done creating all the threads, all of them are
		 * waiting for a signal in the SCHED_WAIT() in start_replay(). */
		SCHED_WAIT();

next:
		t = t->next;
	}
}

static void init_scheduler() {
	assert(__LIBC_PTR(pthread_self) != NULL);
	_my_tinfo->replay_mode_id.tid = __LIBC_PTR(pthread_self)();
	_my_tinfo->replay_mode_id.pid = syscall(SYS_getpid);
	my_cond_init(&_my_tinfo->cond);

	assert(_my_tinfo->state == HANDOFF);


	/* NOTE: We shouldn't need to do anything else (e.g., add
	 * ourselves into the thread linked list, since we are restarting
	 * from a checkpoint that incldues a call to init_thread_scheduler()). */
}

static void print_banner() {
	printf("****************************************************************\n");
	printf("LIBREPLAY 1.0 last compiled %s %s\n", __DATE__, __TIME__);
	printf("DEBUG_LEVEL  = %d\n", DEBUG_LEVEL);
	printf("LOG_BUF_SIZE = %d\n", LOG_BUF_SIZE);
	printf("****************************************************************\n");
}

void PROTECTED start_replay() {
	debug_level = DEBUG_LEVEL;

	assert(_private_info.done_with_init == 0);

	/* Make a direct syscall so that we don't get a pid that's cached
	 * by libc. That is, we want the --real-- pid. */
	DEBUG_MSG(2, "Starting replay.\n");
	DEBUG_MSG(2, "Process %d reincarnated as process %d.\n",
			_private_info.orig_pid, syscall(SYS_getpid));

	init_libc_pointers();
	VERIFY_LIBC_POINTERS();

	_private_info.ckpt_period_us = 2000000;

	/* Remote processes probably ran with output redirected to a
	 * file, with output buffering enabled.  That setting will
	 * remain in effect once we restore libc, unless we override
	 * it here: */
	DEBUG_MSG(2, "Setting line buffer mode.\n");
	__LIBC_PTR(setlinebuf)( stdout );
	__LIBC_PTR(setlinebuf)( stderr );

	ASSERT_SCHED_LOCK_IS_LOCKED();

	init_scheduler();

	assert(_shared_info != NULL);

	/* total_events keeps count of the number of events executed so far.
	 * This must be reset since we are just now starting the replay. */
	_shared_info->total_events = 0;

	/* entry_num keeps count of the number of events executed in the log
	 * thus far. This must be reset since we are starting from the
	 * beginning of the log. Note that it will be reset on each call
	 * to new_log, which takes places when it's time to rotate. */
	_shared_info->entry_num = 0;

	assert(_private_info.done_with_init == 0);


	sigfillset(&_block_set);
	sigdelset(&_block_set, SIGCONT);

	assert(_private_info.done_with_init == 0);

	DEBUG_MSG(2, "_shared_info->cur_pos=%d\n", _shared_info->cur_pos);

	if (_private_info.is_replay == LIBREPLAY_CHECKPOINT) {
		/* We are recovering from a replay checkpoint. */
	} else {
		assert(_private_info.is_replay == LIBLOG_CHECKPOINT);

		/* Liblog checkpoints always start at the beginning of the log. */
		assert(_shared_info->cur_pos == 0);
	}

	/* Open the log file (and prepare for replaying the events). */
	replay_init_log(_shared_info->log_vclock_id, 
			_private_info.is_replay == LIBLOG_CHECKPOINT &&
			_private_info.is_ckpt_master);

	TAILQ_INIT(&head);

	/* Remove any previously installed signal handlers. */
	libreplay_default_signal_handlers();

	/* Install libreplay-specific signal handlers. */
	libreplay_install_signal_handlers();

	/* Restore the threads that existed at the time the checkpoint
	 * was taken. */
	restore_threads();

	ASSERT_SCHED_LOCK_IS_LOCKED();

	/* This must be reset since the memory regions were written by
	 * way of an overlord wrapper (most probably write()). Since that
	 * overlord wrapper was on the call stack, then
	 * overlord_should_call_through must've been equal to 1. */
	overlord_should_call_through = 0;

	/* Checkpoint was written by write(), so libc flag was set.
	 * That flag prevents the logging wrappers from doing anything
	 * on the recovery path, which is important, but we need to
	 * clear it now, because that write() will never return. */
	is_in_libc = 0;

	/* At the time the checkpoint was taken, is_in_library was 2, since
	 * the checkpoint was written using the write() libc calls, which
	 * we capture. Now that we are restoring, we need to decrement
	 * the counter. */
	is_in_library--;
	assert(is_in_library == 1);

	/* Since we are done with initialization, mark it so. I don't think
	 * we use this invariant during replay, however. So this statement
	 * is not stricly necessary. */
	_private_info.done_with_init = 1;


	if (_private_info.is_ckpt_master) {
		/* CHECKPOINT MASTER -- he's the last one to call this function. */
		DEBUG_MSG(2, "CHECKPOINT MASTER\n");

		/* The checkpoint master should've already processed the
		 * log header. */
		assert(_shared_info->cur_pos > 0);

		/* Reset to allow checkpointing during replay. */
		_shared_info->is_ckpt_in_progress = 0;

		_shared_info->last_ckpt_us = get_sys_micros();

		print_banner();

#if WAIT_FOR_GDB
		/* A good place to trap, since all others have also started up
		 * and are waiting. */
		/* Output something so that RDB knows it's time to attach. */
		lprintf("Waiting for gdb.\n");

		__LIBC_PTR(fflush)(NULL);
		while( ! is_traced( syscall(SYS_getpid) ) ) {
			/* Give GDB a good place to attach to any
				forked processes, read symbol tables, and
				set breakpoints. */ 
			sched_yield();
		}
		DEBUG_MSG(2, "Connected to gdb.\n");
#endif

		/* The checkpoint master (i.e., the guy that initiated
		 * the checkpoint during logging) is in the right place (i.e.,
		 * at the end of some log-mode wrapper function).
		 * Thus, we don't want to do a longjmp, since that would result
		 * in him redoing his current call, which would be bad since it's
		 * already been logged and checkpointed. */

		/* The checkpoint master should now process the log entries
		 * and handoff control to the next process/thread. */
	} else {
		/* CHECKPOINT SLAVE. */
		DEBUG_MSG(2, "CHECKPOINT SLAVE\n");

		/* Let the checkpoint master know that it's okay for him to run. */
		assert(_shared_info->ckpt_master != NULL);
		SCHED_SIGNAL(_shared_info->ckpt_master);
		/* We'll be signaled by some process when it's our turn to go. */
		SCHED_WAIT();

		/* This prevents the slave from executing log-mode-only code,
		 * as might happen if it was in an __ASYNC_CALL at the time the
		 * master process took the checkpoint. Since _my_tinfo.context
		 * is setjmp()ed before second-level wrapper functions are
		 * called, this longjmp will return us to the point where we
		 * are about to call the second-level wrapper function,
		 * effectively ignoring the currently executing wrapper. */
		longjmp(_my_tinfo->context, 1);
	}

	/* Only the checkpoint master should reach here. The others
	 * should be waiting for a signal. */
	assert(_private_info.is_ckpt_master);
}

void deliver_queued_signals() {

	struct signal_entry* np, *p, s;
	static int in_handler = 0;
	struct sigaction* act;

	/* Don't process the queued signals if someone is already handling
	 * them. */
	if (in_handler) return;

	in_handler = 1;

	/* For each signal in the list, log the signal to disk and then call
	 * the corresponding signal handler. */
	np = head.tqh_first;
	while (np != NULL) {
		s = *np;

		/* Move to the next node, --- before removing the current node ----. */
		np = np->entries.tqe_next;

		/* Remove the signal entry before calling the handler. This is
		 * crucial, since the signal handler may invoke one of our
		 * wrapper functions, which in turn will call this function again.
		 * The danger is that on this second call, we will process the
		 * the same signal. We want to avoid this situation. */
		p = head.tqh_first;
		TAILQ_REMOVE(&head, head.tqh_first, entries);
		tfree(p);

		act = &_private_info.orig_handlers[s.sig - 1];

		/* Call the application-specified signal handler, if it exists.
		 * If the app did install a handler, we have to
		 * be careful about which handler to invoke--there are two
		 * options sa_handler or sa_sigaction, and only one of those 
		 * can be used. The sa_flags should tell us which is being used. */
		if ((act->sa_flags & SA_SIGINFO)) {
			if (act->sa_sigaction) {
				DEBUG_MSG(3, "deliver_queued_signals: forwarding %s "
						"to the application sa_sigaction\n", strsignal(s.sig));
				{
					int old1 = is_in_library;
					/* This is true since this function should only be called
					 * from within a replay wrapper function. Specifically,
					 * through calls to LOG_TO_BUF(). */
					assert(overlord_should_call_through == 1);

					/* We don't want any systems calls within the application
					 * specified signal handler to call through. */
					overlord_should_call_through = 0;
					is_in_library = 0;
					act->sa_sigaction(s.sig, &s.si, (void*) &s.uc); 
					overlord_should_call_through = 1;
					is_in_library = old1;
				}
			} else { assert (0); }
		} else {
			if (act->sa_handler == SIG_DFL) {
				switch (s.sig) {
					/* The program should stop on a sig int. */
					case SIGINT:
						/* Make sure that any subsequent system calls are not
						 * logged. */
						_private_info.done_with_execution = 1;

						quit("got SIGINT\n"); 
						
						/* Use the syscall rather than libc's exit() since
						 * the latter will call C++ destructors, which would
						 * be incorrect in this case since SIGINT was not
						 * handled during original execution (and thus the
						 * destructors were not called during original execution). */
						syscall(SYS_exit, -1);
						break;
					case SIGQUIT:
						/* Make sure that any subsequent system calls are not
						 * logged. */
						_private_info.done_with_execution = 1;

						quit("got SIGQUIT\n"); syscall(SYS_exit, -1);

						break;
						/* There are more cases in which the program should
						 * terminate, but we haven't handled them yet... */

					default:
						break;
				}
			} else if (act->sa_handler == SIG_IGN) {
				/* Ignore the signal, although this seems very unwise of
				 * the programmer. */
				DEBUG_MSG(3, "deliver_queued_signals: ignoring %s\n", strsignal(s.sig));
			} else {
				DEBUG_MSG(3, "deliver_queued_signals: forwarding %s "
						"to the application sa_handler\n", strsignal(s.sig));
				assert(act->sa_handler != NULL); 
				{
					int old1 = is_in_library;
					assert(overlord_should_call_through == 1);

					/* We don't want any systems calls within the application
					 * specified signal handler to call through. */
					overlord_should_call_through = 0;
					is_in_library = 0;
					act->sa_handler(s.sig);
					overlord_should_call_through = 1;
					is_in_library = old1;
				}
			}
		}
	}

	in_handler = 0;

	return;
}

static __attribute__((destructor)) void replay_finish() {

	DEBUG_MSG(2, "Calling replay_finish\n");
	DEBUG_MSG(2, "Stopped reading log at: (entry %d, cur_pos %d)\n", 
			_shared_info->entry_num, _shared_info->cur_pos);

	/* Wakeup the next thread in line before we exit. We switch to
	 * EXIT mode so that we don't wait after we wakeup the next thread. */
	_my_tinfo->state = EXIT;
	LOG_TO_BUF();

	/* We shouldn't be waiting since we are on our way out. */

	/* Terminate and reap all child processes. Note that just
	 * because this process is exiting doesn't imply that others
	 * are exiting as well. */
	{
		// int status;
		//kill(0, SIGTERM);
		//(*__LIBC_PTR(wait))(&status);
	}

	/* IMPORTANT: keep in mind that the descructor in liblog
	 * log_finish() will also be executed. */
	DEBUG_MSG(2, "Ending replay_finish\n");
}
