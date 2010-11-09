/**
 * Copyright (c) 2004 Regents of the University of California.  All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. Neither the name of the University nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * author:	Dennis Geels
 * $Id: logreplay.h,v 1.89 2006/08/23 03:46:25 geels Exp $
 *
 * event_log.h: Main header file for my event logging/replay system.
 */
#ifndef LOGREPLAY_H
#define LOGREPLAY_H

#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <errno.h>
#include <setjmp.h>

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <arpa/inet.h>

#include <signal.h>
#include <byteswap.h>

#include <linux/unistd.h>

#include "syncops.h"
#include "timings.h"
#include "clock.h"

extern pid_t gettid(void);

/**************************************************
 **************************************************/

#define LIBLOG_CHECKPOINT 0xdeadbeef
#define LIBREPLAY_CHECKPOINT 0xfeedbeef

#if 1
#define MAX_THREADS 256
#else
#define MAX_THREADS 4
#endif

#define MAX_PROCS 1024

/* Maximum length of single log entry. We need this to be well
 * beyond the size of a page times 2, since shared memory updates
 * transport a page's worth of data times 2 (since it's in hex) +
 * other log entry fields. 
 *
 * The read() system call can return a large amount of data,
 * if requested. For example, running liblog on a recursive
 * ``grep'' can cause read() to return at least 512KB of data
 * on some calls. Thus, some log entries may be this big. 
 *
 * Only log2xml and libreplay should need to use this constant.
 * Liblog shouldn't need to since all log entries are written
 * directly to shared memory segment and are not buffered,
 * for maximum efficiency. */
#define LOG_BUF_SIZE (0x1 << 21)

/* Checkpoint every 10 minutes. */
#define CHECKPOINT_PERIOD_US (600*1000000ULL)

/* Default directory to dump logs and checkpoints. */
#define DEFAULT_PATH_STRING "./"

/* Differentiate checkpoints created during replay */
#define REPLAY_CKPT_FILENAME_FORMAT "%s.%d.%llu.%llu.ckpt.rep"

/* The maximum size of the tag string we append to outgoing messages. */
#define MSG_TAG_LEN 56

/* Maximum number of mmaped segments we allow to be mapped. */
#define MAX_SHM_ENTRIES 256		/* System V shared memory */

/**************************************************
 * Useful Macros
 **************************************************/

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define ntohll(x)	(x)
#define htonll(x)	(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define ntohll(x)	bswap_64(x)
#define htonll(x)	bswap_64(x)
#endif

#define FLAT_STR(T, name) \
	char name##_flat_str[(sizeof(T)*2) + 1]

#if ENABLE_CLEAR_STACK
#define CLEAR_STACK_FOOTPRINT() { \
	clear_stack_footprint(); \
}
#else
#define CLEAR_STACK_FOOTPRINT()
#endif

#define __LIBC_PTR(f) __ll_libc_##f

/**************************************************
 * Feature flags.
 **************************************************/
#define WRAP_FILES 1
#define ENABLE_CLEAR_STACK 0

/* Return if the call is libc reentrant or if it is being made before
 * initialization is complete. This essentially prevents logging
 * (i.e., by returning immediately) after the first libc call and until
 * that call returns. */
#define __CALL_LIBC(r, f, ...) \
	is_in_libc++; \
	assert(__LIBC_PTR(f) != NULL); \
	__START_WRAPPER_TIMER(__LIBC_TIMER(f), _call_libc); \
	r = (*__LIBC_PTR(f))(__VA_ARGS__); \
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _call_libc); \
	is_in_libc--; \
	if (!_private_info.done_with_init || is_in_libc || _private_info.is_replay) { \
		return ((r)); \
	} else { \
		/* errno may get trampled by a subsequent libc call. We
		 * save it so that we can write out a log entry later. */ \
		write_errno_log_entry(errno); \
	}

#define __CALL_LIBC_1(f, ...) \
	is_in_libc++; \
	assert(__LIBC_PTR(f) != NULL); \
	__START_WRAPPER_TIMER(__LIBC_TIMER(f), _call_libc); \
	(*__LIBC_PTR(f))(__VA_ARGS__); \
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _call_libc); \
	is_in_libc--; \
	if (!_private_info.done_with_init || is_in_libc || _private_info.is_replay) { \
		return ; \
	} else { \
		/* errno may get trampled by a subsequent libc call. We
		 * save it so that we can write out a log entry later. */ \
		write_errno_log_entry(errno); \
	}

/* Return if the call is libc reentrant or if it is being made before
 * initialization is complete. Unlike the __CALL_LIBC macro, this
 * doesn't invoke the libc function if the aforementioned condition is not met.
 * This is useful when wrapping functions like send and sendto(). See
 * those wrappers for examples on how to use this. */
#define __PREDICATED_CALL_LIBC(r, f, ...) \
	if (!_private_info.done_with_init || is_in_libc) { \
		r = (*__LIBC_PTR(f))(__VA_ARGS__); \
		return ((r)); \
	}

/* Make this call if you don't want any of the system calls
 * further down the stack to be logged. Use this, for example,
 * when you need to make libc calls from within a wrapper. */
#define __INTERNAL_CALL_LIBC_1(f, ...) \
	is_in_libc++; \
	(*__LIBC_PTR(f))(__VA_ARGS__); \
	is_in_libc--;


#define __INTERNAL_CALL_LIBC_2(r, f, ...) \
	is_in_libc++; \
	r = (*__LIBC_PTR(f))(__VA_ARGS__); \
	is_in_libc--;

/* Permit other procs/threads access to the CPU and then invoke the
 * potentially blocking function F. The idea is to prevent the process
 * calling F from hogging the CPU (as might occur on a wait, select,
 * sleep, etc. */
#define __ASYNC_CALL(r, f, ...) { \
	int errno_copy; \
	\
	DEBUG_ENTRY("async call " #f); \
	/* An ASYNC_CALL may be made before liblog get's a chance to
	 * initialize itself. In that case, make sure we don't touch
	 * possibly unitialized data structures. */ \
	if (_private_info.done_with_init) { \
		_shared_info->num_active_threads--; \
		ASSERT_SCHED_INVARIANTS(); \
		RELEASE_SCHED_LOCK(); \
		\
	} \
	is_in_libc++; \
	__START_WRAPPER_TIMER(__LIBC_TIMER(f), _call_libc); \
	r = (*__LIBC_PTR(f))(__VA_ARGS__); \
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _call_libc); \
	errno_copy = errno; \
	is_in_libc--; \
	if (_private_info.done_with_init) { \
		ACQUIRE_SCHED_LOCK(); \
		_shared_info->num_active_threads++; \
		\
		ASSERT_SCHED_INVARIANTS(); \
		\
		LOG_CONTEXT_SWITCH(); \
	} \
	if (!_private_info.done_with_init || is_in_libc) { \
		return ((r)); \
	} else { \
		write_errno_log_entry(errno_copy); \
	} \
}

/* Scheduler macros. These make it easier to understand and write code. */
#define ACQUIRE_SCHED_LOCK() \
	__INTERNAL_CALL_LIBC_1(pthread_mutex_lock, &_shared_info->sched_lock);

#define RELEASE_SCHED_LOCK() \
	__INTERNAL_CALL_LIBC_1(pthread_mutex_unlock, &_shared_info->sched_lock);

#if 0
#define ASSERT_SCHED_LOCK_IS_LOCKED() \
	assert(_shared_info->sched_lock.__m_lock.__status);
#else
#define ASSERT_SCHED_LOCK_IS_LOCKED()
#endif

/* Establish the assumptions we make about the scheduler.
 * These should always holds for the scheduler to work properly.
 * Hopefully, this will help us verify the code and help you
 * understand the code a bit better.
 *
 * Should be called only when you have the sched lock. */
#define ASSERT_SCHED_INVARIANTS() { \
	assert(_shared_info->num_threads <= MAX_THREADS); \
	assert(_shared_info->num_threads >= _shared_info->num_procs); \
	assert(_shared_info->num_threads >= 1); \
	assert(_shared_info->num_active_threads <= _shared_info->num_threads); \
	/* num_active_threads could be 0 if there is only 1 thread and that
	 * thread executes a blocking call. */ \
	assert(_shared_info->num_active_threads >= 0); \
	assert(_shared_info->num_procs <= MAX_PROCS); \
	/* There thread-list should be non-empty. */ \
	assert(_shared_info->head != NULL); \
	/* There should always be space for one more thread. */ \
	assert(_shared_info->free_head != NULL); \
	/* There should always be at least one active thread. */ \
	ASSERT_SCHED_LOCK_IS_LOCKED() \
}

#define SCHED_WAIT() \
	assert(_shared_info != NULL); \
	assert(_my_tinfo != NULL); \
	my_cond_wait(&_my_tinfo->cond, &_shared_info->sched_lock);

#define SCHED_SIGNAL(t) \
	assert(t != NULL); \
	my_cond_signal_wrapper(&t->cond, t->replay_mode_id);


/* Sends a log message to the logger process. */
#define ENTRY(...) { \
	if (!buf_to_shmem(__VA_ARGS__)) { \
		fatal("can't communicate with logger process in ENTRY()\n"); \
	} \
}

#if 0
#define DEBUG_ENTRY(msg, ...) { \
	if (!buf_to_shmem("<debug " msg "/>\n", ##__VA_ARGS__)) { \
		fatal("can't communicate with logger process in DEBUG_ENTRY()\n"); \
	} \
}
#else
#define DEBUG_ENTRY
#endif

#define UNIMPLEMENTED_LOG_WRAPPER(f) fatal("log wrapper for " #f " is not implemented.\n");
#define UNIMPLEMENTED_REPLAY_WRAPPER(f) fatal("replay wrapper for " #f " is not implemented.\n");


/**************************************************
 * Type Definitions and Data Structues
 **************************************************/

struct signal_entry {
	int sig;
	siginfo_t si;
	ucontext_t uc;

	TAILQ_ENTRY(signal_entry) entries;
};

TAILQ_HEAD(tailhead, signal_entry);

/* This is what we append to the end of messages. */
typedef struct tag_struct {
	char tag_str[MSG_TAG_LEN];
	uint64_t vclock;
} tag_t;


typedef struct logentry_header {
	int id;
	int size;
	int64_t vclock;
} logentry_header_t;

/* Logging details for application processes.
 * During logging, some of these variables are used only by the
 * compressor process; only the read-only log_prefix is shared.
 *
 * During replay, the application and scheduler thread may each
 * access these variables, but concurrency is strictly prohibited.
 */
typedef struct {

	/* Number of signals that have been generated, but not
	 * delivered quite yet. */
	int num_pending_sigs;

	/* Time information. */
	uint64_t log_epoch;			// Uniquely identifies a program execution

	/* Log filename and path information. */
	char log_path[PATH_MAX];	// Log pathname (where to put logs)
	char log_prefix[PATH_MAX];	// Program name up to ".<pid>.<time>.log.gz
	char log_name[PATH_MAX];	// Full name of current log (filled in later)

	/* Logging-only variables: */
	int socket_fd;
	int logger_port;			// Logger's incoming port.
	in_addr_t logger_addr;		// Address of logger.


	/* Original process state. */
	pid_t orig_pid;
	pid_t orig_pgid;
	/* Parent process id. */
	pid_t orig_ppid;

	char tag_str[MSG_TAG_LEN];		// The tag we append to outgoing messages
	/* Pointers to application specified signal handlers. */
	struct sigaction orig_handlers[NSIG];

	/* Synchronization variables. */
	pthread_mutex_t barrier_mutex;
	pthread_cond_t barrier_cond;

	/* Execution mode variables. */
	int is_replay;
	int is_ckpt_master;
	/* How often we should take a ckpt. Should be read only. */
	uint64_t ckpt_period_us;

	int num_shm_entries;

	int done_with_init;
	int done_with_execution;
	int about_to_exit;

	volatile int* shmpos;
	volatile char* shmdata;
} private_info_t;

/* Info about application process. During logging and
 * replay, this variable holds information for the currently-running
 * process, which is handy since you can look at important process
 * state using GDB. This data is private in that each process has
 * an instance of this variable. */
extern private_info_t _private_info;

/* The code assumes HANDOFF == 0. */
enum {HANDOFF = 0 /* used by both liblog and libreplay */,
	  EXIT /* this is used by libreplay only */};

/* This is the structure we pass to set/get_thread_area(). It actually
 * describes an entry in the process's LDT (local descriptor table),
 * but set/get_thread_area() interprets it as the descriptor for the
 * thread's TLS segment. */
/*
 * The name of this structure varies among Linux versions.
 * It was `modify_ldt_ldt_s' on some, then changed to
 * `user_desc'.  Always in /usr/include/asm/ldt.h.
 * We re-define it so that we don't have to figure out
 * the right name. */

struct linux_ldt {
	unsigned int  entry_number;
	unsigned long base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit:1;
	unsigned int  contents:2;
	unsigned int  read_exec_only:1;
	unsigned int  limit_in_pages:1;
	unsigned int  seg_not_present:1;
	unsigned int  useable:1;
};

/* A thread's id has two levels: a process id part and a thread
 * id part. We need two levels to deal with the fact that neither
 * level alone is sufficient is to serve as a unique identifier
 * for a thread. */
typedef struct thread_id {
	pid_t pid;
	pthread_t tid;
} thread_id_t;

/* This structure describes a node in our doubly-linked list
 * of threads. */
typedef struct thread_info {
	/* Log mode variables. */
	thread_id_t log_mode_id;

	/* Thread state. */
	int e_val;
	int state;
	jmp_buf context;

	struct linux_ldt tls;
	unsigned int gs;

	/* Replay mode variables. */
	thread_id_t replay_mode_id;
	my_cond_t cond;

	/* Log file currently in use by this thread. */
	FILE* log_file;

	/* Number of rotations that this thread is aware of. If
	 * this falls behind the true number, then we know it
	 * is time to switch to the next log file. */
	int num_rotations;

	/* Use these to traverse the doubly-linked list of threads. */
	struct thread_info* prev;
	struct thread_info* next;
} thread_info_t;

/* Exactly one instance of this structure is shared by all application
 * processes (and threads). */
typedef struct shared_info {
	/* Points to the head of the threads linked list. */
	thread_info_t* head;

	/* Points to the head of the free list. */
	thread_info_t* free_head;

	/* The total number of threads and processes in the system
	 * (uncluding inactive ones). */
	int num_threads;
	int num_procs;

	/* The total number of active (i.e., not blocked) threads
	 * in the system. We don't care about processes since scheduling
	 * is done at thread granularity. */
	int num_active_threads;

	/* Coscheduler mutex. Each application thread must acquire
	 * this lock before running. See the coscheduler (cosched.h) in
	 * liblog for details. */
	pthread_mutex_t sched_lock;

	/* Pointer to the checkpoint master's thread_info_t.
	 * This is used only during replay. */
	thread_info_t* ckpt_master;

	/* Interprocess barrier, used during checkpointing. */
	my_barrier_t proc_ckpt_barrier;
	uint64_t last_ckpt_us;	/* Time of last checkpoint. */
	int is_ckpt_in_progress; /* Use this flag to avoid initiating
									  * a new checkpoint before the previous
									  * one finishes (see liblog/log.c). */

	/* During logging, the vclock is updated by every
	 * process (and no lock is required since processes execute
	 * one at a time). */
	uint64_t vclock;				/* Identifies current log file (usefull
								 * for replay). */
	uint64_t last_clock;		/* Last result of get_cpu_micros(). */

	/* The current log's vlock id. This allows processes to figure out
	 * what log file to rotate to (once the initial rotation to the
	 * log file has taken place). */
	uint64_t log_vclock_id;

	/* Log shared memory segment info. This needs to be in shared memory
	 * since the logger will hand us a new segment once we've filled up
	 * the current segment. And also we share one log with all the other
	 * application processes. */
	int shmid;
	int shmsize;

	/* Statistics. */
	long entry_num;				/* Current entry in log. */
	long total_events;			/* Count across logs. */

	long cur_pos;			/* Current position within the log file. */
	int num_rotations;			/* Number of rotations performed thus far. */

	/* Log-mode coscheduler variables. */
	thread_id_t prev_id;
} shared_info_t;

extern shared_info_t* _shared_info;

/* The current thread's info. This should be a pointer into data in
 * mmaped() shared memory. */
extern __thread thread_info_t* _my_tinfo;

/* This variable is not in thread_info_t because _my_tinfo needs to be
 * explicitly allocated, and yet this variable may need to be accessed
 * before that happens (libckpt does it, for example). */
extern __thread int is_in_libc;

/* We use this to keep track of the errno value during logging. */
extern __thread int last_errno;

extern sigset_t _block_set;

/* Should we call through to the underlying libc function. */
extern __thread int overlord_should_call_through;

/* Are we executing liblog/libreplay code? */
extern __thread int is_in_library;

extern int _in_gdb;	// FALSE, unless gdb sets to TRUE

#define WORKSPACE_SIZE 4096
extern char _liblog_workspace[];

#endif
