#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ckpt.h>
#include <syscall.h>
#include <fcntl.h>
#include <unistd.h>

#include <pthread.h>

#include <sys/types.h>

#define __USE_LARGEFILE64
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

/* For _r_debug and link_map. */
#define __USE_GNU
#include <link.h>
#include <dlfcn.h>

#include "libc_pointers.h"
#include "logger.h"
#include "log.h"
#include "sendlog.h"

#include "misc.h"
#include "clock.h"
#include "errops.h"
#include "dllops.h"
#include "gcc.h"
#include "timings.h"

#include "lwrap_sigs.h"
#include "overlord.h"
#include "msg_coding.h"
#include "cosched.h"
#include "fast_logging.h"

#define LIBREPLAY "libreplay.so"

#define DEBUG 1

#include "debug.h"

sigset_t _block_set;
int _in_gdb = FALSE;	// FALSE, unless gdb sets to TRUE
char _liblog_workspace[WORKSPACE_SIZE];

/* Is this proc the parent process that confuses gdb? */
HIDDEN int __ll_is_confusing_parent = 0;

static void start_banner() {
	time_t t;
	char time_buf[256];

	time(&t);

	strncpy(time_buf, ctime(&t), sizeof(time_buf));
	time_buf[strlen(time_buf)-1] = 0;

	printf("*********************************************************************\n");
	printf("*                                                                   *\n");
	printf("* LIBLOG 1.0 last compiled %s %s                     *\n", __DATE__, __TIME__);
	printf("*                                                                   *\n");
	printf("* PID: %5.5d   DEBUG_LEVEL: %2.2d   TIME: %s     *\n", syscall(SYS_getpid), debug_level, time_buf);                   
	printf("*                                                                   *\n");
	printf("*********************************************************************\n");
}

static void init_scheduler() {
	/* Allocate a shared memory segment for the shared process
	 * list. */
	thread_info_t* free_list;
	int i;

	/* The _shared_info structure should be in inter-process
	 * shared memory so that all process can read/write it. */
	assert( sizeof(shared_info_t) < getpagesize() );
	if ((_shared_info = (shared_info_t*) (*__LIBC_PTR(mmap))(0x0,
			getpagesize(), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		perror("mmap");
		fatal("can't allocate interprocess shared region\n");
	}

	memset((void*)_shared_info, 0x0, sizeof(shared_info_t));

	/* Setup the free list of proc_infos. We allocate proc_infos
	 * from this free list on demand (i.e., when new procs are
	 * created (see lwrap_procs.c). */
	free_list = (thread_info_t*) (*__LIBC_PTR(mmap))(0x0,
			MAX_THREADS * sizeof(thread_info_t),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert(free_list != MAP_FAILED);

	for (i = 0; i < MAX_THREADS - 1; i++) {
		free_list[i].next = &free_list[i+1];
	}
	free_list[i].next = NULL;

	_shared_info->free_head = free_list;

	/* Setup synch. variables. */
	pthread_mutex_init(&_shared_info->sched_lock, NULL);
	my_barrier_init(&_shared_info->proc_ckpt_barrier);

	/* Allocate a thread info from the free list for this process and update
	 * the free list. */
	assert(_shared_info->free_head != NULL);
	_my_tinfo = _shared_info->free_head;
	_shared_info->free_head = _shared_info->free_head->next;

	/* Fill in the thread info's fields. */
	memset(_my_tinfo, 0x0, sizeof(thread_info_t));
	_my_tinfo->log_mode_id.pid = syscall(SYS_getpid);
	_my_tinfo->log_mode_id.tid = (*__LIBC_PTR(pthread_self))();
	assert(_my_tinfo->log_mode_id.pid != 0);
	assert(_my_tinfo->log_mode_id.tid != 0);
	_my_tinfo->prev = _my_tinfo->next = NULL;

	/* Add the newly created thread node to the thread list. Note
	 * that this list resides in interprocess shared memory setup by
	 * the mmap above. */
	_shared_info->head = _my_tinfo;
	_shared_info->num_threads = _shared_info->num_active_threads = 1;
	_shared_info->num_procs = 1;

	/* Acquire the scheduler lock. Once we have it, this process has
	 * exclusive access to the CPU. */
	ACQUIRE_SCHED_LOCK();

	ASSERT_SCHED_INVARIANTS();
}

/* Get this process ready for gdb to take control. */
static void prep_for_gdb() {
	pid_t id;

	/* gdb gets confused when the restart executable replaces
	   its memory with the original application's.
	   Specifically, it has trouble recognizing that the cached
	   process id, the symbol table, and list of loaded
	   libraries have changed.  We fork a new process here, which
	   forces gdb to reset/reread some cached state.  I'm not
	   sure how hard it would be to "fix" gdb, but this trick
	   works for now.
	   (Important: remember to set the gdb variable
	   "follow-fork-mode" to "child".)
	 */

	/* Invoke the system call directly rather than the libc
	 * counterpart, since the pthread_create in
	 * libreplay:restore_processes() will zero out (portions of)
	 * the TLS segment if you do the latter. */
	__INTERNAL_CALL_LIBC_2( id, fork );
	//id = syscall(SYS_fork);

	DEBUG_MSG(2, "fork() = %d\n", id);
	if( id ) {
		/* Mark that the about-to-die process is the confusing
		 * parent. This allows us to avoid certain cleanup code
		 * in the program descructor (i.e., log_finish()) that may
		 * fail since certain program state (e.g., the socket to
		 * the log server) hasn't been set up yet. */
		__ll_is_confusing_parent = 1;

		/* Make the confusing parent disappear. We make a syscall
		 * rather than exit() because we want to avoid calling the
		 * library descructor function (libreplay's in particular). */
		syscall(SYS_exit, 0);
	}
}

/* This function will be called upon checkpoint recovery (but before
 * control is handed to the application). Use this opportunity to
 * load in libreplay, thereby redirecting all future wrapped
 * calls to those defined by libreplay. This function should be
 * kept minimal. */
static void post_restart_handler(void *arg) {
	void *libreplay_handle = NULL;
	void (*start_replay)(void);
	void (*restore_processes)(void);


	/* This is strictly not necessary, but we do so to preserve
	 * the invariant in case it becomes usefull in the future. */
	_private_info.done_with_init = 0;

	assert(arg == NULL);

	/* The libc pointers should still be valid, since the address
	 * is restored to exactly the way it was. */
	VERIFY_LIBC_POINTERS();

	/* This must be called before dlopen(). Why? */
	prep_for_gdb();

	/* Assume logs and checkpoints are in the working directory. */
	/* Set this before calling restore_processes(). */
	strcpy(_private_info.log_path, "./");

	/* This variable should
	 * already be set since the master checkpoint process must've been
	 * within a wrapper call (probably read()) with this variable set when 
	 * taking the checkpoint. */
	assert(overlord_should_call_through == 1);

	/* At the time the checkpoint was taken, is_in_library was 2, since
	 * the checkpoint is initiated within a libc wrapper, and because
	 * libckpt then makes a write() libc call when saving memory maps
	 * to disk. */
	assert(is_in_library == 2);

	/* This flag should've been set before taking the checkpoint, and
	 * hence, it should still be set. We will want to reset it
	 * to allow checkpointing during replay. See replay.c start_replay()
	 * for further clues. */
	assert(_shared_info->is_ckpt_in_progress == 1);

	/* Load libreplay. We want RTLD_NOW so that we get any ``undefined
	 * function'' errors up front. We want RTLD_GLOBAL so that the
	 * library's external symbols are visible to us. This assumes that
	 * it is compiled with -rdynamic or (-Wl,--export-dynamic). */
	libreplay_handle = my_dlopen(LIBREPLAY, RTLD_NOW | RTLD_GLOBAL);

	/* Get a pointer to important functions in libreplay. */
	*(void **) (&start_replay) = my_dlsym(libreplay_handle, "start_replay");
	*(void **) (&restore_processes) = my_dlsym(libreplay_handle,
		"restore_processes");
	assert(start_replay != NULL);
	assert(restore_processes != NULL);

	if (_private_info.is_ckpt_master) {
		/* CHECKPOINT MASTER -- the process that initiated the checkpoint. */

		/* Checkpoint master already has the process and thread lock. */
		ASSERT_SCHED_LOCK_IS_LOCKED();

		/* Other processes may want to know details about the
		 * checkpoint master (e.g., his condition variable). */
		_shared_info->ckpt_master = _my_tinfo;

		/* Reset the barrier since the checkpoint may have been taken
		 * while some processes had already reached the barrier. */
		my_barrier_init(&_shared_info->proc_ckpt_barrier);

		/* This must be called before we switch to replay-mode
		 * wrappers, since this function eventually calls ckpt_restart(). */
		DEBUG_MSG(2, "Master calling restore_processes().\n");
		restore_processes();

	} else {
		/* CHECKPOINT SLAVE -- processes that were waiting for the
		 * coscheduler lock when the checkpoint was initiated. */

		/* Remember, only one thread (and thus one process) can execute
		 * at a time. */
		ACQUIRE_SCHED_LOCK();
	}

	/* Redirect system calls to the replay wrappers. This must be done
	 * after all process checkpoints have been restored. If we do it
	 * before, libckpt will use the replay mode versions, which don't
	 * actually do anything but read from the logs. */
	init_replay_pointers();

	/* Pass control to libreplay. */
	start_replay();

	/* Only the checkpoint master should reach here. The others
	 * should be waiting for the go-ahead signal in libreplay. */
	assert(_private_info.is_ckpt_master);

	assert(_private_info.done_with_init == 1);
	assert(is_in_library == 1);
	assert(_shared_info->is_ckpt_in_progress == 0);

	/* The master should now return from this function and resume
	 * execution at the point where the checkpoint was taken,
	 * which is either in start_logging() or at the end of some
	 * log-mode wrapper function. */
}

/*
 * Initialize the checkpointing subsystem.
 */
static void init_checkpointing() {
	struct ckptconfig cfg;

	DEBUG_MSG(2, "Initializing libckpt.\n");
	/* Must be called before using any libckpt functionality. */
	ckpt_init();
	DEBUG_MSG(2, "Done initializing libckpt.\n");

	memset( &cfg, 0, sizeof(struct ckptconfig));

	cfg.flags = CKPT_CONTINUE;

	/* Continue execution after taking a checkpoint. */
	cfg.continues = 1;

	ckpt_config(&cfg, NULL);

	/* Tell the checkpointing library to call post_restart_handler
	 * before returning control to the application, but after
	 * restoring the checkpointed state. */
	ckpt_on_restart(&post_restart_handler, NULL);

	DEBUG_MSG(2, "Done initializing checkpointing library.\n");
}

static void init_main() {
	/* We need this for our automatic testing script (``run_tests'') to
	 * work. Without it, output is buffered when redirected to a file,
	 * and as a result it doesn't reflect the scheduling order of
	 * multiple processes. */
	__LIBC_PTR(setvbuf)(stdout, (char*)NULL, _IONBF, 0);

	/* We don't want any child processes to reload liblog,
	 * and therefore go through the initialization. That is
	 * unncessary since the child will inherit a copy of liblog
	 * from the parent, and liblog will take care of registering
	 * the child with the logger. */
	unsetenv("LD_PRELOAD");

	DEBUG_MSG(2, "Starting init_main().\n");

	/* This flag is set at the end of start_replay(), where
	 * we are finally done with liblog initialization. */
	_private_info.done_with_init = 0;

	/* By unsetting this variable, we get exclusive access
	 * to the CPU while taking the checkpoint. That is, if
	 * drop_checkpoint() or any of its sub functions makes
	 * a system call, we won't get switched out, since 
	 * INVOKE_COSCHEDULER() will do nothing when this var
	 * is 0.
	 *
	 * This flag is not set until the log_finish() destructor
	 * is called (see below). */
	_private_info.done_with_execution = 0;

	_private_info.is_replay = 0;

	/* Obtain function pointers into libc. */
	init_libc_pointers();

	/* Use log mode wrappers. */
	init_logging_pointers();

	/* For TCP/UDP sockets. */
	init_socket_info();

	/* For our cooperative scheduler. */
	init_scheduler();

	/******************************************************************/
	/* Checkpointing and logging specific initialization starts here. */
	/******************************************************************/

	/* Setup recovery handlers and checkpointing parameters. */
	init_checkpointing();

	/* Catch signals before passing them to the application. */
	install_signal_handlers();

	init_fast_logging();

	init_timers();

	/* Start logging. */
	_private_info.orig_ppid = syscall(SYS_getpid);
	start_logging();

	/* By setting this variable, we allow context switching on 
	 * system calls. */
	_private_info.done_with_init = 1;

	/* About to run application code. */
	is_in_library--;
	assert(is_in_library == 0); 
	assert(overlord_should_call_through == 0);
	assert(is_in_libc == 0);

	/* RECOVERY PATH. DON'T PUT ANY LIBLOG SPECIFIC CODE HERE (!!). */
	/* Recall that the code path going through start_logging()
	 * takes an initial checkpoint. */
	DEBUG_MSG(2, "Ending log_main (_private_info.is_ckpt_master=%d).\n", 
			_private_info.is_ckpt_master);
}

/*
 * This function will automatically be called by the dynamic linker
 * once the library is loaded (e.g., via dlopen()), but before program
 * execution begins. Thus, it is an excellent place for initialization code.
 */
static __attribute__((constructor)) void liblog_start() {
	char *dbglvl = NULL;

	dbglvl = __LIBC_PTR(getenv)("LIBLOG_DEBUG_LEVEL");

	/* Use the default debug level DEBUG_LEVEL if none is specified
	 * on the commandline. */
	debug_level = dbglvl ? atoi(dbglvl) : DEBUG_LEVEL;

	start_banner();

	init_main();

	/* RECOVERY PATH. DON'T PUT ANY LIBLOG SPECIFIC CODE HERE (!!). */

	CLEAR_STACK_FOOTPRINT();
}
