#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include <syscall.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <ckpt.h>


#include <sys/time.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>

#include "libc_pointers.h"
#include "logreplay.h"
#include "gcc.h"
#include "errops.h"
#include "util.h"
#include "misc.h"
#include "clock.h"

#include "replay.h"

#define DEBUG  1
#include "debug.h"

/* Persistent flag for flag_inconsistent_replay below. */
static int stop_if_inconsistent = TRUE;

/* Stop replay and print out the current log line in the buffer. */
void HIDDEN stop_replay( const char* fmt, ...) {
	va_list args;

	lprintf("REPLAY STOPPED: " );

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	lprintf("current line (%s:%ld): %s\n", _private_info.log_name,
	       _shared_info->entry_num, libreplay_io_buf);

	//	print_backtrace();

	/* exit() was calling fflush() */
	// exit(-1);
	__INTERNAL_CALL_LIBC_1( fflush, NULL );

	while (1);
}

/* Gives GDB user a convenient way to continue replay in
   flag_inconsistent_replay().
   To continue, toggle *should_stop from GDB.
   To skip all future checks, set stop_if_inconsistent. 
*/
void HIDDEN stop_replay_trap( int * should_stop ) {

  hook_for_gdb( LL_HOOK_STOP_REPLAY, should_stop );
  
  if( stop_if_inconsistent && *should_stop ) {
    lprintf("Exiting\n" );
  } else {
    lprintf("Overriding failstop; continuing...\n" );
  }
  return;
}

void HIDDEN flag_inconsistent_replay( const char* fmt, ... ) {
  va_list args;
  int should_stop = stop_if_inconsistent;
  
  lprintf("ERROR: Replay has diverged from logs.\n" );
  lprintf("ERROR: ");
  
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);

  // Give GDB a chance to toggle should_stop
  stop_replay_trap( &should_stop );

  if( stop_if_inconsistent && should_stop ) {
    stop_replay( "consistency check failed\n" );
  }	// Else, failstop overriden by GDB.
}

/* Returns TRUE (1) if process #pid is currently being traced, e.g. by
   GDB, or FALSE (0) otherwise.  */
int HIDDEN is_traced( pid_t pid ) {
  /* Implementation relies on /proc/pid/status */
  char buf[LOG_BUF_SIZE];
  char status_filename[LOG_BUF_SIZE];
  int ret, field_len;
  char *str;
  int tracer_pid;
  FILE *status_file;

  ret = snprintf( status_filename, LOG_BUF_SIZE,
		  PROC_STATUS_FMT, (int)pid );
  assert( LOG_BUF_SIZE > ret );

  __INTERNAL_CALL_LIBC_2( status_file, fopen, status_filename, "r" );
  assert( status_file );

  field_len = strlen(TRACER_PID_FIELD);
  do {
    __INTERNAL_CALL_LIBC_2( str, fgets, buf, LOG_BUF_SIZE, status_file );
    assert( str == buf );
    DEBUG_MSG(6, "Checking line: %s", buf );
    if( strncmp( buf, TRACER_PID_FIELD, field_len ) == 0 ) {
      tracer_pid = strtol( &(buf[field_len]), NULL, 0 );
      DEBUG_MSG(6, "strtol %s <= %d", &(buf[field_len]),
			   tracer_pid );
      assert( tracer_pid != LONG_MIN && tracer_pid != LONG_MAX );
      __INTERNAL_CALL_LIBC_1( fclose, status_file );
      return (tracer_pid != 0);
    }
  } while( TRUE );
  abort();
}

/* Drops a checkpoint of current application state. The checkpoint
 * file will have VCLOCK as a unique identifier to distinguish it
 * from the set of checkpoints taken earlier by the same application. */
int HIDDEN libreplay_drop_checkpoint( uint64_t vclock ) {
	char ckpt_filename[PATH_MAX];
	char base_name[PATH_MAX];
	int is_recovering = 0;
	int old;

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

	old = _private_info.is_replay;
	_private_info.is_replay = LIBREPLAY_CHECKPOINT;

	/* Only one process (the checkpoint master) needs to save 
	 * shared memory segments. */
	is_recovering = ckpt_ckpt(ckpt_filename,
			_private_info.is_ckpt_master ? 0 : IGNORE_SHAREDMEM);

	/* If we're not recovering, then we must still be running from the
	 * original checkpoint type. */
	if (!is_recovering) {
		_private_info.is_replay = old;
	}

	DEBUG_MSG(2, "Recovery line. is_recovering=%d\n",
			is_recovering);

	/* RECOVERY PATH. DON'T PUT ANY LIBLOG SPECIFIC CODE HERE (!!). */

	/* RECOVERY LINE. When recovering from the checkpoint, execution will
	 * resume here. Actually, execution will resume somewhere in ckpt_ckpt(),
	 * but as far we care, we can say that it resumes here. */

	return is_recovering;
}
