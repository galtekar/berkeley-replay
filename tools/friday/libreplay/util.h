#ifndef __LOG_UTIL_H
#define __LOG_UTIL_H

#define FUTEX_WAIT (0)
#define FUTEX_WAKE (1)
#define FUTEX_FD (2)
#define FUTEX_REQUEUE (3)

#define PROC_STATUS_FMT "/proc/%d/status"
#define TRACER_PID_FIELD "TracerPid:"

extern void stop_replay(const char* fmt, ...);
extern void flag_inconsistent_replay( const char* fmt, ... );
extern int libreplay_drop_checkpoint( uint64_t vclock );
  
/* Returns TRUE (1) if process #pid is currently being traced, e.g. by
   GDB, or FALSE (0) otherwise.  */
extern int is_traced( pid_t pid );

#endif
