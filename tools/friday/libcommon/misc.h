#ifndef MISC_H
#define MISC_H

#include <inttypes.h>

typedef enum {
  LL_HOOK_WRAPPER_TRAP = 0,
  LL_HOOK_NEXT_LOG,
  LL_HOOK_FORK,
  LL_HOOK_SIGNAL,
  LL_HOOK_WAIT,
  LL_HOOK_THREAD_EXIT,
  LL_HOOK_STOP_REPLAY,
  LL_HOOK_SEGV,
} liblog_hook_code;
// Called at strategic points throughout replay.
extern void hook_for_gdb( liblog_hook_code code, void * datum );

extern void get_prefix_str(char* prefix_str);
extern void construct_ckpt_filename_base(char* path, char* prefix, char* tag, 
	int orig_pid, int orig_pgid, uint64_t epoch, uint64_t vclock, char* filename, int size);
extern void construct_log_filename_base(char* path, char* prefix, char* tag, 
	int orig_pgid, uint64_t epoch, uint64_t vclock, char* filename, int size);
extern void construct_lib_filename_base(char* path, char* prefix, char* tag,
	int orig_pgid, uint64_t epoch, char* filename, int size);
extern void clear_stack_footprint();

#endif
