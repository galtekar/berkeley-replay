#ifndef REPLAY_H
#define REPLAY_H

#include <inttypes.h>
#include <sys/queue.h>
#include <pthread.h>
#include "misc.h"

#if 0
#define TRAP() { int i = 1; while(i); }
#elif 0
#define TRAP() asm("int $3")
#else
#define TRAP() { errno = _my_tinfo->e_val; hook_for_gdb( LL_HOOK_WRAPPER_TRAP, NULL ); }
#endif

extern char libreplay_io_buf[LOG_BUF_SIZE];	

#define LOG_TO_BUF() log_to_buf(libreplay_io_buf, LOG_BUF_SIZE)

extern int log_to_buf(char* buf, size_t buf_size);
extern void deliver_queued_signals();

#endif
