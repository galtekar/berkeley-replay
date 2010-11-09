#ifndef OVERLORD_H
#define OVERLORD_H
#define __USE_LARGEFILE64

#include <stdarg.h>
#include <netdb.h>
#include <utime.h>

#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>

#include <dirent.h>

#include "logreplay.h"

/* Why do we need this macro? Well, a library's constructor
 * (in particular, libckpt's init function, but other libraries
 * also apply), may execute before liblog's and then call a
 * wrapped function. When that happens, we want to make sure
 * the redirection works. That's why this macro is invoked
 * from each wrapper in overlord.c */
#define INIT_POINTERS() { \
	if( !_private_info.done_with_init ) { \
		/* This should execute only when in log mode. */ \
		assert(!_private_info.is_replay); \
		init_libc_pointers(); \
		init_logging_pointers();  \
	} \
}


/* This macro should be called at the beginning of all
 * top-level wrappers (i.e., those in overlord.c). */
#if ENABLE_CLEAR_STACK 
#define PRE_CALL_INIT() pre_call_init()
#else
#define PRE_CALL_INIT() { \
	if (!_private_info.is_replay) { \
		INIT_POINTERS(); \
		LOG_AND_DELIVER_QUEUED_SIGNALS(); \
		INVOKE_COSCHEDULER(); \
	} else { \
		/* Nothing needs to be done here. */ \
	} \
}
#endif

/* Process. */
extern void init_logging_pointers();
extern void init_replay_pointers();

#endif
