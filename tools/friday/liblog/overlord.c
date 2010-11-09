#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <syscall.h>
#include <signal.h>
#include <grp.h>

#define __USE_LARGEFILE64
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>

#include "misc.h"
#include "dllops.h"
#include "errops.h"
#include "gcc.h"
#include "tmalloc.h"

#include "overlord.h"
#include "util.h"
#include "lwrap.h"
#include "timers.h"

#include "libc_pointers.h"
#include "patterns.h"
#include "fast_logging.h"
#include "sendlog.h"

#include "cosched.h"
#include "lwrap_sigs.h"

#define __USE_GNU
#include <dlfcn.h>

#define DEBUG 1
#define MALLOC_DEBUG 1

#include "debug.h"

/* If this flag is set, then the overlord wrappers invoke the real libc
 * functions rather than invoking logging/replay mode wrappers. This is
 * useful for debugging, and also, most wrappers rely on it to prevent
 * recursive calls to other wrappers. In other words, it enforces
 * a ``at most one wrapper function on the stack at any time'' rule. */
__thread int overlord_should_call_through = 0;

/* Gets set anytime we are executing within liblog. It's also set
 * before liblog starts and after liblog finishes. It shouldn't be
 * set when executing application code. */
__thread int is_in_library = 1;


/* CALL_WRAPPER macros: invoke the 2nd-level log-mode/replay-mode 
 * wrapper. We use a macro because it makes the 1st-level wrapper
 * implementation very compact and easy to change. */
#define CALL_WRAPPER(T, f, U) { \
	T ret; \
	/* Careful that this variable's name doesn't conflict with a 
	 * parameter name. */ \
	static int __liblog_is_timer_allocated = 0; \
	\
	is_in_library++; \
	\
	if (!__liblog_is_timer_allocated && _private_info.done_with_init) { \
		__LIBC_TIMER(f) = alloc_new_wrapper_timer("_" #f "_timer"); \
		__liblog_is_timer_allocated = 1; \
	} \
	\
	if (!overlord_should_call_through) { \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _cosched); \
		PRE_CALL_INIT(); \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _cosched); \
		\
		assert(__2nd_level_wrapper_##f != NULL); \
		\
		/* Setting the overlord_should_call_through flag ensures that 
		 * libc calls invoked by wrapper functions (either log or 
		 * replay mode) are passed on to libc, rather than to the
		 * overlord wrappers. */ \
		DEBUG_MSG(5, "wrapper: " #f "\n"); \
		overlord_should_call_through = 1; \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		ret = (*__2nd_level_wrapper_##f) U; \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		overlord_should_call_through = 0; \
	} else { \
		DEBUG_MSG(5, "wrapper (calling through): " #f "\n"); \
		ret = (*__LIBC_PTR(f)) U; \
	} \
	\
	CLEAR_STACK_FOOTPRINT(); \
	is_in_library--; \
	assert(is_in_library >= 0); \
	return ret; \
}

#define CALL_WRAPPER_VARG(T, f, l, U) { \
	T ret; \
	va_list args; \
	/* Careful that this variable's name doesn't conflict with a 
	 * parameter name. */ \
	static int __liblog_is_timer_allocated = 0; \
	\
	is_in_library++; \
	\
	if (!__liblog_is_timer_allocated && _private_info.done_with_init) { \
		__LIBC_TIMER(f) = alloc_new_wrapper_timer("_" #f "_timer"); \
		__liblog_is_timer_allocated = 1; \
	} \
	\
	va_start(args, l); \
	if (!overlord_should_call_through) { \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _cosched); \
		PRE_CALL_INIT(); \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _cosched); \
		\
		assert(__2nd_level_wrapper_##f != NULL); \
		\
		DEBUG_MSG(5, "wrapper: " #f "\n"); \
		overlord_should_call_through = 1; \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		ret = (*__2nd_level_wrapper_##f) U; \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		overlord_should_call_through = 0; \
	} else { \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		DEBUG_MSG(5, "wrapper (calling through): " #f "\n"); \
		ret = (*__liblog_2nd_level_wrapper_##f) U; \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
	} \
	va_end(args); \
	\
	CLEAR_STACK_FOOTPRINT(); \
	is_in_library--; \
	assert(is_in_library >= 0); \
	return ret; \
}

#define CALL_WRAPPER_NORET(f, U) { \
	/* Careful that this variable's name doesn't conflict with a 
	 * parameter name. */ \
	static int __liblog_is_timer_allocated = 0; \
	\
	is_in_library++; \
	\
	if (!__liblog_is_timer_allocated && _private_info.done_with_init) { \
		__LIBC_TIMER(f) = alloc_new_wrapper_timer("_" #f "_timer"); \
		__liblog_is_timer_allocated = 1; \
	} \
	\
	if (!overlord_should_call_through) { \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _cosched); \
		PRE_CALL_INIT(); \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _cosched); \
				\
		assert(__2nd_level_wrapper_##f != NULL); \
		\
		DEBUG_MSG(5, "wrapper: " #f "\n"); \
		overlord_should_call_through = 1; \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		(*__2nd_level_wrapper_##f) U; \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		overlord_should_call_through = 0; \
	} else { \
		DEBUG_MSG(5, "wrapper (calling through): " #f "\n"); \
		(*__LIBC_PTR(f)) U; \
	} \
	\
	CLEAR_STACK_FOOTPRINT(); \
	is_in_library--; \
	assert(is_in_library >= 0); \
}

#define CALL_WRAPPER_NORET_VARG(f, l, U) { \
	va_list args; \
	/* Careful that this variable's name doesn't conflict with a 
	 * parameter name. */ \
	static int __liblog_is_timer_allocated = 0; \
	\
	is_in_library++; \
	\
	if (!__liblog_is_timer_allocated && _private_info.done_with_init) { \
		__LIBC_TIMER(f) = alloc_new_wrapper_timer("_" #f "_timer"); \
		__liblog_is_timer_allocated = 1; \
	} \
	\
	va_start(args, l); \
	if (!overlord_should_call_through) { \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _cosched); \
		PRE_CALL_INIT(); \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _cosched); \
		\
		assert(__2nd_level_wrapper_##f != NULL); \
		\
		DEBUG_MSG(5, "wrapper: " #f "\n"); \
		overlord_should_call_through = 1; \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		/* See note above concerning variadic wrappers. */ \
		(*__2nd_level_wrapper_##f) U; \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		overlord_should_call_through = 0; \
	} else { \
		__START_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
		DEBUG_MSG(5, "wrapper (calling through): " #f "\n"); \
		(*__liblog_2nd_level_wrapper_##f) U; \
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(f), _wrapper); \
	} \
	va_end(args); \
	\
	CLEAR_STACK_FOOTPRINT(); \
	is_in_library--; \
	assert(is_in_library >= 0); \
}



/**************************************************************************
 **************************************************************************/



/* Define the 2nd level wrappers pointers. During logging, these point to the
 * log mode wrappers that are defined in the liblog/lwrap_* files. During replay,
 * these point to the replay mode wrappers that are defined in 
 * libreplay/rwrap_* files. */
#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) static T (*__2nd_level_wrapper_##f)(__VA_ARGS__); 
#define WRAPPERDEF_NORET(f, U, ...) static void (*__2nd_level_wrapper_##f)(__VA_ARGS__); 
#define WRAPPERDEF_VARG(T, f, l, U, ...) static T (*__2nd_level_wrapper_##f)(__VA_ARGS__, va_list ap); 
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) static void (*__2nd_level_wrapper_##f)(__VA_ARGS__, va_list ap); 
/* This include must come after the WRAPPERDEF() macros. */
#include "wrapperdefs.h"

/* Define the 2nd level liblog wrapper pointers. These should always point to
 * the wrappers in liblog/lwrap_*. We need them to invoke log-mode versions
 * of the wrappers during replay. Why? Because the log-mode versions
 * already have the machinery needed to handle call-through for variadic
 * libc wrappers. */
#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) static T (*__liblog_2nd_level_wrapper_##f)(__VA_ARGS__); 
#define WRAPPERDEF_NORET(f, U, ...) static void (*__liblog_2nd_level_wrapper_##f)(__VA_ARGS__); 
#define WRAPPERDEF_VARG(T, f, l, U, ...) static T (*__liblog_2nd_level_wrapper_##f)(__VA_ARGS__, va_list ap); 
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) static void (*__liblog_2nd_level_wrapper_##f)(__VA_ARGS__, va_list ap); 
/* This include must come after the WRAPPERDEF() macros. */
#include "wrapperdefs.h"


/**************************************************************************
 **************************************************************************/


/* IMPORTANT: pre_call_init() must be a function and not a macro,
 * since we need to zero out the portion of the stack that the
 * enclosing functionality uses. */
static void pre_call_init() {
	if (!_private_info.is_replay) {
		INIT_POINTERS();
		LOG_AND_DELIVER_QUEUED_SIGNALS();
		INVOKE_COSCHEDULER();
	} else {
	}
}

/* Initialize function pointers into replay wrappers. */
void HIDDEN init_replay_pointers() {
	void* rh;

	/* Load libreplay. */
	rh = dlopen("libreplay.so", RTLD_NOW);
	if (!rh) {
		fprintf(stderr, "%s\n", dlerror());
		exit(1);
	}

	DEBUG_MSG(2, "Using replay wrapper functions.\n");

#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) *(void **) (&__2nd_level_wrapper_##f) = my_dlsym(rh, "replay_" #f);
#define WRAPPERDEF_NORET(f, U, ...) *(void **) (&__2nd_level_wrapper_##f) = my_dlsym(rh, "replay_" #f);
#define WRAPPERDEF_VARG(T, f, l, U, ...) *(void **) (&__2nd_level_wrapper_##f) = my_dlsym(rh, "replay_" #f);
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) *(void **) (&__2nd_level_wrapper_##f) = my_dlsym(rh, "replay_" #f);
#include "wrapperdefs.h"

	return;
}

/* Initialize function pointers into logging or replay wrappers,
 * depending on what mode we are in right now. */
void HIDDEN init_logging_pointers() {

	/* Obtain pointers into library functions. */

	DEBUG_MSG(2, "Using log wrapper functions.\n");

#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) *(void **) (&__2nd_level_wrapper_##f) = log_##f;
#define WRAPPERDEF_NORET(f, U, ...) *(void **) (&__2nd_level_wrapper_##f) = log_##f;
#define WRAPPERDEF_VARG(T, f, l, U, ...) *(void **) (&__2nd_level_wrapper_##f) = log_##f;
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) *(void **) (&__2nd_level_wrapper_##f) = log_##f;
#include "wrapperdefs.h"

#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) *(void **) (&__liblog_2nd_level_wrapper_##f) = log_##f;
#define WRAPPERDEF_NORET(f, U, ...) *(void **) (&__liblog_2nd_level_wrapper_##f) = log_##f;
#define WRAPPERDEF_VARG(T, f, l, U, ...) *(void **) (&__liblog_2nd_level_wrapper_##f) = log_##f;
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) *(void **) (&__liblog_2nd_level_wrapper_##f) = log_##f;
#include "wrapperdefs.h"
	return;
}


/**************************************************************************
 **************************************************************************/

void* malloc(size_t size) {
	void* ret = NULL;
	static int c = 0;

	/* This wrapper is special--there is no need to log calls to
	 * malloc. However, we do need to zero out the memory
	 * returned by malloc to ensure that it is the same during
	 * logging and replay. This is important because applications
	 * often unintentionally make use of uninitialized buffers
	 * allocated on the heap. The data in these uninitialized
	 * buffers will differ during logging and replay, since the
	 * replay code may modify the heap (e.g., by invoking some
	 * libc function that makes a call to malloc()). Thus, this
	 * is necessary to provide deterministic replay. */

	if (is_in_library) {
		ret = tcalloc(1, size);
	} else {
		c++;
		DEBUG_MSG(6, "calling malloc #%d\n", c);
		assert(__LIBC_PTR(calloc) != NULL);
		assert(__LIBC_PTR(calloc) != &calloc);
		ret = __LIBC_PTR(calloc)(1, size);
	}

	DEBUG_MSG(6, "malloc ret=0x%x size=%d iil=%d\n", ret,
			size, is_in_library);

	errno = ret ? errno : ENOMEM;

	return ret;
}

void* realloc(void* ptr, size_t size) {
	void* ret = NULL;
	static int c = 0;

	if (is_in_library) {
		ret = trealloc(ptr, size);
	} else {
		c++;
		DEBUG_MSG(6, "calling realloc #%d\n", c);
		assert(__LIBC_PTR(realloc) != NULL);
		assert(__LIBC_PTR(realloc) != &realloc);
		ret = __LIBC_PTR(realloc)(ptr, size);
		/* TODO: Initialize realloc bytes. */
	}

	DEBUG_MSG(6, "realloc ret=0x%x ptr=0x%x size=%d iil=%d\n", ret,
			ptr, size, is_in_library);

	errno = ret ? errno : ENOMEM;

	return ret;
}

void* calloc(size_t nmemb, size_t size) {
	void* ret = NULL;
	static int c = 0;

	if (is_in_library) {
		ret = tcalloc(nmemb, size);
	} else {
		c++;
		DEBUG_MSG(6, "calling calloc #%d\n", c);
		assert(__LIBC_PTR(calloc) != NULL);
		assert(__LIBC_PTR(calloc) != &calloc);
		ret = __LIBC_PTR(calloc)(nmemb, size);
	}

	DEBUG_MSG(6, "calloc ret=0x%x nmemb=%d size=%d iil=%d\n", ret,
			nmemb, size, is_in_library);

	errno = ret ? errno : ENOMEM;

	return ret;
}

void free(void* ptr) {

	if (is_in_library || is_tblock(ptr) /* block allocated by tmalloc? */) {
		tfree(ptr);
	} else {
		DEBUG_MSG(6, "calling free ptr=0x%x iil=%d\n", ptr,
				is_in_library);
		assert(__LIBC_PTR(free) != NULL);
		assert(__LIBC_PTR(free) != &free);
		__LIBC_PTR(free)(ptr);
	}
}

/* The following are wrapper definitions for all the wrappers
 * listed in wrapperdefs.h. */
#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) \
	T f(__VA_ARGS__) { \
		CALL_WRAPPER(T, f, U); \
	}
#define WRAPPERDEF_NORET(f, U, ...) \
	void f(__VA_ARGS__) { \
		CALL_WRAPPER_NORET(f, U); \
	}
#define WRAPPERDEF_VARG(T, f, l, U, ...) \
	T f(__VA_ARGS__, ...) { \
		CALL_WRAPPER_VARG(T, f, l, U); \
	}
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) \
	void f(__VA_ARGS__, ...) {\
		CALL_WRAPPER_NORET_VARG(f, l, U); \
	}
#include "wrapperdefs.h"
