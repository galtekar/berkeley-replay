#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#define __USE_GNU
#include <dlfcn.h>
#include <assert.h>
#include <errno.h>
#include <syscall.h>
#include <signal.h>
#include <dirent.h>

#define __USE_LARGEFILE64
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <grp.h>

#include "logreplay.h"
#include "misc.h"
#include "dllops.h"
#include "errops.h"
#include "gcc.h"

#include "libc_pointers.h"

#define DEBUG 1
#include "debug.h"

HIDDEN void* (*__LIBC_PTR(calloc))(size_t nmemb, size_t size);
HIDDEN void* (*__LIBC_PTR(realloc))(void* ptr, size_t size);
HIDDEN void (*__LIBC_PTR(free))(void *ptr);

#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) HIDDEN T (*__LIBC_PTR(f))(__VA_ARGS__);
#define WRAPPERDEF_NORET(f, U, ...) HIDDEN void (*__LIBC_PTR(f))(__VA_ARGS__);
#define WRAPPERDEF_VARG(T, f, l, U, ...) HIDDEN T (*__LIBC_PTR(f))(__VA_ARGS__, ...);
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) HIDDEN void (*__LIBC_PTR(f))(__VA_ARGS__, ...);
/* This include must come after the WRAPPERDEF() macros. */
#include "wrapperdefs.h"


/*
 * Initialize the function pointers into libc functions.
 */
void HIDDEN init_libc_pointers() {
	/* WARNING: do not use any pointer until you call
	 * dlsym() on it and get a valid pointer in a libc
	 * function. */

	static int count = 0;

	count++;

	DEBUG_MSG(5, "Called init_libc_pointers for time #%d.\n", count );
	if (count > 1) {
	  return;
	}

	*(void **) (&__LIBC_PTR(calloc)) = my_dlsym(RTLD_NEXT, "calloc");
	assert(__LIBC_PTR(calloc) != NULL);
	*(void **) (&__LIBC_PTR(realloc)) = my_dlsym(RTLD_NEXT, "realloc");
	assert(__LIBC_PTR(realloc) != NULL);
	*(void **) (&__LIBC_PTR(free)) = my_dlsym(RTLD_NEXT, "free");
	assert(__LIBC_PTR(free) != NULL);

#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) { \
	DEBUG_MSG(6, "Obtaining libc pointer for " #f ".\n"); \
	*(void **) (&__LIBC_PTR(f)) = my_dlsym(RTLD_NEXT, #f); \
	assert(__LIBC_PTR(f) != NULL); \
}
#define WRAPPERDEF_NORET(f, U, ...) { \
	DEBUG_MSG(6, "Obtaining libc pointer for " #f ".\n"); \
	*(void **) (&__LIBC_PTR(f)) = my_dlsym(RTLD_NEXT, #f); \
	assert(__LIBC_PTR(f) != NULL); \
}

#define WRAPPERDEF_VARG(T, f, U, ...) { \
	DEBUG_MSG(6, "Obtaining libc pointer for " #f ".\n"); \
	*(void **) (&__LIBC_PTR(f)) = my_dlsym(RTLD_NEXT, #f); \
	assert(__LIBC_PTR(f) != NULL); \
}

#define WRAPPERDEF_NORET_VARG(f, U, ...) { \
	DEBUG_MSG(6, "Obtaining libc pointer for " #f ".\n"); \
	*(void **) (&__LIBC_PTR(f)) = my_dlsym(RTLD_NEXT, #f); \
	assert(__LIBC_PTR(f) != NULL); \
}
#include "wrapperdefs.h"

	DEBUG_MSG(5, "Done initializing libc pointers.\n");
	return;
}

void HIDDEN verify_libc_pointers() {
#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) { \
	assert(__LIBC_PTR(f) != NULL); \
}
#define WRAPPERDEF_NORET(f, U, ...) { \
	assert(__LIBC_PTR(f) != NULL); \
}

#define WRAPPERDEF_VARG(T, f, U, ...) { \
	assert(__LIBC_PTR(f) != NULL); \
}

#define WRAPPERDEF_NORET_VARG(f, U, ...) { \
	assert(__LIBC_PTR(f) != NULL); \
}
#include "wrapperdefs.h"

	DEBUG_MSG(5, "Done verifying libc pointers.\n");
	return;
}
