#ifndef LIBC_POINTERS
#define LIBC_POINTERS

#include <stdarg.h>
#include <netdb.h>
#include <grp.h>
#include <unistd.h>
#include <dirent.h>
#include <utime.h>

#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/poll.h>


#include "logreplay.h"

#define __USE_LARGEFILE64
#include <sys/stat.h>

#define VERIFY_LIBC_POINTERS() verify_libc_pointers()

extern void init_libc_pointers();
extern void verify_libc_pointers();

extern void* (*__LIBC_PTR(calloc))(size_t nmemb, size_t size);
extern void* (*__LIBC_PTR(realloc))(void* ptr, size_t size);
extern void (*__LIBC_PTR(free))(void *ptr);

#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) extern T (*__LIBC_PTR(f))(__VA_ARGS__); 
#define WRAPPERDEF_NORET(f, U, ...) extern void (*__LIBC_PTR(f))(__VA_ARGS__); 
#define WRAPPERDEF_VARG(T, f, l, U, ...) extern T (*__LIBC_PTR(f))(__VA_ARGS__, ...); 
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) extern void (*__LIBC_PTR(f))(__VA_ARGS__, ...); 

/* The include must come after the WRAPPERDEF() macro. */
#include "wrapperdefs.h"

#endif
