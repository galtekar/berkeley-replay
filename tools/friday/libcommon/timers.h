#ifndef TIMERS_H
#define TIMERS_H
#define __USE_LARGEFILE64

#include <stdarg.h>
#include <netdb.h>
#include <utime.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>

#define __LIBC_TIMER(f) __ll_libc_##f##_timer

#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) extern int __LIBC_TIMER(f);
#define WRAPPERDEF_NORET(f, U, ...) extern int __LIBC_TIMER(f);
#define WRAPPERDEF_VARG(T, f, l, U, ...) extern int __LIBC_TIMER(f);
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) extern int __LIBC_TIMER(f);

/* The include must come after the WRAPPERDEF() macros. */
#include "wrapperdefs.h"

#endif
