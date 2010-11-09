#ifndef LWRAP_H
#define LWRAP_H
#define __USE_LARGEFILE64

#include <stdarg.h>
#include <netdb.h>
#include <utime.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>

#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) extern T log_##f(__VA_ARGS__); 
#define WRAPPERDEF_NORET(f, U, ...) extern void log_##f(__VA_ARGS__); 
#define WRAPPERDEF_VARG(T, f, l, U, ...) extern T log_##f(__VA_ARGS__, va_list ap); 
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) extern void log_##f(__VA_ARGS__, va_list ap); 

/* The include must come after the WRAPPERDEF() macros. */
#include "wrapperdefs.h"

#endif
