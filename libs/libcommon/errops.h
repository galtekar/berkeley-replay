#pragma once 

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>


#define MAX_ERRNO	4095

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
static inline void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline long IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}


extern pid_t   gettid();
#if USING_DIET_LIBC
extern int     vdprintf(int fd, const char *format, va_list arg_ptr);
#endif
extern int    vlprintf(int fd, const char *fmt, va_list args);
extern int    lprintf(int fd, const char* fmt, ...);
extern void    eprintf(const char* fmt, ...);
extern void    print_backtrace();
extern char*   backtrace_str();
extern void    PrintOps_snprintf(char *buf, size_t bufsz, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
