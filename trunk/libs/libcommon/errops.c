#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>

#include <sys/types.h>

#include "syscall.h"
#include "errops.h"
#include "fdops.h"
#include "debug.h"

#define __STDERR 2

#if !USING_DIET_LIBC
pid_t gettid() {
	return syscall(SYS_gettid);
}
#endif

#if USING_DIET_LIBC
/* From dietstdio.h */
struct arg_printf {
  void *data;
  int (*put)(void*,size_t,void*);
};
int __v_printf(struct arg_printf* fn, const char *format, va_list arg_ptr);

static int
fd_write(void *str, size_t nmemb, int fd)
{
   return write(fd, str, nmemb);
}

int 
vdprintf(int fd, const char *format, va_list arg_ptr)
{
   struct arg_printf ap = { (void *) fd, 
      (int (*) (void*, size_t, void*)) fd_write };

   return __v_printf(&ap, format, arg_ptr);
}
#endif

int
vlprintf(int fd, const char *fmt, va_list args)
{
   int res;

   /* Print to stderr by default. */
   if (fd < 0) {
      fd = __STDERR;
   }

	res = vdprintf(fd, fmt, args);

   if (res < 0) {
      printf("can't write to debug log fd %d\n", fd);
      exit(-1);
   }

   return res;
}

int
lprintf(int fd, const char* fmt, ...) 
{
   int res;
	va_list args;

	va_start(args, fmt);
	res = vlprintf(fd, fmt, args);
	va_end(args);

   return res;
}

void
eprintf(const char* fmt, ...) 
{
	va_list args;

   lprintf(__STDERR, "dcr: ");
	va_start(args, fmt);
	vlprintf(__STDERR, fmt, args);
	va_end(args);
}

void
PrintOps_snprintf(char *buf, size_t bufsz, const char *fmt, ...)
{
   int res;
	va_list args;

	va_start(args, fmt);
	res = vsnprintf(buf, bufsz, fmt, args);
   ASSERT(res > -1 && res < bufsz);
	va_end(args);
}
