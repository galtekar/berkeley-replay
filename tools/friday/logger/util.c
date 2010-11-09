#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/unistd.h>

//_syscall0(pid_t,gettid)


#define gettid() syscall(SYS_gettid)


void fatal(const char* fmt, ...) {
	va_list args;

	printf("fatal error: ");

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	exit(-1);
}

void logger_printf(const char* fmt, ...) {
	va_list args;

	printf("[logger-%d]: ", gettid());

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	fflush( stdout );
}
