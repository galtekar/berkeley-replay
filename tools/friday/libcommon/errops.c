#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <execinfo.h>

#include <sys/syscall.h>
#include <sys/types.h>

#include <linux/unistd.h>

#include "logreplay.h"
#include "libc_pointers.h"
#include "gcc.h"

#define gettid() syscall(SYS_gettid)


void HIDDEN warning(const char* fmt, ...) {
	va_list args;

	(*__LIBC_PTR(fprintf))(stderr, "warning: ");

	va_start(args, fmt);
	(*__LIBC_PTR(vfprintf))(stderr, fmt, args);
	va_end(args);
}

char* HIDDEN backtrace_str() {
	void *addresses[10];
	char **strings;
	int c, i, r;
	static char bt_str[4096];
	char* bt_p = bt_str;

	c = backtrace(addresses, 10);

	strings = backtrace_symbols(addresses, c);

	for (i = 0; i < c; i++) {
		//bt_p += sprintf(bt_p, "%d: [0x%8.8x] ", i, (int)addresses[i]) + 1;
		r = sprintf(bt_p, "%s\n", strings[i]);
		bt_p += r;
	}

	return bt_str;
}

void HIDDEN print_backtrace() {
	void *addresses[10];
	char **strings;
	int c, i;

	c = backtrace(addresses, 10);

	strings = backtrace_symbols(addresses, c);

	printf("Backtrace:\n");
	for (i = 0; i < c; i++) {
		printf("%d: [0x%8.8x] ", i, (int)addresses[i]);
		printf("%s\n", strings[i]);
	}
}

void HIDDEN NORETURN fatal(const char* fmt, ...) {
	va_list args;
	void *addresses[10];
	char **strings;
	int c, i;

	printf("fatal [%d]: ", gettid());

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	c = backtrace(addresses, 10);

	strings = backtrace_symbols(addresses, c);

	printf("Backtrace:\n");
	for (i = 0; i < c; i++) {
		printf("%d: [0x%8.8x] ", i, (int)addresses[i]);
		printf("%s\n", strings[i]);
	}

	syscall(SYS_signal, SIGINT, SIG_DFL);
	syscall(SYS_signal, SIGQUIT, SIG_DFL);

	printf("Attach using GDB or hit Ctrl+C to exit.");

	while (1) {
		sleep(3600);
	}

	/* By making a direct system call, we avoid running the destructors,
	 * which in turn prevents cascading segfaults. */
	syscall(SYS_exit);
}

/* Liblog printf. */
void HIDDEN lprintf(const char* fmt, ...) {
	va_list args;

	printf("<%ld>: ", gettid());

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

/* Debug printf. */
void HIDDEN dprintf(const char* fmt, ...) {
	va_list args;

	printf("[(%d)]: ", gettid());

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void HIDDEN quit(const char* fmt, ...) {
	va_list args;

	printf("<%d>: execution stopped: ", gettid());

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}
