#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdlib.h>

typedef struct log_header {
	int64_t vclock;
} log_header_t;

typedef struct log_footer {
	int64_t vclock;
	char reason[256];
} log_footer_t;

extern int open_log(char* filename, int64_t vclock);
extern void close_log( int fd, int64_t vclock, char* reason);

#endif
