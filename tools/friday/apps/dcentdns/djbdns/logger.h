#ifndef _LOGGER_H
#define _LOGGER_H
#ifdef __cplusplus
extern "C" {
#endif
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#define SILENT 4
#define NORMAL 2
#define VERBOSE 1
#define VVERBOSE -1
#define VVVERBOSE -2

#define FILE_LENGTH 256

FILE* init_log(int id,char* host, int port, int level);
void log_to_file(FILE* fptr,const char* temp,...);
void log_default(int level,char* temp,...);
void log_default_notime(int level,char *temp,...);
void log_default_dump(int level,char* dump, int size);
int get_log_level();

#ifdef __cplusplus
}
#endif
#endif
