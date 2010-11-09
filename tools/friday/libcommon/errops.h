#ifndef ERROPS_H
#define ERROPS_H

extern void warning(const char* fmt, ...);
extern void fatal(const char* fmt, ...);
extern void lprintf(const char* fmt, ...);
extern void dprintf(const char* fmt, ...);
extern void quit(const char* fmt, ...);
extern void print_backtrace();
extern char* backtrace_str();

#endif
