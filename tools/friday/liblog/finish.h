#ifndef FINISH_H
#define FINISH_H

/* This needs to be extern since lwrap_misc.c:log_exec will
 * invoke it before performing an exec. */
extern void liblog_finish();

#endif
