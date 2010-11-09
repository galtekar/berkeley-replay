/**
 * Copyright (c) 2004 Regents of the University of California.  All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. Neither the name of the University nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * author:	Dennis Geels
 * $Id: log.h,v 1.14 2006/05/01 08:17:27 galtekar Exp $
 *
 * event_log.h: Main header file for my event logging/replay system.
 */
#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <string.h>
#include <inttypes.h>	// uint64_t
#include <limits.h>	// PATH_MAX
#include <sys/time.h>	// struct timeval, timezone, gettimeofday
#include <sys/socket.h>	// struct sockaddr
#include <netinet/in.h>	// in_addr_t, in_port_t

#include "logreplay.h"

#define POST_WRAPPER_CLEANUP() { \
	/* Restore the errno value to what it was right after we
	 * made the library call. We do this because we may have
	 * trampled errno within the wrapper, after we made the
	 * library call. */ \
	errno = _my_tinfo->e_val; \
	ROTATE_LOG_IF_TIME(); \
}

#define ROTATE_LOG_IF_TIME() { \
	__START_CKPT_TIMER(_rotate_log_if_time); \
	rotate_log_if_time(); \
	__STOP_CKPT_TIMER(_rotate_log_if_time); \
}

#define LOG(format, ...) buf_to_shmem(format, __VA_ARGS__)


/* Writes log entreis to shared memory, rather than use sockets. */
extern int buf_to_shmem(const char* format, ...);

/* Advances _pinfo->vclock (logging only) */
extern void advance_vclock();

/* Register with the logger process and do some rudimentary initialization. */
extern void start_logging();

/* Rotate the log it is time to do so. */
extern void rotate_log_if_time();

/* Writes a checkpoint file with a VCLOCK as part of the filename. 
 * Return 1 during recovery and 0 otherwise. */
extern int liblog_drop_checkpoint( uint64_t vclock );

/* Writes an errno log entry. This is invoked by the __CALL_LIBC macro
 * and family. */
extern void write_errno_log_entry();

#endif
