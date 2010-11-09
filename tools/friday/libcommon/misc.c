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
 * $Id: misc.c,v 1.23 2006/04/21 11:35:24 galtekar Exp $
 *
 * common.c
 *
 * Logging/replay globals, utility methods, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <limits.h> /* for PATH_MAX */
#include <assert.h>
#include <dlfcn.h>
#include <syscall.h>
#include <unistd.h>
#include <inttypes.h>

#include "libc_pointers.h"
#include "logreplay.h"
#include "errops.h"
#include "gcc.h"
#include "misc.h"

#define DEBUG 0


/* We only need this for replay, but it has to be compiled into
   liblog.so, too. */
void HIDDEN hook_for_gdb( liblog_hook_code code, void * datum ) {
  	if( DEBUG ) lprintf( "hook_for_gdb(%d,%p)\n", code, datum );
	assert( (code >= LL_HOOK_WRAPPER_TRAP) );
	return;
}

/* Look at /proc/self/cmdline to get the name of the binary that
 * was originally invoked. That name is the prefix string. */
void HIDDEN get_prefix_str(char* prefix_str) {
	FILE *fp;
	char tmp_str[PATH_MAX];
	char *name_ptr;

	if (!(fp = (*__LIBC_PTR(fopen))("/proc/self/cmdline", "r"))) {
		fatal("can't open /proc/self/cmdline\n");
	}

	/* We are only interested in the 1st parameter (i.e., the name of
	 * the binary). */
	(*__LIBC_PTR(fscanf))(fp, "%s", tmp_str);
	(*__LIBC_PTR(fclose))(fp);

	/* Scan backwards from the end, looking for a '/'. */
	name_ptr = strrchr(tmp_str, '/');
	//assert(name_ptr != NULL);
	//
	/* We don't want the '/' in the final string. */
	if (name_ptr) {
	name_ptr++;
	} else {
		name_ptr = tmp_str;
	}

	strcpy(prefix_str, name_ptr);
}

/* Constructs the name of a checkpoint file. You must append a ``.ckpt'',
 * ``.log.gz'', or whatever to the end if before using it, if you want
 * to avoid conflicts. filename is where the base filename will be
 * stored and size is the size of the available storage space for
 * the name. */
void HIDDEN construct_ckpt_filename_base(char* path, char* prefix, char* tag,
	int orig_pid, int orig_pgid, uint64_t epoch, uint64_t vclock, char* filename, int size) {

	snprintf(filename, size, "%s/%s.%s.%d.%d.%llu.%llu", path,
			prefix, tag, orig_pid, orig_pgid, epoch, vclock);

	return;
}

/* Unlike the name of a checkpoint file, the name of log file only
 * requires that the process group id be in the name. This is because
 * all processes in the process group share the same log. */
void HIDDEN construct_log_filename_base(char* path, char* prefix, char* tag,
	int orig_pgid, uint64_t epoch, uint64_t vclock, char* filename, int size) {

	snprintf(filename, size, "%s/%s.%s.%d.%llu.%llu", path,
		prefix, tag, orig_pgid, epoch, vclock);

	return;
}

/* Even simpler than the log filename.  We assume the library does not
   change while the application is running, so binding this version to
   our epoch (and not ckpt vclock) is sufficient. */
void HIDDEN construct_lib_filename_base(char* path, char* prefix, char* tag,
	int orig_pgid, uint64_t epoch, char* filename, int size) {

	snprintf(filename, size, "%s/%s.%s.%d.%llu", path,
		prefix, tag, orig_pgid, epoch);

	return;
}

void HIDDEN clear_stack_footprint() {
	char buf[8192];
	int i = 0;

	for (i = 0; i < sizeof(buf); i++) {
		buf[i] = 0;
	}	

	return;
}
