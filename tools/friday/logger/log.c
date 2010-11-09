#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>

#define __USE_LARGEFILE64
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "util.h"
#include "log.h"
#include "fdops.h"


/* Opens a new log for reading or writing, depending on the
 * logger_mode.  Will also write/read two-line log header.*/
int open_log(char* filename, int64_t vclock) {
   int fd;
	log_header_t h;

   if ((fd = open(filename, O_EXCL | O_CREAT | O_WRONLY | O_LARGEFILE, 0600)) < 0) {
		perror("open");
      fatal("could not open log file \"%s\"\n", filename);
   }

	h.vclock = vclock;

   safe_write(fd, &h, sizeof(h));

   return fd;
}

/* Closes the log, possibly writing a short footer */
void close_log( int fd, int64_t vclock, char* reason) {
	log_footer_t f;

	f.vclock = vclock;
	strncpy(f.reason, reason, sizeof(f.reason));

   safe_write(fd, &f, sizeof(f));

   /* 
    * Debian doesn't support fsync...?
    * fsync(fileno(fp)); */
   if (close(fd) < 0) {
		perror("close");
	}
}
