#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <sys/stat.h>

#include "debug.h"


int fd2path(int fd, char* buf, int bufsiz) {
	char fdstr[128];
	int ret;

	ASSERT(buf);

	snprintf(fdstr, sizeof(fdstr), "/proc/self/fd/%d", fd);

	/* readlink() does not append a NUL to the end of the result! */
	ret = readlink(fdstr, buf, bufsiz-1);

	ASSERT(ret > 0);

	buf[ret] = 0;

	return ret;
}

dev_t fd2dev(int fd) {
	struct stat buf;

	if (fstat(fd, &buf) == 0) {
		return buf.st_dev;
	}

	/* BUG?: Is this an appropriate error code? */
	ASSERT(0);
	return -1;
}

ino_t fd2inode(int fd) {
	struct stat buf;

	if (fstat(fd, &buf) == 0) {
		return buf.st_ino;
	}

	/* BUG?: Is this an appropriate error code? */
	ASSERT(0);
	return -1;
}
