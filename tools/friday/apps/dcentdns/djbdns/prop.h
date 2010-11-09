/* Copyright 2004 Princeton University */

#ifndef _PROPER_PROP_H_
#define _PROPER_PROP_H_

#include <sys/socket.h>

int
prop_mount_dir(const char *domain,
	       const char *dir,
	       const char *mntpoint,
	       unsigned flags);

#define PROP_MOUNT_GETDIR  0
#define PROP_MOUNT_PUTDIR  1
#define PROP_MOUNT_RDONLY  2

int
prop_get_file_flags(const char *filename);

#define PROP_FILE_NOCHANGE  1
#define PROP_FILE_NOUNLINK  2

int
prop_set_file_flags(const char *filename, unsigned flags);

int
prop_open_file(const char *filename, unsigned flags);

#define PROP_OPEN_READ   1

int
prop_execv(const int *iofd,
	   const char *user,
	   const char **cmd);

/*
 * On Linux and OS X status is 16-bits, so we can just add a bit to
 * indicate whether the child is still live.
 */
#define PROP_CHILD_LIVE    0x40000000

int
prop_create_socket(int family, int type, int proto,
		   const struct sockaddr *sa, socklen_t salen);

#define PF_VALMASK  0xFF  /* must be >= PF_MAX and of the form (2^n - 1) */

int
prop_bind_socket(int sock, struct sockaddr *sa, socklen_t salen);



int
prop_send_op(const char *op, const char *argfmt, ...);

/* curl uses its own set of error codes, need to unify them with errno */
#define PROP_ERRNO_CURLBASE  1000

const char *
prop_errmsg(void);

#endif
