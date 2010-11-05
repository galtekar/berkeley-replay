#pragma once

#include "vkernel/public.h"

#define IOF_SOCK  0x1

/* Inode ops. */
extern long ReadDet_fstat(int fd, struct kstat64 *stat);
extern long ReadDet_lstat(const char *path, struct kstat64 *stat);
extern long ReadDet_stat(const char *path, struct kstat64 *stat);
extern long ReadDet_statfs(const char *path, struct statfs64 *stat);
extern int  ReadDet_readlink(const char *path, char *buf, int bufsize);

extern int  ReadDet_lgetxattr(const char *path, char *kname, void *kvalue, 
                  size_t size);
extern int  ReadDet_lsetxattr(const char *path, char *kname, void *kvalue, size_t size, 
                  int flags);
extern int  ReadDet_llistxattr(const char *path, char *klist, size_t size);
extern int  ReadDet_lremovexattr(const char *path, char *kname);


extern int  ReadDet_chmod(const char *path, mode_t mode);
extern int  ReadDet_lchown(const char *path, uid_t uid, gid_t gid);
extern int  ReadDet_access(const char *path, int mode);
extern int  ReadDet_truncate64(const char * path, loff_t length);

extern int  ReadDet_link(const char *path1, const char *path2, int flags);
extern int  ReadDet_rename(const char *path1, const char *path2);
extern int  ReadDet_symlink(const char *path1, const char *path2);
extern int  ReadDet_unlink(const char *path);
extern int  ReadDet_mkdir(const char *path, int mode);
extern int  ReadDet_rmdir(const char *path);
extern int  ReadDet_mknod(const char *path, int mode, unsigned dev);
extern int  ReadDet_utimes(const char *path, struct timeval *ktimes);
extern int  ReadDet_chdir(const char *path);

/* File ops. */
extern int     ReadDet_open(const char *name, int flags, int mode);
extern int     ReadDet_setfl(int fd, int arg);
extern int     ReadDet_fsync(int fd, int datasync);
extern long    ReadDet_llseek(int fd, loff_t offset, int origin, loff_t *res);
extern int     ReadDet_readdir(int fd, void *buf, filldir_t filler, 
                  size_t size);
extern int     ReadDet_lock(int fd, uint cmd, void *l);
extern int     ReadDet_flock(int fd, uint cmd);
extern int     ReadDet_pipe(int *fds);
extern int     ReadDet_epoll_create(int size);
extern int     ReadDet_epoll_ctl(int epollFd, int fd, int op, 
                  struct epoll_event *kevent);
extern int     ReadDet_epoll_wait(struct EpollStruct *ep, 
                   struct epoll_event *kevents, int maxevents, int timeout);
extern int     ReadDet_io(const int ioReqFlags, const struct FileStruct *filP, const int fd, struct msghdr *kmsgp, int flags, int ioflags, loff_t pos);
extern int     ReadDet_ftruncate64(int fd, loff_t length);
extern int     ReadDet_eventfd2(unsigned int count_initval, int flags);
