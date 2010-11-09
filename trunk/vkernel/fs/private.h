#pragma once

#include "vkernel/public.h"


extern struct FileStruct*  File_GetUnlocked(uint vfd);
extern int                 File_GetUnusedFd();
extern void                File_PutUnusedFd(unsigned int fd);
extern void                File_FdInstall(uint vfd, struct FileStruct * file);
extern int                 File_Close(struct FileStruct *filp);

extern int      VFS_create(struct InodeStruct *dir, struct DentryStruct *dentryp, 
                       int mode, void *data);
extern ssize_t  VFS_io(int isRead, struct FileStruct *filp, struct msghdr *kmsgp, 
                        int flags, loff_t *pos);
extern int      VFS_chmod(struct DentryStruct *dentryp, mode_t mode);


extern int      VFS_access(struct DentryStruct *dentryp, int mode);

extern int    Epoll_OpUnlocked(struct FileStruct *efilp, int vfd, int rfd, int op, 
                               struct epoll_event *kevent);

#define FCNTL_OP_SET 1
#define FCNTL_OP_AND 2
#define FCNTL_OP_OR  4
extern int
Fcntl_FlagsOp(struct FileStruct *filp, ulong flags, int op);
extern void 
Fcntl_SetCloseOnExec(unsigned int fd, int flag);

static INLINE void
Fs_Lock(struct FileSysStruct *fs)
{
   ORDERED_LOCK(&fs->lock);
}

static INLINE void
Fs_Unlock(struct FileSysStruct *fs)
{
   ORDERED_UNLOCK(&fs->lock);
}

static INLINE int
Fs_IsLocked(struct FileSysStruct *fs)
{
   return ORDERED_IS_LOCKED(&fs->lock);
}
