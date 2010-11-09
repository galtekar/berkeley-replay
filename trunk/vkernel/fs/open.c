// vim:ts=3:sw=3:expandtab

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <utime.h>

#include "vkernel/public.h"
#include "private.h"

#if 0
static int
FileUserMaskOp(int isSet, int mask)
{
   int oldMask;

   Fs_Lock(current->fs);

	oldMask = current->fs->umask;
  
   if (isSet) {
      int res;

      current->fs->umask = mask & S_IRWXUGO;

      res = syscall(SYS_umask, mask);
      ASSERT(res == oldMask);
   }

   Fs_Unlock(current->fs);

	return oldMask;
}
#endif

struct AnnNode {
   ulong dev, ino;

   ChannelKind kind;
   struct ListHead list;
};

static SHAREDAREA LIST_HEAD(annList);
SYNCH_DECL_INIT(static SHAREDAREA, annListLock);

static struct AnnNode *
FileFindAnnotation(ulong dev, ulong ino)
{
   struct AnnNode *nP;

   list_for_each_entry(nP, &annList, list) {
      if (nP->dev == dev && nP->ino == ino) {
         DEBUG_MSG(5, "found!\n");
         ASSERT(nP->kind == Chk_Data || nP->kind == Chk_Control);
         return nP;
      }
   }

   return NULL;
}

void
File_MarkFileByIno(VkPlaneTag kind, ulong dev, ulong ino)
{
   struct AnnNode *nP;

   DEBUG_MSG(5, "kind=%d dev=%d ino=%d\n", kind, dev, ino);

   SYNCH_LOCK(&annListLock);

   if ((nP = FileFindAnnotation(dev, ino))) {
      if (kind == VK_PLANE_UNKNOWN) { 
         /* remove the annotation */
         List_Del(&nP->list);
         free(nP); nP = NULL;
      } else if (kind == VK_PLANE_CONTROL) {
         nP->kind = Chk_Control;
      } else if (kind == VK_PLANE_DATA) {
         nP->kind = Chk_Data;
      } else {
         LOG("Invalid annotation kind parameter");
         ASSERT(0);
      }
   } else {
      if (kind == VK_PLANE_CONTROL ||
          kind == VK_PLANE_DATA) {
         nP = malloc(sizeof(*nP));
         nP->dev = dev;
         nP->ino = ino;
         nP->kind = (kind == VK_PLANE_CONTROL) ? Chk_Control : Chk_Data;
         List_Add(&nP->list, &annList);
      } else {
         LOG("Invalid annotation kind parameter");
         ASSERT(0);
      }
   }

   SYNCH_UNLOCK(&annListLock);
}

void
File_MarkFileByFd(int fd, VkPlaneTag tag)
{
   struct FileStruct *filp = File_Get(fd);

   if (IS_ERR(filp)) {
      goto out;
   }

   ASSERT_KPTR(filp);

   switch (tag) {
   case VK_PLANE_CONTROL:
      filp->channel_kind = Chk_Control;
      break;
   case VK_PLANE_DATA:
      filp->channel_kind = Chk_Data;
      break;
   case VK_PLANE_UNKNOWN:
      filp->channel_kind = Chk_Unknown;
      break;
   default:
      break;
   }

   File_Put(filp);
out:
   return;
}

static void
FileSetChannelKind(struct FileStruct *filP)
{
   struct AnnNode *nP;
   struct InodeStruct *inoP = File_Inode(filP);
   ulong ino = Inode_Ino(inoP);
   dev_t dev = Inode_Dev(inoP);

   DEBUG_MSG(5, "dev=%d ino=%d\n", dev, ino);
   if ((nP = FileFindAnnotation(dev, ino))) {
      DEBUG_MSG(5, "kind=%x\n", nP->kind);
      filP->channel_kind = nP->kind;
   } else {
      filP->channel_kind = Chk_Unknown;
   }
}


static struct FileStruct*
FileAlloc()
{
   struct FileStruct *filp;

   filp = SharedArea_Malloc(sizeof(*filp));
   memset(filp, 0, sizeof(*filp));

   ORDERED_LOCK_INIT(&filp->lock, "file");
   List_Init(&filp->epoll_item_list);

   filp->rfd = -1;

   return filp;
}

static void
FileFree(struct FileStruct *filp)
{
   SharedArea_Free(filp, sizeof(*filp));
}

struct FileStruct*
File_GetUnlocked(uint vfd)
{
   struct FileStruct *file;
   struct FilesStruct *files = current->files;

   ASSERT(Files_IsLocked(files));

   DEBUG_MSG(5, "vfd=%d\n", vfd);

   file = Files_LookupUnlocked(files, vfd);

   if (file) {
      ASSERT(file->dentry);

      DEBUG_MSG(5, "name=%s\n", file->dentry->name);

      File_GetFile(file);
      ASSERT(file->dentry);
   } else {
      DEBUG_MSG(5, "didn't find vfd %d\n", vfd);
   }

   return file;
}

struct FileStruct*
File_Get(uint vfd)
{
   struct FileStruct *file;
   struct FilesStruct *files = current->files;

   Files_Lock(files);

   file = File_GetUnlocked(vfd);

   Files_Unlock(files);

   return file;
}

static void
FilePut(struct FileStruct *filp)
{
   Module_OnFileEvent(VK_EVENT_FILE_PUT, filp);

   /* 
    * Since this file is being closed, we have to remove this file from 
    * all epoll sets, as demanded by Linux epoll semantics.
    *
    * XXX: because we release the epoll element when the file object
    * is closed, and not when the vfd is closed, it's possible that
    * sys_epoll_wait will report events for any dup()ed and then
    * closed vfds that correspond to this file object.
    *
    * This appears to be a problem in the Linux epoll implementation
    * as well.
    *
    */
   D__;
   Epoll_Release(filp);

   D__;

   /* Release any backing state. If we're dealing with a
    * pipe inode, for instance, we need to close the backing fd 
    * so that the other end of the pipe will receive an EOF. This
    * can't be done when the inode is destroyed, since that may
    * only happen if the other side receives an EOF. */
   if (filp->f_op->release) {
      DEBUG_MSG(5, "closing rfd=%d\n", filp->rfd);
      filp->f_op->release(filp);
   }

   DEBUG_MSG(5, "deallocating file: rfd=%d\n", filp->rfd);

   ASSERT(filp->dentry);

   Dentry_Put(filp->dentry);
   filp->dentry = NULL;

   FileFree(filp);
   filp = NULL;
}

void
File_Put(struct FileStruct *filp)
{
   int isUnused = 0;

   ASSERT(filp);

   /* XXX: what we really need here is an ordered version
    * of atomic_dec_and_test(&filp->count); */

   File_Lock(filp);

   ASSERT(filp->count > 0);
   filp->count--;
   isUnused = (filp->count == 0);
   DEBUG_MSG(5, "name=%s count=%d\n", File_Dentry(filp)->name, filp->count);

   File_Unlock(filp);

   D__;

   if (isUnused) {
      FilePut(filp);
   }
}

static void
FileFdInstallUnlocked(uint vfd, struct FileStruct *file)
{
   struct FilesStruct *files = current->files;
   struct FdTableStruct *fdt = files->fdt;

   ASSERT(Files_IsLocked(files));

   ASSERT_UNIMPLEMENTED(vfd < fdt->maxFds);
   ASSERT(fdt->vfdTable[vfd] == NULL);

   fdt->vfdTable[vfd] = file;
}


void
File_FdInstall(uint vfd, struct FileStruct * file)
{
   struct FilesStruct *files = current->files;

   Files_Lock(files);

   FileFdInstallUnlocked(vfd, file);

   Files_Unlock(files);
}


static int
FileGetUnusedFdUnlocked()
{
   struct FilesStruct *files = current->files;
   struct FdTableStruct *fdt = files->fdt;
   int err, vfd;

   ASSERT(Files_IsLocked(files));
   ASSERT(sizeof(fdt->openFds->fds_bits) == __FDSET_LONGS*sizeof(ulong));
   ASSERT(sizeof(fdt->openFds->fds_bits) == sizeof(fd_set));
   ASSERT(FD_SETSIZE == __FDSET_LONGS*NFDBITS);

   /* Note that Bit_ routines return bitsetsize+1 for
    * "not found" */
   vfd = Bit_FindNextZeroBit(fdt->openFds->fds_bits, sizeof(fd_set), 
         files->nextFd);

   /* XXX: we need to expand the bit sets and fd table
    * when this fires. */
   ASSERT_UNIMPLEMENTED(vfd < FD_SETSIZE);

   /*
    * XXX: check against the rlimit
    */
   WARN_XXX(0);

   FD_SET(vfd, fdt->openFds);
   FD_CLR(vfd, fdt->closeOnExec); /* default: don't close */
   files->nextFd = vfd + 1;

   err = vfd;

   return err;
}

int
File_GetUnusedFd()
{
   struct FilesStruct *files = current->files;
   int err;

   Files_Lock(files);

   err = FileGetUnusedFdUnlocked();

   Files_Unlock(files);

   return err;
}

static void
FilePutUnusedFdUnlocked(unsigned int vfd)
{
   struct FilesStruct *files = current->files;
   struct FdTableStruct *fdt = files->fdt;

   ASSERT(Files_IsLocked(files));

   ASSERT(FD_ISSET(vfd, fdt->openFds));

	FD_CLR(vfd, fdt->openFds);
   FD_CLR(vfd, fdt->closeOnExec);
	if (vfd < files->nextFd) {
		files->nextFd = vfd;
   }

   fdt->vfdTable[vfd] = NULL;
}

void
File_PutUnusedFd(unsigned int vfd)
{
   struct FilesStruct *files = current->files;

   Files_Lock(files);

   FilePutUnusedFdUnlocked(vfd);

   Files_Unlock(files);
}

int
File_Close(struct FileStruct *filp)
{
   int err = 0;

   Module_OnFileEvent(VK_EVENT_FILE_CLOSE, filp);

   File_Put(filp);

   return err;
}

struct FileStruct *
File_DentryOpen(struct DentryStruct *dentryp, int flags, int mode)
{
   int err;
   struct InodeStruct *inodp = dentryp->inode;
   struct FileStruct *filp;

   /* No need to lock file since it isn't installed in the
    * fd table yet, and thus no one else can see it/access it. */
   filp = FileAlloc();
   if (!filp) {
      err = -ENOMEM;
      goto out;
   }

   filp->count = 1;
   filp->dentry = Dentry_Get(dentryp);
   ASSERT(inodp->f_op);
   filp->f_op = inodp->f_op;
   filp->accMode = (flags+1) & O_ACCMODE;
   filp->flags = flags;
   filp->pos = 0;

   ASSERT(Inode_IsLocked(dentryp->parent->inode));

   /* XXX: Holding the parent lock while blocking in Linux
    * can result is at least 2 deadlock situations:
    *
    * 1. Effective deadlock when file leases
    * come in to play. Lease holder may try and open file before
    * relinquishing the lease, at which point it will try and
    * lock the parent and hang -- until the OS timeout and
    * forces the holder to release the lease. But this timeout
    * can be several seconds long, during which nothing can
    * happen on the file-system. 
    *
    * Open all files in non-blocking mode. If open returns -EAGAIN,
    * and if !(filp->flags & O_NONBLOCK), then Schedule and try again.
    * By relinquishing the parent lock in between retries, we allow
    * other tasks to perform file operations and hence avoid deadlock.
    *
    * 2. Deadlock when dealing with named pipes (FIFOs). 
    * In nonblocking mode, the open below will block until
    * the other end of the pipe is opened. But for that to
    * happen, another task must call sys_open and hence
    * eventually acquire the parent lock. 
    *
    * Relinquish lock, put yourself in wait queue. Other end
    * will wake you upon entrance
    *
    * */

   /* 
    * For mounted files, the open can fail for many reasons,
    * some of which are:
    *    o task doesn't have permissions
    *    o task exceed the max fd num
    *    o Linux kernel runs out of mem
    *    o open not possible on inode (e.g., SOCK inode)
    */
   ASSERT_PTR(filp->f_op);
   if (filp->f_op->open) {
      err = filp->f_op->open(filp, mode);
      DEBUG_MSG(5, "err=%d mode=0x%x\n", err, mode);
      if (err < 0) {
         goto error_out;
      }

      ASSERT(filp->orig_rfd >= 0);
      if (VCPU_IsReplaying()) {
         /* mmap() needs some files to have valid linux fds,
          * XXX: but not all such files will get them (since
          * they may not be around during replay) */
         ASSERT(filp->rfd < 0 || filp->rfd >= 0);
      } else {
         ASSERT(filp->rfd == filp->orig_rfd);
      }
   } else {
      /* For example, shmem files. */
   }

   FileSetChannelKind(filp);

   Module_OnFileEvent(VK_EVENT_FILE_OPEN, filp);
   // XXX: get rid of this hack and use Module_OnFileEvent
   ModRecord_OnFileOpen(filp);

   goto out;

error_out:
   Dentry_Put(filp->dentry);
   FileFree(filp);
   filp = ERR_PTR(err);
out:
   return filp;
}

struct FileStruct *
File_Open(int dfd, const char *path, int flags, int mode, int should_follow)
{
   int err;
   struct FileStruct *filp;
   struct PathStruct ps;

   DEBUG_MSG(5, "dfd=%d path=%s flags=0x%x mode=0x%x\n", dfd, path, flags, mode);

   err = Path_Open(dfd, path, flags, mode | S_IFREG, should_follow, &ps);
   if (err) {
      filp = ERR_PTR(err); 
      D__;
      goto out;
   }

   ASSERT(ps.dentry->inode);
   ASSERT(ps.dentry->inode->i_op);
   ASSERT(ps.dentry->inode->f_op);

   filp = File_DentryOpen(ps.dentry, flags, mode);

   Path_Release(&ps);

out:
   return filp;
}

/*
 * Called directly from user-space by sys_open, and also indirectly
 * from kernel-space via execve() -- for loading in the program
 * executable. 
 *
 */
int
File_OpenFd(int dfd, const char *path, int flags, int mode, int should_follow)
{
   struct FileStruct *filp = NULL;
   int err, vfd;
   //int __umask;

   ASSERT_KPTR(path);

#if 0
   __umask = FileUserMaskOp(0, 0);
   mode &= ~__umask;
#endif

   filp = File_Open(dfd, path, flags, mode, should_follow);

   DEBUG_MSG(5, "filp=0x%x\n", filp);

   if (IS_ERR(filp)) {
      err = PTR_ERR(filp);
      goto out;
   }

   err = File_GetUnusedFd();
   if (err < 0) {
      goto out;
   }

   vfd = err;
   /* file must be completely initialized before it
    * is installed in the fd table. Once installed,
    * other tasks may access it. */
   ASSERT(vfd >= 0);
   File_FdInstall(vfd, filp);

out:
   //if (err == -24) { sleep(1000); }
   return err;
}

long
sys_openat(int dfd, const char __user *path, int flags, int mode)
{
   int err;

   ASSERT_UPTR(path);

   char *tmp = Task_GetName(path);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = File_OpenFd(dfd, tmp, flags, mode, 1);

   Task_PutName(tmp);

out:
   //if (err == -24) { sleep(1000); }
   return err;
}

long
sys_open(const char __user *path, int flags, int mode)
{
   return sys_openat(AT_FDCWD, path, flags, mode);
}

long
sys_creat(const char __user *pathname, int mode)
{
   return sys_open(pathname, O_CREAT | O_WRONLY | O_TRUNC,  mode);
}

static int
FileDupFd(struct FileStruct *file)
{
   struct FilesStruct * files = current->files;
   struct FdTableStruct *fdt;
   int fd;

   Files_Lock(files);

   fd = FileGetUnusedFdUnlocked();

   if (fd >= 0) {
      fdt = files->fdt;
      FD_SET(fd, fdt->openFds);
      FD_CLR(fd, fdt->closeOnExec);
      FileFdInstallUnlocked(fd, file);
   } else {
      File_Put(file);
   }

   Files_Unlock(files);

   return fd;
}

long
sys_dup2(uint oldfd, uint newfd)
{
   struct FileStruct *file, *toFree;
   struct FilesStruct * files = current->files;
   struct FdTableStruct *fdt;
   int err;


   err = newfd;
   if (newfd == oldfd) {
      goto out;
   }

   Files_Lock(files);

   err = -EBADF;
   if (!(file = File_GetUnlocked(oldfd))) {
      goto out_unlock;
   }

   /* XXX: check fd rlimit. */
   /* XXX: check if table needs to be expanded for newfd. */
   WARN_XXX(0);

   fdt = files->fdt;
   ASSERT_UNIMPLEMENTED(newfd < fdt->maxFds);
   toFree = fdt->vfdTable[newfd];

   /* As you can see, the newfd shares the same file object
    * as the oldfd. This means that the two share the same
    * file offsets, attributes, and status flags. But 
    * the close on exec flag is not shared. */
   fdt->vfdTable[newfd] = file;
   FD_SET(newfd, fdt->openFds);
   FD_CLR(newfd, fdt->closeOnExec);

   DEBUG_MSG(5, "oldfd=%d newfd=%d\n", oldfd, newfd);

   /* Doesn't need to be within the files lock, but I'm placing
    * it here to adhere to the single lock/unlock rule. */
   if (toFree) {
      File_Close(toFree);
   }
   err = newfd;

out_unlock:
   Files_Unlock(files);
out:
   return err;
}

long
sys_dup(uint fildes)
{
   int err = -EBADF;
   struct FileStruct *file = File_Get(fildes);

   if (file) {
      err = FileDupFd(file);
   }

   return err;
}

long
sys_close(uint vfd)
{
   struct FilesStruct *files = current->files;
   struct FdTableStruct *fdt;
   struct FileStruct *filp;
   int err = -EBADF;
   
   DEBUG_MSG(5, "vfd=%d\n", vfd);

   Files_Lock(files);

   fdt = files->fdt;

   if (vfd >= fdt->maxFds) {
      goto out_unlock;
   }

   /* Observe that we don't use File_Get() to get
    * a pointer to the file descriptor. This is necessary
    * as it avoids incrementing the file reference count,
    * in turn ensuring that the file object gets deallocated
    * when we do a File_Put(). */
   filp = fdt->vfdTable[vfd];
   if (!filp) {
      goto out_unlock;
   }

   /* Make the vfd available for others. */
   FilePutUnusedFdUnlocked(vfd);

   /* Don't wanna hold this while we close the file --- the VFS release
    * callback may deadlock. */
   Files_Unlock(files);

   err = File_Close(filp);
   
   goto out;

out_unlock:
   Files_Unlock(files);
out:
   return err;
}


long
sys_umask(int mask)
{
   int oldMask;

   /* XXX: is there a good reason to shadow the umask? 
    * just let the kernel maintian and apply it, since
    * its not easy to tell when to apply it (e.g.,
    * depends on mount flags). */
#if 0
   oldMask = FileUserMaskOp(1, mask);
#endif
   
   if (!VCPU_IsReplaying()) {
      oldMask = syscall(SYS_umask, mask);

      DO_WITH_LOG_ENTRY(JustRetval) {
         entryp->ret = oldMask;
      } END_WITH_LOG_ENTRY(0);
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         oldMask = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return oldMask;
}

int
VFS_chmod(struct DentryStruct *dentryp, mode_t mode)
{
   int err;
   struct InodeStruct *inodp = dentryp->inode;

   ASSERT(inodp);

   err = -EINVAL;
   if (inodp->i_op->chmod) {
      err = inodp->i_op->chmod(dentryp, mode);
   }

   return err;
}

long
sys_fchmodat(int dfd, const char __user *filename, mode_t mode)
{
   int err;
   struct PathStruct ps;
   char *tmp;
   
   tmp = Task_GetName(filename);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(dfd, tmp, LOOKUP_LOCK | LOOKUP_FOLLOW, &ps);
   if (err) {
      goto out_putn;
   }

   err = VFS_chmod(ps.dentry, mode);

   Path_Release(&ps);

out_putn:
   Task_PutName(tmp);
out:
   return err;
}

long
sys_chmod(const char __user *filename, mode_t mode)
{
	return sys_fchmodat(AT_FDCWD, filename, mode);
}

long
sys_fchmod(unsigned int fd, mode_t mode)
{
   int err;
   struct FileStruct *filp;

   err = -EBADF;
   filp = File_Get(fd);
   if (!filp) {
      goto out;
   }

   /* XXX: no need to get parent lock. We can get by with
    * just the inode lock if we use fchmod (chmod requires
    * name resolution, opening up the possiblity of a concurrent
    * unlink). */
   Inode_Lock(filp->dentry->parent->inode);

   /* XXX: this chmod could fail because the dentry has been unlinked,
    * and yet we hold an fd to it, which means that fchmod would
    * succeed (had we used it) in this instance. */
   err = VFS_chmod(filp->dentry, mode);

   Inode_Unlock(filp->dentry->parent->inode);

   File_Put(filp);
out:
   return err;
}

static int
VFS_lchown(struct DentryStruct *dentryp, uid_t user, gid_t group)
{
   int err;
   struct InodeStruct *inodp = dentryp->inode;

   ASSERT(inodp);

   err = -EINVAL;
   if (inodp->i_op->lchown) {
      err = inodp->i_op->lchown(dentryp, user, group);
   }

   return err;
}

long
sys_fchownat(int dfd, const char __user *filename, uid_t user,
			  gid_t group, int flag)
{
   int err;
   struct PathStruct ps;
   char *tmp;

   tmp = Task_GetName(filename);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(dfd, tmp, LOOKUP_LOCK |
                     ((flag & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW), &ps);
   if (err) {
      goto out_putn;
   }

   err = VFS_lchown(ps.dentry, user, group);

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

long
sys_chown(const char __user * filename, uid_t user, gid_t group)
{
   return sys_fchownat(AT_FDCWD, filename, user, group, 0);
}


long
sys_lchown(const char __user * filename, uid_t user, gid_t group)
{
   return sys_fchownat(AT_FDCWD, filename, user, group, AT_SYMLINK_NOFOLLOW);
}


long
sys_fchown(unsigned int fd, uid_t user, gid_t group)
{
   int err;
   struct FileStruct *filp;

   err = -EBADF;
   filp = File_Get(fd);
   if (!filp) {
      goto out;
   }

   Inode_Lock(filp->dentry->parent->inode);

   err = VFS_lchown(filp->dentry, user, group);

   Inode_Unlock(filp->dentry->parent->inode);


   File_Put(filp);
out:
   return err;
}

static int
VFS_utimes(struct DentryStruct *dentryp, struct timeval *ktimes)
{
   int err;
   struct InodeStruct *inodp = dentryp->inode;

   ASSERT(inodp);

   /* ktimes == NULL tells utimes to use the current time */
   ASSERT(ktimes || !ktimes);

   err = -EINVAL;
   if (inodp->i_op->utimes) {
      err = inodp->i_op->utimes(dentryp, ktimes);
   }

   return err;
}

static int
UtimesHelper(int dfd, char __user * filename, struct timeval *ktimes)
{
   int err;
   struct PathStruct ps;
   char *tmp;

   /* ktimes == NULL tells utimes to use the current time */
   ASSERT(ktimes || !ktimes);

   tmp = Task_GetName(filename);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(dfd, tmp, LOOKUP_LOCK, &ps);
   if (err) {
      goto out_putn;
   }

   err = VFS_utimes(ps.dentry, ktimes);

   Path_Release(&ps);

out_putn:
   Task_PutName(tmp);
out:
   return err;
}

long
sys_utime(char __user * filename, struct utimbuf __user * utimes)
{
   struct utimbuf kbuf;
   struct timeval ktimes[2];

   if (utimes && Task_CopyFromUser(&kbuf, utimes, sizeof(kbuf)))
      return -EFAULT;

   ktimes[0].tv_sec = kbuf.actime;
   ktimes[0].tv_usec = 0;
   ktimes[1].tv_sec = kbuf.modtime;
   ktimes[1].tv_usec = 0;


	return UtimesHelper(AT_FDCWD, filename, utimes ? ktimes : NULL);
}

long
sys_futimesat(int dfd, char __user *filename, 
           struct timeval __user *utimes)
{
	struct timeval ktimes[2];

	if (utimes && Task_CopyFromUser(&ktimes, utimes, sizeof(ktimes)))
		return -EFAULT;

	return UtimesHelper(dfd, filename, utimes ? ktimes : NULL);
}

long
sys_utimes(char __user *filename, struct timeval __user *utimes)
{
	return sys_futimesat(AT_FDCWD, filename, utimes);
}

#if 0
long
GenericAccess(struct DentryStruct *dentryp, int mode)
{
   return ReadDet_access(Dentry_Name(dentryp), mode);
}
#endif

int
VFS_access(struct DentryStruct *dentryp, int mode)
{
   int err;
   struct InodeStruct *inodp = Dentry_Inode(dentryp);

   /* We expect all fs to define this, and any device nodes
    * to inherit it. Hence it should be defined for all
    * inodes. */
   ASSERT(inodp->i_op->access);

   err = inodp->i_op->access(dentryp, mode);

   return err;
}

long
sys_faccessat(int dfd, const char __user *filename, int mode)
{
   int err;
   struct PathStruct ps;
   char *tmp;

   tmp = Task_GetName(filename);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(dfd, tmp, LOOKUP_LOCK | LOOKUP_FOLLOW, &ps);
   if (err) {
      goto out_putn;
   }

   err = VFS_access(ps.dentry, mode);

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

long
sys_access(const char __user *filename, int mode)
{
   return sys_faccessat(AT_FDCWD, filename, mode);
}

int
VFS_truncate(struct DentryStruct *dentryp, loff_t offset)
{
   int err;
   struct InodeStruct *inodp = dentryp->inode;

   ASSERT(inodp);

   err = -EINVAL;
   if (inodp->i_op->truncate) {
      err = inodp->i_op->truncate(dentryp, offset);
      DEBUG_MSG(5, "err=%d\n", err);
   }

   return err;
}

int
VFS_ftruncate(struct FileStruct *filp, loff_t offset)
{
   int err;

   err = -EINVAL;
   if (filp->f_op->ftruncate) {
      err = filp->f_op->ftruncate(filp, offset);
      DEBUG_MSG(5, "err=%d\n", err);
   }

   return err;
}

long
sys_truncate64(const char __user * path, loff_t length)
{
   int err;
   struct PathStruct ps;
   char *tmp;

   tmp = Task_GetName(path);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(AT_FDCWD, tmp, LOOKUP_LOCK | LOOKUP_FOLLOW, &ps);
   if (err) {
      goto out_putn;
   }

   err = VFS_truncate(ps.dentry, length);

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

long
sys_truncate(const char __user * path, ulong length)
{
   return sys_truncate64(path, length);
}

long
sys_ftruncate64(uint fd, loff_t length)
{
   int err;
   struct FileStruct *filp;

   err = -EBADF;
   filp = File_Get(fd);
   if (!filp) {
      goto out;
   }

   Inode_Lock(filp->dentry->parent->inode);

   err = VFS_ftruncate(filp, length);

   Inode_Unlock(filp->dentry->parent->inode);


   File_Put(filp);
out:
   return err;
}

long
sys_ftruncate(uint fd, ulong length)
{
   return sys_ftruncate64(fd, length);
}
