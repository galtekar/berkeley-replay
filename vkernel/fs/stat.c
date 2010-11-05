#include <errno.h>
#include <sys/stat.h>

#include "vkernel/public.h"
#include "private.h"

/*
 * XXX: These are inode operations, and ideally, we shouldn't need to lock
 * the parent inode to perform them. We should be able to perform these
 * operations using only the target inode's lock. But the Linux syscall
 * corresponding to these inode ops go thorough name resolution and
 * hence operate on Linux dentries. And any operations on Linux dentries
 * requires the parent lock (to ensure that link/lookup/unlink operations
 * are deterministic).
 *
 * We wouldn't have to acquire the parent lock if Linux permitted
 * inode operations on linux file-descriptor rather than
 * pathnames. For example, lstat(fd) rather than lstat(pathname).
 * This should be possible through device-driver support.
 */
SYSCALLDEF(sys_readlinkat, int dfd, const char __user *path, 
           char __user *buf, int bufsiz)
{
   int err, val1, val2;
   uint len;
   char *tmp;
   struct PathStruct ps;

   if (bufsiz <= 0) {
      err = -EINVAL;
      goto out;
   }

   tmp = Task_GetName(path);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   /* XXX: this is a hack to get JAVA working ... eventually
    * we need to emulate the proc fs. */
   if (0 && strcmp(tmp, "/proc/self/exe") == 0) {
      struct DentryStruct *dentryp;

      dentryp = Vma_GetExecDentry();
      ASSERT(dentryp);

      err = 0;
      Path_Init(&ps, dentryp->name, dentryp, 0);
   } else if (sscanf(tmp,"/proc/self/fd/%d", &val1) == 1) {
      struct FileStruct *filp = File_Get(val1);

      if (filp) {
         struct DentryStruct *dentry;
         err = 0;
         dentry = Dentry_Get(filp->dentry);
         Path_Init(&ps, dentry->name, dentry, 0);
         File_Put(filp);
      } else {
         err = -ENOENT;
      }
   } else if (0 && sscanf(tmp, "/proc/%d/fd/%d", &val1, &val2) == 2) {
      /* ``ps aux'' will trigger this. */
      //ASSERT_UNIMPLEMENTED(0);
   } else {
      /*
       * By specifying LOOKUP_READLINK, we ensure that Path_Lookup returns
       * -EINVAL if target isn't a symlink -- this is essential for Python
       *  to work.
       */
      err = Path_Lookup(dfd, tmp, LOOKUP_LOCK | LOOKUP_READLINK, 
            &ps);
   }
   if (err) {
      goto out_putn;
   }

   DEBUG_MSG(5, "READLINK STR=%s\n", ps.pathname);
   /* readlink does not null-terminate the output buffer; hence
    * we do not add 1 to the strlen below. */
   len = strlen(ps.pathname);
   if (len > (unsigned) bufsiz) {
      len = bufsiz;
   }
   if (Task_CopyToUser(buf, ps.pathname, len)) {
      len = -EFAULT;
   }

   err = len;


   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

SYSCALLDEF(sys_readlink, const char __user *path, char __user *buf, int bufsiz)
{
   return sys_readlinkat(AT_FDCWD, path, buf, bufsiz);
}

static int
VFS_lstat(struct DentryStruct *dentryp, struct kstat64 *statp)
{
   int err;
   struct InodeStruct *inodp = dentryp->inode;

   err = -EINVAL;
   if (inodp->i_op->lstat) {
      err = inodp->i_op->lstat(dentryp, statp);
   }

   return err;
}

static int
StatPathHelper(int dfd, const char __user *path, struct kstat64 *statp, 
               int linkStat)
{
   int err;
   struct PathStruct ps;
   char *tmp;

   tmp = Task_GetName(path);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   /* The inode of the link and inode of the link target are two different
    * inodes. Is the stat performed on the link or the link target?
    * Hence the LOOKUP_FOLLOW. */
   D__;
   err = Path_Lookup(dfd, tmp, LOOKUP_LOCK | (!linkStat ? LOOKUP_FOLLOW : 0), 
            &ps);
   D__;

   if (err) {
      goto out_putn;
   }

   err = VFS_lstat(ps.dentry, statp);

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

SYSCALLDEF(sys_newstat, char __user * filename, struct stat __user * statbuf)
{
   int err;
   struct kstat64 __stat;

   err = StatPathHelper(AT_FDCWD, filename, &__stat, 0);
   if (err) {
      return err;
   }

   return Linux_cp_new_stat(&__stat, statbuf);
}

SYSCALLDEF(sys_newlstat, char __user * filename, struct stat __user * statbuf)
{
   int err;
   struct kstat64 __stat;

   err = StatPathHelper(AT_FDCWD, filename, &__stat, 1);
   if (err) {
      return err;
   }

   return Linux_cp_new_stat(&__stat, statbuf);
}

SYSCALLDEF(sys_stat64, char __user * filename, struct kstat64 __user * statbuf)
{
   int err;
   struct kstat64 __stat;

   err = StatPathHelper(AT_FDCWD, filename, &__stat, 0);

   if (!err && Task_CopyToUser(statbuf, &__stat, sizeof(__stat))) {
      err = -EFAULT;
   }

   return err;
}

SYSCALLDEF(sys_lstat64, char __user * filename, struct kstat64 __user * statbuf)
{
   int err;
   struct kstat64 __stat;

   err = StatPathHelper(AT_FDCWD, filename, &__stat, 1);

   if (!err && Task_CopyToUser(statbuf, &__stat, sizeof(__stat))) {
      err = -EFAULT;
   }

   return err;
}


SYSCALLDEF(sys_fstatat64, int dfd, char __user *filename, 
           struct kstat64 __user *statbuf, int flag)
{
   struct kstat64 __stat;
   int err = -EINVAL;

   if ((flag & ~AT_SYMLINK_NOFOLLOW) != 0)
      goto out;

   if (flag & AT_SYMLINK_NOFOLLOW)
      err = StatPathHelper(dfd, filename, &__stat, 1);
   else
      err = StatPathHelper(dfd, filename, &__stat, 0);

   if (!err && Task_CopyToUser(statbuf, &__stat, sizeof(__stat))) {
      err = -EFAULT;
   }

out:
   return err;
}

static int
VFS_fstat(struct FileStruct *filp, struct kstat64 *statp)
{
   int err;

   err = -EINVAL;
   if (filp->f_op->fstat) {
      err = filp->f_op->fstat(filp, statp);
   }

   return err;
}

SYSCALLDEF(sys_fstat64, ulong fd, struct kstat64 __user * statbuf)
{
   int err = -EBADF;
   struct kstat64 __stat;
   struct FileStruct *file;

   D__;

   file = File_Get(fd);
   if (!file) {
      goto out;
   }

   D__;
   Inode_Lock(file->dentry->parent->inode);
   D__;

   /* Can't use VFS_lstat here since underlying file may not
    * be visible in the directory namespace. For example, it
    * may have been unlinked after we opened it. This is
    * what happens with io-redirection in bash, for instance. */
   err = VFS_fstat(file, &__stat);

   if (!err && Task_CopyToUser(statbuf, &__stat, sizeof(__stat))) {
      err = -EFAULT;
   }

   Inode_Unlock(file->dentry->parent->inode);

   File_Put(file);
out:
   return err;
}

#if 0
/* XXX: this has subtleties that I don't understand yet ... e.g., dealing with
 * 16-bit uid/gids. */
static inline u16 old_encode_dev(dev_t dev)
{
   return (MAJOR(dev) << 8) | MINOR(dev);
}

static int cp_old_stat(struct stat64 *stat, struct __old_kernel_stat __user * statbuf)
{
   struct __old_kernel_stat tmp;

   memset(&tmp, 0, sizeof(struct __old_kernel_stat));
   tmp.st_dev = old_encode_dev(stat->st_dev);
   tmp.st_ino = stat->st_ino;
   tmp.st_mode = stat->st_mode;
   tmp.st_nlink = stat->st_nlink;
   if (tmp.st_nlink != stat->st_nlink)
      return -EOVERFLOW;
   SET_UID(tmp.st_uid, stat->st_uid);
   SET_GID(tmp.st_gid, stat->st_gid);
   tmp.st_rdev = old_encode_dev(stat->st_rdev);
#if BITS_PER_LONG == 32
   if (stat->st_size > MAX_NON_LFS)
      return -EOVERFLOW;
#endif	
   tmp.st_size = stat->st_size;
   tmp.st_atime = stat->st_atime;
   tmp.st_mtime = stat->st_mtime;
   tmp.st_ctime = stat->st_ctime;
   return Task_CopyToUser(statbuf,&tmp,sizeof(tmp)) ? -EFAULT : 0;
}

SYSCALLDEF(sys_stat, char __user * filename, struct __old_kernel_stat __user * statbuf)
{

   struct stat64 stat;
   int err;

   err = VFS_stat(AT_FDCWD, filename, &stat, 0);

   if (!SYSERR(err)) {
      err = cp_old_stat(&stat, statbuf);
   }

   return err;
}
#endif
