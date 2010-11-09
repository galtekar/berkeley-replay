#include "vkernel/public.h"
#include "private.h"

static void
FileSysSetCwd(struct DentryStruct *newCwd)
{
   Fs_Lock(current->fs);

   /* XXX: cwdInode may not exist yet for the init task:
    * this should always exist/be set. */
   if (current->fs->cwd) {
      Dentry_Put(current->fs->cwd);
   }

   current->fs->cwd = Dentry_Get(newCwd);

   Fs_Unlock(current->fs);
}

static int
VFS_chdir(struct DentryStruct *base, struct DentryStruct *dentryp)
{
   int err;
   struct InodeStruct *inodp = base->inode;

   err = -EINVAL;
   if (inodp->i_op->chdir) {
      err = inodp->i_op->chdir(dentryp);
   }

   return err;
}

static int
FileSysChdirHelper(struct DentryStruct *base, struct DentryStruct *dentryp)
{
   int err;

   /* 
    * Can't use VFS_permission -- it checks permissions using the real
    * uid/gid. We need the check to be done with the fs uid/gid.
    * Can't use readlink -- doesn't verify that target is directory
    * and that it's executable. sys_chdir seems to be the only call that
    * does exactly what we want.
    */
   err = VFS_chdir(base, dentryp);

   if (!err) {
      FileSysSetCwd(dentryp);
   }

   return err;
}

int
FileSys_Chdir(const char * filename)
{
   int err;
   struct PathStruct ps;

   err = Path_Lookup(AT_FDCWD, filename, LOOKUP_LOCK | LOOKUP_FOLLOW, &ps);
   if (err) {
      goto out;
   }

   err = FileSysChdirHelper(ps.dentry->parent, ps.dentry);

   Path_Release(&ps);

out:
   return err;
}


SYSCALLDEF(sys_chdir, const char __user * filename)
{
   int err;
   char *tmp;

   tmp = Task_GetName(filename);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = FileSys_Chdir(tmp);

   Task_PutName(tmp);
out:
   return err;
}

SYSCALLDEF(sys_fchdir, uint fd)
{
   int err;
   struct FileStruct *file;
   struct DentryStruct *dentry, *pdentry;

   err = -EBADF;
   file = File_Get(fd);
   if (!file) {
      goto out;
   }

   dentry = file->dentry;
   pdentry = dentry->parent;

   Inode_Lock(pdentry->inode);

   err = FileSysChdirHelper(pdentry, dentry);

   Inode_Unlock(pdentry->inode);


   File_Put(file);
out:
   return err;
}

/*
 * On success, must return number of characters written into @buf,
 * including the null-terminator. */
SYSCALLDEF(sys_getcwd, char __user *buf, unsigned long size)
{
   int err;
   struct PathStruct ps;
   struct DentryStruct *cwd;

   Fs_Lock(current->fs);

   cwd = current->fs->cwd;
   ASSERT(cwd);

   /* We don't use Path_Lookup because it will try to acquire
    * the fs lock. */

   /* We need to lock the path to ensure that access returns
    * a deterministic value -- for example, there may be
    * a competing chmod on the same file. */
   err = Path_Resolve(cwd->name, LOOKUP_LOCK, &ps);
   if (err) {
      goto out_unlock;
   }

   /* Check if the cwd inode still refers to a valid directory.
    * Linux doesn't appear to check for execute permission,
    * and instead does a simple existance check (i.e., is it
    * hashed in the dentry cache?). For just an existance check,
    * we could use VFS_access, hence avoiding the need to
    * invoke Linux's getcwd() syscall. */
   err = VFS_access(cwd, F_OK);
   if (!err) {
      char *cwdstr = cwd->name;
      ulong len;

      err = -ERANGE;
      len = strlen(cwdstr)+1;
      if (len <= size) {
         err = len;
         if (Task_CopyToUser(buf, cwdstr, len)) {
            err = -EFAULT;
         }
      }
   }

   Path_Release(&ps);

out_unlock:
   Fs_Unlock(current->fs);

   return err;
}

static INLINE struct FileSysStruct*
CopyFileSysStruct(struct FileSysStruct *old)
{
   struct FileSysStruct *fs = SharedArea_Malloc(sizeof(struct FileSysStruct));
   ASSERT_UNIMPLEMENTED(fs);

   if (fs) {
      fs->count = 1;
      ORDERED_LOCK_INIT(&fs->lock, "filesys");

      Fs_Lock(old);

      fs->cwd = Dentry_Get(old->cwd);

      Fs_Unlock(old);
   } 

   return fs;
}

int 
FileSys_Fork(ulong cloneFlags, struct Task *tsk)
{
   int err = 0;

   if (cloneFlags & CLONE_FS) {
      current->fs->count++;
      goto out;
   }

   tsk->fs = CopyFileSysStruct(current->fs);

   if (!tsk->fs) {
      err = -ENOMEM;
      goto out;
   }

out:
   ASSERT_UNIMPLEMENTED_MSG(err != -ENOMEM, "Should we avoid the RootFs_Fork on -ENOMEM?\n");
   RootFs_Fork(tsk);

   return err;
}

void
FileSys_Exit(struct Task *tsk)
{
   struct FileSysStruct *fs = tsk->fs;

   D__;

   ASSERT_TASKLIST_LOCKED();

   /* XXX: why wouldn't it have an fs?! */
   ASSERT_UNIMPLEMENTED(fs);

   if (fs) {
      tsk->fs = NULL;
      fs->count--;

      /* Must rely on fs->count rather than mm->users since FS sharing
       * is independent of address-space sharing. */
      if (fs->count == 0) {
         SharedArea_Free(fs, sizeof(*fs));
      }
   }

   RootFs_Exit(tsk);
}

void 
FileSys_Exec()
{
   RootFs_Exec();
}
