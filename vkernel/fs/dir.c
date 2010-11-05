#include "vkernel/public.h"
#include "private.h"

/* 
 * Some  (e.g., shmfs) may not have lookup routines, which means that
 * we can't lookup the inode at a later time. This means that the fs's
 * VFS create op must be reponsible for filling the dentryp with
 * the corresponding inode. Hence we pass in the dentry and not just
 * the name.
 */

static int
VFS_mknod(struct InodeStruct *inodp, struct DentryStruct *dentryp, int mode, unsigned dev)
{
   int err;

   ASSERT(inodp);

   err = -EINVAL;
   if (inodp->i_op->mknod) {
      err = inodp->i_op->mknod(inodp, dentryp, mode, dev);
   }

   DEBUG_MSG(5, "err=%d\n", err);
   return err;
}

long
sys_mknodat(int dfd, const char __user *filename, int mode, unsigned dev)
{
   int err;
   struct DentryStruct *dentryp;
   struct PathStruct ps;
   char *tmp;
   struct InodeStruct *dir;

   /* No need to cleanse mode. If Linux doesn't support it, then the
    * VFS op will fail. */

   tmp = Task_GetName(filename);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(dfd, tmp, LOOKUP_INTENT_CREATE | LOOKUP_LOCK, &ps);
   if (err) {
      goto out_putn;
   }

   if (ps.dentry) {
      err = -EEXIST;
      goto out_prel;
   }

   dentryp = Dentry_Open(sbRoot->root, ps.pathname, 
                         O_CREAT | O_EXCL);
   if (IS_ERR(dentryp)) {
      err = PTR_ERR(dentryp);
      goto out_prel;
   }

   dir = sbRoot->root->inode;

   switch (mode & S_IFMT) {
   case 0: case S_IFREG:
      err = VFS_create(dir, dentryp, mode, NULL);
      break;
   case S_IFCHR: case S_IFBLK:
      err = VFS_mknod(dir, dentryp, mode, dev);
      break;
   case S_IFIFO: case S_IFSOCK:
      err = VFS_mknod(dir, dentryp, mode, 0);
      break;
   case S_IFDIR:
      err = -EPERM;
      break;
   default:
      err = -EINVAL;
   }

   Path_Instantiate(&ps, dentryp);

out_prel:
   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

long
sys_mknod(const char __user *filename, int mode, unsigned dev)
{
   return sys_mknodat(AT_FDCWD, filename, mode, dev);
}


/* This is essentially the create() operation, but for directories. */
static int
VFS_mkdir(struct InodeStruct *dir, struct DentryStruct *dentryp, int mode)
{
   int err;

   ASSERT(dir);

   err = -EINVAL;
   if (dir->i_op->mkdir) {
      err = dir->i_op->mkdir(dir, dentryp, mode);
   }

   return err;
}

long
sys_mkdirat(int dfd, const char __user *pathname, int mode)
{
   int err;
   struct PathStruct ps;
   struct DentryStruct *dentryp;
   char *tmp;

   tmp = Task_GetName(pathname);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(dfd, tmp, LOOKUP_INTENT_CREATE | LOOKUP_LOCK, &ps);
   if (err) {
      goto out_putn;
   }

   if (ps.dentry) {
      err = -EEXIST;
      goto out_prel;
   }

   dentryp = Dentry_Open(sbRoot->root, ps.pathname, O_CREAT | O_EXCL);
   if (IS_ERR(dentryp)) {
      err = PTR_ERR(dentryp);
      goto out_prel;
   }

   err = VFS_mkdir(sbRoot->root->inode, dentryp, mode);

   Path_Instantiate(&ps, dentryp);

out_prel:
   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

long
sys_mkdir(const char __user *pathname, int mode)
{
   return sys_mkdirat(AT_FDCWD, pathname, mode);
}


static int
VFS_link(struct DentryStruct *old_entry, struct InodeStruct *dir, 
         struct DentryStruct *dentry, int flags)
{
   int err;

   err = -EINVAL;
   if (dir->i_op->link) {
      err = dir->i_op->link(old_entry, dir, dentry, flags);
   }

   return err;
}

static int
DirLink(int olddfd, const char __user *uoldname, int newdfd, 
        const char __user *unewname, int flags)
{
   int err;
   struct PathStruct new_ps, old_ps;
   struct DentryStruct *dentryp;
   char *koldname, *knewname;

   koldname = Task_GetName(uoldname);
   if (IS_ERR(koldname)) {
      err = PTR_ERR(koldname);
      goto out;
   }

   knewname = Task_GetName(unewname);
   if (IS_ERR(knewname)) {
      err = PTR_ERR(knewname);
      goto out_put_oldname;
   }

   err = Path_Lookup(olddfd, koldname, LOOKUP_LOCK, &old_ps);
   if (err) {
      goto out_put_names;
   }

   err = Path_Lookup(newdfd, knewname, LOOKUP_INTENT_CREATE, &new_ps);
   if (err) {
      goto out_prel_old;
   }

   if (new_ps.dentry) {
      err = -EEXIST;
      goto out_prel_new;
   }

   dentryp = Dentry_Open(sbRoot->root, new_ps.pathname, O_CREAT | O_EXCL);
   if (IS_ERR(dentryp)) {
      err = PTR_ERR(dentryp);
      goto out_prel_new;
   }

   err = VFS_link(old_ps.dentry, sbRoot->root->inode, dentryp, flags);

   Path_Instantiate(&new_ps, dentryp);

out_prel_new:
   Path_Release(&new_ps);
out_prel_old:
   Path_Release(&old_ps);
out_put_names:
   Task_PutName(knewname);
out_put_oldname:
   Task_PutName(koldname);
out:
   return err;
}

long
sys_linkat(int olddfd, const char __user *oldname,
      int newdfd, const char __user *newname, int flags)
{
   return DirLink(olddfd, oldname, newdfd, newname, flags);
}

long
sys_link(const char __user *oldname, const char __user *newname)
{
   return sys_linkat(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
}

static int
VFS_symlink(const char *koldname, struct InodeStruct *dir, 
            struct DentryStruct *dentry)
{
   int err;

   err = -EINVAL;
   if (dir->i_op->symlink) {
      err = dir->i_op->symlink(koldname, dir, dentry);
   }

   return err;
}

/*
 * Symlinks don't require source file/dir to be valid, unlike hardlinks,
 * hence the two different functions.
 */
static int
DirSymLink(int olddfd, const char __user *uoldname, int newdfd, 
        const char __user *unewname, int flags)
{
   int err;
   struct PathStruct new_ps;
   struct DentryStruct *dentryp;
   char *koldname, *knewname;

   koldname = Task_GetName(uoldname);
   if (IS_ERR(koldname)) {
      err = PTR_ERR(koldname);
      goto out;
   }

   knewname = Task_GetName(unewname);
   if (IS_ERR(knewname)) {
      err = PTR_ERR(knewname);
      goto out_put_oldname;
   }

   /* oldname needn't exist since this is a symlink (rather than a hardlink), 
    * so no need to do a Path_Lookup(koldname). */

   err = Path_Lookup(newdfd, knewname, LOOKUP_INTENT_CREATE | LOOKUP_LOCK, 
         &new_ps);
   if (err) {
      goto out_put_names;
   }

   if (new_ps.dentry) {
      err = -EEXIST;
      goto out_prel_new;
   }

   dentryp = Dentry_Open(sbRoot->root, new_ps.pathname, O_CREAT | O_EXCL);
   if (IS_ERR(dentryp)) {
      err = PTR_ERR(dentryp);
      goto out_prel_new;
   }

   err = VFS_symlink(koldname, sbRoot->root->inode, dentryp);

   Path_Instantiate(&new_ps, dentryp);

out_prel_new:
   Path_Release(&new_ps);
out_put_names:
   Task_PutName(knewname);
out_put_oldname:
   Task_PutName(koldname);
out:
   return err;
}


long
sys_symlinkat(const char __user *oldname, int newdfd, 
              const char __user *newname)
{
   return DirSymLink(AT_FDCWD, oldname, newdfd, newname, 0);
}

long
sys_symlink(const char __user *oldname, const char __user *newname)
{
   return sys_symlinkat(oldname, AT_FDCWD, newname);
}


static int
VFS_rmdir(struct InodeStruct *dir, struct DentryStruct *dentryp)
{
   int err;

   err = -EINVAL;
   if (dir->i_op->rmdir) {
      err = dir->i_op->rmdir(dir, dentryp);
   }

   DEBUG_MSG(5, "err=%d\n", err);
   return err;
}

static int
DirRemove(int dfd, const char __user *pathname)
{
   int err;
   struct PathStruct ps;
   char *tmp;

   tmp = Task_GetName(pathname);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(dfd, tmp, LOOKUP_LOCK, &ps);
   if (err) {
      goto out_putn;
   }

   err = VFS_rmdir(ps.dentry->parent->inode, ps.dentry);

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

long
sys_rmdir(const char __user *pathname)
{
   return DirRemove(AT_FDCWD, pathname);
}

static int
VFS_unlink(struct InodeStruct *dir, struct DentryStruct *dentryp)
{
   int err;

   ASSERT(dir);

   err = -EINVAL;
   if (dir->i_op->unlink) {
      err = dir->i_op->unlink(dir, dentryp);
   }

   DEBUG_MSG(5, "err=%d\n", err);
   return err;
}

static int
DirUnlink(int dfd, const char __user *pathname)
{
   int err;
   struct PathStruct ps;
   char *tmp;

   tmp = Task_GetName(pathname);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(dfd, tmp, LOOKUP_LOCK, &ps);
   if (err) {
      goto out_putn;
   }

   err = VFS_unlink(ps.dentry->parent->inode, ps.dentry);

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

long
sys_unlinkat(int dfd, const char __user *pathname, int flag)
{
   int err;

   if ((flag & ~AT_REMOVEDIR) != 0) {
      err = -EINVAL;
      goto out;
   }

   if (flag & AT_REMOVEDIR) {
      err = DirRemove(dfd, pathname);
   } else {
      err = DirUnlink(dfd, pathname);
   }

out:
   return err;
}

long
sys_unlink(const char __user *pathname)
{
   return DirUnlink(AT_FDCWD, pathname);
}

static int
VFS_rename(struct DentryStruct *old_dentry,
           struct InodeStruct *new_dir, struct DentryStruct *new_dentry)
{
   int err = -EINVAL;
   struct InodeStruct *old_dir = old_dentry->parent->inode;

   {
      struct InodeStruct *oldi, *newi;

      oldi = Dentry_Inode(old_dentry);
      newi = Dentry_Inode(new_dentry);

      ASSERT(oldi);
      ASSERT(newi || !newi);

      DEBUG_MSG(5, "old=%s:%lu\n", old_dentry->name, Inode_Ino(oldi));
      DEBUG_MSG(5, "newino=%s:%lu\n", new_dentry->name, 
            newi ? Inode_Ino(newi) : 0);

      if (newi) {
         if (Inode_Ino(oldi) == Inode_Ino(newi)) {
            ASSERT(oldi == newi);
         }
      }
   }

   if (Dentry_Inode(old_dentry) == Dentry_Inode(new_dentry)) {
      /* What Linux does, so we emulate. */
      err = 0;
      goto out;
   }

   if (old_dir->i_op->rename) {
      err = old_dir->i_op->rename(old_dentry, new_dir, new_dentry);
   }

out:
   return err;
}

/*
 * NOTE:
 *    o Linux permits renames only within the same mountpoint (not device)
 *       - it maintains the ino number; renames dentry; thus not a copy
 *
 */
long
sys_renameat(int olddfd, const char __user *oldname,
			     int newdfd, const char __user *newname)
{
   int err;
   struct PathStruct old_ps, new_ps;
   struct DentryStruct *dentryp;
   char *koldname, *knewname;

   koldname = Task_GetName(oldname);
   if (IS_ERR(koldname)) {
      err = PTR_ERR(koldname);
      goto out;
   }

   knewname = Task_GetName(newname);
   if (IS_ERR(knewname)) {
      err = PTR_ERR(knewname);
      goto out_put_oldname;
   }

   /* 
    * XXX: the newname must be in the same mountpoint, and because
    * the mount root is the parent of both source and target, it
    * suffices to acquire just one lock.
    */

   /* XXX: what happens if oldname is a symlink? */
   err = Path_Lookup(olddfd, koldname, LOOKUP_LOCK, &old_ps);
   if (err) {
      goto out_put_names;
   }

   /* LOOKUP_INTENT_CREATE -- not an error if file doesn't exist. */
   /* Note that we don't ask for LOOKUP_LOCK; we already did that
    * above and thus should be holding the parent lock now. */
   err = Path_Lookup(newdfd, knewname, LOOKUP_INTENT_CREATE, &new_ps);
   if (err) {
      goto out_prel_old;
   }

   /* Linux says its not an error if the target already exists. */
   ASSERT(new_ps.dentry || !new_ps.dentry);

   if (new_ps.dentry) {
      dentryp = new_ps.dentry;
   } else {
      /* Note that parent cannot change from underneath us since we are
       * holding the parent lock. */
      dentryp = Dentry_Open(sbRoot->root, new_ps.pathname, O_CREAT);
      if (IS_ERR(dentryp)) {
         err = PTR_ERR(dentryp);
         goto out_prel_new;
      }
      Path_Instantiate(&new_ps, dentryp);
   }

   D__;

   err = VFS_rename(old_ps.dentry, sbRoot->root->inode, dentryp);

   ASSERT(new_ps.dentry);

out_prel_new:
   Path_Release(&new_ps);
out_prel_old:
   Path_Release(&old_ps);
out_put_names:
   Task_PutName(knewname);
out_put_oldname:
   Task_PutName(koldname);
out:
   return err;
}

long
sys_rename(const char __user *oldname, const char __user *newname)
{
	return sys_renameat(AT_FDCWD, oldname, AT_FDCWD, newname);
}
