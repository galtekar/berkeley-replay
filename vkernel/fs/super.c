#include "vkernel/public.h"
#include "private.h"


static SHAREDAREA short idCnt = 0;

static INLINE short
SuperBlockGetId()
{
   short id;

   BKL_Lock();

   id = idCnt++;

   BKL_Unlock();

   return id;
}

struct SuperBlockStruct *
SuperBlock_Alloc(const char *fsname)
{
   struct SuperBlockStruct *sb;


   sb = SharedArea_Malloc(sizeof(*sb));
   memset(sb, 0, sizeof(*sb));
   sb->inodeMap = Map_Create(0);
   strncpy(sb->fsname, fsname, sizeof(sb->fsname));
   ORDERED_LOCK_INIT(&sb->lock, "super");

   sb->id = SuperBlockGetId();

   return sb;
}

struct SuperBlockStruct *
SuperBlock_AllocPseudo(const char *fsname, struct SuperBlockOps *sbOps)
{
   struct SuperBlockStruct *sb;
   struct InodeStruct *inodp;
   struct DentryStruct *dentryp;

   sb = SuperBlock_Alloc(fsname);
   sb->ops = sbOps;

   D__;

   /* 1 is reserved for the root inode. */
   inodp = Inode_Get(sb, "/", 1);

   D__;

   dentryp = Dentry_AllocRoot(inodp);
   ASSERT_PTR(dentryp);

   sb->root = dentryp;

   sb->id = SuperBlockGetId();

   /* Don't hash the dentry -- pseudo file-systems
    * should not be mounted. */

   return sb;
}

void
SuperBlock_Free(struct SuperBlockStruct *sb)
{
   struct InodeStruct *dummy;

   ASSERT(sb->inodeMap);
   Map_Destroy(sb->inodeMap, inoMap, dummy);
   SharedArea_Free(sb, sizeof(*sb));
}

static int
VFS_statfs(struct DentryStruct *dentry, struct statfs64 *statp)
{
   int err = -EINVAL;
   struct SuperBlockStruct *sb = dentry->inode->sb;

   if (sb->ops->statfs) {
      err = sb->ops->statfs(dentry, statp);
   }

   return err;
}

static int 
VFS_statfs_native(struct DentryStruct *dentry, struct statfs *buf)
{
	struct statfs64 st;
	int retval;

	retval = VFS_statfs(dentry, &st);
	if (retval)
		return retval;

	if (sizeof(*buf) == sizeof(st))
		memcpy(buf, &st, sizeof(st));
	else {
		if (sizeof buf->f_blocks == 4) {
			if ((st.f_blocks | st.f_bfree | st.f_bavail) &
			    0xffffffff00000000ULL)
				return -EOVERFLOW;
			/*
			 * f_files and f_ffree may be -1; it's okay to stuff
			 * that into 32 bits
			 */
			if (st.f_files != (u64)-1 &&
			    (st.f_files & 0xffffffff00000000ULL))
				return -EOVERFLOW;
			if (st.f_ffree != (u64)-1 &&
			    (st.f_ffree & 0xffffffff00000000ULL))
				return -EOVERFLOW;
		}

		buf->f_type = st.f_type;
		buf->f_bsize = st.f_bsize;
		buf->f_blocks = st.f_blocks;
		buf->f_bfree = st.f_bfree;
		buf->f_bavail = st.f_bavail;
		buf->f_files = st.f_files;
		buf->f_ffree = st.f_ffree;
		buf->f_fsid = st.f_fsid;
		buf->f_namelen = st.f_namelen;
		buf->f_frsize = st.f_frsize;
		memset(buf->f_spare, 0, sizeof(buf->f_spare));
	}
	return 0;
}

SYSCALLDEF(sys_statfs, const char __user *path, struct statfs __user *buf)
{
   int err;
   struct statfs __stat;
   struct PathStruct ps;
   char *tmp;

   tmp = Task_GetName(path);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(AT_FDCWD, tmp, LOOKUP_LOCK, &ps);
   if (err) {
      goto out_putn;
   }

   err = VFS_statfs_native(ps.dentry, &__stat);

   if (!err && Task_CopyToUser(buf, &__stat, sizeof(__stat))) {
      err = -EFAULT;
   }

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

SYSCALLDEF(sys_fstatfs, uint fd, struct statfs __user *buf)
{
   struct statfs __stat;
   struct FileStruct *file;
   int err;

   err = -EBADF;
   file = File_Get(fd);
   if (!file) {
      goto out;
   }

   /* XXX: why exactly do we need the parent lock for this? */
   Inode_Lock(file->dentry->parent->inode);

   err = VFS_statfs_native(file->dentry, &__stat);

   Inode_Unlock(file->dentry->parent->inode);

   if (!err && Task_CopyToUser(buf, &__stat, sizeof(__stat))) {
      err = -EFAULT;
   }

   File_Put(file);
out:
   return err;
}

SYSCALLDEF(sys_statfs64, const char __user *path, size_t sz, 
           struct statfs64 __user *buf)
{
   int err;
   struct statfs64 __stat;
   struct PathStruct ps;
   char *tmp;

   if (sz != sizeof(*buf)) {
      err = -EINVAL;
      goto out;
   }

   tmp = Task_GetName(path);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   err = Path_Lookup(AT_FDCWD, tmp, LOOKUP_LOCK, &ps);
   if (err) {
      goto out_putn;
   }

   err = VFS_statfs(ps.dentry, &__stat);

   if (!err && Task_CopyToUser(buf, &__stat, sizeof(__stat))) {
      err = -EFAULT;
   }

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

SYSCALLDEF(sys_fstatfs64, uint fd, size_t sz, struct statfs64 __user *buf)
{
   struct statfs64 __stat;
   struct FileStruct *file;
   int err;

   err = -EBADF;
   file = File_Get(fd);
   if (!file) {
      goto out;
   }

   if (sz != sizeof(*buf)) {
      err = -EINVAL;
      goto out_putf;
   }

   /* XXX: why exactly do we need the parent lock for this? */
   Inode_Lock(file->dentry->parent->inode);

   err = VFS_statfs(file->dentry, &__stat);

   Inode_Unlock(file->dentry->parent->inode);

   if (!err && Task_CopyToUser(buf, &__stat, sizeof(__stat))) {
      err = -EFAULT;
   }

out_putf:
   File_Put(file);
out:
   return err;
}

/* XXX: sys_ustat (essentially sys_statfs), sys_statfs, sys_fstatfs */
