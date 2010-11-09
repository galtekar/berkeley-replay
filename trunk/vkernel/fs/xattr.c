#include "vkernel/public.h"
#include "private.h"

#define USE_NEW 1

static int
VFS_xattr(int isGet, struct DentryStruct *dentryp, char *kname, void *kvalue, 
          size_t size, int flags)
{
   int err = -EINVAL;
   struct InodeStruct *inodp = dentryp->inode;


   if (isGet) {
      if (inodp->i_op->lgetxattr) {
         err = inodp->i_op->lgetxattr(dentryp, kname, kvalue, size);
      }
   } else {
      if (inodp->i_op->lsetxattr) {
         err = inodp->i_op->lsetxattr(dentryp, kname, kvalue, size, flags);
      }
   }

   return err;
}

static int
XattrSetHelper(struct DentryStruct *dentryp, char __user *name, 
               void __user *value, size_t size, int flags)
{
	int err;
	void *kvalue = NULL;
	char kname[XATTR_NAME_MAX + 1];

#if USE_NEW
	err = Task_UserStringNCopy(kname, name, sizeof(kname));
#else
	err = strncpy_from_user(kname, name, sizeof(kname));
#endif

	if (err == 0 || err == sizeof(kname))
		err = -ERANGE;
	if (err < 0)
		return err;

	if (size) {
		if (size > XATTR_SIZE_MAX)
			return -E2BIG;
		kvalue = malloc(size);
		if (!kvalue)
			return -ENOMEM;
		if (Task_CopyFromUser(kvalue, value, size)) {
         free(kvalue);
			return -EFAULT;
		}
	}

	err = VFS_xattr(0, dentryp, kname, kvalue, size, flags);
   ASSERT_COULDBE(kvalue == NULL);
   if (kvalue) {
      free(kvalue);
   }
	return err;
}

static int
XattrGetHelper(struct DentryStruct *dentryp, char __user *name, 
               void __user *value, size_t size)
{
	int err;
	void *kvalue = NULL;
	char kname[XATTR_NAME_MAX + 1];

#if USE_NEW
	err = Task_UserStringNCopy(kname, name, sizeof(kname));
#else
	err = strncpy_from_user(kname, name, sizeof(kname));
#endif

	if (err == 0 || err == sizeof(kname))
		err = -ERANGE;
	if (err < 0)
		return err;

	if (size) {
		if (size > XATTR_SIZE_MAX) {
         size = XATTR_SIZE_MAX;
      }
		kvalue = malloc(size);
		if (!kvalue)
			return -ENOMEM;
      memset(kvalue, 0, size);
	}

	err = VFS_xattr(1, dentryp, kname, kvalue, size, 0);

	if (err > 0) {
		if (size && Task_CopyToUser(value, kvalue, err))
			err = -EFAULT;
	} else if (err == -ERANGE && size >= XATTR_SIZE_MAX) {
		/* The file system tried to returned a value bigger
		   than XATTR_SIZE_MAX bytes. Not possible. */
		err = -E2BIG;
	}

   ASSERT_COULDBE(kvalue == NULL);
   if (kvalue) {
      free(kvalue);
   }

   return err;
}



static int
ixattr(int isGet, char __user *path, char __user *name, void __user *value, size_t size, 
       int flags, int linkAttr)
{
   int err, lookupFlags;
   char *tmp;
   struct PathStruct ps;

   tmp = Task_GetName(path);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   lookupFlags = LOOKUP_LOCK | (linkAttr ? 0 : LOOKUP_FOLLOW);

   err = Path_Lookup(AT_FDCWD, tmp, lookupFlags, &ps);
   if (err) {
      goto out_putn;
   }

   if (isGet) {
      err = XattrGetHelper(ps.dentry, name, value, size);
   } else {
      err = XattrSetHelper(ps.dentry, name, value, size, flags);
   }

   Path_Release(&ps);

out_putn:
   Task_PutName(tmp);
out:
   return err;
}


SYSCALLDEF(sys_setxattr, char __user *path, char __user *name, void __user *value,
	        size_t size, int flags)
{
   return ixattr(0, path, name, value, size, flags, 0);
}

SYSCALLDEF(sys_lsetxattr, char __user *path, char __user *name, void __user *value,
	        size_t size, int flags)
{
   return ixattr(0, path, name, value, size, flags, 1);
}

static int
fxattr(int isGet, int fd, char __user *name, void __user *value, size_t size, int flags)
{
   int err = -EBADF;
   struct FileStruct *filp;

   filp = File_Get(fd);
   if (IS_ERR(filp)) {
      err = PTR_ERR(filp);
      goto out;
   }

   Inode_Lock(filp->dentry->parent->inode);

   if (isGet) {
      err = XattrGetHelper(filp->dentry, name, value, size);
   } else {
      err = XattrSetHelper(filp->dentry, name, value, size, flags);
   }

   Inode_Unlock(filp->dentry->parent->inode);

   File_Put(filp);
out:
   return err;
}

SYSCALLDEF(sys_fsetxattr, int fd, char __user *name, void __user *value, size_t size, int flags)
{   
   return fxattr(0, fd, name, value, size, flags);
}

SYSCALLDEF(sys_getxattr, char __user *path, char __user *name, void __user *value,
	        size_t size)
{
   return ixattr(1, path, name, value, size, 0, 0);
}

SYSCALLDEF(sys_lgetxattr, char __user *path, char __user *name, void __user *value,
	        size_t size)
{
   return ixattr(1, path, name, value, size, 0, 1);
}

SYSCALLDEF(sys_fgetxattr, int fd, char __user *name, void __user *value, size_t size)
{
   return fxattr(1, fd, name, value, size, 0);
}

static int
VFS_listxattr(struct DentryStruct *dentryp, char *klist, size_t size)
{
   int err = -EINVAL;
   struct InodeStruct *inodp = Dentry_Inode(dentryp);

   if (inodp->i_op->llistxattr) {
      err = inodp->i_op->llistxattr(dentryp, klist, size);
   }

   return err;
}

static int
XattrList(struct DentryStruct *dentryp, char __user *list, size_t size)
{
	ssize_t err;
	char *klist = NULL;

	if (size) {
		if (size > XATTR_LIST_MAX)
			size = XATTR_LIST_MAX;
		klist = malloc(size);
		if (!klist)
			return -ENOMEM;
	}

   err = VFS_listxattr(dentryp, klist, size);

	if (err > 0) {
		if (size && Task_CopyToUser(list, klist, err))
			err = -EFAULT;
	} else if (err == -ERANGE && size >= XATTR_LIST_MAX) {
		/* The file system tried to returned a list bigger
		   than XATTR_LIST_MAX bytes. Not possible. */
		err = -E2BIG;
	}

   ASSERT_COULDBE(klist == NULL);
   if (klist) {
      free(klist);
   }
   return err;
}

static int
ilistxattr(char __user *path, char __user *list, size_t size, int linkAttr)
{
   int err, lookupFlags;
   char *tmp;
   struct PathStruct ps;


   tmp = Task_GetName(path);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   lookupFlags = LOOKUP_LOCK | (linkAttr ? 0 : LOOKUP_FOLLOW);

   err = Path_Lookup(AT_FDCWD, tmp, lookupFlags, &ps);
   if (err) {
      goto out_putn;
   }

   err = XattrList(ps.dentry, list, size);

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

SYSCALLDEF(sys_listxattr, char __user *path, char __user *list, size_t size)
{
   return ilistxattr(path, list, size, 0);
}

SYSCALLDEF(sys_llistxattr, char __user *path, char __user *list, size_t size)
{
   return ilistxattr(path, list, size, 1);
}

SYSCALLDEF(sys_flistxattr, int fd, char __user *list, size_t size)
{
   int err = -EBADF;
   struct FileStruct *filp;

   filp = File_Get(fd);
   if (!IS_ERR(filp)) {
      goto out;
   }

   Inode_Lock(filp->dentry->parent->inode);

   err = XattrList(filp->dentry, list, size);

   Inode_Unlock(filp->dentry->parent->inode);

   File_Put(filp);
out:
   return err;
}


static int
VFS_removexattr(struct DentryStruct *dentryp, char *kname)
{
   int err = -EINVAL;
   struct InodeStruct *inodp = dentryp->inode;

   if (inodp->i_op->lremovexattr) {
      err = inodp->i_op->lremovexattr(dentryp, kname);
   }

   return err;
}

static int
XattrRemove(struct DentryStruct *dentryp, char __user *name)
{
	int err;
	char kname[XATTR_NAME_MAX + 1];

#if USE_NEW
	err = Task_UserStringNCopy(kname, name, sizeof(kname));
#else
	err = strncpy_from_user(kname, name, sizeof(kname));
#endif
	if (err == 0 || err == sizeof(kname))
		err = -ERANGE;
	if (err < 0)
		return err;

	return VFS_removexattr(dentryp, kname);
}

static int
iremovexattr(char __user *path, char __user *name, int linkAttr)
{
   int err, lookupFlags;
   struct PathStruct ps;
   char *tmp;

   tmp = Task_GetName(path);
   if (IS_ERR(tmp)) {
      err = PTR_ERR(tmp);
      goto out;
   }

   lookupFlags = LOOKUP_LOCK | (linkAttr ? 0 : LOOKUP_FOLLOW);

   err = Path_Lookup(AT_FDCWD, tmp, lookupFlags, &ps);
   if (err) {
      goto out_putn;
   }

   err = XattrRemove(ps.dentry, name);

   Path_Release(&ps);
out_putn:
   Task_PutName(tmp);
out:
   return err;
}

SYSCALLDEF(sys_removexattr, char __user *path, char __user *name)
{
   return iremovexattr(path, name, 0);
}

SYSCALLDEF(sys_lremovexattr, char __user *path, char __user *name)
{
   return iremovexattr(path, name, 1);
}

SYSCALLDEF(sys_fremovexattr, int fd, char __user *name)
{
   int err = -EBADF;
   struct FileStruct *filp;

   filp = File_Get(fd);
   if (IS_ERR(filp)) {
      err = PTR_ERR(filp);
      goto out;
   }

   Inode_Lock(filp->dentry->parent->inode);

   err = XattrRemove(filp->dentry, name);

   Inode_Unlock(filp->dentry->parent->inode);

   File_Put(filp);
out:
   return err;
}
