#include "vkernel/public.h"
#include "private.h"

static int 
VFS_readdir(struct FileStruct *file, filldir_t filler, void *buf, size_t size)
{
   int res = -ENOTDIR;
   if (!file->f_op || !file->f_op->readdir) {
      goto out;
   }

   res = file->f_op->readdir(file, buf, filler, size);

out:
   return res;
}

#define NAME_OFFSET(de) ((int) ((de)->d_name - (char __user *) (de)))
#undef ROUND_UP
#define ROUND_UP(x) (((x)+sizeof(long)-1) & ~(sizeof(long)-1))

struct old_linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_offset;
	unsigned short	d_namlen;
	char		d_name[1];
};

struct readdir_callback {
	struct old_linux_dirent __user * dirent;
	int result;
};

static int 
fillonedir(void * __buf, const char * name, int namlen, loff_t offset,
		     ino_t ino, UNUSED unsigned int d_type)
{
	struct readdir_callback * buf = (struct readdir_callback *) __buf;
	struct old_linux_dirent __user * dirent;
	unsigned long d_ino;

	if (buf->result)
		return -EINVAL;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino)
		return -EOVERFLOW;
	buf->result++;
	dirent = buf->dirent;
#if 0
	if (!access_ok(VERIFY_WRITE, dirent,
			(unsigned long)(dirent->d_name + namlen + 1) -
				(unsigned long)dirent))
		goto efault;
#endif
	if (	__put_user(d_ino, &dirent->d_ino) ||
		__put_user(offset, &dirent->d_offset) ||
		__put_user(namlen, &dirent->d_namlen) ||
		Task_CopyToUser(dirent->d_name, (char*)name, namlen) ||
		__put_user(0, dirent->d_name + namlen))
		goto efault;
	return 0;
efault:
	buf->result = -EFAULT;
	return -EFAULT;
}

SYSCALLDEF(sys_old_readdir, uint fd, struct old_linux_dirent __user * dirent,
           uint count)
{
   int error;
   struct FileStruct * file;
   struct readdir_callback buf;

   error = -EBADF;
   file = File_Get(fd);
   if (!file)
      goto out;

   buf.result = 0;
   buf.dirent = dirent;

   error = VFS_readdir(file, fillonedir, &buf, count);
   if (error >= 0)
      error = buf.result;

   File_Put(file);
out:
   return error;
}

/*
 * New, all-improved, singing, dancing, iBCS2-compliant getdents()
 * interface. 
 */
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

struct getdents_callback {
   struct linux_dirent __user * current_dir;
   struct linux_dirent __user * previous;
   int count;
   int error;
};

static int
filldir(void *__buf, const char *name, int namlen, loff_t offset, ino_t ino,
        uint d_type)
{
   struct linux_dirent __user * dirent;
   struct getdents_callback * buf = (struct getdents_callback *) __buf;
   //ulong d_ino;
   int reclen = ROUND_UP(NAME_OFFSET(dirent) + namlen + 2);

   buf->error = -EINVAL;
   if (reclen > buf->count) {
      return -EINVAL;
   }
   dirent = buf->previous;
   if (dirent) {
      if (__put_user(offset, &dirent->d_off)) {
         goto efault;
      }
   }
   dirent = buf->current_dir;
   if (__put_user(ino, &dirent->d_ino)) {
      goto efault;
   }
   if (__put_user(reclen, &dirent->d_reclen)) {
      goto efault;
   }
   if (Task_CopyToUser(dirent->d_name, (char*)name, namlen)) {
      goto efault;
   }
   if (__put_user(0, dirent->d_name + namlen)) {
      goto efault;
   }
   if (__put_user(d_type, (char __user *) dirent + reclen - 1)) {
      goto efault;
   }
   buf->previous = dirent;
   dirent = (void __user *)dirent + reclen;
   buf->current_dir = dirent;
   buf->count -= reclen;
   return 0;
efault:
   buf->error = -EFAULT;
   return -EFAULT;
}

SYSCALLDEF(sys_getdents, uint vfd, struct linux_dirent __user*
           dirent, uint count)
{
   struct FileStruct *file;
   //struct InodeStruct *inode;
   struct getdents_callback buf;
   struct linux_dirent __user * lastdirent;
   int error;

   error = -EBADF;
   file = File_Get(vfd);
   if (!file) { goto out; }

   buf.current_dir = dirent;
   buf.previous = NULL;
   buf.count = count;
   buf.error = 0;

   error = VFS_readdir(file, filldir, &buf, buf.count);
   if (error < 0) {
      goto out_putf;
   }
   error = buf.error;
   lastdirent = buf.previous;
   if (lastdirent) {
      if (__put_user(file->pos, &lastdirent->d_off))
         error = -EFAULT;
      else
         error = count - buf.count;
   }

out_putf:
   File_Put(file);
out:
   return error;
}

#define ROUND_UP64(x) (((x)+sizeof(u64)-1) & ~(sizeof(u64)-1))

struct linux_dirent64 {
	u64		d_ino;
	s64		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[0];
};

struct getdents_callback64 {
   struct linux_dirent64 __user * current_dir;
   struct linux_dirent64 __user * previous;
   int count;
   int error;
};

static int
filldir64(void *__buf, const char *name, int namlen, 
          loff_t offset, ino_t ino, uint d_type)
{
   struct linux_dirent64 __user *dirent;
   struct getdents_callback64 * buf = (struct getdents_callback64 *) __buf;
   /* The record size is variable: depends on the length of the 
    * directory name. */
   int reclen = ROUND_UP64(NAME_OFFSET(dirent) + namlen + 1);

   buf->error = -EINVAL;	/* only used if we fail.. */
   if (reclen > buf->count)
      return -EINVAL;
   dirent = buf->previous;
   if (dirent) {
      if (__put_user(offset, &dirent->d_off))
         goto efault;
   }
   dirent = buf->current_dir;
   if (__put_user(ino, &dirent->d_ino))
      goto efault;
   if (__put_user(0, &dirent->d_off))
      goto efault;
   if (__put_user(reclen, &dirent->d_reclen))
      goto efault;
   if (__put_user(d_type, &dirent->d_type))
      goto efault;
   if (Task_CopyToUser(dirent->d_name, (char*)name, namlen))
      goto efault;
   if (__put_user(0, dirent->d_name + namlen))
      goto efault;
   buf->previous = dirent;
   dirent = (void __user *)dirent + reclen;
   buf->current_dir = dirent;
   buf->count -= reclen; /* buf->count is size of target mem */
   return 0;
efault:
   buf->error = -EFAULT;
   return -EFAULT;
}

SYSCALLDEF(sys_getdents64, uint vfd, struct linux_dirent64 __user * dirent, uint count)
{
   struct FileStruct * file;
	struct linux_dirent64 __user * lastdirent;
	struct getdents_callback64 buf;
	int error;

	error = -EFAULT;
#if 0
   /*
    * XXX
    */
	if (!access_ok(VERIFY_WRITE, dirent, count))
		goto out;
#endif

	error = -EBADF;
	file = File_Get(vfd);
	if (!file)
		goto out;

	buf.current_dir = dirent;
	buf.previous = NULL;
	buf.count = count;
	buf.error = 0;

	error = VFS_readdir(file, filldir64, &buf, buf.count);
	if (error < 0)
		goto out_putf;
	error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		typeof(lastdirent->d_off) d_off = file->pos;
		error = -EFAULT;
		if (__put_user(d_off, &lastdirent->d_off))
			goto out_putf;
		error = count - buf.count;
	}

out_putf:
   File_Put(file);
out:
	return error;
}
