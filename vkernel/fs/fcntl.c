#include "vkernel/public.h"
#include "private.h"

void 
Fcntl_SetCloseOnExec(unsigned int fd, int flag)
{
	struct FilesStruct *files = current->files;
	struct FdTableStruct *fdt;

	Files_Lock(files);

	fdt = files->fdt;
	if (flag)
		FD_SET(fd, fdt->closeOnExec);
	else
		FD_CLR(fd, fdt->closeOnExec);

   Files_Unlock(files);
}

static int
FcntlGetCloseOnExec(unsigned int fd)
{
	struct FilesStruct *files = current->files;
	struct FdTableStruct *fdt;
	int res;

   Files_Lock(files);

	fdt = files->fdt;
	res = FD_ISSET(fd, fdt->closeOnExec);

   Files_Unlock(files);

	return res;
}

/*
 * The file flags determines the behavior of file objects with
 * respect to file operations.
 * For example, the flags determine issues such as, will the operation
 * block? Or will we get asynchronous notification if data
 * becomes available through a file object?
 *
 * The job of interpreting and implementing these parameters are
 * delegated to the device VFS calls. The Pipe and Linux device, for example,
 * simply invokes the Linux setfl syscall on its backing fd 
 * and lets the kernel
 * handle the flag changes and the task of providing appropriate
 * VFS operation return values and signals.
 */
static int
FcntlFlagOp(struct FileStruct *filp, int isSet, ulong flags)
{
   int oldFlags;

   ASSERT(File_IsLocked(filp));

   oldFlags = filp->flags;

   if (isSet) {
      filp->flags = flags;
   }

   return oldFlags;
}

static int
FcntlFlagsGet(struct FileStruct *filp)
{
   int flags;

   File_Lock(filp);

   flags = FcntlFlagOp(filp, 0, 0);

   File_Unlock(filp);

   return flags;
}


int
Fcntl_FlagsOp(struct FileStruct *filp, ulong flags, int op)
{
   int err;
   ulong newFlags;

   /* required for strict SunOS emulation */
   if (O_NONBLOCK != O_NDELAY)
      if (flags & O_NDELAY)
         flags |= O_NONBLOCK;

   /* Ensure that accesses to the file flags are deterministic. */
   File_Lock(filp);

#define SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | FASYNC | O_DIRECT | O_NOATIME)
   newFlags = filp->flags;
   switch (op) {
   case FCNTL_OP_SET:
      newFlags &= ~SETFL_MASK;
      newFlags |= (flags & SETFL_MASK);
      break;
   case FCNTL_OP_OR:
      newFlags |= (flags & SETFL_MASK);
      break;
   case FCNTL_OP_AND:
      newFlags &= (flags & SETFL_MASK);
      break;
   default:
      ASSERT(0);
      break;
   }

   if (!filp->f_op || !filp->f_op->setfl) {
      err = -EINVAL;
      goto out;
   }

   err = filp->f_op->setfl(filp, newFlags);

   /* XXX: why do we need to shadow the file flags? */
   if (!err) {
      FcntlFlagOp(filp, 1, newFlags);
   }

out:
   File_Unlock(filp);
   return err;
}

#if 0
static INLINE int 
flock_translate_cmd(int cmd) {
	if (cmd & LOCK_MAND)
		return cmd & (LOCK_MAND | LOCK_RW);
	switch (cmd) {
	case LOCK_SH:
		return F_RDLCK;
	case LOCK_EX:
		return F_WRLCK;
	case LOCK_UN:
		return F_UNLCK;
	}
	return -EINVAL;
}

/* Fill in a file_lock structure with an appropriate FLOCK lock. */
static int 
flock_make_lock(struct flock *fl, unsigned int cmd)
{
	int type = flock_translate_cmd(cmd);
	if (type < 0)
		return type;

   DEBUG_MSG(5, "cmd=%d type=%d\n", cmd, type);
	
	fl->l_type = type;
   fl->l_whence = SEEK_SET;
   fl->l_start = 0;
	fl->l_len = 0; /* 0 <==> OFFSET_MAX (see flock_to_posix_lock in Linux) */
	fl->l_pid = current->tgid;
	
	return 0;
}
#endif

/* 
 * sys_flock and the fcntl(F_GETLK/F_SETLK) are advisory locks
 * and are implemented identically in Linux.
 */
long 
sys_flock(unsigned int fd, unsigned int cmd)
{
   struct FileStruct *filp;
#if 0
   struct flock lock;
   int can_sleep, unlock;
#endif
   int err = -EBADF;

   filp = File_Get(fd);
   if (!filp) {
      goto out;
   }

#if 0
   can_sleep = !(cmd & LOCK_NB);
   cmd &= ~LOCK_NB;
   unlock = (cmd == LOCK_UN);

   if (!unlock && !(cmd & LOCK_MAND) && !(filp->accMode & 3)) {
      D__;
      goto out_putf;
   }

   err = flock_make_lock(&lock, cmd);
   if (err) {
      goto out_putf;
      D__;
   }
#endif

   if (filp->f_op && filp->f_op->lock) {
      err = filp->f_op->flock(filp, cmd);
      D__;
   } else {
      //error = flock_lock_file_wait(filp, lock);
      ASSERT_UNIMPLEMENTED(0);
   }

   File_Put(filp);
out:
   return err;
}

static long
FcntlGetLock(struct FileStruct *filp, struct flock __user * l) 
{
	struct flock flock;
	int err;

	err = -EFAULT;
	if (Task_CopyFromUser(&flock, l, sizeof(flock)))
		goto out;


   err = -EINVAL;
	if (filp->f_op && filp->f_op->lock) {
		err = filp->f_op->lock(filp, F_GETLK, &flock);
   } else {
      goto out;
   }

	err = -EFAULT;
	if (!Task_CopyToUser(l, &flock, sizeof(flock)))
		err = 0;
out:
	return err;
}

static long
FcntlSetLock(UNUSED uint vfd, struct FileStruct *filp, uint cmd, 
             const struct flock __user *l)
{
	struct flock flock;
	int err;

	err = -EFAULT;
	if (Task_CopyFromUser(&flock, l, sizeof(flock)))
		goto out;


   err = -EINVAL;
	if (filp->f_op && filp->f_op->lock) {
		err = filp->f_op->lock(filp, cmd, &flock);
   } else {
      goto out;
   }

out:
	return err;
}

static long
FcntlGetLock64(struct FileStruct *filp, struct flock64 __user * l) 
{
	struct flock64 flock;
	int err;

	err = -EFAULT;
	if (Task_CopyFromUser(&flock, l, sizeof(flock)))
		goto out;


   err = -EINVAL;
	if (filp->f_op && filp->f_op->lock) {
		err = filp->f_op->lock(filp, F_GETLK64, &flock);
   } else {
      goto out;
   }

	err = -EFAULT;
	if (!Task_CopyToUser(l, &flock, sizeof(flock)))
		err = 0;
out:
	return err;
}

static long
FcntlSetLock64(UNUSED uint vfd, struct FileStruct *filp, uint cmd, 
             const struct flock64 __user *l)
{
	struct flock64 flock;
	int err;

	err = -EFAULT;
	if (Task_CopyFromUser(&flock, l, sizeof(flock)))
		goto out;


   err = -EINVAL;
	if (filp->f_op && filp->f_op->lock) {
		err = filp->f_op->lock(filp, cmd, &flock);
   } else {
      goto out;
   }

out:
	return err;
}


static long
FcntlDo(uint vfd, uint cmd, ulong arg, struct FileStruct* file)
{
   long err = -EINVAL;

   switch (cmd) {
   case F_DUPFD:
      /* XXX: call the internal dup function, since we already
       * have a handle to FileStruct. */
      err = sys_dup(vfd);
      break;
   case F_GETFD:
      err = FcntlGetCloseOnExec(vfd) ? FD_CLOEXEC : 0;
      break;
   case F_SETFD:
      err = 0;
      Fcntl_SetCloseOnExec(vfd, arg & FD_CLOEXEC);
      break;
   case F_GETFL:
      err = FcntlFlagsGet(file);
      break;
   case F_SETFL:
      err = Fcntl_FlagsOp(file, arg, FCNTL_OP_SET);
      break;
   case F_GETLK:
      /* Determines whether lock is already held and if so returns info
       * about existing lock. */
      err = FcntlGetLock(file, (struct flock __user *) arg);
      break;
   case F_SETLK:
      /* Acquire a lock. If cannot be acquired, then returns -- does not
       * block. */
   case F_SETLKW:
      /* Like F_SETLK, but blocks if lock cannot be acquired. */
      err = FcntlSetLock(vfd, file, cmd, (struct flock __user *) arg);
      break;

   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   return err;
}


long
sys_fcntl64(uint vfd, uint cmd, ulong arg)
{
   struct FileStruct *file;
   SyscallRet err;

   err = -EBADF;
   file = File_Get(vfd);
   if (!file) {
      goto out;
   }

   DEBUG_MSG(5, "vfd=%d cmd=0x%x (%d)\n", vfd, cmd, cmd);

   switch (cmd) {
      /* MySql uses these, apparently. */
   case F_GETLK64:
      /* Determines whether lock is already held and if so returns info
       * about existing lock. */
      err = FcntlGetLock64(file, (struct flock64 __user *) arg);
      break;
   case F_SETLK64:
      /* Acquire a lock. If cannot be acquired, then returns -- does not
       * block. */
   case F_SETLKW64:
      /* Like F_SETLK, but blocks if lock cannot be acquired. */
      err = FcntlSetLock64(vfd, file, cmd, (struct flock64 __user *) arg);
      break;
   default:
      err = FcntlDo(vfd, cmd, arg, file);
      break;
   }

   File_Put(file);
out:
   return err;
}

long
sys_fcntl(uint vfd, uint cmd, ulong arg)
{
   return sys_fcntl64(vfd, cmd, arg);
}
