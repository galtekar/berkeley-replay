#include <errno.h>
#include <sys/ioctl.h>

#include "vkernel/public.h"
#include "private.h"

static long 
IoctlDo(struct FileStruct *filp, uint cmd, ulong arg)
{
   /* Linux returns -ENOTTY, not -EINVAL. So must we. */
	int error = -ENOTTY;

   ASSERT(filp->f_op);

   if (filp->f_op->ioctl) {
      error = filp->f_op->ioctl(filp, cmd, arg);
   }

   return error;
}

static int
FileIoctlDo(struct FileStruct *filp, uint cmd, ulong arg)
{
   switch (cmd) {
   case FIBMAP:
      /* XXX: get block size of inode */
   case FIGETBSZ:
      /* XXX: returns inode->size - filp->f_pos */
   case FIONREAD:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   return IoctlDo(filp, cmd, arg);
}

int 
VFS_ioctl(struct FileStruct *filp, UNUSED uint fd, uint cmd, ulong arg)
{
   int on, error = 0;

   DEBUG_MSG(5, "cmd=0x%x\n", cmd);

	switch (cmd) {
      /* XXX: Close-on-exec. */
   case FIOCLEX:
      Fcntl_SetCloseOnExec(fd, 1);
      break;
   case FIONCLEX:
      Fcntl_SetCloseOnExec(fd, 0);
      break;
      /* XXX: asynch io notification */
   case FIOASYNC:
      /* XXX: io queue size (??) */
   case FIOQSIZE:
      ASSERT_UNIMPLEMENTED(0);
      break;

   case FIONBIO:
      if ((error = __get_user(on, (int __user *)arg)) != 0) {
         break;
      }

      if (on) {
         error = Fcntl_FlagsOp(filp, O_NONBLOCK, FCNTL_OP_OR);
      } else {
         error = Fcntl_FlagsOp(filp, ~O_NONBLOCK, FCNTL_OP_AND);
      }
      break;
   default:
      if (S_ISREG(filp->dentry->inode->mode)) {
         /* For regular files. */
         error = FileIoctlDo(filp, cmd, arg);
      } else {
         /* For devices (e.g., pipes, ttys, sound cards, etc.) */
         error = IoctlDo(filp, cmd, arg);
      }
      break;
   }
   return error;
}

SYSCALLDEF(sys_ioctl, uint fd, uint cmd, ulong arg)
{
   struct FileStruct * filp;
   int error = -EBADF;

   filp = File_Get(fd);
   if (!filp)
      goto out;

   error = VFS_ioctl(filp, fd, cmd, arg);
   File_Put(filp);
out:
   return error;
}
