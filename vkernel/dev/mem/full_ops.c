#include "vkernel/public.h"
#include "private.h"

static int
Full_open(struct FileStruct *filp, int mode)
{
   int err;

   filp->orig_rfd = err = ReadDet_open(File_Name(filp), filp->flags, mode);

   if (VCPU_IsReplaying()) {
      filp->rfd = -1;
   } else {
      filp->rfd = filp->orig_rfd;
   }

   return err;
}

static void
Full_release(struct FileStruct *filp)
{
   int err;

   if (filp->rfd >= 0) {
      ASSERT(!VCPU_IsReplaying());
      err = SysOps_Close(filp->rfd);
      ASSERT(!err);
      filp->rfd = -1;
   } else {
      ASSERT(VCPU_IsReplaying());
   }
}

/* Linux driver zeros out the user buffer, so we must emulate. */
static ssize_t
DevMemReadZero(UNUSED const struct FileStruct *filp, struct msghdr *kmsgp, 
                UNUSED const int flags)
{
   uint i;
   ssize_t written = 0;

   for (i = 0; i < kmsgp->msg_iovlen; i++) {
      ssize_t len = kmsgp->msg_iov[i].iov_len;
      ssize_t unwritten;

      if (!len) {
         continue;
      }

      unwritten = Task_ClearUser(kmsgp->msg_iov[i].iov_base, len);
      if (unwritten) {
         written = -EFAULT;
         goto out;
      }

      written += len;
   }

out:
   return written;
}

static ssize_t
Full_io(const int isRead, const struct FileStruct *filp, struct msghdr *kmsgp, 
        const int flags, UNUSED loff_t pos)
{
   ssize_t err;

   if (isRead) {
      err = DevMemReadZero(filp, kmsgp, flags);
   } else {
      err = -ENOSPC;
   }

   return err;
}

static long
Full_fstat(struct FileStruct *filp, struct kstat64 *statp)
{
   return ReadDet_fstat(filp->rfd, statp);
}

static int
Full_llseek(struct FileStruct *filp, loff_t offset, int origin, loff_t *result)
{
   return ReadDet_llseek(filp->rfd, offset, origin, result);
}

const struct FileOps Full_Fops = {
   .open =     Full_open,
   .release =  Full_release,
   .llseek =   Full_llseek,
   .io =       Full_io,
   /* Linux does not permit mmapping /dev/full. */
   .mmap =     NULL,
   .fstat =    Full_fstat,
};
