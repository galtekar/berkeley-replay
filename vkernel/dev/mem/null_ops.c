#include "vkernel/public.h"
#include "private.h"

static int
Null_open(struct FileStruct *filp, int mode)
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
Null_release(struct FileStruct *filp)
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

static ssize_t
Null_io(const int isRead, UNUSED const struct FileStruct *filp, 
        struct msghdr *kmsgp, UNUSED const int flags, UNUSED loff_t pos)
{
   uint i;
   ssize_t totLen = 0;

   for (i = 0; i < kmsgp->msg_iovlen; i++) {
      totLen += kmsgp->msg_iov[i].iov_len;
   }

   return isRead ? 0 /* 0 = EOF */ : totLen;
}

static int
Null_llseek(struct FileStruct * filp, UNUSED loff_t offset, UNUSED int orig,
            loff_t *result)
{
   /* NOTE: "=" is not an error --- see Linux/drivers/char/mem.c:null_lseek */
   *result = (filp->pos = 0);

   return 0;
}

static long
Null_fstat(struct FileStruct *filp, struct kstat64 *statp)
{
   return ReadDet_fstat(filp->rfd, statp);
}

const struct FileOps Null_Fops = {
   /* No need for .open, sinc reads and writes return simple
    * values. */
   .open =     Null_open,
   .release =  Null_release,
   .llseek =   Null_llseek,
   .io =       Null_io,
   /* Linux does not permit mmapping /dev/null. */
   .mmap =     NULL,
   .fstat =    Null_fstat,
};
