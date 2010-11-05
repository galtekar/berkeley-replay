#include "vkernel/public.h"
#include "private.h"

/* ----- Handles /dev/random and /dev/urandom ----- */

static int
Random_open(struct FileStruct *filp, int mode)
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
Random_release(struct FileStruct *filp)
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
Random_io(
      const int ioReqFlags, 
      const struct FileStruct *filp, 
      struct msghdr *kmsgp, 
      UNUSED const int flags, 
      loff_t pos)
{
   int err;

   err = ReadDet_io(ioReqFlags, filp, filp->rfd, kmsgp, 0, 0, pos);

   DEBUG_MSG(5, "err=%d\n", err);

   return err;
}


static int
Random_ioctl(UNUSED struct FileStruct *filp, uint cmd, UNUSED ulong arg)
{
   DEBUG_MSG(5, "cmd=0x%x\n", cmd);

   /* What kind of ioctls would one issue to these drivers? 
    * See linux/drivers/char/random.c . */
   switch (cmd) {
   case RNDGETENTCNT:
   case RNDADDTOENTCNT:
   case RNDADDENTROPY:
   case RNDZAPENTCNT:
   case RNDCLEARPOOL:
      ASSERT_UNIMPLEMENTED(0);
      break;
   default:
      return -EINVAL;
   }

   return 0;
}

static long
Random_fstat(struct FileStruct *filp, struct kstat64 *statp)
{
   return ReadDet_fstat(filp->rfd, statp);
}

static int
Random_llseek(struct FileStruct *filp, loff_t offset, int origin, loff_t *result)
{
   return ReadDet_llseek(filp->rfd, offset, origin, result);
}

const struct FileOps Random_Fops = {
   .open =     Random_open,
   .release =  Random_release,
   .io =       Random_io,
   .ioctl =    Random_ioctl,
   /* Neither /dev/urandom nor /dev/random drivers
    * permit memory mapping. */
   .mmap =     NULL,
   .fstat =    Random_fstat,
   .llseek =   Random_llseek,
};
