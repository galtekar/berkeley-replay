#include "vkernel/public.h"
#include "private.h"

/* Not really a device nor a filesystem. And doesn't really
 * belong in pipefs. Find this a better home. */

static int
Fifo_open(struct FileStruct *filp, int mode)
{
   int err;

   /* XXX: this may block, and so we'll want to give up the inode lock and 
    * reschedule until a reader arrives. */
   filp->orig_rfd = err = ReadDet_open(filp->dentry->name, filp->flags, mode);

   if (VCPU_IsReplaying()) {
      filp->rfd = -1;
   } else {
      filp->rfd = err;
   }

   return err;
}

static void
Fifo_release(struct FileStruct *filp)
{
   SysOps_Close(filp->rfd);
}

static ssize_t
Fifo_io(const int ioReqFlags, const struct FileStruct *filp, struct msghdr *kmsgp, 
        const int flags, loff_t pos)
{
   int err;

   err = ReadDet_io(ioReqFlags, filp, filp->rfd, kmsgp, flags, 0, pos);

   return err;
}

static int
Fifo_fsync(struct FileStruct *filp, int datasync)
{
   int err;

   err = ReadDet_fsync(filp->rfd, datasync);

   return err;
}

static int
Fifo_setfl(struct FileStruct *filp, int flags)
{
   int err;

   err = ReadDet_setfl(filp->rfd, flags);

   return err;
}

static int
Fifo_select(const struct FileStruct *filP, const int is_read, const int should_block)
{
   ASSERT_UNIMPLEMENTED(0);
   return 0;
}

const struct FileOps Fifo_Fops = {
   .llseek =   &no_llseek,
   .open =     &Fifo_open,
   .release =  &Fifo_release,
   .io =       &Fifo_io,
   .fsync =    &Fifo_fsync,
   .setfl =    &Fifo_setfl,
   .select =   &Fifo_select,
};
