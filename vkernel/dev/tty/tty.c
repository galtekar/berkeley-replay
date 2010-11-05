#include "vkernel/public.h"
#include "private.h"


static void
Tty_InitInode(struct InodeStruct *inodp)
{
   inodp->i_op =  &RdTty_Iops;
   inodp->f_op =  &RdTty_Fops;
   inodp->major = InodeMajor_Device;
}

static const struct DeviceStruct ttyDev = {
   .major = DEV_MAJOR_TTY, 
   .init = &Tty_InitInode
};

static const struct DeviceStruct ttySynDev = {
   .major = DEV_MAJOR_TTYSYN, 
   .init = &Tty_InitInode
};

static const struct DeviceStruct unix98ptmx_dev = {
   /* Same major # as tty. */
   .major = DEV_MAJOR_PTMX,
   .init = &Tty_InitInode
};

static const struct DeviceStruct unix98pts_dev = {
   .major = DEV_MAJOR_UNIX98PTS,
   .init = &Tty_InitInode
};


static int
DevTty_Init()
{
   Device_Register(&ttyDev);
   Device_Register(&ttySynDev);

   Device_Register(&unix98ptmx_dev);
   Device_Register(&unix98pts_dev);

   return 0;
}

DEVICE_INITCALL(DevTty_Init);
