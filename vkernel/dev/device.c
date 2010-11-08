#include "vkernel/public.h"

#define MAX_DEVICES 256

SHAREDAREA devinit_t deviceTable[MAX_DEVICES] = { NULL, };

void
Device_Register(const struct DeviceStruct *devp)
{
   ASSERT(devp->major < MAX_DEVICES);

   deviceTable[devp->major] = devp->init;
}

void
Device_InitInode(struct InodeStruct *inodp, ulong rdev)
{
   devinit_t initcb = NULL;
   int major = MAJOR(rdev);

   DEBUG_MSG(5, "major=%d minor=%d\n", major, MINOR(rdev));
   ASSERT(major < MAX_DEVICES);
   initcb = deviceTable[major];

   /* Is the device major supported? */
   ASSERT_UNIMPLEMENTED(initcb);

   initcb(inodp);
}
