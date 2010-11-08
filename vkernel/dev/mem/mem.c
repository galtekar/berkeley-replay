#include "vkernel/public.h"
#include "private.h"

#define DEV_MINOR_NULL     3
#define DEV_MINOR_ZERO     5
#define DEV_MINOR_FULL     7
#define DEV_MINOR_RANDOM   8
#define DEV_MINOR_URANDOM  9


static void
Mem_InitInode(struct InodeStruct *inodp)
{
   /* We expect to inherit the underlying fs inode so that
    * we needn't define basic iops such as access for each
    * device. */
   ASSERT(inodp->i_op);

   switch (MINOR(Inode_RDev(inodp))) {
   case DEV_MINOR_NULL:
      inodp->f_op = &Null_Fops;
      break;
   case DEV_MINOR_RANDOM:
      inodp->f_op = &Random_Fops;
      break;
   case DEV_MINOR_URANDOM:
      inodp->f_op = &Random_Fops;
      break;
   case DEV_MINOR_FULL:
      inodp->f_op = &Full_Fops;
      break;
   case DEV_MINOR_ZERO:
      //inodp->f_op = &Zero_Fops;
      ASSERT_UNIMPLEMENTED(0);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   inodp->major = InodeMajor_Device;
}


static const struct DeviceStruct memDev = {
   .major = DEV_MAJOR_MEM,
   .init = &Mem_InitInode
};

static int
DevMem_Init()
{
   Device_Register(&memDev);

   return 0;
}

CORE_INITCALL(DevMem_Init);
