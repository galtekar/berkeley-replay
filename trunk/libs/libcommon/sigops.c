#include "sigops.h"
#include "syscall.h"
#include "linux.h"

const size_t SigOps_RtSigFrameSize = sizeof(struct rt_sigframe);

void 
SigOps_SetMask(sigset_t *mask, sigset_t *orig)
{
   int ret;

   ASSERT(orig || !orig);
   ASSERT(mask || !mask);
   ret = sigprocmask(SIG_SETMASK, mask, orig);
   ASSERT(ret == 0);
}

void 
SigOps_Mask(long mask, sigset_t *orig)
{
   sigset_t blockmask;
   int ret;

   SigOps_InitSet(&blockmask, mask);

   ASSERT(orig || !orig);
   ret = sigprocmask(SIG_SETMASK, &blockmask, orig);
   ASSERT(ret == 0);
}


int
SigOps_IsSubset(sigset_t* subset, sigset_t *set)
{
   sigset_t r;

   SigOps_AndSets(&r, subset, set);

   return (memcmp(subset, &r, _NSIG_BYTES) == 0);
}

int
SigOps_IsBlocked(ulong mask)
{
   int ret;
   sigset_t blockmask;
   sigset_t currset;

   SigOps_InitSet(&blockmask, mask);

   ret = sigprocmask(SIG_SETMASK, NULL, &currset);
   ASSERT(ret == 0);

   return SigOps_IsSubset(&blockmask, &currset);
}

int
SigOps_IsMask(ulong mask)
{
   int ret;
   sigset_t blockmask;
   sigset_t currset;

   SigOps_InitSet(&blockmask, mask);

   ret = sigprocmask(SIG_SETMASK, NULL, &currset);
   ASSERT(ret == 0);

   DEBUG_MSG(6, "blockmask=0x%x currset=0x%x mask=0x%x\n",
         blockmask.sig[0], currset.sig[0], mask);

   return SigOps_IsSubset(&blockmask, &currset) &&
      SigOps_IsSubset(&currset, &blockmask);
}
