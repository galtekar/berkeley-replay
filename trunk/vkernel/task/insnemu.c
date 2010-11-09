#include "vkernel/public.h"
#include "private.h"

u64
InsnEmu_DoRDTSC()
{
	u64 val;

   if (!VCPU_IsReplaying()) {
      val = X86_rdtsc();

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(RDTSC) {
            entryp->time = val;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(RDTSC) {
         val = entryp->time;
      } END_WITH_LOG_ENTRY(0);
   }

   return val;
}
