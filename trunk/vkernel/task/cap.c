#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "vkernel/public.h"
#include "private.h"

int Cap_Flags = 0;
struct perfctr_info Cap_PerfInfo;
static int isCapInitialized = 0;

int
Cap_Test(int flag)
{
   ASSERT(isCapInitialized);
   return Cap_Flags & flag;
}

void
Cap_Set(int flag)
{
   ASSERT(isCapInitialized);
   Cap_Flags |= flag;
}

static void
Cap_BrCnt()
{
   /* Test for hardware branch counting support. 
    * Right now, that means looking for the perfctr
    * driver. */
   //LOG("de_enabled=%d vcpuMode=0x%x\n", VCPU_IsDEEnabled(), vcpuMode);
   if (VCPU_IsDEEnabled()) {
      int fd = open("/dev/perfctr", O_RDONLY);
      if( fd >= 0 ) {
         perfctr_info(fd, &Cap_PerfInfo);
         close(fd);

         LOG("KERNEL extensions available (%s) : ",
               perfctr_info_cpu_name(&Cap_PerfInfo));
         if (Cap_PerfInfo.cpu_features & PERFCTR_FEATURE_RDPMC) {
            LOG("rdpmc ");
            Cap_Flags |= CAP_HARD_BRCNT;
         }

         if (Cap_PerfInfo.cpu_features & PERFCTR_FEATURE_PCINT) {
            LOG("pmi ");
            Cap_Flags |= CAP_PMI;
         }

         /* Supported by Pentium IV and higher. */
         Cap_Flags |= CAP_FPUandTSC_EMU;
         LOG("sysemu\n");
      } else {
         LOG("KERNEL extensions not available (driver loaded?).\n");
      }
   } else {
      LOG("Direct execution disabled; no need for KERNEL extensions.\n");
   }
}

static int
Cap_Init()
{
   Cap_BrCnt();

   isCapInitialized = 1;

   return 0;
}

/* PRECORE because BrCnt subsystem is CORE and needs to
 * knows caps on init. */
PRECORE_INITCALL(Cap_Init);
