#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libcommon/compiler.h>
#include <libcommon/pmcops.h>
#include <libcommon/debug.h>

ullong startBrCnt = 0;
ullong iter = 0;
struct perfctr_info perfInfo;
struct vperfctr_control control;
struct vperfctr *perfCtr;
volatile const struct vperfctr_state *perfCtrKernelStatePtr;

extern void BrCntTest_Main();


void
BrCntTest_Check(ullong endBrCnt, ulong overhead, ulong N, ulong type)
{
   ullong pureDiff = (endBrCnt - startBrCnt);
   ullong compDiff = pureDiff - overhead;

#if 0
   if (overhead != 0) {
      printf("i=%llu pureDiff=%llu compDiff=%llu overhead=%d\n", iter, 
            pureDiff, compDiff, overhead);
   }
#endif

   if (compDiff != N) {
      printf("i=%llu startBrCnt=%llu endBrCnt=%llu compDiff=%llu N=%lu type=%lu overhead=%lu\n", 
            iter, startBrCnt, endBrCnt, compDiff, N, type, overhead);
      //ASSERT(overhead > 0);
   }
   //ASSERT(compDiff == N);

   iter++;
}

void
Init()
{
   perfCtr = vperfctr_open();

   if( perfCtr ) {
      vperfctr_info(perfCtr, &perfInfo);

      if (perfInfo.cpu_features & PERFCTR_FEATURE_RDPMC) {
         printf("RDPMC supported.\n");
      } else {
         printf("RDPMC not supported.\n");
         exit(-1);
      }

      if (perfInfo.cpu_features & PERFCTR_FEATURE_PCINT) {
         printf("PMI supported.\n");
      } else {
         printf("PMI not supported.\n");
      }

      perfCtrKernelStatePtr = perfCtr->kstate;
   } else {
      printf("PERFCTR extensions not available.\n");
      exit(-1);
   }

   PmcOps_SetupCounter(PMC_BR, &perfInfo, &control.cpu_control);

   if( vperfctr_control(perfCtr, &control) < 0 ) {
      FATAL("can't enable counter\n");
   }

   BrCntTest_Main();

   vperfctr_close(perfCtr);
}
