#pragma once

#include "compiler.h"

#include <bitset>


#define BTRACER_STATS 1

#define USE_RSB 1

#if BTRACER_STATS
#define STATS_ONLY(x) x
#else
#define STATS_ONLY(x)
#endif

#if USE_RSB
#define RSB_SIZE 128 /* gimp maxCallDepth=39 */
#endif

#define MAX_BRANCHES 50000

typedef ulong BucketType;

class Thread;


struct BranchInfoStruct {
   ulong pc;
#if BTRACER_STATS
   uint numBranches;
#endif
   uint idx;
   uint target;
   uint table;
   uchar shr;
};


class BranchIdMap : public bitset<MAX_BRANCHES> {
public:
   size_t get() {
      for (size_t i = 0; i < size(); i++) {
         if (!test(i)) {
            set(i, true);
            return i;
         }
      }

      /* XXX: need to increase MAX_BRANCHES */
      ASSERT_UNIMPLEMENTED(0);
   }

   void put(size_t pos) {
      set(pos, false);
   }
};

typedef pair<const ADDRINT, ulong> BranchPair;
class BranchPcMap : public map<ADDRINT, ulong> {
};

struct BtracerStruct {
   BucketType *buf;
   BucketType *bufPtr;
   int logFd;
   struct BranchInfoStruct branchInfo[MAX_BRANCHES];
#if BTRACER_STATS
   uint numCondDirect, numCondIDirect;
   uint numUncondDirect, numUncondIDirect;
   uint numUncondIDirectCalls, numUncondIDirectJumps, numRets;
   uint condMispredicts, btbMispredicts, rsbMispredicts;
   uint numCondExec, numCallExec, numRetExec, numBtbExec;
   int callDepth;
   int maxCallDepth;
#endif
#if USE_RSB
   uint rsb[RSB_SIZE];
   uint rsbIdx;
#endif
};

VOID Btracer_ThreadStart(struct BtracerStruct *);
VOID Btracer_ThreadEnd(struct BtracerStruct *);
VOID Btracer_Init();
VOID Btracer_Fini();
VOID Btracer_Clone(Thread *child);
VOID Btracer_ThreadStart(ThreadId pid);
VOID Btracer_ThreadFinish();
VOID Btracer_Instruction(INS ins);
