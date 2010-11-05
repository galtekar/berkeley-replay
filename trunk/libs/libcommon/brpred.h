#pragma once

#include "public.h"

#define USE_RSB 1

#if USE_RSB
#define RSB_SIZE 128 /* gimp maxCallDepth=39 */
#endif

/* 
 * This should the maximum number of static
 * branch locations a task is expected to execute.
 * This is not a hard upper limit -- we don't allocate
 * memory based on this amount, but serves as a sanity
 * check -- that is if we ever exceed this amount, then
 * we may need to start thinking about flushing
 * all the branch nodes, since we're talking about
 * a lot of memory.
 *
 * 50000 appears to be sufficient for sh and ls. */
#define MAX_BRANCHES 50000

typedef ulong BucketType;

struct BranchNodeStruct {
   struct MapField map;
#if STATS
   uint numBranches;
#endif
   uint idx;
   uint target;
   uint table;
   uchar shr;
};

struct BPred {
   struct MapStruct *map;
#if STATS
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

struct BranchNodeStruct*   BPred_GetBranch(struct BPred *btr, ulong insAddr);

/* Returns 1 if branch is predicted to be taken, 0 if predicted not taken. */
INLINE int     BPred_PredictBranch(struct BranchNodeStruct *brp);
INLINE void    BPred_LearnBranch(struct BranchNodeStruct *brp, int isTaken);
INLINE ulong   BPred_PredictIndirectJump(struct BranchNodeStruct *brp);
INLINE void    BPred_LearnIndirectJump(struct BranchNodeStruct *brp, ulong actualTarget);

#if USE_RSB
INLINE void       BPred_LearnDirectCall(struct BPred *bt, ulong retAddr);
INLINE void       BPred_LearnIndirectCall(struct BPred *bt, struct BranchNodeStruct *brp, 
                                             ulong actualTarget, ulong retAddr);
INLINE ulong                     BPred_PredictRet(struct BPred *bt);
INLINE void                      BPred_LearnRet(struct BPred *bt);
#endif

extern struct BPred*     BPred_Create();
extern void                      BPred_Destroy(struct BPred *bt);
