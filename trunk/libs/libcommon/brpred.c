#include <string.h>

#include "public.h"

struct BranchNodeStruct*
BPred_GetBranch(struct BPred *btr, ulong insAddr)
{
   struct MapStruct *btrMap = btr->map;
   struct BranchNodeStruct *node = NULL;

   if (btrMap->size > MAX_BRANCHES) {
      /* XXX: remove and free all (?) the nodes,
       * but if we do this, we have to flush the
       * translation cache, since the node addresses
       * are burned into helper calls */
      ASSERT_UNIMPLEMENTED(0);
   } else {
      Map_Find(btrMap, map, insAddr, node);
   }

   if (!node) {
      node = SharedArea_Malloc(sizeof(*node));
      memset(node, 0, sizeof(*node));
      Map_NodeInit(&node->map, insAddr);

      Map_Insert(btrMap, map, insAddr, node);
   }

   return node;
}

/* Returns 1 if branch is predicted to be taken, 0 if predicted not taken. */
INLINE int
BPred_PredictBranch(struct BranchNodeStruct *brp)
{
   uint idx = brp->shr & 0xF;
   uchar tabIdx = idx*2;
   ASSERT(0 <= idx && idx < 16);
   uint mask = 0x3 << tabIdx;
   uchar pred = (brp->table & mask) >> tabIdx;
   ASSERT(pred <= 3);

   /* Is the 2-bit counter >= 2? Indicates a not-taken guess. */

   return !(pred & 0x2);
}

INLINE void
BPred_LearnBranch(struct BranchNodeStruct *brp, int isTaken)
{

   uint idx = brp->shr & 0xF;
   uchar tabIdx = idx*2;
   ASSERT(0 <= idx && idx < 16);
   uint mask = 0x3 << tabIdx;
   uchar pred = (brp->table & mask) >> tabIdx;
   ASSERT(pred <= 3);

   if (isTaken) { 
      if (pred > 0) {
         pred--;
         brp->table = (brp->table & ~mask) | ((uint)pred << tabIdx);
      }
      brp->shr = (brp->shr << 1) | 0x1;
   } else {
      if (pred < 3) {
         pred++;
         brp->table = (brp->table & ~mask) | ((uint)pred << tabIdx);
      }
      brp->shr = brp->shr << 1;
   }
}

INLINE ulong
BPred_PredictIndirectJump(struct BranchNodeStruct *brp)
{
   return brp->target;
}

INLINE void
BPred_LearnIndirectJump(struct BranchNodeStruct *brp, ulong actualTarget)
{
   if (brp->target != actualTarget) {
      brp->target = actualTarget;
   }
}

#if USE_RSB

#if STATS
#define PushToRSB() \
   bt->rsb[bt->rsbIdx] = retAddr; \
bt->rsbIdx = (bt->rsbIdx + 1) % RSB_SIZE; \
ASSERT(bt->rsbIdx < RSB_SIZE); \
   bt->callDepth++; \
   if (bt->callDepth > bt->maxCallDepth) { \
      bt->maxCallDepth = bt->callDepth; \
   } \
   STATS_ONLY(bt->numCallExec++;);
#else
#define PushToRSB() \
   bt->rsb[bt->rsbIdx] = retAddr; \
   bt->rsbIdx = (bt->rsbIdx + 1) % RSB_SIZE; \
   ASSERT(bt->rsbIdx < RSB_SIZE);
#endif

INLINE void 
BPred_LearnDirectCall(struct BPred *bt, ulong retAddr) 
{
   PushToRSB();
}


INLINE void
BPred_LearnIndirectCall(struct BPred *bt, 
      struct BranchNodeStruct *brp, ulong actualTarget, ulong retAddr)
{
   PushToRSB();

   if (brp->target != actualTarget) {
      brp->target = actualTarget;
   }
}

INLINE ulong
BPred_PredictRet(struct BPred *bt)
{
   int rsbIdx = (bt->rsbIdx - 1) % RSB_SIZE;
   ASSERT(rsbIdx < RSB_SIZE);


   return bt->rsb[rsbIdx];
}

INLINE void
BPred_LearnRet(struct BPred *bt)
{

   bt->rsbIdx = (bt->rsbIdx - 1) % RSB_SIZE;
   ASSERT(bt->rsbIdx < RSB_SIZE);
}
#endif

struct BPred*
BPred_Create()
{
   struct BPred *btr;

   btr = malloc(sizeof(*btr));
   memset(btr, 0, sizeof(*btr));

   btr->map = Map_Create(0);
   ASSERT(btr->map);

   ASSERT(btr);

   return btr;
}

void
BPred_Destroy(struct BPred *bt)
{
   struct BranchNodeStruct *node;

   ASSERT(bt);

#if STATS
   DEBUG_MSG(5,
         "Static stats:\n"
         "\tnumCondDirect=%u numCondIDirect=%u\n"
         "\tnumUncondDirect=%u numUncondIDirect=%u\n"
         "\tnumUncondIDirectCalls=%u numUncondIDirectJumps=%u numRets=%u\n"
         "Dynamic stats:\n"
         "\tnumCondExec=%u numBtbExec=%u numCallExec=%u numRetExec=%u\n"
         "\tcondMispredicts=%u btbMispredicts=%u rsbMispredicts=%u\n"
         "\tmaxCallDepth=%u\n",
         bt->numCondDirect, bt->numCondIDirect,
         bt->numUncondDirect, bt->numUncondIDirect,
         bt->numUncondIDirectCalls, bt->numUncondIDirectJumps, bt->numRets,
         bt->numCondExec, bt->numBtbExec, bt->numCallExec, bt->numRetExec,
         bt->condMispredicts, bt->btbMispredicts, bt->rsbMispredicts,
         bt->maxCallDepth
         );
#endif

   Map_Destroy(bt->map, map, node);

   free(bt);
}
