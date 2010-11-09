#pragma once

#include "public.h"

extern SHAREDAREA struct MapStruct *tntMemMap;
extern SHAREDAREA struct SynchLock tntMemLock;


extern int isTaintInitialized;

extern void
TaintMap_IRStmt(IRSB *bbOut, IRStmt *st);
extern void
TaintMapFlowCopy(HWord dstKey, HWord srcKey, HWord len);
extern void 
TaintMapFlowUnary(HWord op, HWord dstKey, HWord dstLen, 
                HWord srcKey, HWord srcLen);
extern void 
TaintMapFlowBinary(HWord op, HWord dstKey, HWord dstLen, 
                 HWord srcKey1, HWord src1Len, 
                 HWord srcKey2, HWord src2Len);
extern void 
TaintMapFlowTrinary(HWord dstKey, HWord dstLen, 
                  HWord condVal, HWord condKey, HWord condLen, 
                  HWord trueKey, HWord trueLen,
                  HWord falseKey, HWord falseLen);
extern void
TaintMapFlowLoad(TaskRegs *vex, HWord locKey, HWord locLen,
                 HWord dstKey, HWord srcKey, HWord len);
extern void
TaintMapFlowStore(TaskRegs *vex, HWord locKey, HWord locLen,
                  HWord dstKey, HWord srcKey, HWord len);

#if STATS
extern void
TaintMapFlowExit(TaskRegs *vex, HWord guardKey, HWord guardLen);
#endif


struct TaintNode {
   /* @key must be 64 bits to accommodate our 64-bit global addresses */
   MAP_HEADER64();

   /* Origins that influenced this data location. */
   struct TaintSet set;
};

static INLINE struct TaintNode*
TaintNodeFind(struct MapStruct *map, u64 key)
{
   struct TaintNode *node = NULL;

#if DEBUG
   if (map == tntMemMap) {
      ASSERT(Synch_IsLocked(&tntMemLock));
   }
#endif

   return Map_Find64(map, key, node);
}

static INLINE struct TaintNode*
TaintMapAddNode(struct MapStruct *map, u64 key)
{
   struct TaintNode *node = NULL;

#if DEBUG
   if (map == tntMemMap) {
      u32 vaddr = (u32) key;

      ASSERT(Synch_IsLocked(&tntMemLock));

      if (GlobalAddr_IsMemAddr(key)) {
         /* Lower 32-bits should be a valid user-space virtual address. */
         ASSERT(Task_IsAddrInUser(vaddr));
      }
   }
#endif

   /* No need for duplicates. */
   node = TaintNodeFind(map, key);

   if (!node) {
      node = SharedArea_Malloc(sizeof(*node)); 
      node->key = key;
      node->data = NULL;

      Map_Insert64(map, key, node);
   }

   return node;
}
