#include "vkernel/public.h"
#include "private.h"

/*
 * Data structures:
 *
 * The main data structure is a conceptual hashtable that maps from memory
 * locations to a bit indicating whether the address is tainted or not.
 * The implementation of the hashtable is such that the bit is actually
 * a hash node with additional details about the tainted location.
 *
 * In practice, we have two hashtables. One that maps from addresses
 * in RAM to taint nodes and another that maps from locations in
 * thread state (registers, temps) to taint nodes. We have two for
 * simplicity and performance -- it avoids the need for a local-state
 * address encoding scheme and the need to lock all hashtable accesses
 * (accesses to thread-local state needn't be locked).
 *
 * All memory locations (global and thread-local) are addressed at
 * byte granularity and taint is propagated at that granularity as well.
 */

#define TAINT_DEBUG 1

#if TAINT_DEBUG

#define TAINT_MSG(s, ...) \
   lprintf(CURRENT_LFD, "Taint --- " s, ##__VA_ARGS__);

#else
#error "XXX"
#endif


#define KEY2STR(key) \
   (TaintMap_IsKeyTmp(key) ? "t" : \
    (TaintMap_IsKeyReg(key) ? "r" : \
     (TaintMap_IsKeyConst(key) ? "c" : "m")))

/*
 * -----------------------------------------------------------
 * TaintMapTaintByte ---
 *
 * Summary:
 *
 *    Taints the byte at location @transDestKey. If the key
 *    represents a location in RAM, then it should be the
 *    global address for that location.
 *
 * -----------------------------------------------------------
 */
static struct TaintNode*
TaintMapTaintByte(struct MapStruct *map, u64 transDestKey, struct TaintSet *set) {
   struct TaintNode *node = NULL;

#if DEBUG
   ASSERT(set);
   ASSERT(!TaintSet_IsEmpty(set));
#endif


   if (map == tntMemMap) {
      SYNCH_LOCK(&tntMemLock);
   }


   node = TaintNodeFind(map, transDestKey);

   if (!node) {
      DEBUG_MSG(7, "Inserting key 0x%16.16llx\n", transDestKey);
      node = TaintMapAddNode(map, transDestKey);
   } else {
      DEBUG_MSG(7, "Key 0x%16.16llx is already in map.\n",
                transDestKey);
      /* It's already symbolic, so no need to allocate a
       * new node. But note that we're about to replace the
       * token set of the current node with a potentially different
       * token set. */

      STATS_ONLY(TaintSet_StatOp(&node->set, StatOp_Dec, TTOK_STAT_REF);)
   }

   /* Record the racing access that influences this byte. */
   TaintSet_Copy(&node->set, set);

   STATS_ONLY(TaintSet_StatOp(&node->set, StatOp_Inc, TTOK_STAT_REF);)

   ASSERT(node->key == transDestKey);


   if (map == tntMemMap) {
      SYNCH_UNLOCK(&tntMemLock);
   }

   return node;
}

static void
TaintMapTaintByteAndInitNode(struct MapStruct *map, u64 gaddr,
                             struct TaintSet *set)
{
   struct TaintNode *node = NULL;

   /* Not all bytes of a src extent need be tainted. */
   if (!TaintSet_IsEmpty(set)) {
      node = TaintMapTaintByte(map, gaddr, set);
   }
}

static void
TaintMapTaintMem(HWord dstKey, struct TaintExtent *srcExt)
{
   int i;
#if DEBUG
   ASSERT(TaintMap_IsKeyMem(dstKey));
#endif

   /* CAREFUL: Don't hold the taintMemLock and then acquire
    * the vma lock (which GlobalAddr_FromVirt()) does as that
    * will deadlock with the code in TaintMapVmaUnmap(), which
    * tries to acquire the taintMemLock while holding the
    * vma lock.
    *
    * So don't do this:
    *
    *    Synch_Lock(&tntMemLock);
    *
    */

   for (i = 0; i < srcExt->len; i++) {
      u64 transKey = GlobalAddr_FromVirt(dstKey + i, 0);

      DEBUG_MSG(7, "transKey=0x%16.16llx\n", transKey);

      TaintMapTaintByteAndInitNode(tntMemMap, transKey, &srcExt->set[i]);
   }

   /* ... and continuing from above, don't do this:
    *    Synch_Unlock(&tntMemLock);
    */
}

static void
TaintMapTaintLocal(HWord dstKey, struct TaintExtent *srcExt)
{
   int i;

   ASSERT(TaintMap_IsKeyReg(dstKey) ||
          TaintMap_IsKeyTmp(dstKey));

   for (i = 0; i < srcExt->len; i++) {
      TaintMapTaintByteAndInitNode(current->tntMap, dstKey + i, &srcExt->set[i]);
   }
}

/*
 * -----------------------------------------------------------
 *  TaintMap_TaintKey ---
 *
 *  Summary:
 *
 *  How we taint and what hastable we update depends on the
 *  type of the target location being tainted.
 *
 * -----------------------------------------------------------
 */
void
TaintMap_TaintKey(HWord dstKey, struct TaintExtent *srcExt)
{
#if TAINT_DEBUG
   /* At least one of the bytes in the source extend must be
    * tainted by at least 1 taint token. But note that not
    * all bytes of the srcExt need be tainted. */
   struct TaintSet set;
   int i;

   TaintExtent_ToSet(&set, srcExt);
   ASSERT(!TaintSet_IsEmpty(&set));

   TAINT_MSG("dest: %s%d/0x%x -- srcExt: %d\n",
             KEY2STR(dstKey),
             TaintMap_Key2Loc(dstKey),
             TaintMap_Key2Loc(dstKey),
             srcExt->len);
   for (i = 0; i < srcExt->len; i++) {
      TAINT_MSG("%d: (%d) -- 0x%x, ...\n", i, srcExt->set[i].size,
                srcExt->set[i].origin[0]);
   }
#endif

   ASSERT(isTaintInitialized);

   if (TaintMap_IsKeyReg(dstKey) ||
         TaintMap_IsKeyTmp(dstKey)) {
      TaintMapTaintLocal(dstKey, srcExt);
   } else if (TaintMap_IsKeyMem(dstKey)) {
      TaintMapTaintMem(dstKey, srcExt);
   } else {
      /* Can't propagate taint to a const or origin. */
      ASSERT(0);
   }
}


/*
 * -----------------------------------------------------------
 * TaintMapUntaintByte ---
 *
 * Summary:
 *
 *    Removes the taint at the given byte.
 *
 * -----------------------------------------------------------
 */

static void
TaintMapPrintUntaintOp(HWord dstKey, size_t len)
{
   TAINT_MSG("0x%x -- dest: %s%d/0x%x len: %d\n",
             Task_GetCurrentRegs()->R(eip),
             KEY2STR(dstKey),
             TaintMap_Key2Loc(dstKey),
             TaintMap_Key2Loc(dstKey),
             len
            );
}

static void
TaintMapUntaintByte(struct MapStruct *map, u64 transDestKey)
{
   struct TaintNode *node;

   ASSERT_KPTR(map);

   if (map == tntMemMap) {
      SYNCH_LOCK(&tntMemLock);
   }

   node = TaintNodeFind(map, transDestKey);

   if (node) {
      STATS_ONLY(TaintSet_StatOp(&node->set, StatOp_Dec, TTOK_STAT_REF);)

      Map_Remove(map, node);
      SharedArea_Free(node, sizeof(*node));
      node = NULL;
   }

   if (map == tntMemMap) {
      SYNCH_UNLOCK(&tntMemLock);
   }
}


static void
TaintMapUntaintMem(HWord dstKey, size_t len)
{
   int i;

   ASSERT(TaintMap_IsKeyMem(dstKey));

   /* The memory symolic map is shared among all tasks
    * in the system. */

   for (i = 0; i < len; i++) {
      /* Assumption: called when writing to memory. */
      u64 gaddr = GlobalAddr_FromVirt(dstKey + i, 0);
      TaintMapUntaintByte(tntMemMap, gaddr);
   }
}

static void
TaintMapUntaintLocal(HWord dstKey, size_t len)
{
   int i;

   ASSERT(TaintMap_IsKeyReg(dstKey) || TaintMap_IsKeyTmp(dstKey));

   /* No locking necessary since we are updated the
    * task-local symbolic map. */

   for (i = 0; i < len; i++) {
      TaintMapUntaintByte(current->tntMap, dstKey + i);
   }
}

static void
TaintMapUntaintKey(HWord dstKey, struct TaintExtent *dstExt)
{
   size_t len = dstExt->len;

   TaintMapPrintUntaintOp(dstKey, len);

   if (TaintMap_IsKeyReg(dstKey) || TaintMap_IsKeyTmp(dstKey)) {
      TaintMapUntaintLocal(dstKey, len);
   } else {
      ASSERT(TaintMap_IsKeyMem(dstKey));
      TaintMapUntaintMem(dstKey, len);
   }
}

int
TaintMapIsByteTainted(struct TaintSet *set, struct MapStruct *map, u64 transKey)
{
   struct TaintNode *node;

   if (map == tntMemMap) {
      SYNCH_LOCK(&tntMemLock);
   }

   node = TaintNodeFind(map, transKey);

   if (node) {
      if (set) {
         *set = node->set;
      }
      ASSERT(set->size > 0);
   } else {
      if (set) {
         set->size = 0;
      }
   }

   if (map == tntMemMap) {
      SYNCH_UNLOCK(&tntMemLock);
   }

   return node != NULL;
}

static int
TaintMapIsMemTainted(HWord key, size_t len, struct TaintExtent *extp)
{
   int i, isTainted = 0;

   ASSERT(TaintMap_IsKeyMem(key));
   ASSERT(extp || !extp);

   for (i = 0; i < len; i++) {
      /* Assumption: called when reading from memory. */
      u64 gaddr = GlobalAddr_FromVirt(key + i, 1);
      if (TaintMapIsByteTainted(extp ? &extp->set[i] : NULL,
                                tntMemMap, gaddr)) {
         isTainted = 1;
      }
   }

   if (extp) {
      extp->len = isTainted ? len : 0;
   }

   return isTainted;
}

static int
TaintMapIsLocalTainted(HWord key, size_t len, struct TaintExtent *extp)
{
   int i, isTainted = 0;

   ASSERT(TaintMap_IsKeyReg(key) || TaintMap_IsKeyTmp(key));
   ASSERT(extp || !extp);

   /* No locking necessary since we are updating the
    * task-local symbolic map. */

   for (i = 0; i < len; i++) {
      if (TaintMapIsByteTainted(extp ? &extp->set[i] : NULL,
                                current->tntMap, key + i)) {
         isTainted = 1;
      }
   }

   if (extp) {
      extp->len = isTainted ? len : 0;
   }

   return isTainted;
}

static int
TaintMapGetRangeExtent(HWord key, size_t len, struct TaintExtent *extp)
{
   ASSERT(isTaintInitialized);
   ASSERT(extp || !extp);

   if (TaintMap_IsKeyReg(key) || TaintMap_IsKeyTmp(key)) {
      return TaintMapIsLocalTainted(key, len, extp);
   } else if (TaintMap_IsKeyMem(key)) {
      return TaintMapIsMemTainted(key, len, extp);
   } else if (TaintMap_IsKeyOrigin(key)) {
      /* Origins are the source of all taint, and hence always tainted. */
      ASSERT(0);
      return 1;
   } else {
      ASSERT(TaintMap_IsKeyConst(key));
      /* Constants and origins are never tainted, although
       * the latter can be a source of taint. */
      if (extp) {
         extp->len = 0;
      }
      return 0;
   }
}

/*
 * -----------------------------------------------------------
 *  TaintMap_GetRangeExtent ---
 *
 *  Summary:
 *
 *  Get the set of origins associated with a given key
 *  range.
 *
 *  Params:
 *    @extp -- OUT: origin pointers for given range
 *    @key  -- IN: start of the key range
 *    @len  -- IN: length of the key range
 *
 *  Return:
 *    1 iff key range is tainted, 0 otherwise
 *
 * -----------------------------------------------------------
 */
int
TaintMap_GetRangeExtent(HWord key, size_t len, struct TaintExtent *extp)
{
   ASSERT(extp);

   return TaintMapGetRangeExtent(key, len, extp);
}

/*
 * -----------------------------------------------------------
 *  TaintMap_IsRangeTainted ---
 *
 *  Summary:
 *
 *  Is any byte in the given key range tainted?
 *
 *  Params:
 *    @extp -- OUT: origin pointers for given range
 *    @key  -- IN: start of the key range
 *    @len  -- IN: length of the key range
 *
 *  Return:
 *    1 iff key range is tainted, 0 otherwise
 *
 * -----------------------------------------------------------
 */
int
TaintMap_IsRangeTainted(HWord key, size_t len)
{
   return TaintMapGetRangeExtent(key, len, NULL);
}


static void
TaintMapPrintTaintUnary(HWord dstKey, HWord dstLen, HWord srcKey, HWord srcLen)
{
   TAINT_MSG(
      "0x%x -- dest: %s%8.8d/0x%8.8x (%2.2d) <-- src: %s%8.8d/0x%8.8x (%2.2d)\n",
      Task_GetCurrentRegs()->R(eip),
      KEY2STR(dstKey),
      TaintMap_Key2Loc(dstKey),
      TaintMap_Key2Loc(dstKey),
      dstLen,
      KEY2STR(srcKey),
      TaintMap_Key2Loc(srcKey),
      TaintMap_Key2Loc(srcKey),
      srcLen
   );
}

/*
 * For IR that simply copies from one loc to the other
 * without running inputs through some kind of function (e.g, 32to1).
 */
void
TaintMapFlowCopy(HWord dstKey, HWord srcKey, HWord len)
{
   int isSrcTainted, isDstTainted;
   struct TaintExtent srcExt, dstExt;

   /* XXX: memory access may be to kernel portion of address space,
    * which we've reserved as keys for special values (e.g., consts).
    * We need to catch those not do any taint flow to those -- may
    * overwrite taint regions. */
   ASSERT(TaintMap_IsKeyTmp(srcKey) ||
          TaintMap_IsKeyMem(srcKey) ||
          TaintMap_IsKeyReg(srcKey) ||
          TaintMap_IsKeyConst(srcKey));

   ASSERT(TaintMap_IsKeyTmp(dstKey) ||
          TaintMap_IsKeyMem(dstKey) ||
          TaintMap_IsKeyReg(dstKey));


   isSrcTainted = TaintMap_GetRangeExtent(srcKey, len, &srcExt);
   isDstTainted = TaintMap_GetRangeExtent(dstKey, len, &dstExt);

   if (isSrcTainted) {
      TaintMap_TaintKey(dstKey, &srcExt);

      TaintMapPrintTaintUnary(dstKey, len, srcKey, len);

#if STATS
      TaintExtent_UnionStatOp(&srcExt, StatOp_Inc, TTOK_STAT_COPY);
#endif
   } else if (!isSrcTainted && isDstTainted) {
      TaintMapUntaintKey(dstKey, &dstExt);
   }
}

#if STATS
static void
TaintMapUpdateStatByOp(HWord op, struct TaintExtent *ext, StatOp statOp)
{
   int slot = -1;

#define OP_RANGE(a, b) (op >= a && op <= b)

   if (OP_RANGE(Iop_Add8, Iop_CmpNE64) ||
         OP_RANGE(Iop_MullS8, Iop_CmpwNEZ64) ||
         OP_RANGE(Iop_DivU32, Iop_DivModS128to64)) {

      slot = TTOK_STAT_INT_BINOP;

   } else if (OP_RANGE(Iop_Not8, Iop_Not64) ||
              OP_RANGE(Iop_8Uto16, Iop_1Sto64)) {

      slot = TTOK_STAT_INT_UNOP;

   } else if (OP_RANGE(Iop_AddF64, Iop_DivF64r32) ||
              OP_RANGE(Iop_AtanF64, Iop_ScaleF64)) {

      slot = TTOK_STAT_FP_TRIOP;

   } else if (OP_RANGE(Iop_SinF64, Iop_RoundF64toInt) ||
              OP_RANGE(Iop_F64toI16, Iop_F64toI64) ||
              (op == Iop_CmpF64)) {

      slot = TTOK_STAT_FP_BINOP;

   } else if (OP_RANGE(Iop_NegF64, Iop_AbsF64) ||
              op == Iop_I16toF64 ||
              op == Iop_I32toF64 ||
              op == Iop_F32toF64 ||
              OP_RANGE(Iop_ReinterpF64asI64, Iop_ReinterpI32asF32)) {

      slot = TTOK_STAT_FP_UNOP;

   }

   if (slot >= 0) {
      TaintExtent_UnionStatOp(ext, statOp, slot);
   } else {
      /* XXX: Unhandled op -- should probably do something about that... */
   }

#undef OP_RANGE
}
#endif

/*
 * -----------------------------------------------------------
 * TaintMapFlowUnary ---
 *
 * Summary:
 *
 *
 * -----------------------------------------------------------
 */

void
TaintMapFlowUnary(HWord op, HWord dstKey, HWord dstLen,
                  HWord srcKey, HWord srcLen)
{
   int isSrcTainted, isDestTainted;
   struct TaintExtent srcExt, dstExt;


   ASSERT(TaintMap_IsKeyTmp(srcKey) ||
          TaintMap_IsKeyMem(srcKey) ||
          TaintMap_IsKeyReg(srcKey) ||
          TaintMap_IsKeyConst(srcKey));

   ASSERT(TaintMap_IsKeyTmp(dstKey) ||
          TaintMap_IsKeyMem(dstKey) ||
          TaintMap_IsKeyReg(dstKey));

   isSrcTainted = TaintMap_GetRangeExtent(srcKey, srcLen, &srcExt);
   isDestTainted = TaintMap_GetRangeExtent(dstKey, dstLen, &dstExt);

   if (isSrcTainted) {
      struct TaintExtent joinExt;

      TaintExtent_Init(&joinExt, dstLen);

      TaintExtent_Join(&joinExt, &srcExt);

      TaintMap_TaintKey(dstKey, &joinExt);

      TaintMapPrintTaintUnary(dstKey, dstLen, srcKey, srcLen);

#if STATS
      TaintMapUpdateStatByOp(op, &joinExt, StatOp_Inc);
#endif
   } else if (isDestTainted) {
      TaintMapUntaintKey(dstKey, &dstExt);
   }
}

#if DEBUG
static void
TaintMapPrintTaintBinary(HWord dstKey, HWord src1Key, HWord src2Key)
{
   DEBUG_MSG(7,
             "0x%x -- dest: %s%d/0x%x <-- src1: %s%d/0x%x  src2: %s%d/0x%x\n",
             Task_GetCurrentRegs()->R(eip),
             KEY2STR(dstKey),
             TaintMap_Key2Loc(dstKey),
             TaintMap_Key2Loc(dstKey),
             KEY2STR(src1Key),
             TaintMap_Key2Loc(src1Key),
             TaintMap_Key2Loc(src1Key),
             KEY2STR(src2Key),
             TaintMap_Key2Loc(src2Key),
             TaintMap_Key2Loc(src2Key)
            );
}
#endif
/*
 * Destination and args are always tmps, so cannot be an origin access.
 *
 * @len is the type of the binary operation's result, not that
 * of the operands.
 */
void
TaintMapFlowBinary(HWord op, HWord dstKey, HWord dstLen,
                   HWord srcKey1, HWord src1Len,
                   HWord srcKey2, HWord src2Len)
{
   struct TaintExtent src1Ext, src2Ext, dstExt;
   int isSrc1Tainted, isSrc2Tainted, isDestTainted;


   /* The result of binary ops in VEX IR are always assigned to
    * a temp before being assigned to memory or register. */
   ASSERT(TaintMap_IsKeyTmp(dstKey));

   /* If either srcKey is a const, then we should be in
    * TaintMapFlowUnary rather than in this func. */
   ASSERT(TaintMap_IsKeyTmp(srcKey1));
   ASSERT(TaintMap_IsKeyTmp(srcKey2));

   isSrc1Tainted = TaintMapIsLocalTainted(srcKey1, src1Len, &src1Ext);
   isSrc2Tainted = TaintMapIsLocalTainted(srcKey2, src2Len, &src2Ext);
   isDestTainted = TaintMapIsLocalTainted(dstKey, dstLen, &dstExt);

   if (isSrc1Tainted || isSrc2Tainted) {
      struct TaintExtent joinExt;

      TaintExtent_Init(&joinExt, dstLen);

      if (isSrc1Tainted && isSrc2Tainted) {
         TaintExtent_Join(&joinExt, &src1Ext);
         TaintExtent_Join(&joinExt, &src2Ext);

         TaintMap_TaintKey(dstKey, &joinExt);
      } else if (isSrc1Tainted) {
         TaintExtent_Join(&joinExt, &src1Ext);

         TaintMap_TaintKey(dstKey, &joinExt);
      } else if (isSrc2Tainted) {
         TaintExtent_Join(&joinExt, &src2Ext);

         TaintMap_TaintKey(dstKey, &joinExt);
      } else {
         ASSERT(0);
      }

#if DEBUG
      TaintMapPrintTaintBinary(dstKey, srcKey1, srcKey2);
#endif

#if STATS
      TaintMapUpdateStatByOp(op, &joinExt, StatOp_Inc);
#endif
   } else if (isDestTainted) {
      TaintMapUntaintKey(dstKey, &dstExt);
   }
}

/*
 * This is used to handle Mux IR stmts. Like FlowBinary, the destination
 * and args are temps (or consts) and thus cannot be an origin access.
 */
void
TaintMapFlowTrinary(HWord dstKey, HWord dstLen,
                    HWord condVal, HWord condKey, HWord condLen,
                    HWord trueKey, HWord trueLen,
                    HWord falseKey, HWord falseLen)
{
   int isCondKeyTainted;
   struct TaintExtent condExt;

   /* condKey, trueKey, and falseKey may be -1, which indicates that
    * they are constants. */
   ASSERT(TaintMap_IsKeyTmp(dstKey));
   ASSERT(!(!TaintMap_IsKeyConst(condKey)) || TaintMap_IsKeyTmp(condKey));
   ASSERT(!(!TaintMap_IsKeyConst(trueKey)) || TaintMap_IsKeyTmp(trueKey));
   ASSERT(!(!TaintMap_IsKeyConst(falseKey)) || TaintMap_IsKeyTmp(falseKey));

   isCondKeyTainted  = TaintMap_GetRangeExtent(condKey, condLen, &condExt);

   if (isCondKeyTainted) {
      /* The result could non-deterministically be either branch, we
       * don't know which. So we indicate this uncertainty by tainting
       * the dstKey. FormGen should constrain the dstKey to either
       * branch ... */
      struct TaintExtent joinExt;

      TaintExtent_Init(&joinExt, dstLen);

      TaintExtent_Join(&joinExt, &condExt);

      TaintMap_TaintKey(dstKey, &joinExt);
   } else {
      /* We're assuming that dstKey, trueKey, and falseKey are the
       * same size. */
      ASSERT(dstLen == trueLen && trueLen == falseLen);

      if (condVal) {
         TaintMapFlowCopy(dstKey, trueKey, trueLen);
      } else {
         TaintMapFlowCopy(dstKey, falseKey, falseLen);
      }
   }
}

#if STATS
static void
TaintMapStatLoadStore(int isLoad, HWord locKey, HWord locLen)
{
   struct TaintExtent ext;

   if (TaintMap_GetRangeExtent(locKey, locLen, &ext)) {
      TaintExtent_UnionStatOp(&ext, StatOp_Inc,
                              isLoad ? TTOK_STAT_PTR_LOAD : TTOK_STAT_PTR_STORE);
   }
}
#endif

void
TaintMapFlowLoad(TaskRegs *vex, HWord locKey, HWord locLen,
                 HWord dstKey, HWord srcKey, HWord len)
{
   ASSERT(TaintMap_IsKeyTmp(locKey) || TaintMap_IsKeyConst(locKey));
   ASSERT_MSG(TaintMap_IsKeyMem(srcKey) && TaintMap_IsKeyTmp(dstKey),
              "dstKey=0x%x srcKey=0x%x\n", dstKey, srcKey);

   TaintMapFlowCopy(dstKey, srcKey, len);

   STATS_ONLY(TaintMapStatLoadStore(1, locKey, locLen);)
}

void
TaintMapFlowStore(TaskRegs *vex, HWord locKey, HWord locLen,
                  HWord dstKey, HWord srcKey, HWord len)
{
   ASSERT(TaintMap_IsKeyTmp(locKey) || TaintMap_IsKeyConst(locKey));
   ASSERT((TaintMap_IsKeyTmp(srcKey) || TaintMap_IsKeyConst(srcKey)) &&
          TaintMap_IsKeyMem(dstKey));

   TaintMapFlowCopy(dstKey, srcKey, len);

   STATS_ONLY(TaintMapStatLoadStore(0, locKey, locLen);)
}

#if STATS
void
TaintMapFlowExit(TaskRegs *vex, HWord guardKey, HWord guardLen)
{

   ASSERT(TaintMap_IsKeyTmp(guardKey));

   {
      struct TaintExtent ext;
      if (TaintMap_GetRangeExtent(guardKey, guardLen, &ext)) {

         TAINT_MSG("0x%x -- guardKey: %s%d/0x%x\n",
                   Task_GetCurrentRegs()->R(eip),
                   KEY2STR(guardKey),
                   TaintMap_Key2Loc(guardKey),
                   TaintMap_Key2Loc(guardKey));

         TaintExtent_UnionStatOp(&ext, StatOp_Inc, TTOK_STAT_EXIT);
      }
   }
}
#endif
