#include "vkernel/public.h"
#include "private.h"

static int wantsComments = 1;

struct PathWriteByte {
   int pathId;
   struct CgByte byte;

   struct ListHead list;
};

/* Maps from memory location to a list of symbolic bytes written to that
 * location along each path to the join point. */
struct JointWriteByte {
   struct MapField64 addrMap;
   struct ListHead pathList;

   /* Number of paths to the join point that write to this location. */
   int nrPaths;
};

static void
JointAdd(struct MapStruct *setP, const u64 pathId, const u64 addr)
{
   struct JointWriteByte *jwbP;
   
   if (!(jwbP = Map_Find(setP->mapP))) {
      jwbP = malloc(sizeof(*jwbP));
      Map_NodeInit64(jwbP->addrMap, addr);
      List_Init(&jwbP->pathList);
      jwbP->nrPaths = 0;

      Map_Insert64(setP->mapP, addrMap, addr, jwbP);
   }

   struct PathWriteByte *pwbP = malloc(sizeof(*pwbP));
   pwbP->pathId = pathId;
   cg_SymLookup(addr, &pwbP->byte);
#error "XXX: get reference to byte if symbolic"
   List_Init(&pwbP->list);
   List_Add(&pwbP->list, &jwbP->list);

   jwbP->nrPaths++;
}

static void
JointDel(struct MapStruct *setP, struct JointWriteByte *jwbP)
{
   struct PathWriteByte *pwbP, *dummyP;

   list_for_each_entry_safe(pwbP, dummyP, &jwbP->pathList, list) {
      List_Del(&pwbP->list);
      free(pwbP);
      pwbP = NULL;
   }
   jwbP->nrPaths = 0;

   Map_Remove(setP->mapP, addrMap, jwbP);

   free(jwbP);
   jwbP = NULL;
}

static void
JointAddWriteSet(struct MapStruct *dstSetP, const u64 pathId, 
                 const struct MapStruct *wrSetP)
{
   struct WriteByte *wbP;

   MAP_FOR_EACH_ENTRY_SAFE_DO(wrSetP, addrMap, wbP) {
      const u64 addr = wbP->addrMap.key;
      JointAdd(dstSetP, pathId, addr);
   } END_MAP_FOR_EACH_ENTRY_SAFE;
}

/* --------------------------------------------------------------- */

void
cgJoinCond(const u64 joinId, const u64 pathId)
{
   CgenOut("JOINCONDv%dj%llup%llu", curr_vcpu->id, joinId, pathId);
}

static INLINE void
cg_DeclareJoinCond(const u64 joinId, const u64 pathId)
{
   cgJoinCond(joinId, pathId);
   CgenOut(" : BOOLEAN;\n");
}


#if 0
static void
cgEmitJointWrite(u64 joinId, u64 pathId, u64 addr, u64 idx,
                    struct Term *tP)
{
   cg_DeclareJointWrite(joinId, addr, idx+1);

   if (tP->kind == Tk_Symbolic) {
      CG_ASSIGN(cg_PrintJointWrite(joinId, addr, idx),
            CG_ITE(
               cg_BranchCond(joinId, pathId, 0),
               CG_BV(tP->Data.bvP),
               cg_PrintJointWrite(joinId, addr, idx+1)));
   } else {
      CG_ASSIGN(cg_PrintJointWrite(joinId, addr, idx),
            CG_ITE(
               cg_BranchCond(joinId, pathId, 0),
               /* XXX: should be bv or concrete val. */
               CG_CONST(Ity_I8, tP->Data.byte),
               cg_PrintJointWrite(joinId, addr, idx+1)));
   }
}

static void
cgEmitJointWritesForPath(
      u64 joinId,
      u64 pathId,
      struct MapStruct *pathWrSetP,
      struct MapStruct *jointWrSetP
      )
{
   struct WriteByte *pwbP;

   MAP_FOR_EACH_ENTRY_SAFE_DO(pathWrSetP, addrMap, pwbP) {
      const u64 addr = pwbP->addrMap.key;
      DEBUG_MSG(5, "addr=0x%llx\n", addr);
#if 1
      struct JointWriteByte *jwbP = Map_Find64(jointWrSetP, addrMap, addr, jwbP);
      if (!jwbP) {
         cg_DeclareJointWrite(joinId, addr, 0);

         jwbP = malloc(sizeof(*jwbP));
         Map_NodeInit64(&jwbP->addrMap, addr);
         jwbP->idx = 0;
         Map_Insert64(jointWrSetP, addrMap, addr, jwbP);
      }


      int isTainted = 0;
      struct ByteVar *bvP = NULL;

      if (addr < PAGE_SIZE) {
         isTainted = TaintMap_IsRegTainted(current, addr, 1, (void**)&bvP);
      } else {
         isTainted = TaintMap_IsMemTainted(&addr, 1, (void**)&bvP);
      }

      struct Term term;

      if (isTainted) {
         term.kind = Tk_Symbolic;
         term.Data.bvP = bvP;
      } else {
         uchar byteVal;
         if (addr < PAGE_SIZE) {
            Task_CopyFromRegs(&byteVal, addr, 1);
         } else {
            ulong vAddr = GlobalAddr_GetVAddr(addr);
            int err = copy_from_user(&byteVal, (void*)vAddr, 1);
            ASSERT(!err);
         }

         term.kind = Tk_Concrete;
         term.Data.byte = byteVal;
      }

      cgEmitJointWrite(joinId, pathId, addr, jwbP->idx, &term);
      ASSERT_KPTR(jwbP);
      jwbP->idx++;
#endif
   } END_MAP_FOR_EACH_ENTRY_SAFE;
}
#endif

static void
cgEmitExistsOnePathToJoinPoint(const u64 joinId, const u64 nrPathsExplored)
{
   u64 i;

   CG_COMMENT("Exists at least one path to join point\n");
   cg_DeclareJoinCond(joinId, 0);

   for (i = 0; i < nrPathsExplored; i++) {
      /* At least one of the explored paths must hold. */
      cg_DeclareJoinCond(joinId, i+1);
      CG_EQUIV(cgJoinCond(joinId, i), 
            CG_ITE(
               cg_BranchCond(joinId, i, 0),
               CG_TRUE,
               cgJoinCond(joinId, i+1)));
   }
   CG_EQUIV(cgJoinCond(joinId, i), CG_FALSE);

   /* At least one of the paths holds true. */
   CG_EQUIV(cgJoinCond(joinId, 0), CG_TRUE);
}

#if 0
static void
cgJoinLinkToNextJoinSegment(u64 joinId, struct MapStruct *jointWrSetP)
{
   struct JointWriteByte *jwbP;

   MAP_FOR_EACH_ENTRY_SAFE_DO(jointWrSetP, addrMap, jwbP) {
      u64 addr = jwbP->addrMap.key;
      ASSERT(jwbP->idx >= 1);

      struct ByteVar *bvP = NULL;
      cg_MakeJointWriteCVs(joinId, addr, 1, (void**)&bvP);

      if (addr < PAGE_SIZE) {
         cg_TaintRegWithBv(addr, 1, &bvP);
      } else {
         cg_TaintMemWithBv(&addr, 1, &bvP);
      }
   } END_MAP_FOR_EACH_ENTRY_SAFE;
}
#endif

static void
cgEmitJointWriteForLocTerm(u64 joinId, u64 pathId, u64 addr, u64 idx,
                           const struct CgByte *bP)
{
   cg_DeclareJointWrite(joinId, addr, idx+1);

   if (bP->kind == Cbk_Symbolic) {
      CG_ASSIGN(cg_PrintJointWrite(joinId, addr, idx),
            CG_ITE(
               cg_BranchCond(joinId, pathId, 0),
               CG_BV(bP->Data.bvP),
               cg_PrintJointWrite(joinId, addr, idx+1)));
   } else {
      CG_ASSIGN(cg_PrintJointWrite(joinId, addr, idx),
            CG_ITE(
               cg_BranchCond(joinId, pathId, 0),
               /* XXX: should be bv or concrete val. */
               CG_CONST(Ity_I8, bP->Data.byte),
               cg_PrintJointWrite(joinId, addr, idx+1)));
   }
}

static void
cgEmitJointWriteForLoc(const u64 joinId, const struct JointWriteByte *jwbP)
{
   struct PathWriteByte *pwbP;
   struct ListHead *pwbListP = &jwbP->list;
   u64 addr = jwbP->addrMap.key;

   int idx = 0;
   list_for_each_entry(pwbP, pwbListP, list) {
      struct CgByte *tP = &pwbP->byte;
      ASSERT_KPTR(tP);

      cgEmitJointWriteForLocTerm(joinId, pwbP->pathId, addr, idx, tP);
      idx++;
   }

   /* The default value if memory location isn't written (i.e., if
    * solver selects a path that doesn't write to this location). */
   CG_ASSIGN(cg_PrintJoinWrite(joinId, addr, idx), origByteAtThisLoc);
}

static void
cgEmitJointWrites(u64 jointId, struct MapStruct *jointWrSetP)
{
   struct JointWriteByte *jwbP;

   MAP_FOR_EACH_ENTRY_SAFE_DO(jointWrSetP, addrMap, jwbP) {
      u64 addr = jwbP->addrMap.key;
      struct ListHead *pwbListP = &jwbP->list;
      int pathCount = jwbP->listSize;
      int allSame = jwbP->isAllSame;

      ASSERT(pathCount <= nrPaths);

      isWrittenByAll = (pathCount == nrPaths);
      if (!(isWrittenByAll && isSameValue)) {
         struct cgByte *origByteAtThisLocP = Cgen_SymMapLookup(addr);

         ASSERT_KPTR(tP);
         cgEmitJointWriteForLoc(joinId, jwbP, origByteAtThisLocP);

         /* Make sure the next join segment uses this written value. */
         struct ByteVar *bvP = NULL;
         cg_MakeJointWriteCVs(joinId, addr, 1, (void**)&bvP);

         if (addr < PAGE_SIZE) {
            cg_TaintRegWithBv(addr, 1, &bvP);
         } else {
            cg_TaintMemWithBv(&addr, 1, &bvP);
         }
      }
   } END_MAP_FOR_EACH_ENTRY_SAFE;
}


static int
cgDoCFGJoinWork(struct PathSelector *psP, struct MapStruct *pathWrSetP)
{
   const u64 joinId = curr_vcpu->nrCompletedJoins;
   const u64 pathId = psP->pathId;

   cgExit_EmitNonInlinePathCond(joinId, pathId);

   int hasExploredAllPathsToJoinPoint = psP->onJoin(psP);


   if (hasExploredAllPathsToJoinPoint) {

      /* Connect this join point to the next. */
      cgEmitJointWrites(joinID, curr_vcpu->jointWrSetP);

      /* Make sure that at least one path to this join point holds. */
      cgEmitExistsOnePathToJoinPoint(joinId, pathId+1);

      return 1;
   }

   return 0;
}

#if 0
/* XXX: we may need to invoke the join callback outside of the TC, in
 * order to avoid confusing VEX on ckpt restore. */
static void
cgOnTcInvalidateAndJump()
{
}
#endif

#if 0
/*
 * Summary:
 *
 * Update undo set of ckpt to reflect state changes made in the current
 * IRSB as well as previous IRSBs. This is needed to capture all changes
 * made since the last fork point.
 *
 */
static void
cgJoinUpdateUndoSet(struct cgCkpt *ckptP)
{
   ASSERT_KPTR(curr_vcpu->bbSetP);

   cgCkpt_Union(ckptP, curr_vcpu->bbSetP);

   cgCkpt_Free(curr_vcpu->bbSetP);
   curr_vcpu->bbSetP = NULL;
}
#endif

static void
cgOnCFGJoinBrkptCb(void *argP)
{
   struct PathSelector *psP = (struct PathSelector*) argP;
   const ulong joinIP = curr_regs->R(eip);

   /* Create the joint write set, before we restore the ckpt. */
   struct MapStruct *pathWrSetP = Map_Create(0);
   cgCkptStack_GetWriteSet(pathWrSetP);
   JointAddWriteSet(pathWrSetP);

   /* We need to restore the ckpt before we emit the joint write
    * constraints, since we need to know the symbolic state at the start
    * of the join point. */
   struct cgCkpt *ckptP = cgCkptStack_Pop();
   ASSERT_KPTR(ckptP);
   cgCkpt_Restore(ckptP);
   cgCkpt_Free(ckptP);
   ckptP = NULL;

   if (cgDoCFGJoinWork(psP, pathWrSetP)) {
      curr_vcpu->isJoinPending = 0;
      curr_vcpu->nrCompletedJoins++;

      Brkpt_RmStatic(joinIP);
      curr_regs->guest_IP_AFTER_TINVAL = joinIP;
   } else {
      CG_COMMENT("----- Exploring new path %llu on join segment %llu -----\n", 
            cgPsP->pathId, curr_vcpu->nrCompletedJoins);
      /* Resume at the restored IP. */
      curr_regs->guest_IP_AFTER_TINVAL = curr_regs->R(eip);
   }

   struct WriteByte *wbP;
   Map_Destroy(pathWrSetP, addrMap, wbP);
   pathWrSetP = NULL;

   DEBUG_MSG(5, "resuming at 0x%x\n", curr_regs->guest_IP_AFTER_TINVAL);
}

static ulong
cgJoinGetIPOfNextLoggedEvent()
{
   struct EntryHeader *hdrP = NULL;
   ulong ip = 0;

   ASSERT(VCPU_IsReplaying());

   hdrP = PEEK_LOG_ENTRY_HEADER(&curr_vcpu->replayLog);
   ASSERT_KPTR(hdrP);

   if (hdrP->id == LogEntryId_PreemptionTimer ||
       hdrP->id == LogEntryId_PreemptionFault) {
      ip = hdrP->eip;
   } else {
      /* A syscall -- when the entry was logged, EIP was already
       * advanced to the next insn. */
      ip = hdrP->eip - 2;
   }

   DEBUG_MSG(7, "next_event_IP=0x%x\n", ip);


   ASSERT_UPTR((void*)ip);

   return ip;
}

/* 
 * Summary:
 *
 * Setup the next join point.
 *
 * Assumptions:
 *
 * Must be done before we enter the translation cache, since then we can't 
 * setup static breakpoints once we start executing translated code.
 * Hence this is done in the vkernel, right before we resume user mode
 * execution.
 *
 * Also must be done by the tasking executing the join point.
 */
static void
cgJoinSetupNext()
{
   /* Start a new context. 
    * XXX: maintaining undos too expensive when used with the recoded
    * path selector. */
   cgCkptStack_PushNew();

   ulong joinIP = cgJoinGetIPOfNextLoggedEvent();

   /* XXX: ASSSERt that join even is for the current task. */

   Brkpt_SetStatic(joinIP, &cgOnCFGJoinBrkptCb, (void*)cgPsP);

   CG_COMMENT("----- [ Starting joint segment %llu ] ----- \n", 
         curr_vcpu->nrCompletedJoins);

   cgPsP->onFork(cgPsP, joinIP);

   if (curr_vcpu->jointWrSetP) {
      struct JointWriteByte *jwbP;

      ASSERT_KPTR(setP->mapP);

      MAP_FOR_EACH_ENTRY_SAFE_DO(setP->mapP, addrMap, jwbP) {
         JointDel(setP, jwbP);
      } END_MAP_FOR_EACH_ENTRY_SAFE;
   }
   curr_vcpu->jointWrSetP = Map_Create(0);
}

void
cgJoin_OnResumeUserMode()
{
   if (!curr_vcpu->isJoinPending) {
      D__;
      cgJoinSetupNext(); 
      curr_vcpu->isJoinPending = 1;
   }
}

void
cgJoin_InitVCPU(struct VCPU *vcpuP)
{
   vcpuP->isJoinPending = 0;
   vcpuP->nrCompletedJoins = 0;
   vcpuP->jointWrSetP = NULL;
}

static void
CgenCopyFromUser(
      const struct IoVec *iov_ptr,
      const size_t totalLen,
      const void *logDataP,
      const size_t logDataLen
      )
{
   ASSERT(totalLen > 0);
   ASSERT_MSG(logDataLen <= totalLen, "logDataLen=%lu totalLen=%lu",
         logDataLen, totalLen);
   ASSERT(logDataLen > 0);
   ASSERT(logDataP);

   STATS_ONLY(cgProf_NrTotalOutBytes += totalLen);

   void **dataPA = malloc(sizeof(void*) * logDataLen);
   const int is_read = 1;
   struct GAddrRange gaddr_ranges[MAX_NR_RANGES];
   int nr_ranges = MAX_NR_RANGES;

   GlobalAddr_FromRange2(current->mm, gaddr_ranges, &nr_ranges,
         (ulong) usrP, logDataLen, is_read);

   if (TaintMap_AreMemRangesTainted(gaddr_ranges, nr_ranges, dataPA)) {
      cgEmitOutput(dataPA, logDataP, logDataLen);
   } 

   free(dataPA);
}



static void
CgenCopyToUser(
      const char __user *usrP,
      const size_t totalLen,
      const void *logDataP,
      const size_t logDataLen
      )
{
   size_t originLen = totalLen - logDataLen;

   ASSERT(originLen >= 0);
   ASSERT(originLen <= totalLen);

   STATS_ONLY(cgProf_NrTotalInBytes += totalLen);


   if (logDataLen) {
#if DEBUG_UPDATE_GUEST
      struct CgByte **bytePA = malloc(sizeof(*bytePA) * logDataLen);

      cgByte_MakeConcrete(logDataP, logDataLen, bytePA);
      cgMap_UpdateVAddr((ulong) usrP, bytePA, logDataLen);

      cgByte_PutAll(bytePA, logDataLen);
      free(bytePA);
      bytePA = NULL;
#endif
   }

   if (originLen) {
#if DEBUG_UPDATE_GUEST
      ASSERT(logDataLen < totalLen);

      cgMap_WriteOrigin((ulong) usrP + logDataLen, originLen);
#endif
   }

}



