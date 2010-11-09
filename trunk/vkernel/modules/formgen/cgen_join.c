#include "vkernel/public.h"
#include "private.h"

static int wantsComments = 1;

struct PathWriteByte {
   int pathId;
   struct CgByte *byteP;

   struct ListHead list;
};

/* Maps from memory location to a list of symbolic bytes written to that
 * location along each path to the join point. */
struct JointWriteByte {
   struct MapField64 addrMap;

   /* Number of paths to the join point that write to this location. */
   int nrPaths;

   /* Bytes written to this location along each path. */
   struct ListHead pathList;

   /* Do all paths reference the same symbolic/concrete value? 
    * This is an optimization: we could determine this by scanning the
    * list. */
   int isUniform;
};

#if 1
static void
JointWriteSetAdd(struct MapStruct *setP, const u64 pathId, const u64 addr)
{
#if 1
   struct JointWriteByte *jwbP;
  
   //DEBUG_MSG(5, "addr=%llx\n", addr);
   if (!(jwbP = Map_Find64(setP, addrMap, addr, jwbP))) {
      jwbP = malloc(sizeof(*jwbP));
      Map_NodeInit64(&jwbP->addrMap, addr);
      List_Init(&jwbP->pathList);
      jwbP->nrPaths = 0;
      jwbP->isUniform = 1;

      Map_Insert64(setP, addrMap, addr, jwbP);
   }

   struct PathWriteByte *pwbP = malloc(sizeof(*pwbP));
   pwbP->pathId = pathId;

   struct MAddrRange mr = { .kind = addr < PAGE_SIZE ? Mk_Reg : Mk_Gaddr, 
      .start = addr, .len = 1 };
   int err = cgMap_Read(&mr, &pwbP->byteP);
   ASSERT_UNIMPLEMENTED(!err);

   List_Init(&pwbP->list);
   if (jwbP->nrPaths > 0) {
      if (jwbP->isUniform) {
         struct PathWriteByte *tailP = List_PeekTop(&jwbP->pathList, 
               list, tailP);

         ASSERT_KPTR(tailP);

         if (!cgByte_IsEqual(pwbP->byteP, tailP->byteP)) {
            jwbP->isUniform = 0;
            List_Add(&pwbP->list, &jwbP->pathList);
         }
      } else {
         List_Add(&pwbP->list, &jwbP->pathList);
      }
   } else {
      List_Add(&pwbP->list, &jwbP->pathList);
   }

   jwbP->nrPaths++;
#endif
}
#endif

static void
JointWriteSetDel(struct MapStruct *setP, struct JointWriteByte *jwbP)
{
   struct PathWriteByte *pwbP, *dummyP;

   list_for_each_entry_safe(pwbP, dummyP, &jwbP->pathList, list) {
      cgByte_Put(pwbP->byteP);
      pwbP->byteP = NULL;
      List_Del(&pwbP->list);
      free(pwbP);
      pwbP = NULL;
   }
   jwbP->nrPaths = 0;

   Map_Remove(setP, addrMap, jwbP);

   free(jwbP);
   jwbP = NULL;
}

#if 1
static void
JointWriteSetUnion(struct MapStruct *dstSetP, const u64 pathId, 
                   struct MapStruct *wrSetP)
{
   struct WriteByte *wbP;

   MAP_FOR_EACH_ENTRY_SAFE_DO(wrSetP, addrMap, wbP) {
      const u64 addr = wbP->addrMap.key64;
      JointWriteSetAdd(dstSetP, pathId, addr);
   } END_MAP_FOR_EACH_ENTRY_SAFE;
}
#endif

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


#if 1
static void
cgJoinEmitExistsOnePathToJoinPoint(const u64 joinId, 
      const u64 nrPathsExplored)
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
#endif

static INLINE MapAddrKind
AddrToKind(u64 addr)
{
   return addr < PAGE_SIZE ? Mk_Reg : Mk_Gaddr;
}

static void
cgEmitJointWriteForLoc(const u64 jointVarName, const u64 joinId, const struct JointWriteByte *jwbP)
{
   struct PathWriteByte *pwbP;
   u64 addr = jwbP->addrMap.key64;

   
   cg_StartNewLocalScope();

   CG_NEW_VAR(Ity_I8, CG_LSCOPEI(0));

   int idx = 0;
   list_for_each_entry(pwbP, &jwbP->pathList, list) {
      struct CgByte *bP = pwbP->byteP;
      ASSERT_KPTR(bP);

      //cgEmitJointWriteForLocTerm(joinId, pwbP->pathId, addr, idx, bP);
      CG_NEW_VAR(Ity_I8, CG_LSCOPEI(idx+1));

      CG_ASSIGN(CG_LSCOPEI(idx),
            CG_ITE(
               cg_BranchCond(joinId, pwbP->pathId, 0),
               cg_PrintSymByte(bP),
               CG_LSCOPEI(idx+1)));

      idx++;
   }

   struct CgByte *origByteAtThisLocP;

   const struct MAddrRange mr  = { .kind = AddrToKind(addr), 
      .start = addr, .len = 1 };

   int err = cgMap_Read(&mr, &origByteAtThisLocP);
   ASSERT_UNIMPLEMENTED(!err);

   /* The default value if memory location isn't written (i.e., if
    * solver selects a path that doesn't write to this location). */
   CG_ASSIGN(CG_LSCOPEI(idx), cg_PrintSymByte(origByteAtThisLocP));
   cgByte_Put(origByteAtThisLocP);

   cg_DeclareJointWrite(jointVarName);
   CG_ASSIGN(cg_PrintJointVarNow(jointVarName), CG_LSCOPEI(0));
}

static void
cgConstructJointState(const u64 joinId, const int nrPathsExplored,
                  struct MapStruct *jointWrSetP)
{
   struct JointWriteByte *jwbP;

   MAP_FOR_EACH_ENTRY_SAFE_DO(jointWrSetP, addrMap, jwbP) {
      u64 addr = jwbP->addrMap.key64;
      int pathCount = jwbP->nrPaths;

      ASSERT(pathCount <= nrPathsExplored);

      int isWrittenByAll = (pathCount == nrPathsExplored);

      if (isWrittenByAll && jwbP->isUniform) {
         struct PathWriteByte *tailP = List_PeekTop(&jwbP->pathList, 
               list, tailP);
         ASSERT_KPTR(tailP);

         const struct MAddrRange mr  = { .kind = AddrToKind(addr), 
            .start = addr, .len = 1 };
         cgMap_Write(&mr, &tailP->byteP);
      } else {
         /* Sigh. This location may be emultiple values, so we need a 
          * joint symbolic variable for it. */
         const u64 jointVarName = VA(joinCounter)++;

         cgEmitJointWriteForLoc(jointVarName, joinId, jwbP);

         const int nrRanges = 1;
         const struct MAddrRange rangeA[1] = { 
            { .kind = AddrToKind(addr),
              .start = addr,
              .len = 1 } };

         struct CgByte *bytePA[1];

         cgByte_MakeSymbolic(CondVar_JointWrite, jointVarName, 1, bytePA);
         cgMap_UpdateMAddr(rangeA, nrRanges, bytePA);

         cgByte_PutAll(bytePA, 1);
      }
   } END_MAP_FOR_EACH_ENTRY_SAFE;
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
cgJoinDoComplete()
{
   const ulong joinIP = curr_regs->R(eip);

   curr_vcpu->isJoinPending = 0;
   curr_vcpu->nrCompletedJoins++;

   UNUSED int res = Brkpt_RmStatic(joinIP);
   ASSERT(res == 1);

   curr_regs->guest_IP_AFTER_TINVAL = joinIP;
}

/*
 * Summary:
 *
 * When there are multiple paths from the previous segment to this
 * one, we need to update the symbolic state at this join point to
 * reflect possible executions along these paths.
 */
void
cgJoinDoMultiplePathWork(const u64 joinId, const u64 pathId)
{
   /* Create the joint write set, before we restore the ckpt. */
   struct MapStruct *pathWrSetP = Map_Create(0);
   cgCkptStack_GetWriteSet(pathWrSetP);
   JointWriteSetUnion(curr_vcpu->jointWrSetP, pathId, pathWrSetP);

   struct WriteByte *wbP;
   Map_Destroy(pathWrSetP, addrMap, wbP);
   pathWrSetP = NULL;

#if 1
   /* We need to restore the ckpt before we emit the joint write
    * constraints, since we need to know the symbolic state at the 
    * start of the join point. */
   struct cgCkpt *ckptP = cgCkptStack_Pop();
   ASSERT_KPTR(ckptP);
   cgCkpt_Restore(ckptP);
   cgCkpt_Free(ckptP);
   ckptP = NULL;
#endif
}

/*
 * Summary:
 *
 * No need to reason about multiple paths (and hence create joint state)
 * if there is only one path from the previous join point to this one. 
 * This is the common case (e.g., during startup when we know all
 * the inputs) and hence is designed to be fast.
 *
 */
static void
cgJoinDoSinglePathWork()
{
   struct cgCkpt *ckptP = cgCkptStack_Pop();
   ASSERT_KPTR(ckptP);
   cgCkpt_Free(ckptP);
   ckptP = NULL;

   cgJoinDoComplete();
}

static void
cgJoinBrkptCb(void *argP)
{
   struct PathSelector *psP = (struct PathSelector*) argP;
   const u64 joinId = curr_vcpu->nrCompletedJoins;
   const u64 pathId = psP->pathId;

   int isDoneExploringAllPaths = psP->onJoin(psP);
   int nrPathsExplored = pathId + 1;

   /* Is this needed if there is only one path? 
    * Yes, we want solver to choose inputs consistent with path. */
   cgExit_EmitNonInlinePathCond2(joinId, pathId);

   if (isDoneExploringAllPaths && nrPathsExplored == 1) {
      /* Fast path. */

      cgJoinDoSinglePathWork();
   } else {
      /* Slow path. */

      ASSERT_UNIMPLEMENTED(0);

      cgJoinDoMultiplePathWork(joinId, pathId);

      /* XXX: roll this in with the multi-path work function */
      if (isDoneExploringAllPaths) {
         D__;
         cgConstructJointState(joinId, nrPathsExplored, 
               curr_vcpu->jointWrSetP);

         cgJoinEmitExistsOnePathToJoinPoint(joinId, nrPathsExplored);

         cgJoinDoComplete();
      } else {
         CG_COMMENT(
               "----- Exploring new path %llu on join segment %llu -----\n", 
               cgPsP->pathId, curr_vcpu->nrCompletedJoins);
         /* Resume at the restored IP. */
         curr_regs->guest_IP_AFTER_TINVAL = curr_regs->R(eip);
      }
   }

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

   DEBUG_MSG(5, "entry=%s ip=0x%x\n", entryId2Str[(int)hdrP->id], hdrP->eip);
   if (hdrP->id == LogEntryId_PreemptionTimer ||
         hdrP->id == LogEntryId_PreemptionFault) {
      ip = hdrP->eip;
   } else {
      /* A syscall -- when the entry was logged, EIP was already
       * advanced to the next insn. XXX: find a way to verify this
       * assumption. */
      ip = hdrP->eip - 2;
   }

   DEBUG_MSG(5, "next_event_IP=0x%x\n", ip);


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
 * Also must be done by the task executing the join point.
 */
static void
cgJoinSetupNext()
{
   ASSERT(!cgCkptStack_PeekTop());

   DEBUG_MSG(5, "Starting join segment %llu\n", curr_vcpu->nrCompletedJoins);

   /* Start a new context. 
    * XXX: maintaining undos too expensive when used with the recorded
    * path selector. */
   cgCkptStack_PushNew();

   ulong joinIP = cgJoinGetIPOfNextLoggedEvent();

   /* XXX: ASSSERt that join even is for the current task. */

   Brkpt_SetStatic(joinIP, &cgJoinBrkptCb, (void*)cgPsP);

   CG_COMMENT("----- [ Starting joint segment %llu ] ----- \n", 
         curr_vcpu->nrCompletedJoins);

   cgPsP->onFork(cgPsP, joinIP);

   struct MapStruct *setP = curr_vcpu->jointWrSetP;

   if (setP) {
      struct JointWriteByte *jwbP;

      MAP_FOR_EACH_ENTRY_SAFE_DO(setP, addrMap, jwbP) {
         //DEBUG_MSG(5, "Deleing 0x%llx\n", jwbP->addrMap.key64);
         JointWriteSetDel(setP, jwbP);
      } END_MAP_FOR_EACH_ENTRY_SAFE;

      ASSERT(Map_GetSize(setP) == 0);
      Map_Destroy(setP, addrMap, jwbP);
      curr_vcpu->jointWrSetP = NULL;
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
