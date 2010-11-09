#include "vkernel/public.h"
#include "private.h"

/* 
 * TREAT_REP_PREFIX_AS_BRANCH
 *
 * Set this to 0 if you want to replay a branch trace collected 
 * using PIN.  Since PIN doesn't consider insn with the REP prefix 
 * to be conditional branches, we shouldn't either. Note that this won't
 * work if the branch trance was hardware-produced: the hardware doesn't
 * recognize the rep prefix as a branch (at least not P4 perf hardware).
 *
 * Set this to 1 if you intend to use branch check only for determinism
 * checking purposes.
 */
#define TREAT_REP_PREFIX_AS_BRANCH 1

static const int  wantsComments = 1;
static const Bool wantsInlinePathQueries = False;



struct BranchCond {
   struct MapField64 brIdMap;

   u64 pathId;

   u64 execCount; /* Helps with debugging. */
   PsBranchKind kind;

   IRTemp tmp;

   ulong dst;
};

void
cg_BranchCond(const u64 joinId, const u64 pathId, const u64 brId)
{
   CgenOut("BCv%dj%llup%llub%llu", curr_vcpu->id, joinId, pathId, brId);
}

static INLINE void
cg_DeclareBranchCond(const u64 joinId, const u64 pathId, const u64 brId)
{
   cg_BranchCond(joinId, pathId, brId);
   CgenOut(" : BOOLEAN;\n");
}

static void
cgEmitBranchClause(const struct BranchCond *bcP)
{
   switch (bcP->kind) {
   case Pbk_Cond:
      ASSERT(bcP->dst == 1 || bcP->dst == 0);
      CG_EQUAL(cg_PrintVar(CondVar_Tmp, curr_vcpu->id, bcP->execCount, 
                           bcP->tmp), 
            CG_CONST(Ity_I1, bcP->dst));
      break;
   default:
      ASSERT(bcP->dst >= PAGE_SIZE);
      CG_EQUAL(cg_PrintVar(CondVar_Tmp, curr_vcpu->id, bcP->execCount, 
                           bcP->tmp), 
            CG_CONST(Ity_I32, bcP->dst));
      break;
   }
}

static void
cgEmitBranchCond(const u64 joinId, const struct BranchCond *bcP, const u64 brId)
{
   const u64 pathId = bcP->pathId;

   cg_DeclareBranchCond(joinId, pathId, brId+1);

   CG_EQUIV(cg_BranchCond(joinId, pathId, brId), 
         CG_ITE(
            cgEmitBranchClause(bcP),
            cg_BranchCond(joinId, pathId, brId+1),
            CG_FALSE));
}

static void
cgEmitInlineBranchCond(const struct BranchCond *bcP)
{
   ASSERT_UNIMPLEMENTED(0);
#if 0
   if (bcP->brIdMap.key == 0) {
      cg_DeclarePathCond(bcP->pathId);
   }

#endif
}

void
cgExit_EmitNonInlinePathCond(const u64 joinId, const u64 pathId)
{
   struct BranchCond *bcP = NULL, *tmpP = NULL;

   CG_COMMENT("----- Join point %llu, path %llu ----- \n", joinId, pathId);

   //if (Map_GetSize(curr_vcpu->pcMapP) > 0) {
      cg_DeclareBranchCond(joinId, pathId, 0);

      u64 brIdx = 0;
      list_for_each_entry_safe(bcP, tmpP, &curr_vcpu->pcMapP->list, 
            brIdMap.list) {
         cgEmitBranchCond(joinId, bcP, brIdx);
         brIdx++;
         Map_Remove(curr_vcpu->pcMapP, brIdMap, bcP);
         free(bcP);
         bcP = NULL;
      }

      CG_EQUIV(cg_BranchCond(joinId, pathId, brIdx), CG_TRUE);
   //}
}

/*
 * This version may result in better splits, since not all vars are tied
 * together. However, this is not really applicable if we do not know the
 * original path. */
void
cgExit_EmitNonInlinePathCond2(const u64 joinId, const u64 pathId)
{
   struct BranchCond *bcP = NULL, *tmpP = NULL;

   CG_COMMENT("----- Join point %llu, path %llu ----- \n", joinId, pathId);

   u64 brIdx = 0;
   list_for_each_entry_safe(bcP, tmpP, &curr_vcpu->pcMapP->list, 
         brIdMap.list) {
      CG_ASSERT(cgEmitBranchClause(bcP));
      brIdx++;
      Map_Remove(curr_vcpu->pcMapP, brIdMap, bcP);
      free(bcP);
      bcP = NULL;
   }
}


static void
cgBranchEmitWork(const PsBranchKind pbk, const IRTemp dstTmp, u64 pathId, u64 brId, ulong dst)
{
   struct BranchCond *bcP = malloc(sizeof(*bcP));

   Map_NodeInit64(&bcP->brIdMap, brId);
   bcP->pathId = pathId;
   bcP->kind = pbk;
   bcP->dst = dst;
   bcP->tmp = dstTmp;
   bcP->execCount = VA(bbExecCount);

   if (wantsInlinePathQueries) {

      cgEmitInlineBranchCond(bcP);

      free(bcP);
      bcP = NULL;
   } else {
      Map_Insert64(curr_vcpu->pcMapP, brIdMap, brId, bcP);
   }
}


static ulong
cgBranchWork(const PsBranchKind pbk, const IRTemp dstTmp, const ulong dstRes, 
             const ulong fallRes)
{
   ulong selRes = dstRes;

   ASSERT_KPTR(cgPsP);
   ASSERT(current->is_in_code_cache);

   cgPsP->advanceBranch(cgPsP, pbk, dstRes, fallRes);

   DEBUG_MSG(6, "pbk=0x%x dstTmp=%d dstRes=0x%x fallRes=0x%x pred=0x%x\n",
         pbk, dstTmp, dstRes, fallRes, cgPsP->selTarget);

   if (cg_IsArgTainted(dstTmp)) {
     
#if 0
      !(tc == TCode_TmpUntainted || tc == TCode_TmpUndefined ||
            current->isInsnUnconstrained)) {
#endif

      /* The branch condition/target tmp is tainted by unknown input, so 
       * we don't know where the original run went. So we invoke the
       * path-selector to figure out where it may have gone.  
       *
       * CAUTION: this assumes that state influenced/tainted by unknown
       * inputs has been marked as tainted. This may not be the
       * case if array regions are unsoundly/non-conservatively selected. 
       * As a result, we could seee branch divergence. */

      PathSelCmd cmd = cgPsP->getBranchTarget(cgPsP, &selRes);
      if (cmd == Pck_Fork) {
         DEBUG_MSG(5, "forking context\n");
         /* Backtrack may be required, so fork the execution context. */
         cgCkptStack_PushNew();
      } else {
         /* No backtrack required, perhaps because there is only one
          * possible target (despite the branch being tainted). */
      }

      cgBranchEmitWork(pbk, dstTmp, cgPsP->pathId, cgPsP->brId, selRes);
   }

   return cgPsP->selTarget;
}

static ulong
cg_DirtyHelper_IndirectJump(const IRTemp dstTmp, const ulong dstIP)
{
   ASSERT(dstTmp >= 0);

   return cgBranchWork(Pbk_IndJump, dstTmp, dstIP, 0);
}

static ulong
cg_DirtyHelper_IndirectCall(const IRTemp dstTmp, const ulong dstIP,
      const ulong retIP)
{
   ASSERT(dstTmp >= 0);

   return cgBranchWork(Pbk_IndCall, dstTmp, dstIP, retIP);
}

static ulong
cg_DirtyHelper_Ret(const IRTemp dstTmp, const ulong dstIP)
{
   ASSERT(dstTmp >= 0);

   return cgBranchWork(Pbk_Ret, dstTmp, dstIP, 0);
}

static void
cg_DirtyHelper_DirectCall(const ulong dstIP, const ulong retIP)
{
   cgBranchWork(Pbk_DirectCall, -1, dstIP, retIP);
}

static int
cg_DirtyHelper_Cond(const IRTemp condTmp, const int condVal/*,*/) 
   //const ulong takenIP, const ulong notTakenIP)
{
   ASSERT(condVal == 1 || condVal == 0);
#if 0
   ASSERT_UPTR((void*)takenIP);
   ASSERT_UPTR((void*)notTakenIP);
   ASSERT(takenIP != notTakenIP);
#endif

   return cgBranchWork(Pbk_Cond, condTmp, condVal, 0);
}


/* XXX: there's a lot of code duplication here with the brchk code. */
int
cg_InstrCondExit(IRSB *bbOut, ulong currInsAddr, ulong currInsLen, IRStmt *st)
{
   IRDirty *dirty;
   int isBranchIns;

#if TREAT_REP_PREFIX_AS_BRANCH
   isBranchIns = BinTrns_IsTracedBranch(st->Ist.Exit.jk);
#else
   isBranchIns = BinTrns_IsTracedBranch(st->Ist.Exit.jk) && !BinTrns_IsRepPrefix(pc);
#endif

   if (isBranchIns) {
      int origGuardTmp, compGuardTmp, dirtyTmp, wideGuardTmp;
      IRStmt *narrowSt;


      /* VEX doesn't accept Ity_I1 as dirty function arguments, so we
       * must widen the exit guard bit. We could modify VEX to support 
       * it, but that may introduce bugs. And this is a simple enough fix. */
      ASSERT(st->Ist.Exit.guard->tag == Iex_RdTmp);
      origGuardTmp = st->Ist.Exit.guard->Iex.RdTmp.tmp;
      wideGuardTmp = newIRTemp(bbOut->tyenv, Ity_I32);
      addStmtToIRSB(bbOut,
            IRStmt_WrTmp(wideGuardTmp,
               IRExpr_Unop(Iop_1Uto32, st->Ist.Exit.guard)));

      dirtyTmp = newIRTemp(bbOut->tyenv, Ity_I32);
      dirty = MACRO_unsafeIRDirty_1_N(dirtyTmp, 0, 
            cg_DirtyHelper_Cond,
            mkIRExprVec_2(
               /* Taint is not propagated to the widened guard, so make
                * sure you use the original guard tmp. */
               mkIRExpr_UInt(origGuardTmp),
               IRExpr_RdTmp(wideGuardTmp) //,
#if 0
               IRExpr_Const(st->Ist.Exit.dst),
               mkIRExpr_HWord(currInsAddr+currInsLen)
#endif
               )
            );
      dirty->nFxState = 1;

      /* We'll need to save all GPRs + EIP; no FP regs */
      dirty->fxState[0].fx = Ifx_Modify;
      dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_EAX);
      dirty->fxState[0].size = 
         offsetof(VexGuestX86State, guest_IP_AT_SYSCALL) -
         offsetof(VexGuestX86State, guest_EAX);

      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));


      /* VEX accepts only Ity_I1 as branch guards, so we must narrow. */
      compGuardTmp = newIRTemp(bbOut->tyenv, Ity_I1);
      narrowSt = IRStmt_WrTmp(compGuardTmp, 
            IRExpr_Unop(Iop_32to1, IRExpr_RdTmp(dirtyTmp)));
      addStmtToIRSB(bbOut, narrowSt);

      /* Rewrite the exit to use our computed guard. */
      st = IRStmt_Exit(IRExpr_RdTmp(compGuardTmp), st->Ist.Exit.jk,
            st->Ist.Exit.dst);
   } 

   addStmtToIRSB(bbOut, st);

   return 0;
}

void
cg_InstrNonCondExit(IRSB *bbOut, ulong currInsAddr, ulong currInsLen)
{
   const int isIndirect = BinTrns_IsIndirectExit(bbOut);

   /* BrChk needs to know about direct calls (in addition
    * to all indirect jumps) to maintain its RSB. */
   if (isIndirect || bbOut->jumpkind == Ijk_Call) {
      IRDirty *dirty = NULL;
      IRExpr *dstExprP = bbOut->next;

      if (isIndirect) {
         /* Figure out what kind of indirect jump we are dealing
          * with and setup the appropriate helper call. We expect
          * the helper calls to return the (recorded) jump target
          * and we make sure that we exit the IRSB to that target. */
         ASSERT(dstExprP->tag == Iex_RdTmp);

         if (bbOut->jumpkind == Ijk_Boring) {
            dirty = MACRO_unsafeIRDirty_0_N(0, 
                  cg_DirtyHelper_IndirectJump,
                  mkIRExprVec_2(
                     mkIRExpr_UInt(cg_GetTempOrConst(dstExprP)),
                     dstExprP
                     )
                  );
         } else if (bbOut->jumpkind == Ijk_Call) {
            dirty = MACRO_unsafeIRDirty_0_N(0, 
                  cg_DirtyHelper_IndirectCall,
                  mkIRExprVec_3(
                     mkIRExpr_UInt(cg_GetTempOrConst(dstExprP)),
                     dstExprP,
                     /* retaddr (relevant for calls only) */
                     mkIRExpr_HWord(currInsAddr+currInsLen)
                     )
                  );
         } else if (bbOut->jumpkind == Ijk_Ret) {
            dirty = MACRO_unsafeIRDirty_0_N(0, 
                  cg_DirtyHelper_Ret,
                  mkIRExprVec_2(
                     mkIRExpr_UInt(cg_GetTempOrConst(dstExprP)),
                     dstExprP
                     )
                  );
         }

         ASSERT(dirty);

         /* Make sure we jump to the path-selector specified target. */
         dirty->tmp = newIRTemp(bbOut->tyenv, Ity_I32);
         bbOut->next = IRExpr_RdTmp(dirty->tmp);
      } else {
         ASSERT(bbOut->jumpkind == Ijk_Call);
         ASSERT(dstExprP->tag == Iex_Const);

         dirty = MACRO_unsafeIRDirty_0_N(0, 
               cg_DirtyHelper_DirectCall,
               mkIRExprVec_2(
                  /* retaddr (relevant for calls only) */
                  dstExprP,
                  mkIRExpr_HWord(currInsAddr+currInsLen)
                  )
               );
      }

      ASSERT(dirty);
      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   }
}

void
cg_BranchFini()
{
   int i;

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpuP = VCPU_Ptr(i);
      struct BranchCond *bcP = NULL;

#if 0
      ASSERT_UNIMPLEMENTED(NR_VCPU == 1);
      cgDoCFGJoinWork(cgPsP);
      ASSERT(!cgUndo_PeekTop());
#endif

      ASSERT(Map_GetSize(vcpuP->pcMapP) == 0);
      Map_Destroy(vcpuP->pcMapP, brIdMap, bcP);
   }
}
