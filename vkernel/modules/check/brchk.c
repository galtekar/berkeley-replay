/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

/*
 * During logging, record the path taken by a thread.
 * We record branch outcomes and indirect branch targets.
 * During replay, force the thread along the recorded path 
 * (i.e., path-enforced execution). 
 */

/* 
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

/* If a branch outcome diverges from the recorded outcome,
 * should we force the recorded outcome? */
static int enforceBranches = 1;

static void
BrChkTreatDivergenceAsError()
{
   FATAL("Divergence detected.\n");
}

#if 0
/* Returns 1 if misprediction, 0 if not. */
static INLINE int
BrChkHandleBranchMispredict()
{
   int res = 1;
   ullong currBrCnt = BrCnt_Get();

   if (Check_IsLogging()) {
      CHECK_DO_WITH_LOG_ENTRY(BrChkMispredict) {
         entryp->brCnt = currBrCnt;
      } END_WITH_LOG_ENTRY(0);
   } else {
      DECLARE_LOG_ENTRY_POINTER(BrChkMispredict, peekp);
      if (CHECK_PEEK_LOG_ENTRY(BrChkMispredict, peekp)) {
         if (peekp->brCnt == currBrCnt) {
            /* Consume the entry. */
            CHECK_DO_WITH_LOG_ENTRY(BrChkMispredict) {
               ASSERT(entryp->brCnt == currBrCnt);
            } END_WITH_LOG_ENTRY(0);
            res = 1;
         } else {
            /* There wasn't a misprediction at this brcnt during
             * logging, so the predictor must be right. */
            DEBUG_MSG(5, "peekp->brCnt=%llu brCnt=%llu\n",
                  peekp->brCnt, currBrCnt);
            res = 0;
         }
      } else {
         res = 0;
      }
   }

   return res;
}

/* PEX = Path-Enforced Execution. */
#define TEST_PEX_MODE 0

#if DEBUG
/*
 * Predictions should be deterministic.
 */
static INLINE void
BrChkSanityCheckPrediction(ulong pred)
{
   if (Check_IsLogging()) {
      CHECK_DO_WITH_LOG_ENTRY(BrChkPrediction) {
         entryp->pred = pred;
      } END_WITH_LOG_ENTRY(0);

   } else {
      CHECK_DO_WITH_LOG_ENTRY(BrChkPrediction) {
         ASSERT(pred == entryp->pred);
      } END_WITH_LOG_ENTRY(0);
   }

   DEBUG_MSG(7, "pred=0x%x\n", pred);
}

static INLINE void
BrChkSanityCheckOutcome(ulong outcome)
{
   if (Check_IsLogging()) {
      CHECK_DO_WITH_LOG_ENTRY(BrChkOutcome) {
         entryp->outcome = outcome;
      } END_WITH_LOG_ENTRY(0);

   } else {
      CHECK_DO_WITH_LOG_ENTRY(BrChkOutcome) {
         ASSERT(outcome == entryp->outcome);
      } END_WITH_LOG_ENTRY(0);
   }

   DEBUG_MSG(7, "outcome=0x%x\n", outcome);
}
#endif
#endif


int
BrChk_DirtyHelper_Branch(ulong currInsAddr, int isTaken)
{
#if 0
   int pred;
   int correctOutcome;
   struct BranchNodeStruct *brp;
   
   brp = BPred_GetBranch(current->bt.brPredP, currInsAddr);


   pred = BPred_PredictBranch(brp);
#if DEBUG
   BrChkSanityCheckPrediction(pred);
#endif


#if TEST_PEX_MODE
   if (Check_IsReplaying()) {
      isTaken = !pred;
   }
#endif

   DEBUG_MSG(7, "pred=%d isTaken=%d\n", pred, isTaken);

   correctOutcome = pred;

   if (Check_IsLogging()) {
      if (pred != isTaken) {
         BrChkHandleBranchMispredict();
         correctOutcome = isTaken;
      } else {
         ASSERT(correctOutcome == isTaken);
      }
   } else {

      if (BrChkHandleBranchMispredict()) {
#if DEBUG
         /* Note that there may have been a mispredict, even
          * if pred == isTaken -- that's because isTaken may
          * be different during replay, due to input/race-induced 
          * divergences. */
         ASSERT(pred == isTaken || pred != isTaken);
#endif

         correctOutcome = !pred;
      } else {
         ASSERT(correctOutcome == pred);

         if (pred != isTaken) {
            if (!enforceBranches) {
               BrChkTreatDivergenceAsError();
            }
         }
      }
   }

   BPred_LearnBranch(brp, correctOutcome);

#if DEBUG
   if (Check_IsLogging()) {
      ASSERT(correctOutcome == isTaken);
   }

   BrChkSanityCheckOutcome(correctOutcome);
#endif

   return correctOutcome;
#endif
   int outcome = BrTrace_DoCond(current->bt.brPredP, currInsAddr, isTaken);

   if (outcome != isTaken) {
      if (!enforceBranches) {
         BrChkTreatDivergenceAsError();
      }
   }

   return outcome;
}

#if 0
/* Returns correct target address of jump, 0 if predicted address is
 * the correct target address. */
static INLINE int
BrChkHandleIndirectMispredict(ulong actualTarget, ulong * correctAddrp)
{
   int res = 0;
   ullong currBrCnt = BrCnt_Get();

   if (Check_IsLogging()) {
      CHECK_DO_WITH_LOG_ENTRY(BrChkIndirectJumpMispredict) {
         entryp->brCnt = currBrCnt;
         entryp->actualTarget = actualTarget;
      } END_WITH_LOG_ENTRY(0);

   } else {
      DECLARE_LOG_ENTRY_POINTER(BrChkIndirectJumpMispredict, peekp);
      if (CHECK_PEEK_LOG_ENTRY(BrChkIndirectJumpMispredict, peekp)) {
         if (peekp->brCnt == currBrCnt) {
            /* Consume the log entry. */
            CHECK_DO_WITH_LOG_ENTRY(BrChkIndirectJumpMispredict) {
               *correctAddrp = entryp->actualTarget;
            } END_WITH_LOG_ENTRY(0);
            res = 1;
         } else {
            /* Premature mispredict ... predictor is correct. */
         }
      } else {
         /* Not an indirect jump log entry, and thus an indirect jump
          * could not have occurred at this point. Hence,
          * this is a premature mispredict or divergence and the predictor 
          * is correct. */
      }
   }

#if 0
   if (!res) {
      *correctAddrp = actualTarget;
   }
#endif

   return res;
}

static INLINE void
BrChkIndJumpPredWork(ulong predAddr, ulong actualTargetAddr, 
                     ulong * correctAddrp)
{
   if (Check_IsLogging()) {
      if (predAddr != actualTargetAddr) {
         BrChkHandleIndirectMispredict(actualTargetAddr, correctAddrp);
         *correctAddrp = actualTargetAddr;
      } else {
         ASSERT(*correctAddrp == predAddr);
         ASSERT(predAddr == actualTargetAddr);
         ASSERT(*correctAddrp == actualTargetAddr);
      }
   } else {
      if (BrChkHandleIndirectMispredict(actualTargetAddr, correctAddrp)) {

         /* During logging actualTarget may have differed, but during
          * replay it could be be same (due to divergences). */
         ASSERT(*correctAddrp == actualTargetAddr || 
                *correctAddrp != actualTargetAddr);
      } else {
         /* There was no mispredict at this point, so predAddr is
          * correct. Don't use actualTargetAddr, since that is not
          * reliable during replay --- it may have diverged. */

         if (0 /* VCPU_IsReplaying() == VALUE */) {
#if !DEBUG
#error "XXX: implement this check"
#endif
            if (predAddr != actualTargetAddr) {
               BrChkTreatDivergenceAsError();
            }

            ASSERT(*correctAddrp == predAddr);
         } else {
            *correctAddrp = predAddr;
         }
      }
   }
}

static INLINE ulong
BrChkGetIndJumpPred(struct BranchNodeStruct *brp, ulong actualTargetAddr)
{
   ulong predAddr, correctAddr;

   correctAddr = predAddr = BPred_PredictIndirectJump(brp);
#if DEBUG
   /* XXX: wouldn't it be more useful to sanity check the correctAddr?
    * */
   BrChkSanityCheckPrediction(predAddr);
#endif

#if TEST_PEX_MODE
   if (Check_IsReplaying()) {
      actualTargetAddr = 0xdeadbeef;
   }
#endif

   DEBUG_MSG(7, "predAddr=0x%x targetAddr=0x%x\n", 
         predAddr, actualTargetAddr);

   BrChkIndJumpPredWork(predAddr, actualTargetAddr, &correctAddr);

#if DEBUG
   BrChkSanityCheckOutcome(correctAddr);
#endif

   return correctAddr;
}
#endif

static ulong
BrChk_DirtyHelper_IndirectJump(ulong currInsAddr, ulong actualTargetAddr)
{
#if 0
   ulong correctAddr;
   struct BranchNodeStruct *brp;

   brp = BPred_GetBranch(current->bt.brPredP, currInsAddr);

   correctAddr = BrChkGetIndJumpPred(brp, actualTargetAddr);

   BPred_LearnIndirectJump(brp, correctAddr);

   return correctAddr;
#else
   return BrTrace_DoIndirectJump(current->bt.brPredP, currInsAddr, 
         actualTargetAddr);
#endif
}

static ulong
BrChk_DirtyHelper_IndirectCall(ulong currInsAddr, ulong actualTargetAddr, 
      ulong retTargetAddr)
{
#if 0
   ulong correctAddr;
   struct BranchNodeStruct *brp;
   struct BPred *bt = current->bt.brPredP;

   brp = BPred_GetBranch(bt, currInsAddr);

   correctAddr = BrChkGetIndJumpPred(brp, actualTargetAddr);

   BPred_LearnIndirectCall(bt, brp, correctAddr, retTargetAddr);

   return correctAddr;
#else
   return BrTrace_DoIndirectCall(current->bt.brPredP, currInsAddr, 
         actualTargetAddr, retTargetAddr);
#endif
}

static void
BrChk_DirtyHelper_DirectCall(ulong currInsAddr, ulong retTargetAddr)
{
#if 0
   struct BPred *bt = current->bt.brPredP;

   DEBUG_MSG(7, "Direct call: retAddr=0x%x\n", retTargetAddr);

   /* Value is encoded in instruction, so destination is always the same 
    * and thus predictable. We still need to put the retaddr in the RSB
    * though. */
   BPred_LearnDirectCall(bt, retTargetAddr);
#else
   BrTrace_DoDirectCall(current->bt.brPredP, currInsAddr,
         retTargetAddr);
#endif
}

static ulong
BrChk_DirtyHelper_Ret(ulong currInsAddr, ulong actualTargetAddr)
{
#if 0
   ulong predAddr, correctAddr;
   struct BPred *bt = current->bt.brPredP;

   correctAddr = predAddr = BPred_PredictRet(bt);
#if DEBUG
   BrChkSanityCheckPrediction(predAddr);
#endif

   BrChkIndJumpPredWork(predAddr, actualTargetAddr, &correctAddr);

   /* Advance the RSB pointer. */
   BPred_LearnRet(bt);

#if DEBUG
   BrChkSanityCheckOutcome(correctAddr);
#endif

   return correctAddr;
#else
   return BrTrace_DoRet(current->bt.brPredP, currInsAddr, actualTargetAddr);
#endif
}


static void
BrChkIRExit(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRDirty *dirty;
   int isBranchIns;

#if TREAT_REP_PREFIX_AS_BRANCH
   isBranchIns = BinTrns_IsTracedBranch(st->Ist.Exit.jk);
#else
   isBranchIns = BinTrns_IsTracedBranch(st->Ist.Exit.jk) && !BinTrns_IsRepPrefix(pc);
#endif

   if (isBranchIns) {
      int compGuardTmp, dirtyTmp, wideGuardTmp;
      IRStmt *narrowSt;


      /* VEX doesn't accept Ity_I1 as dirty function arguments, so we
       * must widen the exit guard bit. We could modify VEX to support 
       * it, but that may introduce bugs. And this is a simple enough fix. */
      wideGuardTmp = newIRTemp(bbOut->tyenv, Ity_I32);
      addStmtToIRSB(bbOut,
            IRStmt_WrTmp(wideGuardTmp,
               IRExpr_Unop(Iop_1Uto32, st->Ist.Exit.guard)));

      dirtyTmp = newIRTemp(bbOut->tyenv, Ity_I32);
      dirty = unsafeIRDirty_1_N(dirtyTmp, 0, "BrChk_DirtyHelper_Branch",
            &BrChk_DirtyHelper_Branch,
            mkIRExprVec_2(
               mkIRExpr_HWord(pc),
               IRExpr_RdTmp(wideGuardTmp)
               )
            );
      dirty->nFxState = 1;

      /* We'll need to save all GPRs + EIP; no FP regs */
      dirty->fxState[0].fx = Ifx_Modify;
      dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_EAX);
      dirty->fxState[0].size = offsetof(VexGuestX86State, guest_IP_AT_SYSCALL) -
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
}

static void
BrChkIRStmt(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   switch (st->tag)
   {
   case Ist_Exit:
      /* Must insert helpers before the jump takes
       * place. */
      BrChkIRExit(bbOut, pc, st);
      break;

   default:
      addStmtToIRSB(bbOut, st);
      break;
   }
}

static IRSB*
BrChkInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   int i;
   IRSB *bbOut;
   ulong currInsAddr = 0, currInsLen = 0;
   int isIndirect;

   ASSERT(bbIn->stmts_used > 0);

   bbOut = emptyIRSB();
   bbOut->tyenv = deepCopyIRTypeEnv(bbIn->tyenv);
   bbOut->jumpkind = bbIn->jumpkind;
   bbOut->next = deepCopyIRExpr(bbIn->next);

   for (i = 0; i < bbIn->stmts_used; i++) {
      IRStmt *st = bbIn->stmts[i];
      if (st->tag == Ist_IMark) {
         currInsAddr = st->Ist.IMark.addr;
         currInsLen = st->Ist.IMark.len;
      }

      if (!currInsAddr) {
         ASSERT(!currInsLen);
         /* Skip instrumentation of IR preamble if it exists 
          * (e.g., self-check preamble if self-checking is turned on). */
         addStmtToIRSB(bbOut, st);
         continue;
      }

      /* Add helper calls if necessary (e.g., callouts to inform
       * BrChk of a load/store or branch emulation). */
      ASSERT(currInsAddr);
      BrChkIRStmt(bbOut, currInsAddr, st);
   }

   isIndirect = BinTrns_IsIndirectExit(bbOut);

   /* BrChk needs to know about direct calls (in addition
    * to all indirect jumps) to maintain its RSB. */
   if (isIndirect || bbOut->jumpkind == Ijk_Call) {
      IRDirty *dirty = NULL;

      if (isIndirect) {
         /* Figure out what kind of indirect jump we are dealing
          * with and setup the appropriate helper call. We expect
          * the helper calls to return the (recorded) jump target
          * and we make sure that we exit the IRSB to that target. */
         ASSERT(bbOut->next->tag == Iex_RdTmp);
         if (bbOut->jumpkind == Ijk_Boring) {
            dirty = unsafeIRDirty_0_N(0, "BrChk_DirtyHelper_IndirectJump",
                  &BrChk_DirtyHelper_IndirectJump,
                  mkIRExprVec_2(
                     mkIRExpr_HWord(currInsAddr),
                     bbOut->next /* jump target */
                     )
                  );
         } else if (bbOut->jumpkind == Ijk_Call) {
            dirty = unsafeIRDirty_0_N(0, "BrChk_DirtyHelper_IndirectCall",
                  &BrChk_DirtyHelper_IndirectCall,
                  mkIRExprVec_3(
                     mkIRExpr_HWord(currInsAddr),
                     bbOut->next /* jump target */,
                     /* retaddr (relevant for calls only) */
                     mkIRExpr_HWord(currInsAddr+currInsLen)
                     )
                  );
         } else if (bbOut->jumpkind == Ijk_Ret) {
            dirty = unsafeIRDirty_0_N(0, "BrChk_DirtyHelper_Ret",
                  &BrChk_DirtyHelper_Ret,
                  mkIRExprVec_2(
                     mkIRExpr_HWord(currInsAddr),
                     bbOut->next /* jump target */
                     )
                  );
         }

         ASSERT(dirty);
         /* Make sure we jump to the recorded target. */
         dirty->tmp = newIRTemp(bbOut->tyenv, Ity_I32);
         bbOut->next = IRExpr_RdTmp(dirty->tmp);
      } else {
         ASSERT(bbOut->jumpkind == Ijk_Call);
         dirty = unsafeIRDirty_0_N(0, "BrChk_DirtyHelper_DirectCall",
               &BrChk_DirtyHelper_DirectCall,
               mkIRExprVec_2(
                  /* retaddr (relevant for calls only) */
                     mkIRExpr_HWord(currInsAddr),
                  mkIRExpr_HWord(currInsAddr+currInsLen)
                  )
               );
      }

      ASSERT(dirty);
      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   }

#if 0
   DEBUG_MSG(5, "After branch check.\n");
   ppIRSB(bbOut);
#endif

   return bbOut;
}

static void
BrChkFork(struct Task *tsk)
{
   /* XXX: we should inherit the prediction histories on 
    * thread/process creations to avoid mispredictions. */
   tsk->bt.brPredP = BPred_Create();
}


static void
BrChkSelfExit()
{
   BPred_Destroy(current->bt.brPredP);
   current->bt.brPredP = NULL;
}

static struct Module mod = {
   .name       = "Branch Check",
   .modeFlags  = 0xFFFFFFFF,
   .onStartFn  = NULL,
   .onTermFn   = &BrChkSelfExit,
   .onForkFn   = &BrChkFork,
   .onExitFn   = NULL,
   .instrFn    = &BrChkInstrument,
   /* Must be done before formgen, so that it can see the recorded
    * branch outcome during replay. */
   .order      = MODULE_ORDER_FIRST,
};

int
BrChk_Init()
{
   if (1) {
      DEBUG_MSG(5, "Initializing branch check.\n");
      Module_Register(&mod);
      BrChkFork(current);

      return 1;
   }

   return 0;
}
