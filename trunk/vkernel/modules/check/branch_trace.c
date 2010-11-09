#include "vkernel/public.h"
#include "private.h"

/* 
 * Each thread gets its own branch predictor.
 *
 * We don't burn branch nodes pointers into helper calls.
 * The reason is that different threads may run the same
 * instructions but the translation cache is shared among
 * all threads.
 *
 * Rather than burn in, we do the lookup for the branch node
 * within the helper call. This may be slow, but I see no
 * way around unless we give each thread a TC, but that
 * has a different set of problems...
 */

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



int
BrTrace_DoCond(struct BPred *bP, ulong currInsAddr, int isTaken)
{
   int pred;
   int correctOutcome;
   struct BranchNodeStruct *brp;

   ASSERT(isTaken == 0 || isTaken == 1);

   brp = BPred_GetBranch(bP, currInsAddr);


   pred = BPred_PredictBranch(brp);
#if DEBUG
   BrChkSanityCheckPrediction(pred);
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
}

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
#if 0
#if !DEBUG
#error "XXX: implement this check"
#endif
            if (predAddr != actualTargetAddr) {
               BrChkTreatDivergenceAsError();
            }
#endif

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

   DEBUG_MSG(7, "predAddr=0x%x targetAddr=0x%x\n", 
         predAddr, actualTargetAddr);

   BrChkIndJumpPredWork(predAddr, actualTargetAddr, &correctAddr);

#if DEBUG
   BrChkSanityCheckOutcome(correctAddr);
#endif

   return correctAddr;
}

ulong
BrTrace_DoIndirectJump(struct BPred *bP, ulong currInsAddr, ulong actualTargetAddr)
{
   ulong correctAddr;
   struct BranchNodeStruct *brp;

   brp = BPred_GetBranch(bP, currInsAddr);

   correctAddr = BrChkGetIndJumpPred(brp, actualTargetAddr);

   BPred_LearnIndirectJump(brp, correctAddr);

   return correctAddr;
}

ulong
BrTrace_DoIndirectCall(struct BPred *bP, ulong currInsAddr, 
      ulong actualTargetAddr, ulong retTargetAddr)
{
   ulong correctAddr;
   struct BranchNodeStruct *brp;

   brp = BPred_GetBranch(bP, currInsAddr);

   correctAddr = BrChkGetIndJumpPred(brp, actualTargetAddr);

   BPred_LearnIndirectCall(bP, brp, correctAddr, retTargetAddr);

   return correctAddr;
}

void
BrTrace_DoDirectCall(struct BPred *bP, ulong currInsAddr, ulong retTargetAddr)
{
   DEBUG_MSG(7, "Direct call: retAddr=0x%x\n", retTargetAddr);

   /* Value is encoded in instruction, so destination is always the same 
    * and thus predictable. We still need to put the retaddr in the RSB
    * though. */
   BPred_LearnDirectCall(bP, retTargetAddr);
}

ulong
BrTrace_DoRet(struct BPred *bP, ulong currInsAddr, ulong actualTargetAddr)
{
   ulong predAddr, correctAddr;

   correctAddr = predAddr = BPred_PredictRet(bP);
#if DEBUG
   BrChkSanityCheckPrediction(predAddr);
#endif

   BrChkIndJumpPredWork(predAddr, actualTargetAddr, &correctAddr);

   /* Advance the RSB pointer. */
   BPred_LearnRet(bP);

#if DEBUG
   BrChkSanityCheckOutcome(correctAddr);
#endif

   return correctAddr;
}
