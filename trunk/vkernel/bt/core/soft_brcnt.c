#include "vkernel/public.h"
#include "private.h"

#include <errno.h>

/* 
 * ----- Software branch counting -----
 *
 * The goal of this module is to emulate the hardware branch
 * counting mechanism precisely while running code in BT.
 * For example, if the harware counter increments by 2 for a conditional
 * jumps, so must the software counter. This property allows
 * us to replay in BT and deliver events at branch counts collected
 * with the hardware counter.
 *
 * Since the hardware counter measures both taken and not taken
 * branches, so do we. We also count jumps, calls, rets, and
 * indirect varietes, just like the hardware counter. But note
 * that the hardware counter doesn't count rep instrFnuctions.
 * So we make sure we don't either by inspecting the instrFnuction
 * opcode (we can't tell just by looking at the IR).
 *
 */

static void
Core_x86g_DirtyHelper_CondBranch()
{
   /* Hardware counter increments by 2 on conditional branches
    * (essentially all Jcc -- JNE, JZ, JE, etc).
    * Why it does so is beyond me, but we must emulate nevertheless. */
   current->softBrCnt += 2;
}

static void
Core_x86g_DirtyHelper_NonCondBranch()
{
   /* The hardware counter increments by 1 for calls, rets, directs jumps,
    * and indirect varieties, as you would expect. */
   current->softBrCnt++;
}

static void
SoftBrCntIRExit(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRDirty *dirty;
   int isBranchIns;

   /* PMCs don't consider instructions with the REP prefix
    * to be branches, so we shouldn't either. This consistency is
    * important, as it allows us to replay in BT mode those executions
    * logged in DE mode (i.e., with HW branch counts). */
   isBranchIns = BinTrns_IsBranch(st->Ist.Exit.jk) && 
                 !BinTrns_IsRepPrefix(pc);

   if (isBranchIns) {
      dirty = unsafeIRDirty_0_N(0, 
            "Core_x86g_DirtyHelper_CondBranch",
            &Core_x86g_DirtyHelper_CondBranch,
            mkIRExprVec_0()
            );

      ASSERT(st->Ist.Exit.jk == Ijk_Boring);
      /* Will the guard ever be a constant? Don't think so. */
      ASSERT(st->Ist.Exit.guard->tag == Iex_RdTmp);
      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   }

   addStmtToIRSB(bbOut, st);
}


static void
SoftBrCntIRStmt(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   switch (st->tag)
   {
   case Ist_Exit:
      /* Must insert helpers before the jump takes place. */
      SoftBrCntIRExit(bbOut, pc, st);
      break;
   default:
      addStmtToIRSB(bbOut, st);
      break;
   }
}

static IRSB*
SoftBrCntInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   int i;
   IRSB *bbOut;
   IRDirty *dirty;
   ulong currInsAddr = 0, currInsLen = 0;
   int insHasCondExit = 0;

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
         insHasCondExit = 0;
      }

      if (!currInsAddr) {
         ASSERT(!currInsLen);
         /* Skip instrumentation of IR preamble if it exists 
          * (e.g., self-check preamble if self-checking is turned on). */
         addStmtToIRSB(bbOut, st);
         continue;
      }


      /* Could be MapFail when dealing with segment selectors. */
      if (st->tag == Ist_Exit && st->Ist.Exit.jk == Ijk_Boring) {
         insHasCondExit = 1;
      }

      /* Add helper calls if necessary (e.g., callouts to inform
       * SoftBrCnt of a branch). */
      ASSERT(currInsAddr);
      SoftBrCntIRStmt(bbOut, currInsAddr, st);
   }

   if (insHasCondExit) {
      ASSERT(bbOut->jumpkind == Ijk_Boring);
   }

   /* Now instrument unconditional exits. Also, hardware counter doesn't
    * count rep prefix as a branch, so neither should we. 
    *
    * Note that Ijk_Boring doesn't imply the instrFnuction is a branch.
    * It could be a REPed instrFnuction.
    *
    * CAREFUL: The REP prefix can come before a RET insn (!!). */
   if (!insHasCondExit && BinTrns_IsBranch(bbOut->jumpkind) && 
       (bbOut->jumpkind != Ijk_Boring || !BinTrns_IsRepPrefix(currInsAddr))) {
      /* BB exit statements don't have guards and thus are always taken. */
      dirty = unsafeIRDirty_0_N(0,
            "Core_x86g_DirtyHelper_NonCondBranch",
            &Core_x86g_DirtyHelper_NonCondBranch,
            mkIRExprVec_0()
            );
      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   }

   return bbOut;
}

static void
SoftBrCntFork(struct Task *tsk)
{
   tsk->softBrCnt = 0;
}

static struct Module mod = {
   .name          = "Software Branch Counting",
   .modeFlags     = 0xFFFFFFFF,
   .onStartFn     = NULL,
   .onTermFn      = NULL,
   .onForkFn      = SoftBrCntFork,
   .onExitFn      = NULL,
   .instrFn       = SoftBrCntInstrument,
   .order         = MODULE_ORDER_CORE,
};

static int
SoftBrCnt_Init()
{
   if (1) {
      Module_Register(&mod);
   }

   current->softBrCnt = 0;

   return 0;
}

BT_INITCALL(SoftBrCnt_Init);
