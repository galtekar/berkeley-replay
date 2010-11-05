/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

/*
 * ----- Software preemption ----- 
 *
 * The vkernel uses preemptions to provide multitasking
 * and to deliver asynchronous signals. In DE mode,
 * the hardware provides preemptions in the form of a
 * timer signal. But in BT mode, we can't receive timer signals.
 * That's because, in BT mode, we execute code from within the 
 * code cache. This code cache lies within the vkernel segment and
 * and (almost) all signals are blocked while executing vkernel
 * code. Hence the need for BT software preemption arises.
 *
 * Design goals:
 *    
 *    Preemption should happen at the start or end of an IRSB, but 
 *    never within. This simplifies reasoning about replay.
 *
 *    Emulate hardware preemption as closely as possible: look-ahead 
 *    preemption schdeduling -- anticipate upcoming preemption and request
 *    notification. For hardware preemption, this is done after
 *    a syscall, since we know that only a preemption or syscall
 *    entry can come next.
 *
 *
 * History:
 *
 *    o Intially implemented as a check before every IRSB exit. If
 *    exceeded threshold brach count, then would assert the PREEMPT
 *    flag, hence letting the gate code know that a preemption was
 *    generated. The problem was that this required additional memory in
 *    the dispatch to recognize when the PREEMPT flag was set and to
 *    bail out into the gate code.
 *
 *    o The initial scheme was replaced with one in which we check for
 *    preemption at the start of every IRSB, and if a threshold number
 *    of IRSBs has been executed, then we bail out with a Ijk_Yield
 *    error code. This doesn't require any additional machinery, as the
 *    dispatch code is already written to recognize when the dispatcher
 *    returns an error code.
 *
 */

/* How many IRSBs executed before context switch preemption? The 
 * lower the value, the lower the signal delivery latency and the greater 
 * the overhead. */
#define PREEMPT_THRESHOLD 2000

static INLINE void
PreemptReset(struct Task *tsk)
{
   tsk->ticksToPreempt = PREEMPT_THRESHOLD;
}

/*
 * Returns 1 if we should issue a software preemption. 
 */
static int
Core_x86g_DirtyHelper_SoftPreemptCheck()
{
   current->ticksToPreempt--;

   if (current->ticksToPreempt == 0) {
      PreemptReset(current);

      DEBUG_MSG(5, "Software preemption @ brCnt=%llu.\n",
            BrCnt_Get());

      Task_SetCurrentFlag(TIF_PREEMPT_TIMER);
      return 1;
   }

   return 0;
}

static void
PreemptIRPreamble(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRTemp dirtyTmp = newIRTemp(bbOut->tyenv, Ity_I32);
   addStmtToIRSB(bbOut, IRStmt_Dirty(
      unsafeIRDirty_1_N(dirtyTmp, 0, "Core_x86g_DirtyHelper_SoftPreemptCheck", 
         &Core_x86g_DirtyHelper_SoftPreemptCheck,
         mkIRExprVec_0()
         )));

   IRTemp guardTmp = newIRTemp(bbOut->tyenv, Ity_I1);
   addStmtToIRSB(bbOut, 
         IRStmt_WrTmp(guardTmp, 
            IRExpr_Unop(Iop_32to1, IRExpr_RdTmp(dirtyTmp))));

   addStmtToIRSB(bbOut, 
         IRStmt_Exit(IRExpr_RdTmp(guardTmp), Ijk_Yield,
            IRConst_U32(pc)));
}

static IRSB*
PreemptInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   int i;
   IRSB *bbOut;
   ulong currInsAddr = 0, currInsLen = 0;

   ASSERT(bbIn->stmts_used > 0);

   bbOut = emptyIRSB();
   bbOut->tyenv = deepCopyIRTypeEnv(bbIn->tyenv);
   bbOut->jumpkind = bbIn->jumpkind;
   bbOut->next = deepCopyIRExpr(bbIn->next);

   for (i = 0; i < bbIn->stmts_used; i++) {
      IRStmt *st = bbIn->stmts[i];

      if (st->tag == Ist_IMark) {
         if (!currInsAddr) {
            PreemptIRPreamble(bbOut, st->Ist.IMark.addr, st);
         }

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
       * Preempt of a load/store or branch emulation). */
      ASSERT(currInsAddr);
      addStmtToIRSB(bbOut, st);
   }
   return bbOut;
}

static void
PreemptFork(struct Task *tsk)
{
   PreemptReset(tsk);
}

static struct Module mod = {
   .name          = "Software Preemption",
   .modeFlags     = 0xFFFFFFFF,
   .onStartFn     = NULL,
   .onTermFn      = NULL,
   .onForkFn      = PreemptFork,
   .onExitFn      = NULL,
   .onVmaEventFn  = NULL,
   .instrFn       = PreemptInstrument,
   .order         = MODULE_ORDER_CORE,
};

static int
Preempt_Init()
{
#define SOFT_PREEMPT_ENABLED 0

#if SOFT_PREEMPT_ENABLED
#warning "replay won't work, for some reason"
#endif

   /* This module is asserted only during non-replay mode. During replay,
    * we take preemptions from the log file. */
   if (0) {
      if (!VCPU_IsReplaying()) {
         PreemptReset(current);
         Module_Register(&mod);
      }
   }

   return 0;
}

BT_INITCALL(Preempt_Init);
