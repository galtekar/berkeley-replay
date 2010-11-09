#include "vkernel/public.h"
#include "private.h"

#define DEBUG_HACK 0

/*
 * Design notes:
 *
 * o Must exit and enter dispatch loop on RDTSC rather than
 * handle it via a dirty helper. 
 *
 * The reason is that there
 * may be an upcoming preemption in the same super-block, in
 * which case we need to invalidate the block and instrument it
 * with notification checks (see notify.c). But we can't
 * do that if we are still executing the super-block.
 *
 * If we do handle it via a dirty helper, then we will miss
 * preemption points. I've seen this happen with mySql, usually
 * at the very start of a thread's execution, where it makes
 * an RDTSC call and then, while executing the super block,
 * gets a preemption.
 *
 * We initially handled RDTSC with a helper rather than an exit
 * because it seems that other code in the translated block
 * makes use of the dirtyTmp written by the RDTSC helper, which
 * meant that we had to rewrite that code if we wanted to
 * instrument notifications, and that's more work.
 *
 * The lesson seems to be that we must exit to dispatch
 * after returning from a helper call that consumes a log-entry.
 *
 */

#if DEBUG_HACK
static void
EntryIRMark(IRSB *bbOut, IRStmt *st, ulong currInsAddr)
{
   IRDirty *dirty;

   dirty = unsafeIRDirty_0_N(0, "Core_x86g_Dirtyhelper_IRMark",
         &Core_x86g_DirtyHelper_IRMark, 
         mkIRExprVec_1(mkIRExpr_HWord(currInsAddr)));

   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}
#endif

static IRSB*
EntryInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   int i, foundTscCall = 0;

   IRSB *bbOut;
   ulong currInsAddr = 0, currInsLen = 0;

   ASSERT(bbIn->stmts_used > 0);

   bbOut = emptyIRSB();
   bbOut->tyenv = deepCopyIRTypeEnv(bbIn->tyenv);
   bbOut->jumpkind = bbIn->jumpkind;
   bbOut->next = deepCopyIRExpr(bbIn->next);

   for (i = 0; i < bbIn->stmts_used && !foundTscCall; i++) {
      IRStmt *st = bbIn->stmts[i];
      if (st->tag == Ist_IMark) {
         currInsAddr = st->Ist.IMark.addr;
         currInsLen = st->Ist.IMark.len;

#if DEBUG_HACK
         EntryIRMark(bbOut, st, currInsAddr);
#endif
      }

      if (!currInsAddr) {
         ASSERT(!currInsLen);
         /* Skip instrumentation of IR preamble if it exists 
          * (e.g., self-check preamble if self-checking is turned on). */
         addStmtToIRSB(bbOut, st);
         continue;
      }

      if (st->tag == Ist_Exit) {
         ASSERT(!BinTrns_IsSyscall(st->Ist.Exit.jk));
      }

      if (st->tag == Ist_Dirty &&
          strstr(st->Ist.Dirty.details->cee->name, "RDTSC")) {
         foundTscCall = 1;
      } else {
         addStmtToIRSB(bbOut, st);
      }
   }


   if (foundTscCall) {
      /* Fixup -- pick an unused (hopefully) Ijk_ to represent a TSC
       * call. */
      bbOut->jumpkind = Ijk_Sys_int129;
      //bbOut->next = mkIRExpr_HWord(currInsAddr+currInsLen);
      /* We need to emulate trap behavior in DE mode -- there eip is
       * the instruction of the trapping insns, NOT the instruction
       * after it. */
      bbOut->next = mkIRExpr_HWord(currInsAddr);
   } else if (BinTrns_IsSyscall(bbOut->jumpkind)) {
   } else if (BinTrns_IsTrap(bbOut->jumpkind)) {
      ASSERT_UNIMPLEMENTED(0);
   }

   return bbOut;
}

static struct Module mod = {
   .name          = "Vkernel Entry Interception",
   .modeFlags     = 0xFFFFFFFF,
   .onStartFn     = NULL,
   .onTermFn      = NULL,
   .onForkFn      = NULL,
   .onExitFn      = NULL,
   .onVmaEventFn  = NULL,
   .instrFn       = &EntryInstrument,
   .order         = MODULE_ORDER_FIRST,
};

static int
Entry_Init()
{
   Module_Register(&mod);

   return 0;
}

BT_INITCALL(Entry_Init);
