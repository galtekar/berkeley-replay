#include "vkernel/public.h"
#include "private.h"

#if MAX_NR_VCPU > 1
static void
BusLockAcquire()
{
   Bus_Lock();
}

static void
BusLockRelease()
{
   Bus_Unlock();
}

static void
BusLockIRMBE(IRSB *bbOut, ulong currInsAddr, IRStmt *st)
{
   IRDirty *dirty;

   if (st->Ist.MBE.event == Imbe_BusLock) {
      dirty = unsafeIRDirty_0_N(0, "BusLockAcquire", 
            &BusLockAcquire,
            mkIRExprVec_0()
            );

      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   } else if (st->Ist.MBE.event == Imbe_BusUnlock) {
      dirty = unsafeIRDirty_0_N(0, "BusLockRelease", 
            &BusLockRelease,
            mkIRExprVec_0()
            );

      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   }
   addStmtToIRSB(bbOut, st);
}

static void
BusLockIRStmt(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   switch (st->tag)
   {
   case Ist_MBE:
      BusLockIRMBE(bbOut, pc, st);
      break;
   default:
      addStmtToIRSB(bbOut, st);
      break;
   }
}

static IRSB*
BusLockInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
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

      ASSERT(currInsAddr);
      BusLockIRStmt(bbOut, currInsAddr, st);
   }

   return bbOut;
}

static struct Module mod = {
   .name       = "Bus Lock Emulation",
   .modeFlags  = 0xFFFFFFFF,
   .onStartFn  = NULL,
   .onTermFn   = NULL,
   .onForkFn   = NULL,
   .onExitFn   = NULL,
   .instrFn    = &BusLockInstrument,
   .order      = MODULE_ORDER_FIRST,
};

static int
BusLock_Init()
{
   if (NR_VCPU > 1) {
      Module_Register(&mod);
   }

   return 0;
}

BT_INITCALL(BusLock_Init);
#endif
