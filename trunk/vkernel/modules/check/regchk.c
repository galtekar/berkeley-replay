#include <errno.h>

#include "vkernel/public.h"
#include "private.h"

/*
 *
 * Known errors:
 *
 * o App (e.g., java) sets FPU CW precision (bits 8 and 9) to a 
 * non-64 bit precision during logging, but during BT-mode replay,
 * VEX ignores the non-64 bit setting (but it does output an emulation
 * warning). And when the CW is observed in the future via FSTCW, 
 * VEX returns the default status word of 0x037F (ORed with the 
 * rounding) mode, which then causes divergence in the register to 
 * which the CW was loaded.
 */


static void
RegChkNonRepPrefixHelper(TaskArchState *archSt)
{
   ASSERT(curr_regs == &archSt->vex);

   /* SS trap is generated for each REP iteration. */
   Check_DoRegs(&archSt->vex);
}

static void
RegChkRepPrefixHelper(TaskArchState *archSt)
{
   /* Record only once, right before the first iteration --
    * even if there is no first iteration. This is to mimic
    * our recording of ss traps. */
   DEBUG_MSG(5, "repCount=%d\n", current->bt.repCount);
   if (current->bt.repCount == 0) {
      Check_DoRegs(&archSt->vex);
   }

   current->bt.repCount++;
}

static void
RegChkRepExitHelper(int willExit)
{
   if (willExit) {
      current->bt.repCount = 0;
   }
}

static void
RegChkRepFallExitHelper(ulong pc, ulong nextPc)
{
   if (nextPc != pc) {
      current->bt.repCount = 0;
   }
}

static void
RegChkNonRepPrefix(IRSB *bbOut)
{
   IRDirty *dirty;

   dirty = BinTrns_DirtyHelperThatReadsRegs(0,
               "RegChkNonRepPrefixHelper",
               &RegChkNonRepPrefixHelper,
               mkIRExprVec_0());

   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

static void
RegChkRepPrefix(IRSB *bbOut)
{
   IRDirty *dirty;

   dirty = BinTrns_DirtyHelperThatReadsRegs(0, "RegChkRepPrefixHelper",
                  &RegChkRepPrefixHelper,
                  mkIRExprVec_0());
   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

static void
RegChkRepExit(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRDirty *dirty;

   int wideGuardTmp;

   ASSERT(st->tag == Ist_Exit);

   /* VEX doesn't accept Ity_I1 as dirty function arguments, so we
    * must widen the exit guard bit. We could modify VEX to support 
    * it, but that may introduce bugs. And this is a simple enough fix. */
   wideGuardTmp = newIRTemp(bbOut->tyenv, Ity_I32);
   addStmtToIRSB(bbOut,
         IRStmt_WrTmp(wideGuardTmp,
            IRExpr_Unop(Iop_1Uto32, st->Ist.Exit.guard)));

   dirty = unsafeIRDirty_0_N(0, "RegChkRepExitHelper", 
         &RegChkRepExitHelper, 
         mkIRExprVec_1(
            IRExpr_RdTmp(wideGuardTmp)
            ));
   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

static INLINE int
BT_IsInsnPutEip(IRStmt *st)
{
   uint oGuestEIP = offsetof(VexGuestX86State, guest_EIP);

   /* First insn in IRSB doesn't set the EIP -- should
    * already be set by dispatch. */
   return (st->tag == Ist_Put && st->Ist.Put.offset == oGuestEIP);
}

IRSB*
RegChk_Instrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   int i, imarkCount = 0, doneWithFirstImark = 0;
   IRSB *bbOut;
   ulong currInsAddr = 0, currInsLen = 0;
   int isAlreadyInstrumented = 0;

   ASSERT(bbIn->stmts_used > 0);

   bbOut = emptyIRSB();
   bbOut->tyenv = deepCopyIRTypeEnv(bbIn->tyenv);
   bbOut->jumpkind = bbIn->jumpkind;
   bbOut->next = deepCopyIRExpr(bbIn->next);

   for (i = 0; i < bbIn->stmts_used; i++) {
      IRStmt *st = bbIn->stmts[i];
      if (st->tag == Ist_IMark) {
         imarkCount++;
         isAlreadyInstrumented = 0;
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
      ASSERT(currInsLen);


      if (BinTrns_IsRepPrefix(currInsAddr) && st->tag == Ist_Exit &&
               st->Ist.Exit.dst->Ico.U32 != currInsAddr) {
            RegChkRepExit(bbOut, currInsAddr, st);
            addStmtToIRSB(bbOut, st);
      } else {
         addStmtToIRSB(bbOut, st);

         if ((imarkCount == 1  && !doneWithFirstImark) || BT_IsInsnPutEip(st)) {
            if (imarkCount == 1) {
               doneWithFirstImark = 1;
            }

            /* Sometimes, a PUT(EIP) can happen even on the first block --
             * because the RDTSC helper has placed it there. */
            if (!isAlreadyInstrumented) {
               if (BinTrns_IsRepPrefix(currInsAddr)) {
                  RegChkRepPrefix(bbOut);
               } else {
                  RegChkNonRepPrefix(bbOut);
               }

               isAlreadyInstrumented = 1;
            }
         }
      }
   }

   if (BinTrns_IsRepPrefix(currInsAddr)) {
      addStmtToIRSB(bbOut, IRStmt_Dirty(
               unsafeIRDirty_0_N(0, "RegChkRepFallExitHelper", 
                  &RegChkRepFallExitHelper, 
                  mkIRExprVec_2(
                     mkIRExpr_HWord(currInsAddr),
                     bbOut->next
                     ))
               ));
   }

   return bbOut;
}

static struct Module mod = {
   .name       = "Register Check",
   .modeFlags  = 0xFFFFFFFF,
   .onStartFn  = NULL,
   .onTermFn   = NULL,
   .onForkFn   = NULL,
   .onExitFn   = NULL,
   .instrFn    = &RegChk_Instrument,
   /* XXX: RegChk must be done after entry interception since Entry_*
    * wipes out all IR stmts of an RDTSC instruction and replaces it
    * with an exit. If we had a regchk callout there, that would get
    * wiped out too. */
   .order      = 6,
};

int
RegChk_Init()
{
   if (1) {
      DEBUG_MSG(5, "Initializing regchk.\n");
      ASSERT(!(VCPU_GetMode() & VCPU_MODE_SINGLESTEP));
      Module_Register(&mod);

      return 1;
   }

   return 0;
}
