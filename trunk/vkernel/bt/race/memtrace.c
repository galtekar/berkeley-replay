/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

#include <errno.h>

/*
 * o We need to tell the race detector about the execution point
 * at which the access took place in addition to the access target
 * memory location. This execution points is the x86-triple 
 * <EIP, ECX, brCnt>. We could obtain EIP and ECX from VEX guest
 * state when executing the access helper function. But for
 * instructions that use the REP prefix, ECX is not accurate at
 * the time those helper functions execute. Namely, ECX may have
 * already been advanced. We get around this by keeping track
 * of the triple after every IRMark, and hence before any IR
 * stmts for an instruction execute, thereby ensuring that the triple's
 * value corresponds to the start of the instruction.
 *
 */

/* Useful for measuring overhead of mem reference trancing alone. */
STATS_ONLY(int statsTraceButDontAddToSegment = 0;)

static void
MemTraceLoadHelper(ulong vaddr, ulong pc, int typeSize)
{
   struct ExecPoint *ep = &current->bt.memTrace.ep;

#define OUTPUT_ACCESS 0
#if OUTPUT_ACCESS
   LOG("Read @ 0x%x . from 0x%x . len %d\n",
         pc, vaddr, typeSize);
#endif

   ASSERT(ep->eip == pc);

#if STATS
   if (statsTraceButDontAddToSegment) {
      return;
   }
#endif

   if (!Task_IsAddrInAppStack(vaddr)) {
      Segment_AddRead(ep, vaddr, typeSize);
   }
}

static void
MemTraceStoreHelper(ulong vaddr, ulong pc, int typeSize)
{
   struct ExecPoint *ep = &current->bt.memTrace.ep;

#if OUTPUT_ACCESS
   LOG("Write @ 0x%x . to 0x%x . len %d\n",
         pc, vaddr, typeSize);
#endif

   ASSERT(ep->eip == pc);

#if STATS
   if (statsTraceButDontAddToSegment) {
      return;
   }
#endif

   if (!Task_IsAddrInAppStack(vaddr)) {
      Segment_AddWrite(ep, vaddr, typeSize);
   }
}

static void
MemTraceInsnHelper(TaskRegs *vex, ulong pc)
{
   struct ExecPoint *ep = &current->bt.memTrace.ep;

   /* CAREFUL: Don't use vex->guest_EIP -- it may not have
    * been updated to the new instruction yet. */
   ep->eip = pc;
   ep->ecx = vex->guest_ECX;
   ep->brCnt = BrCnt_Get();
}

static void
MemTraceIRWrTmpLoad(IRSB *bbOut, Addr64 pc, IRExpr *e)
{
   IRExpr *typeSizeArg, *pcArg;
   IRDirty *dirty;

   typeSizeArg = mkIRExpr_HWord(sizeofIRType(e->Iex.Load.ty));
   pcArg = mkIRExpr_HWord(pc);

   dirty = unsafeIRDirty_0_N(0, "MemTraceLoadHelper", &MemTraceLoadHelper,
         mkIRExprVec_3(e->Iex.Load.addr, pcArg, typeSizeArg));
   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

static void
MemTraceIRWrTmp(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRExpr * rhs; 

   rhs = st->Ist.WrTmp.data; 

   switch (rhs->tag)
   {
   case (Iex_Load):
      MemTraceIRWrTmpLoad(bbOut, pc, rhs); 
      break; 
   default:
      break;
   }

   return; 
}

static void
MemTraceIRStore(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRExpr *typeSizeArg, *pcArg;
   IRDirty *dirty;
   int typeSize = -1;
   IRExpr *addr = st->Ist.Store.addr;
   IRExpr *data = st->Ist.Store.data;
   IRType tmpType;

   tmpType = typeOfIRExpr(bbOut->tyenv, data);
   typeSize = sizeofIRType(tmpType);
   ASSERT(typeSize >= 1);

   typeSizeArg = mkIRExpr_HWord(typeSize);
   pcArg = mkIRExpr_HWord(pc);

   dirty = unsafeIRDirty_0_N(0, "MemTraceStoreHelper", &MemTraceStoreHelper,
         mkIRExprVec_3(addr, pcArg, typeSizeArg));
   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

static void
MemTraceIRIMark(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRDirty *dirty;

   dirty = unsafeIRDirty_0_N(0, "MemTraceInsnHelper",
         &MemTraceInsnHelper,
         mkIRExprVec_1(mkIRExpr_HWord(pc)));
   dirty->needsBBP = True;
   dirty->nFxState = 1;
   dirty->fxState[0].fx = Ifx_Read;
   dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_ECX);
   dirty->fxState[0].size = sizeof(ulong);
   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

static void
MemTraceIRStmt(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   switch (st->tag)
   {
   case Ist_IMark:
      addStmtToIRSB(bbOut, st);
      MemTraceIRIMark(bbOut, pc, st);
      break;
   case Ist_WrTmp:
      addStmtToIRSB(bbOut, st);
      MemTraceIRWrTmp(bbOut, pc, st); 
      break;
   case Ist_Store:
      addStmtToIRSB(bbOut, st);
      MemTraceIRStore(bbOut, pc, st); 
      break;
   default:
      addStmtToIRSB(bbOut, st);
      break;
   }
}

static IRSB*
MemTraceInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   int i;
   IRSB *bbOut;
   ulong currInsAddr = 0, currInsLen;

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

      /* Add helper calls if necessary (e.g., callouts to inform
       * MemTrace of a load/store or branch emulation). */
      if (currInsAddr) {
         MemTraceIRStmt(bbOut, currInsAddr, st);
      } else {
         /* We're in a self-check preamble. */
      }
   }

   return bbOut;
}

#if 0
static void
MemTraceParseOptions()
{
#if STATS
   config_setting_t *e;


   if ((e = config_lookup(&cfgSession, 
               "race_detect.memtrace_only"))) {

      statsTraceButDontAddToSegment = config_setting_get_bool(e);
   }
#endif
}
#endif

static struct Module mod = {
   .name       = "Memory Access Trace",
   .modeFlags  = 0xFFFFFFFF,
   .onStartFn  = NULL,
   .onTermFn   = NULL,
   .onForkFn   = NULL,
   .onExitFn   = NULL,
   .instrFn    = &MemTraceInstrument,
   .order      = MODULE_ORDER_FIRST,
};

int
MemTrace_Init()
{
   if (VCPU_GetMode() & VCPU_MODE_RACEDETECT) {
      Module_Register(&mod);
   }

   return 0;
}
