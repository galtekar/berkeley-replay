/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <errno.h>

#include "vkernel/public.h"
#include "private.h"

static void
DerefChkLoadHelper(ulong vaddr, ulong pc, int typeSize)
{
   DEBUG_MSG(7, "Read @ 0x%x . from 0x%x . len %d\n",
         pc, vaddr, typeSize);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY_DATA(LoadChk, typeSize) {
         memcpy(datap, (void*) vaddr, typeSize);
      } END_WITH_LOG_ENTRY(0);

   } else if (VCPU_IsReplaying()) {
      int match;
      DO_WITH_LOG_ENTRY(LoadChk) {
         match = (memcmp(datap, (void*) vaddr, typeSize) == 0);
      } END_WITH_LOG_ENTRY(typeSize);

      if (!match) {
         DEBUG_MSG(5, "Divergence @ pc 0x%x on vaddr 0x%x\n",
               pc, vaddr);
      }
      ASSERT(match);
   }

}

static void
DerefChkStoreHelper(ulong vaddr, ulong pc, int typeSize)
{
   DEBUG_MSG(7, "Write @ 0x%x . to 0x%x . len %d\n",
         pc, vaddr, typeSize);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY_DATA(StoreChk, typeSize) {
         memcpy(datap, (void*) vaddr, typeSize);
      } END_WITH_LOG_ENTRY(0);

   } else if (VCPU_IsReplaying()) {
      int match;
      DO_WITH_LOG_ENTRY(StoreChk) {
         match = (memcmp(datap, (void*) vaddr, typeSize) == 0);
      } END_WITH_LOG_ENTRY(typeSize);

      if (!match) {
         DEBUG_MSG(5, "Divergence @ pc 0x%x on vaddr 0x%x\n",
               pc, vaddr);
      }
      ASSERT(match);
   }
}

static void
DerefChkIRWrTmpLoad(IRSB *bbOut, Addr64 pc, IRExpr *e)
{
   IRExpr *typeSizeArg, *pcArg;
   IRDirty *dirty;

   typeSizeArg = mkIRExpr_HWord(sizeofIRType(e->Iex.Load.ty));
   pcArg = mkIRExpr_HWord(pc);

   dirty = unsafeIRDirty_0_N(0, "DerefChkLoadHelper", &DerefChkLoadHelper,
         mkIRExprVec_3(e->Iex.Load.addr, pcArg, typeSizeArg));
   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

static void
DerefChkIRWrTmp(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRExpr * rhs; 

   rhs = st->Ist.WrTmp.data; 

   switch (rhs->tag)
   {
   case (Iex_Load):
      DerefChkIRWrTmpLoad(bbOut, pc, rhs); 
      break; 
   default:
      break;
   }

   return; 
}

static void
DerefChkIRStore(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRExpr *typeSizeArg, *pcArg;
   IRDirty *dirty;
   int typeSize = -1;
   IRExpr *addr = st->Ist.Store.addr;

   switch (addr->tag) {
   case Iex_RdTmp: 
      {
         IRType tmpType;
         IRTemp tmp;

         tmp = addr->Iex.RdTmp.tmp;
         tmpType = bbOut->tyenv->types[tmp];
         typeSize = sizeofIRType(tmpType);
      }
      break;
   case Iex_Const:
      typeSize = sizeofIRConst(addr->Iex.Const.con);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   ASSERT(typeSize > 0);
   typeSizeArg = mkIRExpr_HWord(typeSize);
   pcArg = mkIRExpr_HWord(pc);

   dirty = unsafeIRDirty_0_N(0, "DerefChkStoreHelper", &DerefChkStoreHelper,
         mkIRExprVec_3(addr, pcArg, typeSizeArg));
   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

static void
DerefChkIRStmt(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   switch (st->tag)
   {
   case Ist_WrTmp:
      addStmtToIRSB(bbOut, st);
      DerefChkIRWrTmp(bbOut, pc, st); 
      break;
   case Ist_Store:
      addStmtToIRSB(bbOut, st);
      DerefChkIRStore(bbOut, pc, st); 
      break;
   default:
      addStmtToIRSB(bbOut, st);
      break;
   }
}

static IRSB*
DerefChkInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
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

      /* Add helper calls if necessary (e.g., callouts to inform
       * DerefChk of a load/store or branch emulation). */
      ASSERT(currInsAddr);
      DerefChkIRStmt(bbOut, currInsAddr, st);
   }

   return bbOut;
}

static struct Module mod = {
   .name       = "Dereference Check",
   .modeFlags  = 0xFFFFFFFF,
   .onStartFn  = NULL,
   .onTermFn   = NULL,
   .onForkFn   = NULL,
   .onExitFn   = NULL,
   .instrFn    = &DerefChkInstrument,
   .order      = MODULE_ORDER_FIRST,
};

int
DerefChk_Init()
{
   if (1) {
      DEBUG_MSG(5, "Initializing derefchk.\n");
      Module_Register(&mod);

      return 1;
   }

   return 0;
}
