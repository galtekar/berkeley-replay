/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <errno.h>

#include "vkernel/public.h"
#include "private.h"

/*
 * Summary:
 *
 * LibVEX's does do CPUID emulation, but it is unsuitable for our
 * needs. Namely, it produces some generic results that may not
 * match the results of an actual CPUID call on the host machine.
 * But that's exactly what we need in order to replay in BT an
 * execution that was collected in DE mode.
 *
 * In this module, we replace LibVEX's CPUID emulation with our
 * own. Our emulation gets CPUID info from the @cpuidMatrix, which
 * we load with the host's actual CPUID results. During replay, we
 * ensure the same results are loaded into the @cpuidMatrix,
 * hence providing CPUID determinism.
 */

static void
Core_x86g_DirtyHelper_CPUID(VexGuestX86State *st)
{
   uint op = st->guest_EAX;
#define C(idx) (&(((uint*)curr_vcpu->cpuidMatrix)[(idx)*4]))
  
   uint *p;

   DEBUG_MSG(5, "op=0x%x\n", op);
   switch (op) {
   case 0x0:
   case 0x1:
   case 0x2:
   case 0x3:
   case 0x4:
   case 0x5:
   case 0x6:
      p = C(op);
      break;
   case 0xa:
      p = C(7);
      break;
   case 0x80000000:
   case 0x80000001:
   case 0x80000002:
   case 0x80000003:
   case 0x80000004:
   case 0x80000005:
   case 0x80000006:
   case 0x80000007:
   case 0x80000008:
      p = C(8+(0xF & op));
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      p = NULL;
      break;
   }

   Task_WriteReg(st, eax, p[0]);
   Task_WriteReg(st, ebx, p[1]);
   Task_WriteReg(st, ecx, p[2]);
   Task_WriteReg(st, edx, p[3]);
}

static void
CpuIdIRDirty(IRSB *bbOut, IRStmt *st)
{

   const char *dirtyName = st->Ist.Dirty.details->cee->name;

   if (strstr(dirtyName, "x86g_dirtyhelper_CPUID")) {

      IRDirty *dirty;

      dirty = unsafeIRDirty_0_N(0, 
            "Core_x86g_DirtyHelper_CPUID",
            &Core_x86g_DirtyHelper_CPUID,
            mkIRExprVec_0());
      dirty->needsBBP = True;
      dirty->nFxState = 4;

      dirty->fxState[0].fx = Ifx_Modify;
      dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_EAX);
      dirty->fxState[0].size = 4;
      dirty->fxState[1].fx = Ifx_Write;
      dirty->fxState[1].offset = offsetof(VexGuestX86State, guest_EBX);
      dirty->fxState[1].size = 4;
      dirty->fxState[2].fx = Ifx_Write;
      dirty->fxState[2].offset = offsetof(VexGuestX86State, guest_ECX);
      dirty->fxState[2].size = 4;
      dirty->fxState[3].fx = Ifx_Write;
      dirty->fxState[3].offset = offsetof(VexGuestX86State, guest_EDX);
      dirty->fxState[3].size = 4;

      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   } else {
      addStmtToIRSB(bbOut, st);
   }
}

static void
CpuIdIRStmt(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   switch (st->tag)
   {
   case Ist_Dirty:
      CpuIdIRDirty(bbOut, st); 
      break;
   default:
      addStmtToIRSB(bbOut, st);
      break;
   }
}

static IRSB*
CpuIdInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
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
       * CpuId of a load/store or branch emulation). */
      ASSERT(currInsAddr);
      CpuIdIRStmt(bbOut, currInsAddr, st);
   }

   return bbOut;
}

struct Module mod = {
   .name       = "CPUID Emulation",
   .modeFlags  = 0xFFFFFFFF,
   .onStartFn  = NULL,
   .onTermFn   = NULL,
   .onForkFn   = NULL,
   .onExitFn   = NULL,
   .instrFn    = &CpuIdInstrument,
   .order      = MODULE_ORDER_FIRST,
};

static int
CpuId_Init()
{
   if (1) {
      Module_Register(&mod);
   }

   return 0;
}

BT_INITCALL(CpuId_Init);
