/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/task/private.h"

#include "libvex.h"
#include "libvex_guest_x86.h"

#include "libcommon/sharedarea.h"
#include "libcommon/context.h"

#include <errno.h>

static void
PinLoadHelper(TaskArchState *archSt, ulong addr, ulong pc, int typeSize)
{
   /* Tell Pin about the load. */
   syscall(SYS_emu_mem, 0, addr, pc, archSt->vex.guest_ECX, typeSize);
}

#if 0
typedef
   struct {
      /* What to call, and details of args/results */
      IRCallee* cee;    /* where to call */
      IRExpr*   guard;  /* :: Ity_Bit.  Controls whether call happens */
      IRExpr**  args;   /* arg list, ends in NULL */
      IRTemp    tmp;    /* to assign result to, or IRTemp_INVALID if none */

      /* Mem effects; we allow only one R/W/M region to be stated */
      IREffect  mFx;    /* indicates memory effects, if any */
      IRExpr*   mAddr;  /* of access, or NULL if mFx==Ifx_None */
      Int       mSize;  /* of access, or zero if mFx==Ifx_None */

      /* Guest state effects; up to N allowed */
      Bool needsBBP; /* True => also pass guest state ptr to callee */
      Int  nFxState; /* must be 0 .. VEX_N_FXSTATE */
      struct {
         IREffect fx;   /* read, write or modify?  Ifx_None is invalid. */
         Int      offset;
         Int      size;
      } fxState[VEX_N_FXSTATE];
   }
   IRDirty;
#endif

static void
PinIRWrTmpLoad(IRSB *bbOut, Addr64 pc, IRExpr *e)
{
   IRExpr *typeSizeArg, *pcArg;
   IRDirty *dirty;

   typeSizeArg = mkIRExpr_HWord(sizeofIRType(e->Iex.Load.ty));
   pcArg = mkIRExpr_HWord(pc);

   dirty = unsafeIRDirty_0_N(0, "PinLoadHelper", &PinLoadHelper,
         mkIRExprVec_3(e->Iex.Load.addr, pcArg, typeSizeArg));
   dirty->needsBBP = True;
   dirty->nFxState = 1;
   dirty->fxState[0].fx = Ifx_Read;
   dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_ECX);
   dirty->fxState[0].size = 4;

   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

#if 0
   extern 
      IRDirty* unsafeIRDirty_0_N ( Int regparms, HChar* name, void* addr, 
            IRExpr** args );

   extern IRExpr** mkIRExprVec_3 ( IRExpr*, IRExpr*, IRExpr* );
#endif

static void
PinIRWrTmp(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRExpr * rhs; 

   rhs = st->Ist.WrTmp.data; 

   switch (rhs->tag)
   {
   case (Iex_Load):
      PinIRWrTmpLoad(bbOut, pc, rhs); 
      break; 
   default:
      break;
   }

   return; 
}

static void
PinStoreHelper(TaskArchState *archSt, ulong addr, ulong pc, int typeSize)
{
   syscall(SYS_emu_mem, 1, addr, pc, archSt->vex.guest_ECX, typeSize);
}

static void
PinIRStore(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRExpr *typeSizeArg, *pcArg;
   IRDirty *dirty;
   int typeSize;
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
      ASSERT_UNIMPLEMENTED(0);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   ASSERT(typeSize);
   typeSizeArg = mkIRExpr_HWord(typeSize);
   pcArg = mkIRExpr_HWord(pc);

   dirty = unsafeIRDirty_0_N(0, "PinStoreHelper", &PinStoreHelper,
         mkIRExprVec_3(addr, pcArg, typeSizeArg));
   dirty->needsBBP = True;
   dirty->nFxState = 1;
   dirty->fxState[0].fx = Ifx_Read;
   dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_ECX);
   dirty->fxState[0].size = 4;
   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
}

static void
PinBranchHelperNotTaken(ulong insAddr)
{
   syscall(SYS_emu_branch, insAddr, 1);
   current->brCnt++;
   DEBUG_MSG(5, "brCnt=%d pc=0x%x\n", current->brCnt, insAddr);
}

static void
PinBranchHelperTaken(ulong insAddr)
{
   syscall(SYS_emu_branch, insAddr, 0);
   current->brCnt++;
   DEBUG_MSG(5, "brCnt=%d pc=0x%x\n", current->brCnt, insAddr);
}

static void
PinIRExit(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   IRDirty *dirty;
   int isBranchIns;

   switch (st->Ist.Exit.jk) {
   case Ijk_Boring:
      isBranchIns = 1;
      break;
   case Ijk_MapFail:
      isBranchIns = 0;
      break;
   case Ijk_SigTRAP:
      isBranchIns = 0;
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   /* PIN doesn't consider instructions with the REP prefix
    * to be conditional branches, so we shouldn't either. */
   isBranchIns = isBranchIns && !BT_IsRepPrefix(pc);

   if (isBranchIns) {
      /* Not-taken path. */
      dirty = unsafeIRDirty_0_N(0, "PinBranchHelperTaken", 
            &PinBranchHelperTaken,
            mkIRExprVec_1(
               mkIRExpr_HWord(pc)
               )
            );
      dirty->guard = deepCopyIRExpr(st->Ist.Exit.guard);
      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   }


   addStmtToIRSB(bbOut, st);

   if (isBranchIns) {
      dirty = unsafeIRDirty_0_N(0, "PinBranchHelperNotTaken", 
            &PinBranchHelperNotTaken,
            mkIRExprVec_1(
               mkIRExpr_HWord(pc)
               )
            );
      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   }
}

static void
PinIndirectJumpHelper(ulong insAddr, int isIndirect, int jumpKind, 
      ulong nextInsAddr, ulong targetAddr)
{
   syscall(SYS_emu_ijump, insAddr, isIndirect, jumpKind, nextInsAddr, 
         targetAddr);
}

static void
PinIRStmt(IRSB *bbOut, Addr64 pc, IRStmt *st)
{
   switch (st->tag)
   {
   case Ist_WrTmp:
      addStmtToIRSB(bbOut, st);
      PinIRWrTmp(bbOut, pc, st); 
      break;
   case Ist_Store:
      addStmtToIRSB(bbOut, st);
      PinIRStore(bbOut, pc, st); 
      break;
   case Ist_Exit:
      /* Must insert helpers before the jump takes
       * place. */
      PinIRExit(bbOut, pc, st);
      break;
   default:
      addStmtToIRSB(bbOut, st);
      break;
   }
}

IRSB*
Pin_Instrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   int i;
   IRSB *bbOut;
   ulong currInsAddr, currInsLen;
   IRDirty *dirty;
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

      /* Add helper calls if necessary (e.g., callouts to inform
       * Pin of a load/store or branch emulation). */
      ASSERT(currInsAddr);
      PinIRStmt(bbOut, currInsAddr, st);
   }

   switch (bbOut->next->tag) {
   case Iex_RdTmp:
      isIndirect = 1;
      break;
   case Iex_Const:
      isIndirect = 0;
      ASSERT(bbOut->jumpkind != Ijk_Ret);
      break;
   default:
      ASSERT(0);
      break;
   }

   /* Pin needs to know about direct calls (in addition
    * to all indirect jumps) to maintain its RSB. */
   if (isIndirect || bbOut->jumpkind == Ijk_Call) {

      dirty = unsafeIRDirty_0_N(0, "PinIndirectJumpHelper", 
            &PinIndirectJumpHelper,
            mkIRExprVec_5(
               mkIRExpr_HWord(currInsAddr),
               mkIRExpr_HWord(isIndirect), 
               mkIRExpr_HWord(bbOut->jumpkind),
               /* retaddr (relevant for calls) */
               mkIRExpr_HWord(currInsAddr+currInsLen), 
               bbOut->next /* jump target */
               )
            );
      addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));
   }

   return bbOut;
}

void
Pin_Fork(struct Task *tsk)
{
   tsk->brCnt = 0;
}
