#include "vkernel/public.h"
#include "private.h"

/*
 *
 * --- Precise exception for VEX (ABANDONED) ---
 *
 * XXX: This code is seriously broken. The main problem is that simply
 * restoring regs to the start to their state at the start of the insn
 * on fault is no gaurantted to result in a consistent register state,
 * due to VEX optimization, which caches register state in temporaries.
 * Not sure how this can work without VEX support.
 *
 * At any rate, I'll have to abandon this code, because we don't need it
 * when running in direct execution, and that's what matters.
 */

static void
PreExRestoreRegs(TaskRegs *trP, char *regBufP, int numArgs)
{
   int i;
   char *regP = (char*) trP;
   char *p = regBufP;

   for (i = 0; i < numArgs; i++) {
      UInt *offP, *tyP;
      char *valP;

      offP = (UInt*)p;
      p += sizeof(UInt);
      tyP = (UInt*)p;
      p += sizeof(UInt);
      valP = p;
      p += sizeofIRTypeAsArg(*tyP);

      ASSERT(*offP >= 0 && *offP <= offsetof(TaskRegs, padding1));
      memcpy(regP+*offP, valP, sizeofIRType(*tyP));
   }

#if DEBUG
   const siginfo_t *siP = current->frameP->pinfo;
   ASSERT(siP->si_signo == SIGSEGV);
   ASSERT(siP->si_code == SEGV_ACCERR ||
          siP->si_code == SEGV_MAPERR);
#endif

   /* Causes an exit with special error code indicating a fault
    * occurred. */
   trP->guest_IS_FAULT_PENDING = 1;
}

/*
 * Summary:
 *    Stores/Loads the given value to the specified memory location; but if
 *    the store generates a fault, it undoes any changes to register
 *    state made before the store, but within the same instruction, and
 *    then exists with a sigsegv.
 *
 *    @argBuf is a placeholder for a variable length buffer of arguments.
 *    These arguest form a list of [writeVal, off1, len1, val1, off2, len2,
 *    val2, ...], where writeVal is the value being written by the the
 *    store, and off_i, len_i, and val_i are the offset, length, and value
 *    of a register state that was overwritten before the store. 
 */
static u64
PreEx_DirtyHelper_Load(TaskRegs *trP, void * usrP, UInt dataTy, UInt numArgs, ...)
{
   ASSERT_KPTR(trP);

   char *p = (char*)&numArgs + sizeof(numArgs);
   u64 val = 0LLU;

   ASSERT(val == 0);
   ASSERT(sizeofIRType(dataTy) <= 8);

   /* copy_from_user and not Task_CopyFromUser, since we're not in
    * vkernel-proper at this point, we're in the translator. */
   DEBUG_MSG(7, "usrP=0x%x dataSz=%d\n", usrP, sizeofIRType(dataTy));
   ASSERT_UPTR(usrP);
   ASSERT(trP->guest_IS_FAULT_PENDING == 0);
   if (copy_from_user(&val, usrP, sizeofIRType(dataTy))) {
      PreExRestoreRegs(trP, p, numArgs);

      /* The returned value may be arbitrary ,since we will exit BB
       * before it is actually used. */
      return 0;
   } else {
      return val;
   }
}


static void
PreEx_DirtyHelper_Store(TaskRegs *trP, void * usrP, UInt dataTy, UInt numArgs, ...)
{
   ASSERT_KPTR(trP);

   char *p = (char*)&numArgs + sizeof(numArgs);

   char *wrValP = p;
   p += sizeofIRTypeAsArg(dataTy);

   /* copy_to_user and not Task_CopyToUser, since we're not in
    * vkernel-proper at this point, we're in the translator. */
   DEBUG_MSG(7, "usrP=0x%x dataSz=%d val=0x%x\n", usrP, sizeofIRType(dataTy), 
         *(ulong*)wrValP);
   ASSERT_UPTR(usrP);
   ASSERT(trP->guest_IS_FAULT_PENDING == 0);
   if (copy_to_user(usrP, wrValP, sizeofIRType(dataTy))) {
      PreExRestoreRegs(trP, p, numArgs);
   } 
}


static void
PreExInstrLdSt(IRSB *bbP, IRStmt *stP, const HWord currInsAddr, 
                   IRStmt **putA, const IRTemp *savedA, const int numPuts)
{
   IRTemp faultTmp, guardTmp;
   IRDirty *dP;
   int isLoad;

   if (stP->tag == Ist_WrTmp && 
         stP->Ist.WrTmp.data->tag == Iex_Load) {
      isLoad = 1;
   } else {
      ASSERT(stP->tag == Ist_Store);
      isLoad = 0;
   }

   size_t vecLen = 3 + (!isLoad ? 1 : 0) + 3*numPuts + 1;
   IRExpr **vecA = LibVEX_Alloc(vecLen * sizeof(IRExpr*));
   int i = 0;

   ASSERT(numPuts > 0);

   if (isLoad) {
      IRExpr *dataP = stP->Ist.WrTmp.data;
      vecA[i++] = dataP->Iex.Load.addr;
      IRType dataTy = dataP->Iex.Load.ty;
      vecA[i++] = mkIRExpr_UInt(dataTy);
   } else {
      vecA[i++] = stP->Ist.Store.addr;
      IRType dataTy = typeOfIRExpr(bbP->tyenv, stP->Ist.Store.data);
      vecA[i++] = mkIRExpr_UInt(dataTy);
   }

   vecA[i++] = mkIRExpr_UInt(numPuts);
   if (!isLoad) {
      vecA[i++] = stP->Ist.Store.data;
   }

   int j;
   for (j = 0; j < numPuts; j++) {
      int k = i + 3*j;
      IRType dataTy;
      IRStmt *sP = putA[j];

      switch (sP->tag) {
      case Ist_Put:
         vecA[k] = mkIRExpr_UInt(sP->Ist.Put.offset);
         dataTy = typeOfIRExpr(bbP->tyenv, sP->Ist.Put.data);
         ASSERT(dataTy != Ity_I1);
         break;
      case Ist_PutI:
         {
            IRTemp offTmp = newIRTemp(bbP->tyenv, Ity_I32);
            UInt base = sP->Ist.PutI.bias + sP->Ist.PutI.descr->base;
            addStmtToIRSB(bbP, 
                  IRStmt_WrTmp(offTmp,
                     IRExpr_Binop(Iop_Add32, 
                        mkIRExpr_UInt(base), sP->Ist.PutI.ix)));
            vecA[k] = IRExpr_RdTmp(offTmp);
            dataTy = typeOfIRExpr(bbP->tyenv, sP->Ist.PutI.data);
         }
         break;
      default:
         ASSERT_UNIMPLEMENTED(0);
         break;
      }
      vecA[k+1] = mkIRExpr_UInt(dataTy);
      vecA[k+2] = IRExpr_RdTmp(savedA[j]);
   }
   vecA[vecLen-1] = NULL;

   IRTemp dirtyTmp = newIRTemp(bbP->tyenv, Ity_I64);
   if (isLoad) {
      dP = BT_UnsafeIRDirty_1_N(bbP, dirtyTmp,
            "PreEx_DirtyHelper_Load",
            PreEx_DirtyHelper_Load,
            vecA);

   } else {
      dP = BT_UnsafeIRDirty_0_N(bbP,
            "PreEx_DirtyHelper_Store",
            PreEx_DirtyHelper_Store,
            vecA);
   }
   /* We may need to undo changes to arbitrary get state. XXX: declare
    * only those portions of guest state that we know will be touched. */
   dP->needsBBP = True;
   dP->nFxState = 1;
   dP->fxState[0].fx = Ifx_Modify;
   dP->fxState[0].offset = 0;
   dP->fxState[0].size = offsetof(TaskRegs, padding1);
   addStmtToIRSB(bbP, IRStmt_Dirty(dP));

   if (isLoad) {
      IRTemp loadTmp = stP->Ist.WrTmp.tmp;
      switch (typeOfIRExpr(bbP->tyenv, stP->Ist.WrTmp.data)) {
      case Ity_I64:
         addStmtToIRSB(bbP, 
               IRStmt_WrTmp(loadTmp, IRExpr_RdTmp(dirtyTmp)));
         break;
      case Ity_I32:
         addStmtToIRSB(bbP, 
               IRStmt_WrTmp(loadTmp, 
                  IRExpr_Unop(Iop_64to32, IRExpr_RdTmp(dirtyTmp))));
         break;
      case Ity_I16:
         addStmtToIRSB(bbP, 
               IRStmt_WrTmp(loadTmp, 
                  IRExpr_Unop(Iop_64to16, IRExpr_RdTmp(dirtyTmp))));
         break;
      case Ity_I8:
         {
            IRTemp tmp1 = newIRTemp(bbP->tyenv, Ity_I32);
            addStmtToIRSB(bbP, 
                  IRStmt_WrTmp(tmp1, 
                     IRExpr_Unop(Iop_64to32, IRExpr_RdTmp(dirtyTmp))));
            addStmtToIRSB(bbP, 
                  IRStmt_WrTmp(loadTmp, 
                     IRExpr_Unop(Iop_32to8, IRExpr_RdTmp(tmp1))));
         }
         break;
      case Ity_F64:
         addStmtToIRSB(bbP, 
               IRStmt_WrTmp(loadTmp, 
                  IRExpr_Unop(Iop_ReinterpI64asF64, IRExpr_RdTmp(dirtyTmp))));
         break;
      case Ity_F32:
         {
            IRTemp tmp1 = newIRTemp(bbP->tyenv, Ity_I32);
            addStmtToIRSB(bbP, 
                  IRStmt_WrTmp(tmp1, 
                     IRExpr_Unop(Iop_64to32, IRExpr_RdTmp(dirtyTmp))));
            addStmtToIRSB(bbP, 
                  IRStmt_WrTmp(loadTmp, 
                     IRExpr_Unop(Iop_ReinterpI32asF32, IRExpr_RdTmp(tmp1))));
         }
         break;
      default:
         ASSERT_UNIMPLEMENTED(0);
         break;
      };
   }

   faultTmp = newIRTemp(bbP->tyenv, Ity_I32);
   addStmtToIRSB(bbP,
         IRStmt_WrTmp(faultTmp,
            IRExpr_Get(offsetof(VexGuestX86State, guest_IS_FAULT_PENDING), 
               Ity_I32)));
   guardTmp = newIRTemp(bbP->tyenv, Ity_I1);
   addStmtToIRSB(bbP, 
         IRStmt_WrTmp(guardTmp, 
            IRExpr_Unop(Iop_32to1, IRExpr_RdTmp(faultTmp))));
   addStmtToIRSB(bbP, 
         IRStmt_Exit(IRExpr_RdTmp(guardTmp), Ijk_PrecExpsn,
            IRConst_U32(currInsAddr)));
}

static IRSB*
PreExDoInstrWork(IRSB *bbIn, const int *lastFaultableStmtA)
{
   int i;
   IRSB *bbOut;
   ulong currInsAddr = 0, currInsLen = 0;
   int lastFaultableStmt = -1;

#define MAX_NR_PUTS 10
   IRStmt *putA[MAX_NR_PUTS];
   IRTemp savedA[MAX_NR_PUTS];
   int numPuts = 0, fixedUp = 0;

   bbOut = emptyIRSB();
   bbOut->tyenv = deepCopyIRTypeEnv(bbIn->tyenv);
   bbOut->jumpkind = bbIn->jumpkind;
   bbOut->next = deepCopyIRExpr(bbIn->next);

   for (i = 0; i < bbIn->stmts_used; i++) {
      IRStmt *st = bbIn->stmts[i];
      if (st->tag == Ist_IMark) {
         currInsAddr = st->Ist.IMark.addr;
         currInsLen = st->Ist.IMark.len;
         numPuts = 0;
         lastFaultableStmt = lastFaultableStmtA[i];
         ASSERT(lastFaultableStmt >= -1);
      }

      if (currInsAddr && i < lastFaultableStmt) {
         /* We're not in the preamble and this insn has a faultable
          * stmt. So save the targets of all state modifcations (guest
          * registers and memory) before that last faultable insn. */
         if (st->tag == Ist_Put) {
            if (st->Ist.Put.offset == offsetof(VexGuestX86State, guest_EIP)) {
               ASSERT(st->Ist.Put.data->tag == Iex_Const);
            } else {
               ASSERT(numPuts < MAX_NR_PUTS);
               IRType putTy = typeOfIRExpr(bbOut->tyenv, st->Ist.Put.data);
               putA[numPuts] = st;
               savedA[numPuts] = newIRTemp(bbOut->tyenv, putTy);
               addStmtToIRSB(bbOut, 
                     IRStmt_WrTmp(savedA[numPuts],
                        IRExpr_Get(st->Ist.Put.offset, putTy)));
               numPuts++;
            }
         } else if (st->tag == Ist_PutI) {
            ASSERT(numPuts < MAX_NR_PUTS);
            IRType putTy = typeOfIRExpr(bbOut->tyenv, st->Ist.PutI.data);
            putA[numPuts] = st;
            savedA[numPuts] = newIRTemp(bbOut->tyenv, putTy);
            addStmtToIRSB(bbOut, 
                  IRStmt_WrTmp(savedA[numPuts],
                     IRExpr_GetI(st->Ist.PutI.descr, st->Ist.PutI.ix,
                        st->Ist.PutI.bias)));
            numPuts++;
         } else if (st->tag == Ist_Dirty && 
               st->Ist.Dirty.details->mFx != Ifx_None) {
            ppIRSB(bbIn);
            ASSERT_UNIMPLEMENTED(0);
         } else if (st->tag == Ist_Store) {
            ppIRSB(bbIn);
            /* XXX: PUSHA insn (java) triggers this */
            ASSERT_UNIMPLEMENTED(0);
         }
      } 

      fixedUp = 0;

      if (numPuts) {
         switch (st->tag) {
         case Ist_Store:
            PreExInstrLdSt(bbOut, st, currInsAddr, putA, savedA, 
                  numPuts);
            fixedUp = 1;
            break;
         case Ist_WrTmp:
            if (st->Ist.WrTmp.data->tag == Iex_Load) {
               PreExInstrLdSt(bbOut, st, currInsAddr, putA, savedA,
                     numPuts);
               fixedUp = 1;
            }
            break;
         case Ist_Dirty:
            if (st->Ist.Dirty.details->mFx != Ifx_None) {
               ASSERT_UNIMPLEMENTED(0);
               fixedUp = 1;
            }
            break;
         default:
            break;
         }
      }

      if (!fixedUp) {
         addStmtToIRSB(bbOut, st);
      }
   }

   return bbOut;
}


IRSB*
PreEx_Instr(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   ASSERT(bbIn->stmts_used > 0);

   int i, lastFaultableStmt = -1;

   /* --- Does the block need instrumenting? --- 
    *
    * It does if it (1) modifies guest state (i.e., does PUTs), (2) has at
    * least one load or store, and (3) the guest modification happens
    * before the load or store. */

   /* XXX: ideally, VEX should give us this info so that we needn't scan
    * through the IRSB once more. Currently, we need two passes: one to
    * determine if this block is a candidate and another to do the
    * actual instrumenting. */
   int lastFaultableStmtA[bbIn->stmts_used];
   
   memset(lastFaultableStmtA, 0, sizeof(lastFaultableStmtA));

   /* Going backwards... */
   for (i = bbIn->stmts_used-1; i >= 0; i--) {
      IRStmt *st = bbIn->stmts[i];
      if (st->tag == Ist_IMark) {
         //if (hasPutsBeforeLastFaultableStmt) {
            lastFaultableStmtA[i] = lastFaultableStmt;
         //}

         lastFaultableStmt = -1;
         //hasPutsBeforeLastFaultableStmt = 0;
      }

      if (lastFaultableStmt == -1 && (st->tag == Ist_Store ||
          (st->tag == Ist_WrTmp && st->Ist.WrTmp.data->tag == Iex_Load))) {
         lastFaultableStmt = i;
      }

#if 0
      if (lastFaultableStmt > -1 && st->tag == Ist_Put) {
         if (st->Ist.Put.offset == offsetof(VexGuestX86State, guest_EIP)) {
            /* IP update doesn't count. It's done for every insns. */
            ASSERT(st->Ist.Put.data->tag == Iex_Const);
         } else {
            hasPutsBeforeLastFaultableStmt = 1;

            break;
         }
      }
#endif
   }

   return PreExDoInstrWork(bbIn, lastFaultableStmtA);
}
