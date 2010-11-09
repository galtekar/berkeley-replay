#include "vkernel/public.h"
#include "private.h"

static void
cgEmitDirtyLoadF80(const IRTemp lhsTmp, const IRType lhsTy, 
      const IRTemp addrTmp, const HWord addr, const UInt len, 
      const struct PackedArgs argBuf)
{
#if PRODUCT
#error "XXX"
#endif
   WARN_XXX_MSG(0, "x86g_dirtyhelper_loadF80le unhandled");
}

void
cg_InstrDirtyLoadF80(IRSB *bb, const IRStmt *s)
{
   const IRDirty *dirtyP = s->Ist.Dirty.details;
   const IRExpr *mAddr = dirtyP->mAddr;
   IRDirty *emitDirtyP;

   ASSERT(mAddr->tag == Iex_RdTmp);
   ASSERT(dirtyP->tmp != IRTemp_INVALID);

   emitDirtyP = unsafeIRDirty_0_N(0,
         "cgEmitDirtyLoadF80",
         &cgEmitDirtyLoadF80,
         mkIRExprVec_7(
            mkIRExpr_UInt(dirtyP->tmp),
            mkIRExpr_UInt(typeOfIRTemp(bb->tyenv, dirtyP->tmp)),
            mkIRExpr_UInt(mAddr->Iex.RdTmp.tmp),
            dirtyP->mAddr,
            mkIRExpr_UInt(dirtyP->mSize),
            BT_ArgFixup(bb, IRExpr_RdTmp(dirtyP->tmp)),
            mkIRExpr_UInt(DEBUG_MAGIC)
            )
         );

   addStmtToIRSB(bb, IRStmt_Dirty(emitDirtyP));

   /* XXX: is it safe to call the helper during symbolic execution?
    * it's parameters may be wack and so it may crash. */
}

static void
cgEmitDirtyStoreF80(IRTemp addrTmp, HWord addr, UInt len, IRTemp dataTmp)
{
#if PRODUCT
#error "XXX"
#endif
   /* XXX: this is not really a store or a unop, but a
    * combination of both. We need to simplify this dirty
    * function into manageable IROps: one complication is
    * that there is no F80 IR type, so we'll need to
    * simplify the store into multiple stores. */
   WARN_XXX_MSG(0, "x86g_dirtyhelper_storeF80le unhandled");
}

void
cg_InstrDirtyStoreF80(IRSB *bb, const IRStmt *s)
{
   const IRDirty *dirtyP = s->Ist.Dirty.details;
   const IRExpr *mAddr = dirtyP->mAddr;
   IRExpr **cArgA = dirtyP->args;
   IRDirty *emitDirtyP;

   ASSERT(mAddr->tag == Iex_RdTmp);
   ASSERT(cArgA[1]->tag == Iex_RdTmp);

   emitDirtyP = unsafeIRDirty_0_N(0,
         "cgEmitDirtyStoreF80",
         &cgEmitDirtyStoreF80,
         mkIRExprVec_4(
            mkIRExpr_UInt(mAddr->Iex.RdTmp.tmp),
            dirtyP->mAddr,
            mkIRExpr_UInt(dirtyP->mSize),
            mkIRExpr_UInt(cArgA[1]->Iex.RdTmp.tmp)
            )
         );

   addStmtToIRSB(bb, IRStmt_Dirty(emitDirtyP));

   /* Don't add the helper call itself, as it may crash when run during
    * symbolic execution. */
}


/* XXX: delete; no longer needed because we use the Task_WriteReg
 * macro in the CPUID module to write the results; dcgen will intercept
 * these and mark the corredponing memory as concrete. */
#if 0
static void
cgEmitDirtyCPUID(Int eaxOff, Int ebxOff, Int ecxOff, Int edxOff)
{
#if 0
   const size_t len = 4;

   /* The vkernel's CPUID emulation produces deterministic results -- it's 
    * all based on a precomputed table. So the target registers will
    * become concrete. Hence we untaint the target regs. */
   cg_UntaintReg(current, eaxOff, len);
   cg_UntaintReg(current, ebxOff, len);
   cg_UntaintReg(current, ecxOff, len);
   cg_UntaintReg(current, edxOff, len);
#else
   ASSERT_UNIMPLEMENTED(0);
#endif
}

static void
cgInstrDirtyCPUID(IRSB *bb, const IRStmt *s)
{
   const IRDirty *dirtyP = s->Ist.Dirty.details;
   IRDirty *emitDirtyP;

#if DEBUG
#define CHECK_FX(i, reg, st) \
   ASSERT(dirtyP->fxState[i].fx == st); \
   ASSERT(dirtyP->fxState[i].offset == offsetof(VexGuestX86State, reg)); \
   ASSERT(dirtyP->fxState[i].size == 4);

   ASSERT(dirtyP->nFxState == 4);
   CHECK_FX(0, guest_EAX, Ifx_Modify);
   CHECK_FX(1, guest_EBX, Ifx_Write);
   CHECK_FX(2, guest_ECX, Ifx_Write);
   CHECK_FX(3, guest_EDX, Ifx_Write);
#endif

   emitDirtyP = unsafeIRDirty_0_N(0,
         "cgEmitDirtyCPUID",
         &cgEmitDirtyCPUID,
         mkIRExprVec_4(
            mkIRExpr_UInt(dirtyP->fxState[0].offset),
            mkIRExpr_UInt(dirtyP->fxState[1].offset),
            mkIRExpr_UInt(dirtyP->fxState[2].offset),
            mkIRExpr_UInt(dirtyP->fxState[3].offset)
            )
         );

   addStmtToIRSB(bb, IRStmt_Dirty(emitDirtyP));
}
#endif

static void
cgInstrDirtyIgnored(IRSB *bb, const IRStmt *s)
{
   /* Nothing to do -- No need to generate constraints. */
}

#if DEBUG
static void
cgInstrDirtyRDTSC(IRSB *bb, const IRStmt *s)
{
   /* 
    * No need to generate constraints, since RDTSC's
    * behavior doesn't rely on an input value -- it just
    * returns the current CPU timestamp counter value.
    *
    * Shouldn't be called: core/entry.c will remove this dirty
    * helper  and replace it with a Ijk_Boring, hence
    * allowing the vkernel to emulate the RDTSC.
    */
   NOTREACHED();
}
#endif

#if 0
/* ----- Branch check instr ----- 
 *
 * Gotta propagate taint across these; otherwise, the exit
 * instrumentation will not detect that the exit's guard is tainted, and
 * hence will not generate a branch-outcome constraint. That's because
 * the branch check helper modifies the branch guards to ensure that
 * execution follows the originally recorded path. */

static void
cgEmitBrChkGeneric(IRTemp tmpLhs, IRType lhsTy, IRTemp tmpRhs)
{
   ASSERT(tmpLhs != IRTemp_INVALID);
   ASSERT(tmpRhs != IRTemp_INVALID);

   TCode tc;

   if ((tc = TaintMap_IsTmpTainted(tmpRhs))) {
      TaintMap_TaintTmp(tmpLhs, tc);

      cg_DeclareTmp(tmpLhs, lhsTy);
   }
}

static void
cgInstrDirtyBrChkGeneric(IRSB *bbP, const IRStmt *sP)
{
   const IRDirty *dirtyP = sP->Ist.Dirty.details;
   IRDirty *emitDirtyP;

   /* We assume the lhs tmp is the second arg. */
   ASSERT(dirtyP->tmp != IRTemp_INVALID);
   ASSERT(dirtyP->args[1]);
   ASSERT(dirtyP->args[1]->tag == Iex_RdTmp);

   IRTemp lhsTmp = dirtyP->tmp;
   IRTemp rhsTmp = dirtyP->args[1]->Iex.RdTmp.tmp;

   emitDirtyP = MACRO_unsafeIRDirty_0_N(0,
         cgEmitBrChkGeneric,
         mkIRExprVec_3(
            mkIRExpr_UInt(lhsTmp),
            mkIRExpr_UInt(typeOfIRTemp(bbP->tyenv, lhsTmp)),
            mkIRExpr_UInt(rhsTmp)
            )
         );
   addStmtToIRSB(bbP, IRStmt_Dirty(emitDirtyP));
}
#endif


/* ---------- Instrumentation selector ---------- */

/* XXX: if any of these dirty helpers change their name, then we won't
 * detect and instrument them. Can we key by function address that by
 * name? */
static const struct InstrCall handledDirtyA[] = {
   /* --- FPU stuff --- */
   { .name = "x86g_dirtyhelper_loadF80le", .fn = cg_InstrDirtyLoadF80 },
   { .name = "x86g_dirtyhelper_storeF80le", .fn = cg_InstrDirtyStoreF80 },

#if 0
   /* --- Path-enforced execution stuff --- */
   { .name = "BrChk_DirtyHelper_Ret", .fn = cgInstrDirtyBrChkGeneric },
   { .name = "BrChk_DirtyHelper_Branch", .fn = cgInstrDirtyBrChkGeneric },
   { .name = "BrChk_DirtyHelper_IndirectJump", .fn = cgInstrDirtyBrChkGeneric },
   { .name = "BrChk_DirtyHelper_IndirectCall", .fn = cgInstrDirtyBrChkGeneric },
   /* No effect on guest state -- just pushes retaddr on RSB. */
   { .name = "BrChk_DirtyHelper_DirectCall", .fn = cgInstrDirtyIgnored },
#endif

   /* --- Misc. --- */

   { .name = "Core_x86g_DirtyHelper_CPUID", .fn = cgInstrDirtyIgnored },

   /* --- No need to handle, for various reasons --- */

   /*
    * These are vkernel-installed dirty helpers that either
    * don't modify guest state (e.g., condbranch) or do
    * modify state but are handled by intercepting
    * copy_to_user calls (e.g, sysentry and rdtsc).
    * */
   { .name = "Core_x86g_DirtyHelper_CondBranch", .fn = cgInstrDirtyIgnored },
   { .name = "Core_x86g_DirtyHelper_NonCondBranch", .fn = cgInstrDirtyIgnored },
   { .name = "Core_x86g_DirtyHelper_SysEntry", .fn = cgInstrDirtyIgnored },
   { .name = "Core_x86g_DirtyHelper_RDTSC", .fn = cgInstrDirtyIgnored },


   /* -- Debug checks -- */
#if DEBUG
   { .name = "x86g_dirtyhelper_RDTSC", .fn = cgInstrDirtyRDTSC },
#endif

   { .name = "", .fn = NULL }
};

void 
cg_InstrDirty(IRSB * bb, const IRStmt * s)
{
   const IRDirty *dirtyP = s->Ist.Dirty.details;
   const IRCallee *calleeP = dirtyP->cee;

   const struct InstrCall *dP = handledDirtyA;

   while (dP->fn) {
      ASSERT(strlen(dP->name));
      if (strncmp(calleeP->name, dP->name, 
               strlen(dP->name)) == 0) {
         dP->fn(bb, s);
         return;
      }

      dP++;
   }

   ppIRStmt((IRStmt*) s);
   ASSERT_UNIMPLEMENTED_MSG(0, "Unhandled dirty: %s\n",
         calleeP->name);
}
