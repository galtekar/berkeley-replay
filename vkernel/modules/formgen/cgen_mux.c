/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"


static const int wantsComments = 1;

static void 
cgEmitTmpMux0X(
      UInt lhsTmp,
      UInt condTmp,
      UInt trueTmp,
      UInt falseTmp,
      UInt assignTy,
      UInt condVal,
      struct PackedArgs argBuf
      )
{
#define NUM_ARGS 2
   ULong argValA[NUM_ARGS] = { 0 };
   IRType tyA[NUM_ARGS] = { assignTy, assignTy };
   int numArgs;
   TCode isArgTaintedA[NUM_ARGS];

   TCode isCondTainted = 0, isTrueTainted = 0, isFalseTainted = 0;
   int shouldLhsBeTainted = 0;

   ASSERT(condTmp == -1 || condTmp >= 0);
   ASSERT(trueTmp == -1 || trueTmp >= 0);
   ASSERT(falseTmp == -1 || falseTmp >= 0);

   /* ---------- Propagate taint ---------- */

   isCondTainted = cg_IsArgTainted(condTmp);
   isTrueTainted = cg_IsArgTainted(trueTmp);
   isFalseTainted = cg_IsArgTainted(falseTmp);

   if (isCondTainted) { 
      numArgs = 2;
      isArgTaintedA[0] = isTrueTainted;
      isArgTaintedA[1] = isFalseTainted;
      shouldLhsBeTainted = isCondTainted;
   } else {
      numArgs = 1;
      if (condVal == 0) {
         isArgTaintedA[0] = isTrueTainted;
         shouldLhsBeTainted = isTrueTainted;
      } else {
         isArgTaintedA[0] = isFalseTainted;
         shouldLhsBeTainted = isFalseTainted;
      }
   }

   if (shouldLhsBeTainted) {
      if (cg_PropagateOpTaint(lhsTmp, assignTy, isArgTaintedA, 
               numArgs)) {
         return;
      }
   } else {
      TaintMap_UntaintTmp(lhsTmp);
      return;
   }

   /* ---------- Generate constraints ---------- */

   cg_UnpackArgs(argValA, tyA, &argBuf, NUM_ARGS);

   CG_NEW_LOCAL_SCOPE();

   if (isCondTainted || (!isCondTainted && condVal == 0)) {
      if (isTrueTainted) {
         CG_NEW_VAR_INIT(assignTy, CG_LSCOPE("true"), 
               CG_TMP(trueTmp));
      } else {
         CG_NEW_VAR_INIT(assignTy, CG_LSCOPE("true"), 
               CG_CONST(assignTy, argValA[0]));
      }
   }

   if (isCondTainted || (!isCondTainted && condVal != 0)) {
      if (isFalseTainted) {
         CG_NEW_VAR_INIT(assignTy, CG_LSCOPE("false"), 
               CG_TMP(falseTmp));
      } else {
         CG_NEW_VAR_INIT(assignTy, CG_LSCOPE("false"), 
               CG_CONST(assignTy, argValA[1]));
      }
   }

   CG_NEW_VAR(assignTy, CG_TMP(lhsTmp));

   if (isCondTainted) {
      /* lhs may be either the true or false expsn. */

      CG_ASSIGN(CG_TMP(lhsTmp),
            CG_ITE(
               CG_EQUAL(CG_TMP(condTmp), CG_CONST(Ity_I8, 0)),
               CG_LSCOPE("true"),
               CG_LSCOPE("false")
               ));
   } else {
      if (condVal == 0) {
         /* lhs is true expsn. */
         CG_ASSIGN(CG_TMP(lhsTmp), CG_LSCOPE("true"));
      } else {
         /* lhs is false expsn. */
         CG_ASSIGN(CG_TMP(lhsTmp), CG_LSCOPE("false"));
      }
   }
}

void 
cg_InstrTmpMux0X(IRSB * bb, const IRStmt * s)
{
   IRExpr * rhs = s->Ist.WrTmp.data;
   IRExpr * condExpr = rhs->Iex.Mux0X.cond;
   IRExpr * trueExpr = rhs->Iex.Mux0X.expr0;
   IRExpr * falseExpr = rhs->Iex.Mux0X.exprX;

   HWord lhsName = (HWord)s->Ist.WrTmp.tmp;
   HWord condName;
   HWord trueName;
   HWord falseName;

   IRType lhsTy = typeOfIRTemp(bb->tyenv, lhsName),
          condTy, trueTy, falseTy;
   IRDirty * d;

   ASSERT(s->tag == Ist_WrTmp);
   ASSERT(rhs->tag == Iex_Mux0X);

   ASSERT(condExpr->tag == Iex_RdTmp ||
         condExpr->tag == Iex_Const);
   ASSERT(trueExpr->tag == Iex_RdTmp ||
         trueExpr->tag == Iex_Const);
   ASSERT(falseExpr->tag == Iex_RdTmp || 
         falseExpr->tag == Iex_Const);

   condName = cg_GetTempOrConst(condExpr);
   condTy = typeOfIRExpr(bb->tyenv, condExpr);

   trueName = cg_GetTempOrConst(trueExpr);
   trueTy = typeOfIRExpr(bb->tyenv, trueExpr);

   falseName = cg_GetTempOrConst(falseExpr);
   falseTy = typeOfIRExpr(bb->tyenv, falseExpr);

   ASSERT(condTy == Ity_I8);
   ASSERT(lhsTy == trueTy);
   ASSERT(lhsTy == falseTy);

   ASSERT(sizeof(IRTemp) == sizeof(UInt));

   d = unsafeIRDirty_0_N(0,
         "cgEmitTmpMux0X",
         &cgEmitTmpMux0X,
         mkIRExprVec_9(
            mkIRExpr_UInt(lhsName),
            mkIRExpr_UInt(condName),
            mkIRExpr_UInt(trueName),
            mkIRExpr_UInt(falseName),
            mkIRExpr_UInt(lhsTy),
            BT_ArgFixup(bb, condExpr),
            BT_ArgFixup(bb, trueExpr),
            BT_ArgFixup(bb, falseExpr),
            mkIRExpr_UInt(DEBUG_MAGIC)
            )
         );

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}
