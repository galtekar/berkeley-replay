#include "vkernel/public.h"
#include "private.h"

#include "../private.h"

static Int
mySizeofIRType(IRType ty)
{
   switch (ty) {
   case Ity_I1:
      return 1;
   default:
      return sizeofIRType(ty);
      break;
   }
}

static void
TaintMapInstrFlowCopyExpr(IRSB *bb, IRExpr *lhs, IRExpr *rhs, IRType rhsTy)
{
   IRDirty * d; 

   d = unsafeIRDirty_0_N(0,
         "TaintMapFlowCopy",
         &TaintMapFlowCopy,
         mkIRExprVec_3( lhs, rhs,
            mkIRExpr_HWord(mySizeofIRType(rhsTy))));

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}

static void
TaintMapInstrFlowCopy(IRSB *bb, HWord lhsKey, HWord rhsKey, IRType rhsTy)
{
   TaintMapInstrFlowCopyExpr(bb, mkIRExpr_HWord(lhsKey), mkIRExpr_HWord(rhsKey),
         rhsTy);
}

static void
TaintMapInstrFlowUnaryExpr(IRSB *bb, IROp op,
                         IRExpr *lhs, IRType lhsTy, 
                         IRExpr *rhs, IRType rhsTy)
{
   IRDirty * d; 

   d = unsafeIRDirty_0_N(0,
         "TaintMapFlowUnary",
         &TaintMapFlowUnary,
         mkIRExprVec_5( 
            mkIRExpr_HWord(op),
            lhs, mkIRExpr_HWord(mySizeofIRType(lhsTy)),
            rhs, mkIRExpr_HWord(mySizeofIRType(rhsTy))));

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}

static void
TaintMapInstrFlowUnary(IRSB *bb, IROp op, HWord lhsKey, IRType lhsTy, 
                     HWord rhsKey, IRType rhsTy)
{
   TaintMapInstrFlowUnaryExpr(bb, op, mkIRExpr_HWord(lhsKey), lhsTy,
                            mkIRExpr_HWord(rhsKey), rhsTy);
}

static void
TaintMapInstrFlowBinary(IRSB *bb, IROp op,
                      HWord lhsKey, IRType lhsTy,
                      HWord rhsKey1, IRType rhs1Ty,
                      HWord rhsKey2, IRType rhs2Ty)
{
   IRDirty * d; 

   d = unsafeIRDirty_0_N(0,
         "TaintMapFlowBinary",
         &TaintMapFlowBinary,
         mkIRExprVec_7(
            mkIRExpr_HWord(op),
            mkIRExpr_HWord(lhsKey),
            mkIRExpr_HWord(mySizeofIRType(lhsTy)),
            mkIRExpr_HWord(rhsKey1),
            mkIRExpr_HWord(mySizeofIRType(rhs1Ty)),
            mkIRExpr_HWord(rhsKey2),
            mkIRExpr_HWord(mySizeofIRType(rhs2Ty))));
   addStmtToIRSB(bb,IRStmt_Dirty(d));  
}

static void
TaintMapInstrFlowTrinaryExpr(IRSB *bb,
                         IRExpr *lhsKey, IRType lhsTy, 
                         IRExpr *condVal, IRExpr *condKey, IRType condTy,
                         IRExpr *trueKey, IRType trueTy,
                         IRExpr *falseKey, IRType falseTy)
{
   IRDirty * d; 

   d = unsafeIRDirty_0_N(0,
         "TaintMapFlowTrinary",
         &TaintMapFlowTrinary,
         mkIRExprVec_9( 
            lhsKey,
            mkIRExpr_HWord(mySizeofIRType(lhsTy)),
            condVal,
            condKey,
            mkIRExpr_HWord(mySizeofIRType(condTy)),
            trueKey, 
            mkIRExpr_HWord(mySizeofIRType(trueTy)),
            falseKey, 
            mkIRExpr_HWord(mySizeofIRType(falseTy))));

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}



static void 
isIRTmpUnop(IRSB * bb, IRStmt * s)
{
   IRExpr * rhs, * arg;
   IRTemp lhsTmp;
   HWord  rhsTmp;
   IROp op;

   ASSERT(s->tag == Ist_WrTmp); 
   rhs = s->Ist.WrTmp.data;
   ASSERT(rhs->tag == Iex_Unop); 

   lhsTmp = s->Ist.WrTmp.tmp; 

   arg = rhs->Iex.Unop.arg; 
   op = rhs->Iex.Unop.op;

   switch (arg->tag)
   {
   case (Iex_Const):
      ASSERT_UNIMPLEMENTED(0);
      break; 

   case (Iex_RdTmp):
      rhsTmp = arg->Iex.RdTmp.tmp; 
      TaintMapInstrFlowUnary(bb, op,
         TaintMap_Loc2Key(lhsTmp, TmpLoc),
         typeOfIRTemp(bb->tyenv, lhsTmp),
         TaintMap_Loc2Key(rhsTmp, TmpLoc),
         typeOfIRExpr(bb->tyenv, rhs));
      break; 
   default:
      ppIRStmt(s); 
      ASSERT_UNIMPLEMENTED(0);
      break; 
   }
}

static void 
isIRTmpBinop(IRSB * bb, IRStmt * s)
{
   IRExpr *rhs, *arg1, *arg2;
   IRTemp lhsTmp;
   HWord arg1Name, arg2Name, lhsKey, arg1Key, arg2Key;
   IRType lhsTy, arg1Ty, arg2Ty;
   IROp op;


   ASSERT(s->tag == Ist_WrTmp); 
   rhs = s->Ist.WrTmp.data;
   ASSERT(rhs->tag == Iex_Binop); 

   lhsTmp = s->Ist.WrTmp.tmp; 
   lhsKey = TaintMap_Loc2Key(lhsTmp, TmpLoc); 
   lhsTy = typeOfIRTemp(bb->tyenv, lhsTmp);

   arg1 = rhs->Iex.Binop.arg1; 
   arg2 = rhs->Iex.Binop.arg2; 
   arg1Ty = typeOfIRExpr(bb->tyenv, arg1);
   arg2Ty = typeOfIRExpr(bb->tyenv, arg2);
   op = rhs->Iex.Binop.op;

   /* For example, Shl(I32, I8). */
   ASSERT(arg1Ty == arg2Ty || arg1Ty != arg2Ty);

   if (arg1->tag == Iex_RdTmp || arg2->tag == Iex_RdTmp) {
      if (arg1->tag == Iex_RdTmp && arg2->tag == Iex_RdTmp) {
         arg1Name = (HWord)arg1->Iex.RdTmp.tmp; 
         arg1Key = TaintMap_Loc2Key(arg1Name,TmpLoc); 
         arg2Name = (HWord)arg2->Iex.RdTmp.tmp; 
         arg2Key = TaintMap_Loc2Key(arg2Name,TmpLoc); 

         TaintMapInstrFlowBinary(bb, op,
               lhsKey, lhsTy,
               arg1Key, arg1Ty,
               arg2Key, arg2Ty);
      } else if (arg1->tag == Iex_RdTmp) {
         arg1Name = (HWord)arg1->Iex.RdTmp.tmp; 
         arg1Key = TaintMap_Loc2Key(arg1Name,TmpLoc); 
         TaintMapInstrFlowUnary(bb, op,
               lhsKey, lhsTy, arg1Key, arg1Ty);
      } else if (arg2->tag == Iex_RdTmp) {
         arg2Name = (HWord)arg2->Iex.RdTmp.tmp; 
         arg2Key = TaintMap_Loc2Key(arg2Name,TmpLoc); 
         TaintMapInstrFlowUnary(bb, op,
               lhsKey, lhsTy, arg2Key, arg2Ty);
      } else {
         ASSERT(0);
      }
   } else {
      /* If both operands are constant, then make the sink concrete. */
      TaintMapInstrFlowUnary(bb, op, lhsKey, lhsTy, Key_Const, lhsTy);
   }
}

static void 
isIRTmpCCallCalcCondition(IRSB * bb, IRStmt * s)
{
   IRExpr * call; 
   IRExpr** cargs; 
   IRCallee * callee;
   IRTemp lhsTmp;
   IRType depTy;

   lhsTmp = s->Ist.WrTmp.tmp;

   call = s->Ist.WrTmp.data; 
   ASSERT(call->tag == Iex_CCall); 
   callee = call->Iex.CCall.cee;
   cargs = call->Iex.CCall.args;  

   ASSERT(cargs[0]); /* cond */
   ASSERT(cargs[1]); /* cc_op */
   ASSERT(cargs[2]); /* cc_dep1 */
   ASSERT(cargs[3]); /* cc_dep2 */
   ASSERT(cargs[4]); /* cc_ndep */
   ASSERT(cargs[0]->tag != Iex_RdTmp);
   ASSERT(cargs[1]->tag == Iex_RdTmp);
   ASSERT(cargs[2]->tag == Iex_RdTmp);
   ASSERT(cargs[3]->tag == Iex_RdTmp);
   ASSERT(cargs[4]->tag == Iex_RdTmp);

   ASSERT(typeOfIRExpr(bb->tyenv, cargs[2]) == 
          typeOfIRExpr(bb->tyenv, cargs[3]));
   depTy = typeOfIRExpr(bb->tyenv, cargs[2]);

   TaintMapInstrFlowBinary(bb, 
         Iop_And32 /* for stat pruposes, treat as binop */,
         TaintMap_Loc2Key(lhsTmp, TmpLoc),
         typeOfIRTemp(bb->tyenv, lhsTmp),
         TaintMap_Loc2Key(cargs[2]->Iex.RdTmp.tmp, TmpLoc),
         depTy,
         TaintMap_Loc2Key(cargs[3]->Iex.RdTmp.tmp, TmpLoc),
         depTy);
}

static void 
isIRTmpCCallCalcEflags(IRSB * bb, IRStmt * s)
{
   IRExpr *call; 
   IRCallee *callee;
   IRExpr** cargs; 
   IRTemp lhsTmp;
   IRType depTy;

   lhsTmp = s->Ist.WrTmp.tmp;

   call = s->Ist.WrTmp.data; 
   ASSERT(call->tag == Iex_CCall); 
   callee = call->Iex.CCall.cee;
   cargs = call->Iex.CCall.args; 

   ASSERT(cargs[0]); /* cc_op */
   ASSERT(cargs[1]); /* cc_dep1 */
   ASSERT(cargs[2]); /* cc_dep2 */
   ASSERT(cargs[3]); /* cc_ndep */
   ASSERT(cargs[0]->tag == Iex_RdTmp);
   ASSERT(cargs[1]->tag == Iex_RdTmp);
   ASSERT(cargs[2]->tag == Iex_RdTmp);
   ASSERT(cargs[3]->tag == Iex_RdTmp);

   ASSERT(typeOfIRExpr(bb->tyenv, cargs[1]) == 
          typeOfIRExpr(bb->tyenv, cargs[2]));
   depTy = typeOfIRExpr(bb->tyenv, cargs[1]);

   TaintMapInstrFlowBinary(bb, Iop_And32 /* for stat purposes, treat as binop */,
         TaintMap_Loc2Key(lhsTmp, TmpLoc),
         typeOfIRTemp(bb->tyenv, lhsTmp),
         TaintMap_Loc2Key(cargs[1]->Iex.RdTmp.tmp, TmpLoc),
         depTy,
         TaintMap_Loc2Key(cargs[2]->Iex.RdTmp.tmp, TmpLoc),
         depTy);
}

/*
 * -- x86g_create_mxcsr --
 *
 * We treat this as a unary op since it takes the
 * argument, applies a few shift and or, and returns
 * the same sized (32-bit) result. 
 *
 */
static void
isIRTmpCCallCreateMXCSR(IRSB *bb, IRStmt *s)
{
   IRExpr** cargs; 
   IRTemp lhsTmp, rhsTmp;

   lhsTmp = s->Ist.WrTmp.tmp;
   cargs = s->Ist.WrTmp.data->Iex.CCall.args;

   ASSERT(cargs[0]);
   ASSERT(cargs[0]->tag == Iex_RdTmp);

   rhsTmp = cargs[0]->Iex.RdTmp.tmp;

   TaintMapInstrFlowUnary(bb, 
         Iop_32to1 /* for stat purposes, treat as unary op */,
         TaintMap_Loc2Key(lhsTmp, TmpLoc),
         typeOfIRTemp(bb->tyenv, lhsTmp),
         TaintMap_Loc2Key(rhsTmp, TmpLoc),
         typeOfIRTemp(bb->tyenv, rhsTmp));
}

static void
isIRTmpCCallCheckLDMXCSR(IRSB *bb, IRStmt *s)
{
   IRExpr** cargs; 
   IRTemp lhsTmp, rhsTmp;

   lhsTmp = s->Ist.WrTmp.tmp;
   cargs = s->Ist.WrTmp.data->Iex.CCall.args;

   ASSERT(cargs[0]);
   ASSERT(cargs[0]->tag == Iex_RdTmp);

   rhsTmp = cargs[0]->Iex.RdTmp.tmp;

   TaintMapInstrFlowUnary(bb, 
         Iop_32to1 /* for stat purposes, treat as unary op */,
         TaintMap_Loc2Key(lhsTmp, TmpLoc),
         typeOfIRTemp(bb->tyenv, lhsTmp),
         TaintMap_Loc2Key(rhsTmp, TmpLoc),
         typeOfIRTemp(bb->tyenv, rhsTmp));
}

static void 
isIRTmpCCall(IRSB * bb, IRStmt * s)
{
   IRExpr * call; 
   IRCallee * callee;

   call = s->Ist.WrTmp.data; 
   ASSERT(call->tag == Iex_CCall); 
   callee = call->Iex.CCall.cee;

   /* XXX: we use strncmp since the actual name contains more than
    * just the name of the function being called. */
   if (!strncmp(callee->name, "x86g_calculate_condition", 24)) {
      isIRTmpCCallCalcCondition(bb, s); 
   } else if (!strncmp(callee->name, "x86g_calculate_eflags_c", 23) ||
         !strncmp(callee->name, "x86g_calculate_eflags_all", 25)) {
      isIRTmpCCallCalcEflags(bb, s);
   } else if (!strncmp(callee->name, "x86g_use_seg_selector", 21)) {
      DEBUG_MSG(5,"Unhandled isIR x86g_use_seg_selector\n");
      WARN_XXX(0);
   } else if (!strncmp(callee->name, "x86g_create_mxcsr", 17)) {
      isIRTmpCCallCreateMXCSR(bb, s); 
   } else if (!strncmp(callee->name, "x86g_check_ldmxcsr", 18)) {
      isIRTmpCCallCheckLDMXCSR(bb, s);
   } else {
      WARN_UNIMPLEMENTED_MSG(0,
            "Unhandled ccall %s\n", callee->name);
      return; 
   }
}


/* 
 * Add instrumentation for statement of form tX = Mux0X(tA,tB,tZ) 
 * Complication here is that tA, tB, tZ could be constants.       
 *                                                                
 * Strict interpretation:                                         
 * tX should be tainted if tA is true and tB is tainted OR tA     
 * is false and tZ is tainted OR if tA is tainted.
 *
 * Loose interpretation:                                          
 * tX should be tainted if any one of tA, tB, tZ is tainted.      
 *
 * isIRTmpMux0X implements the strict interpretation.              
 */

static void 
isIRTmpMux0X(IRSB * bb, IRStmt * s)
{
   IRExpr *rhs, *condExpr, *trueExpr, *falseExpr;
   HWord condName, condKey, falseName, falseKey; 
   HWord trueName, trueKey, lhsKey; 
   IRTemp lhsTmp;

   rhs = s->Ist.WrTmp.data; 
   ASSERT(rhs->tag == Iex_Mux0X); 
   condExpr = rhs->Iex.Mux0X.cond; 
   falseExpr = rhs->Iex.Mux0X.expr0; 
   trueExpr = rhs->Iex.Mux0X.exprX; 

   ASSERT(condExpr->tag == Iex_RdTmp || condExpr->tag == Iex_Const); 
   ASSERT(trueExpr->tag == Iex_RdTmp || trueExpr->tag == Iex_Const); 
   ASSERT(falseExpr->tag == Iex_RdTmp || falseExpr->tag == Iex_Const); 

   lhsTmp = s->Ist.WrTmp.tmp; 
   lhsKey = TaintMap_Loc2Key(lhsTmp, TmpLoc); 

   if (condExpr->tag == Iex_RdTmp) {
      condName = (HWord)condExpr->Iex.RdTmp.tmp; 
      condKey = TaintMap_Loc2Key(condName, TmpLoc);
   } else { 
      ASSERT(condExpr->tag == Iex_Const);
      condKey = Key_Const;
   }

   if (trueExpr->tag == Iex_RdTmp) {
      trueName = (HWord)trueExpr->Iex.RdTmp.tmp;
      trueKey = TaintMap_Loc2Key(trueName, TmpLoc); 
   } else {
      ASSERT(trueExpr->tag == Iex_Const);
      trueKey = Key_Const;
   }

   if (falseExpr->tag == Iex_RdTmp) {
      falseName = (HWord)falseExpr->Iex.RdTmp.tmp; 
      falseKey = TaintMap_Loc2Key(falseName, TmpLoc); 
   } else {
      ASSERT(falseExpr->tag == Iex_Const);
      falseKey = Key_Const;
   }

   TaintMapInstrFlowTrinaryExpr(bb,
               mkIRExpr_HWord(lhsKey),
               typeOfIRTemp(bb->tyenv, lhsTmp),
               condExpr,
               mkIRExpr_HWord(condKey),
               typeOfIRExpr(bb->tyenv, condExpr),
               mkIRExpr_HWord(trueKey), 
               typeOfIRExpr(bb->tyenv, trueExpr),
               mkIRExpr_HWord(falseKey),
               typeOfIRExpr(bb->tyenv, falseExpr)); 
}

static void 
isIRTmpTmp(IRSB * bb, IRStmt * s, IRTemp ty)
{
   IRExpr * rhs; 
   HWord lhsKey, rhsKey;

   ASSERT(s->tag == Ist_WrTmp);
   rhs = s->Ist.WrTmp.data; 
   ASSERT(rhs->tag == Iex_RdTmp); 

   lhsKey = TaintMap_Loc2Key(s->Ist.WrTmp.tmp,TmpLoc); 
   rhsKey = TaintMap_Loc2Key(rhs->Iex.RdTmp.tmp,TmpLoc); 

   TaintMapInstrFlowCopy(bb, lhsKey, rhsKey, ty);
}

static void 
isIRTmpGet(IRSB * bb, IRStmt * s, IRTemp ty)
{
   IRExpr * rhs; 
   HWord lhsKey, rhsKey;

   ASSERT(s->tag == Ist_WrTmp);
   rhs = s->Ist.WrTmp.data; 
   ASSERT(rhs->tag == Iex_Get); 

   lhsKey = TaintMap_Loc2Key(s->Ist.WrTmp.tmp,TmpLoc); 
   rhsKey = TaintMap_Loc2Key(rhs->Iex.Get.offset,RegLoc); 

   TaintMapInstrFlowCopy(bb, lhsKey, rhsKey, ty);
}

static void 
isIRTmpLoad(IRSB * bb, IRStmt * st, IRTemp ty)
{
   IRDirty *d;
   IRExpr *rhs, *addrExpr;
   HWord locTmp, lhsTmp, locKey, lhsKey;
   IRType locTy, dataTy;

   ASSERT(st->tag == Ist_WrTmp);
   rhs = st->Ist.WrTmp.data;
   ASSERT(rhs->tag == Iex_Load);

   lhsTmp = st->Ist.WrTmp.tmp;
   lhsKey = TaintMap_Loc2Key(lhsTmp, TmpLoc);

   addrExpr = rhs->Iex.Load.addr;
   ASSERT(addrExpr->tag == Iex_RdTmp || addrExpr->tag == Iex_Const);
   locTmp = addrExpr->Iex.RdTmp.tmp;
   if (addrExpr->tag == Iex_RdTmp) {
      locKey = TaintMap_Loc2Key(locTmp, TmpLoc);
   } else {
      locKey = Key_Const;
   }
   locTy = typeOfIRExpr(bb->tyenv, addrExpr);
   dataTy = typeOfIRTemp(bb->tyenv, lhsTmp);

   d = BinTrns_DirtyHelperThatReadsExecPoint(
         0,
         "TaintMapFlowLoad",
         &TaintMapFlowLoad,
         mkIRExprVec_5(
            mkIRExpr_HWord(locKey),
            mkIRExpr_HWord(mySizeofIRType(locTy)),
            mkIRExpr_HWord(lhsKey),
            addrExpr,
            mkIRExpr_HWord(mySizeofIRType(dataTy))));

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}

static void
isIRTmpConst(IRSB * bb, IRStmt * s, IRTemp ty)
{
   IRTemp lhsTmp;
   HWord  lhsKey;

   ASSERT(s->tag == Ist_WrTmp); 

   lhsTmp = (HWord) s->Ist.WrTmp.tmp; 
   lhsKey = TaintMap_Loc2Key(lhsTmp, TmpLoc); 

   TaintMapInstrFlowCopy(bb, lhsKey, Key_Const, ty);
}


static void
isIRTmpCopy(IRSB *bb, IRStmt *s)
{
   HWord lhsTmp;
   IRType lhsTy, rhsTy;
   IRExpr *rhs;

   ASSERT (s->tag == Ist_WrTmp);

   rhs = s->Ist.WrTmp.data;
   lhsTmp = s->Ist.WrTmp.tmp;
   lhsTy = typeOfIRTemp(bb->tyenv, lhsTmp);
   rhsTy = typeOfIRExpr(bb->tyenv, rhs);

   ASSERT(lhsTy == rhsTy);

   switch (rhs->tag) {
   case Iex_Const:
      isIRTmpConst(bb,s, lhsTy);
      break;
   case Iex_Get:
      isIRTmpGet(bb,s, lhsTy);
      break;
   case Iex_Load:
      isIRTmpLoad(bb,s, lhsTy); 
      break; 
   case Iex_RdTmp:
      isIRTmpTmp(bb,s, lhsTy); 
      break; 
   default:
      ASSERT(0);
      break;
   }
}

static void 
isIRTmp(IRSB * bb, IRStmt * s)
{
   IRExpr * rhs;

   ASSERT(s->tag == Ist_WrTmp);
   rhs = s->Ist.WrTmp.data;

   switch (rhs->tag) {
   case (Iex_Const):
   case (Iex_Get):
   case (Iex_Load):
   case (Iex_RdTmp):
      isIRTmpCopy(bb, s);
      break;
   case(Iex_Binop):
      isIRTmpBinop(bb, s); 
      break;
   case(Iex_Unop):
      isIRTmpUnop(bb, s); 
      break; 
   case (Iex_CCall):
      isIRTmpCCall(bb, s); 
      break; 
   case (Iex_Mux0X):
      isIRTmpMux0X(bb, s); 
      break; 
   case (Iex_GetI):
      /* Seems to be for FPU ops. */
      WARN_XXX(0);
      break;
   case (Iex_Triop):
      /* Seems to be for FPU ops. */
      WARN_XXX(0);
      break;
   case (Iex_Qop):
      WARN_XXX(0);
      break;
   default:
      ppIRExpr(rhs); 
      ASSERT_UNIMPLEMENTED_MSG(0, "Unhandled IRExpr %d\n", rhs->tag);
      break;
   }
} 

static void 
isIRPut(IRSB * bb, IRStmt * s)
{
   IRExpr * data;
   HWord lhsKey, rhsKey;
   IRType dataTy;

   lhsKey = TaintMap_Loc2Key(s->Ist.Put.offset, RegLoc); 
   data = s->Ist.Put.data; 
   dataTy = typeOfIRExpr(bb->tyenv, data);

   switch(data->tag) {
   case (Iex_Const):
      TaintMapInstrFlowCopy(bb, lhsKey, Key_Const, dataTy);
      break; 
   case (Iex_RdTmp):
      rhsKey = TaintMap_Loc2Key(data->Iex.RdTmp.tmp, TmpLoc);
      TaintMapInstrFlowCopy(bb, lhsKey, rhsKey, dataTy);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break; 
   }
}

static void 
isIRStore(IRSB * bb, IRStmt * st)
{
   IRDirty *d;
   IRExpr *addrExpr, *dataExpr;
   HWord locTmp, locKey, rhsKey;
   IRType locTy, dataTy;

   ASSERT(st->tag == Ist_Store);

   addrExpr = st->Ist.Store.addr;
   ASSERT(addrExpr->tag == Iex_RdTmp || addrExpr->tag == Iex_Const);
   if (addrExpr->tag == Iex_RdTmp) {
      locTmp = addrExpr->Iex.RdTmp.tmp;
      locKey = TaintMap_Loc2Key(locTmp, TmpLoc);
   } else {
      locKey = Key_Const;
   }
   locTy = typeOfIRExpr(bb->tyenv, addrExpr);
   dataExpr = st->Ist.Store.data;
   dataTy = typeOfIRExpr(bb->tyenv, dataExpr);

   switch (dataExpr->tag) {
   case (Iex_Const):
      rhsKey = Key_Const;
      break; 
   case (Iex_RdTmp):
      rhsKey = TaintMap_Loc2Key(dataExpr->Iex.RdTmp.tmp, TmpLoc); 
      break; 
   default:
      ASSERT_UNIMPLEMENTED(0);
      return; 
   }

   d = BinTrns_DirtyHelperThatReadsExecPoint(
         0,
         "TaintMapFlowStore",
         &TaintMapFlowStore,
         mkIRExprVec_5(
            mkIRExpr_HWord(locKey),
            mkIRExpr_HWord(mySizeofIRType(locTy)),
            addrExpr,
            mkIRExpr_HWord(rhsKey),
            mkIRExpr_HWord(mySizeofIRType(dataTy))));

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}

static void
isIRExit(IRSB *bb, IRStmt *st)
{
   HWord guardKey;
   IRExpr *guard = st->Ist.Exit.guard;
   IRTemp guardTmp;
   IRType guardTy;
   IRDirty *d;

   ASSERT(guard->tag == Iex_RdTmp);

   guardTmp = guard->Iex.RdTmp.tmp;
   guardKey = TaintMap_Loc2Key(guardTmp, TmpLoc);
   guardTy = typeOfIRTemp(bb->tyenv, guardTmp);

   d = BinTrns_DirtyHelperThatReadsExecPoint(
         0,
         "TaintMapFlowExit",
         &TaintMapFlowExit,
         mkIRExprVec_2(
            mkIRExpr_HWord(guardKey),
            mkIRExpr_HWord(mySizeofIRType(guardTy)))
         );

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}


void 
TaintMap_IRStmt(IRSB * bb, IRStmt * s)
{
   switch (s->tag) {
   case Ist_NoOp:
      break;
   case Ist_IMark:
      break;
   case Ist_AbiHint:
      break;
   case Ist_Put:
      isIRPut(bb,s); 
      break;
   case Ist_PutI:
      WARN_XXX(0);
      break;
   case Ist_WrTmp:
      isIRTmp(bb,s); 
      break;
   case Ist_Store:
      isIRStore(bb,s); 
      break;
   case Ist_Dirty:
      break;
   case Ist_MBE:
      break;
   case Ist_Exit:
      STATS_ONLY(isIRExit(bb, s);)
      break;
   default:
      DEBUG_MSG(5,"Unhandled statement in isIRStmt: "); 
      ppIRStmt(s);
      DEBUG_MSG(5,"\n"); 
      ASSERT_UNIMPLEMENTED(0);
      break;
   }
}
