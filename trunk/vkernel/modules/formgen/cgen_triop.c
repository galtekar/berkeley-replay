#include "vkernel/public.h"
#include "private.h"

static const int wantsComments = 1;

static void
cgEmitTmpTriopWork(UInt theOp, UInt lhsTmp, UInt lhsTy,
      struct ArgStruct *arg1, struct ArgStruct *arg2,
      struct ArgStruct *arg3)
{
   ASSERT(arg1->tmp >= -1);
   ASSERT(arg2->tmp >= -1);
   ASSERT(arg3->tmp >= -1);

   switch (theOp) {
   default:
      ppIROp(theOp);
      ASSERT_UNIMPLEMENTED_MSG(0, "\nUnhandled IR op\n");
      break;
   }
}

static void
cgEmitTmpTriop(
      UInt theOp, UInt lhsTmp, UInt lhsTy, 
      UInt arg1Ty, Int arg1Tmp,
      UInt arg2Ty, Int arg2Tmp,
      UInt arg3Ty, Int arg3Tmp,
      struct PackedArgs argBuf
      )
{
   struct ArgStruct arg1, arg2 ,arg3;
#define NUM_ARGS 3
   TCode isArgTaintedA[NUM_ARGS];
   ULong argValA[NUM_ARGS] = { 0 };
   IRType tyA[NUM_ARGS] = { arg1Ty, arg2Ty, arg3Ty };

   ASSERT(sizeofIRType(arg1Ty));
   ASSERT(sizeofIRType(arg2Ty));
   ASSERT(sizeofIRType(arg3Ty));


   /* -------- Propagate taint -------- */

   isArgTaintedA[0] = cg_IsArgTainted(arg1Tmp);
   isArgTaintedA[1] = cg_IsArgTainted(arg2Tmp);
   isArgTaintedA[2] = cg_IsArgTainted(arg3Tmp);

   if (cg_PropagateOpTaint(lhsTmp, lhsTy, isArgTaintedA, NUM_ARGS)) {
      return;
   }

   /* -------- Generate constraints -------- */

   /* Encapsulate each arg cleanly in a struct. The hard
    * part is in extracting the argument values from the arg
    * array. The layout depends on the type of each arg. */

   cgProf_UpdateCounter();

   cg_UnpackArgs(argValA, tyA, &argBuf, NUM_ARGS);
   cg_MkArg(&arg1, arg1Ty, arg1Tmp, argValA[0]);
   cg_MkArg(&arg2, arg2Ty, arg2Tmp, argValA[1]);
   cg_MkArg(&arg3, arg3Ty, arg3Tmp, argValA[2]);

   cgEmitTmpTriopWork(theOp, lhsTmp, lhsTy, &arg1, &arg2, &arg3);
}

void 
cg_InstrTmpTriop(IRSB * bb, const IRStmt * s)
{
   IRExpr *rhs, *arg1, *arg2, *arg3;
   IRDirty * d; 
   UInt lhsTmp, arg1Tmp, arg2Tmp, arg3Tmp;
   UInt lhsTy, arg1Ty, arg2Ty, arg3Ty; 
   UInt theOp; 

   ASSERT_KPTR(bb);
   ASSERT_KPTR(s);
   ASSERT(s->tag == Ist_WrTmp); 
   rhs = s->Ist.WrTmp.data; 
   ASSERT(rhs->tag == Iex_Triop); 
   arg1 = rhs->Iex.Triop.arg1;
   arg2 = rhs->Iex.Triop.arg2; 
   arg3 = rhs->Iex.Triop.arg3; 
   theOp = rhs->Iex.Triop.op; 

   lhsTmp = (HWord) s->Ist.WrTmp.tmp;
   lhsTy = typeOfIRTemp(bb->tyenv, lhsTmp);

   arg1Ty = typeOfIRExpr(bb->tyenv, arg1);
   arg1Tmp = cg_GetTempOrConst(arg1);

   arg2Ty = typeOfIRExpr(bb->tyenv, arg2);
   arg2Tmp = cg_GetTempOrConst(arg2);

   arg3Ty = typeOfIRExpr(bb->tyenv, arg3);
   arg3Tmp = cg_GetTempOrConst(arg3);

   d = unsafeIRDirty_0_N(0,
         "cgEmitTmpTriop",
         &cgEmitTmpTriop,
         mkIRExprVec(13,
            mkIRExpr_UInt(theOp), /* pushed last */
            mkIRExpr_UInt(lhsTmp),
            mkIRExpr_UInt(lhsTy),
            mkIRExpr_UInt(arg1Ty),
            mkIRExpr_UInt(arg1Tmp),
            mkIRExpr_UInt(arg2Ty),
            mkIRExpr_UInt(arg2Tmp),
            mkIRExpr_UInt(arg3Ty),
            mkIRExpr_UInt(arg3Tmp),
            BT_ArgFixup(bb, arg1),
            BT_ArgFixup(bb, arg2),
            BT_ArgFixup(bb, arg3),
            mkIRExpr_UInt(DEBUG_MAGIC)
            )
         );
   addStmtToIRSB(bb,IRStmt_Dirty(d)); 

   return; 
}
