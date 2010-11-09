#include "vkernel/public.h"
#include "private.h"

static const int wantsComments = 1;

enum { cgIop_Identity };

/*
 * Summary:
 *    Constrains the number of leading or trailing zeros.
 *
 * Complexity:
 *    O(#bits). XXX: do this in O(lg(#bits)).
 */
static void
cgEmitCntZeros(int wantsFwd, IRType lhsTy, IRType argTy, IRTemp argTmp, int nz)
{
   const int nrBits = IRTYPE2BITS(lhsTy);

   ASSERT(nz >= 0 && nz <= nrBits);

   ULong datamask = ~(~0LLU << nrBits);

   ULong mask = wantsFwd ? ~0LLU >> (nrBits-nz) : ~0LLU << (nrBits-nz);
   mask &= datamask;

   CG_ITE(
         /* IF */
         CG_EQUAL(CG_AND(CG_TMP(argTmp), CG_CONST(argTy, mask)), 
                  CG_CONST(argTy, 0)),

         /* THEN */
         CG_CONST(lhsTy, nz),

         /* ELSE */
         ({
            if (nz > 1) {
               cgEmitCntZeros(wantsFwd, lhsTy, argTy, argTmp, nz-1);
            } else {
               CG_CONST(lhsTy, 0);
            }
         })
      );
}


static void 
cgEmitTmpUnop(
   IROp op,
   IRTemp lhsTmp,
   IRType lhsTy,
   IRTemp argTmp,
   IRType argTy
)
{
   ASSERT(lhsTmp != -1);
   ASSERT(lhsTy == Ity_I1 || sizeofIRType(lhsTy));
   ASSERT(argTy == Ity_I1 || sizeofIRType(argTy));

#define NUM_ARGS 1
   TCode isArgTaintedA[NUM_ARGS];

   /* ----- Propagate taint ----- */

   isArgTaintedA[0] = cg_IsArgTainted(argTmp);

   if (cg_PropagateOpTaint(lhsTmp, lhsTy, isArgTaintedA, NUM_ARGS)) {
      return;
   }

   ASSERT(argTmp != -1);

   /* ----- Generate constraints ----- */

   cgProf_UpdateCounter();

   cg_DeclareTmp(lhsTmp, lhsTy);

   switch (op) {
   case cgIop_Identity:
      ASSERT(lhsTy == argTy);
      CG_ASSIGN(CG_TMP(lhsTmp), CG_TMP(argTmp));
      break;

   case Iop_Not1:
   case Iop_Not8:
   case Iop_Not16:
   case Iop_Not32:
      ASSERT(lhsTy == argTy);
      CG_ASSIGN(CG_TMP(lhsTmp), CG_INV(CG_TMP(argTmp)));
      break;

   /* ----- Generated on BSF/BSR; used by wget and others ----- */

   case Iop_Clz32: /* BSR (starting from idx n); reverse */
   case Iop_Clz64:
      CG_COMMENT("Iop_Clz\n");
      CG_ASSIGN(CG_TMP(lhsTmp), cgEmitCntZeros(0, lhsTy, argTy, argTmp, IRTYPE2BITS(argTy)));
      break;
   case Iop_Ctz32: /* BSF (starting from idx 0); forward */
   case Iop_Ctz64:
      CG_COMMENT("Iop_Ctz\n");
      CG_ASSIGN(CG_TMP(lhsTmp), cgEmitCntZeros(1, lhsTy, argTy, argTmp, IRTYPE2BITS(argTy)));
      break;


   /* ----- Widening without sign extension ----- */

   case Iop_1Uto8:
   case Iop_1Uto32:
   case Iop_1Uto64:
   case Iop_8Uto16:
   case Iop_8Uto32:
   case Iop_8Uto64:
   case Iop_16Uto32:
   case Iop_16Uto64:
   case Iop_32Uto64:
      ASSERT(T2B(lhsTy) > T2B(argTy));
      CG_ASSIGN(CG_TMP(lhsTmp),
            CG_X(CG_TMP(argTmp), T2B(lhsTy)-T2B(argTy)));
      break;

   /* ----- Widening with sign extension ----- */

   case Iop_1Sto8:
   case Iop_1Sto16:
   case Iop_1Sto32:
   case Iop_1Sto64:
   case Iop_8Sto16:
   case Iop_8Sto32:
   case Iop_8Sto64:
   case Iop_16Sto32:
   case Iop_16Sto64:
   case Iop_32Sto64:
      ASSERT(T2B(lhsTy) > T2B(argTy));
      CG_ASSIGN(CG_TMP(lhsTmp), CG_SX(lhsTy, CG_TMP(argTmp)));
      break;

   /* ----- Narrowing ----- */

   case Iop_16to8:
   case Iop_32to1:
   case Iop_32to8:
   case Iop_32to16:
   case Iop_64to8:
   case Iop_64to16:
   case Iop_64to32:
      ASSERT(T2B(lhsTy) < T2B(argTy));
      CG_ASSIGN(CG_TMP(lhsTmp), CG_CAST(lhsTy, CG_TMP(argTmp)));
      break;
   case Iop_16HIto8:
   case Iop_32HIto16:
   case Iop_64HIto32:
      ASSERT(T2B(lhsTy) < T2B(argTy));
      CG_ASSIGN(CG_TMP(lhsTmp), CG_HI(argTy, CG_TMP(argTmp)));
      break;

   default:
      ppIROp(op);
      ASSERT_UNIMPLEMENTED_MSG(0, "\nUnhandled op");
      break;
   }
}

void
cg_InstrTmpUnop(IRSB * bb, const IRStmt * s)
{
   IRExpr * rhs;
   IRExpr * arg;
   IROp op;
   IRDirty * d;
   IRTemp lhsTmp;
   IRTemp argTmp = -1;
   IRType lhsTy, argTy = 0;

   ASSERT_KPTR(s);
   ASSERT(s->tag == Ist_WrTmp);
   rhs = s->Ist.WrTmp.data;
   lhsTmp = s->Ist.WrTmp.tmp;
   lhsTy = typeOfIRTemp(bb->tyenv, lhsTmp);

   if (rhs->tag == Iex_Unop) {
      arg = rhs->Iex.Unop.arg;
      op = rhs->Iex.Unop.op;

      switch (arg->tag) {
      case Iex_RdTmp:
      case Iex_Const:
         argTmp = cg_GetTempOrConst(arg);
         argTy = typeOfIRExpr(bb->tyenv, arg);
         break;
      default:
         ASSERT(0);
         break;
      }
   } else {
      ASSERT(rhs->tag == Iex_RdTmp || rhs->tag == Iex_Const);
      argTmp = cg_GetTempOrConst(rhs);
      argTy = typeOfIRExpr(bb->tyenv, rhs);
      op = cgIop_Identity;
   } 

   d = unsafeIRDirty_0_N(0,
         "cgEmitTmpUnop",
         cgEmitTmpUnop,
         mkIRExprVec_5(
            mkIRExpr_UInt(op),
            mkIRExpr_UInt(lhsTmp),
            mkIRExpr_UInt(lhsTy),
            mkIRExpr_UInt(argTmp),
            mkIRExpr_UInt(argTy)
            )
         );
   addStmtToIRSB(bb, IRStmt_Dirty(d));

   return;
}
