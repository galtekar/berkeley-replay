/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

static const int wantsComments = 1;

typedef enum { SHL, SHR, SAR } ShfKind;

static void
cgEmitShift(const ShfKind sk, const IRType lhsTy, const struct ArgStruct *arg1,
            const struct ArgStruct *arg2, const int shiftVal)
{
   CG_ITE(
         /* IF */
         CG_EQUAL(CG_ARG_DEF(arg2), CG_CONST(arg2->ty, shiftVal)),

         /* THEN */
         ({
            switch (sk) {
            case SHL:
               CG_SHL(lhsTy, CG_ARG_DEF(arg1), shiftVal);
               break;
            case SHR:
               CG_SHR(lhsTy, CG_ARG_DEF(arg1), shiftVal);
               break;
            case SAR:
               CG_SAR(lhsTy, CG_ARG_DEF(arg1), shiftVal);
               break;
            default:
               ASSERT(0);
               break;
            };
         }),

         /* ELSE */
         ({
            if (shiftVal > 0) {
               cgEmitShift(sk, lhsTy, arg1, arg2, shiftVal-1); 
            } else {
               /* We should've covered all the cases by now, so this
                * the solver should never hold true. */
               CG_ARG(lhsTy, arg1);
            }
         })
      );
}

static void
cgEmitTmpBinopWork(UInt op, UInt lhsTmp, UInt lhsTy,
      struct ArgStruct *arg1, struct ArgStruct *arg2)
{
   ASSERT(arg1->tmp >= -1);
   ASSERT(arg2->tmp >= -1);

   cg_DeclareTmp(lhsTmp, lhsTy);

   switch (op) {
   case Iop_32HLto64:
      CG_ASSIGN(CG_HI(Ity_I64, CG_TMP(lhsTmp)), 
            CG_ARG(Ity_I32, arg1));
      CG_ASSIGN(CG_LO(Ity_I64, CG_TMP(lhsTmp)), 
            CG_ARG(Ity_I32, arg2));
      break; 

   case Iop_Add8:
   case Iop_Add16:
   case Iop_Add32:
   case Iop_Add64:
      ASSERT(arg1->ty == arg2->ty);
      CG_ASSIGN(CG_TMP(lhsTmp), CG_ADD(lhsTy,
               CG_ARG(lhsTy, arg1), CG_ARG(lhsTy, arg2)));
      break;
   case Iop_Sub8:
   case Iop_Sub16: 
   case Iop_Sub32:
   case Iop_Sub64:
      ASSERT(arg1->ty == arg2->ty);
      CG_ASSIGN(CG_TMP(lhsTmp), CG_SUB(lhsTy,
               CG_ARG(lhsTy, arg1), CG_ARG(lhsTy, arg2)));
      break;

      /* Non-widening multiplies: result will have same
       * number of bits as operands. */
   case Iop_Mul8:
   case Iop_Mul16:
   case Iop_Mul32:
   case Iop_Mul64:
      {
         ASSERT(arg1->ty == arg2->ty);
         ASSERT(T2B(lhsTy) == T2B(arg1->ty));
         CG_ASSIGN(CG_TMP(lhsTmp), 
               CG_MULT(lhsTy, 
                  CG_ARG(arg1->ty, arg1), 
                  CG_ARG(arg2->ty, arg2))
               );
      }
      break;
      /* Widening multiplies: result will have twice as many
       * bits as the operands. */
   case Iop_MullU8:
   case Iop_MullU16:
   case Iop_MullU32:
   case Iop_MullU64:
      {
         ASSERT(arg1->ty == arg2->ty);
         ASSERT(T2B(lhsTy) == T2B(arg1->ty)*2);
         int xBits = T2B(lhsTy) - T2B(arg1->ty);
         CG_ASSIGN(CG_TMP(lhsTmp), 
               CG_MULT(lhsTy, 
                  CG_X(CG_ARG(arg1->ty, arg1), xBits), 
                  CG_X(CG_ARG(arg2->ty, arg2), xBits))
               );
      }
      break;
      /* Signed widening multiply. */
   case Iop_MullS8:
   case Iop_MullS16:
   case Iop_MullS32:
   case Iop_MullS64:
      {
         IRType ty = arg1->ty;

         ASSERT(T2B(lhsTy) == 2*T2B(ty));
         ASSERT(arg1->ty == arg2->ty);

         /* To get the correct signed result, we need to
          * double the precision (from n to 2n bits) of the 
          * operands before we do an unsigned multiplication,
          * then truncate the result to 2n bits (XXX: explain
          * why this works). */
         CG_ASSIGN(CG_TMP(lhsTmp), 
               CG_MULT(lhsTy, 
                  CG_SX(lhsTy, CG_ARG(ty, arg1)), 
                  CG_SX(lhsTy, CG_ARG(ty, arg2)))
               );
      }
      break;

   case Iop_Xor8:
   case Iop_Xor16:
   case Iop_Xor32:
   case Iop_Xor64:
      ASSERT(arg1->ty == arg2->ty);
      CG_ASSIGN(CG_TMP(lhsTmp), CG_XOR(
               CG_ARG(lhsTy, arg1), CG_ARG(lhsTy, arg2)));
      break; 

   case Iop_And8:
   case Iop_And16:
   case Iop_And32:
   case Iop_And64:
      ASSERT(arg1->ty == arg2->ty);
      CG_ASSIGN(CG_TMP(lhsTmp), CG_AND(
               CG_ARG(lhsTy, arg1), CG_ARG(lhsTy, arg2)));
      break;

   case Iop_Or8:
   case Iop_Or16:
   case Iop_Or32:
   case Iop_Or64:
      ASSERT(arg1->ty == arg2->ty);
      CG_ASSIGN(CG_TMP(lhsTmp), CG_OR(
               CG_ARG(lhsTy, arg1), CG_ARG(lhsTy, arg2)));
      break; 

#if 0
#define SHIFT(dir) \
      { \
         ASSERT(arg2->val <= IRTYPE2BITS(arg1->ty)); \
         if (arg2->tag == Iex_Const || \
               !TaintMap_IsTmpTainted(arg2->tmp)) { \
            CG_ASSIGN(CG_TMP(lhsTmp), \
                  CG_##dir(lhsTy, CG_ARG_DEF(arg1), \
                     (int)(arg2->val))); \
         } else { \
            int shiftVal; \
            ASSERT(arg2->tag == Iex_RdTmp); \
            for (shiftVal = 0; shiftVal < IRTYPE2BITS(arg1->ty); shiftVal++) { \
               CG_ASSERT( \
                     CG_ITE( \
                        CG_EQUAL(CG_ARG(Ity_I32, arg2),  /* IF */ \
                           CG_CONST(Ity_I32, shiftVal)), \
                        CG_EQUAL(CG_TMP(lhsTmp), /* THEN */ \
                           CG_##dir(lhsTy, CG_ARG_DEF(arg1), \
                              (shiftVal))), \
                        CG_TRUE)); /* ELSE */ \
            } \
         } \
      }
#endif
#define SHIFT(dir) \
      { \
         ASSERT(arg2->val <= IRTYPE2BITS(arg1->ty)); \
         if (arg2->tag == Iex_Const || \
               !TaintMap_IsTmpTainted(arg2->tmp)) { \
            CG_ASSIGN(CG_TMP(lhsTmp), \
                  CG_##dir(lhsTy, CG_ARG_DEF(arg1), \
                     (int)(arg2->val))); \
         } else { \
            ASSERT(arg2->tag == Iex_RdTmp); \
            CG_ASSIGN(CG_TMP(lhsTmp), \
               cgEmitShift(dir, lhsTy, arg1, arg2, IRTYPE2BITS(arg1->ty))); \
         } \
      }
   case Iop_Shl8:
   case Iop_Shl16:
   case Iop_Shl32:
   case Iop_Shl64: 
      SHIFT(SHL);
      break;

   case Iop_Shr8:
   case Iop_Shr16:
   case Iop_Shr32:
   case Iop_Shr64: 
      SHIFT(SHR);
      break; 

   case Iop_Sar8:
   case Iop_Sar16:
   case Iop_Sar32:
   case Iop_Sar64:
      SHIFT(SAR);
      break; 

#define CMP(pred, v1, v2) \
      ASSERT(lhsTy == Ity_I1); \
      ASSERT(arg1->ty == arg2->ty); \
      CG_ASSIGN(CG_TMP(lhsTmp), \
            CG_ITE( \
               /* If */ \
               CG_##pred(CG_ARG_DEF(arg1), CG_ARG_DEF(arg2)), \
               /* Then */ \
               CG_CONST(Ity_I1, (v1)), \
               /* Else */ \
               CG_CONST(Ity_I1, (v2))));

   case Iop_CmpLT32S:
   case Iop_CmpLT64S:
      CMP(SLT, 1, 0);
      break;
   case Iop_CmpLT32U:
   case Iop_CmpLT64U:
      CMP(LT, 1, 0);
      break;
   case Iop_CmpLE32S:
   case Iop_CmpLE64S:
      CMP(SLE, 1, 0);
      break;
   case Iop_CmpLE32U:
   case Iop_CmpLE64U:
      CMP(LE, 1, 0);
      break;

   case Iop_CmpNE8:
   case Iop_CmpNE16:
   case Iop_CmpNE32:
   case Iop_CmpNE64:
   case Iop_CasCmpNE8:
   case Iop_CasCmpNE16:
   case Iop_CasCmpNE32:
   case Iop_CasCmpNE64:
      CMP(EQUAL, 0, 1);
      break; 
   case Iop_CmpEQ8:
   case Iop_CmpEQ16:
   case Iop_CmpEQ32:
   case Iop_CmpEQ64:
   case Iop_CasCmpEQ8:
   case Iop_CasCmpEQ16:
   case Iop_CasCmpEQ32:
   case Iop_CasCmpEQ64:
      CMP(EQUAL, 1, 0);
      break; 

#define DIVMOD(mod,div) \
      CG_NEW_LOCAL_SCOPE(); \
      CG_NEW_VAR(Ity_I64, CG_LSCOPE("res")); \
      /* Quotient occupies lower 32-bits, remainder the higher  \
       * 32-bits. */ \
      /* The remainder should always be less than the divisor. \
       * So we can truncate to 32-bits without precision loss. */ \
      CG_ASSIGN(CG_HI(Ity_I64, CG_LSCOPE("res")), \
         CG_LO(Ity_I64, CG_##mod(Ity_I64,  \
            CG_ARG(Ity_I64, arg1), CG_ARG(Ity_I64, arg2)))); \
      /* Quotient. */ \
      CG_NEW_VAR_INIT(Ity_I64, CG_LSCOPE("quotient"), \
            CG_##div(Ity_I64, CG_ARG(Ity_I64, arg1), CG_ARG(Ity_I64, arg2))); \
      CG_ASSIGN(CG_LO(Ity_I64, CG_LSCOPE("res")), \
         CG_LO(Ity_I64, CG_LSCOPE("quotient"))); \
      CG_ASSIGN(CG_TMP(lhsTmp), CG_LSCOPE("res"));

   case Iop_DivModU64to32:

#if 0
      /* XXX: quotients > (2^32 - 1) generate a division exception (#DE),
       * in which case nothing should get written to the registers
       * (see x86 docs for DIV instruction pseudo-code). 
       * Check for this case. */
      CG_ASSIGN(CG_TMP(lhsTmp), 
            CG_ITE(
               CG_LT(CG_CONST(Ity_I64, 0xFFFFFFFF), CG_LSCOPE("quotient")),
               CG_TMP(lhsTmp),
               CG_LSCOPE("res")));
#endif
      DIVMOD(UMOD, UDIV);
      break;
   case Iop_DivModS64to32:
      DIVMOD(SMOD, SDIV);
      break;
   default:
      ppIROp(op);
      ASSERT_UNIMPLEMENTED_MSG(0, "\nUnhandled IR op\n");
      break;
   }
}

static void
cgEmitTmpBinop(
      UInt op, UInt lhsTmp, UInt lhsTy, 
      UInt arg1Ty, Int arg1Tmp,
      UInt arg2Ty, Int arg2Tmp,
      struct PackedArgs argBuf
      )
{
   struct ArgStruct arg1, arg2;
#define NUM_ARGS 2
   TCode isArgTaintedA[NUM_ARGS];
   ULong argValA[NUM_ARGS] = { 0 };
   IRType tyA[NUM_ARGS] = { arg1Ty, arg2Ty };

   ASSERT(sizeofIRType(arg1Ty));
   ASSERT(sizeofIRType(arg2Ty));


   /* -------- Propagate taint -------- */

   isArgTaintedA[0] = cg_IsArgTainted(arg1Tmp);
   isArgTaintedA[1] = cg_IsArgTainted(arg2Tmp);

   if (cg_PropagateOpTaint(lhsTmp, lhsTy, isArgTaintedA, NUM_ARGS)) {
      return;
   }

   /* -------- Generate constraints -------- */

   ASSERT(arg1Ty == arg2Ty || arg1Ty != arg2Ty);

   cgProf_UpdateCounter();

   cg_UnpackArgs(argValA, tyA, &argBuf, NUM_ARGS);
   cg_MkArg(&arg1, arg1Ty, arg1Tmp, argValA[0]);
   cg_MkArg(&arg2, arg2Ty, arg2Tmp, argValA[1]);

   cgEmitTmpBinopWork(op, lhsTmp, lhsTy, &arg1, &arg2);
}

/* XXX: merge unsigned/signed into single helper? */
static u64
cgDoUDivIfConcrete(IRTemp dividentTmp, u64 divident, IRTemp divisorTmp, u32 divisor)
{
   if ((cg_IsArgTainted(dividentTmp) ||
       cg_IsArgTainted(divisorTmp))) {
      /* Doesn't matter what value we return. */
      return 0;
   }

   u64 res = 0;
   u32 *quoP = (u32*)&res;
   u32 *remP = quoP+1;

   ASSERT_UNIMPLEMENTED(divisor != 0);

   *quoP = divident / divisor;
   *remP = divident % divisor;

   return res;
}

static s64
cgDoSDivIfConcrete(IRTemp dividentTmp, s64 divident, IRTemp divisorTmp, s32 divisor)
{
   if ((cg_IsArgTainted(dividentTmp) ||
       cg_IsArgTainted(divisorTmp))) {
      /* Doesn't matter what value we return. */
      return 0;
   }

   s64 res = 0;
   s32 *quoP = (s32*)&res;
   s32 *remP = quoP+1;

   ASSERT_UNIMPLEMENTED(divisor != 0);

   *quoP = divident / divisor;
   *remP = divident % divisor;

   return res;
}

int
cg_InstrTmpBinop(IRSB * bb, const IRStmt * s)
{
   IRExpr *rhs, *arg1, *arg2;
   IRDirty * d;
   UInt lhsTmp, arg1Tmp, arg2Tmp;
   UInt lhsTy, arg1Ty, arg2Ty;
   UInt op;
   int discStmt = 0;

   ASSERT_KPTR(bb);
   ASSERT_KPTR(s);
   ASSERT(s->tag == Ist_WrTmp); 
   rhs = s->Ist.WrTmp.data; 
   ASSERT(rhs->tag == Iex_Binop); 
   arg1 = rhs->Iex.Binop.arg1;
   arg2 = rhs->Iex.Binop.arg2; 
   op = rhs->Iex.Binop.op; 

   lhsTmp = (HWord) s->Ist.WrTmp.tmp;
   lhsTy = typeOfIRTemp(bb->tyenv, lhsTmp);

   arg1Ty = typeOfIRExpr(bb->tyenv, arg1);
   arg1Tmp = cg_GetTempOrConst(arg1);

   arg2Ty = typeOfIRExpr(bb->tyenv, arg2);
   arg2Tmp = cg_GetTempOrConst(arg2);

   ASSERT(arg1Ty == arg2Ty || arg1Ty != arg2Ty);

   /* ----- First, replace ops with non-faulting ones, if necessary. ----- */
   if (!ASSUME_ALL_INPUTS_KNOWN) {
      /* We don't now the original inputs, so these operations may
       * fault if executed natively, hence screwing up the replay by
       * generating an event when one was never recorded. Replace with 
       * non-faulting counterparts. */
      switch (op) {
      case Iop_DivModU64to32:
         ASSERT(arg1Ty == Ity_I64);
         ASSERT(arg2Ty == Ity_I32);

#if 1
         /* XXX: should this be a clean helper?
          * Methinks not. It reads the taint map, so it's not a pure
          * function. Let's make it dirty to be safe. */
         addStmtToIRSB(bb,
               IRStmt_Dirty(
                  MACRO_unsafeIRDirty_1_N(lhsTmp, 0, cgDoUDivIfConcrete,
                     mkIRExprVec_4(
                        mkIRExpr_UInt(arg1Tmp),
                        arg1,
                        mkIRExpr_UInt(arg2Tmp),
                        arg2))));
         discStmt = 1;
#endif
         break;
      case Iop_DivModS64to32:
#if 1
         ASSERT(arg1Ty == Ity_I64);
         ASSERT(arg2Ty == Ity_I32);

         /* XXX: should this be a clean helper?
          * Methinks not. It reads the taint map, so it's not a pure
          * function. Let's make it dirty to be safe. */
         addStmtToIRSB(bb,
               IRStmt_Dirty(
                  MACRO_unsafeIRDirty_1_N(lhsTmp, 0, cgDoSDivIfConcrete,
                     mkIRExprVec_4(
                        mkIRExpr_UInt(arg1Tmp),
                        arg1,
                        mkIRExpr_UInt(arg2Tmp),
                        arg2))));
         discStmt = 1;
#endif
         break;
      case Iop_DivU32:
      case Iop_DivS32:
      case Iop_DivU64:
      case Iop_DivS64:
      case Iop_DivModU128to64:
      case Iop_DivModS128to64:
         ASSERT_UNIMPLEMENTED(0);
         discStmt = 1;
         break;
      default:
         break;
      }
   } else {
      /* All inputs known, so no need to replace with non-faulting
       * versions of operations. */
   }

   /* ----- Now do the constraint generation instrumentation. ----- */

   d = unsafeIRDirty_0_N(0,
         "cgEmitTmpBinop",
         &cgEmitTmpBinop,
#if DEBUG
         mkIRExprVec_10(
#else
            mkIRExprVec_9(
#endif
               mkIRExpr_UInt(op), /* pushed last */
               mkIRExpr_UInt(lhsTmp),
               mkIRExpr_UInt(lhsTy),
               mkIRExpr_UInt(arg1Ty),
               mkIRExpr_UInt(arg1Tmp),
               mkIRExpr_UInt(arg2Ty),
               mkIRExpr_UInt(arg2Tmp),
               BT_ArgFixup(bb, arg1),
               BT_ArgFixup(bb, arg2)
#if DEBUG
               ,
               mkIRExpr_UInt(DEBUG_MAGIC)
#endif
               )
            );
   addStmtToIRSB(bb,IRStmt_Dirty(d)); 

   return (discStmt ? 0 : 1);
}
