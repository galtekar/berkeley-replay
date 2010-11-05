/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

#include "guest_generic_bb_to_IR.h"
#include "guest_x86_defs.h"

static const int wantsComments = 1;

struct CalcStruct {
   struct ArgStruct dep1; /* DEP1 */
   struct ArgStruct dep2; /* DEP2 */
   struct ArgStruct ndep; /* NDEP */

   UInt opVal, condVal;
};

typedef enum {FlagOp_CalcC, FlagOp_CalcAll, FlagOp_CalcCond} 
FlagOp;


/* XXX: BUG 36 */
#if 1
#define U_D1 (1 << 0) /* uses DEP1 */
#define U_D2 (1 << 1) /* uses DEP2 */
#define U_ND (1 << 2) /* uses NDEP */

/* Describes the arguments used in computing the flag value of a given 
 * operation. Used to determine if lhs should be tainted or not. Flags 
 * are O S Z A C P in that order. 
 *
 * To make this table, I looked at the corresponding macros in 
 * VEX/priv/guest_x86_helpers.c . Specifically, I looked at the args
 * involved in computing each flag. */
static int thunkUseA[X86G_CC_OP_NUMBER][6] = {
#define ADD_ARGS { \
      /* O */ U_D1 | U_D2, \
      /* S */ U_D1 | U_D2, \
      /* Z */ U_D1 | U_D2, \
      /* A */ U_D1 | U_D2, \
      /* C */ U_D1 | U_D2, \
      /* P */ U_D1 | U_D2 \
}
   [X86G_CC_OP_ADDB] = ADD_ARGS,
   [X86G_CC_OP_ADDW] = ADD_ARGS,
   [X86G_CC_OP_ADDL] = ADD_ARGS,
#define SUB_ARGS ADD_ARGS
   [X86G_CC_OP_SUBB] = SUB_ARGS,
   [X86G_CC_OP_SUBW] = SUB_ARGS,
   [X86G_CC_OP_SUBL] = SUB_ARGS,
#define ADC_ARGS { \
      /* O */ U_D1 | U_D2 | U_ND, \
      /* S */ U_D1 | U_D2 | U_ND, \
      /* Z */ U_D1 | U_D2 | U_ND, \
      /* A */ U_D1 | U_D2 | U_ND, \
      /* C */ U_D1 | U_D2 | U_ND, \
      /* P */ U_D1 | U_D2 | U_ND \
}
   [X86G_CC_OP_ADCB] = ADC_ARGS,
   [X86G_CC_OP_ADCW] = ADC_ARGS,
   [X86G_CC_OP_ADCL] = ADC_ARGS,
#define SBB_ARGS ADC_ARGS
   [X86G_CC_OP_SBBB] = SBB_ARGS,
   [X86G_CC_OP_SBBW] = SBB_ARGS,
   [X86G_CC_OP_SBBL] = SBB_ARGS,
#define LOGIC_ARGS { \
      /* O */ 0, \
      /* S */ U_D1, \
      /* Z */ U_D1, \
      /* A */ 0, \
      /* C */ 0, \
      /* P */ U_D1 \
}
   [X86G_CC_OP_LOGICB] = LOGIC_ARGS,
   [X86G_CC_OP_LOGICW] = LOGIC_ARGS,
   [X86G_CC_OP_LOGICL] = LOGIC_ARGS,
#define INC_ARGS { \
      /* O */ U_D1, \
      /* S */ U_D1, \
      /* Z */ U_D1, \
      /* A */ U_D1, \
      /* C */ U_ND, \
      /* P */ U_D1 \
}
   [X86G_CC_OP_INCB] = INC_ARGS,
   [X86G_CC_OP_INCW] = INC_ARGS,
   [X86G_CC_OP_INCL] = INC_ARGS,
#define DEC_ARGS INC_ARGS
   [X86G_CC_OP_DECB] = DEC_ARGS,
   [X86G_CC_OP_DECW] = DEC_ARGS,
   [X86G_CC_OP_DECL] = DEC_ARGS,
#define SHL_ARGS { \
      /* O */ U_D1 | U_D2, \
      /* S */ U_D1, \
      /* Z */ U_D1, \
      /* A */ 0, \
      /* C */ U_D2, \
      /* P */ U_D1 \
}
   [X86G_CC_OP_SHLB] = SHL_ARGS,
   [X86G_CC_OP_SHLW] = SHL_ARGS,
   [X86G_CC_OP_SHLL] = SHL_ARGS,
#define SHR_ARGS SHL_ARGS
   [X86G_CC_OP_SHRB] = SHR_ARGS,
   [X86G_CC_OP_SHRW] = SHR_ARGS,
   [X86G_CC_OP_SHRL] = SHR_ARGS,
#define ROL_ARGS { \
      /* O */ U_D1, \
      /* S */ U_ND, \
      /* Z */ U_ND, \
      /* A */ U_ND, \
      /* C */ U_D1, \
      /* P */ U_ND \
}
   [X86G_CC_OP_ROLB] = ROL_ARGS,
   [X86G_CC_OP_ROLW] = ROL_ARGS,
   [X86G_CC_OP_ROLL] = ROL_ARGS,
#define ROR_ARGS ROL_ARGS
   [X86G_CC_OP_RORB] = ROR_ARGS,
   [X86G_CC_OP_RORW] = ROR_ARGS,
   [X86G_CC_OP_RORL] = ROR_ARGS,
#define MUL_ARGS { \
      /* O */ U_D1 | U_D2, \
      /* S */ U_D1 | U_D2, \
      /* Z */ U_D1 | U_D2, \
      /* A */ 0, \
      /* C */ U_D1 | U_D2, \
      /* P */ U_D1 | U_D2 \
}
   [X86G_CC_OP_UMULB] = MUL_ARGS,
   [X86G_CC_OP_UMULW] = MUL_ARGS,
   [X86G_CC_OP_UMULL] = MUL_ARGS,
   [X86G_CC_OP_SMULB] = MUL_ARGS,
   [X86G_CC_OP_SMULW] = MUL_ARGS,
   [X86G_CC_OP_SMULL] = MUL_ARGS
};
#endif


/* Returns a bitmask of eflags fields used for a given operation */
static int
cgMaskFromCond(HWord condVal) 
{
   switch (condVal) {
   case X86CondNO:
   case X86CondO: /* OF == 1 */
      return X86G_CC_MASK_O;
      break;
   case X86CondNZ:
   case X86CondZ: /* ZF == 1 */
      return X86G_CC_MASK_Z;
      break;
   case X86CondNB:
   case X86CondB: /* CF == 1 */
      return X86G_CC_MASK_C;
      break;
   case X86CondNBE:
   case X86CondBE: /* (CF or ZF) == 1 */
      return (X86G_CC_MASK_C | X86G_CC_MASK_Z);
      break;
   case X86CondNS:
   case X86CondS: /* SF == 1 */
      return X86G_CC_MASK_S;
      break;
   case X86CondNP:
   case X86CondP: /* PF == 1 */
      return X86G_CC_MASK_P;
      break;
   case X86CondNL:
   case X86CondL: /* (SF xor OF) == 1 */
      return (X86G_CC_MASK_S | X86G_CC_MASK_O);
      break;
   case X86CondNLE:
   case X86CondLE: /* ((SF xor OF) or ZF)  == 1 */
      return (X86G_CC_MASK_S | X86G_CC_MASK_O | X86G_CC_MASK_Z);
      break;
   default:
      ASSERT_UNIMPLEMENTED_MSG(0, "unhandled condition: %d\n",
            condVal);
      return -1;
      break;
   }

   NOTREACHED();
}

/* parityTable[i] == 1 <===> i has even number of bits */
static const UChar parityTable[256] = {
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
};

static void
cgGenParityTable(const char *nameStr)
{
   int i;

   /* Ity_I32 and not Ity_I8 because we will assign this
    * to a Ity_I32 variable subsequently. */
   CG_NEW_ARRAY(8, Ity_I32, nameStr);

      for (i = 0; i < sizeof(parityTable); i++) {
         CG_ASSIGN(
               CG_ELEM(nameStr, CG_CONST(Ity_I8, i)),
               CG_CONST(Ity_I32, parityTable[i]));
      }
}

typedef enum {ParityKind_Res, ParityKind_Dep1} ParityKind;

static void
cgDoParityFlag(const ParityKind pk)
{
   /* PF -- This flag is unlikely to be used in modern software
    * (it's Intel legacy from the 8080 and used mostly in old drivers for
    * hardware that can't do hardware parity checking (e.g., old modems)), 
    * so you might thing that it probably isn't worth 
    * implementing. However, VEX IR does appear to make
    * use of it, for example when dumping the contents of
    * eflags. This happens with wget, for example. But
    * it's not clear that wget actually observes the
    * parity bit. */

   char nameStr[256];

   snprintf(nameStr, sizeof(nameStr), "ParTab%llu", 
         VA(parityCounter)++);

   /* Generate the partity array only on first use. */
   cgGenParityTable(nameStr);

   switch (pk) {
   case ParityKind_Res:
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("pf"),
            CG_ELEM(nameStr, 
               CG_CAST(Ity_I8, 
                  CG_LSCOPE("res"))));
      break;
   case ParityKind_Dep1:
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("pf"),
            CG_ELEM(nameStr, 
               CG_CAST(Ity_I8, 
                  CG_LSCOPE("dep1"))));
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

}

/* Number of right shifts required to move most-significant-bit 
 * of given type to the least-significant-bit. */
#define MSB_POS(ty) (IRTYPE2BITS(ty) - 1)

#define WANTS(f) (mask & X86G_CC_MASK_##f)

static void
cgCalculateConditionGenericAF()
{
   CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("af"),
         CG_AND(
            CG_SHR(Ity_I32,
               CG_XOR(
                  CG_XOR(
                     CG_LSCOPE("res"), 
                     CG_LSCOPE("argL")),
                  CG_LSCOPE("argR")),
               X86G_CC_SHIFT_A),
            CG_CONST(Ity_I32, 1))
         );
}

static void
cgCalculateConditionSetup_ADD_SUB(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask, 
      const int isAdd)
{
   /* AUX vars appear to be needed for all flags, so
    * were don't test the conditional. */

   CG_NEW_VAR(Ity_I32, CG_LSCOPE("argL"));
   CG_ASSIGN(CG_LSCOPE("argL"), CG_ARG_DEF(&cp->dep1));


   CG_NEW_VAR(Ity_I32, CG_LSCOPE("argR"));
   CG_ASSIGN(CG_LSCOPE("argR"), CG_ARG_DEF(&cp->dep2));

   if (isAdd) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("res"),
            CG_ADD(Ity_I32, CG_LSCOPE("argL"), 
               CG_LSCOPE("argR")));
   } else {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("res"),
            CG_SUB(Ity_I32, CG_LSCOPE("argL"), 
               CG_LSCOPE("argR")));
   }

   if (WANTS(C)) {
      if (isAdd) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"),
               CG_ITE(
                  CG_LT(CG_CAST(dataTy, CG_LSCOPE("res")), 
                     CG_CAST(dataTy, CG_LSCOPE("argL"))), 
                  CG_CONST(Ity_I32, 1), CG_CONST(Ity_I32, 0)
                  ));
      } else {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"),
               CG_ITE(
                  CG_LT(CG_CAST(dataTy, CG_LSCOPE("argL")), 
                     CG_CAST(dataTy, CG_LSCOPE("argR"))), 
                  CG_CONST(Ity_I32, 1), CG_CONST(Ity_I32, 0)
                  ));
      }
   }

   if (WANTS(P)) {
      cgDoParityFlag(ParityKind_Res);
   }

   if (WANTS(A)) {
      cgCalculateConditionGenericAF();
   }

   if (WANTS(Z)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("zf"),
            CG_ITE(
               CG_EQUAL(CG_LSCOPE("res"), CG_CONST(Ity_I32, 0)),
               CG_CONST(Ity_I32, 1),
               CG_CONST(Ity_I32, 0))
            );
   }

   if (WANTS(S)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("sf"),
            CG_AND(CG_SHR(Ity_I32, CG_LSCOPE("res"), 
                   MSB_POS(dataTy)),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(O)) {
      if (isAdd) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("of"),
               CG_AND(CG_SHR(Ity_I32,
                     CG_AND(
                        CG_XOR(
                           CG_XOR(CG_LSCOPE("argL"), 
                              CG_LSCOPE("argR")),
                           CG_CONST(Ity_I32, -1)),
                        CG_XOR(CG_LSCOPE("argL"), 
                           CG_LSCOPE("res"))),
                     MSB_POS(dataTy)), CG_CONST(Ity_I32, 1)));
      } else {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("of"),
               CG_AND(CG_SHR(Ity_I32,
                     CG_AND(
                        CG_XOR(CG_LSCOPE("argL"), 
                           CG_LSCOPE("argR")),
                        CG_XOR(CG_LSCOPE("argL"), 
                           CG_LSCOPE("res"))),
                     MSB_POS(dataTy)), CG_CONST(Ity_I32, 1)));
      }
   }
}

static void
cgCalculateCondition_ADD(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateConditionSetup_ADD_SUB(dataTy, cp, mask, 1);
}

static void
cgCalculateCondition_SUB(const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateConditionSetup_ADD_SUB(dataTy, cp, mask, 0);
}

static void
cgCalculateCondition_LOGIC(const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   if (WANTS(P) || WANTS(Z) || WANTS(S)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("dep1"), 
            CG_ARG_DEF(&cp->dep1));
   }

   if (WANTS(C)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"), 
            CG_CONST(Ity_I32, 0));
   }

   if (WANTS(P)) {
      cgDoParityFlag(ParityKind_Dep1);
   }

   if (WANTS(A)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("af"), 
            CG_CONST(Ity_I32, 0));
   }

   if (WANTS(Z)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("zf"),
            CG_ITE(
               CG_EQUAL(CG_LSCOPE("dep1"), 
                  CG_CONST(Ity_I32, 0)),
               CG_CONST(Ity_I32, 1),
               CG_CONST(Ity_I32, 0))
            );
   }

   if (WANTS(S)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("sf"),
            CG_AND(CG_SHR(Ity_I32, CG_LSCOPE("dep1"), 
                  MSB_POS(dataTy)),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(O)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("of"), 
            CG_CONST(Ity_I32, 0));
   }
}

static void
cgCalculateCondition_INC_DEC(const HWord dataTy, 
      const struct CalcStruct *cp,
      const uint mask, 
      const int isInc)
{

   if (WANTS(P) || WANTS(A) || WANTS(Z) || WANTS(S) || WANTS(O)) {
      CG_NEW_VAR(Ity_I32, CG_LSCOPE("res"));
      CG_ASSIGN(CG_LSCOPE("res"), CG_ARG_DEF(&cp->dep1));
   }

   if (WANTS(C)) {
      /* XXX: duplicate code--use helper function */
      CG_ASSIGN(CG_LSCOPE("ndep"), CG_ARG_DEF(&cp->ndep));
   }

   if (WANTS(C)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"),
            CG_AND(
               CG_SHR(Ity_I32, CG_LSCOPE("ndep"), 
                  X86G_CC_SHIFT_C),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(P)) {
      cgDoParityFlag(ParityKind_Res);
   }

   if (WANTS(A)) {
      if (isInc) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("argL"),
               CG_SUB(Ity_I32, CG_LSCOPE("res"), 
                  CG_CONST(Ity_I32, 1)));
      } else {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("argL"),
               CG_ADD(Ity_I32, CG_LSCOPE("res"), 
                  CG_CONST(Ity_I32, 1)));
      }

      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("argR"),
            CG_CONST(Ity_I32, 1));

      cgCalculateConditionGenericAF();
   }

   if (WANTS(Z)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("zf"),
            CG_ITE(
               CG_EQUAL(CG_LSCOPE("res"), CG_CONST(Ity_I32, 0)),
               CG_CONST(Ity_I32, 1),
               CG_CONST(Ity_I32, 0))
            );
   }

   if (WANTS(S)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("sf"),
            CG_AND(
               CG_SHR(Ity_I32, CG_LSCOPE("res"), 
                  MSB_POS(dataTy)),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(O)) {
      const ulong signMask = 1 << MSB_POS(dataTy);
      ulong ofMask;

      if (isInc) {
         ofMask = signMask;
      } else {
         ofMask = signMask - 1;
      }

      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("of"),
            CG_ITE(
               CG_EQUAL(CG_LSCOPE("res"), 
                  CG_CONST(Ity_I32, (ofMask))),
               CG_CONST(Ity_I32, 1), /* then */
               CG_CONST(Ity_I32, 0)  /* else */
               )); 
   }
}

static void
cgCalculateCondition_INC(const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateCondition_INC_DEC(dataTy, cp, mask, 1);
}

static void
cgCalculateCondition_DEC(const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateCondition_INC_DEC(dataTy, cp, mask, 0);
}

static void
cgCalculateConditionEmitDep1(const struct CalcStruct *cp, 
      const IRType dataTy)
{
   CG_NEW_VAR(Ity_I32, CG_LSCOPE("dep1"));
   CG_ASSIGN(CG_LSCOPE("dep1"), CG_ARG_DEF(&cp->dep1));
}

static void
cgCalculateConditionEmitDep2(const struct CalcStruct *cp, 
      const IRType dataTy)
{
   CG_NEW_VAR(Ity_I32, CG_LSCOPE("dep2"));
   CG_ASSIGN(CG_LSCOPE("dep2"), CG_ARG_DEF(&cp->dep2));
}

static void
cgCalculateConditionEmitDep12(const struct CalcStruct *cp, 
      const IRType dataTy)
{
   cgCalculateConditionEmitDep1(cp, dataTy);
   cgCalculateConditionEmitDep2(cp, dataTy);
}

static void
cgCalculateConditionEmitNDep(const struct CalcStruct *cp, 
      const IRType dataTy)
{
   CG_NEW_VAR(Ity_I32, CG_LSCOPE("ndep"));
   CG_ASSIGN(CG_LSCOPE("ndep"), CG_ARG_DEF(&cp->ndep));
}

static void
cgCalculateCondition_ADC_SBB(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask, 
      const int isAdc)
{
   /* AUX vars appear to be needed for all flags, so
    * were don't test the conditional. */

   cgCalculateConditionEmitDep12(cp, dataTy);
   cgCalculateConditionEmitNDep(cp, dataTy);

   CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("oldC"),
         CG_AND(
            CG_LSCOPE("ndep"), CG_CONST(Ity_I32, X86G_CC_MASK_C)));

   CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("argL"),
         CG_LSCOPE("dep1"));

   CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("argR"),
         CG_XOR(CG_LSCOPE("dep2"), 
            CG_LSCOPE("oldC")));

   if (isAdc) {
      if (WANTS(C) || WANTS(P) || WANTS(Z) || WANTS(S) || WANTS(O)) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("res"),
               CG_ADD(Ity_I32,
                  CG_ADD(Ity_I32,
                     CG_LSCOPE("argL"), 
                     CG_LSCOPE("argR")),
                  CG_LSCOPE("oldC")));
      }
   } else {
      if (WANTS(P) || WANTS(Z) || WANTS(S) || WANTS(O)) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("res"),
               CG_SUB(Ity_I32,
                  CG_SUB(Ity_I32,
                     CG_LSCOPE("argL"), 
                     CG_LSCOPE("argR")),
                  CG_LSCOPE("oldC")));
      }
   }

   if (WANTS(C)) {
      if (isAdc) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"),
               CG_ITE(
                  CG_EQUAL(CG_LSCOPE("oldC"), 
                     CG_CONST(Ity_I32, 0)),
                  CG_ITE(
                     CG_LT(CG_LSCOPE("res"), CG_LSCOPE("argL")),
                     CG_CONST(dataTy, 1),
                     CG_CONST(dataTy, 0)
                     ),
                  CG_ITE(
                     CG_LE(CG_LSCOPE("res"), CG_LSCOPE("argL")),
                     CG_CONST(dataTy, 1),
                     CG_CONST(dataTy, 0)
                     )
                  ));
      } else {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"),
               CG_ITE(
                  CG_EQUAL(CG_LSCOPE("oldC"), 
                     CG_CONST(Ity_I32, 0)),
                  CG_ITE(
                     CG_LT(CG_LSCOPE("argL"), CG_LSCOPE("argR")),
                     CG_CONST(dataTy, 1),
                     CG_CONST(dataTy, 0)
                     ),
                  CG_ITE(
                     CG_LE(CG_LSCOPE("argL"), CG_LSCOPE("argR")),
                     CG_CONST(dataTy, 1),
                     CG_CONST(dataTy, 0)
                     )
                  ));
      }
   }

   if (WANTS(P)) {
      cgDoParityFlag(ParityKind_Res);
   }

   if (WANTS(A)) {
      cgCalculateConditionGenericAF();
   }

   if (WANTS(Z)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("zf"),
            CG_ITE(
               CG_EQUAL(CG_LSCOPE("res"), CG_CONST(Ity_I32, 0)),
               CG_CONST(Ity_I32, 1),
               CG_CONST(Ity_I32, 0))
            );
   }

   if (WANTS(S)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("sf"),
            CG_AND(
               CG_SHR(Ity_I32, CG_LSCOPE("res"), 
                  MSB_POS(dataTy)),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(O)) {
      if (isAdc) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("of"),
               CG_AND(CG_SHR(Ity_I32,
                     CG_AND(
                        CG_XOR(
                           CG_XOR(CG_LSCOPE("argL"), 
                              CG_LSCOPE("argR")),
                           CG_CONST(Ity_I32, -1)),
                        CG_XOR(CG_LSCOPE("argL"), 
                           CG_LSCOPE("res"))),
                     MSB_POS(dataTy)), CG_CONST(Ity_I32, 1)));
      } else {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("of"),
               CG_AND(CG_SHR(Ity_I32,
                     CG_AND(
                        CG_XOR(CG_LSCOPE("argL"),
                           CG_LSCOPE("argR")),
                        CG_XOR(CG_LSCOPE("argL"),
                           CG_LSCOPE("res"))),
                     MSB_POS(dataTy)), CG_CONST(Ity_I32, 1)));
      }
   }
}

static void
cgCalculateCondition_ADC(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateCondition_ADC_SBB(dataTy, cp, mask, 1);
}

static void
cgCalculateCondition_SBB(const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateCondition_ADC_SBB(dataTy, cp, mask, 0);
}

static void
cgCalculateCondition_SHL_SHR(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask, 
      const int isShl)
{
   if (WANTS(P) || WANTS(Z) || WANTS(S) || WANTS(O)) {
      cgCalculateConditionEmitDep1(cp, dataTy);
   }
   if (WANTS(C) || WANTS(O)) {
      cgCalculateConditionEmitDep2(cp, dataTy);
   }

   if (WANTS(C)) {
      if (isShl) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"),
               CG_AND(
                  CG_SHR(Ity_I32, CG_LSCOPE("dep2"), 
                     MSB_POS(dataTy)),
                  CG_CONST(Ity_I32, 1)));
      } else {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"),
               CG_AND(CG_LSCOPE("dep2"),
                  CG_CONST(Ity_I32, 1)));
      }
   }

   if (WANTS(P)) {
      cgDoParityFlag(ParityKind_Dep1);
   }

   if (WANTS(A)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("af"),
            CG_CONST(Ity_I32, 0));
   }

   if (WANTS(Z)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("zf"),
            CG_ITE(
               CG_EQUAL(CG_LSCOPE("dep1"), CG_CONST(Ity_I32, 0)),
               CG_CONST(Ity_I32, 1),
               CG_CONST(Ity_I32, 0))
            );
   }

   if (WANTS(S)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("sf"),
            CG_AND(
               CG_SHR(Ity_I32, CG_LSCOPE("dep1"), 
                  MSB_POS(dataTy)),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(O)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("of"),
            CG_AND(
               CG_SHR(Ity_I32,
                  CG_XOR(
                     CG_LSCOPE("dep2"), 
                     CG_LSCOPE("dep1")),
                  MSB_POS(dataTy)), 
               CG_CONST(Ity_I32, 1)));
   }
}

static void
cgCalculateCondition_SHL(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateCondition_SHL_SHR(dataTy, cp, mask, 1);
}

static void
cgCalculateCondition_SHR(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateCondition_SHL_SHR(dataTy, cp, mask, 0);
}

static void
cgCalculateCondition_ROL_ROR(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask, 
      const int isRol)
{
   /* XXX: Use thunkUseA to determine whether to generate or
    * not. */
   if (WANTS(C) || WANTS(O)) {
      cgCalculateConditionEmitDep1(cp, dataTy);
   }

   if (WANTS(P) || WANTS(A) || WANTS(Z) || WANTS(S)) {
      cgCalculateConditionEmitNDep(cp, dataTy);
   }

   if (WANTS(C)) {
      if (isRol) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"),
               CG_AND(CG_LSCOPE("dep1"),
                  CG_CONST(Ity_I32, 1)));
      } else {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("cf"),
               CG_AND(
                  CG_SHR(Ity_I32, CG_LSCOPE("dep1"), 
                     MSB_POS(dataTy)),
                  CG_CONST(Ity_I32, 1)));
      }
   }

   if (WANTS(P)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("pf"),
            CG_AND(
               CG_SHR(Ity_I32, CG_LSCOPE("ndep"), 
                  X86G_CC_SHIFT_P),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(A)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("af"),
            CG_AND(
               CG_SHR(Ity_I32, CG_LSCOPE("ndep"), 
                  X86G_CC_SHIFT_A),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(Z)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("zf"),
            CG_AND(
               CG_SHR(Ity_I32, CG_LSCOPE("ndep"), 
                  X86G_CC_SHIFT_Z),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(S)) {
      CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("sf"),
            CG_AND(
               CG_SHR(Ity_I32, CG_LSCOPE("ndep"), 
                  X86G_CC_SHIFT_S),
               CG_CONST(Ity_I32, 1)));
   }

   if (WANTS(O)) {
      if (isRol) {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("of"),
               CG_XOR(
                  CG_AND(
                     CG_SHR(Ity_I32, CG_LSCOPE("dep1"), 
                        MSB_POS(dataTy)),
                     CG_CONST(Ity_I32, 1)),

                  CG_AND(CG_LSCOPE("dep1"),
                     CG_CONST(Ity_I32, 1)))
               );
      } else {
         CG_NEW_VAR_INIT(Ity_I32, CG_LSCOPE("of"),
               CG_XOR(
                  CG_AND(
                     CG_SHR(Ity_I32, CG_LSCOPE("dep1"), 
                        MSB_POS(dataTy)),
                     CG_CONST(Ity_I32, 1)),

                  CG_AND(
                     CG_SHR(Ity_I32, CG_LSCOPE("dep1"), 
                        MSB_POS(dataTy)-1),
                     CG_CONST(Ity_I32, 1)))
               );
      }
   }
}

static void
cgCalculateCondition_ROL(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateCondition_ROL_ROR(dataTy, cp, mask, 1);
}

static void
cgCalculateCondition_ROR(
      const HWord dataTy, 
      const struct CalcStruct *cp, 
      const uint mask)
{
   cgCalculateCondition_ROL_ROR(dataTy, cp, mask, 0);
}


/* @mask is a bitmask of eflags fields for which we should generate
 * constraints (most operations use only a subset of the fields). */
static void
cgEmitCalculateEflagsWork(const struct CalcStruct *cp, 
      uint mask)
{
   /* Each call to a flag computation function will require a new set of
    * constraint variables. For example, the AF flag for this call should
    * not be confused with the AF flag for a previous call. For this reason,
    * we start a new scope, which is simply a number postfixed to each
    * variable name to bind it to a particular invocation of this
    * function. */
   CG_NEW_LOCAL_SCOPE();

#define WORK(kind, ty) \
   cgCalculateCondition_##kind(ty, cp, mask)
   switch (cp->opVal) {
   case X86G_CC_OP_ADDB:
      WORK(ADD, Ity_I8);
      break;
   case X86G_CC_OP_ADDW:
      WORK(ADD, Ity_I16);
      break;
   case X86G_CC_OP_ADDL:
      WORK(ADD, Ity_I32);
      break;
   case X86G_CC_OP_SUBB:
      WORK(SUB, Ity_I8);
      break;
   case X86G_CC_OP_SUBW:
      WORK(SUB, Ity_I16);
      break;
   case X86G_CC_OP_SUBL:
      WORK(SUB, Ity_I32);
      break;
   case X86G_CC_OP_ADCB:
      WORK(ADC, Ity_I8);
      break;
   case X86G_CC_OP_ADCW:
      WORK(ADC, Ity_I16);
      break;
   case X86G_CC_OP_ADCL:
      WORK(ADC, Ity_I32);
      break;
   case X86G_CC_OP_SBBB:
      WORK(SBB, Ity_I8);
      break;
   case X86G_CC_OP_SBBW:
      WORK(SBB, Ity_I16);
      break;
   case X86G_CC_OP_SBBL:
      WORK(SBB, Ity_I32);
      break;
   case X86G_CC_OP_LOGICB:
      WORK(LOGIC, Ity_I8);
      break;
   case X86G_CC_OP_LOGICW:
      WORK(LOGIC, Ity_I16);
      break;
   case X86G_CC_OP_LOGICL:
      WORK(LOGIC, Ity_I32);
      break;
   case X86G_CC_OP_INCB:
      WORK(INC, Ity_I8);
      break;
   case X86G_CC_OP_INCW:
      WORK(INC, Ity_I16);
      break;
   case X86G_CC_OP_INCL:
      WORK(INC, Ity_I32);
      break;
   case X86G_CC_OP_DECB:
      WORK(DEC, Ity_I8);
      break;
   case X86G_CC_OP_DECW:
      WORK(DEC, Ity_I16);
      break;
   case X86G_CC_OP_DECL:
      WORK(DEC, Ity_I32);
      break;
   case X86G_CC_OP_SHLB:
      WORK(SHL, Ity_I8);
      break;
   case X86G_CC_OP_SHLW:
      WORK(SHL, Ity_I16);
      break;
   case X86G_CC_OP_SHLL:
      WORK(SHL, Ity_I32);
      break;
   case X86G_CC_OP_SHRB:
      WORK(SHR, Ity_I8);
      break;
   case X86G_CC_OP_SHRW:
      WORK(SHR, Ity_I16);
      break;
   case X86G_CC_OP_SHRL:
      WORK(SHR, Ity_I32);
      break;
   case X86G_CC_OP_ROLB:
      WORK(ROL, Ity_I8);
      break;
   case X86G_CC_OP_ROLW:
      WORK(ROL, Ity_I16);
      break;
   case X86G_CC_OP_ROLL:
      WORK(ROL, Ity_I32);
      break;
   case X86G_CC_OP_RORB:
      WORK(ROR, Ity_I8);
      break;
   case X86G_CC_OP_RORW:
      WORK(ROR, Ity_I16);
      break;
   case X86G_CC_OP_RORL:
      WORK(ROR, Ity_I32);
      break;
   default:
      ASSERT_UNIMPLEMENTED_MSG(0, 
            "Unhandled opVal=%d\n", cp->opVal);
      break;
   }
}

static void
cgEmitFlagsCalcCond(const HWord lhsTmp, 
      const struct CalcStruct *cP, const uint mask)
{
   const HWord inv = cP->condVal & 1;

   ASSERT(inv == 0 || inv == 1);

   CG_COMMENT("CalcCond: op=0x%x cond=0x%x inv=0x%x\n", cP->opVal,
         cP->condVal, inv);


   cgEmitCalculateEflagsWork(cP, mask);

#define CG_SET_GUARD(pred) \
   cg_DeclareTmp(lhsTmp, Ity_I32); \
   if (inv) { \
      CG_ASSIGN(CG_TMP(lhsTmp), CG_XOR(CG_CONST(Ity_I32, inv), pred)) \
   } else { \
      CG_ASSIGN(CG_TMP(lhsTmp), pred) \
   } \

/* XXX: don't emit the XOR if inv is 0 */
#define CG_SET_RESULT(flagStr) \
      CG_SET_GUARD(CG_LSCOPE(flagStr))

   /* We assume that condVal is never symbolic. It is always a constant
    * as far I can tell by looking at the IR. This means
    * we needn't generate any ITE constraint for it. */
   switch (cP->condVal) {
   case X86CondNO:
   case X86CondO: /* OF == 1 */
      CG_SET_RESULT("of");
      break;
   case X86CondNZ:
   case X86CondZ: /* ZF == 1 */
      CG_SET_RESULT("zf");
      break;
   case X86CondNB:
   case X86CondB: /* CF == 1 */
      CG_SET_RESULT("cf");
      break;
   case X86CondNBE:
   case X86CondBE: /* (CF or ZF) == 1 */
      CG_SET_GUARD(CG_OR(CG_LSCOPE("cf"), CG_LSCOPE("zf")));
      break;
   case X86CondNS:
   case X86CondS: /* SF == 1 */
      CG_SET_RESULT("sf");
      break;
   case X86CondNP:
   case X86CondP: /* PF == 1 */
      CG_SET_RESULT("pf");
      break;
   case X86CondNL:
   case X86CondL: /* (SF xor OF) == 1 */
      CG_SET_GUARD(CG_XOR(CG_LSCOPE("sf"), CG_LSCOPE("of")));
      break;
   case X86CondNLE:
   case X86CondLE: /* ((SF xor OF) or ZF)  == 1 */
      CG_SET_GUARD(
               CG_OR(CG_XOR(CG_LSCOPE("sf"), CG_LSCOPE("of")),
                  CG_LSCOPE("zf")));
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }
}

static void
cgEmitFlagsCalcC(const HWord lhsTmp, const struct CalcStruct *cP,
      const uint mask)
{
   cgEmitCalculateEflagsWork(cP, mask);

   CG_NEW_TMP_INIT(Ity_I32, lhsTmp, 
         CG_CAST(Ity_I32, CG_SHL(Ity_I32, CG_LSCOPE("cf"), 
               X86G_CC_SHIFT_C)));
}

static void
cgEmitFlagsCalcAll(const HWord lhsTmp, const struct CalcStruct *cP,
      const uint mask)
{
   cgEmitCalculateEflagsWork(cP, mask);

   CG_NEW_TMP_INIT(Ity_I32, lhsTmp, 
         CG_CAST(Ity_I32, 
            CG_OR(CG_SHL(Ity_I32, CG_LSCOPE("of"), 
                  X86G_CC_SHIFT_O),
               CG_OR(CG_SHL(Ity_I32, CG_LSCOPE("sf"),
                  X86G_CC_SHIFT_S),
                  CG_OR(CG_SHL(Ity_I32, CG_LSCOPE("zf"),
                     X86G_CC_SHIFT_Z),
                     CG_OR(CG_SHL(Ity_I32, CG_LSCOPE("af"),
                        X86G_CC_SHIFT_A),
                        CG_OR(CG_SHL(Ity_I32, CG_LSCOPE("cf"),
                           X86G_CC_SHIFT_C),
                           CG_SHL(Ity_I32, CG_LSCOPE("pf"),
                              X86G_CC_SHIFT_P))))))));
}

static void
cgEmitFlags(
      UInt flagOp,
      UInt lhsTmp, UInt lhsTy, UInt dep1Tmp, UInt dep2Tmp, 
      UInt ndepTmp, UInt condVal, UInt opVal, HWord dep1Val, 
      HWord dep2Val, HWord ndepVal, IRType depTy)
{
#define NUM_ARGS 3
   TCode isArgTaintedA[NUM_ARGS] = { TCode_TmpUntainted };
   uint mask;

   switch (flagOp) {
   case FlagOp_CalcC:
      mask = X86G_CC_MASK_C;
      break;
   case FlagOp_CalcAll:
      mask = (X86G_CC_MASK_O | X86G_CC_MASK_S | 
            X86G_CC_MASK_Z | X86G_CC_MASK_A | X86G_CC_MASK_C | 
            X86G_CC_MASK_P);
      break;
   case FlagOp_CalcCond:
      mask = cgMaskFromCond(condVal);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   int i;

   ASSERT(opVal < X86G_CC_OP_NUMBER);
  
#define NUM_FLAGS  6
   int flagMaskA[NUM_FLAGS] = { X86G_CC_MASK_O, X86G_CC_MASK_S, 
      X86G_CC_MASK_Z, X86G_CC_MASK_A, X86G_CC_MASK_C,
      X86G_CC_MASK_P };

   for (i = 0; i < NUM_FLAGS; i++) {
      if (mask & flagMaskA[i]) {
         const int argMask = thunkUseA[opVal][i];
         const int tmpA[NUM_ARGS] = { dep1Tmp, dep2Tmp, ndepTmp };
         const int useA[NUM_ARGS] = { U_D1, U_D2, U_ND };
         int j;

         for (j = 0; j < NUM_ARGS; j++) {
            if (argMask & useA[j]) {
               TCode tc = cg_IsArgTainted(tmpA[j]);
               if (isArgTaintedA[j] == TCode_TmpUndefined ||
                     tc == TCode_TmpUndefined) {
                  isArgTaintedA[j] = TCode_TmpUndefined;
               } else if (isArgTaintedA[j] == TCode_TmpDefined ||
                     tc == TCode_TmpDefined) {
                  isArgTaintedA[j] = TCode_TmpDefined;
               }
            }
         }
      }
   }

   if (cg_PropagateOpTaint(lhsTmp, lhsTy, isArgTaintedA, NUM_ARGS)) {
      return;
   }

   cgProf_UpdateCounter();

   if (cg_OptOutputFormula) {
      struct CalcStruct calc;
      calc.opVal = opVal;
      calc.condVal = condVal;
      /* All deps are assumed to have the same type. */
      cg_MkArg(&calc.dep1, depTy, dep1Tmp, dep1Val);
      cg_MkArg(&calc.dep2, depTy, dep2Tmp, dep2Val);
      cg_MkArg(&calc.ndep, depTy, ndepTmp, ndepVal);

      switch (flagOp) {
      case FlagOp_CalcC:
         cgEmitFlagsCalcC(lhsTmp, &calc, mask);
         break;
      case FlagOp_CalcAll:
         cgEmitFlagsCalcAll(lhsTmp, &calc, mask);
         break;
      case FlagOp_CalcCond:
         cgEmitFlagsCalcCond(lhsTmp, &calc, mask);
         break;
      default:
         ASSERT_UNIMPLEMENTED(0);
         break;
      }
   }
}

static void
cgInstrCalcFlagsWork(IRSB *bb, const IRStmt *s, const FlagOp flagOp)
{
   HWord lhsTmp = s->Ist.WrTmp.tmp;
   IRExpr * call = s->Ist.WrTmp.data;
   IRExpr ** cargs = call->Iex.CCall.args;
   IRType lhsTy = typeOfIRTemp(bb->tyenv, lhsTmp), depTy;
   IRDirty * d; 

   ASSERT(call->tag == Iex_CCall); 
   ASSERT(cargs[0]); /* cc_op */
   ASSERT(cargs[1]); /* cc_dep1 */
   ASSERT(cargs[2]); /* cc_dep2 */
   ASSERT(cargs[3]); /* cc_ndep */
   ASSERT(cargs[0]->tag == Iex_RdTmp || cargs[0]->tag == Iex_Const);
   ASSERT(cargs[1]->tag == Iex_RdTmp || cargs[1]->tag == Iex_Const);
   ASSERT(cargs[2]->tag == Iex_RdTmp || cargs[2]->tag == Iex_Const);
   ASSERT(cargs[3]->tag == Iex_RdTmp || cargs[3]->tag == Iex_Const);

   ASSERT(typeOfIRExpr(bb->tyenv, cargs[1]) == 
         typeOfIRExpr(bb->tyenv, cargs[2]));
   ASSERT(typeOfIRExpr(bb->tyenv, cargs[1]) == 
         typeOfIRExpr(bb->tyenv, cargs[3]));

   depTy = typeOfIRExpr(bb->tyenv, cargs[1]);
   ASSERT(sizeofIRExpr(bb->tyenv, cargs[0]) == sizeof(UInt));
   ASSERT(sizeofIRExpr(bb->tyenv, cargs[1]) == sizeof(HWord));


   /* XXX: verify that cc_op is never tainted. */

   d = unsafeIRDirty_0_N(0,
         "cgEmitFlags",
         &cgEmitFlags,
         mkIRExprVec_12(
            mkIRExpr_UInt(flagOp),
            mkIRExpr_UInt(lhsTmp),
            mkIRExpr_UInt(lhsTy),
            mkIRExpr_UInt(cg_GetTempOrConst(cargs[1])),
            mkIRExpr_UInt(cg_GetTempOrConst(cargs[2])),
            mkIRExpr_UInt(cg_GetTempOrConst(cargs[3])),
            mkIRExpr_UInt(0),
            cargs[0],
            cargs[1],
            cargs[2],
            cargs[3],
            mkIRExpr_HWord(depTy)
            )
         );   

   addStmtToIRSB(bb, IRStmt_Dirty(d)); 
}

static void
cgInstrCalcFlagsC(IRSB *bb, const IRStmt *s)
{
   cgInstrCalcFlagsWork(bb, s, FlagOp_CalcC);
}

static void
cgInstrCalcFlagsAll(IRSB *bb, const IRStmt *s)
{
   cgInstrCalcFlagsWork(bb, s, FlagOp_CalcAll);
}

static void
cgInstrCalcCond(IRSB *bb, const IRStmt *s)
{
   UInt lhsTmp = s->Ist.WrTmp.tmp;
   IRExpr * call = s->Ist.WrTmp.data;
   IRExpr ** cargs = call->Iex.CCall.args;
   IRType lhsTy = typeOfIRTemp(bb->tyenv, lhsTmp), depTy;
   IRDirty * d; 

   ASSERT(lhsTmp != -1);

   ASSERT(cargs[0]); /* cond */
   ASSERT(cargs[1]); /* cc_op */
   ASSERT(cargs[2]); /* cc_dep1 */
   ASSERT(cargs[3]); /* cc_dep2 */
   ASSERT(cargs[4]); /* cc_ndep */

   ASSERT(cargs[0]->tag == Iex_Const);
   ASSERT(cargs[1]->tag == Iex_RdTmp || cargs[1]->tag == Iex_Const);
   ASSERT(cargs[2]->tag == Iex_RdTmp || cargs[2]->tag == Iex_Const);
   ASSERT(cargs[3]->tag == Iex_RdTmp || cargs[3]->tag == Iex_Const);
   ASSERT(cargs[4]->tag == Iex_RdTmp || cargs[4]->tag == Iex_Const);
  
   ASSERT(typeOfIRExpr(bb->tyenv, cargs[0]) ==
          typeOfIRExpr(bb->tyenv, cargs[1]));
   ASSERT(sizeofIRExpr(bb->tyenv, cargs[0]) == sizeof(UInt));
   ASSERT(typeOfIRExpr(bb->tyenv, cargs[2]) == 
         typeOfIRExpr(bb->tyenv, cargs[3]));
   ASSERT(typeOfIRExpr(bb->tyenv, cargs[2]) == 
         typeOfIRExpr(bb->tyenv, cargs[4]));
   ASSERT(sizeofIRExpr(bb->tyenv, cargs[2]) == sizeof(HWord));

   depTy = typeOfIRExpr(bb->tyenv, cargs[2]);
   ASSERT(depTy == Ity_I32);


   /* XXX: need to verify that cc_op is never tainted. */

   d = unsafeIRDirty_0_N(0,
         "cgEmitFlags",
         &cgEmitFlags,
         mkIRExprVec_12(
            mkIRExpr_UInt(FlagOp_CalcCond),
            mkIRExpr_UInt(lhsTmp),
            mkIRExpr_UInt(lhsTy),
            mkIRExpr_UInt(cg_GetTempOrConst(cargs[2])),
            mkIRExpr_UInt(cg_GetTempOrConst(cargs[3])),
            mkIRExpr_UInt(cg_GetTempOrConst(cargs[4])),
            cargs[0],
            cargs[1],
            cargs[2],
            cargs[3],
            cargs[4],
            mkIRExpr_UInt(depTy)
            )
         );

   addStmtToIRSB(bb, IRStmt_Dirty(d)); 
}

/*
 * Propagate taint, generate constraints for x86g_use_seg_selector, which
 * translates from 'virtual' to 'linear' addresses. 
 *
 * If the segment selector or the offset into the segment is
 * tainted, then we conseratively assume that the resulting 'linear'
 * address may be anything. 
 */
static void
cgEmitUseSegSelector(
      const IRTemp lhsTmp,
      const IRTemp ldtTmp,
      const IRTemp gdtTmp,
      const IRTemp segSelTmp,
      const IRTemp offsetTmp)
{
   /* The guest LDT and GDT pointers are changed only via syscalls
    * (e.g., sys_set_thread_area), and they should play out the same
    * value during replay, so there is no need to taint them, ever. */
   ASSERT(!cg_IsArgTainted(ldtTmp));
   ASSERT(!cg_IsArgTainted(gdtTmp));

#define NUM_ARGS_SEG_SEL 2
   TCode isArgTaintedA[NUM_ARGS_SEG_SEL];

   isArgTaintedA[0] = cg_IsArgTainted(segSelTmp);
   isArgTaintedA[1] = cg_IsArgTainted(offsetTmp);

   if (cg_PropagateOpTaint(lhsTmp, Ity_I64, isArgTaintedA, NUM_ARGS_SEG_SEL)) {
      return;
   }

   cg_DeclareTmp(lhsTmp, Ity_I64);

#if PRODUCT 
#error "XXX: how should we constrain lhsTmp?"
#endif
}

static void
cgInstrUseSegSelector(IRSB *bb, const IRStmt *s)
{
   IRTemp lhsTmp = s->Ist.WrTmp.tmp;
   IRExpr * call = s->Ist.WrTmp.data;
   IRExpr ** cargs = call->Iex.CCall.args;

#if DEBUG
   ASSERT(cargs[0]); /* ldt */
   ASSERT(cargs[1]); /* gdt */
   ASSERT(cargs[2]); /* seg_selector */
   ASSERT(cargs[3]); /* virtual_addr */
   ASSERT(cargs[0]->tag == Iex_RdTmp || cargs[0]->tag == Iex_Const);
   ASSERT(cargs[1]->tag == Iex_RdTmp || cargs[1]->tag == Iex_Const);
   ASSERT(cargs[2]->tag == Iex_RdTmp || cargs[2]->tag == Iex_Const);
   ASSERT(cargs[3]->tag == Iex_RdTmp || cargs[3]->tag == Iex_Const);
   IRType lhsTy = typeOfIRTemp(bb->tyenv, lhsTmp);
   ASSERT(lhsTy == Ity_I64);
#endif

   IRTemp ldtTmp = cg_GetTempOrConst(cargs[0]);
   IRTemp gdtTmp = cg_GetTempOrConst(cargs[1]);
   IRTemp segSelTmp = cg_GetTempOrConst(cargs[2]);
   IRTemp virtAddrTmp = cg_GetTempOrConst(cargs[3]);
   
   ASSERT(sizeof(IRTemp) == sizeof(UInt));
   addStmtToIRSB(bb, 
         IRStmt_Dirty(
            MACRO_unsafeIRDirty_0_N(0,
               cgEmitUseSegSelector,
               mkIRExprVec_5(
                  mkIRExpr_UInt(lhsTmp),
                  mkIRExpr_UInt(ldtTmp),
                  mkIRExpr_UInt(gdtTmp),
                  mkIRExpr_UInt(segSelTmp),
                  mkIRExpr_UInt(virtAddrTmp)
                  )
               )));   
}

static void
cgEmitCreateFPUCW(UInt lhsTmp, IRType lhsTy, UInt argTmp)
{
   int res;

   res = cg_IsArgTainted(argTmp);

   if (res) {
      /* Allow it be 'anything' for now.
       *
       * XXX: constrain it more precisely once we truly understand 
       * VEX floating-point. */
      cg_DeclareTmp(lhsTmp, lhsTy);
   } else {
      TaintMap_UntaintTmp(lhsTmp);
   }
}

static void
cgInstrCreateFPUCW(IRSB *bb, const IRStmt *s)
{
   IRTemp lhsTmp = s->Ist.WrTmp.tmp;
   IRType lhsTy = typeOfIRExpr(bb->tyenv, s->Ist.WrTmp.data);
   IRExpr * callP = s->Ist.WrTmp.data;
   IRExpr ** cArgA = callP->Iex.CCall.args;
   IRDirty *d;

   ASSERT(cArgA[0]->tag == Iex_RdTmp);

   d = unsafeIRDirty_0_N(0,
         "cgEmitCreateFPUCW",
         &cgEmitCreateFPUCW,
         mkIRExprVec_3(
            mkIRExpr_UInt(lhsTmp),
            mkIRExpr_UInt(lhsTy),
            mkIRExpr_UInt(cg_GetTempOrConst(cArgA[0]))
            )
         );

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}

static void
cgEmitCheckFLDCW(UInt lhsTmp, IRType lhsTy, UInt argTmp)
{
   int res;

   // XXX: use the PropagateOpTaint fn
   //if (cg_PropagateOpTaint(lhsTmp, lhsTy, isArgTaintedA, NUM_ARGS_SEG_SEL)) {
   res = cg_IsArgTainted(argTmp);

   if (res) {
      /* Allow it be 'anything' for now.
       *
       * XXX: constrain it more precisely once we truly understand 
       * VEX floating-point. */
      cg_DeclareTmp(lhsTmp, lhsTy);
   } else {
      TaintMap_UntaintTmp(lhsTmp);
   }
}

static void
cgInstrCheckFLDCW(IRSB *bb, const IRStmt *s)
{
   IRTemp lhsTmp = s->Ist.WrTmp.tmp;
   IRType lhsTy = typeOfIRExpr(bb->tyenv, s->Ist.WrTmp.data);
   IRExpr * callP = s->Ist.WrTmp.data;
   IRExpr ** cArgA = callP->Iex.CCall.args;
   IRDirty *d;

   d = MACRO_unsafeIRDirty_0_N(0,
         cgEmitCheckFLDCW,
         mkIRExprVec_3(
            mkIRExpr_UInt(lhsTmp),
            mkIRExpr_UInt(lhsTy),
            mkIRExpr_UInt(cg_GetTempOrConst(cArgA[0]))
            )
         );

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}

static void
cgEmitCalcFXAM(const IRTemp lhsTmp, const IRType lhsTy, const IRTemp arg1Tmp, 
               const IRTemp arg2Tmp)
{
#define NUM_ARGS_SEG_SEL 2
   TCode isArgTaintedA[NUM_ARGS_SEG_SEL];

   isArgTaintedA[0] = cg_IsArgTainted(arg1Tmp);
   isArgTaintedA[1] = cg_IsArgTainted(arg2Tmp);

   if (cg_PropagateOpTaint(lhsTmp, lhsTy, isArgTaintedA, NUM_ARGS_SEG_SEL)) {
      return;
   }

   /* Allow it be 'anything' for now.
    *
    * XXX: constrain it more precisely once we truly understand 
    * VEX floating-point. */
   cg_DeclareTmp(lhsTmp, lhsTy);
}


static void
cgInstrCalcFXAM(IRSB *bb, const IRStmt *s)
{
   IRTemp lhsTmp = s->Ist.WrTmp.tmp;
   IRType lhsTy = typeOfIRExpr(bb->tyenv, s->Ist.WrTmp.data);
   IRExpr * callP = s->Ist.WrTmp.data;
   IRExpr ** cArgA = callP->Iex.CCall.args;
   IRDirty *d;

   d = MACRO_unsafeIRDirty_0_N(0,
         cgEmitCalcFXAM,
         mkIRExprVec_4(
            mkIRExpr_UInt(lhsTmp),
            mkIRExpr_UInt(lhsTy),
            mkIRExpr_UInt(cg_GetTempOrConst(cArgA[0])),
            mkIRExpr_UInt(cg_GetTempOrConst(cArgA[1]))
            )
         );

   addStmtToIRSB(bb, IRStmt_Dirty(d));
}


/* ---------- Instrumentation selector ---------- */

static const struct InstrCall handledCCallA[] = {
   { .name = "x86g_calculate_condition", .fn = cgInstrCalcCond },
   { .name = "x86g_calculate_eflags_c", .fn = cgInstrCalcFlagsC },
   { .name = "x86g_calculate_eflags_all", .fn = cgInstrCalcFlagsAll },
   { .name = "x86g_use_seg_selector", .fn = cgInstrUseSegSelector },
   { .name = "x86g_create_fpucw", .fn = cgInstrCreateFPUCW },
   { .name = "x86g_check_fldcw", .fn = cgInstrCheckFLDCW },
   { .name = "x86g_calculate_FXAM", .fn = cgInstrCalcFXAM },
   { .name = "", .fn = NULL }
};

void 
cg_InstrTmpCCall(IRSB * bb, const IRStmt * s)
{
   IRExpr * callP = s->Ist.WrTmp.data;
   IRCallee * calleeP = callP->Iex.CCall.cee;

   ASSERT(callP->tag == Iex_CCall); 

   const struct InstrCall *cP = handledCCallA;

   while (cP->fn) {
      ASSERT(strlen(cP->name));
      if (strncmp(calleeP->name, cP->name, 
               strlen(cP->name)) == 0) {
         cP->fn(bb, s);
         return;
      }

      cP++;
   }

   ASSERT_UNIMPLEMENTED_MSG(0, "Unhandled CCall: %s\n",
         calleeP->name);
}
