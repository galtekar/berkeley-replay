#include "vkernel/public.h"
#include "private.h"

/* ------------ Taint propagation helpers ------------- */
 
static INLINE int
cgIsArgUndefined(const TCode *argA, const int numArgs)
{
   int i, res = 0;

   for (i = 0; i < numArgs; i++) {
      DEBUG_ONLY(TaintMap_VerifyTCode(argA[i]););
      res |= (argA[i] == TCode_TmpUndefined);
   }

   return res;
}

static INLINE int
cgIsArgTainted(const TCode *argA, const int numArgs)
{
   int i, res = 0;

   for (i = 0; i < numArgs; i++) {
      DEBUG_ONLY(TaintMap_VerifyTCode(argA[i]););
      res |= argA[i];
   }

   return res;
}

/* Returns 1 iff: no args are tainted or at least one
 * arg is undefined. */
int
cg_PropagateOpTaint(const IRTemp lhsTmp, const IRType lhsTy, 
      const TCode *argA, const int numArgs) 
{
   if (!cgIsArgTainted(argA, numArgs)) {
      TaintMap_UntaintTmp(lhsTmp);
      return 1;
   }

   if (cgShouldSkipCgen(lhsTy) ||
       cgIsArgUndefined(argA, numArgs)) {
      TaintMap_TaintTmp(lhsTmp, TCode_TmpUndefined);
      return 1;
   }

   TaintMap_TaintTmp(lhsTmp, TCode_TmpDefined);

   return 0;
}

/* --------------- Arg helpers --------------- */

void
cg_PrintArg(const IRType ty, const struct ArgStruct *argP)
{
   if (argP->tmp == -1) {
      CG_CONST(ty, argP->val);
   } else {
      ASSERT(argP->tmp >= 0);
      ASSERT(argP->tmp != -1);

      if (!TaintMap_IsTmpTainted(argP->tmp)) {
         CG_CONST(ty, argP->val);
      } else {
         int i, obits, nbits;

         obits = IRTYPE2BITS(argP->ty);
         nbits = IRTYPE2BITS(ty);

         /* XXX: should we sign-extend signed types? */
         /* Extend if required. */
         if (nbits > obits) {
            CgenOut("0bin");
            for (i = 0; i < nbits-obits; i++) {
               CgenOut("0");
            }
            CgenOut(" @ ");
         } else if (nbits == obits) {
            /* No need for extension. */
         } else {
            /* XXX: Must truncate. */
            ASSERT_UNIMPLEMENTED(0);
         }

         CG_TMP(argP->tmp);
      }
   }
}

/*
 * Encode an argument to a helper function. The arg may be a const or a
 * tmp. */
void
cg_MkArg(struct ArgStruct *argP, UInt ty, Int tmp, ULong val)
{
   ASSERT(argP);

   argP->ty = ty;
   argP->tmp = tmp;
   if (argP->tmp == -1) {
      argP->tag = Iex_Const;
   } else {
      argP->tag = Iex_RdTmp;
   }
   argP->val = val;

   ASSERT(argP->tmp >= -1);
}


/* --------------- Packed args --------------- */

#if 0
/* XXX: since src and dst are unsigned, this could be simplified to a
 * memcpy. */
static INLINE ULong
cg_Interpret(const IRType ty, const UChar* bufP)
{
   ULong res;

   ASSERT_KPTR(bufP);

   switch (ty) {
   case Ity_I8:
      {
         UChar *p = (UChar*)bufP;
         DEBUG_MSG(5, "8: *p=0x%x\n", *p);
         res = *p;
      }
      break;
   case Ity_I16:
      {
         UShort *p = (UShort*)bufP;
         DEBUG_MSG(5, "16: *p=0x%x\n", *p);
         res = *p;
      }
      break;
   case Ity_I32:
   case Ity_F32:
      {
         UInt *p = (UInt*)bufP;
         DEBUG_MSG(5, "32: *p=0x%x\n", *p);
         res = *p;
      }
      break;
   case Ity_I64:
   case Ity_F64:
      {
         ULong *p = (ULong*)bufP;
         DEBUG_MSG(5, "64: *p=0x%llx\n", *p);
         res = *p;
      }
      break;
   default:
      ASSERT_UNIMPLEMENTED_MSG(0, "ty=%d\n", ty);
      break;
   }

   return res;
}
#endif

void
cg_UnpackArgs(ULong *argValA, const IRType *tyA, const struct PackedArgs *bufP, 
              const int numArgs)
{
   int i;
   UChar *tmpP = (UChar*) bufP;
   DEBUG_ONLY(UInt *magicP;)

   for (i = 0; i < numArgs; i++) {
#if 0
      /* XXX: simplify to memcpy */
      argValA[i] = cg_Interpret(tyA[i], tmpP);
#else
      argValA[i] = 0;
      memcpy(&argValA[i], tmpP, sizeofIRType(tyA[i]));
#endif

      tmpP += sizeofIRTypeAsArg(tyA[i]);
   }

#if DEBUG
   magicP = (UInt*) tmpP;
   /* Verify stack layout -- that args are not corrupted. */
   ASSERT(*magicP == DEBUG_MAGIC);
#endif
}


TCode
cg_IsArgTainted(IRTemp argTmp)
{
   TCode tc;

   if (argTmp != IRTemp_INVALID) {
      tc = TaintMap_IsTmpTainted(argTmp);
   } else {
      tc = TCode_TmpUntainted;
   }

   return tc;
}
