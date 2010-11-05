/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

/* 
 * VEX support only Ity_I32 and Ity_I64 as dirty args, but you can use
 * this function to translate other types into these valid types.
 */
IRExpr *
BT_ArgFixup(IRSB *bbP, IRExpr *expP)
{
   IRStmt *reinterpSt;
   IRTemp newTmp;
   IRType expTy;

   expTy = typeOfIRExpr(bbP->tyenv, expP);

   switch (expTy) {
      case Ity_I32:
      case Ity_I64:
         /* VEX supports these types as helper args. */
         return expP;
      case Ity_I8:
      case Ity_I16: 
         {
            /* VEX doesn't support these as helper args, so we need to
             * widen to Ity_I32. */
            IRTemp wideTmp = newIRTemp(bbP->tyenv, Ity_I32);
            addStmtToIRSB(bbP, 
                  IRStmt_WrTmp(wideTmp, 
                     IRExpr_Unop(expTy == Ity_I8 ? Iop_8Uto32 : Iop_16Uto32, 
                        expP)));
            return IRExpr_RdTmp(wideTmp);
         }
      case Ity_F32:
         {
            newTmp = newIRTemp(bbP->tyenv, Ity_I32);
            reinterpSt = IRStmt_WrTmp(newTmp, 
                  IRExpr_Unop(Iop_ReinterpF32asI32, expP));
            addStmtToIRSB(bbP, reinterpSt);
            return IRExpr_RdTmp(newTmp);
         }
      case Ity_F64:
         {
            newTmp = newIRTemp(bbP->tyenv, Ity_I64);
            reinterpSt = IRStmt_WrTmp(newTmp, 
                  IRExpr_Unop(Iop_ReinterpF64asI64, expP));
            addStmtToIRSB(bbP, reinterpSt);
            return IRExpr_RdTmp(newTmp);
         }
      default:
         ASSERT_UNIMPLEMENTED(0);
         break;
   } 

   return NULL;
}

static void
BTArgVecFixup(IRSB *bbP, IRExpr **argA)
{
   int i = 0;
   while (argA[i] != NULL) {
      argA[i] = BT_ArgFixup(bbP, argA[i]);
      i++;
   }
}

IRDirty* 
BT_UnsafeIRDirty_0_N ( IRSB *bbP, HChar* name, void* addr, 
                             IRExpr** args ) 
{
   IRDirty *dP;

   BTArgVecFixup(bbP, args);
   dP = unsafeIRDirty_0_N(0, name, addr, args);

   return dP;
}

IRDirty* 
BT_UnsafeIRDirty_1_N ( IRSB *bbP, IRTemp dst, 
      HChar* name, void* addr, IRExpr** args ) 
{
   IRDirty *dP;

   BTArgVecFixup(bbP, args);
   dP = unsafeIRDirty_1_N(dst, 0, name, addr, args);

   return dP;
}
