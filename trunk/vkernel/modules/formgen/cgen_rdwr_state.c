#include "vkernel/public.h"
#include "private.h"

#if 0 // Original
#if ASSUME_ALL_INPUTS_KNOWN
#define IGNORE_SYMBOLIC_PTRS 1
#else
#define IGNORE_SYMBOLIC_PTRS 0
#endif


/* Include the original store/put IR in the output IR?
 *
 * DEFAULT: off, because they may write to aribtrary locations if the
 * address is symbolic. */
#if IGNORE_SYMBOLIC_PTRS
#define ENABLE_STORE_PUT 1
#else
// Use store/put emulation dirty helpers that don't generate signals
// on fault
#define ENABLE_STORE_PUT 0 
#endif

#else 
// Added this to get taint propagation accross symbolic ptrs working,
// needed for getting HotDep'10 results.
#define IGNORE_SYMBOLIC_PTRS 0
#define ENABLE_SYMBOLIC_LOAD_PTRS 1
#define ENABLE_SYMBOLIC_STORE_PTRS 1
#define ENABLE_STORE_PUT 1
#endif

/* Include our symbolic map updates in the output IR?
 *
 * DEFUALT: yes, because we need to keep track of guest updates in the
 * symbolic map. */
#define INSTR_ENABLED 1

#if INSTR_ENABLED
#define IS_CAS_INSTR_ENABLED 1
#define IS_GET_INSTR_ENABLED 1
#define IS_PUT_INSTR_ENABLED 1
#define IS_STORE_INSTR_ENABLED 1
#define IS_LOAD_INSTR_ENABLED 1
#define IS_SAFE_LOAD_INSTR_ENABLED 1
#endif




/*
 * Should we be conservative in dealing with stores to symbolic
 * pointers? 
 */
#define WANTS_SOUND_SYMBOLIC_STORES 1

#if !DEBUG && !WANTS_SOUND_SYMBOLIC_STORES
/* Not recommended. Fromgen will likely diverge, due to locations not
 * being marked symbolic when in fact they should. */
#error "Symbolic stores are not sound -- formula generation will likely fail"
#endif

static const int wantsComments = 1;


static INLINE int
cgIsSymbolicPtr(const IRTemp addrTmp)
{
#if IGNORE_SYMBOLIC_PTRS
   return 0;
#else
   return (addrTmp != IRTemp_INVALID && TaintMap_IsTmpTainted(addrTmp));
#endif
}

/* ---------- Guest reg/mem Reads : tmp = Load() ---------- */

static INLINE ULong
cgExtractByte(const UInt byteNo, const ULong val)
{
   ASSERT(byteNo >= 0 && byteNo < 16);

   return (val & (0xFF << (byteNo*8))) >> (byteNo*8);
}

static int
cgIsSrcUniform(void **dataPA, const size_t len)
{
   int i, c = 0;
   const struct ByteVar *bvPP = NULL;

   ASSERT(len > 0);

   for (i = 0; i < len; i++) {
      const void *dataCP = dataPA[i];

      if (dataCP) {
         const struct ByteVar *bvCP = 
            (const struct ByteVar *) dataCP;

         ASSERT_KPTR(bvCP);

         if (c < 0) {
            break;
         } 

         if (bvCP->byte != i) {
            break;
         }

         if (c >= 1) {
            ASSERT(bvPP);

            if (bvPP->cvP != bvCP->cvP) {
               break;
            }
         }
         
         c++;
         bvPP = bvCP;
      } else {
         if (c > 0) {
            break;
         }

         c--;
      }
   } 

   /* How many uniform before disuniformity detected? */
   return c;
}

static void
cgEmitLoadByteWork(const HWord lhsTmp, const ULong lhsVal, void **dataPA, 
                   const size_t len) 
{
   int i;

   for (i = 0; i < len; i++) {
      void *dataP = dataPA[i];

      if (dataP) {
         const struct ByteVar *bvP = 
            (const struct ByteVar *) dataP;
         struct CondVar *cvP = bvP->cvP;

         ASSERT_KPTR(bvP);
         ASSERT_KPTR(cvP);

#if DEBUG
         {

            ASSERT(bvP);
            ASSERT(cvP);

            if (cvP->tag == CondVar_Origin) {
               if(!(cvP->len >= 1)) {
                  DLOG("vcpu=%d bbExecCount=%llu name=%llu\n",
                        cvP->vcpu, cvP->bbExecCount,
                        cvP->name);
                  ASSERT(0);
               }
            }
         }
#endif

         cg_LazyDeclareIfNeeded(cvP);
         CG_ASSIGN(CG_EXTRACT_BYTE(CG_TMP(lhsTmp), i), 
               CG_BV(bvP));

      } else {
         CG_ASSIGN(CG_EXTRACT_BYTE(CG_TMP(lhsTmp), i),
               CG_CONST(Ity_I8, cgExtractByte(i, lhsVal)));
      }
   }
}

static void
cgEmitLoad(
      void **dataPA, 
      const IRTemp lhsTmp, 
      /* Must be large enough to accommodate largest value. */
      const ULong lhsVal,
      const IRType ty)
{

   ssize_t len = cg_SizeOfIRType(ty);

   ASSERT((Int)lhsTmp >= 0)
   ASSERT(len > 0);

   /* ----- Propagate taint ----- */

   if (cgShouldSkipCgen(ty)) {
      TaintMap_TaintTmp(lhsTmp, TCode_TmpUndefined);
      return;
   }

   TaintMap_TaintTmp(lhsTmp, TCode_TmpDefined);

   /* ----- Generate constraints ----- */

   cg_DeclareTmp(lhsTmp, ty);

   int c = cgIsSrcUniform(dataPA, len);

   //DEBUG_MSG(5, "c=%d len=%d\n", c, len);

   if (c == len) {
      /* Source is entirely symbolic and references
       * contigious bytes of a symbolic variable. */

      struct ByteVar *bvP = (struct ByteVar *) dataPA[0];
      struct CondVar *cvP = bvP->cvP;

      ASSERT_KPTR(bvP);
      ASSERT_KPTR(cvP);

      /* If tmp or origin at the source memory location
       * has a different size than the target tmp, 
       * we can't do a simple assignment -- that won't typecheck
       * in the theorem prover; so we do it byte by
       * byte. */
      if (len == cvP->len) {
         cg_LazyDeclareIfNeeded(cvP);
         CG_ASSIGN(CG_TMP(lhsTmp), CG_CV(cvP));
      } else {
         cgEmitLoadByteWork(lhsTmp, lhsVal, dataPA, len);
      } 
   } else {
      /* Source is a mix of symbolic and concrete bytes. */

      ASSERT_MSG(c != -len, "shouldn't have invoked this function if source is concrete\n");
      ASSERT_MSG(c > -len && c < len, "len=%d c=%d", len, c);

      cgEmitLoadByteWork(lhsTmp, lhsVal, dataPA, len);
   }
}


static void 
cgEmitTmpGetWork(const IRTemp lhsTmp, const UInt offset, const IRType ty, 
                 const struct PackedArgs *argBufP)
{
   size_t len = cg_SizeOfIRType(ty);
   void *dataPA[len];

   ASSERT((Int)lhsTmp >= 0);

   if (TaintMap_IsRegTainted(current, offset, len, dataPA)) {
#if DEBUG
      int i;
      for (i = 0; i < len; i++) {
         if (dataPA[i]) {
            ASSERT_KPTR(dataPA[i]);
         }
      }
#endif
      ULong lhsVal;
      
      cg_UnpackArgs(&lhsVal, &ty, argBufP, 1);

      cgEmitLoad(dataPA, lhsTmp, lhsVal, ty);
      cgProf_UpdateCounter();
   } else {
      TaintMap_UntaintTmp(lhsTmp);
   }
}


static void 
cgEmitTmpGet(const IRTemp lhsTmp, const HWord offset, const IRType ty, 
             struct PackedArgs argBuf)
{
   cgEmitTmpGetWork(lhsTmp, offset, ty, &argBuf);
}

void
cg_InstrTmpGet(IRSB *bb, const IRStmt *s)
{
   IRDirty *d;
   IRExpr *rhs = s->Ist.WrTmp.data;
   Int offset = rhs->Iex.Get.offset;
   const Int lhsTmp = s->Ist.WrTmp.tmp;
   const IRType getTy = rhs->Iex.Get.ty;

   if (IS_GET_INSTR_ENABLED) {
      d = unsafeIRDirty_0_N(0,
            "cgEmitTmpGet",
            cgEmitTmpGet,
            mkIRExprVec_5(
               mkIRExpr_UInt(lhsTmp),
               mkIRExpr_UInt(offset),
               mkIRExpr_UInt(getTy),
               /* Could be of variable size, so push this
                * last. */
               BT_ArgFixup(bb, IRExpr_RdTmp(lhsTmp)),
               mkIRExpr_UInt(DEBUG_MAGIC)
               )
            );

      addStmtToIRSB(bb, IRStmt_Dirty(d));
   }
}


static int
cgHandleSymbolicGetIPtr(const IRTemp lhsTmp, const IRType lhsTy, 
                        const Int base, const size_t len, const IRTemp ixTmp)
{
   ASSERT(base >= 0);
   ASSERT(lhsTmp != IRTemp_INVALID);

   if (!cgIsSymbolicPtr(ixTmp)) {
      return 0;
   }

   /* Assume, conservatively, that the load may be from any address. */
   TaintMap_TaintTmp(lhsTmp, TCode_TmpDefined);
   cg_DeclareTmp(lhsTmp, lhsTy);

#if PRODUCT
#error "XXX: need to generate array constraints: lhsTmp = Array[ixTmp]"
#endif
   ASSERT_UNIMPLEMENTED_MSG(0,
         "Loading from symbolic ptr: lhsTmp %d addrTmp %d\n",
         lhsTmp, ixTmp);

   return 1;
}


static void
cgEmitTmpGetI(IRTemp lhsTmp, Int base, IRType elemTy, Int nElems, UInt ixTmp, 
              Int ix, Int bias, const struct PackedArgs argBuf)
{
   Int offset = cgCalcArrayOffset(base, elemTy, nElems,
         ix, bias);
   size_t len = sizeofIRType(elemTy)*nElems;

   if (!cgHandleSymbolicGetIPtr(lhsTmp, elemTy, base, len, ixTmp)) {
      cgEmitTmpGetWork(lhsTmp, offset, elemTy, &argBuf);
   } else {
      cgProf_UpdateCounter();
   }
}

void
cg_InstrTmpGetI(IRSB *bb, const IRStmt *s)
{
   IRDirty *d;
   IRExpr *rhs = s->Ist.WrTmp.data;
   IRTemp lhsTmp = s->Ist.WrTmp.tmp;
   const IRRegArray *raP = rhs->Iex.GetI.descr;
   IRExpr *ixP = rhs->Iex.GetI.ix;
   const IRTemp ixTmp = cg_GetTempOrConst(ixP);
   Int bias = rhs->Iex.GetI.bias;

#if DEBUG
   const IRType ixTy = typeOfIRExpr(bb->tyenv, ixP);
   ASSERT(ixTy == Ity_I32);
   ASSERT(sizeofIRType(ixTy) == sizeof(UInt));
   const IRType lhsTy = typeOfIRTemp(bb->tyenv, lhsTmp);
   ASSERT(lhsTy == raP->elemTy);
#endif

   if (IS_GET_INSTR_ENABLED) {
      d = unsafeIRDirty_0_N(0,
            "cgEmitTmpGetI",
            cgEmitTmpGetI,
            mkIRExprVec_9(
               mkIRExpr_UInt(lhsTmp),
               mkIRExpr_UInt(raP->base),
               mkIRExpr_UInt(raP->elemTy),
               mkIRExpr_UInt(raP->nElems),
               mkIRExpr_UInt(ixTmp),
               ixP,
               mkIRExpr_UInt(bias),
               /* Could be of variable size, so push this
                * last. */
               BT_ArgFixup(bb, IRExpr_RdTmp(lhsTmp)),
               mkIRExpr_UInt(DEBUG_MAGIC)
               )
            );

      addStmtToIRSB(bb, IRStmt_Dirty(d));
   }
}

static int optWantsPreciseArrayReadConstraints  = 0;
static int optWantsPreciseArrayWriteConstraints = 0;

#if 0
static void
cgGetPossibleLoadStoreTargets(int isLoad, struct Range *dstRangeA, 
      int *nrTargets)
{
   int i;

   for (i = 0; i < nrRegions && i < *nrTargets; i++) {
      const struct VirtRange *rP = &ptrRegions[i];

      ASSERT_UNIMPLEMENTED(rP->len <= PAGE_SIZE);

      u64 *gAddrA = malloc(sizeof(*gAddrA) * rP->len);
      GlobalAddr_FromRange(gAddrA, rP->start, rP->len, 1);

      dstRangeA[i].start = MapAddr_Gaddr(gAddrA[0]);
      dstRangeA[i].len = rP->len;

      DEBUG_MSG(5, "start=0x%x:0x%llx len=%d\n", rP->start, gAddrA[0], rP->len);

      free(gAddrA);
      gAddrA = NULL;
   }
   *nrTargets = nrRegions;
}
#endif

/*
 * Constrain @addrTmp to fall within one of the specified virtual address
 * ranges.
 */
static void
cgEmitAddrConstraints(const IRTemp addrTmp, const IRType dataTy,
                      const struct VirtRange *rangeA, const int nrRanges)
{
   int i;
   const size_t dataLen = cg_SizeOfIRType(dataTy);

   cg_StartNewLocalScope();

   CG_NEW_BOOL(CG_LSCOPEI(0));

   for (i = 0; i < nrRanges; i++) {
      const struct VirtRange *vrP = &rangeA[i];

      CG_COMMENT("Address must be in [0x%x, %d]\n", vrP->start, vrP->len);


      /* Constrain addrTmp to fall within these ranges:
       *
       * start <= addrTmp <= addrTmp+dataLen < end */
      CG_NEW_VAR(Ity_I1, CG_LSCOPE("LO"));
      CG_ASSIGN(CG_LSCOPE("LO"), 
            CG_ITE(
               CG_LE(CG_CONST(Ity_I32, vrP->start), CG_TMP(addrTmp)),
               CG_CONST(Ity_I1, 1),
               CG_CONST(Ity_I1, 0)));

      CG_NEW_VAR(Ity_I1, CG_LSCOPE("HI"));
      CG_ASSIGN(CG_LSCOPE("HI"), 
         CG_ITE(
            CG_LT(CG_TMP(addrTmp), 
               CG_CONST(Ity_I32, vrP->start + vrP->len - dataLen)),
               CG_CONST(Ity_I1, 1),
               CG_CONST(Ity_I1, 0)));

      CG_NEW_BOOL(CG_LSCOPEI(i+1));

      CG_EQUIV(CG_LSCOPEI(i), 
            CG_ITE(
               CG_EQUAL(
                  CG_AND(CG_LSCOPE("LO"), CG_LSCOPE("HI")),
                  CG_CONST(Ity_I1, 1)),
               CG_TRUE,
               CG_LSCOPEI(i+1)));
   }

   CG_EQUIV(CG_LSCOPEI(i), CG_FALSE);
   CG_EQUIV(CG_LSCOPEI(0), CG_TRUE);
}


static void
cgEmitSymbolicLoadFromVirtRange(const struct VirtRange *vrP, 
                  const IRTemp addrTmp, const IRType lhsTy)
{
   const size_t lhsLen = cg_SizeOfIRType(lhsTy);
  
   /* ----- Read the symbolic bytes at the virt range ----- */

   struct CgByte **bytePA = malloc(sizeof(*bytePA) * vrP->len);

   CG_NEW_VAR(lhsTy, CG_LSCOPEI(0));

   struct GAddrRange gaddrRanges[MAX_NR_RANGES];
   int nrRanges = MAX_NR_RANGES;

   const int isRead = 1;
   GlobalAddr_FromRange2(current->mm, gaddrRanges, &nrRanges, vrP->start, vrP->len, isRead);

   int i, pos = 0;
   for (i = 0; i < nrRanges; i++) {
      const struct GAddrRange *grP = &gaddrRanges[i];

      ASSERT(pos < vrP->len);
      const struct MAddrRange mr = { .kind = Mk_Gaddr, .start = grP->start, 
         .len = grP->len };
      cgMap_Read(&mr, &bytePA[pos]);
      pos += grP->len;
   }


   /* ----- Constrain loaded value to bytes in virt range ----- */
   CG_COMMENT("Loading from symbolic pointer with range [0x%x, %d].\n",
         vrP->start, vrP->len);

   cg_StartNewLocalScope();

   CG_NEW_VAR(lhsTy, CG_LSCOPEI(0));

   int j, k;
   for (j = 0; j < (vrP->len - lhsLen); j++) {
      CG_NEW_VAR(lhsTy, CG_LSCOPE_NAMED("tmp", j));

      for (k = 0; k < lhsLen; k++) {
         ASSERT(j + k < vrP->len);

         CG_ASSIGN(CG_EXTRACT_BYTE(CG_LSCOPE_NAMED("tmp", j), k),
               cg_PrintSymByte(bytePA[j+k]));
      }

      CG_NEW_VAR(lhsTy, CG_LSCOPEI(j+1));

      CG_ASSIGN(CG_LSCOPEI(j),
            CG_ITE(
               CG_EQUAL(
                  CG_TMP(addrTmp),
                  CG_CONST(Ity_I32, vrP->start+j)),
               CG_LSCOPE_NAMED("tmp", j),
               CG_LSCOPEI(j+1)
               )
            );
   }

   cgByte_PutAll(bytePA, vrP->len);
   free(bytePA);
   bytePA = NULL;
}

static int
cgHandleSymbolicLoadPtr(const IRTemp lhsTmp, const IRType lhsTy, 
                        const IRTemp addrTmp)
{
   ASSERT(lhsTmp != IRTemp_INVALID);

   /* Assign a new symbolic var to result of each load. Useful for testing
    * constraint generator, but results in huge formulas. */
   if (!cgIsSymbolicPtr(addrTmp)) {
      return 0;
   }

   /* ----- Load ptr is tainted ----- */

   TaintMap_TaintTmp(lhsTmp, TCode_TmpDefined);
   cg_DeclareTmp(lhsTmp, lhsTy);

   if (optWantsPreciseArrayReadConstraints) {
      int i;

      ASSERT_UNIMPLEMENTED(nrPtrRegions > 0);

      for (i = 0; i < nrPtrRegions; i++) {
         cgEmitSymbolicLoadFromVirtRange(&ptrRegions[i], addrTmp, lhsTy);
      }

      /* XXX: multiplex all subranges to lhsTmp */
      ASSERT_UNIMPLEMENTED(0);

      cgEmitAddrConstraints(addrTmp, lhsTy, ptrRegions, nrPtrRegions);
   } else {
      /* Since the address is tainted, we assume, conservatively, that the 
       * load value may be arbitrary (perhaps equal to a value in some
       * mapped memory location, but not necessarily). */
   }

   return 1;
}

static void 
cgEmitTmpLoadWork(
      const IRTemp addrTmp, const HWord vaddr, 
      const IRType loadTy, const IRTemp lhsTmp, const ULong lhsVal)
{
   const size_t len = cg_SizeOfIRType(loadTy);

   ASSERT_MSG(len <= ARCH_MAX_ACCESS_LEN, "len=%d too big to alloc on stack", 
              len);

   struct GAddrRange gaddrRanges[MAX_NR_RANGES];
   int nrRanges = MAX_NR_RANGES;
   void *dataPA[len];


   DEBUG_MSG(5, "TMP_LOAD: 0x%x len=%d\n", vaddr, len);
   if (!cgHandleSymbolicLoadPtr(lhsTmp, loadTy, addrTmp)) {

      cgProf_AddAccess(Pak_Load, vaddr);

      const int is_read = 1;
      GlobalAddr_FromRange2(current->mm, gaddrRanges, &nrRanges, vaddr, 
            len, is_read);

      if (TaintMap_AreMemRangesTainted(gaddrRanges, nrRanges, dataPA)) {
#if DEBUG
         int i;
         for (i = 0; i < len; i++) {
            if (dataPA[i]) {
               ASSERT_KPTR(dataPA[i]);
            }
         }
#endif
         DEBUG_MSG(5, "tainted\n");
         cgEmitLoad(dataPA, lhsTmp, lhsVal, loadTy);
         cgProf_UpdateCounter();
      } else {
         DEBUG_MSG(5, "not tainted\n");
         TaintMap_UntaintTmp(lhsTmp);
      }
   } else {
      cgProf_UpdateCounter();
   }
}

static void 
cgEmitTmpLoad(
      const IRTemp addrTmp, const HWord vaddr, 
      const IRType loadTy, const IRTemp lhsTmp, 
      const struct PackedArgs argBuf)
{
   ULong lhsVal;

   cg_UnpackArgs(&lhsVal, &loadTy, &argBuf, 1);

   cgEmitTmpLoadWork(addrTmp, vaddr, loadTy, lhsTmp, lhsVal);
}

static u64
cgLoadOnlyIfConcPtr(void __user * usrP, const IRTemp addrTmp, 
                    const UInt dataTy)
{
   ASSERT_MSG(VCPU_IsReplaying(), "This load ignores faults!\n");
   ASSERT(sizeofIRType(dataTy) <= 8);
   u64 val = 0LLU;


   /* If this is non-value-deterministic replay, there's a chance that 
    * dereferencing a symbolic pointer will result in a map/protection 
    * fault; or worse, it may overwrite concrete data (in the case of a 
    * store)-- so don't do it. 
    * This can happen because program invariants may be violated due to
    * a lack of inputs, path-enforced execution, and/or skipped 
    * execution. */
   if (!env.is_value_det && cgIsSymbolicPtr(addrTmp)) {
      /* We can return an arbitrary value, since it won't be used in
       * subsequent formula gen anyway (because the lhs will be 
       * symbolic). */
      ASSERT(val == 0);
      goto out;
   }

   DEBUG_MSG(7, "usrP=0x%x dataSz=%d\n", usrP, sizeofIRType(dataTy));
   ASSERT_UPTR(usrP);

#if PRODUCT
#error "XXX"
   /* XXX: this is not a perfect emulation: it's not atomic like a
    * regular load; each byte is copied at a time; does this matter? */
#endif
   int err;
   if ((err = copy_from_user(&val, usrP, sizeofIRType(dataTy)))) {
#if WANTS_SOUND_SYMBOLIC_STORES
      /* Pointer is not symbolic, so shouldn't segfault. If there was a
       * segfault in the original run, then we should've handled it
       * already. */
      ASSERT_MSG(0, "err=%d\n", err);
#endif
      return 0;
   } 

out:
   return val;
}


int
cg_InstrTmpLoad(IRSB *bbP, const IRStmt *stP)
{
   IRExpr *rhs = stP->Ist.WrTmp.data;
   IRExpr *addrExpr = rhs->Iex.Load.addr;
   const Int lhsTmp = stP->Ist.WrTmp.tmp;
   const IRType lhsTy = rhs->Iex.Load.ty;
   const IRTemp addrTmp = cg_GetTempOrConst(addrExpr);

#if DEBUG
   IRType addrTy = typeOfIRExpr(bbP->tyenv, addrExpr);
   ASSERT(sizeofIRType(addrTy) == sizeof(HWord));
#endif

   if (IS_SAFE_LOAD_INSTR_ENABLED) {
      IRTemp dirtyTmp = newIRTemp(bbP->tyenv, Ity_I64);
#if PRODUCT
#error "XXX: do we need to declare the memory effects?"
#else
      addStmtToIRSB(bbP,
            IRStmt_Dirty(
               MACRO_unsafeIRDirty_1_N(dirtyTmp, 0, cgLoadOnlyIfConcPtr,
                  mkIRExprVec_3(
                     addrExpr,
                     mkIRExpr_UInt(addrTmp),
                     mkIRExpr_UInt(lhsTy)))));
#endif

      /* ----- Assign result to load's lhs tmp ----- */
      {
         IRTemp loadTmp = stP->Ist.WrTmp.tmp;
         IRType loadTy = typeOfIRExpr(bbP->tyenv, stP->Ist.WrTmp.data);
         switch (loadTy) {
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
         case Ity_I8:
            /* VEX doesn't support the 64to16/64to8 ops: you'll get a
             * dynamic "cannot reduce tree" error if you try it. */
            {
               IROp op = (loadTy == Ity_I16) ? Iop_32to16 : Iop_32to8;
               IRTemp tmp1 = newIRTemp(bbP->tyenv, Ity_I32);
               addStmtToIRSB(bbP, 
                     IRStmt_WrTmp(tmp1, 
                        IRExpr_Unop(Iop_64to32, IRExpr_RdTmp(dirtyTmp))));
               addStmtToIRSB(bbP, 
                     IRStmt_WrTmp(loadTmp, 
                        IRExpr_Unop(op, IRExpr_RdTmp(tmp1))));
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
   }

   if (IS_LOAD_INSTR_ENABLED) {
      addStmtToIRSB(bbP,
            IRStmt_Dirty(
               MACRO_unsafeIRDirty_0_N(0,
                  cgEmitTmpLoad,
                  mkIRExprVec_6(
                     mkIRExpr_UInt(addrTmp),
                     addrExpr,
                     mkIRExpr_UInt(lhsTy),
                     mkIRExpr_UInt(lhsTmp),
                     BT_ArgFixup(bbP, IRExpr_RdTmp(lhsTmp)),
                     mkIRExpr_UInt(DEBUG_MAGIC)
                     )
                  )));
   }

   return IS_SAFE_LOAD_INSTR_ENABLED ? 0 : 1;
}

/* ---------- Guest reg/mem stores ---------- */

static void
cgEmitSymbolicStoreToVirtRange(
      const struct VirtRange *vrP, const IRTemp addrTmp,
      const IRTemp dataTmp, const IRType dataTy, struct CgByte **dataBytePA)
{
   const size_t dataLen = cg_SizeOfIRType(dataTy);

   ASSERT(dataLen <= vrP->len);

   /* ----- Read the pre-store symbolic bytes at the virt range ----- */
   struct CgByte **origBytePA = malloc(sizeof(*origBytePA) * vrP->len);

   struct GAddrRange gaddrRanges[MAX_NR_RANGES];
   int nrRanges = MAX_NR_RANGES;

   /* XXX: pull out to read virt range */
   const int isRead = 0;
   GlobalAddr_FromRange2(current->mm, gaddrRanges, &nrRanges, vrP->start, vrP->len, isRead);

   int i;
   size_t pos = 0;
   for (i = 0; i < nrRanges; i++) {
      const struct GAddrRange *grP = &gaddrRanges[i];

      ASSERT(pos < vrP->len);
      const struct MAddrRange mr = { .kind = Mk_Gaddr, .start = grP->start,
         .len = grP->len };
      cgMap_Read(&mr, &origBytePA[pos]);
      pos += grP->len;
   }

   int j, k;
   /* ----- Constrain store targets to datum or orig byte ----- */
   CG_COMMENT("Storing to symbolic pointer with range [0x%x, %d].\n", 
         vrP->start, vrP->len);

   struct CgByte **newBytePA = malloc(sizeof(*newBytePA) * vrP->len);

   for (j = 0; j < vrP->len; j++) {
      const u64 arrayWriteName = VA(arrayCounter)++;
      cg_DeclareArrayWrite(arrayWriteName);

      if (optWantsPreciseArrayWriteConstraints) {
         cg_StartNewLocalScope();

         CG_NEW_VAR(Ity_I8, CG_LSCOPEI(0));

         for (k = 0; k < dataLen; k++) {
            CG_NEW_VAR(Ity_I8, CG_LSCOPEI(k+1));

            /* Was the k-th byte of the datum written to this pos in the
             * array? If so, then this loc should take on its value. */
            CG_ASSIGN(
                  CG_LSCOPEI(k),
                  CG_ITE(
                     CG_EQUAL(CG_TMP(addrTmp), CG_CONST(Ity_I32, 
                           (vrP->start+j-k))),
                     cg_PrintSymByte(dataBytePA[k]),
                     CG_LSCOPEI(k+1)));
         }

         /* If none of the data bytes fall on this byte, then this byte 
          * retains its original value. */
         CG_ASSIGN(CG_LSCOPEI(k), cg_PrintSymByte(origBytePA[j]));

         CG_ASSIGN(cg_PrintArrayVarNow(arrayWriteName), CG_LSCOPEI(0));
      }

      cgByte_MakeSymbolic(CondVar_ArrayWrite, arrayWriteName, 1, 
            &newBytePA[j]);
   }

   cgMap_UpdateGAddr(gaddrRanges, nrRanges, newBytePA);

   cgByte_PutAll(newBytePA, vrP->len);
   free(newBytePA);
   newBytePA = NULL;

   cgByte_PutAll(origBytePA, vrP->len);
   free(origBytePA);
   origBytePA = NULL;
}

const int maxPtrRegionsConsidered = 10;

static int
cgHandleSymbolicStorePtr(const IRTemp addrTmp, const HWord vaddr,
      const IRTemp dataTmp, const IRType dataTy, 
      struct CgByte **dataBytePA) 
{
   if (!cgIsSymbolicPtr(addrTmp)) {
      return 0;
   }

   int rgnId = -1;

   if (env.is_value_det) {
      /* We know the write must be within [vaddr, vaddr+dataLen]. */
      const size_t dataLen = cg_SizeOfIRType(dataTy);

      rgnId = Cgen_AddPtrRegion(vaddr, dataLen);
   } else {
      /* XXX: we need to perform the store..., so we can't just ignore this
       * assert. If we don't do the store, then the appropriate targets locs
       * won't be made symbolic and the branch predictor won't be invoked
       * on branches (b/c it will think those branches are concrete). 
       *
       * Also consider the implications of picking regions
       * unsoundly/non-conservatively. We can't just invoke the path
       * selector for tainted branches...taint would no longer be
       * accurate.
       * */
#if WANTS_SOUND_SYMBOLIC_STORES
      ASSERT_UNIMPLEMENTED(nrPtrRegions > 0);
#endif
   }

#if WANTS_SOUND_SYMBOLIC_STORES
   ASSERT_MSG(nrPtrRegions > 0, "Results will be unsound otherwise.");
#endif

   ASSERT_MSG(nrPtrRegions == 1, "nrPtrRegions=%d", nrPtrRegions);
   LOG("nrPtrRegions=%d\n", nrPtrRegions);

   int i;
   for (i = 0; i < MIN(maxPtrRegionsConsidered, nrPtrRegions); i++) {
      cgEmitSymbolicStoreToVirtRange(&ptrRegions[i], addrTmp, dataTmp, dataTy, 
            dataBytePA);

      cgEmitAddrConstraints(addrTmp, dataTy, ptrRegions, 
            MIN(maxPtrRegionsConsidered, nrPtrRegions));
   }

   if (env.is_value_det) {
      ASSERT(rgnId >= 0);
      Cgen_RmPtrRegion(rgnId);
   }

   return 1;
}


static struct CondVar *
cgMakeDatumBytes(struct CgByte **bytePA, const IRTemp dataTmp, 
      const char *dataValP, const size_t len)
{
   ASSERT_KPTR(bytePA);
   ASSERT_KPTR(dataValP);
   ASSERT(len > 0);

   struct CondVar *cvP = NULL;
   const TCode tc = cg_IsArgTainted(dataTmp);

   switch (tc) {
   case TCode_TmpUndefined:
      cvP = cgByte_MakeSymbolic(CondVar_Origin, VA(originCounter)++, len, 
            bytePA);
      break;
   case TCode_TmpDefined:
      cvP = cgByte_MakeSymbolic(CondVar_Tmp, dataTmp, len, bytePA);
      break;
   case TCode_TmpUntainted:
      cgByte_MakeConcrete(dataValP, len, bytePA);
      break;
   default:
      ASSERT(0);
      break;
   }

   return cvP;
}

#if 1
static void
cgEmitConditionalWork(
      const u64 casVarName,
      const IRTemp oldTmp, const ULong oldVal,
      const IRTemp expdTmp, const ULong expdVal,
      const IRTemp dataTmp, const ULong dataVal,
      const struct CondVar *casCvP, 
      const IRType storeTy)
{
   ASSERT(oldTmp != IRTemp_INVALID);

   cg_DeclareCAS(casVarName, storeTy);

   cg_StartNewLocalScope();

   if (cg_IsArgTainted(oldTmp)) {
      CG_NEW_VAR_INIT(storeTy, CG_LSCOPE("old"),
            CG_TMP(oldTmp));
   } else {
      CG_NEW_VAR_INIT(storeTy, CG_LSCOPE("old"),
            CG_CONST(storeTy, oldVal));
   }

   if (cg_IsArgTainted(expdTmp)) {
      CG_NEW_VAR_INIT(storeTy, CG_LSCOPE("expd"),
            CG_TMP(expdTmp));
   } else {
      CG_NEW_VAR_INIT(storeTy, CG_LSCOPE("expd"),
            CG_CONST(storeTy, expdVal));
   }

   if (cg_IsArgTainted(dataTmp)) {
      CG_NEW_VAR_INIT(storeTy, CG_LSCOPE("data"),
            CG_TMP(dataTmp));
   } else {
      CG_NEW_VAR_INIT(storeTy, CG_LSCOPE("data"),
            CG_CONST(storeTy, dataVal));
   }

   CG_ASSIGN(CG_CV(casCvP),
         CG_ITE(
            CG_EQUAL(CG_LSCOPE("old"), CG_LSCOPE("expd")),
            CG_LSCOPE("data"),
            CG_TMP(oldTmp)));
}
#endif


static void
cgEmitStoreConditionalWork(
      const int isConditionalStore,
      const IRTemp addrTmp, const HWord vaddr, 
      const IRType storeTy, 
      const IRTemp oldTmp, const ULong oldVal,
      const IRTemp expdTmp, const ULong expdVal,
      const IRTemp dataTmp, const char *dataValP)
{
   const size_t len = cg_SizeOfIRType(storeTy);

#if DEBUG || 0
   ASSERT_KPTR(dataValP);
   ASSERT_MSG(len <= ARCH_MAX_ACCESS_LEN, "len=%d too big to alloc on stack", 
         len);
   ASSERT(len > 0);

   size_t buflen = (len*2)+1;
   char buf[buflen];
   /* XXX: hex_encode should take max_outbufsize arg */
   hex_encode(buf, buflen, dataValP, len);
   DEBUG_MSG(5, "buf=%s\n", buf);
#endif

   struct CgByte *dataBytePA[len];
   // CAREFUL: make sure this is in scope when you free down below!
   struct CgByte *casBytePA[len]; 
   struct CgByte **bytePA = dataBytePA;

   int isDatumTainted =
      cgMakeDatumBytes(dataBytePA, dataTmp, dataValP, len) ? 1 : 0;

   if (isConditionalStore) {
      if (cg_IsArgTainted(oldTmp) || cg_IsArgTainted(expdTmp)) {
         const u64 casVarName = VA(casCounter)++;
         ULong dataVal = 0;

         //ASSERT_UNIMPLEMENTED(0);
         memcpy(&dataVal, dataValP, len);

         const struct CondVar *casCvP = 
            cgByte_MakeSymbolic(CondVar_CAS, casVarName, len, casBytePA);
         ASSERT_KPTR(casCvP);

         cgEmitConditionalWork(casVarName, oldTmp, oldVal, expdTmp, expdVal,
               dataTmp, dataVal, casCvP, storeTy);

         cgByte_PutAll(dataBytePA, len);

         /* Store the CAS'd variable rather than the datum var. */
         bytePA = casBytePA;

         isDatumTainted = 1;
      } else if (oldVal != expdVal) {
         /* Don't do the store, per CMPXCHG semantics. */
         goto out;
      }
   } 

   ASSERT_KPTR(bytePA);
   if (cgHandleSymbolicStorePtr(addrTmp, vaddr, dataTmp, storeTy, bytePA)) {
      cgProf_UpdateCounter();
   } else {
      /* ----- Update to concrete/constant location ----- */
      if (isDatumTainted) {
         cgProf_UpdateCounter();
      }

      cgProf_AddAccess(Pak_Store, vaddr);
      cgMap_UpdateVAddr(vaddr, bytePA, len);
   }

out:
   ASSERT_KPTR(bytePA);
   cgByte_PutAll(bytePA, len);
}

static void
cgEmitStore(
      const IRTemp addrTmp, const HWord vaddr, 
      const IRType dataTy, const IRTemp dataTmp, 
      const struct PackedArgs argBuf)
{
   ULong dataVal;
   cg_UnpackArgs(&dataVal, &dataTy, &argBuf, 1);

   const char *dataValP = (const char *) &dataVal;

   cgEmitStoreConditionalWork(0, addrTmp, vaddr, dataTy, 
         IRTemp_INVALID, 0, IRTemp_INVALID, 0, dataTmp, dataValP);
}


int
cg_InstrStoreStmt(IRSB * bb, const IRStmt * s)
{
   IRExpr *dataExpr = s->Ist.Store.data;
   IRExpr *addrExpr = s->Ist.Store.addr;
   const IRType dataTy = typeOfIRExpr(bb->tyenv, dataExpr);

   const IRTemp dataTmp = cg_GetTempOrConst(dataExpr);
   const IRTemp addrTmp = cg_GetTempOrConst(addrExpr);

#if DEBUG
   IRType addrTy = typeOfIRExpr(bb->tyenv, addrExpr);
   ASSERT(sizeofIRType(addrTy) == sizeof(HWord));
   ASSERT(dataExpr->tag == Iex_Const || dataExpr->tag == Iex_RdTmp);
#endif

   /* 
    * DESIGN NOTE:
    *
    * We emulate loads and CAS with dirty helpers, but we don't emulate 
    * stores with a dirty helper. This is intentional. We need the
    * emulation to deal with symbolic pointers during replay. But
    * stores to symbolic pointers needn't go through so long as the
    * corresponding location(s) in the taint map are tainted.
    * That's because subsequent loads from those locations will see
    * that the locations are tainted and will as a result
    * return a constant dummy value (0, see the load/cas emulator). So
    * it doesn't matter if the location is updated or not.
    */

   if (IS_STORE_INSTR_ENABLED) {
      /* Store helper must go before the store operation, as a throw to the
       * ckpt module. */
      IRDirty *dirtyP = 
         MACRO_unsafeIRDirty_0_N(0,
               cgEmitStore,
               mkIRExprVec_6(
                  mkIRExpr_UInt(addrTmp),
                  addrExpr,
                  mkIRExpr_UInt(dataTy),
                  mkIRExpr_UInt(dataTmp),
                  BT_ArgFixup(bb, dataExpr),
                  mkIRExpr_UInt(DEBUG_MAGIC)
                  )
               );
      addStmtToIRSB(bb, IRStmt_Dirty(dirtyP));
   }

#if ENABLE_STORE_PUT
   return -1;
#else
   return 0;
#endif
}

static void
cgEmitPutWork(const HWord offset, const Int arrayBase, const size_t arrayLen,
      const IRTemp ixTmp, const IRTemp dataTmp, const IRType dataTy, 
      const char *dataValP)
{
   const size_t len = cg_SizeOfIRType(dataTy);
   struct CgByte *bytePA[len];

   const int isDatumTainted = 
      cgMakeDatumBytes(bytePA, dataTmp, dataValP, len) ? 1 : 0;

   struct MAddrRange rangeA[1];
   int nrRanges;

   if (cgIsSymbolicPtr(ixTmp)) {
      /* ----- Update to symbolic/variable location ----- */

      cgProf_UpdateCounter();
      ASSERT_UNIMPLEMENTED(0);
   } else {
      /* ----- Update to concrete/constant location ----- */

      nrRanges = 1;
      rangeA[0].kind = Mk_Reg;
      rangeA[0].start = offset;
      rangeA[0].len = len;

      if (isDatumTainted) {
         cgProf_UpdateCounter();
      }
   }

   cgMap_UpdateMAddr(rangeA, nrRanges, bytePA);
   cgByte_PutAll(bytePA, len);
}

static void
cgEmitPut(UInt offset, IRTemp dataTmp, IRType dataTy, ...)
{
   const char *dataValP = (char*)&dataTy + sizeof(dataTy);

   cgEmitPutWork(offset, 0, MAX_NR_REGS, IRTemp_INVALID, dataTmp, dataTy, 
         dataValP);
}

int
cg_InstrPutStmt(IRSB * bb, const IRStmt * s)
{
   IRExpr *dataExpr = s->Ist.Put.data;
   const Int offset = s->Ist.Put.offset;
   const IRType dataTy = typeOfIRExpr(bb->tyenv, dataExpr);

   /* We don't ever taint EIP, nor do we directly read from it,
    * so there is no sense in trying to untaint it. But we need the
    * helper call anyway for the ckpt module. */
#if 0
   if (offset == offsetof(TaskRegs, guest_EIP)) {
      ASSERT(dataExpr->tag == Iex_Const);
      return 1;
   }
#endif

   if (IS_PUT_INSTR_ENABLED) {
      IRDirty *dirtyP = MACRO_unsafeIRDirty_0_N(0,
            cgEmitPut,
            mkIRExprVec_5(
               mkIRExpr_UInt(offset),
               mkIRExpr_UInt(cg_GetTempOrConst(dataExpr)),
               mkIRExpr_UInt(dataTy),
               BT_ArgFixup(bb, dataExpr),
               mkIRExpr_UInt(DEBUG_MAGIC)
               )
            );

      /* So that VEX optimization knows what its register cache should be
       * invalidated...Seems to be essential. */
      dirtyP->nFxState = 1;
      dirtyP->fxState[0].fx = Ifx_Modify;
      dirtyP->fxState[0].offset = offset;
      dirtyP->fxState[0].size = cg_SizeOfIRType(dataTy);
      addStmtToIRSB(bb, IRStmt_Dirty(dirtyP));
   }

#if ENABLE_STORE_PUT
   return -1;
#else
   return 0;
#endif
}

static void
cgEmitPutI(Int base, IRType elemTy, Int nElems, IRTemp ixTmp, Int ix, 
      Int bias, IRTemp dataTmp, ...)
{
   Int offset = cgCalcArrayOffset(base, elemTy, nElems,
         ix, bias);
   size_t arrayLen = sizeofIRType(elemTy)*nElems;
   const char *dataValP = (char*)&dataTmp + sizeof(dataTmp);

   cgEmitPutWork(offset, base, arrayLen, ixTmp, dataTmp, elemTy, dataValP);
}

int
cg_InstrPutIStmt(IRSB * bb, const IRStmt * s)
{
   IRExpr *dataP = s->Ist.PutI.data;
   const IRRegArray *raP = s->Ist.PutI.descr;
   IRExpr *ixP = s->Ist.PutI.ix;
   const IRTemp ixTmp = cg_GetTempOrConst(ixP);
   const Int bias = s->Ist.PutI.bias;
   const Int dataTmp = cg_GetTempOrConst(dataP);

#if DEBUG
   ASSERT(s->tag == Ist_PutI);
   const IRType ixTy = typeOfIRExpr(bb->tyenv, ixP);
   ASSERT(ixTy == Ity_I32);
   ASSERT(sizeof(UInt) == sizeofIRType(ixTy));
   const IRType dataTy = typeOfIRExpr(bb->tyenv, dataP);
   ASSERT(dataTy == raP->elemTy);
   ASSERT(dataP->tag == Iex_Const || dataP->tag == Iex_RdTmp);
#endif

   if (IS_PUT_INSTR_ENABLED) {
      addStmtToIRSB(bb,
            IRStmt_Dirty(
               MACRO_unsafeIRDirty_0_N(0,
                  cgEmitPutI,
                  mkIRExprVec_8(
                     mkIRExpr_UInt(raP->base),
                     mkIRExpr_UInt(raP->elemTy),
                     mkIRExpr_UInt(raP->nElems),
                     mkIRExpr_UInt(ixTmp),
                     ixP,
                     mkIRExpr_UInt(bias),
                     mkIRExpr_UInt(dataTmp),
                     BT_ArgFixup(bb, dataP)
                     )
                  )));
   }

#if ENABLE_STORE_PUT
   return -1;
#else
   return 0;
#endif
}

/* ---------- CAS (Load + Store) ---------- */

static void
cgEmitCAS(const IRTemp addrTmp, const HWord vaddr,
      const IRType accessTy, const IRTemp lhsTmp,
      const IRTemp expdTmp,
      const IRTemp dataTmp,
      struct PackedArgs argBuf)
{
   ASSERT(lhsTmp != IRTemp_INVALID);

#define NR_ARGS 3
   ULong argValA[NR_ARGS] = { 0 /* lhs/old */, 0 /* expd */, 0  /* data */ };
   IRType argTyA[NR_ARGS] = { accessTy, accessTy, accessTy };
   cg_UnpackArgs(argValA, argTyA, &argBuf, NR_ARGS);

   cgEmitTmpLoadWork(addrTmp, vaddr, accessTy, lhsTmp, argValA[0]);

   const char *dataValP = (const char *) &argValA[2];
   cgEmitStoreConditionalWork(1, addrTmp, vaddr, accessTy,
         lhsTmp, argValA[0],
         expdTmp, argValA[1],
         dataTmp, dataValP);
}

static ulong
cgWordCASOnlyIfConcPtr(void __user *usrP, const IRTemp addrTmp,
      const u32 expdLo, const u32 dataLo)
{
   ulong oldVal = expdLo;

   if (!env.is_value_det && cgIsSymbolicPtr(addrTmp)) {
      /* Don't do the CAS, since the symbolic pointer points to some
       * undetermined location. Doing so may corrupt untainted state
       * and screw up replay. Note that we do something similar for
       * loads as well. */
      return 0;
   }

   ASSERT_UPTR(usrP);

   /* XXX: we need only the old value, no need to make a write, because
    * that'll be done by cgMap_Update()... */
   if (cmpxchg_user(usrP, &oldVal, dataLo)) {
#if WANTS_SOUND_SYMBOLIC_STORES
      /* If there was a segfault at this insn, we should've handled it
       * already: a dynamic brkpt shoud've been isntalled at the start of
       * this insn and triggered, and the previously logged fault
       * processed. */
      ASSERT(0);
#endif
   }

   return oldVal;
}

int
cg_InstrCAS(IRSB *bb, const IRStmt *s)
{
   const IRCAS *casP = s->Ist.CAS.details;
   ASSERT_UNIMPLEMENTED_MSG(casP->oldHi == IRTemp_INVALID,
         "XXX: we need double-word cas support\n");

   IRExpr *addrExprP = casP->addr;
   IRExpr *expdExprP = casP->expdLo;
   IRExpr *dataExprP = casP->dataLo;

   const IRTemp addrTmp = cg_GetTempOrConst(addrExprP);

   const IRType lhsTy = typeOfIRExpr(bb->tyenv, casP->expdLo);
   const IRTemp lhsTmp = casP->oldLo;
   ASSERT(lhsTmp != IRTemp_INVALID);

   DEBUG_ONLY(const IRTemp expdTy = typeOfIRExpr(bb->tyenv, expdExprP);)
   const IRTemp expdTmp = cg_GetTempOrConst(expdExprP);

   DEBUG_ONLY(const IRType dataTy = typeOfIRExpr(bb->tyenv, dataExprP);)
   const IRTemp dataTmp = cg_GetTempOrConst(dataExprP);

   ASSERT(expdTy == lhsTy);
   ASSERT(dataTy == lhsTy);


   if (!ENABLE_STORE_PUT) {
      addStmtToIRSB(bb,
            IRStmt_Dirty(
               MACRO_unsafeIRDirty_1_N(lhsTmp, 0, cgWordCASOnlyIfConcPtr,
                  mkIRExprVec_4(
                     addrExprP,
                     mkIRExpr_UInt(addrTmp),
                     casP->expdLo,
                     casP->dataLo
                     )
                  )));
   }

   if (IS_CAS_INSTR_ENABLED) {
      addStmtToIRSB(bb, 
            IRStmt_Dirty(
               MACRO_unsafeIRDirty_0_N(0, cgEmitCAS,
                  mkIRExprVec_10(
                     mkIRExpr_UInt(addrTmp),
                     addrExprP,

                     mkIRExpr_UInt(lhsTy),
                     mkIRExpr_UInt(lhsTmp),

                     mkIRExpr_UInt(expdTmp),

                     mkIRExpr_UInt(dataTmp),

                     BT_ArgFixup(bb, IRExpr_RdTmp(lhsTmp)),
                     BT_ArgFixup(bb, expdExprP),
                     BT_ArgFixup(bb, dataExprP),
                     mkIRExpr_UInt(DEBUG_MAGIC)
                     )
                  )));
   }

#if ENABLE_STORE_PUT
   return 1; /* cgEmitCAS needs value of oldTmp to be filled in, so place after */
#else
   return 0;
#endif
}
