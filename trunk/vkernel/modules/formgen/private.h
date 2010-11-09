#pragma once


#define ASSUME_ALL_INPUTS_KNOWN 1

static INLINE int
IRTYPE2BITS(IRType ty)
{
   switch (ty) {
   case Ity_I1:
      return 1;
   default:
      return sizeofIRType(ty)*8;
      break;
   }

   NOTREACHED();
}
#define T2B(ty) IRTYPE2BITS(ty)

typedef enum {
   Mk_Reg = 0xc001,
   Mk_Gaddr,
} MapAddrKind;

typedef u64 MapAddr;

#define MAX_NR_RANGES 4
struct MAddrRange {
   MapAddrKind kind;

   MapAddr start;
   size_t len;
};




/* ---------------- Taint flow ---------------- */

#define MAX_NR_REGS offsetof(TaskRegs, padding1)
#define MAX_NR_TMPS 512


extern int  TaintMap_Init();
extern void TaintMap_Fini();
extern void TaintMap_OnVmaUnmap(const struct VmaStruct *vma, 
               ulong istart, size_t ilen);
extern void TaintMap_OnTaskExit(struct Task *tsk);
extern void TaintMap_OnTaskFork(struct Task *tsk);
extern void TaintMap_OnExit();
extern void TaintMap_OnFork();

extern void
TaintMap_TaintMem(const struct Task *tskP, const u64 startGaddr, size_t len, 
                  void **dataPA);
extern size_t
TaintMap_UntaintMem(const struct Task *tskP, const u64 startGaddr,
                    const size_t len, void **dataPA);
#if 0
extern size_t
TaintMap_IsMemTainted(const u64 *gAddrA, size_t len, void **dataPA);
#endif
extern size_t
TaintMap_IsMemRangeTainted(const u64 startGAddr, const size_t len, void **dataPA);
extern size_t
TaintMap_AreMemRangesTainted(const struct GAddrRange *gaddr_ranges, 
      const int nr_ranges, void **dataPA);

extern void
TaintMap_TaintReg(struct Task *tskP, UInt off, size_t len, void **dataPA);
extern int
TaintMap_UntaintReg(struct Task *tskP, UInt off, size_t len, void **dataPA);
extern void
TaintMap_UntaintTmp(IRTemp id);
extern int
TaintMap_IsRegTainted(const struct Task *tskP, UInt off, size_t len, void **dataPA);

typedef enum { TCode_TmpUntainted = 0, TCode_TmpUndefined, TCode_TmpDefined } TCode;
extern TCode
TaintMap_IsTmpTainted(IRTemp tmpName);
extern void
TaintMap_TaintTmp(IRTemp id, TCode tc);

#if 0
extern void TaintMap_EnablePageProt();
extern void TaintMap_DisablePageProt();
extern int
TaintMap_IsAddrProtected(ulong addr);
extern struct ASpaceProtStat *
TaintMap_IsPageProtOn();
#endif

struct ASpaceProtStat {
   struct MapField64 pageMap;
};


static INLINE int
cg_SizeOfIRType(IRType ty)
{
   return ty == Ity_I1 ? 1 : sizeofIRType(ty);
}

#if DEBUG
static INLINE void
TaintMap_VerifyTCode(TCode tc)
{
   ASSERT(tc == TCode_TmpUntainted ||
          tc == TCode_TmpUndefined ||
          tc == TCode_TmpDefined);
}
#endif

/* --- Symbolic map operations (i.e., constraint variable tracking) --- */

typedef enum { 
   CondVar_Tmp = 0xc001, 
   CondVar_Origin,
   CondVar_JointWrite,
   CondVar_ArrayWrite,
   CondVar_CAS,
} CondVarTag;

struct CondVar {
   CondVarTag tag;

   u64 bbExecCount;
   ssize_t len; /* for origins only */
   u64 name;

   int vcpu; /* VCPU id */
   int isDeclared;

   int count; /* ref count */
};

static INLINE int
CondVar_IsEqual(struct CondVar *aP, struct CondVar *bP)
{
   return (aP->name == bP->name &&
      aP->tag == bP->tag &&
      aP->bbExecCount == bP->bbExecCount &&
      aP->vcpu == bP->vcpu);
}

struct ByteVar {
   struct CondVar *cvP;

   size_t byte; /* byte index of CondVar */

   int count; /* ref count */
};


extern struct ByteVar * cg_GetByteVar(struct ByteVar *bvP);
static INLINE void
cg_GetByteVars(struct ByteVar **bvPA, const size_t len)
{
   int i;

   for (i = 0; i < len; i++) {
      cg_GetByteVar(bvPA[i]);
   }
}
extern int   cg_PutByteVar(struct ByteVar *bvP);

static INLINE int
cgByteVar_IsEqual(struct ByteVar *aP, struct ByteVar *bP)
{
   return aP->byte == bP->byte && CondVar_IsEqual(aP->cvP, bP->cvP);
}

/* ------------------- Symbolic map --------------------- */

typedef enum {
   Cbk_Symbolic = 0xc001,
   Cbk_Concrete,
} CgByteKind;

/* XXX: we could shorten this to 8 bytes if needed. */
struct CgByte {
   CgByteKind kind;
   union {
      struct ByteVar *bvP;
      uchar val;
   } Data;

   int count;
};


static INLINE struct CgByte *
cgByte_Get(struct CgByte *bP)
{
#if DEBUG
   if (bP->kind == Cbk_Symbolic) {
      struct ByteVar *bvP = bP->Data.bvP;

      ASSERT_KPTR(bvP);
      ASSERT(bvP->count > 0);
   } else {
      ASSERT(bP->kind == Cbk_Concrete);
   }
#endif

   bP->count++;

   return bP;
}

#if 0
static INLINE struct CgByte *
cgByte_Alloc()
{
   struct CgByte *bP = malloc(sizeof(*bP));

   memset(bP, 0, sizeof(*bP));

   return cgByte_Get(bP
}
#endif

static INLINE void
cgByte_Put(struct CgByte *bP)
{
   ASSERT_KPTR(bP);
   ASSERT(bP->count > 0);

   bP->count--;

   if (bP->count == 0) {
      if (bP->kind == Cbk_Symbolic) {
         ASSERT_KPTR(bP->Data.bvP);
         cg_PutByteVar(bP->Data.bvP);
         bP->Data.bvP = NULL;
      }

      free(bP);
      bP = NULL;
   }
}

static INLINE void
cgByte_PutAll(struct CgByte **bytePA, const size_t len)
{
   int i;

   for (i = 0; i < len; i++) {
      cgByte_Put(bytePA[i]);
      bytePA[i] = NULL;
   }
}

static INLINE int
cgByte_IsEqual(struct CgByte *aP, struct CgByte *bP)
{
   if (aP->kind == bP->kind) {
      if (aP->kind == Cbk_Symbolic) {
         return cgByteVar_IsEqual(aP->Data.bvP, bP->Data.bvP);
      } else {
         ASSERT(aP->kind == Cbk_Concrete);
         return aP->Data.val == bP->Data.val;
      }
   }

   return 0;
}


extern struct CondVar *
cgByte_MakeSymbolic(const CondVarTag tag, const u64 name, 
                   size_t len, struct CgByte **bytePA);
extern void
cgByte_MakeOrigin(const size_t len, struct CgByte **bytePA);
extern void
cgByte_MakeConcrete(const char *valA, size_t len, struct CgByte **bytePA);



extern void cgMap_OnTaskFork(struct Task *tsk);
extern void cgMap_OnTaskExit(struct Task *tsk);
extern void cgMap_OnVmaUnmap(const struct VmaStruct *vmaP, 
               ulong startAddr, size_t len);
extern void cgMap_OnVmaFork(struct Task *tskP, 
               const struct VmaStruct *vmaP);


extern int
cgMap_Read(const struct MAddrRange *srcRangeP, struct CgByte **bytePA);
extern int
cgMap_Write(const struct MAddrRange *dstRangeP, struct CgByte **bytePA);
extern void
cgMap_UpdateMAddr(const struct MAddrRange *dstRangeA, const int nrRanges,
             struct CgByte **bytePA);
extern void
cgMap_UpdateGAddr(const struct GAddrRange *dstRangeA, const int nrRanges,
             struct CgByte **bytePA);
extern void
cgMap_UpdateVAddr(const ulong vaddr, struct CgByte **bytePA, 
                const size_t len);
extern void
cgMap_WriteOrigin(const ulong vaddr, const size_t len);


/* ---------------- Constraint generation ---------------- */


struct PackedArgs
{
   char buf[sizeof(ULong)*8];

   /* Space for the magic if four Ity_I128's are supplied. */
   UInt magic;
};

extern void
cg_UnpackArgs(ULong *argValA, const IRType *tyA, const struct PackedArgs *bufP, 
              const int numArgs);

static INLINE int
cgIsSupportedType(IRType ty)
{
   return ((ty == Ity_I1) ||
           (ty == Ity_I8) ||
           (ty == Ity_I16) ||
           (ty == Ity_I32) ||
           (ty == Ity_I64));
}


/* ----- Constraint emit functions ----- */

extern void
cg_PrintVar(const CondVarTag kind, const int vcpuId, const u64 bbExecCount, 
            const u64 name);

static INLINE void
cg_PrintVarNow(CondVarTag kind, const u64 name)
{
   cg_PrintVar(kind, curr_vcpu->id, VA(bbExecCount), name);
}

static INLINE void
cg_PrintArrayVarNow(const u64 name)
{
   cg_PrintVarNow(CondVar_ArrayWrite, name);
}

static INLINE void
cg_PrintJointVarNow(const u64 name)
{
   cg_PrintVarNow(CondVar_JointWrite, name);
}

static INLINE void
cg_PrintTmpVarNow(const u64 name)
{
   cg_PrintVarNow(CondVar_Tmp, name);
}

extern void
cg_PrintLocalVarNow(const char *nameStr, const u64 idx);

static INLINE void
cg_StartNewLocalScope()
{
   VA(localScope)++;
}

extern void
cg_DeclareCondVar(const CondVarTag kind, const int vcpuId, 
                  const u64 bbExecCount, const u64 name, const size_t lenInBits);

static INLINE void
cg_DeclareTmp(const IRTemp tmpName, const IRType ty)
{
   cg_DeclareCondVar(CondVar_Tmp, curr_vcpu->id, VA(bbExecCount), tmpName, 
         T2B(ty));
}

static INLINE void
cg_DeclareJointWrite(const u64 name)
{
   cg_DeclareCondVar(CondVar_JointWrite, curr_vcpu->id, VA(bbExecCount),
         name, T2B(Ity_I8));
}

static INLINE void
cg_DeclareArrayWrite(const u64 name)
{
   cg_DeclareCondVar(CondVar_ArrayWrite, curr_vcpu->id, VA(bbExecCount),
         name, T2B(Ity_I8));
}

static INLINE void
cg_DeclareCAS(const u64 name, const IRType ty)
{
   cg_DeclareCondVar(CondVar_CAS, curr_vcpu->id, VA(bbExecCount),
         name, T2B(ty));
}


extern void cgPrint_Commit();
extern void cgPrint_InitVCPU(struct VCPU *);
extern void cg_PrintCondVar(const struct CondVar *);
extern void cg_PrintByteVar(const struct ByteVar *);
extern void cg_PrintSymByte(const struct CgByte *bP);
extern void CgenOut(const char *fmt, ...);

static INLINE void
cg_LazyDeclareIfNeeded(struct CondVar *cvP)
{
   /* Origins are not declared until they are actually used; this
    * optimization ensures that there aren't a million sub-formulas 
    * each with just an origin declaration. */
   if (cvP->tag == CondVar_Origin && !cvP->isDeclared) {
      cg_DeclareCondVar(CondVar_Origin, cvP->vcpu, cvP->bbExecCount,
            cvP->name, cvP->len*8);
      cvP->isDeclared = 1;
      ASSERT(cvP->isDeclared);
   }
}

#if 0
static INLINE void
cg_EmitMemOrigin(const u64 *gAddrA, const size_t len)
{
   ASSERT(len > 0);
   ASSERT_KPTR(gAddrA);

#if 0
   /* This has the benefit of generating fewer origin variables, but we 
    * won't able to split the formula into many independent units. */
   cg_TaintMemWithOrigin(VA(originCounter), gAddrA, len);
   VA(originCounter++);
#else
   /* We'll get better formula splitting with this, as
    * it allows the splitter to treat each byte of input a
    * a different variable. */
   size_t i;
   for (i = 0; i < len; i++) {
      cg_TaintMemWithOrigin(VA(originCounter), gAddrA+i, 1);
      VA(originCounter++);
   }
#endif

}

static INLINE void
cg_EmitRegOrigin(const HWord regOff, const size_t len)
{
   ASSERT(len > 0);

   /* Q: Is there any sense in treating each register byte as
    * a different origin? 
    * A: It'll result in better splits, since operations on a few bytes
    * will be disjoint from the others. */
   cg_TaintRegWithOrigin(VA(originCounter), regOff, len);
   VA(originCounter++);
}
#endif


#define CG_ORIGIN_DEV  (1 << 0)
#define CG_ORIGIN_DATA (1 << 1)
#define CG_ORIGIN_FILE (1 << 2)
#define CG_ORIGIN_INET (1 << 3)
#define CG_ORIGIN_PIPE (1 << 4)
#define CG_ORIGIN_UNIX (1 << 5)

extern int cgForcedOriginFlags;

/* ----- IR instrumentation routines. ----- */

extern void
Cgen_UserCopyCB(
      const int isRead,
      const struct CopySource *srcP, 
      const struct IoVec *iov_ptr,
      const size_t totalLen);
extern void 
Cgen_RegCopyCB(
      const int isRead,
      const struct CopySource *srcP, 
      const uint offset, 
      const size_t len);


extern void cg_InstrTmpUnop(IRSB * bb, const IRStmt * s);
extern int  cg_InstrTmpBinop(IRSB * bb, const IRStmt * s);
extern void cg_InstrTmpTriop(IRSB * bb, const IRStmt * s);
extern void cg_InstrTmpCCall(IRSB * bb, const IRStmt * s);
extern void cg_InstrTmpMux0X(IRSB * bb, const IRStmt * s);

extern void cg_InstrTmpGet(IRSB *bb, const IRStmt *s);
extern void cg_InstrTmpGetI(IRSB *bb, const IRStmt *s);
extern int  cg_InstrTmpLoad(IRSB *bb, const IRStmt *s);
extern void cg_InstrDirtyLoadF80(IRSB *bb, const IRStmt *s);

extern int  cg_InstrPutStmt(IRSB * bb, const IRStmt * s);
extern int  cg_InstrPutIStmt(IRSB * bb, const IRStmt * s);
extern int  cg_InstrStoreStmt(IRSB * bb, const IRStmt * s);
extern void cg_InstrDirtyStoreF80(IRSB *bb, const IRStmt *s);
extern int  cg_InstrPreExit(IRSB * bb, const IRStmt * s);
extern int  cg_InstrCondExit(IRSB *bbOut, ulong currInsAddr, ulong currInsLen, IRStmt *st);
extern void cg_InstrNonCondExit(IRSB *bbOut, ulong currInsAddr, ulong currInsLen);
extern int  cg_InstrCAS(IRSB * bb, const IRStmt * s);
extern void cg_InstrDirty(IRSB *, const IRStmt *);
extern IRSB* Cgen_Instrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
                             VexGuestExtents *extents, IRType gWorTy,
                             IRType hWordTy);




static INLINE IRTemp
cg_GetTempOrConst(const IRExpr *expP)
{
   IRTemp tmp;

   if (expP->tag == Iex_RdTmp) {
      tmp = expP->Iex.RdTmp.tmp;
      ASSERT(tmp != IRTemp_INVALID);
   } else {
      ASSERT(expP->tag == Iex_Const);
      tmp = IRTemp_INVALID;
   }

   return tmp;
}

struct ArgStruct {
   IRExprTag tag;

   UInt ty;

   Int tmp; /* -1 if const */

   ULong val;
};


extern void
cg_PrintArg(const IRType ty, const struct ArgStruct *argP);
extern void
cg_MkArg(struct ArgStruct *argP, UInt ty, Int tmp, ULong val);
extern TCode
cg_IsArgTainted(IRTemp argTmp);
extern int
cg_PropagateOpTaint(const IRTemp lhsTmp, const IRType lhsTy, 
      const TCode *argA, const int numArgs);

static INLINE int
cgShouldSkipCgen(const IRType lhsTy)
{
   return current->isInsnUnconstrained || !cgIsSupportedType(lhsTy);
}


static INLINE Int
cgCalcArrayOffset(Int base, IRType elemTy, Int nElems, Int ix, Int bias)
{
   size_t len = sizeofIRType(elemTy);

   ASSERT(nElems > 0);
   Int idx = ((ix + bias) % nElems);
   if (idx < 0) {
      idx = nElems + idx;
   }

   ASSERT(base >= 0)
   Int offset = base + (idx * len);

   ASSERT_MSG(idx >= 0 && idx < nElems, "ix=%d bias=%d nElems=%d idx=%x offset=%x\n", ix, bias, nElems, idx, offset);

   return offset;
}

typedef void (*InstrFn)(IRSB *, const IRStmt *);

struct InstrCall {
   char name[256];
   InstrFn fn;
};

#if 0
#define DIRTY(name, argC, ...) \
   unsafeIRDirty_0_N(0, #name, &name, ##__VA_ARGS__);

#if DEBUG
#define DIRTY_PACKED_X(name, argC, ...) \
   unsafeIRDirty_0_N(0, #name, &name, \
         mkIRExpr_Vec_#argC(##__VA_ARGS__, \
            mkIRExpr_UInt(DEBUG_MAGIC)))
#define DIRTY_PACKED(name, argC, ...) \
   DIRT_PACKED_X(name, (argC
#else
#define DIRTY_PACKED(name, argC, ...) \
   unsafeIRDirty_0_N(0, #name, &name, \
         mkIRExpr_Vec_#argC(##__VA_ARGS__))
#endif
#endif


/* ---------- Profiling functions ---------- */

struct CgenInsnNode {
   struct MapField64 offMap;

   u64 nrCnstr;     // # of constraints generated by insn
   u64 nrExec; // # of times insn was executed
};

struct CgenFileNode {
   struct MapField64 fileMap;

   struct MapStruct *insnMapP;
   char name[512];
   int isUnconstrained;
};

static INLINE struct CgenInsnNode*
cgGetInsnProf()
{
   return (struct CgenInsnNode*) current->cgCurrInsnP;
}

static INLINE struct CgenFileNode*
cgGetInsnBinary()
{
   return (struct CgenFileNode*) current->cgCurrBinP;
}

static INLINE void
cgProf_UpdateCounter()
{
   struct CgenInsnNode *cP = cgGetInsnProf();

   if (cP) {
      cP->nrCnstr++;

      ASSERT(cP->nrCnstr > 0);
   }
}

typedef enum
{
  Pak_Load = 0xc001,
  Pak_Store,
} ProfAccessKind;

extern void
cgProf_AddAccess(const ProfAccessKind kind, const ulong vaddr);
extern void
cgProf_OnResumeUserMode();
extern void
cgProf_MoveToInsn(const HWord eip);
extern void
cgProf_Init();
extern void
cgProf_Fini();

extern u64 cgProf_NrTaintedInBytes;
extern u64 cgProf_NrTaintedOutBytes;
extern u64 cgProf_NrTotalInBytes;
extern u64 cgProf_NrTotalOutBytes;


extern int cg_OptOutputFormula;

struct CgenBBoxRegion {
   char dsoName[256];
   ulong start;
   ulong end;
};

#define MAX_BBOX_REGIONS 32
extern int cg_OptNumBBoxReg;
extern struct CgenBBoxRegion cg_OptBBoxRegA[MAX_BBOX_REGIONS];

/* ---------------- Path selector --------------- */

typedef enum {
   Pbk_Cond = 0xc001,
   Pbk_DirectCall,
   Pbk_DirectJump,
   Pbk_IndJump,
   Pbk_IndCall,
   Pbk_Ret,
} PsBranchKind;

typedef enum {
   Pck_Fork = 0xc001,
   Pck_Cont,
   Pck_Abandon
} PathSelCmd;

struct PathSelector {
   u64 pathId, brId;
   ulong selTarget;
   void (*onFork)(struct PathSelector *, ulong);
   int (*onJoin)(struct PathSelector *);
   PathSelCmd (*getBranchTarget)(struct PathSelector *, ulong *targetP);
   void (*advanceBranch)(struct PathSelector *, const PsBranchKind, 
         const ulong dstIP, const ulong retIP);
   int (*onInit)(struct PathSelector *);
   void (*onTaskEnter)(struct PathSelector *);
   void (*onTaskExit)(struct PathSelector *);
};

extern struct PathSelector *cgPsP;
extern void cgPsel_Init();
extern void cgPsel_OnTaskStart();
extern void cgPsel_OnTaskTerm();

/* -------------- Symbolic context -------------- */


struct UndoByte {
   struct MapField64 addrMap;

   struct CgByte *byteP;
   int count;
};

struct WriteByte {
   struct MapField64 addrMap;
};

extern struct cgCkpt * cgCkpt_Alloc();
extern void   cgCkpt_Free(struct cgCkpt *);
extern void   cgCkpt_UnionWrSet(struct MapStruct *dstSetP, 
      const struct cgCkpt *srcSetP);
extern void   cgCkpt_Restore(const struct cgCkpt *);

extern struct cgCkpt * cgCkptStack_PeekTop();
extern struct cgCkpt * cgCkptStack_Pop();
extern void  cgCkptStack_Push(struct cgCkpt *);
extern void  cgCkptStack_GetWriteSet(struct MapStruct *wrSetP);
extern void  cgCkptStack_PushNew();

extern void
cgCkptStack_OnPreUpdate(const struct MAddrRange *rP);

extern void cgCkptStack_Init();

/* ---------- Exits ---------- */

extern void
cg_BranchCond(const u64 joinId, const u64 pathId, const u64 brId);
extern void cgExit_EmitNonInlinePathCond(const u64 joinId, const u64 pathId);
extern void cgExit_EmitNonInlinePathCond2(const u64 joinId, const u64 pathId);
extern void cg_BranchFini();


/* ---------- Join point ---------- */

extern void cgJoin_InitVCPU(struct VCPU *);
extern void cgJoin_OnResumeUserMode();

/* ---------- CFG ---------- */

extern void CFG_Init();
extern void CFG_OnVmaMap(const struct VmaStruct *vmaP);

/* ---------- Pointer regions ----------- */
#define MAX_PTR_REGIONS 100

extern struct VirtRange ptrRegions[MAX_PTR_REGIONS];
extern int nrPtrRegions;
extern void
cgPtr_OnVmaEvent(const VmaEventKind evk, const struct VmaStruct *vmaP,
             const ulong istart, const size_t ilen);


#include "macros.h"
