/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

#if 0
#undef LOG
#define LOG(s, ...)
#endif


/* ---------- Module options ---------- */
int                   cg_OptOutputFormula = 1;
int                   cg_OptEnableProfiling = 1;
struct CgenBBoxRegion cg_OptBBoxRegA[MAX_BBOX_REGIONS];
int                   cg_OptNumBBoxReg = 0;
int                   cg_OptUseMMU = 0;

static int wantsCgen = 0;
static int wantsComments = 1;



/* ---------- Instrumentation main loop ---------- */

static void
cgIMark(TaskArchState *archSt, const HWord eip)
{
   /* Don't use @archSt->vex.guest_EIP since that may not
    * be updated yet. Used @eip instead. */

   if (cg_OptEnableProfiling) {
      cgProf_MoveToInsn(eip);

      current->isInsnUnconstrained = cgGetInsnBinary()->isUnconstrained; 
   }

   DEBUG_MSG(5, "=== IMARK <0x%lx, 0x%x, %llu, %llu> ===\n",
            eip, archSt->vex.guest_ECX, BrCnt_Get(), VA(bbExecCount));

#if 1
   if (DEBUG_LEVEL(7)) {
      CG_COMMENT("\n");
      CG_COMMENT("=== IMARK <0x%lx, 0x%x, %llu, %llu> ===\n",
            eip, archSt->vex.guest_ECX, BrCnt_Get(), VA(bbExecCount));
      CG_COMMENT("\n");
   }
#endif
}

static void
cgInstrIMark(IRSB* bb, IRStmt *s)
{
   IRDirty *dirty;

   dirty = unsafeIRDirty_0_N(0, 
         "cgIMark",
         &cgIMark,
         mkIRExprVec_1(
            mkIRExpr_HWord(s->Ist.IMark.addr)
            )
         );
   dirty->needsBBP = True;
   dirty->nFxState = 1;
   dirty->fxState[0].fx = Ifx_Read;
   dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_ECX);
   dirty->fxState[0].size = 4;

   addStmtToIRSB(bb, IRStmt_Dirty(dirty));
}

static int
cgInstrTmp(IRSB * bb, const IRStmt * s)
{
   IRExpr * rhs = s->Ist.WrTmp.data;

   ASSERT(bb);
   ASSERT(s);
   ASSERT(s->tag == Ist_WrTmp);

   switch (rhs->tag) {
   case(Iex_Get):
      if (1) cg_InstrTmpGet(bb, s);
      break;

   case(Iex_GetI):
      if (1) cg_InstrTmpGetI(bb, s);
      break;

   case(Iex_Load):
      if (1) return cg_InstrTmpLoad(bb, s);
      break;

   case(Iex_Mux0X):
      if (1) cg_InstrTmpMux0X(bb, s);
      break;

   case(Iex_Binop):
      if (1) return cg_InstrTmpBinop(bb, s);
      break;

   case(Iex_Triop):
      cg_InstrTmpTriop(bb, s);
      break;

   case(Iex_Unop):
   case(Iex_RdTmp):
   case(Iex_Const):
      cg_InstrTmpUnop(bb, s);
      break;

   case(Iex_CCall):
      if (1) cg_InstrTmpCCall(bb, s);
      break;

   default:
      ppIRStmt((IRStmt*)s);
      ASSERT_UNIMPLEMENTED_MSG(0, "Unhandled Ist_WrTmp\n");
      break;
   }

   return 1;
}

typedef enum {
   Place_BeforeStmt,
   Place_AfterStmt,
   Place_OmitStmt,
} IntrPlacement;

static int
CgenIRStmt(IRSB* bb, ulong currInsAddr, ulong currInsLen, IRStmt* s)
{
   ASSERT_KPTR(bb);
   ASSERT_KPTR(s);

   switch (s->tag) {
   case Ist_IMark:
      if (1) cgInstrIMark(bb, s);
      break;
   case Ist_Put:
      if (1) return cg_InstrPutStmt(bb, s);
      break;
   case Ist_PutI:
      if (1) return cg_InstrPutIStmt(bb, s);
      break;
   case Ist_Store:
      if (1) return cg_InstrStoreStmt(bb, s);
      break;
   case Ist_WrTmp:
      if (1) return cgInstrTmp(bb, s);
      break;
   case Ist_Dirty:
      if (1) cg_InstrDirty(bb, s);
      break;
   case Ist_CAS:
      if (1) return cg_InstrCAS(bb, s);
      break;
   case Ist_Exit: 
      if (1) return cg_InstrCondExit(bb, currInsAddr, currInsLen, s);
      break;
   case Ist_AbiHint:
   case Ist_NoOp:
   case Ist_MBE:
      break;
   default:
      ppIRSB(bb);
      ppIRStmt(s);
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   return 1 /* 1 <--> place after the stmt */;
}

static void
cg_DirtyHelper_BB_Start_NoMMU()
{
   VA(bbExecCount)++;

#if 0
   /* We don't know which exit in this IRSB will cause a fork, so we
    * assume that one will and maintain the undo state for it. */
   if (curr_vcpu->bbSetP) {
      if (curr_vcpu->isJoinPending) {
         struct cgCkpt *topP = cgCkptStack_PeekTop();
         ASSERT_KPTR(topP);

         /* We can only recover to IRSB boundaries; insns boundaries may
          * not be up-to-date due to VEX optimization. */
         cgCkpt_Union(topP, curr_vcpu->bbSetP);
      }

      cgCkpt_Free(curr_vcpu->bbSetP);
      curr_vcpu->bbSetP = NULL;
   } else {
      /* First IRSB executed. */
   }

   if (curr_vcpu->isJoinPending) {
      curr_vcpu->bbSetP = cgCkpt_Alloc();
   }
#endif
}

static void
cgInstrBBStart(IRSB *bb, VexGuestExtents *vgeP)
{
   IRDirty *d = NULL;

   d = unsafeIRDirty_0_N(0,
         "cg_DirtyHelper_BB_Start_NoMMU",
         &cg_DirtyHelper_BB_Start_NoMMU,
         mkIRExprVec_0(
            )
         );
   addStmtToIRSB(bb, IRStmt_Dirty(d));
}

#if 0
static INLINE void
catIRSB(IRSB *aP, const IRSB *bP)
{
   ASSERT_KPTR(aP);
   ASSERT_KPTR(bP);
   ASSERT(bP->stmts_used > 0);

   int i;

   for (i = 0; i < bP->stmts_used; i++) {
      addStmtToIRSB(aP, bP->stmts[i]);
   }
}
#endif

IRSB*
Cgen_Instrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *vgeP, IRType guestWordTy, 
      IRType hWordTy)
{
   int i;
   IRSB *bbOut;
   ulong currInsAddr = 0, currInsLen = 0;

   ASSERT(vgeP->n_used == 1);
   ASSERT(bbIn->stmts_used > 0);
   ASSERT(guestWordTy == Ity_I32);

   bbOut = emptyIRSB();
   bbOut->tyenv = deepCopyIRTypeEnv(bbIn->tyenv);
   bbOut->jumpkind = bbIn->jumpkind;
   bbOut->next = deepCopyIRExpr(bbIn->next);

   for (i = 0; i < bbIn->stmts_used; i++) {
      IRStmt *st = bbIn->stmts[i];

      if (st->tag == Ist_IMark) {
         if (!currInsAddr) {
            /* First IMark of IRBB. */
            cgInstrBBStart(bbOut, vgeP);
         }
         currInsAddr = st->Ist.IMark.addr;
         currInsLen = st->Ist.IMark.len;
      }

      if (!currInsAddr) {
         /* Skip instrumentation of IR preamble if it exists.
          * Skip instrumentation of all stmts if cg is
          * disabled. */
         addStmtToIRSB(bbOut, st);
         continue;
      }

      addStmtToIRSB(bbOut, st);
      int stPos = bbOut->stmts_used-1;
      ASSERT(stPos >= 0);

      int res = CgenIRStmt(bbOut, currInsAddr, currInsLen, st);
      if (res > 0) {
         /* The common case: nothing needs to be done. */
      } else {
         /* Move all statements below the stmt up, hence replacing the
          * stmt. */
         int j;
         for (j = stPos+1; j < bbOut->stmts_used; j++) {
            bbOut->stmts[j-1] = bbOut->stmts[j];
         }
         bbOut->stmts_used--;

         if (res < 0) {
            addStmtToIRSB(bbOut, st);
         } else {
            ASSERT(res == 0);
         }
      } 
   }

   if (1) cg_InstrNonCondExit(bbOut, currInsAddr, currInsLen);

   return bbOut;
}

void
Cgen_OnTaskFork(struct Task *tskP)
{
   cgMap_OnTaskFork(tskP);

   current->isInsnUnconstrained = 0;
}

void
Cgen_OnTaskExit(struct Task *tskP)
{
   cgMap_OnTaskExit(tskP);
}

static void
CgenOnVmaEvent(const VmaEventKind evk, const struct VmaStruct *vmaP,
               const ulong istart, const size_t ilen)
{
   switch (evk) {
   case Vek_Map:
      //CFG_OnVmaMap(vmaP);
      break;
   case Vek_Unmap:
      cgMap_OnVmaUnmap(vmaP, istart, ilen);
      break;
   default:
      break;
   }

   cgPtr_OnVmaEvent(evk, vmaP, istart, ilen);
}

/* ---------- Module fini ---------- */

#if 0
static void
CgenOutVCPU(struct VCPU *vcpu, const char *fmt, ...)
{
   va_list args;

   if (cg_OptOutputFormula) {
      va_start(args, fmt);
      vfprintf(vcpu->cgenFile, fmt, args);
      va_end(args);
   }
}
#endif

void
Cgen_Fini()
{
   int i;

   cg_BranchFini();

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpuP = VCPU_Ptr(i);

#if 0
      if (cg_OptOutputFormula) {
         CgenOutVCPU(vcpuP, "QUERY(FALSE);\n");

#if 0
         ASSERT(vcpuP->cgenFile);
         fclose(vcpuP->cgenFile);
#endif
      }
#endif
      Log_Close(&vcpuP->cgLog);
   }

   cgProf_Fini();
   TaintMap_Fini();

}

#if 0
/* Commented out, because initially my plan was to setup the next join
 * point after each join point has been hit. But this won't work easily
 * in the case of multiple threads. We can't set the next join point on
 * the current one because it may occur in a different address space.
 *
 * It's best to just do a check for join point setup on user-mode
 * resumption (i.e., context switch points). If it hasn't been set up 
 * then do it.
 */
static void
CgenOnSyscall()
{
   cgExit_OnJoinPoint();
}

static void
CgenOnPreempt()
{
   ASSERT_UNIMPLEMENTED(0);
   cgExit_OnJoinPoint();
}
#endif

static void
CgenOnResumeUserMode()
{
   cgJoin_OnResumeUserMode();
   cgProf_OnResumeUserMode();
}

static void
CgenOnStart()
{
   cgPsel_OnTaskStart();
}

static void
CgenOnTerm()
{
   cgPsel_OnTaskTerm();
}


static size_t
CgenGetNrBytesTainted(const ulong start, size_t len)
{
   struct GAddrRange gaddr_ranges[MAX_NR_RANGES];
   int nr_ranges = MAX_NR_RANGES;
   const int isRead = 1;

   GlobalAddr_FromRange2(current->mm, gaddr_ranges, &nr_ranges, start, 
         len, isRead);
   return TaintMap_AreMemRangesTainted(gaddr_ranges, nr_ranges, NULL);
}

static void
CgenAssertConcrete(const ulong start, const size_t len)
{
   const size_t nr_bytes_tainted = CgenGetNrBytesTainted(start, len);
   if (nr_bytes_tainted != 0) {
      LOG("Assert concrete failed: start=0x%x len=%d (%d bytes)\n", 
            start, len, nr_bytes_tainted);
      ASSERT(0);
   }
}

static void
CgenAssertSymbolic(const ulong start, const size_t len)
{
   const size_t nr_bytes_tainted = CgenGetNrBytesTainted(start, len);
   if (nr_bytes_tainted != len) {
      LOG("Assert symbolic failed: start=0x%x len=%d nr_bytes_tainted=%d\n"
            , start, len, nr_bytes_tainted);
      ASSERT(0);
   }
}

static int
CgenOnClientRequest(const int reqNo, const HWord *argA, HWord *retValP)
{
   int wasHandled = 1;

   switch (reqNo) {
      /* XXX: move to formgen module; this requires implementing a
       * Module_OnClientRequest callback. */
   case VK_USERREQ__CG_ADD_PTR_REGION: 
   case VK_USERREQ__CG_RM_PTR_REGION:
      ASSERT(0);
      if (reqNo == VK_USERREQ__CG_ADD_PTR_REGION) {
         ulong start = argA[1];
         size_t len = argA[2];
         DEBUG_MSG(5, "start=0x%x len=%lu\n", start, len);
         *retValP = Cgen_AddPtrRegion(start, len);
      } else {
         ASSERT(reqNo == VK_USERREQ__CG_RM_PTR_REGION);
         int id = argA[1];
         DEBUG_MSG(5, "id=%lu\n", id);
         *retValP = Cgen_RmPtrRegion(id);
      }
      break;

   case VK_USERREQ__CG_ASSERT_CONCRETE: {
      const ulong start = argA[1];
      const size_t len = argA[2];
      CgenAssertConcrete(start, len);
      break;
   }

   case VK_USERREQ__CG_ASSERT_SYMBOLIC: {
      const ulong start = argA[1];
      const size_t len = argA[2];
      CgenAssertSymbolic(start, len);
      break;
   }

   case VK_USERREQ__MARK_MEMORY: 
   case VK_USERREQ__MARK_ASSERT_MEMORY: {
      const ulong start = argA[1];
      const size_t len = argA[2];
      const VkPlaneTag plane_tag = argA[3];

      if (reqNo == VK_USERREQ__MARK_MEMORY) {
         switch (plane_tag) {
         case VK_PLANE_DATA:
            cgMap_WriteOrigin(start, len);
            break;
         case VK_PLANE_CONTROL:
            ASSERT_UNIMPLEMENTED(0);
            break;
         case VK_PLANE_UNKNOWN:
            ASSERT_UNIMPLEMENTED(0);
            break;
         default:
            ASSERT(0);
            break;
         }
      } else {
         switch (plane_tag) {
         case VK_PLANE_DATA:
            CgenAssertSymbolic(start, len);
            break;
         case VK_PLANE_CONTROL:
            CgenAssertConcrete(start, len);
            break;
         default:
            ASSERT(0);
            break;
         }
      }
      break;
   }

   default:
      wasHandled = 0;
      break;
   }

   return wasHandled;
}



/* ---------- Module init ---------- */

static struct Module mod = {
   .name          = "Formula Generation",
   .modeFlags     = 0xFFFFFFFF,
   .onForkFn      = Cgen_OnTaskFork,
   .onExitFn      = Cgen_OnTaskExit,
   .onStartFn     = CgenOnStart,
   .onTermFn      = CgenOnTerm,
   .onVmaEventFn  = CgenOnVmaEvent,
   .onShutdownFn  = Cgen_Fini,
   .instrFn       = Cgen_Instrument,
   .onUserCopyFn  = Cgen_UserCopyCB,
   .onRegCopyFn   = Cgen_RegCopyCB,
#if 0
   .onSyscallFn   = CgenOnSyscall,
   .onPreemptFn   = CgenOnPreempt,
#endif
   .onResumeUserFn = CgenOnResumeUserMode,
   .onClientReqFn = CgenOnClientRequest,
   .order         = MODULE_ORDER_PRECORE
};

#if !CG_SLOW_WRITE
static PROCESSAREA uint cgLogLocalRotationGeneration[MAX_NR_VCPU] = { 0 };
#endif

static void
CgenOpenOutFile(struct VCPU *vcpuP)
{
#if CG_SLOW_WRITE
   char *fileStr = malloc(PATH_MAX);

   snprintf(fileStr, PATH_MAX, "%s/vcpu-%d.dc",
         session.dir, vcpuP->id);

   DEBUG_MSG(5, "cgenFile=%s\n", fileStr);
   vcpuP->cgenFile = fopen(fileStr, "w+");
   ASSERT(vcpuP->cgenFile);
   CG_COMMENT("STP Constraint File (VCPU %d)\n", vcpuP->id);
   free(fileStr);
   fileStr = NULL;
#else
   const int optWantsLogging = 1, isProtectedInReplay = 0;

   Log_Setup(&vcpuP->cgLog, "dc", vcpuP, cgLogLocalRotationGeneration,
         optWantsLogging, isProtectedInReplay);
#endif
}

static int
CgenInit()
{
   int i;

   if (!wantsCgen) {
      return 0;
   }

#if MAX_NR_VCPU > 1
   ASSERT_UNIMPLEMENTED_MSG(0, 
         "Locking not done properly in module."
         "Compile with PRODUCT=1 to reveal problems.");
#endif

   Module_Register(&mod);

   TaintMap_Init();

   Cgen_OnTaskFork(current);

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpuP = VCPU_Ptr(i);
      vcpuP->pcMapP = Map_Create(0);
      vcpuP->bbExecCount = 0;
      vcpuP->jcCounter = 0;
      vcpuP->localScope = 0;
      vcpuP->originCounter = 0;
      vcpuP->joinCounter = 0;
      vcpuP->arrayCounter = 0;
      vcpuP->casCounter = 0;
      vcpuP->parityCounter = 0;


      if (cg_OptOutputFormula) {
         CgenOpenOutFile(vcpuP);
      }

      cgJoin_InitVCPU(vcpuP);
      cgPrint_InitVCPU(vcpuP);
   }

   /* XXX: do we need a different path selector for each CPU? */
   cgProf_Init();
   cgPsel_Init();
   cgCkptStack_Init();

   CFG_Init();

   return 0;
}

MODULE_INITCALL(CgenInit);

/* ---------- Option processing ---------- */

enum { ALL_OPT, DATA_OPT, DEV_OPT, FILE_OPT, INET_OPT, PIPE_OPT, UNIX_OPT };
static const char *const subOptTokens[] = {
   [ALL_OPT] = "all",
   [DATA_OPT] = "data",
   [DEV_OPT] = "dev",
   [FILE_OPT] = "file",
   [INET_OPT] = "inet",
   [PIPE_OPT] = "pipe",
   [UNIX_OPT] = "unix",
   NULL
};

enum { Opt_AssumeUnknown, Opt_GenForm, Opt_EnableProfiling };

static int
ParseOpt(int opt, const char *arg)
{
   int err = 0;

   wantsCgen = 1;

   switch (opt) {
   case Opt_AssumeUnknown:
      {
         int subOpt;
         char *saveP = NULL;

         /* strtok modified the src buffer ... piece of junk. */
         char argBuf[256];
         strncpy(argBuf, arg, sizeof(argBuf));

         while ((subOpt = MiscOps_GetNextSubOpt(argBuf, &saveP, 
                     subOptTokens)) != -1) {
            //eprintf("subOpt=%d\n", subOpt);
            switch (subOpt) {
            case ALL_OPT:
               cgForcedOriginFlags = ~0;
               break;
            case DATA_OPT:
               cgForcedOriginFlags |= CG_ORIGIN_DATA;
               break;
            case DEV_OPT:
               cgForcedOriginFlags |= CG_ORIGIN_DEV;
               break;
            case FILE_OPT:
               cgForcedOriginFlags |= CG_ORIGIN_FILE;
               break;
            case INET_OPT:
               cgForcedOriginFlags |= CG_ORIGIN_INET;
               break;
            case PIPE_OPT:
               cgForcedOriginFlags |= CG_ORIGIN_PIPE;
               break;
            case UNIX_OPT:
               cgForcedOriginFlags |= CG_ORIGIN_UNIX;
               break;
            case '?':
               eprintf("invalid origin subopt\n");
               err = -1;
               break;
            default:
               ASSERT(0);
               break;
            }
         }
      }
      break;
   case Opt_GenForm:
      cg_OptOutputFormula = Arg_ParseBool(arg);
      break;
   case Opt_EnableProfiling:
      cg_OptEnableProfiling = Arg_ParseBool(arg);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   };

   return err;
}

/* XXX: "DCGen.AssumeUnknown" --> "AssumeUnknown" */
static struct ModOpt optA[] = {
   [Opt_AssumeUnknown] = { "DCGen.AssumeUnknown", ParseOpt, Opk_Str, "",
      "Assumes inputs from any of the following are unknown: dev,file,inet,unix" },

   [Opt_GenForm] = { "DCGen.OutputFormula", ParseOpt, Opk_Bool, "1",
      "Output a formula (as opposed to just doing the analysis)" },

   [Opt_EnableProfiling] = { "DCGen.EnableProfiling", ParseOpt, Opk_Bool, "1",
      "Output per-instruction costraint profiles and stats" },

   { "", NULL, Opk_Bool, "", "" },
};

extern struct ModDesc MODULE_VAR(Base);

static struct ModDesc *depA[] = { &MODULE_VAR(Base), NULL };
static struct ModDesc *confA[] = { NULL };

MODULE_BASIC(
      DCGen,
      "Generates a determinism condition",
      depA,
      confA,
      optA,
      NULL);
