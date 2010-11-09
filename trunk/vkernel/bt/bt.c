#include "vkernel/public.h"
#include "private.h"

#include </usr/local/include/valgrind/valgrind.h>

static VexArchInfo          vai;
static VexArch              va;
static VexAbiInfo           vex_abiinfo;

/* 0 means don't do self check (faster, but not reliable in presense
 * of dynamically generated code). > 0 means do self check.
 * XXX: 1 should mean do self check for stack code */
static int btSelfCheckMode = 0;

int                  bt_x86_have_mxcsr = 0;

/* This is the optimization level that Valgrind runs on; so
 * presumably its the best tested. Lower levels are known to be
 * buggy (e.g., the JVM at opt level 0). 
 *
 * DEFAULT 2*/
#define SAFE_IROPT_LEVEL 2 /* also happens to be highest */

#if !DEBUG
#if SAFE_IROPT_LEVEL != 2
#error "XXX: BUG 41: Java needs opt level 2 to work with VEX 3.5"
#endif
#endif

static int optIROptLevel = SAFE_IROPT_LEVEL;

/* Try and resume in DE after running this IRSB. */
static INLINE IRJumpKind
BTModifyJumpToYield(IRJumpKind jk)
{
   switch (jk) {
   case Ijk_Boring:
   case Ijk_Call:
   case Ijk_Ret:
      /* By returing a Ijk_Yield VEX err code to the dispatcher,
       * we will force a mode selection decision to be made. */
      return Ijk_Yield;
      break;
   default:
      return jk;
      break;
   }
}

static IRSB*
BTInstrumentInsEmu(IRSB *bbIn)
{
   int i;

   for (i = 0; i < bbIn->stmts_used; i++) {
      IRStmt *st = bbIn->stmts[i];

      if (st->tag == Ist_Exit) {
         st->Ist.Exit.jk = BTModifyJumpToYield(st->Ist.Exit.jk);
      }
   }

   bbIn->jumpkind = BTModifyJumpToYield(bbIn->jumpkind);

   return bbIn;
}

static IRSB*
BTInstrumentBB(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   IRSB *bbOut = NULL;

   ASSERT(bbIn->stmts_used > 0);

   if (Task_IsDebugLevel(6)) {
      DEBUG_MSG(6, "Input BB\n");
      ppIRSB(bbIn);
   }

   for_each_module() {
      DEBUG_MSG(5, "Considering module: %s\n", 
            modp->name);
      if ((modp->modeFlags & VCPU_GetMode()) && modp->instrFn) {
         DEBUG_MSG(5, "Applying: %s\n", modp->name);
         ASSERT(strlen(modp->name) > 0);
         bbOut = modp->instrFn(opaque, bbIn, layout, extents, 
               gWorTy, hWordTy);
         bbIn = bbOut;
         if (Task_IsDebugLevel(7)) {
            ppIRSB(bbIn);
         }
      }
   } end_for_each_module;

   if (Task_TestFlag(current, TIF_INSEMU)) {
      bbOut = BTInstrumentInsEmu(bbIn);
   }
   bbIn = bbOut;

#if 0
   if (0) {
      bbOut = PreEx_Instr(opaque, bbIn, layout, extents, gWorTy, hWordTy);
   }
#endif

   bbIn = NULL;
   ASSERT(bbOut);

   if (Task_IsDebugLevel(6)) {
      DEBUG_MSG(6, "Output BB\n");
      ppIRSB(bbOut);
   }

   return bbOut;
}

static __attribute__((noreturn)) void 
failure_exit ( void ) 
{
   LibVEX_ShowAllocStats();
   ASSERT_MSG(0, "VEX failure!\n");
   exit(0);
}

/* logging output function */
static void 
log_bytes( HChar* str, Int nbytes ) 
{
   QUIET_DEBUG_MSG(0, "%s", str);
}

static Bool
chase_into_ok(void *opaque, Addr64 addr64)
{
   /* Since we're doing this a BBL at a time, we don't want to
    * double the work by chasing into a BBL that we will call
    * translate() on. */
   return False;
}

static Bool
BTDoSelfCheck()
{
   ASSERT(btSelfCheckMode >= 0 && btSelfCheckMode <= 2);

   if (btSelfCheckMode > 0) {
      return True;
   }

   return False;
}

void
BT_Translate(ulong bblAddr, uchar* codeBuf, size_t codeBufSz,
      int *codeBufSzUsed, VexGuestExtents *vge, void *InsCallback, 
      void* cbArg)
{
   VexTranslateArgs     vta;
   VexTranslateResult   tres;
   int do_self_check = BTDoSelfCheck();


   vta.arch_guest = va;
   vta.archinfo_guest = vai;
   vta.arch_host = va;
   vta.archinfo_host = vai;
   vta.abiinfo_both = vex_abiinfo;

   vta.guest_bytes = (UChar*)bblAddr;
   vta.guest_bytes_addr = (Addr64)bblAddr;
   vta.callback_opaque = cbArg;
   vta.chase_into_ok = &chase_into_ok;
   vta.preamble_function = NULL;
   vta.guest_extents = vge;
   vta.host_bytes = codeBuf; /* tmpBuf */
   vta.host_bytes_size = codeBufSz /* N_TMPBUF */;
   vta.host_bytes_used = codeBufSzUsed;

   vta.instrument1 = InsCallback;
   vta.instrument2 = NULL;

   vta.finaltidy = NULL;
   vta.do_self_check = do_self_check;
   vta.traceflags = 0;
   
   vta.dispatch = (void*)&BT_InnerLoop;

   if (Task_IsDebugLevel(6)) {
      vta.traceflags = VEX_TRACE_FE;
      //vta.traceflags = VEX_TRACE_VCODE;
   }

   tres = LibVEX_Translate(&vta);

   ASSERT(tres == VexTransOK);
   ASSERT(*codeBufSzUsed <= codeBufSz);
   ASSERT(*codeBufSzUsed > 0);
}

void
BT_TranslateBlock(ulong bblAddr, uchar* codeBuf, size_t codeBufSz,
     int *codeBufSzUsed, VexGuestExtents *vge)
{
   BT_Translate(bblAddr, codeBuf, codeBufSz, codeBufSzUsed,
         vge, &BTInstrumentBB, NULL);
}


/* Create a zeroed-out GDT. */
#define GDT_SIZE (VEX_GUEST_X86_GDT_NENT * sizeof(VexGuestX86SegDescr))
VexGuestX86SegDescr* 
BT_AllocZeroedX86GDT()
{  
   char *ptr;

   size_t nbytes = GDT_SIZE;

   ptr = SharedArea_Malloc(nbytes);
   memset(ptr, 0, nbytes);

   return (VexGuestX86SegDescr*) ptr;
}

static VexGuestX86SegDescr*
BTCloneX86GDT(struct Task *tsk)
{
   VexGuestX86SegDescr *gdtOut, *gdtIn;

   gdtIn = (VexGuestX86SegDescr*) Task_GetRegs(tsk)->guest_GDT;

   gdtOut = BT_AllocZeroedX86GDT();

   memcpy(gdtOut, gdtIn, GDT_SIZE);

   return gdtOut;
}

static void
BTFreeX86GDT(struct Task *tsk) {
   VexGuestX86SegDescr *gdt = 
      (VexGuestX86SegDescr*)Task_GetRegs(tsk)->guest_GDT;
   size_t nbytes = GDT_SIZE;

   if (gdt) {
      SharedArea_Free(gdt, nbytes);
      Task_GetRegs(tsk)->guest_GDT = 0;
   }
}

static void
BTInitGuest(struct Task *tsk)
{
   TaskRegs *regs = Task_GetRegs(tsk);

   /* Don't initialize since on forks/clones child inherits taskregs
    * from parent. And regs is already filled in with parent context. */
   /*LibVEX_GuestX86_initialise(regs);
    *regs = *(Task_GetCurrentRegs());*/

   ASSERT(curr_regs->guest_GDT == regs->guest_GDT);
   if (curr_regs->guest_GDT) {
      /* Child gets a copy of the GDT. */
      Task_WriteReg(regs, GDT, (HWord) BTCloneX86GDT(current)); 
   }
}

#define VGA_x86

#if defined(VGA_x86)
#  define VG_CLREQ_ARGS       guest_EAX
#  define VG_CLREQ_RET        guest_EDX
#elif defined(VGA_amd64)
#  define VG_CLREQ_ARGS       guest_RAX
#  define VG_CLREQ_RET        guest_RDX
#elif defined(VGA_ppc32) || defined(VGA_ppc64)
#  define VG_CLREQ_ARGS       guest_GPR4
#  define VG_CLREQ_RET        guest_GPR3
#else
#  error Unknown arch
#endif

#define CLREQ_ARGS(regs)   (regs->VG_CLREQ_ARGS)
#define CLREQ_RET(regs)    (regs->VG_CLREQ_RET)
#define O_CLREQ_RET        (offsetof(VexGuestArchState, VG_CLREQ_RET))

// These macros write a value to a client's thread register, and tell the
// tool that it's happened (if necessary).

#define SET_CLREQ_RETVAL(zzval) \
   do { CLREQ_RET(Task_GetCurrentRegs()) = (zzval); \
   } while (0)

static void 
BTDoClientRequest ()
{
   HWord* arg = (HWord*)(CLREQ_ARGS(Task_GetCurrentRegs()));
   HWord req_no = arg[0];

   DEBUG_MSG(5, "req no = 0x%llx, arg = %p\n", (ULong)req_no, arg);

   // XXX: rename to session.optHonorClientRequests
   if (!session.optUseAnnotations) {
      return;
   }

   switch (req_no) {
   case VG_USERREQ__CLIENT_CALL0: {
      HWord lvl = (HWord)arg[1];

      DEBUG_MSG(5, "client request: SET DEBUG LEVEL, lvl %d\n", lvl);
      SET_CLREQ_RETVAL(debug_level);
      debug_level = lvl;
      break;
   }

   case VG_USERREQ__PRINTF: {
      DEBUG_MSG(5, "client request: PRINTF\n");
      Int count = 
         vlprintf(CURRENT_LFD, (char *)arg[1], (void*)arg[2] );
      SET_CLREQ_RETVAL( count );
      break; 
   }
   case VG_USERREQ__DISCARD_TRANSLATIONS:
      DEBUG_MSG(5, "client request: DISCARD_TRANSLATIONS,"
            " addr %p,  len %lu\n",
            (void*)arg[1], arg[2] );

      TrnsTab_Invalidate(arg[1], arg[2]);
      SET_CLREQ_RETVAL(0);     /* return value is meaningless */
      break;

   case VK_USERREQ__MARK_FILE_BY_INO: {
      const int plane_tag = arg[1];
      const ulong dev = arg[2];
      const ulong ino = arg[3];

      File_MarkFileByIno(plane_tag, dev, ino);
      SET_CLREQ_RETVAL(0);
      break;
   }

   case VK_USERREQ__MARK_FILE_BY_FD: {
      const int fd = arg[1];
      const VkPlaneTag plane_tag = arg[2];

      File_MarkFileByFd(fd, plane_tag);
      SET_CLREQ_RETVAL(0);
      break;
   }
    
   default: {
      HWord retVal = 0;
      const int wasHandled = Module_OnClientReq(req_no, arg, &retVal);
      if (wasHandled) {
         SET_CLREQ_RETVAL(retVal);
      }

#if 0
      /* Module that loads it may not be loaded. */
      ASSERT_UNIMPLEMENTED_MSG(wasHandled, 
            "unhandled client request: req_no=%d\n", req_no);
#endif
      break;
   }
   };
}

/* Returns 1 iff should enter vkernel. */
int REGPARM(1)
BT_HandleErrorCode(uint trc)
{
#if 1
   if (trc != VK_TRC_INNER_FASTMISS && Task_TestFlag(current, TIF_INSEMU)) {
      Task_ClearCurrentFlag(TIF_INSEMU);
   }
#endif

   switch (trc) {
   case VEX_TRC_JMP_SYS_INT129:  /* generated by entry module on RDTSC */
      Task_SetCurrentFlag(TIF_TSCCALL);
      break;
   case VEX_TRC_JMP_SYS_INT128:  /* generated by VEX on syscall, x86-linux */
      Task_SetCurrentFlag(TIF_SYSCALL);
      break;
   case VEX_TRC_JMP_SIGSEGV: /* generated by VEX on INT $0x40 .. $0x42 */
      /* generated by software preemption module */
      Task_SetCurrentFlag(TIF_PREEMPT_FAULT);
      break;
   case VK_TRC_INNER_FASTMISS:
      TrnsTab_HandleFastMiss();
      break;
   case VEX_TRC_JMP_YIELD:
      /* Guest is done emulating a FPU/MMX instr and wants to return to
       * DE mode OR VEX detected a REP NOP insn sequence or got a
       * software preemption. */
      break;
   case VEX_TRC_JMP_TINVAL:
      TrnsTab_Invalidate(curr_regs->guest_TISTART, curr_regs->guest_TILEN);
      if (curr_regs->guest_IP_AFTER_TINVAL) {
         curr_regs->R(eip) = curr_regs->guest_IP_AFTER_TINVAL;
         curr_regs->guest_IP_AFTER_TINVAL = 0;
      }
      break;
   case VEX_TRC_JMP_EMWARN: 
      {
         VexEmWarn ew;
         char*    what;
         ew   = (VexEmWarn)curr_regs->guest_EMWARN;
         what = (ew < 0 || ew >= EmWarn_NUMBER)
            ? "unknown (?!)"
            : LibVEX_EmWarn_string(ew);
         DEBUG_MSG(3, "VEX emulation warning: %s\n", what);
      }
      break;
   case VEX_TRC_JMP_CLIENTREQ:
      BTDoClientRequest();
      break;
   case VK_TRC_INVARIANT_FAILED:
      /* This typically happens if, after running generated code,
         it is detected that host CPU settings (eg, FPU/Vector
         control words) are not as they should be.  Vex's code
         generation specifies the state such control words should
         be in on entry to Vex-generated code, and they should be
         unchanged on exit from it.  Failure of this assertion
         usually means a bug in Vex's code generation. */
      DEBUG_MSG(5, 
            "%d: run_innerloop detected host "
            "state invariant failure", trc);
      break;
   case VEX_TRC_JMP_MAPFAIL:
      ASSERT_UNIMPLEMENTED_MSG(0, "MapFail\n");
      break;
   default:
      ASSERT_UNIMPLEMENTED_MSG(0, "trc=%d\n", trc);
      break;
   }


   /* XXX: flag should be a vcpu flag. */
   if (Task_TestFlag(current, TIF_ENTER_DEBUG_LOOP)) {
      /* Flag should be cleared by the debug loop, as a kind of ack. */
      Server_NotifyAndEnterControlLoop(current->dbgRespEv);
   }

   if (Task_TestFlag(current, TIF_PREEMPT) ||
       Task_TestFlag(current, TIF_CALL_MASK)) {
      /* Guest did a Ijk_Yield on preemption OR we're replaying a
       * preemption (in which case flag was asserted by notification
       * handler). */

      /* XXX: Notification handler asserts flag, yet BT code needs to know
       * about flag. We need better organization. */
      return 1;
   }

   return 0;
}

void
BT_Fork(struct Task *tsk)
{
   BTInitGuest(tsk);
   ASSERT(tsk->is_in_code_cache == 0);
}

void
BT_Exit(struct Task *tsk)
{
   /* GDT is never shared among tasks, not even threads.
    * So always deallocate. */
   BTFreeX86GDT(tsk);
}

void
BT_Exec()
{
   /* XXX: We want to wipe out the TLS descriptor entries, but isn't
    * wiping out the entire GDT overkill? I guess this is a matter of
    * figuring out if the GDT has non-TLS uses. */
   BTFreeX86GDT(current);
   /* FPU/MMX state needs to be initialized. */
   LibVEX_GuestX86_initialise(curr_regs);
   /* XXX: must update symbolic map on init. */
}

static void
BTInitCaps()
{
   uint eax, ebx, ecx, edx;
   int gotSSE1, gotSSE2;

   /* 
    * Must set hwcaps appropriately -- determines 
    * the code generated by VEX.
    *
    * e.g., MFence -- could be "mfence" or "sfence ; lock addl $0,0(%esp)",
    * depending on whether host supports SSE1 or SSE2.
    *
    */

   LibVEX_default_VexArchInfo(&vai);

   X86_cpuid(0, &eax, &ebx, &ecx, &edx);

   if (eax < 1) {
      /* eax > 0 is invalid */
      goto out;
   }

   X86_cpuid(1, &eax, &ebx, &ecx, &edx);

   gotSSE1 = (edx & (1 << 25)) != 0;
   gotSSE2 = (edx & (1 << 26)) != 0;

   va = VexArchX86;

   if (gotSSE2 && gotSSE1) {
      vai.hwcaps = VEX_HWCAPS_X86_SSE1 | VEX_HWCAPS_X86_SSE2;
      bt_x86_have_mxcsr = 1;
      goto out;
   }

   if (gotSSE1) {
      vai.hwcaps = VEX_HWCAPS_X86_SSE1;
      bt_x86_have_mxcsr = 1;
      goto out;
   }

   vai.hwcaps = 0; /* no SSE */
   bt_x86_have_mxcsr = 0;

out:
   return;
}

static int
BT_Init()
{
   VexControl vc;

   /* Init with optimization. */
   LibVEX_default_VexControl(&vc);
   vc.iropt_level = optIROptLevel;

   /* BUG 41: XXX */
   ASSERT_MSG(vc.iropt_level == SAFE_IROPT_LEVEL, "BUG 41: Java will likely trigger VEX FPU emulation bug (present in VEX 3.5 or older) if opt_level < 2\n");

   /* Instrumentation generated by a module may exceed VEX's 
    * maximum register allocation bandwidth if we allow a large
    * number of insns in an IRSB. In particular, 60 insns
    * have exhausted it in the past in formgen, due to a large 
    * number of dirty calls handling PutIs. */
   vc.guest_max_insns = 50;
   ASSERT(vc.guest_max_insns <= 50);

   /* We want registers to be up-to-date at an exception...but I believe
    * setting this flag to achieve precise exceptions is only necessary 
    * when iropt_level is > 0. */
   vc.iropt_precise_memory_exns = True;

   /* Unrolling and chasing into other BBs will screw up the branch 
    * counts--they will become out of sync with the DE mode recorded counts, 
    * because VEX will eliminate some of the backward jumps, and hence we 
    * won't count those. 
    *
    * XXX: is there a way to support these opts without screwing up the
    * branch count? */
   vc.iropt_unroll_thresh = 0;
   vc.guest_chase_thresh = 0;


   LibVEX_Init (
         /* failure exit function */
         &failure_exit,
         /* logging output function */
         &log_bytes,
         /* debug paranoia level */
         5,
         /* Are we supporting valgrind checking? */
         False,
         /* Control ... */
         /*READONLY*/
         &vc
         );


   BTInitCaps();

   LibVEX_default_VexAbiInfo(&vex_abiinfo);

   BTInitGuest(current);

   return 0;
}

void ASMLINKAGE
BT_ResumeUserModeSanityCheck(ulong gsp)
{
   if (gsp != (ulong) curr_regs) {
      DEBUG_MSG(5, "gsp=0x%x curr_regs=0x%x\n", gsp, (ulong) curr_regs);
   }

   /* Guest-state pointer (gsp) may not be at curr_regs if we
    * came out of a translated block prematurely (e.g., to handle
    * a SIGSEGV). */
   ASSERT(gsp == (ulong) curr_regs ||
          gsp != (ulong) curr_regs);
}

CORE_INITCALL(BT_Init);
