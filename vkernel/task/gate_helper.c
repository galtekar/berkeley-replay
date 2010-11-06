/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

/* Routines to aid vkernel entrances. */


static INLINE void
Gate_EFLAGS_ToRegs(ulong eflags, TaskRegs *regs)
{
   /* When DF is set, then counting is done by subtracting 1
    * (the so called ``auto-incrementing'') and hence the -1
    * encoding. */
   regs->guest_DFLAG = (eflags & X86_EFLAGS_DF) ? -1 : 1;
   regs->guest_IDFLAG = (eflags & X86_EFLAGS_ID) ? 1 : 0;
   regs->guest_ACFLAG = (eflags & X86_EFLAGS_AC) ? 1 : 0;
#ifdef REQ_TFFLAG
   regs->guest_TFFLAG = (eflags & X86_EFLAGS_TF) ? 1 : 0;
#endif

   DEBUG_MSG(6, "dflag=0x%x idflag=0x%x acflag=0x%x\n",
         regs->guest_DFLAG, regs->guest_IDFLAG, regs->guest_ACFLAG);

   /* Tell VEX to use the OSZACP bits in @eflags. */
   regs->guest_CC_OP = 0; /* X86G_CC_OP_COPY */
   regs->guest_CC_DEP1 = eflags;
}

#define COPY_REGS() \
   COPY(EAX, eax); \
   COPY(ECX, ecx); \
   COPY(EDX, edx); \
   COPY(EBX, ebx); \
   COPY(ESP, esp); \
   COPY(EBP, ebp); \
   COPY(ESI, esi); \
   COPY(EDI, edi); \
   COPY(EIP, eip);

static void
GateSigCtxToRegs(struct sigcontext *scP, TaskRegs *regs)
{
#if 0
#undef COPY
#define COPY(v, p) regs->guest_##v = scP->p
   COPY_REGS();
   COPY(CS, cs);
   COPY(SS, ss);
   COPY(DS, ds);
   COPY(ES, es);
   COPY(FS, fs);
   COPY(GS, gs); 
#endif

   /* NOTE: No need to copy over FP/XMM/SSE regs here. We do
    * this on demand when an FP/XMM/SSE instruction is executed
    * in BT mode. */

   Gate_EFLAGS_ToRegs(scP->eflags, regs);
}

static void
GateRegsToSigCtx(TaskRegs *regs, struct sigcontext *scP)
{
#if 0
   /* All GPRs */
#undef COPY
#define COPY(v, p) scP->p = regs->guest_##v
   COPY_REGS();
   COPY(CS, cs);
   COPY(SS, ss);
   COPY(DS, ds);
   COPY(ES, es);
   COPY(FS, fs);
   COPY(GS, gs);
#endif

   /* EFLAGS -- if we came out of BT, then guest_CC_DEP1 may not
    * be accurate. We need to get VEX to reconstruct eflags for us. 
    * If we came out of DE, then there is no harm in having
    * VEX reconstruct it (it'll just be a CC_OP_COPY). */
   scP->eflags = LibVEX_GuestX86_get_eflags(regs);
   DEBUG_MSG(6, "eflags=0x%x\n", regs->R(eflags));

   /* FP/MMX/SSE only if touched. */
   WARN_XXX(0);
}

void ASMLINKAGE
Gate_SafeDisableFPUandTSCEmulation()
{
   if (Cap_Test(CAP_FPUandTSC_EMU)) {
#if 1
      int err;

      ASSERT(current->perfctr);
      err = vperfctr_emu_disable(current->perfctr);
      ASSERT(!err);
#endif
   }
}

#if 0
void
Task_SafeEnableEmu()
{
   if (Cap_Test(CAP_FPUEMU)) {
      int err;

      ASSERT(current->perfctr);
      err = vperfctr_emu_enable(current->perfctr);
      ASSERT(!err);
   }
}
#endif

void ASMLINKAGE
Gate_SetupSigCtxForExit(struct rt_sigframe *frameP)
{
   ASSERT(frameP == (struct rt_sigframe*) curr_regs);


   /* ----- Sanity checks ----- */

   /* Linux restores the alternate stack to what's in the
    * rt_sigframe when it does a sigreturn. Not sure why,
    * but we must ensure that it keeps the vkernel stack as
    * the alternate stack. */
   DEBUG_MSG(5, "uc_stack=0x%x ss_sp=0x%x ss_size=0x%x ss_flags=0x%x\n", 
         &frameP->uc.uc_stack, frameP->uc.uc_stack.ss_sp,
         frameP->uc.uc_stack.ss_size,
         frameP->uc.uc_stack.ss_flags);
   ASSERT(current->sigstack_ss.ss_sp);
   ASSERT(memcmp(&frameP->uc.uc_stack, &current->sigstack_ss, 
            sizeof(current->sigstack_ss)) == 0);



   /* ----- Setup app-mode signal mask ----- */

   ASSERT(sizeof(frameP->uc.uc_sigmask) == sizeof(sigset_t));
   ASSERT(sizeof(current->blocked) == sizeof(sigset_t));

   /* Careful not to block the special signals -- e.g., those that tell
    * us when a syscall has been executed or a segfault occurred. If you
    * do, then the kernel may enter a silent loop -- syscall -> signal
    * -> blocked -> resume -> syscall -> ... and so on. */
   {
      sigset_t mask;
      sigset_t blockables;

      SigOps_InitSet(&blockables, ~_ALWAYS_UNBLOCKED);
      SigOps_AndSets(&mask, &current->blocked, &blockables);

      memcpy(&frameP->uc.uc_sigmask, &mask, sizeof(sigset_t));

      ASSERT(SigOps_IsEqual(&frameP->uc.uc_sigmask, &mask)); 
   }



   /* ----- Setup app-mode register state ----- */

   GateRegsToSigCtx(curr_regs, &frameP->uc.uc_mcontext);

   /* Should return to app code... */
   ASSERT(Task_IsAddrInUser(frameP->uc.uc_mcontext.eip));


   if ((VCPU_GetMode() & VCPU_MODE_SINGLESTEP)) {
      DEBUG_MSG(5, "SS enabled.\n");
      /* Set the trap flag (TF). This ensures that will get a
       * trap signal after the next app-mode instruction is executed. */
      frameP->uc.uc_mcontext.eflags |= X86_EFLAGS_TF;
   }
}


static INLINE int 
EntryIsInt3Sig(siginfo_t *si)
{
   return si->si_signo == SIGTRAP;
}


/*
 * Handle the syscall.
 *
 * We must deal with syscall arg divergences, however,
 * which could happen due to a race when NR_VCPU > 1.
 */
static void 
GateDoSyscallWork()
{
   int sysno, sysret;
   TaskRegs *regs = Task_GetCurrentRegs();
   struct SyscallArgs args;

   //Debug_PrintTaskRegs(Task_GetCurrentRegs());
   
   Task_Regs2Args(regs, &args);


   current->orig_eax = sysno = args.eax;

   /* XXX: handle this error gracefully */
   ASSERT_UNIMPLEMENTED_MSG(0 <= sysno && sysno < NR_SYSCALLS,
         "sysno=%s", get_syscall_name(sysno));


   Debug_MarkSyscallStart(&args);

   Module_OnPreSyscall();

   sysret = sys_call_table[sysno](args);

   Task_WriteReg(regs, eax, sysret);

   Module_OnPostSyscall();

   Debug_MarkSyscallEnd(sysno, sysret);
}

void
GateDoRDTSCWork()
{
   u64 val;
	int* p;
   TaskRegs *regs = Task_GetCurrentRegs();

   /* Emulation is disabed by module on emulation trap, and on entrance 
    * to BT, so shouldn't be on here. */

   val = InsnEmu_DoRDTSC();
   /* NOTE: Don't re-enable emulation. If we enter DE mode, then
    * it will be re-enabled. Otherwise if we are going
    * to BT mode, then keep it off. */

	p = (int*)&val;

   Task_WriteReg(regs, eax, p[0]);
   Task_WriteReg(regs, edx, p[1]);
#if PRODUCT
   /* XXX: removed because it was causing problem in the dcgen join brkpt
    * code. */
#error "this may break the DCGEN join brkpt code, test thoroughly!!"
#else
   /* Advance past the RDTSC instruction. */
   Task_WriteReg(regs, eip, regs->R(eip)+2);
#endif
}

static void
GateRecordReplayRegs(const uint off, const size_t len)
{
   char *startP = ((char*)curr_regs) + off;
   
   DO_WITH_LOG_ENTRY_DATA(RegisterState, len) {
      if (VCPU_IsLogging()) {
         /* Save reg. state. */
         memcpy(datap, startP, len);

         /* XXX: what about FP state? */
      } else if (VCPU_IsReplaying()) {
         /* XXX: just verify determinism on value-det replays. */
         memcpy(startP, datap, len);
      }

      struct CopySource cs = { .tag = Sk_Generic, .logDataP = datap, 
         .loggedLen = len };
      Module_OnRegCopy(1, &cs, off, len);
   } END_WITH_LOG_ENTRY(0);
}

static void
GateRecordReplayVclock()
{
   DO_WITH_LOG_ENTRY(VclockState) {
      if (VCPU_IsLogging()) {
         uint64_t last_clock = curr_vcpu->last_clock, 
                  new_clock = get_sys_micros();
#if PRODUCT
#error "XXX: what if system time gets reset in between?
#else
         int64_t time_elapsed_since_last_event = (new_clock - last_clock);
#endif

         curr_vcpu->vclock += time_elapsed_since_last_event;
         curr_vcpu->last_clock = new_clock;
         entryp->vclock = curr_vcpu->vclock;
      } else if (VCPU_IsReplaying()) {
         curr_vcpu->vclock = entryp->vclock;
      }
   } END_WITH_LOG_ENTRY(0);
}


/* Work common to entrance from DE and BT mode. */
static INLINE void
GateCommonWork()
{
#if DEBUG
#define SAVETSS(t, v) savesegment(t, (v))
   ushort tss_val;

   /* The vkernel TSS segment register should contain
    * the vkernel's selector -- it was set on entrance
    * from DE or in Task_Start. This should hold even
    * if we are coming out of BT dispatch. */
   SAVETSS(TSS, tss_val);
   ASSERT(tss_val == vkTssSelector);
#endif

   const uint off = offsetof(VexGuestX86State, guest_GS);
   const size_t len = offsetof(VexGuestX86State, pad2) - off;
   ASSERT(len <= 256);

   GateRecordReplayRegs(off, len);
   GateRecordReplayVclock();

   if (Task_TestFlag(current, TIF_SYSCALL)) {
      DEBUG_MSG(5, "Syscall vector.\n");
      GateDoSyscallWork();
   } else if (Task_TestFlag(current, TIF_TSCCALL)) {
      DEBUG_MSG(5, "TSC vector.\n");
      GateDoRDTSCWork();
   } else if (Task_TestFlag(current, TIF_PREEMPT)) {
      DEBUG_MSG(5, "Preempt vector.\n");
      /* Work is done on exit from vkernel. */
   }
}

void
Gate_FromBTHelper()
{
#if DEBUG
   DEBUG_MSG(5, "nextBblAddr=0x%x brCnt=%llu\n",
         curr_regs->R(eip), BrCnt_Get());
   ASSERT((Task_TestFlag(current, TIF_CALL_MASK) ^
         Task_TestFlag(current, TIF_PREEMPT)));
#endif

   if (Task_TestFlag(current, TIF_TSCCALL)) {
      /* XXX: removed to make dcgen join brkpt predictable.
       * RDTSC eip behavior should be consistent with syscall behavior. */
#if 0
      /* EIP right now is that of the instruction following
       * the TSC instruction. But to be consistent with
       * DE mode, we want EIP to point to TSC insn. */
      Task_GetCurrentRegs()->R(eip) -= 2;
#endif
   } else if (Task_TestFlag(current, TIF_SYSCALL)) {
      /* Nothing specific to BT needs to be done. */
   } else if (Task_TestFlag(current, TIF_PREEMPT_FAULT)) {
      /* The work will be done in the preemption code, invoked
       * right before leaving the vkernel. */
      /* XXX: why not move it up here? */
   }

   GateCommonWork();
}

static int
GateVerifyTscInsn(ulong addr)
{
   uchar *p = (uchar*) addr;

   /*
    * XXX: should check for RDPMC as well.
    */

   /* RDTSC opcode is 0x310F 
    * RDTSCP opcode is 0xF9010F */
   return (p[0] == 0x0F && p[1] == 0x31) ||
      (p[0] == 0x0F && p[1] == 0x01 && p[2] == 0xF9);
}

static void
GateEntryFromDE(int signr, siginfo_t *si, ucontext_t *uc)
{
   TaskRegs *regs = Task_GetCurrentRegs();
   struct sigcontext *scp = &uc->uc_mcontext;
   int singleStep = 0;

   ASSERT_MSG(regs->R(eip) == scp->eip, 
         "&regs->eip=0x%x &scp->eip=0x%x\n", &regs->R(eip), &scp->eip);
   ASSERT(!Signal_IsSnoopSig(si));
   ASSERT(!Task_IsAddrInKernel(scp->eip));
   ASSERT(Task_IsAddrInCodeCache(scp->eip) ||
         Task_IsAddrInUser(scp->eip));

   /* Verify experimentally -- is the pending flag set
    * for non-PMI entrances? 
    *
    * Yes -- e.g., PMI is set in
    * single-step mode, and then we resume, upon which we trap
    * due to single step while PMI is pending. */
   //ASSERT(BrCnt_IsPMISig(si) || !Task_TestFlag(current, TIF_PMI_PENDING));

   DEBUG_MSG(5, "EIP 0x%x ECX 0x%x BRCNT %llu\n", 
         scp->eip, scp->ecx, BrCnt_Get());


   /* Setup the task regs. */
   GateSigCtxToRegs(scp, regs);

   ASSERT(TRAP_BRKPT != SI_KERNEL);
   ASSERT(SI_KERNEL != SI_PMC_OVF);
   ASSERT(SI_KERNEL != SI_PERF_SYSEMU);
   ASSERT(SI_PMC_OVF != SI_PERF_SYSEMU);
   if (EntryIsInt3Sig(si)) {
      switch (si->si_code) {
      case TRAP_BRKPT:
         singleStep = 1;
         Task_SetCurrentFlag(TIF_SINGLE_STEP);
         break;
      case SI_KERNEL:
         /* Breakpoint instruction trap (i.e., for 0xCC opcode). */
         ASSERT_UNIMPLEMENTED(0);
         break;
      default:
         ASSERT(0);
         break;
      }
   } else if (signr == SIG_RESERVED_USER) {
      if (Signal_IsTimerSig(si)) {
         Task_SetCurrentFlag(TIF_PREEMPT_TIMER);
      } else {
         /* XXX: A user-generated signal -- perhaps from a user timer? */
         ASSERT_UNIMPLEMENTED_MSG(0, "si->si_code=%d\n", si->si_code);
      }
   } else if (signr == SIG_RESERVED_TRAP) {
      switch (si->si_code) {
      case SI_PMC_OVF:
         ASSERT(!Task_IsAddrInKernel(scp->eip));
         ASSERT(VCPU_IsReplaying());
         BrCnt_OnPMI(si->si_pmc_ovf_mask);
         break;
      case SI_PERF_SYSEMU:
         Task_SetCurrentFlag(TIF_SYSCALL);
         //GateDoSyscallWork();
         break;
      case SI_PERF_TSCEMU:
         /* XXX:  When user-mode #GPs, the kernel will send us a
          * SI_PERF_TSCEMU code, but it may not be due to TSC trap,
          * hence this assert. */
         ASSERT_UNIMPLEMENTED(GateVerifyTscInsn(scp->eip));
         Task_SetCurrentFlag(TIF_TSCCALL);
         //GateDoRDTSCWork();
         break;
      case SI_PERF_FPUEMU:
         Task_SetCurrentFlag(TIF_INSEMU);
         break;
      case 0x1:
         ASSERT_UNIMPLEMENTED(0);
         break;
      default:
         /* MMX/SSE2 instruction trap. */
         Task_SetCurrentFlag(TIF_INSEMU);
         break;
      }
   } else if (Signal_IsCrashSig(si->si_signo)) {
      Task_SetCurrentFlag(TIF_PREEMPT_FAULT);
   } else {
      ASSERT(0);
   }

   GateCommonWork();
}


static void
GateEntryFromVK(siginfo_t *si, ucontext_t *uc)
{
#if DEBUG
   struct sigcontext *scp = &uc->uc_mcontext;

   /* perfctr should've disabled the PMI counter upon PMI,
    * so branches in the vkernel shouldn't trigger a PMI. */
   ASSERT(!BrCnt_IsPMISig(si));
   ASSERT(!EntryIsInt3Sig(si));
   ASSERT(Signal_IsSnoopSig(si) || !Signal_IsSnoopSig(si));
   ASSERT(Task_IsAddrInKernel(scp->eip));
#endif

   if (Signal_IsTimerSig(si)) {
      return;
   }

   Signal_EntryFromVK(si, uc);
}


/* If you change this, then you must change arg sequence in
 * entry.S:Entry_SignalHardBrCnt . */
struct BrCntStruct {
   ullong cnt;
   /* number of branches executed to RDPMC the brCnt */
   ulong overhead; 
};

#if DEBUG
static void
GateShowDebugInfo(siginfo_t *sip, struct sigcontext *scp)
{
   Debug_Mark();
   QUIET_DEBUG_MSG(5, "   SIG:   %8.8d   TID:   %8.8d  VAL: 0x%8.8x  CDE: 0x%8.8x\n"
         "   SRC:   %s\n", 
         sip->si_signo, sip->si_pid, sip->si_value.sival_int, sip->si_code, 
         Task_IsAddrInKernel(scp->eip) ? "KERNEL" : "USER");
   Debug_PrintContext(5, scp);
   //QUIET_DEBUG_MSG(7, "ESP on entrance: 0x%x\n", frameP);
   Debug_Mark();
}
#endif

/*
 * Summary:
 *
 * Returns -1 if we should sigreturn (possible to bt or vkernel code), or 
 * 1 if we should resume in usermode (and skip the sigreturn).
 *
 * We almost always want to resume the insn that was interrupted. This
 * applies even if we were interrupted in the code-cache, because at that 
 * point, we can't re-execute all UOps for the instruction again, since
 * VEX doesn't truly support precise exceptions (there is some support 
 * for it, but it is inadequate/incomplete).
 *
 * We need to bail out if we hit a crash (a synchronous signal).
 * XXX: but register state at that point will not be precise (e.g., on a
 * call instruction, %esp will have been decremented before the fault on
 * the store)
 */
int FASTCALL
Gate_Work(const struct BrCntStruct * brp, struct rt_sigframe *frameP)
{
   int shouldSigRet = 1;
   int signr = frameP->sig;
   siginfo_t *sip = (siginfo_t*)&frameP->info;
   ucontext_t *ucp = (ucontext_t*)&frameP->uc;
   struct sigcontext *scp = &frameP->uc.uc_mcontext;

#if DEBUG
   GateShowDebugInfo(sip, scp);

   /* Frame won't overwrite task regs if we got signal while
    * executing in translatation cache.  */
   ASSERT((ulong)frameP == (ulong)curr_regs ||
         (ulong)frameP != (ulong)curr_regs);
   ASSERT_MSG(Task_IsInTaskStack(), 
         "stackBase=0x%x currStackPtr=0x%x top=0x%x\n", 
         Task_GetStackBase(current), currentStackPointer,
         Task_GetStackBase(current)+sizeof(struct TaskStack));
   ASSERT(brp || !brp);
   if (Task_IsAddrInImage(scp->eip)) {
      ASSERT_MSG(Task_IsAddrInKernel(scp->eip) || Task_IsAddrInCodeCache(scp->eip) ||
            Task_IsAddrInVDSO(scp->eip),
            "scp->eip=0x%x\n", scp->eip);
   }
#endif


   /* We need access to the siginfo to deliver crash signals;
    * see PreemptDo() for more info. Unfortunately, the si
    * is not always at current->stacks.un.frame -- if we came out
    * of BT, then it's placed somewhere further down the stack. */
   current->frameP = frameP;

   if (Task_IsAddrInKernel(scp->eip)) {
      GateEntryFromVK(sip, ucp);
   } else if (Task_IsAddrInCodeCache(scp->eip)) {
      shouldSigRet = 0;
      if (Signal_IsTimerSig(sip)) {
         shouldSigRet = 1; 
      } else if (Signal_IsCrashSig(sip->si_signo)) {
         /* We treat these crash sigs as preemptions that happen to have
          * signals associated with them. The preemption code will
          * generate the appropriate signal. */
         Task_SetCurrentFlag(TIF_PREEMPT_FAULT);
      }

      /* Need to reset the flag; otherwise, we'll get a "shouldn't
       * invalidate from within the code cache" error on shutdown (which,
       * could happen if this results in a kill signal (e.g., segv)). */
      ASSERT(current->is_in_code_cache);
      current->is_in_code_cache = 0;
      Signal_Queue(sip);
   } else if (Task_IsAddrInUser(scp->eip)) {
      ASSERT(frameP == &current->stack.un.frame);

      if (brp) {
         ASSERT(Cap_Test(CAP_HARD_BRCNT));

         /* 
          * Compensate for the overhead of reading the branch count.
          *
          * br.overhead contains the overhead of reading the counter
          * itself.
          *
          * No need to compensate for int3 -- it shouldn't be counted
          * as a branch.
          *
          */

         /* XXX: Calls to BrCnt_Get() before this will return incorrect
          * results. So check that this is the first thing on entrance. */
         current->brCntOnEntry = brp->cnt - 2*brp->overhead;

         DEBUG_MSG(9, "brCntOnEntry=%llu vkBrCnt=%llu delta=%llu\n", 
               current->brCntOnEntry, current->vkBrCnt,
               current->brCntOnEntry - current->vkBrCnt);
      }

      GateEntryFromDE(signr, sip, ucp);

      shouldSigRet = 0;
   } else {
      ASSERT(0);
   }

   return shouldSigRet ? -1 : 1;
}

/*
 *-----------------------------------------------------------------------
 *
 * Gate_SelectResumeMode --
 *
 * Summary:
 *
 *    Called by the dipatch loop to determine whether we resume executing
 *    user-mode code in BT or DE mode. If we are going to execute in BT
 *    mode, translate the next IRSB and put it in the code cache so that 
 *    the dispatch loop can execute it.
 *
 * Returns:
 *
 *    RESUME_BT if dispatch should enter binary translation mode 
 *         (even temporarily via TIF_BT_INSEMU)
 *    RESUME_DE if dispatch should enter direct-execution
 *
 * Note:
 *
 *    VEX will put the nextBbl addr in %eax, hence the regparm(1).
 *    fastcall would not work here since that would require the first
 *    arg to be in %ecx.
 *
 *-----------------------------------------------------------------------
 */
int REGPARM(1) 
Gate_SelectResumeMode(ulong nextBblAddr)
{
   int res = -1;
   int shouldCheckBrkptInBT = 0;
   extern void Check_HandleSingleStep();

   /* If you change these constants, then asm in entry.S must be updated. */
#define RESUME_DE 0
#define RESUME_BT 1
#if 0
   DEBUG_MSG(5, "nextBblAddr=0x%x brCnt=%llu\n", 
         nextBblAddr, BrCnt_Get());
#endif


#if DEBUG
#if 0
   /* IRSB exits are caused by branches. */
   if (!(vcpuMode & VCPU_MODE_SINGLESTEP)) {
      if (current->lastBrCnt > 0) {
         ASSERT(BrCnt_Get() - current->lastBrCnt > 0);
         current->lastBrCnt = BrCnt_Get();
      }
   }
#endif
#endif

   /* We are not entering the kernel -- we are about to 
    * execute user-mode code. 
    *
    * We could be coming from user-mode in BT (e.g., after
    * exiting from an IRSB) or from the vkernel (e.g., 
    * after a syscall or a preempt).
    *
    * We are interested in getting to DE mode since it's
    * the fastest. But we may have to settle for BT mode.
    * This is where we decide.
    */

   /* We have originally entered through the VDSO, which lies
    * somewhere in vkernel image, though not in the official
    * vkernel text area. */
   ASSERT(!Task_IsAddrInImage(nextBblAddr) || 
         Task_IsAddrInImage(nextBblAddr));

   ASSERT(!Task_IsAddrInKernel(nextBblAddr));

   /* Preemption can happen after an IRSB exit (that's when
    * software preemption asserts the TIF_PREEMPT flag) or right 
    * after a syscall (that's when hardware preemptions occur).
    *
    * This is the best place to setup preemption notifications.
    * Foremost because we are here either due to an IRSB
    * exit or a syscall). 
    *
    * Second we are guaranteed to get fresh translations of target
    * IRSBs. This is not the case if we were to setup preemptions
    * from within helper calls -- there may be a notification
    * in the same IRSB and we would have to do insert additional
    * checks to invalidate them. */
   {
      struct Brkpt * brkP;

      if ((brkP = Brkpt_PeekFirst())) {

         ASSERT(brkP->kind != Bpk_Dynamic || VCPU_IsReplaying());

         /* If we can't setup a PMI to reliably occur before the event
          * execution point, then we should crawl up to the point
          * in BT mode. It's slow, but at least we won't miss it. */
         shouldCheckBrkptInBT = ((brkP->kind == Bpk_Static) ||
            (Brkpt_CalcNrBranchesTillHit(brkP) <= PMI_MAX_LATENCY)) ||
            current->insnStepCount > 0;
      }
   }


   if (!VCPU_IsDEEnabled() || !Cap_Test(CAP_HARD_BRCNT) 
         || shouldCheckBrkptInBT || Task_TestFlag(current, TIF_INSEMU)) {
      res = RESUME_BT;
      Task_SetCurrentFlag(TIF_BT_MODE);
   } else {
      /* We're free to resume user-level in DE mode. */
      Task_ClearCurrentFlag(TIF_BT_MODE);
      res = RESUME_DE;
   }

   ASSERT(res == RESUME_DE || res == RESUME_BT);

#if DEBUG
   /* XXX: This call doesn't belong in this fn, since fn is invoked
    * even from the BT inner loop. */
   ASSERT_UNIMPLEMENTED(!(VCPU_GetMode() & VCPU_MODE_SINGLESTEP));
   /* Must come after signal handling to ensure that we record
    * start of signal handler. Must come after MODE flag is
    * set, since where we record depends on it. */
#if 0
   Check_HandleSingleStep();
#endif
#endif

   DEBUG_MSG(5, "Resuming in %s mode.\n", (res == RESUME_DE) ? "DE" : "BT");
   //Debug_PrintTaskRegs(Task_GetCurrentRegs());

   return res;
}
