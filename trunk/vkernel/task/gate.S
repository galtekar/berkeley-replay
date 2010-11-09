.file	"entry.S"

#include "vkernel/macros.h"
#include "libcommon/pmcops.h"

/*
 *-----------------------------------------------------------------------
 *
 * File:Gate --
 *
 * Summary:
 *    
 *    Contains entry/exit points to/from vkernel. Nothing
 *    enters/leaves the vkernel without going through here first.
 *    Entrypoints are organized by type of work performed. 
 *
 *    The entrypoint for machines with hardware branch count support
 *    differs from those of machines with no hardware branch count support,
 *    namely because reading the hardware branch counters requires
 *    a call to RDPMC, which will #GP at CPL 3 if appropriate hardware 
 *    bits aren't set by the perfctr kernel driver.
 *
 *-----------------------------------------------------------------------
 */


/*-----------------------------------------------------------------------
 *
 * MacroUpdateVkernelBrCnt --
 *
 * Summary:
 *
 *    Updates the number of branches executed by the vkernel. This
 *    helps us determine the number of branches executed by app-code
 *    since perfctr's virtual counter value = #br in app-code +
 *    #br in vkernel code (i.e., #br executed at CPL 3).
 *
 *    Intended to be called immediately before return to user context.
 *
 *-----------------------------------------------------------------------
 */
.macro MacroUpdateVkernelBrCnt
   MacroReadBrCnt

   /* This shouldn't be done in C code, since calling into it would 
    * introduce additional jumps. Moreover, the number of additional 
    * jumps introduced may depend on compiler optimizations, and thus 
    * may be hard to enumerate and risky to predict. */

   /* This is 64-bit arithmetic. */
   movl %TSS:oBRCNT_ON_ENTRY, %ebx
   movl %TSS:(oBRCNT_ON_ENTRY+4), %ecx
   subl %ebx, %eax
   sbbl %ecx, %edx

   /* EDI should contain the branch overhead of reading the counter
    * itself, set by MacroReadBrCnt above. But we needn't compensate
    * for that overhead here, since it is already included in the
    * count returned in EDX:EAX. See MacroReadBrCnt for more info. */
   addl %eax, %TSS:oVK_BRCNT
   adcl %edx, %TSS:(oVK_BRCNT+4)

   /* Overhead of 4 brcnts that doesn't get included in EDX:EAX
    * result from MacroReadBrCnt. */
   addl $4, %TSS:oVK_BRCNT
   adcl $0, %TSS:(oVK_BRCNT+4)
.endm


.macro MacroPrepareForSigReturn
   /* Ideally, %esp should point to the struct rt_sigframe
    * placed on the stack by Linux on entry into the syscall. 
    * 
    * But this may not always be the case -- we could've come out
    * of a BT block prematurely (e.g., due to a SIGSEGV), in which
    * case %esp won't point to the struct rt_sigframe. So here we
    * make it point there just in case this happens.
    */
   GET_CURRENT_TASK(%ecx)
   leal oTASK_REGS(%ecx), %esp

   movl %esp, %ecx
   call Gate_SetupSigCtxForExit /* assumed to be ASMLINKAGE */

   /* At this point, %esp should point to an rt_sigframe
    * filled-in with the user-mode context. */
.endm

/*
 * CAUTION: Macro shouldn't contain branch instructions, since
 * that'll pollute the app-mode branch count. */
.macro MacroSigReturn
   /* Assumption: %esp points to an rt_sigframe that's filled
    * with the target context. */

   /* The return address is the first field of the sigframe.
    * The Linux sys_rt_sigreturn assumes that the
    * return address has already been popped. Here we
    * meet that assumption. We could use the standard RET,
    * but that would increase the HW branch count. */
   popl %eax

   /*
    * BUG: The following sequence enters the kernel twice, when really
    * we can do it with just one call. One option is to make a ioctl
    * call that reenabes the emulation and does the sigreturn. But in
    * the future we'll replace the sigreturn with a context switch, and
    * so we won't need to enter the kernel at all. So there is no point
    * in making such an ioctl call. 
    */

   /* We want app to trap on FP/SSE/RDTSC, so re-enable emulation. 
    * Note that we do this in ASM rather than in C code because the
    * latter would require we CALL the function, which in turn would
    * pollute the branch count. */
   movl $0, %edx /* arg3 --- ioctl arg */
   movl %TSS:oPERFCTR, %ebx
   movl oPERFCTR_FD(%ebx), %ebx
   movl $VPERFCTR_IOCTL_CMD_EMU_ENABLE, %ecx
   movl $SYS_ioctl, %eax

   /* BUG 42: This should be executed, but results in kernel lock-up
    * when running in direct execution. */
   SYSCALL_ENTER_LINUX

   /* This syscall shouldn't be counted as a branch by our PMC;
    * it should count only branches and jumps. */
   movl $SYS_rt_sigreturn, %eax
   SYSCALL_ENTER_LINUX
   ASM_NOTREACHED
.endm

/*
 *-----------------------------------------------------------------------
 *
 * Gate_ResumeInDE --
 *
 * Summary:
 *
 *   Return to the app context at which we entered the vkernel. 
 *   This is done via a call to sys_sigreturn, which allows us to 
 *   atomically change to the user-mode signal mask and change to the 
 *   user-mode register context. This atomicity prevents
 *   kernel reentrance via preemption signals.
 *
 * Side effects:
 *
 *    If hardware branch counting is enabled, the number of vkernel 
 *    branches executed is updated.
 *
 *-----------------------------------------------------------------------
 */
STARTPROC(Gate_ResumeInDE)

   /* We want any branches made by this macro's code to be included
    * before any RDPMCs, such as those in MacroReadBrCnt. */
   MacroPrepareForSigReturn

   /* Skip the rdpmc if no hardware brcnt. */
   movl Cap_Flags, %eax
   andl $CAP_HARD_BRCNT, %eax
   je no_hard_brcnt

   /* Setup PMI before reading the HW branch count so that the setup
    * will be rolled into the branch-count update. Otherwise,
    * we'l have to correct for the branches executed for PMI setup. 
    * Besides, the PMI won't be precise anyway and so it can tolerate 
    * some amount of error. */
   movl vcpuMode, %eax
   andl $VCPU_MODE_REPLAY, %eax
   jne  hardbrcnt_pmi_resume

hardbrcnt_nopmi_resume:
   MacroUpdateVkernelBrCnt
   /* ====== No branch instructions permitted beyond here. ====== */
   MacroSigReturn
   ASM_NOTREACHED

hardbrcnt_pmi_resume:
   /* Must be done before updating vkernel brcnt,
    * otherwise branches executed in fn will lead to app-mode
    * brcnt. */
   call BrCnt_CalcPmiTarget
   movl %eax, %ebp /* %eax (pmiTarget) is about to be clobbered. */
   testl %ebp, %ebp
   je hardbrcnt_nopmi_resume

   /* Okay, we have a PMI to setup. */
   MacroUpdateVkernelBrCnt
   /* ====== No branch instructions permitted beyond here. ====== */

   /* XXX: don't make syscall if pmiTarget is 0. */
   /* Setup the hard branch counter to generate PMI when target brnct
    * is reached. Must be done after all vkernel branches have been
    * executed to ensure that we don't trip a PMI while executing
    * vkernel code. */
   movl %ebp, %edx /* arg3 -- pmiTarget parm. */
   movl %TSS:oPERFCTR, %ebx
   movl oPERFCTR_FD(%ebx), %ebx
   movl $VPERFCTR_IOCTL_CMD_START_ICTR_1, %ecx
   movl $SYS_ioctl, %eax
   SYSCALL_ENTER_LINUX

no_hard_brcnt:
   MacroSigReturn
   ASM_NOTREACHED
ENDPROC(Gate_ResumeInDE)



STARTPROC(Gate_ResumeUserMode)
   movl %TSS:oTASK_FLAGS, %ecx

   /* We may enter the kernel for events that are not
    * deterministically replayed, such as PMI signals. 
    * But we should be careful not to drain signals on
    * these events, as that would result in divergence. 
    */


    /* Checks for preemptions first. Recall that we consider
     * crashes to be preemptions as well. Hence we need to
     * process them before calling Signal_OnResumeUserMode. */

   andl $TIF_PREEMPT, %ecx
   jz 1f
   call Preempt_OnResumeUserMode
1:
   movl %TSS:oTASK_FLAGS, %ecx
   andl $(TIF_PREEMPT | TIF_CALL_MASK), %ecx
   jz 2f
   call Signal_OnResumeUserMode 
2:
  
   /* Must be done before deciding on mode -- can't resume
      in DE if a preemption notification is within PMI latency. */
   MacroScheduleUpcomingPreemption

   call Module_OnResumeUserMode

   /* Gate_SelectResumeMode expects next entrypoint in %eax */
   movl %TSS:oTASK_REGS_EIP, %eax
   call Gate_SelectResumeMode /* assumed to be REGPARM */

   /* Clear the work flags, but careful not to clobber results
   * in EAX. */
   andl $~(TIF_PREEMPT | TIF_CALL_MASK | TIF_SINGLE_STEP), %TSS:oTASK_FLAGS
   testl %eax, %eax

   je Gate_ResumeInDE

   /* VEX generates FPU (and TSC?) ops, and lets us intercept them
    * without hardware support. So we don't need hardware FPU/TSC 
    * emulation when executing VEX code. 
    *
    * Also note that if emulation is supported, then it must be enabled
    * (at this point), because we can reach here only from DE mode. 
    * Moreover, we enable FPU/TSC emulation before exiting to DE mode. */
   call Gate_SafeDisableFPUandTSCEmulation
   jmp BT_ResumeUserMode
ENDPROC(Gate_ResumeUserMode)


STARTPROC(Gate_FromBT)
   call Gate_FromBTHelper
   jmp Gate_ResumeUserMode
ENDPROC(Gate_FromBT)

.macro MacroSetupTSS
   movw vkTssSelector, %TSS
.endm

/*
 *-----------------------------------------------------------------------
 *
 * Gate_SignalHardBrCnt --
 *
 * Summary: 
 *
 *    This is the first vkernel code executed when we get a signal in
 *    user mode on a machine that supports hardware branch counting. 
 *
 * Challenge:
 *
 *    The goal here is to get an accurate count of the number of
 *    branches executed by app-code thus far.
 *    The main challenge is that the hardware branch counter ticks
 *    for either CPL = 0 or CPL > 0 code. Since the vkernel operates
 *    at CPL 3, we've chosen the latter tick configuration. However,
 *    this means that the branch counter will tick for app-code
 *    (which is deterministically replayed) and vkernel code
 *    (which is not replayed), thereby adding unpredictable noise
 *    to the app-code branch count.
 *
 *    We solve this problem by counting the number of branches executed
 *    within the vkernel, and by subtracting that value from the
 *    total value to get the app-code branch count (see BrCnt_Get()).
 *
 * Alignment:
 *    Linux double-quadword-aligns the stack pointer appropriately for 
 *    signal handler frames.
 *
 *-----------------------------------------------------------------------
 */

STARTPROC(Gate_SignalHardBrCnt)
   /* At this point, %esp points to the struct rt_sigframe */
   MacroSetupTSS
   movl %esp, %ebp

   MacroReadBrCnt

   pushl %edi           /* overhead of reading brCnt */
   pushl %edx           /* upper 32-bits of brCnt */
   pushl %eax           /* lower 32-bits of brCnt */

   movl %esp, %ecx      /* struct BrCntStruct * */
   movl %ebp, %edx      /* struct rt_sigframe * */
   call Gate_Work      /* assumed to be FASTCALL */
   addl $3*WORD_SIZE, %esp
   testl %eax, %eax

   js sigreturn /* if SF=1 */

resume_user_mode:
   jmp Gate_ResumeUserMode
   ASM_NOTREACHED

sigreturn:
   /* We either came from vkernel mode due to a signal (e.g., one received at a
    * drainage point or server data msg), or we got a server message. 
    * For the latter, this ret may sigreturn us back to user-code. 
    *
    * Careful!: Don't do a RET -- that'll take us into the VDSO, which is
    * technically non-vkernel code, which in turn would result in a syscall
    * emulation trap. */
   popl %eax
   movl $SYS_rt_sigreturn, %eax
   SYSCALL_ENTER_LINUX
   ASM_NOTREACHED

ENDPROC(Gate_SignalHardBrCnt)

/*
 *-----------------------------------------------------------------------
 *
 * Gate_SignalSoftBrCnt --
 *
 * Summary: 
 *
 *    This is the first vkernel code executed when we get a signal in
 *    user mode or vkernel mode (at selected drainage points, of course)
 *    on a machine that doesn't support hardware branch counting.
 *
 *    Unlike its counterpart above, it does doesn't read the hardware 
 *    branch count, but instead relies on software branch counts
 *    collected in BT mode.
 *
 * Alignment:
 *    Linux double-quadword-aligns the stack pointer appropriately for 
 *    signal handler frames.
 *
 *-----------------------------------------------------------------------
 */

STARTPROC(Gate_SignalSoftBrCnt)
   MacroSetupTSS
   movl $0, %ecx     /* struct BrCntStruct * */
   movl %esp, %edx   /* struct rt_sigframe * */
   call Gate_Work   /* assumed to be FASTCALL */
   testl %eax, %eax

   js sigreturn /* if SF=1 */

   jmp resume_user_mode
   ASM_NOTREACHED

ENDPROC(Gate_SignalSoftBrCnt)


/* 
 * Linux provides the so called ``vsyscall'' page -- a syscall
 * trampoline to kernel-land. Unfortunately, this page may move
 * around from execution to execution for security purposes.
 * But this screws with determinism.
 *
 * Our solution is to make the app use our vsyscall page, which
 * stays put from execution to execution.
 *
 * We don't want the vsyscall entry in the text section,
 * since then it will be counted as being part of the vkernel.
 * Thus any code that executed in the .vsyscall section will
 * be considered user-mode code.
 */
.section .vsyscall,"ax",@progbits
STARTPROC(Gate_vsyscall)
   int $0x80
   ret
ENDPROC(Gate_vsyscall)

STARTPROC(Gate_vsigreturn)
   popl %eax
   movl $SYS_sigreturn, %eax
   int $0x80
ENDPROC(Gate_vsigreturn)

STARTPROC(Gate_vrt_sigreturn)
   movl $SYS_rt_sigreturn, %eax
   int $0x80
ENDPROC(Gate_vrt_sigreturn)

/* Must place a dummy instruction at the end of vsyscall page to
 * to deal with the fact that on syscall entrance, the reported
 * eip is addrof(syscall)+2, which would be outside of the vsyscall
 * region without this dummy instruction. */
STARTPROC(Gate_vsyscall_end_dummy)
   ASM_NOTREACHED
ENDPROC(Gate_vsyscall_end_dummy)
.previous
