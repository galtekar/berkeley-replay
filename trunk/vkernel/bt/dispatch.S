.file "dispatch.S"

#include "vkernel/macros.h"
#include "private.h"
#include "libvex_trc_values.h"
#include "libcommon/spinlock.h"

/*
 *-----------------------------------------------------------------------
 *
 * BT_InnerLoop --
 *
 * Summary:
 *
 *    Called by VEX translated code to return to the dispatch loop.
 *
 * At entry we expect: 
 *    o %eax is next guest addr, %ebp is either
 *    o a VEX_TRC_ error code or a pointer to guest state.
 *
 *-----------------------------------------------------------------------
 */
STARTPROC(BT_InnerLoop)
   movl %eax, %TSS:oTASK_REGS_EIP

   movl $0, %TSS:oIS_IN_CODE_CACHE

	/* Is there an error code in %ebp?  If yes, handle it. */
   GET_CURRENT_TASK(%ebx)
   leal oTASK_REGS(%ebx), %ecx
	cmpl	%ecx, %ebp
	jnz	gsp_changed

   /* No need to check flags explicity now. Syscalls, software
    * preemptions and rdtsc now results in a gsp change. */
#if 0
   /* The gsp won't change if we get a software preemption, syscall, or rdtsc.
    * So must explicitly check for that here. */
   movl %TSS:oTASK_FLAGS, %ecx
   andl $(TIF_PREEMPT | TIF_CALL_MASK), %ecx
   movl $VEX_TRC_JMP_SYS_INT128, %eax
   jne exit_inner_loop
#endif

   /* Must be done before translation lookup to ensure
      that we don't execute stale translations (i.e., those
      invalidated by the notification request.). */
   MacroScheduleUpcomingPreemption

   /*
    * XXX: RACE
    *
    * We do the lookup in the fast cache, unlock the tt_lock,
    * and jump to the host address. But right before the jump,
    * the host code gets invalidated by some other thread.
    *
    */

   /* Try a fast lookup in the translation cache.
    * We must acquire a read lock on the cache to
    * protect against concurrent invalidations. */
   movl  %TSS:oTASK_REGS_EIP, %ecx
	movl	%ecx, %ebx			/* next guest addr */
	andl	$TT_FAST_MASK, %ebx		/* entry# */
   mSpin_ReadLock    tt_lock
	movl	tt_fast+0(,%ebx,8), %esi	/* .guest */
	movl	tt_fast+4(,%ebx,8), %edi	/* .host */
   mSpin_ReadUnlock  tt_lock
	cmpl	%ecx, %esi
	jnz	fast_lookup_failed

   /* Found a match.  Jump to .host.
    * 
    * VEX calling conventions dictate that before executing
    * a translated block in the code cache, EBP should point to 
    * VEX guest state, and ESP should point to a reasonable stack 
    * address (that doesn't trample VEX guest state)
    */
   movl $1, %TSS:oIS_IN_CODE_CACHE
	jmp 	*%edi
	ud2	/* persuade insn decoders not to speculate past here */

	/* NOTE: Generated code should run, then jump back to
	   BT_InnerLoop. */
   ASM_NOTREACHED

fast_lookup_failed:
   movl $VK_TRC_INNER_FASTMISS, %eax
   jmp exit_inner_loop
   ASM_NOTREACHED

gsp_changed:
   /* We're here because translated code returned an error code.
      This happens, for example, when a translation attempt
      fails, a syscall is executed, or the guest code wants a 
      translation invalidated (not always errors). */

	/* %eip is not up to date here.  first, need to write
	   %eax back to %eip. */
   movl %eax, %TSS:oTASK_REGS_EIP
   movl %ebp, %eax
   jmp exit_inner_loop
   ASM_NOTREACHED

exit_inner_loop:
   /* We're leaving.  Check that nobody messed with %mxcsr or %fpucw.  
      We can't mess with %eax here as it holds the tentative return 
      value, but any other is OK. */
#if !defined(ENABLE_INNER)
        /* This check fails for self-hosting, so skip in that case */
	pushl	$0
	fstcw	(%esp)
	cmpl	$0x027F, (%esp)
	popl	%esi /* get rid of the word without trashing %eflags */
	jnz	invariant_violation
#endif
   /* XXX: reinstate this check when we start testing other platforms */
	cmpl	$0, bt_x86_have_mxcsr
	jz	L2
	pushl	$0
	stmxcsr	(%esp)
	andl	$0xFFFFFFC0, (%esp)  /* mask out status flags */
	cmpl	$0x1F80, (%esp)
	popl	%esi
	jnz	invariant_violation
L2:	/* otherwise we're OK */
	jmp	exit_inner_loop_REALLY

invariant_violation:
	movl	$VK_TRC_INVARIANT_FAILED, %eax
	jmp	exit_inner_loop_REALLY

exit_inner_loop_REALLY:
   call BT_HandleErrorCode /* assumed to be REGPARM(1) */
   testl %eax, %eax
   jne Gate_FromBT 

   /* Decide what mode we should resume user-mode execution in. */
   movl %TSS:oTASK_REGS_EIP, %eax
   /* XXX: should this be called Resume_SelectMode? */
   call Gate_SelectResumeMode /* assumed to be REGPARM */
   testl %eax, %eax
   je Gate_ResumeInDE
   jmp BT_ResumeUserMode
   ASM_NOTREACHED
ENDPROC(BT_InnerLoop)

/*
 *-----------------------------------------------------------------------
 *
 * BT_ResumeUserMode --
 *
 * Summary:
 *
 *    Called on exit from the vkernel, when we want to execute
 *    the app in BT mode. This simply segways into the dispatch loop.
 *
 * Assumption:
 *    %esp points to guest state registers
 *-----------------------------------------------------------------------
 */


STARTPROC(BT_ResumeUserMode)

   #if DEBUG
   movl %esp, %ecx
   call BT_ResumeUserModeSanityCheck
   #endif

   /* Setup the guest-state pointer. */
   GET_CURRENT_TASK(%ebx)
   leal oTASK_REGS(%ebx), %ebp

   /* Stack begins right beneath the VEX guest state. 
    * This is the stack that translated code will use when 
    * run. */
   movl %ebp, %esp 

   /* Load address of code block to execute. */
   movl %TSS:oTASK_REGS_EIP, %eax 

	/* set host FPU control word to the default mode expected 
      by VEX-generated code.  See comments in libvex.h for
      more info. */
	finit
	pushl	$0x027F
	fldcw	(%esp)
	addl	$4, %esp
	
	/* set host SSE control word to the default mode expected 
	   by VEX-generated code. */

   /* XXX: reinstate this check when we start testing other 
    * platforms */
	cmpl	$0, bt_x86_have_mxcsr
	jz	L1
	pushl	$0x1F80
	ldmxcsr	(%esp)
	addl	$4, %esp
L1:
	/* set dir flag to known value */
	cld

   jmp BT_InnerLoop
ENDPROC(BT_ResumeUserMode)
