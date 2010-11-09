.file	"rsyscall.S"

#include "vkernel/macros.h"
#include "errno.h"


#if 0
/* Define and make space for the real_vsyscall pointer. */
.globl real_vsyscall
	.data
	.align 4
	.type	real_vsyscall, @object
	.size	real_vsyscall, 4
real_vsyscall:
	.long	0
#endif

/**************** Macros to save register state. *****************/

/* Note: %ebp should be pushed first on the stack to simulate
 * the pusb %ebp typically done at the prologue. This provides
 * better/correct unwinding of the stack. 
 *
 * XXX: Is this true? Verify and fix if needed.
 *
 */

/*
 * XXX: no need to save ECX or EAX -- verify and implement.
 */
.macro MacroPushRegs
	pushl %ebp;
	pushl %edi;
	pushl %esi;
	pushl %edx;
	pushl %ecx;
	pushl %ebx;
.endm

.macro MacroPopRegs
	popl	%ebx;
	popl	%ecx;
	popl	%edx;
	popl	%esi;
	popl	%edi;
	popl	%ebp;
.endm

.macro MacroDoArgs
   movl oSYSARGS_EAX(%ecx), %eax
   movl oSYSARGS_EBX(%ecx), %ebx
   movl oSYSARGS_EDX(%ecx), %edx
   movl oSYSARGS_ESI(%ecx), %esi
   movl oSYSARGS_EDI(%ecx), %edi
   movl oSYSARGS_EBP(%ecx), %ebp
   movl oSYSARGS_ECX(%ecx), %ecx
.endm

/*****************************************************************/

.text

/*
 * ----------------------------------------------------------------
 * Summary:
 *    Makes a system call, given a pointer to a struct SysArgs
 *    in %ecx.
 *
 * Notes:
 *    Should be extern'ed as ASMLINKAGE so that the caller will
 *    place arg in %ecx rather than pushing it on the stack.
 *
 * ----------------------------------------------------------------
 */
STARTPROC(Task_RealSyscall)
	MacroPushRegs
	MacroDoArgs

   SYSCALL_ENTER_LINUX

	MacroPopRegs

	/* %eax should contain the return value of the syscall. */

	ret
ENDPROC(Task_RealSyscall)


/* Not meant to be called during replay. */
STARTPROC(Task_BlockingRealSyscall)
	MacroPushRegs

   /*
    * We want the syscall to return immediately with EINTR
    * if we got an IPI -- the IPI is a reschedule request
    * from another task that must be handled before
    * blocking in order to avoid stalls and possible deadlock.
    *
    * Note that we use an exception table to catch the race
    * where we get kicked after checking for pending ipi
    * but before making the syscall.
    */
   MacroDoArgs
1: pushl %eax     /* We're about to clobber the sysno arg. */
2: movl  %TSS:oTASK_FLAGS, %eax
/* Is there a pending event? If so, we need to handle it right away,
 * and hence we shouldn't invoke the blocking syscall. This
 * ensures responsiveness to IPIs and other signals (e.g., SIGINT
 * from terminal). */
3: andl  $TIF_INTR_PENDING, %eax 
4: movl  $-EINTR, %eax
5: jne   ipipending
6: popl  %eax
7: SYSCALL_ENTER_LINUX
   jmp   out

ipipending:
   addl $4, %esp

out:
   /* Clear TIF_IO_PENDING immediately after syscall to avoid IPIs -- IPIs
    * aren't desirable; if we do get them, then we'll have to
    * bail out of the IO syscall, and doing that excessively
    * can result in livelock. Note, however, that even though we clear 
    * it, we may still get an IPI since the kernel mask hasn't been 
    * reenabled yet. */
   andl $~(TIF_IO_PENDING), %TSS:oTASK_FLAGS
   MacroPopRegs

	/* %eax should contain the return value of the syscall. */

	ret
.section .__ex_table, "a"
/* 
 * What does this table mean? It says that if we get a signal after 
 * reading TIF_INTR_PENDING but before making the syscall, then we
 * should check TIF_INTR_PENDING again. Handling this race is the
 * reason why we implemented this routine in asm.
 */
   .long 3b, 2b, 0 /* 0 means execute on any signal */
   .long 4b, 2b, 0
   .long 5b, 2b, 0
   .long 6b, 2b, 0
   .long 7b, 1b, 0
.previous
ENDPROC(Task_BlockingRealSyscall)

STARTPROC(Task_RealClone)
	/* Here's the expected layout of the stack:
		========================
		parent's retaddr    <--- %esp
		========================

		1st arg (SyscallArgs*) is in ECX
	*/

	MacroPushRegs
	MacroDoArgs

   /* Note that %ecx no longer points to the fastcall argument --
    * it now holds the sys_clone argument corresponding to %ecx. */

   /* Note that %eax == SYS_clone or SYS_fork */
   SYSCALL_ENTER_LINUX

	testl %eax, %eax

	/* %eax > 0 iff this is the parent. */
	jl parent

	/* %eax == 0 iff this is the child. */
	jz child

	/* On error (i.e., %eax < 0), return. */

parent:

   /* On original stack. */
	MacroPopRegs
	ret

child:
   /* This isn't required for sys_clone since the kernel
    * will set %esp to %ecx (the address of ther monitor stack). 
    * But the kernel doesn't do it for sys_fork and so we must do 
    * it to ensure that Task_Start executes on the monitor
    * stack. This in turn ensures that we don't introduce
    * non-determinism in to the app's stack. */
   movl %ecx, %esp

   /* On child stack -- should be the kernel stack,
      with expected layout: 

      TaskRegs <--- %esp

      Moreover, the TaskRegs should be filled in with user-mode
      context this task should resume in.
    */

   jmp Start_TaskBirth

   ASM_NOTREACHED
ENDPROC(Task_RealClone)


/*
 * Fork a process and make it execute the specified syscall
 * without race conditions on the presumably shared stack. 
 * That means nether parent nor child should concurrently
 * write to the stack.
 * This can be used to implement system(), for example.
 */
STARTPROC(Task_ChildSyscall)
   MacroPushRegs
   
   movl $SYS_fork, %eax
   SYSCALL_ENTER_LINUX

   testl %eax, %eax

   jl ChildSyscall_parent

   jz ChildSyscall_child

ChildSyscall_parent:
   movl %eax, %ebx /* pid */
   movl $0, %ecx /* int* status */
   movl $0, %edx /* options */
   movl $SYS_waitpid, %eax
   SYSCALL_ENTER_LINUX

   MacroPopRegs
   ret

ChildSyscall_child:
   MacroDoArgs

   SYSCALL_ENTER_LINUX
ENDPROC(Task_ChildSyscall)
