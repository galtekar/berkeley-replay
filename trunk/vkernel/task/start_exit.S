.file "start_exit.S"

#include "vkernel/macros.h"
#include "libcommon/spinlock.h"


/* 
 * --------------------------------------------------------------------------
 * _start --
 *
 *    vkernel execution begins here. Our job is to simply trampoline to
 *    the init code. It will take care of allocating the initial task struct,
 *    preparing the stack, execing init, etc.
 * --------------------------------------------------------------------------
 */
.text
STARTPROC(_start)
   movl %esp, entryESP

   /*
    * We begin execution on a process-private startup stack 
    * (distinct from the stack provided by Linux) for two
    * reasons. First we need to setup the shared area before we can
    * become the initTask, because the initTask lives in the SHAREDAREA.
    * If we started in the initTask stack, then SHAREDAREA setup will
    * fail and most-likely crash the kernel. The second reason is that 
    * we don't want to introduce non-determinism into the app's stack
    * by using it for startup. Besides, it will disappear once we
    * exec the init process.
    */
   leal startupTask, %esp
   leal oTASK_REGS(%esp), %esp

   /*
    * Setup the shared area, environment vars, auxV, etc.
    */
   call System_PreInit

   /*
    * Now that the shared area has been setup, it's safe to switch to the init
    * process's stack.
    */
   leal initTask, %esp
   leal oTASK_REGS(%esp), %esp

   /* Init the Task TSS so that in case we get a signal (SIGSEGV or SIGABRT)
    * during initialization, we won't segfault in entry.S when we
    * try to setup the TSS register. 
    *
    * We could install the task segment in the clone (with CLONE_SETTLS),
    * but then we won't be able to install the libpthread TLS segment
    * using clone. Hence we install the task segment separately. */
   leal initTask, %ecx
   call Task_SetupTLS /* assumed to be FASTCALL */
   call System_Init 

   movl $1, hasAppExecutionBegun
   jmp Start_TaskBirth

   ASM_NOTREACHED
ENDPROC(_start)

STARTPROC(Start_TaskBirth)
   call Task_Start

   jmp Gate_ResumeUserMode

   ASM_NOTREACHED
ENDPROC(Start_TaskBirth)

/*
 * Free the task struct and terminate task execution.
 * A little tricky because we can't be on the task stack when
 * we deallocate the task struct (since the task stack is part
 * of the task struct). So must switch to exit stack,
 * but that has to be protected against concurrent exits. 
 *
 * XXX: don't be fooled -- we acquire a ``write'' lock here, but
 * no one every acquires a read lock -- any spin lock would do here.
 */
STARTPROC(Exit_Die)
   /* Protect access to the shared exit stack. */
   mSpin_WriteLock   exitLock

   movl $SYS_gettid, %eax
   SYSCALL_ENTER_LINUX
   movl %eax, %ebx

   /* We re-use the startupTask's stack for the exit stack. */
   GET_CURRENT_TASK(%eax)
   leal startupTask, %esp
   leal oTASK_REGS(%esp), %esp


   /* Set the task's tid -- otherwise sync routines need it to
    * acquire locks. */
   movl %ebx, oTASK_REAL_PID+startupTask

   movl oPERFCTR(%eax), %ecx
   movl $0, oPERFCTR(%eax)
   movl oPERFCTR_PAGE_IDX(%eax), %edx


   pushl %ecx
   pushl %edx

   /* We're now on the exit stack and not on the task stack. 
    * So it's safe to free the task struct now. */
   call Task_Put

   popl %edx
   popl %ecx

   call BrCnt_SelfExit

   /* There are ASSERTs in Task_Put -- if they fire, we want them to
    * write to the debug logs. Hence close the debug logs as late as
    * possible. */
   call Debug_Exit

   mSpin_WriteUnlock exitLock

   /* CAUTION: don't access the exit stack -- there will be a race */
   movl $SYS_exit, %eax
   SYSCALL_ENTER_LINUX
   ASM_NOTREACHED
ENDPROC(Exit_Die)

/* Let the linker know we don't need an executable stack */
.section .note.GNU-stack,"",@progbits
