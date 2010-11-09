#include <libcommon/asmmacros.h>
#include <libcommon/pmcops.h>
#include <libcommon/arch.h>
#include <libcommon/syscallids.h>

.comm array, 4096
.comm jumpTarget, WORD_SIZE

.macro MacroTest type:req, numReps:req, checkN:req
   PmcOps_MacroReadBrCnt2 perfCtrKernelStatePtr

   leal startBrCnt, %ebx
   movl %eax, (%ebx)
   movl %edx, 4(%ebx)

.ifeq \type-0
   .rept \numReps
      leal 1f, %eax
      movl %eax, jumpTarget
      leal jumpTarget, %eax
      jmp *(%eax)
      1:
   .endr
.else
   .ifeq \type-1
      movl $-1, %ecx
      movl $-1, %ebx
      movl $SYS_write, %eax
      .rept \numReps
         int $0x80
         rdtsc
         movl $0, %eax
         cpuid
      .endr
   .else
      .ifeq \type-2
         cld /* ensure counter is incremented */
         .rept \numReps
            movl $0, %eax
            leal array, %edi
            movl $1024, %ecx
            rep stosl
         .endr

      .else
         .ifeq \type-3
            movl $\numReps, %ecx
         2:
            dec %ecx
            jne 2b
         .else
            .ifeq \type-4
            movl $\numReps, %ecx
            leal 4f, %eax
            movl %eax, jumpTarget
            leal jumpTarget, %eax
            3:
            /* Does it count far calls?
             *
             * XXX: not really a far call. */
             call *%cs:(%eax)
             dec %ecx
             jne 3b
             jmp 5f
            4:
             ret
            5:
            .endif
         .endif
      .endif
   .endif
.endif
      

   PmcOps_MacroReadBrCnt2 perfCtrKernelStatePtr

   pushl $\type
   pushl $\checkN
   pushl %edi
   pushl %edx
   pushl %eax
   call BrCntTest_Check
   addl $WORD_SIZE*5, %esp
.endm

#define TEST_BRANCHES(r) MacroTest 0 r r
#define TEST_SYSCALLS(r) MacroTest 1 r 0
#define TEST_REP(r) MacroTest 2 r 0
/* This hardware counter counts conditional jumps 2. */
#define TEST_LOOP(r) MacroTest 3 r (r*2)
/* +1 for jump past the ret */
#define TEST_CALLRET(r) MacroTest 4 r (r*4)+1

STARTPROC(BrCntTest_Main)
again:
   TEST_BRANCHES(0)
   TEST_BRANCHES(1)
   TEST_BRANCHES(10)
   TEST_BRANCHES(100)
   TEST_BRANCHES(1000)
   TEST_BRANCHES(10000)
   TEST_BRANCHES(100000)

#if 1
   TEST_SYSCALLS(0)
   TEST_SYSCALLS(1)
   TEST_SYSCALLS(10)
   TEST_SYSCALLS(100)
   TEST_SYSCALLS(1000)
   TEST_SYSCALLS(10000)
   TEST_SYSCALLS(100000)

   TEST_REP(0)
   TEST_REP(1)
   TEST_REP(10)
   TEST_REP(100)
   TEST_REP(1000)
   TEST_REP(10000)
   TEST_REP(1000000)


   TEST_LOOP(1)
   TEST_LOOP(10)
   TEST_LOOP(100)
   TEST_LOOP(1000)
   TEST_LOOP(10000)
   TEST_LOOP(100000)
   TEST_LOOP(1000000)
   TEST_LOOP(10000000)
   TEST_LOOP(100000000)
   TEST_LOOP(1000000000)


   TEST_CALLRET(1)
   TEST_CALLRET(10)
   TEST_CALLRET(100)
   TEST_CALLRET(1000)
   TEST_CALLRET(10000)
   TEST_CALLRET(100000)
   TEST_CALLRET(1000000)
   TEST_CALLRET(10000000)
   TEST_CALLRET(100000000)
   TEST_CALLRET(1000000000)
#endif


   jmp again
ENDPROC(BrCntTest_Main)
