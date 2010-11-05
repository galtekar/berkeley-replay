#pragma once

#ifdef __ASSEMBLER__

#define C_LABEL(name) name:

#define C_SYMBOL_NAME(name) name

#define STARTPROC(name) \
        .global C_SYMBOL_NAME(name); \
        .align 4;\
        C_LABEL(name);\
        .type name,@function;

#define ENDPROC(name) \
        .type name, @function; \
        .size name, . - name

#define VARIABLE(name) \
        .globl C_SYMBOL_NAME(name); \
        .data; \
        .align 4; \
        .type name, @object; \
        C_LABEL(name);

#define END(name) \
        .size name, .-name

#define SYSCALL_ENTER_LINUX int $0x80

#define ASM_NOTREACHED \
         hlt /* will SIGSEGV at CPL 3 */


/* Don't have to worry about clobbered regs. 
 * XXX: this needs optimization (!!) .. is there CPUID
 * flag that doesn't clobber registers? */
.macro MacroSafeCPUID
   pushl %eax
   pushl %ebx
   pushl %ecx
   pushl %edx
   movl $0, %eax
   cpuid
   popl %edx
   popl %ecx
   popl %ebx
   popl %eax
.endm

.macro MacroReadBrCnt
   PmcOps_MacroReadBrCnt %TSS:oPERFCTR_CPUSTATE
.endm

#else /* __ASSEMBLER__ */

/*
 * Save a segment register.
 */
#define savesegment(seg, value) \
	asm volatile("mov %%" #seg ",%0":"=rm" (value));



#endif
