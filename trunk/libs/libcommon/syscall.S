.file	"rsyscall.S"

#include "syscallids.h"

/**************** Macros to save register state. *****************/

#define PUSH_REGS \
	pushl %ebp; \
	pushl %edi; \
	pushl %esi; \
	pushl %edx; \
	pushl %ecx; \
	pushl %ebx;

#define POP_REGS \
	popl	%ebx; \
	popl	%ecx; \
	popl	%edx; \
	popl	%esi;	\
	popl	%edi; \
	popl	%ebp;

#define DO_ARGS \
	movl	52(%esp), %ebp; \
	movl	48(%esp), %edi; \
	movl	44(%esp), %esi; \
	movl	40(%esp), %edx; \
	movl	36(%esp), %ecx; \
	movl	32(%esp), %ebx; \
	movl	28(%esp), %eax;

.text

/* XXX: need to do argument count checking ... currently
 * not robust against missed argument (may be substituted with garbage). */
/* Invokes the real syscall by jumpying to the appropriate
   location in the VDSO page. This function is meant
   to be called from within one of our syscall handlers. */
.globl __syscall
.type	__syscall, @function
__syscall:
	/* Here's the expected stack layout at this point. :
		========================
		7th arg - %ebp
		6th arg - %edi
		5th arg - %esi
		4rd arg - %edx
		3rd arg - %ecx
		2nd arg - %ebx
		1st arg - %eax 
		parent's retaddr    <--- %esp
		========================
	*/

	PUSH_REGS
	DO_ARGS

	/* BUG: Call through to the syscall stub in the VDSO page instead? */
	int $0x80

	POP_REGS

	/* %eax should contain the return value of the syscall. */

	ret
.size __syscall,.-.__syscall
