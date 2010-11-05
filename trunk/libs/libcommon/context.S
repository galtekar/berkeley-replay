/* Save current context.
   Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2001.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include "syscallids.h"

#define SIG_BLOCK 0
#define SIG_SETMASK  2

/* Offsets of the fields in the ucontext_t structure.  */
#define oLINK     4
#define oSS_SP    8
#define oSS_SIZE  16
#define oGS    20
#define oFS    24
#define oES		28
#define oDS		32
#define oEDI      36
#define oESI      40
#define oEBP      44
#define oESP      48
#define oEBX      52
#define oEDX      56
#define oECX      60
#define oEAX      64
#define oEIP      76
#define oCS			80
#define oEFL		84
#define oUESP		88
#define oSS			92
#define oFPREGS      96
#define oSIGMASK  108
#define oFPREGSMEM   236


.globl Context_Get
.type Context_Get, @function
Context_Get:
	/* Load address of the context data structure.  */
	movl	4(%esp), %eax

	/* Return value of getcontext.  EAX is the only register whose
	   value is not preserved. We store 1 in it so that upon
	   setcontext() this function will return 1, thereby emulating
	   longjmp behavior. */
	movl	$1, oEAX(%eax)

	/* Save the 32-bit register values and the return address.  */
	movl	%ecx, oECX(%eax)
	movl	%edx, oEDX(%eax)
	movl	%edi, oEDI(%eax)
	movl	%esi, oESI(%eax)
	movl	%ebp, oEBP(%eax)
	movl	(%esp), %ecx
	movl	%ecx, oEIP(%eax)
	leal	4(%esp), %ecx		/* Exclude the return address.  */
	movl	%ecx, oESP(%eax)
	movl	%ebx, oEBX(%eax)

	/* Save the segment registers. */
	xorl	%edx, %edx
	movw	%fs, %dx
	movl	%edx, oFS(%eax)

	movw	%gs, %dx
	movl	%edx, oGS(%eax)

	movw	%es, %dx
	movl	%edx, oES(%eax)

	movw	%ds, %dx
	movl	%edx, oDS(%eax)

	movw	%cs, %dx
	movl	%edx, oCS(%eax)

	movw	%ss, %dx
	movl	%edx, oSS(%eax)


	/* We have separate floating-point register content memory on the
	   stack.  We use the __fpregs_mem block in the context.  Set the
	   links up correctly.  */
	leal	oFPREGSMEM(%eax), %ecx
	movl	%ecx, oFPREGS(%eax)
	/* Save the floating-point context.  */
	fnstenv	(%ecx)
	/* And load it right back since the processor changes the mask.
	   Intel thought this opcode to be used in interrupt handlers which
	   would block all exceptions.  */
	fldenv	(%ecx)

	/* Save the current signal mask.  */
	pushl	%ebx
	leal	oSIGMASK(%eax), %edx
	xorl	%ecx, %ecx
	movl	$SIG_BLOCK, %ebx
	movl	$SYS_sigprocmask, %eax
	int	$0x80
	popl	%ebx
	cmpl	$-4095, %eax		/* Check %eax for error.  */
	jae	SYSCALL_ERROR_LABEL_0	/* Jump to error handler if error.  */

	/* All done, return 0 for success.  */
	xorl	%eax, %eax

SYSCALL_ERROR_LABEL_0:
	ret
.size Context_Get, .-Context_Get

.globl Context_Set
.type Context_Set, @function
Context_Set:
	/* Load address of the context data structure.  */
	movl	4(%esp), %eax

#if 0
	/* Get the current signal mask.  Note that we preserve EBX in case
	   the system call fails and we return from the function with an
	   error.  */
	pushl	%ebx
	xorl	%edx, %edx
	leal	oSIGMASK(%eax), %ecx
	movl	$SIG_SETMASK, %ebx
	movl	$SYS_sigprocmask, %eax
	int	$0x80
	popl	%ebx
	cmpl	$-4095, %eax		/* Check %eax for error.  */
   ret
#if 0
	jae	SYSCALL_ERROR_LABEL_1	/* Jump to error handler if error.  */
#endif

	/* EAX was modified, reload it.  */
	movl	4(%esp), %eax
#endif

#if 0
	/* Restore the floating-point context.  Not the registers, only the
	   rest.  */
	movl	oFPREGS(%eax), %ecx
	fldenv	(%ecx)
#endif

	/* Restore the segment registers. */
	xorl	%ecx, %ecx
	movl	oFS(%eax), %ecx
	movw	%cx, %fs

	movl	oGS(%eax), %ecx
	movw	%cx, %gs

	movl	oES(%eax), %ecx
	movw	%cx, %es

#ifdef YOU_REALLY_WANT_A_CRASH
	/* Can't change code segment from CPL 3: you'll get an illegal 
    * instruction error. */
	movl	oCS(%eax), %ecx
	movw	%cx, %cs
#endif

	movl	oDS(%eax), %ecx
	movw	%cx, %ds

	movl	oSS(%eax), %ecx
	movw	%cx, %ss

	/* Fetch the address to return to.  */
	movl	oEIP(%eax), %ecx


	/* Push the return address on the new stack so we can return there.  */
	pushl	%ecx

	/* Load the values of all the 32-bit registers (except ESP).
	   Since we are loading from EAX, it must be last.  */
	movl	oEDI(%eax), %edi
	movl	oESI(%eax), %esi
	movl	oEBP(%eax), %ebp
	movl	oEBX(%eax), %ebx
	movl	oEDX(%eax), %edx
	movl	oECX(%eax), %ecx
	movl	oEAX(%eax), %eax
	/* Load the new stack pointer.  */
	movl	oESP(%eax), %esp

	/* The following 'ret' will pop the address of the code and jump
	   to it.  */

SYSCALL_ERROR_LABEL_1:
	ret
.size Context_Set, .-Context_Set

.globl Context_SetSeg
.type Context_SetSeg, @function
Context_SetSeg:
	/* Load address of the context data structure.  */
	movl	4(%esp), %eax

	/* Restore the segment registers. */
	xorl	%ecx, %ecx
	movl	oFS(%eax), %ecx
	movw	%cx, %fs

	movl	oGS(%eax), %ecx
	movw	%cx, %gs

	movl	oES(%eax), %ecx
	movw	%cx, %es

#if 0
	/* This is illegal: you'll get an illegal instruction error. */
	movl	oCS(%eax), %ecx
	movw	%cx, %cs
#endif

	movl	oDS(%eax), %ecx
	movw	%cx, %ds

	movl	oSS(%eax), %ecx
	movw	%cx, %ss

	ret
.size Context_SetSeg, .-Context_SetSeg
