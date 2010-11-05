// -----------------------------------------------------------------------
// Purpose: Just fork a child. This tests vkernel's forking and exit
// handling code.
// -----------------------------------------------------------------------
.text
.globl _start
.type _start, @function
_start:
   movl $2, %eax
   int $0x80
   testl %eax, %eax
   jl parent
   jz child
parent:
   movl %eax, %ebx /* pid */
   movl $0, %ecx /* int* status */
   movl $0, %edx /* options */
   movl $7, %eax
   int $0x80
child:
   movl $1, %eax
   int $0x80
.size _start,.-_start
