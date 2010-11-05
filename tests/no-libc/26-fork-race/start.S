/* 
 * --------------------------------------------------------------------------
 * _start --
 *
 *    vkernel execution begins here. Our job is to simply trampoline to
 *    the init code. It will take care of allocating the initial task struct,
 *    loading the binary, preparing the stack, etc.
 * --------------------------------------------------------------------------
 */
.text
.globl _start
.type _start, @function
_start:
   movl %esp, entryESP

   call Init_Pre

   movl $1, %eax
   int $0x80

   hlt
.size _start,.-_start
