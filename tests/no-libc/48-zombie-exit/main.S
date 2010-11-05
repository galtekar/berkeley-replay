// ------------------------------------------------------------------------
// Purpose:
//
// We use this to test vkernel's shutdown code in the presence of zombies.
// Before the init task dies, it should kill all other processes and
// reap them. If other process are already dead, they should be reaped
// (if they haven't been already).
// ------------------------------------------------------------------------
.text
.globl _start
.type _start, @function
_start:
   // Fork
   movl $2, %eax
   int $0x80

   // Exit
   movl $1, %eax
   int $0x80
.size _start,.-_start
