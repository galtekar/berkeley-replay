.text
.globl _start
.type _start, @function
_start:
   movl $0, %eax
   movl $0, (%eax)

   /* VEX decoder should produce a NoDecode for this. */
   ud2
.size _start,.-_start
