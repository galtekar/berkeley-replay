.text
.globl _start
.type _start, @function
_start:
again:
#if 0
   /* Kernel won't segfault on this, even if
    * 0xffffe000 page isn't mapped. But will
    * segfault on 0xfffff000. */
   movl $0xffffe000, %eax
   movl (%eax), %ecx
#endif
   //movl $0xdeadbeef, %eax
   movl $0xc0011dea, %eax
   jmp again
.size _start,.-_start
