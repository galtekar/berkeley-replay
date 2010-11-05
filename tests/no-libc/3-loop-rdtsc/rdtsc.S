.text
.globl _start
.type _start, @function
_start:
again:
#if 0
   movl $0, %eax
   cpuid
#endif
   rdtsc
   jmp again
.size _start,.-_start
