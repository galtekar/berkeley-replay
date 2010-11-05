.text
.globl _start
.type _start, @function
_start:
again0:
   jmp again1
again1:
   rdtsc
   jmp again0
.size _start,.-_start
