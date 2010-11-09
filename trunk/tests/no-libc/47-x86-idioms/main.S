.text
.globl _start
.type _start, @function
_start:
   xorl %eax, %eax
   xorl %ebx, %ebx
   subl %ecx, %ecx
   sbbl %edx, %edx
   movl $1, %eax
   int $0x80
.size _start,.-_start
