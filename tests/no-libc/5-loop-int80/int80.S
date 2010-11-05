.text
.globl _start
.type _start, @function
_start:
again:
   movl $4, %eax /* 4 = SYS_write */
   int $0x80

   jmp again

   movl $1, %eax
   int $0x80
.size _start,.-_start
