#include <libcommon/asmmacros.h>

STARTPROC(_start)
   movl %esp, %ecx

   subl $4, %esp
   leal 4(%ecx), %edx
   pushl %edx
   pushl (%ecx)
   call Init

   movl $1, %eax
   int $0x80

   hlt
ENDPROC(_start)
