#include <libcommon/asmmacros.h>
#include <libcommon/syscallids.h>

/*
 * Useful for testing taint flow.
 */

.comm array, 4096

STARTPROC(_start)
again:

   movl $1024, %ecx
   movl array, %eax
   movl $0, %ebx
1:
   movl %eax, array(, %ebx, 4)

   addl $1, %ebx
   loop 1b /* execute loop %ecx times */


   movl $SYS_exit, %eax
   SYSCALL_ENTER_LINUX
ENDPROC(_start)
