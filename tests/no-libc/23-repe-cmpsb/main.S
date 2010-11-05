#include <libcommon/asmmacros.h>
#include <libcommon/syscallids.h>

/*
 * Compares bytes in array1 and array2 for at most
 * 4096 bytes. But stop when notmatching byte is found. 
 *
 * VEX generated code for REPE differs a little from 
 * that of REP.
 */

.comm array1, 4096
.comm array2, 4096

STARTPROC(_start)
   cld /* ensure target address is incremented during REP */
again:
   movl $0, %eax
   leal array1, %edi
   leal array2, %esi
   movl $1024, %ecx
   repe cmpsb

   movl $SYS_write, %eax
   movl $-1, %ebx
   movl $0, %ecx
   SYSCALL_ENTER_LINUX

   jmp again

   movl $SYS_exit, %eax
   SYSCALL_ENTER_LINUX
ENDPROC(_start)
