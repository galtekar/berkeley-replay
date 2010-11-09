// ------------------------------------------------------------------------
// Purpose: Test vkernel's (VEX's) handling of the REP x86 prefix.
// Useful for understanding what the translation is and its implications
// for branch counting.
// ------------------------------------------------------------------------

#include <libcommon/asmmacros.h>
#include <libcommon/syscallids.h>

.comm array, 4096

STARTPROC(_start)
   cld 
   movl $0, %eax
again:
   leal array, %edi
   movl $1024, %ecx
   rep stosl

   movl $SYS_exit, %eax
   SYSCALL_ENTER_LINUX
ENDPROC(_start)
