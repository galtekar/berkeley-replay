#include <libcommon/asmmacros.h>
#include <libcommon/syscallids.h>
//#include <libcommon/memops.h>

.comm array, 4096

STARTPROC(_start)
again:

   jmp 1f
1:
   jmp again

   movl $SYS_exit, %eax
   SYSCALL_ENTER_LINUX
ENDPROC(_start)
