#include <libcommon/asmmacros.h>
#include <libcommon/syscallids.h>

.text
.globl _start
.type _start, @function
_start:
   movl $0, %eax
   movl $0, (%eax)

   /* Must make syscall to tell VEX decoder not
    * to decode past here. */
   movl $SYS_exit, %eax
   int $0x80
.size _start,.-_start
