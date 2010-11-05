#include "spinlock.h"
#include "arch.h"

.file "spinlock.S"

/* EAX is expected to contain addess of lock */

.align	4
.globl	__write_lock_failed
__write_lock_failed:
	lock; addl $RW_LOCK_BIAS, (%eax)
1:	rep; nop
	cmpl	$RW_LOCK_BIAS, (%eax)
	jne	1b
	lock; subl $RW_LOCK_BIAS, (%eax)
	jnz	__write_lock_failed
	ret

.align	4
.globl	__read_lock_failed
__read_lock_failed:
	lock; incl (%eax)
1:	rep; nop
	cmpl $1, (%eax)
	js	1b
	lock; decl (%eax)
	js	__read_lock_failed
	ret
