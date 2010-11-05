#pragma once

#define RW_LOCK_BIAS		 0x01000000
#define RW_LOCK_BIAS_STR	"0x01000000"

#ifdef __ASSEMBLER__
/* 
 * We expect @rw to be an address. 
 *
 * We expect these routines not to touch the stack.
 * The vkernel relies on this to share an exit stack. */

.macro mSpin_ReadLock rw:req
   /* Must load lock address into eax so that
    * the slow path knows the address to poll on 
    * (see __read_lock_failed). */
   leal \rw, %eax
   lock; subl $1, (%eax)
   jns 1f
   call __read_lock_failed
1:
.endm

.macro mSpin_WriteLock rw:req
   leal \rw, %eax
	lock; subl $RW_LOCK_BIAS, (%eax)
	jz 1f
	call __write_lock_failed
1:
.endm

.macro mSpin_ReadUnlock rw:req
	lock; incl \rw
.endm

.macro mSpin_WriteUnlock rw:req
   lock; addl $RW_LOCK_BIAS, \rw
.endm

#else /* __ASSEMBLER__ */


/**
 * read_can_lock - would read_trylock() succeed?
 * @lock: the rwlock in question.
 */
#define Spin_CanReadLock(x)		((int)(*x) > 0)

/**
 * write_can_lock - would write_trylock() succeed?
 * @lock: the rwlock in question.
 */
#define Spin_CanWriteLock(x)		((*x) == RW_LOCK_BIAS)

#define RW_LOCK_INIT RW_LOCK_BIAS

static INLINE void
Spin_ReadLock(volatile int *rw)
{
   asm volatile(LOCK_PREFIX "subl $1,(%0)\n\t"
         "jns 1f\n"
         "call __read_lock_failed\n\t"
         "1:\n"
         ::"a" (rw) : "memory");
}

static INLINE void
Spin_WriteLock(volatile int *rw)
{
	asm volatile(LOCK_PREFIX "subl $" RW_LOCK_BIAS_STR ",(%0)\n\t"
			"jz 1f\n"
			"call __write_lock_failed\n\t"
			"1:\n"
			::"a" (rw) : "memory");
}

static INLINE void 
Spin_ReadUnlock(volatile int *rw)
{
	asm volatile(LOCK_PREFIX "incl %0" :"+m" (*rw) : : "memory");
}

static INLINE void 
Spin_WriteUnlock(volatile int *rw)
{
	asm volatile(LOCK_PREFIX "addl $" RW_LOCK_BIAS_STR ", %0"
				 : "+m" (*rw) : : "memory");
}

#endif
