#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/socket.h>

#include "errops.h"
#include "compiler.h"
#include "usercopy.h"
#include "sharedarea.h"


#undef sigmask /* glibc's sigmask won't work in asm */
#define sigmask(sig) (1 << ((sig) - 1))

/* Generic arbitrary sized copy.  */
#define __copy_user(to,from,size,fault_mask)					\
do {									\
	int __d0, __d1, __d2;						\
	__asm__ __volatile__(						\
		"	cmp  $7,%0\n"					\
		"	jbe  1f\n"					\
		"	movl %1,%0\n"					\
		"	negl %0\n"					\
		"	andl $7,%0\n"					\
		"	subl %0,%3\n"					\
		"4:	rep; movsb\n"					\
		"	movl %3,%0\n"					\
		"	shrl $2,%0\n"					\
		"	andl $3,%3\n"					\
		"	.align 2,0x90\n"				\
		"0:	rep; movsl\n"					\
		"	movl %3,%0\n"					\
		"1:	rep; movsb\n"					\
		"2:\n"							\
		".section .fixup,\"ax\"\n"				\
		"5:	addl %3,%0\n"					\
		"	jmp 2b\n"					\
		"3:	lea 0(%3,%0,4),%0\n"				\
		"	jmp 2b\n"					\
		".previous\n"						\
		".section .__ex_table,\"a\"\n"				\
		"	.align 4\n"					\
		"	.long 4b,5b,"fault_mask"\n"					\
		"	.long 0b,3b,"fault_mask"\n"					\
		"	.long 1b,2b,"fault_mask"\n"					\
		".previous"						\
		: "=&c"(size), "=&D" (__d0), "=&S" (__d1), "=r"(__d2)	\
		: "3"(size), "0"(size), "1"(to), "2"(from)		\
		: "memory");						\
} while (0)

#define __copy_user_zeroing(to,from,size,fault_mask)				\
do {									\
	int __d0, __d1, __d2;						\
	__asm__ __volatile__(						\
		"	cmp  $7,%0\n"					\
		"	jbe  1f\n"					\
		"	movl %1,%0\n"					\
		"	negl %0\n"					\
		"	andl $7,%0\n"					\
		"	subl %0,%3\n"					\
		"4:	rep; movsb\n"					\
		"	movl %3,%0\n"					\
		"	shrl $2,%0\n"					\
		"	andl $3,%3\n"					\
		"	.align 2,0x90\n"				\
		"0:	rep; movsl\n"					\
		"	movl %3,%0\n"					\
		"1:	rep; movsb\n"					\
		"2:\n"							\
		".section .fixup,\"ax\"\n"				\
		"5:	addl %3,%0\n"					\
		"	jmp 6f\n"					\
		"3:	lea 0(%3,%0,4),%0\n"				\
		"6:	pushl %0\n"					\
		"	pushl %%eax\n"					\
		"	xorl %%eax,%%eax\n"				\
		"	rep; stosb\n"					\
		"	popl %%eax\n"					\
		"	popl %0\n"					\
		"	jmp 2b\n"					\
		".previous\n"						\
		".section .__ex_table,\"a\"\n"				\
		"	.align 4\n"					\
		"	.long 4b,5b,"fault_mask"\n"					\
		"	.long 0b,3b,"fault_mask"\n"					\
		"	.long 1b,6b,"fault_mask"\n"					\
		".previous"						\
		: "=&c"(size), "=&D" (__d0), "=&S" (__d1), "=r"(__d2)	\
		: "3"(size), "0"(size), "1"(to), "2"(from)		\
		: "memory");						\
} while (0)

/*
 * Copy a null terminated string from userspace.
 */

#define __do_strncpy_from_user(dst,src,count,res,fault_mask)			   \
do {									   \
	int __d0, __d1, __d2;						   \
	__asm__ __volatile__(						   \
		"	testl %1,%1\n"					   \
		"	jz 2f\n"					   \
		"0:	lodsb\n"					   \
		"	stosb\n"					   \
		"	testb %%al,%%al\n"				   \
		"	jz 1f\n"					   \
		"	decl %1\n"					   \
		"	jnz 0b\n"					   \
		"1:	subl %1,%0\n"					   \
		"2:\n"							   \
		".section .fixup,\"ax\"\n"				   \
		"3:	movl %5,%0\n"					   \
		"	jmp 2b\n"					   \
		".previous\n"						   \
		".section __ex_table,\"a\"\n"				   \
		"	.align 4\n"					   \
		"	.long 0b,3b,"fault_mask"\n"					   \
		".previous"						   \
		: "=d"(res), "=c"(count), "=&a" (__d0), "=&S" (__d1),	   \
		  "=&D" (__d2)						   \
		: "i"(-EFAULT), "0"(count), "1"(count), "3"(src), "4"(dst) \
		: "memory");						   \
} while (0)

#define str(x) #x
#define xstr(x) str(x)

#define __do_cmpxchg32(res, ptr, oldP, new, fault_mask) \
   res = 0; \
   do { \
   __asm__ __volatile__( \
         "0: lock; cmpxchgl %2,%3\n" \
         "2:\n" \
         ".section .fixup,\"ax\"\n" \
         "3: movl %5,%1\n" \
         "   jmp 2b\n" \
         ".previous\n" \
         ".section .__ex_table,\"a\"\n" \
         "  .align 4\n" \
         "  .long 0b,3b,"fault_mask"\n" \
         ".previous\n" \
         : "=a"(*oldP), "=m"(res) \
         : "r"(new), "m"(*__xg(ptr)), "0"(*oldP), "i"(-EFAULT) \
         : "memory"); \
   } while (0)

int
cmpxchg_user(volatile void *ptr, ulong *oldP, ulong newVal)
{
   int res;

   __do_cmpxchg32(res, ptr, oldP, newVal, xstr(sigmask(SIGSEGV)));

   ASSERT_MSG(res == 0 || res == -EFAULT, "res=%d\n", res);

   return res;
}


ulong
copy_to_user(void __user *to, const void *from, ulong n) 
{
   /* XXX: verify @to is really in user-space. */
   __copy_user(to, from, n, xstr(sigmask(SIGSEGV)));

   return n;
}

ulong
copy_from_user(void *to, const void __user *from, ulong n) 
{
   /* XXX: verify @from is really from user-space */
   __copy_user_zeroing(to, from, n, xstr(sigmask(SIGSEGV)));

   return n;
}

ulong
copy_to_user_iov(
      const struct iovec *vec, 
      ulong vlen, 
      const char *src, 
      ulong bytesToCopy)
{
   int i;
   ulong sum = 0;
   const char *p = src;
   int err = 0;

   for (i = 0; i < vlen; i++) {
      if (bytesToCopy < sum + vec[i].iov_len) {
         break;
      }

      if (copy_to_user(vec[i].iov_base, p, vec[i].iov_len)) {
         err = -1;
         goto out;
      }
      sum += vec[i].iov_len;
      p += vec[i].iov_len;
   }

   if (i < vlen) {
      if (copy_to_user(vec[i].iov_base, p, bytesToCopy - sum)) {
         err = -1;
         goto out;
      }
   }

out:
   return err;
}

ulong
copy_from_user_iov(
      char *dest, 
      const struct iovec *vec, 
      ulong vlen, 
      ulong bytesToCopy)
{
   int err = 0;
   ulong sum = 0;
   int i;
   char *p = dest;

   for (i = 0; i < vlen; i++) {
      if (bytesToCopy < sum + vec[i].iov_len) {
         break;
      }

      if (copy_from_user(p, vec[i].iov_base, vec[i].iov_len)) {
         err = -1;
         goto out;
      }
      sum += vec[i].iov_len;
      p += vec[i].iov_len;
   }

   if (i < vlen) {
      if (copy_from_user(p, vec[i].iov_base, bytesToCopy - sum)) {
         err = -1;
         goto out;
      }
   }

out:
   return err;
}

long
strncpy_from_user(char *dst, const char __user *src, long count)
{
   long res;
   __do_strncpy_from_user(dst, src, count, res, xstr(sigmask(SIGSEGV)));  
   return res;
}

/**
 * strnlen_user: - Get the size of a string in user space.
 * @s: The string to measure.
 * @n: The maximum valid length
 *
 * Get the size of a NUL-terminated string in user space.
 *
 * Returns the size of the string INCLUDING the terminating NUL.
 * On exception, returns 0.
 * If the string is too long, returns a value greater than @n.
 */
long strnlen_user(const char __user *s, long n)
{
#if 0
   // original
	unsigned long mask = -__addr_ok(s);
#else
	unsigned long mask = -1;
#endif
	unsigned long res, tmp;

	__asm__ __volatile__(
		"	testl %0, %0\n"
		"	jz 3f\n"
		"	andl %0,%%ecx\n"
		"0:	repne; scasb\n"
		"	setne %%al\n"
		"	subl %%ecx,%0\n"
		"	addl %0,%%eax\n"
		"1:\n"
		".section .fixup,\"ax\"\n"
		"2:	xorl %%eax,%%eax\n"
		"	jmp 1b\n"
		"3:	movb $1,%%al\n"
		"	jmp 1b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 4\n"
		"	.long 0b,2b\n"
		".previous"
		:"=r" (n), "=D" (s), "=a" (res), "=c" (tmp)
		:"0" (n), "1" (s), "2" (0), "3" (mask)
		:"cc");
	return res & mask;
}

/*
 * Zero Userspace
 */

#define __do_clear_user(addr,size)					\
do {									\
	int __d0;							\
  	__asm__ __volatile__(						\
		"0:	rep; stosl\n"					\
		"	movl %2,%0\n"					\
		"1:	rep; stosb\n"					\
		"2:\n"							\
		".section .fixup,\"ax\"\n"				\
		"3:	lea 0(%2,%0,4),%0\n"				\
		"	jmp 2b\n"					\
		".previous\n"						\
		".section __ex_table,\"a\"\n"				\
		"	.align 4\n"					\
		"	.long 0b,3b\n"					\
		"	.long 1b,2b\n"					\
		".previous"						\
		: "=&c"(size), "=&D" (__d0)				\
		: "r"(size & 3), "0"(size / 4), "1"(addr), "a"(0));	\
} while (0)



/**
 * clear_user: - Zero a block of memory in user space.
 * @to:   Destination address, in user space.
 * @n:    Number of bytes to zero.
 *
 * Zero a block of memory in user space.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
unsigned long
clear_user(void __user *to, unsigned long n)
{
   __do_clear_user(to, n);

   return n;
}
