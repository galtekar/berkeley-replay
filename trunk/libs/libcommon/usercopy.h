#pragma once

#include "compiler.h"





#if 0
#define __get_user_x(size,ret,x,ptr) \
	__asm__ __volatile__("call __get_user_" #size \
		:"=a" (ret),"=d" (x) \
		:"0" (ptr))


/* Careful: we have to cast the result to the type of the pointer for sign reasons */
/**
 * get_user: - Get a simple variable from user space.
 * @x:   Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only.  This function may sleep.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
#define get_user(x,ptr)							\
({	int __ret_gu;							\
	unsigned long __val_gu;						\
	__chk_user_ptr(ptr);						\
	switch(sizeof (*(ptr))) {					\
	case 1:  __get_user_x(1,__ret_gu,__val_gu,ptr); break;		\
	case 2:  __get_user_x(2,__ret_gu,__val_gu,ptr); break;		\
	case 4:  __get_user_x(4,__ret_gu,__val_gu,ptr); break;		\
	default: __get_user_x(X,__ret_gu,__val_gu,ptr); break;		\
	}								\
	(x) = (__typeof__(*(ptr)))__val_gu;				\
	__ret_gu;							\
})
#endif

extern int cmpxchg_user(volatile void *ptr, ulong *oldP, ulong newVal);

extern ulong copy_to_user(void __user *to, const void *from, ulong n);

extern ulong copy_from_user(void *to, const void __user *from, ulong n);

extern ulong
copy_to_user_iov(
      const struct iovec *vec, 
      ulong vlen, 
      const char *src, 
      ulong bytesToCopy);

extern ulong
copy_from_user_iov(
      char *dest, 
      const struct iovec *vec, 
      ulong vlen, 
      ulong bytesToCopy);

extern long strncpy_from_user(char *ddst, const char __user *src, long count);

extern long strnlen_user(const char __user *s, long n);

#if 0
extern char * getname(const char __user * filename);

extern void putname(const char *filename);
#endif

extern ulong clear_user(void __user *to, unsigned long n);
