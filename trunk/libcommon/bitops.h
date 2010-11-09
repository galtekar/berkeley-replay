#pragma once

#include "public.h"

#define ADDR (*(volatile long *) addr)

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 */
static INLINE int 
Bit_TestSet(int nr, volatile unsigned long * addr)
{
   int oldbit;

   __asm__ __volatile__(
         "btsl %2,%1\n\tsbbl %0,%0"
         :"=r" (oldbit),"+m" (ADDR)
         :"Ir" (nr) : "memory");
   return oldbit;
}

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 */
static INLINE int 
Bit_TestClear(int nr, volatile unsigned long * addr)
{
   int oldbit;

   __asm__ __volatile__(
         "btrl %2,%1\n\tsbbl %0,%0"
         :"=r" (oldbit),"+m" (ADDR)
         :"Ir" (nr) : "memory");
   return oldbit;
}

static INLINE int 
Bit_Test(int nr, const volatile unsigned long * addr)
{
	int oldbit;

	__asm__ __volatile__(
		"btl %2,%1\n\tsbbl %0,%0"
		:"=r" (oldbit)
		:"m" (ADDR),"Ir" (nr));
	return oldbit;
}

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.  
 * It may be reordered on other architectures than x86.
 * It also implies a memory barrier.
 */
static INLINE int 
Bit_SynchTestSet(int nr, volatile unsigned long * addr)
{
   int oldbit;

   __asm__ __volatile__( LOCK_PREFIX
         "btsl %2,%1\n\tsbbl %0,%0"
         :"=r" (oldbit),"+m" (ADDR)
         :"Ir" (nr) : "memory");
   return oldbit;
}

/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It can be reorderdered on other architectures other than x86.
 * It also implies a memory barrier.
 */
static INLINE int 
Bit_SynchTestClear(int nr, volatile unsigned long * addr)
{
   int oldbit;

   __asm__ __volatile__( LOCK_PREFIX
         "btrl %2,%1\n\tsbbl %0,%0"
         :"=r" (oldbit),"+m" (ADDR)
         :"Ir" (nr) : "memory");
   return oldbit;
}

/**
 * find_first_zero_bit - find the first zero bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-index of the first zero bit, not the number of the byte
 * containing a bit.
 */
static INLINE int 
Bit_FindFirstZeroBit(const unsigned long *addr, unsigned size)
{
	int d0, d1, d2;
	int res;

	if (!size)
		return 0;
	/* This looks at memory. Mark it volatile to tell gcc not to move it around */
	__asm__ __volatile__(
		"movl $-1,%%eax\n\t"
		"xorl %%edx,%%edx\n\t"
		"repe; scasl\n\t"
		"je 1f\n\t"
		"xorl -4(%%edi),%%eax\n\t"
		"subl $4,%%edi\n\t"
		"bsfl %%eax,%%edx\n"
		"1:\tsubl %%ebx,%%edi\n\t"
		"shll $3,%%edi\n\t"
		"addl %%edi,%%edx"
		:"=d" (res), "=&c" (d0), "=&D" (d1), "=&a" (d2)
		:"1" ((size + 31) >> 5), "2" (addr), "b" (addr) : "memory");
	return res;
}

/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static INLINE unsigned long 
__ffs(unsigned long word)
{
	__asm__("bsfl %1,%0"
		:"=r" (word)
		:"rm" (word));
	return word;
}

/**
 * find_first_bit - find the first set bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-number of the first set bit, not the number of the byte
 * containing a bit.
 */
static INLINE unsigned 
Bit_FindFirstBit(const unsigned long *addr, unsigned size)
{
	unsigned x = 0;

	while (x < size) {
		unsigned long val = *addr++;
		if (val)
			return __ffs(val) + x;
		x += (sizeof(*addr)<<3);
	}
	return x;
}

/**
 * find_next_bit - find the first set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
static INLINE int 
Bit_FindNextBit(const unsigned long *addr, int size, int offset)
{
	const unsigned long *p = addr + (offset >> 5);
	int set = 0, bit = offset & 31, res;

	if (bit) {
		/*
		 * Look for nonzero in the first 32 bits:
		 */
		__asm__("bsfl %1,%0\n\t"
			"jne 1f\n\t"
			"movl $32, %0\n"
			"1:"
			: "=r" (set)
			: "r" (*p >> bit));
		if (set < (32 - bit))
			return set + offset;
		set = 32 - bit;
		p++;
	}
	/*
	 * No set bit yet, search remaining full words for a bit
	 */
	res = Bit_FindFirstBit(p, size - 32 * (p - addr));
	return (offset + set + res);
}

/**
 * find_next_zero_bit - find the first zero bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 *
 * Returns bitsetsize+1 if no zero bits.
 */
static INLINE int 
Bit_FindNextZeroBit(const unsigned long *addr, int size, int offset)
{
	unsigned long * p = ((unsigned long *) addr) + (offset >> 5);
	int set = 0, bit = offset & 31, res;

	if (bit) {
		/*
		 * Look for zero in the first 32 bits.
		 */
		__asm__("bsfl %1,%0\n\t"
			"jne 1f\n\t"
			"movl $32, %0\n"
			"1:"
			: "=r" (set)
			: "r" (~(*p >> bit)));
		if (set < (32 - bit))
			return set + offset;
		set = 32 - bit;
		p++;
	}
	/*
	 * No zero yet, search remaining full bytes for a zero
	 */
	res = Bit_FindFirstZeroBit(p, size - 32 * (p - (unsigned long *) addr));
	return (offset + set + res);
}

