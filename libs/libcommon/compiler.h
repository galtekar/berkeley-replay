#pragma once

#define INLINE inline

typedef unsigned long long ullong;
typedef unsigned long ulong;
typedef unsigned int  uint;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef long SyscallRet;

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

typedef signed long long s64;
typedef unsigned long long u64;

#define UNUSED       __attribute__ ((unused))
#define ALIGN(x)        __attribute__ ((aligned (x)))
#define FASTCALL        __attribute__ ((fastcall))
#define ASMLINKAGE      FASTCALL 

#ifndef REGPARM
#define REGPARM(x)      __attribute__ ((regparm (x)))
#endif

#define NORETURN        __attribute__ ((noreturn))

#ifndef offsetof
#define offsetof(t, m) __builtin_offsetof(t, m)
#endif

#define __user          __attribute__((address_space(3)))

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#ifndef __attribute_used__
#define __attribute_used__	__attribute__((__used__))
#endif


#ifndef TRUE
#define TRUE  1
#elif TRUE != 1
#error
#endif

#ifndef FALSE
#define FALSE 0
#elif FALSE != 0
#error
#endif
