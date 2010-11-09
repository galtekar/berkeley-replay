#include "gcc.h"

#define __LIBC_TIMER(f) __ll_libc_##f##_timer

#undef WRAPPERDEF
#undef WRAPPERDEF_NORET
#undef WRAPPERDEF_VARG
#undef WRAPPERDEF_NORET_VARG
#define WRAPPERDEF(T, f, U, ...) HIDDEN int __LIBC_TIMER(f) = 0;
#define WRAPPERDEF_NORET(f, U, ...) HIDDEN int __LIBC_TIMER(f) = 0;
#define WRAPPERDEF_VARG(T, f, l, U, ...) HIDDEN int __LIBC_TIMER(f) = 0;
#define WRAPPERDEF_NORET_VARG(f, l, U, ...) HIDDEN int __LIBC_TIMER(f) = 0;

/* This include must come after the WRAPPERDEF() macros. */
#include "wrapperdefs.h"
