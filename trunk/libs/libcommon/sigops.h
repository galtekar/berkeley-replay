#pragma once

#include <signal.h>

#include "arch.h"
#include "compiler.h"
#include "debug.h"

#define _NSIG_BYTES (_NSIG_WORDS*sizeof(ulong))

#if SIGRTMIN > BITS_PER_LONG
/* XXX: same as sigmask() so merge it */
#define M(sig) (1ULL << ((sig)-1))
#else
#define M(sig) (1UL << ((sig)-1))
#endif

#define T(sig, mask) (M(sig) & (mask))
#define SIG_KERNEL_STOP_MASK (\
	M(SIGSTOP)   |  M(SIGTSTP)   |  M(SIGTTIN)   |  M(SIGTTOU)   )

#ifdef SIGEMT
#define M_SIGEMT	M(SIGEMT)
#else /* x86 doesn't have this */
#define M_SIGEMT	0
#endif

#define SIG_KERNEL_ONLY_MASK (\
	M(SIGKILL)   |  M(SIGSTOP))

#define SIG_KERNEL_COREDUMP_MASK (\
        M(SIGQUIT)   |  M(SIGILL)    |  M(SIGTRAP)   |  M(SIGABRT)   | \
        M(SIGFPE)    |  M(SIGSEGV)   |  M(SIGBUS)    |  M(SIGSYS)    | \
        M(SIGXCPU)   |  M(SIGXFSZ)   |  M_SIGEMT                     )

#define SIG_KERNEL_CRASH_MASK (\
        M(SIGILL)    |  M(SIGABRT)   | \
        M(SIGFPE)    |  M(SIGSEGV)   |  M(SIGBUS)    |  M(SIGSYS)    | \
        M(SIGXCPU)   |  M(SIGXFSZ)   |  M_SIGEMT                     )

#define SIG_KERNEL_IGNORE_MASK (\
        M(SIGCONT)   |  M(SIGCHLD)   |  M(SIGWINCH)  |  M(SIGURG)    )

#define sig_kernel_only(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_ONLY_MASK))
#define sig_kernel_crash(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_CRASH_MASK))
#define sig_kernel_coredump(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_COREDUMP_MASK))
#define sig_kernel_ignore(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_IGNORE_MASK))
#define sig_kernel_stop(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_STOP_MASK))

#define sig_user_defined(t, signr) \
	(((t)->sigHand->action[(signr)-1].sa_handler != SIG_DFL) &&	\
	 ((t)->sigHand->action[(signr)-1].sa_handler != SIG_IGN))

#define sig_fatal(t, signr) \
	(!T(signr, SIG_KERNEL_IGNORE_MASK|SIG_KERNEL_STOP_MASK) && \
	 (t)->sigHand->action[(signr)-1].sa_handler == SIG_DFL)


#define _SIG_SET_BINOP(name, op)					\
static INLINE void name(sigset_t *r, const sigset_t *a, const sigset_t *b) \
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
	ulong a0, a1, a2, a3, b0, b1, b2, b3;			\
									\
	switch (_NSIG_WORDS) {						\
	    case 4:							\
		a3 = a->sig[3]; a2 = a->sig[2];				\
		b3 = b->sig[3]; b2 = b->sig[2];				\
		r->sig[3] = op(a3, b3);					\
		r->sig[2] = op(a2, b2);					\
	    case 2:							\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
	    case 1:							\
		a0 = a->sig[0]; b0 = b->sig[0];				\
		r->sig[0] = op(a0, b0);					\
		break;							\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}

#define _sig_or(x,y)	((x) | (y))
_SIG_SET_BINOP(SigOps_OrSets, _sig_or)

#define _sig_and(x,y)	((x) & (y))
_SIG_SET_BINOP(SigOps_AndSets, _sig_and)

#define _sig_nand(x,y)	((x) & ~(y))
_SIG_SET_BINOP(SigOps_NandSets, _sig_nand)

#define _SIG_SET_OP(name, op)						\
static inline void name(sigset_t *set)					\
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
									\
	switch (_NSIG_WORDS) {						\
	    case 4: set->sig[3] = op(set->sig[3]);			\
		    set->sig[2] = op(set->sig[2]);			\
	    case 2: set->sig[1] = op(set->sig[1]);			\
	    case 1: set->sig[0] = op(set->sig[0]);			\
		    break;						\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}

#define _sig_not(x)	(~(x))
_SIG_SET_OP(SigOps_NotSet, _sig_not)

/* Some extensions for manipulating the low 32 signals in particular.  */

static INLINE void 
SigOps_AddSetMask(sigset_t *set, ulong mask)
{
	set->sig[0] |= mask;
}

static INLINE void 
SigOps_DelSetMask(sigset_t *set, ulong mask)
{
	set->sig[0] &= ~mask;
}

static INLINE int 
SigOps_TestSetMask(sigset_t *set, ulong mask)
{
	return (set->sig[0] & mask) != 0;
}

static INLINE int 
SigOps_IsEmptySet(sigset_t *set)
{
   ASSERT(sizeof(sigset_t) == _NSIG_WORDS*WORD_SIZE);

	switch (_NSIG_WORDS) {
	case 4:
		return (set->sig[3] | set->sig[2] |
			set->sig[1] | set->sig[0]) == 0;
	case 2:
		return (set->sig[1] | set->sig[0]) == 0;
	case 1:
		return set->sig[0] == 0;
	default:
      ASSERT_UNIMPLEMENTED(0);
		return 0;
	}
}

static INLINE void 
SigOps_InitSet(sigset_t *set, unsigned long mask)
{
   ASSERT(sizeof(sigset_t) == _NSIG_WORDS*WORD_SIZE);
   memset(set, 0, sizeof(*set));

	set->sig[0] = mask;
	switch (_NSIG_WORDS) {
	default:
		memset(&set->sig[1], 0, sizeof(long)*(_NSIG_WORDS-1));
		break;
	case 2: set->sig[1] = 0;
	case 1: ;
	}
}

extern void 
SigOps_SetMask(sigset_t *mask, sigset_t *orig);

extern void 
SigOps_Mask(long mask, sigset_t *orig);

extern int
SigOps_IsSubset(sigset_t* subset, sigset_t *set);

extern int
SigOps_IsBlocked(ulong mask);

extern int
SigOps_IsMask(ulong mask);

static INLINE int
SigOps_IsEqual(sigset_t *aP, sigset_t *bP)
{
   return SigOps_IsSubset(aP, bP) && SigOps_IsSubset(bP, aP);
}
