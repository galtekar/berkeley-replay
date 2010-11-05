#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "compiler.h"
#include "listops.h"
#include "debug.h"
#include "atomic.h"

#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_FD		2
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8



struct __xchg_dummy { unsigned long a[100]; };
#define __xg(x) ((struct __xchg_dummy *)(x))
#define xchg(ptr,v) ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))

/*
 * Note: no "lock" prefix even on SMP: xchg always implies lock anyway
 * Note 2: xchg has side effect, so that attribute volatile is necessary,
 *	  but generally the primitive is invalid, *ptr is output argument. --ANK
 */
static INLINE ulong
__xchg(unsigned long x, volatile void * ptr, int size)
{
      switch (size) {
      case 1:
			__asm__ __volatile__("xchgb %b0,%1"
				:"=q" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
		case 2:
			__asm__ __volatile__("xchgw %w0,%1"
				:"=r" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
		case 4:
			__asm__ __volatile__("xchgl %0,%1"
				:"=r" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
	}
	return x;
}

struct SynchLock {
   volatile uint lock;

   /* How many recursive invocations? */
   volatile uint recursion_level;

   /* How many folks waiting on lock? */
   atomic_t wait_count;

};

struct SynchCond {
	struct SynchLock lock;

	volatile uint woken_seq;
	volatile uint wakeup_seq;
	volatile uint total_seq;
};

struct SynchBarrier {
	volatile int count;

	struct SynchLock mutex;
	struct SynchCond cond;
};

/* Locks. */
extern int Synch_TestSetBit(int nr, volatile ulong * addr);
extern int Synch_TestClearBit(int nr, volatile ulong * addr);
#define SYNCH_LOCK_INIT { .lock = 0, .recursion_level = 0, .wait_count.counter = 0 }
extern void Synch_LockInit(struct SynchLock *sl);
extern int  Synch_IsLockOwner(const struct SynchLock *sl);
extern void Synch_Lock(struct SynchLock *sl);
extern int  Synch_TryLock(struct SynchLock *sl);
extern void Synch_Unlock(struct SynchLock *sl);
extern int  Synch_IsLocked(const struct SynchLock *sl);

/* Futex. */
extern long Synch_FutexWait(volatile uint *uaddr, int val);
extern long Synch_FutexWake(volatile uint *uaddr, int numWaiters);

/* Barrier. */
extern void Synch_BarrierInit(struct SynchBarrier *b);
extern void Synch_BarrierWait(struct SynchBarrier *b, int num_threads);

/* Condition variables. */
#define SYNCH_COND_INIT { .lock = SYNCH_LOCK_INIT, \
   .woken_seq = 0, \
   .wakeup_seq = 0, \
   .total_seq = 0, \
}
extern void Synch_CondInit(struct SynchCond *pcv);
extern int Synch_CondWait(struct SynchCond *pcv, struct SynchLock *mutex);
extern void Synch_CondSignal(struct SynchCond *pcv);
extern void Synch_CondBroadcast(struct SynchCond *pcv);

#if MAX_NR_VCPU == 1
#define SYNCH_LOCK(l)
#define SYNCH_UNLOCK(l)
#define SYNCH_DECL_INIT(pre, name)
#define SYNCH_IS_LOCKED(l) 1
#define SYNCH_IS_LOCKOWNER(l) 1
#else
#define SYNCH_LOCK(l) Synch_Lock(l)
#define SYNCH_UNLOCK(l) Synch_Unlock(l)
#define SYNCH_DECL_INIT(pre, name) pre struct SynchLock name = SYNCH_LOCK_INIT
#define SYNCH_IS_LOCKED(l) Synch_IsLocked(l)
#define SYNCH_IS_LOCKOWNER(l) Synch_IsLockOwner(l)
#endif

struct WaitQueue
{
   void *priv;
   int priority;
   struct SynchCond cond;
   struct ListHead taskList;
};

struct WaitQueueHead
{
   struct SynchLock lock;
   struct ListHead taskList;
};

#define __WAITQUEUE_INITIALIZER(name, tsk, prio) {				\
	.priv	= tsk,						\
   .priority = prio, \
   .cond = SYNCH_COND_INIT, \
	.taskList	= { NULL, NULL } }

#define DECLARE_WAITQUEUE(name, tsk, prio)					\
	struct WaitQueue name = __WAITQUEUE_INITIALIZER(name, tsk, prio)

#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= SYNCH_LOCK_INIT,		\
	.taskList	= { &(name).taskList, &(name).taskList } }

static INLINE void
WaitQueue_InitHead(struct WaitQueueHead *q)
{
   List_Init(&q->taskList);
   Synch_LockInit(&q->lock);
}

#if DEBUG
static INLINE void
WaitQueue_Print(struct WaitQueueHead *q)
{
   struct WaitQueue *curr;

   list_for_each_entry(curr, &q->taskList, taskList) {
      DEBUG_MSG(5, "priority=%d\n",
            curr->priority);
   }
}
#endif

static INLINE void 
WaitQueue_Add(struct WaitQueueHead *q, struct WaitQueue *n)
{
   struct WaitQueue *curr;
   struct ListHead *targetHead = &q->taskList;

  Synch_Lock(&q->lock);

#if 0
   DEBUG_MSG(5, "Before\n");
   WaitQueue_Print(q);
#endif

   /* keep sorted by ascending priority */
   list_for_each_entry(curr, &q->taskList, taskList) {
      if (n->priority < curr->priority) {
         targetHead = &curr->taskList;
         break;
      }
   }


   List_AddTail(&n->taskList, targetHead);

#if 0
   DEBUG_MSG(5, "After\n");
   WaitQueue_Print(q);
#endif

   Synch_Unlock(&q->lock);
}

static INLINE void
WaitQueue_Remove(struct WaitQueueHead *q, struct WaitQueue *wait)
{
   Synch_Lock(&q->lock);

#if 0
   DEBUG_MSG(5, "Before\n");
   WaitQueue_Print(q);
#endif
   List_Del(&wait->taskList);
#if 0
   DEBUG_MSG(5, "After\n");
   WaitQueue_Print(q);
#endif

   Synch_Unlock(&q->lock);
}


#ifdef __cplusplus
}
#endif
