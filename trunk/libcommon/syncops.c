#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

#include "../vkernel/public.h"

#if 0
/* CAUTION: doing this will make the vkernel system-call bound, due to
 * all the calls to sys_gettid(). */
#define GET_TID() gettid()
#else
#define GET_TID() current->realPid
#endif

static INLINE long
SynchFutex(volatile uint *uaddr, int op, int val)
{
   long res;

   res = syscall(SYS_futex, uaddr, op, val, NULL);

   return res;
}

INLINE long
Synch_FutexWait(volatile uint *uaddr, int val)
{
   return SynchFutex(uaddr, FUTEX_WAIT, val);
}

INLINE long
Synch_FutexWake(volatile uint *uaddr, int numWaiters)
{
   return SynchFutex(uaddr, FUTEX_WAKE, numWaiters);
}


static INLINE int
SynchCompareAndSwap(volatile void *ptr, ulong old, ulong new)
{
   unsigned long prev;

   __asm__ __volatile__("lock; cmpxchgl %1,%2"
         : "=a"(prev)
         : "r"(new), "m"(*__xg(ptr)), "0"(old)
         : "memory");
   return prev;
}

#define SYNCH_UNLOCKED 0

void Synch_LockInit(struct SynchLock *sl) 
{
   sl->lock = SYNCH_UNLOCKED;
   sl->recursion_level = 0;
   atomic_set(&sl->wait_count, 0);
}

int Synch_IsLocked(const struct SynchLock *sl) {
   return sl->lock != SYNCH_UNLOCKED;
}

int
Synch_IsLockOwner(const struct SynchLock *sl)
{
   uint tid = GET_TID();

   ASSERT(tid > 0);

   return Synch_IsLocked(sl) && sl->lock == tid;
}

int
Synch_TryLock(struct SynchLock *sl)
{
	ASSERT(sl);
   int failure;
   uint oldVal, tid = GET_TID();

   ASSERT(tid != SYNCH_UNLOCKED);
   ASSERT(tid > 0);
   ASSERT(tid == gettid());

   DEBUG_MSG(8, "lock=0x%x\n", sl);
   failure = ((oldVal = SynchCompareAndSwap((void*)&sl->lock, 
               SYNCH_UNLOCKED, tid)) != SYNCH_UNLOCKED &&
         oldVal != tid);

   if (!failure) {
      ASSERT(Synch_IsLocked(sl));
      sl->recursion_level++;

      WARN(sl->recursion_level == 1);
   }

   return !failure;
}

void Synch_Lock(struct SynchLock *sl) 
{
   uint oldVal, tid = GET_TID();

	ASSERT(sl);
   ASSERT(tid != SYNCH_UNLOCKED);
   ASSERT(tid > 0);
   ASSERT(tid == gettid());

   DEBUG_MSG(8, "lock=0x%x mytid=%d\n", sl, tid);
   while ((oldVal = SynchCompareAndSwap((void*)&sl->lock, 
               SYNCH_UNLOCKED, tid)) != SYNCH_UNLOCKED &&
         oldVal != tid /* don't wait you are already holding lock */) {
      int res;
      /* We didn't get the lock on the first try, so
       * wait in the kernel until signalled. */
      DEBUG_MSG(6, "waiting: current owner=%d\n", sl->lock);
      atomic_inc(&sl->wait_count);
      do {
         res = Synch_FutexWait(&sl->lock, oldVal);
         /* We may get a timer signal. */
         ASSERT(res == -EINTR || res != -EINTR);
      } while (res == -EINTR);
      DEBUG_MSG(6, "res=%d\n", res);
      atomic_dec(&sl->wait_count);

      ASSERT(res == 0 || res == -EWOULDBLOCK);
   }

   /* May or may not be recursive acquisition. */
   ASSERT(oldVal != tid || oldVal == tid);
   ASSERT(Synch_IsLocked(sl));

   sl->recursion_level++;

   /* If this fires, then you are trying to recursively lock.
    * This is not necessarily a bug, but should be avoided
    * since it makes reasoning about synchronization harder. */
   WARN(sl->recursion_level == 1);
}

void Synch_Unlock(struct SynchLock *sl) 
{
   int oldVal, tid = GET_TID();

	ASSERT(sl);
   ASSERT(tid != SYNCH_UNLOCKED);
   ASSERT(tid > 0);
   ASSERT(tid == gettid());
   ASSERT(Synch_IsLocked(sl));

   /* Almost always a bug when you try to unlock a lock that is 
    * already unlocked. */
   ASSERT(sl->recursion_level > 0);
   sl->recursion_level--;

   if (sl->recursion_level == 0) {
      /* On x86, must use atomic op for unlock to ensure that writes 
       * are serialized. We use CAS so we can check that we did
       * own the lock that we have unlocked. An atomic XCHG would
       * work here as well.
       *
       * XXX: release version should simply be locked write, since
       * we don't do any ownership checks anyway.
       */ 
      oldVal = SynchCompareAndSwap((void*)&sl->lock, tid, SYNCH_UNLOCKED);

      /* Are you trying to unlock something that you didn't lock? */
      ASSERT(oldVal == tid);

      if (atomic_read(&sl->wait_count)) {
         Synch_FutexWake(&sl->lock, 1);
      }
   }
}

void Synch_BarrierInit(struct SynchBarrier *b) {

   ASSERT(b != NULL);

	memset(b, 0x0, sizeof(struct SynchBarrier));

	Synch_LockInit(&b->mutex);
	Synch_CondInit(&b->cond);
}

void Synch_Barrier(struct SynchBarrier *b, int num_threads) {
	/* A num_threads barrier. If b resides in inter-process
	 * shared memory, then threads from different processes
	 * can use it to synchronize. */

	ASSERT(b != NULL);

	Synch_Lock(&b->mutex);
	if (++b->count == num_threads) {
		b->count = 0;
		Synch_CondBroadcast(&b->cond);
	}
	else {
		Synch_CondWait(&b->cond, &b->mutex);
	}

	Synch_Unlock(&b->mutex);
}

void Synch_CondInit(struct SynchCond* pcv) {

	ASSERT(pcv != NULL);

	memset(pcv, 0x0, sizeof(struct SynchCond));
	Synch_LockInit(&pcv->lock);
}


/* Returns 0 on success and -1 if aborted. */
static long
SynchCondWaitAndCallback(
      struct SynchCond* pcv, struct SynchLock* mut, 
      long (*futex_wait_callback)(volatile uint *futex, int val),
      void (*callback)(void*), void *arg)
{

   int val, seq;
   long futex_res, retval = 0;
   volatile uint* futex;
   int callback_has_been_called = 0;


   ASSERT(pcv != NULL);
   ASSERT(mut != NULL);
   ASSERT(Synch_IsLocked(mut));

   /* If the unlock and the suspend is atomic, and if other
    * processes acquire this lock (MUT) before sending a signal, then
    * we are guaranteed that we will receive that signal, since the 
    * other process will not be able to run and thus send the signal
    * until we release MUT. */

   Synch_Lock(&pcv->lock);


   Synch_Unlock(mut);

   /* We have one more waiter on this condition variable. */
   pcv->total_seq++;
   val = seq = pcv->wakeup_seq;

   futex = &pcv->wakeup_seq;

   do {
      Synch_Unlock(&pcv->lock);

      /* Should only be called once. */
      if (!callback_has_been_called && callback) {
         callback(arg);
         callback_has_been_called = 1;
      }

      /* Wait in the kernel until the value has changed (or there may be 
       * no waiting if the value has already changed, which is possible
       * if someone signalled us before we got here). */
      if (futex_wait_callback) {
         futex_res = futex_wait_callback(futex, val);
      } else {
         futex_res = Synch_FutexWait(futex, val);
      }
      DEBUG_MSG(5, "futex_res=%d\n", futex_res);
#if 0
      ASSERT(futex_res == -EWOULDBLOCK || futex_res == -EINTR
            || futex_res == -ECANCELED || futex_res == 0);

      if (futex_res == -ECANCELED) {
         Synch_Lock(&pcv->lock);
         /* Remove yourself from the wait queue. */
         pcv->total_seq--;
         Synch_Unlock(&pcv->lock);
         retval = -1;
         goto out;
      }
#endif
      /* CAUTION: the futex callback may wakeup spuriously, in which 
       * case we need to try again. Hence the loop. */
      ASSERT(futex_res == -EWOULDBLOCK || futex_res == -EINTR
            || futex_res == 0);


      Synch_Lock(&pcv->lock);

      /* Are we eligible for wakeup? */
      val = pcv->wakeup_seq;
      /* 
       * XXX: Don't understand why we need pcv->woken_seq.
       */
      DEBUG_MSG(6, "after val=%d seq=%d woken_seq=%d\n", val, seq,
            pcv->woken_seq);
      /* Check that this isn't a spurious futex wakeup (e.g.,
       * due to a signal from Linux). */
   } while(val == seq || pcv->woken_seq == val);

   /* One more process woken up. */
   pcv->woken_seq++;

   Synch_Unlock(&pcv->lock);

   D__;
   Synch_Lock(mut);
   D__;

   ASSERT(Synch_IsLocked(mut));

   return retval;
}

int
Synch_CondWait(struct SynchCond* pcv, struct SynchLock* mut) 
{
   return SynchCondWaitAndCallback(pcv, mut, NULL, NULL, NULL);
}

void Synch_CondSignal(struct SynchCond* pcv) 
{
   volatile uint* futex;

   ASSERT(pcv != NULL);

   /* By acquiring the lock associated with the condition variable,
    * we are guaranteed the condition variable is waiting for a signal,
    * assuming we are sending the signal after acquiring MUT. */
   Synch_Lock(&pcv->lock);

   /* Is there anyone waiting on this condition variable?
    * If no one is waiting for the signal, then it is lost. */
   if (pcv->total_seq > pcv->wakeup_seq) {
      futex = &pcv->wakeup_seq;
      pcv->wakeup_seq++;
      Synch_FutexWake(futex, 1);
      DEBUG_MSG(5, "futex=0x%x *futex=%d\n", futex, *futex);
   } else {
      /* Lost signal! This is almost always a bug, since in all
       * our applications, there is at least 1 waiter at the time
       * of a signal. */
      DEBUG_MSG(5, "LOST SIGNAL! total_seq=%d wakeup_seq=%d\n", pcv->total_seq,
            pcv->wakeup_seq);
      ASSERT(0);
   }

   D__;
   Synch_Unlock(&pcv->lock);
   D__;
}

void Synch_CondBroadcast(struct SynchCond* pcv) 
{
   volatile uint* futex;

   ASSERT(pcv != NULL);

   Synch_Lock(&pcv->lock);

   if (pcv->total_seq > pcv->wakeup_seq) {
      pcv->wakeup_seq = pcv->total_seq;

      Synch_Unlock(&pcv->lock);

      futex = &pcv->wakeup_seq;

      /* Wake-up all the threads in the system waiting on this
       * condition variable. */
      Synch_FutexWake(futex, INT_MAX);

      return;
   }

   Synch_Unlock(&pcv->lock);
}
