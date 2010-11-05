/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "vkernel/public.h"
#include "private.h"

/* When the guest's vkernel signal mask is changed, should we update the 
 * guest's kernel signal mask as well? */
#define UPDATE_LINUX_MASK 1


struct SigQueue {
   struct ListHead list;
   struct siginfo info;
};

typedef unsigned long old_sigset_t;     /* at least 32 bits */
#if 1
typedef void __signalfn_t(int);
typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t(void);
typedef __restorefn_t *__sigrestore_t;
#endif

struct old_sigaction {
   __sighandler_t _sa_handler;
   old_sigset_t sa_mask;
   unsigned long sa_flags;
   __sigrestore_t sa_restorer;
};

typedef void (*SigHandlerType)(int, siginfo_t*, void*);

static int
SignalGroupSendSigInfo(int sig, struct siginfo *info, struct Task *p);
static void
SignalNotifyParentCldStop(struct Task *ts, int why);

#if DEBUG
static int
SignalIsValidLinuxMask()
{
   sigset_t currmask, checkmask, blockables;

   SigOps_SetMask(NULL, &currmask);
   SigOps_InitSet(&blockables, ~_ALWAYS_UNBLOCKED);

   SigOps_AndSets(&checkmask, &currmask, &blockables);

   return SigOps_IsSubset(&checkmask, &currmask) &&
      SigOps_IsSubset(&currmask, &checkmask);
}
#endif


/* True if we are on the alternate signal stack.  */
static INLINE int
on_sig_stack(ulong sp)
{
   return (sp - current->sas_ss_sp < current->sas_ss_size);
}

/*
 * sigaltstack controls
 */
#define SS_ONSTACK  1
#define SS_DISABLE  2

static INLINE int
sas_ss_flags(ulong sp)
{
   return (current->sas_ss_size == 0 ? SS_DISABLE
         : on_sig_stack(sp) ? SS_ONSTACK : 0);
}

#define SIG_PREEMPT_TIMER   SIG_RESERVED_USER
#define SIGSNOOP     SIG_RESERVED_KERNEL
#define SIGIPI       SIG_RESERVED_KERNEL
/* XXX: Linux seems to put some random value (?) for si_value when
 * sending signals with sys_tkill. */
#define SIG_ID_IPI       0
/* These can be arbitrary since these are timer_create() signals
 * and thus allow for signal payloads. */
#define SIG_ID_PREEMPT   0xbeefdead
#define SIG_ID_SNOOP     0xfeedbeef

int
Signal_IsTimerSig(const siginfo_t *si)
{
   return ((uint)si->si_signo == SIG_PREEMPT_TIMER) &&
      ((uint)si->si_value.sival_int == SIG_ID_PREEMPT);
}

int
Signal_IsCrashSig(int signr)
{
   return sig_kernel_crash(signr);
}

int
Signal_IsPreemptSig(const siginfo_t *si)
{
   return Signal_IsTimerSig(si) || Signal_IsCrashSig(si->si_signo);
}

int
Signal_IsSnoopSig(const siginfo_t *si)
{
   return ((uint)si->si_signo == SIGSNOOP) &&
      ((uint)si->si_value.sival_int == SIG_ID_SNOOP);
}

int
Signal_IsIPISig(const siginfo_t *si)
{
   ASSERT(SIG_ID_IPI == 0);

   /* XXX: wish we could specify an si_value for the IPIs, but tkill
    * doesn't permit it (or so it seems to me). This hack sucks
    * since it assumes that any vkernel signal that is neither a preemption
    * or snoop signal is an ipi signal. This is not true. Linux
    * could send us a SIGUSR2. */
   return (si->si_signo == SIGIPI) && !Signal_IsTimerSig(si) &&
      !Signal_IsSnoopSig(si);
}



static INLINE int
SignalIsFromVkernel(const siginfo_t *si)
{
   return Signal_IsTimerSig(si) || Signal_IsIPISig(si) ||
      Signal_IsSnoopSig(si);
}

void
Panic_Oops(const char* str, const siginfo_t *sip, const ucontext_t *ucp)
{
   const struct sigcontext *scp = &ucp->uc_mcontext;

   LOG("Oops: %s\n", str);
   LOG("   SIG:   %8.8d   TID:   %8.8d  VAL: 0x%8.8x  CDE: 0x%8.8x\n"
         "   LOC:   %s\n",
         sip->si_signo, sip->si_pid, sip->si_value.sival_int, sip->si_code,
         Task_IsAddrInKernel(scp->eip) ? "KERNEL" : "USER");
   Print_Context(scp);
}

static INLINE int
TaskIsInReplayLogDummy(ulong cr2)
{
   /* Can't be in the log dummy if the log isn't setup yet. */
   return (curr_vcpu->replayLog.logStart) &&
      Log_IsAddrInLogDummy(&curr_vcpu->replayLog, cr2);
}

static void
SignalErrorHandler(int signum, siginfo_t * sip, ucontext_t *uc)
{
   struct sigcontext *scp = &uc->uc_mcontext;

   ASSERT(Task_IsInTaskStack());

   Panic_Oops(sys_siglist[signum], sip, uc);

   if (TaskIsInReplayLogDummy(scp->cr2)) {
      FATAL("possible replay log overflow\n");
   }

   if (signum == SIGABRT) {
      FATAL("assertion failure\n");
   } else {
      FATAL("vkernel crashed\n");
   }

   NOTREACHED();
}


/*
 * Re-calculate pending state from the set of locally pending
 * signals, globally pending signals, and blocked signals.
 */
static INLINE int
SignalHasPending(sigset_t *set, sigset_t *blocked)
{
   ulong ready;
   long i;

   switch (_NSIG_WORDS) {
   default:
      for (i = _NSIG_WORDS, ready = 0; --i >= 0 ;)
         ready |= set->sig[i] &~ blocked->sig[i];
      break;

   case 4:
      ready  = set->sig[3] &~ blocked->sig[3];
      ready |= set->sig[2] &~ blocked->sig[2];
      ready |= set->sig[1] &~ blocked->sig[1];
      ready |= set->sig[0] &~ blocked->sig[0];
      break;

   case 2:
      ready  = set->sig[1] &~ blocked->sig[1];
      ready |= set->sig[0] &~ blocked->sig[0];
      break;

   case 1:
      ready  = set->sig[0] &~ blocked->sig[0];
   }

   DEBUG_MSG(5, "set=0x%x:0x%x blocked=0x%x:0x%x\n",
         set->sig[1], set->sig[0],
         blocked->sig[1], blocked->sig[0]);
   return ready !=  0;
}

#define PENDING(p,b) SignalHasPending(&(p)->signal, (b))
void
Signal_RecalcSigPending(struct Task *t)
{
   ASSERT_SIGLOCK_LOCKED(t);

   /*
    * XXX:
    *
    * What happens when groupStopCount > 0?
    */
   if (
         PENDING(&t->pending, &t->blocked)
         ||
         PENDING(&t->signal->sharedPending, &t->blocked)
      ) {
      D__;
      Task_SetSigPending(t, 0);
   } else {
      D__;
      Task_ClearSigPending(t, 0);
   }

#if 0
   if (!scheduler_enabled()) {
      if (isSigpending) {
         /* XXX Turn on preempt timer. */
      } else {
         /* XXX Turn off preempt timer. */
      }
   }
#endif
}

static struct SigQueue*
SignalSigQueueAlloc() {
   struct SigQueue *q;
   q = (struct SigQueue*)SharedArea_Malloc(sizeof(*q));
   DEBUG_MSG(5, "q=0x%x\n", q);
   List_Init(&q->list);

   return q;
}

static void
SignalSigQueueFree(struct SigQueue *q)
{
   DEBUG_MSG(5, "q=0x%x\n", q);
   SharedArea_Free(q, sizeof(struct SigQueue));
}

#define SEND_SIG_PRIV   ((struct siginfo *) 1)
static int
SignalSendSignal(int signr, struct siginfo *info, struct SigPending *pending)
{
   struct SigQueue *q;
#if 0
   struct rlimit rlim;
#define RLIMIT_SIGPENDING   11  /* max number of pending signals */

   getrlimit(RLIMIT_SIGPENDING, &rlim);
#endif

   /*
    * XXX: check sigpending length against rlimit.
    */

   q = SignalSigQueueAlloc();
   ASSERT_UNIMPLEMENTED(q);

   List_AddTail(&q->list, &pending->list);

   sigaddset(&pending->signal, signr);

   switch ((ulong) info) {
   case(ulong)SEND_SIG_PRIV:
      q->info.si_signo = signr;
      q->info.si_errno = 0;
      q->info.si_code = SI_KERNEL;
      q->info.si_pid = 0;
      q->info.si_uid = 0;
      break;
   default:
      q->info = *info;
      break;
   }

   return 0;
}

#define LEGACY_QUEUE(sigptr, sig) \
   (((sig) < SIGRTMIN) && sigismember(&(sigptr)->signal, (sig)))

/*
 * Tell a process that it has a new active signal.
 */
void
Signal_WakeUp(struct Task *t, int resume)
{
   unsigned int mask;

   D__;

   ASSERT_SIGLOCK_LOCKED(t);

   Task_SetSigPending(t, 0);

   /*
    * For SIGKILL, we want to wake it up in the stopped/traced case.
    * By using wake_up_state, we ensure the process will wake up and
    * handle its death signal.
    */

   mask = TASK_INTERRUPTIBLE;
   if (resume) {
      mask |= TASK_STOPPED | TASK_TRACED;
   }

   /* current is already awake -- it must be for it to call
    * this function. */
   if (t != current) {
      D__;
      Sched_WakeUpState(t, mask);
   }
}

static int
SignalSpecificSendSigInfo(int sig, struct siginfo *info, struct Task *t)
{
   int ret = 0;

   ASSERT_SIGLOCK_LOCKED(t);

   DEBUG_MSG(5, "sending %d to pid %d\n", sig, t->pid);
   if (LEGACY_QUEUE(&t->pending, sig)) {
      goto out;
   }

   ret = SignalSendSignal(sig, info, &t->pending);

   /*
    * The target task may be in TASK_INTERRUPTIBLE state: blocked
    * on a syscall or waitpid/sigsuspending. Slap it in the face
    * and wake it.
    */
   /*
    * XXX:
    *
    * Must make sure vkernel blocked set matches kernel
    * blocked set -- can't restart syscall if signals
    * arrives but is blocked.
    *
    *
    */
   DEBUG_MSG(5, "ret=%d sig=0x%llx\n", ret, t->blocked);
   if (!ret && !sigismember(&t->blocked, sig)) {
      D__;
      Signal_WakeUp(t, sig == SIGKILL);
   }
out:
   return ret;
}

static int
SignalWants(int sig, struct Task *p)
{
   ASSERT_SIGLOCK_LOCKED(p);

   if (sigismember(&p->blocked, sig))
      return 0;
   if (sig == SIGKILL)
      return 1;
   if (p->state & (TASK_STOPPED | TASK_TRACED))
      return 0;

   return !Task_TestSigPending(p, 0);
}

/*
 * Remove signals in mask from the pending set and queue.
 * Returns 1 if any signals were found.
 *
 * All callers must be holding the siglock.
 *
 * This version takes a sigset mask and looks at all signals,
 * not just those in the first mask word.
 */
static int
SignalRemoveFromQueueFull(sigset_t *mask, struct SigPending *s)
{
   struct SigQueue *q;
   sigset_t m;

   SigOps_AndSets(&m, mask, &s->signal);
   if (SigOps_IsEmptySet(&m))
      return 0;

   SigOps_NandSets(&s->signal, &s->signal, mask);
   list_for_each_entry(q, &s->list, list) {
      if (sigismember(mask, q->info.si_signo)) {
         List_DelInit(&q->list);
         SignalSigQueueFree(q);
      }
   }
   return 1;
}

/*
 * Remove signals in mask from the pending set and queue.
 * Returns 1 if any signals were found.
 *
 * All callers must be holding the siglock.
 */
static int
SignalRemoveFromQueue(ulong mask, struct SigPending *s)
{
   struct SigQueue *q;

   if (!SigOps_TestSetMask(&s->signal, mask))
      return 0;

   SigOps_DelSetMask(&s->signal, mask);
   list_for_each_entry(q, &s->list, list) {
      if (q->info.si_signo < SIGRTMIN &&
            (mask & sigmask(q->info.si_signo))) {
         List_DelInit(&q->list);
         SignalSigQueueFree(q);
      }
   }

   return 1;
}

void
Signal_FlushSigQueue(struct SigPending *queue)
{
   struct SigQueue *q;

   sigemptyset(&queue->signal);
   while (!List_IsEmpty(&queue->list)) {
      q = list_entry(queue->list.next, struct SigQueue , list);
      List_DelInit(&q->list);
      SignalSigQueueFree(q);
   }
}

/* Called on exec. */
void
Signal_FlushSignalHandlers(struct Task *t, int forceDefault)
{
   int i;
   struct sigaction *ka = &t->sigHand->action[0];

   for (i = _NSIG; i != 0; i--) {
      /* Subtlety: if signal is ignored, then it stays ignored. */
      if (forceDefault || ka->sa_handler != SIG_IGN) {
         ka->sa_handler = SIG_DFL;
      }
      ka->sa_flags = 0;
      sigemptyset(&ka->sa_mask);
      ka++;
   }
}

static void
SignalForceSigInfo(int signr, struct siginfo *info, struct Task* ts)
{
   int blocked, ignored;
   struct sigaction *action;

   ACQUIRE_SIGLOCK(ts);

   action = &ts->sigHand->action[signr-1];
   ignored = action->sa_handler == SIG_IGN;
   blocked = sigismember(&ts->blocked, signr);

   if (blocked || ignored) {
      action->sa_handler = SIG_DFL;
      if (blocked) {
         sigdelset(&ts->blocked, signr);
         Signal_RecalcSigPending(ts);
      }
   }

   SignalSpecificSendSigInfo(signr, info, ts);

   RELEASE_SIGLOCK(ts);
}

/*
 * When things go south during signal handling, we
 * will force a SIGSEGV. And if the signal that caused
 * the problem was already a SIGSEGV, we'll want to
 * make sure we don't even try to deliver the signal..
 */
static void
SignalForceSigSegv(int sig, struct Task* ts)
{
   if (sig == SIGSEGV) {
      ts->sigHand->action[sig - 1].sa_handler = SIG_DFL;
   }

   SignalForceSigInfo(SIGSEGV, SEND_SIG_PRIV, ts);
}

static void
SignalForceSig(int sig, struct Task *t)
{
   SignalForceSigInfo(sig, SEND_SIG_PRIV, t);
}

/*
 * Handle magic process-wide effects of stop/continue signals.
 * Unlike the signal actions, these happen immediately at signal-generation
 * time regardless of blocking, ignoring, or handling.  This does the
 * actual continuing for SIGCONT, but not the actual stopping for stop
 * signals.  The process stop is done as a signal action for SIG_DFL.
 */
static void
SignalHandleStopSignal(int sig, struct Task *p)
{
   struct Task *t;

   ASSERT_SIGLOCK_LOCKED(p);

   if (p->signal->flags & SIGNAL_GROUP_EXIT) {
      /*
       * The process is in the middle of dying already.
       */
      return;
   }

   if (sig_kernel_stop(sig)) {
      /*
       * This is a stop signal. Remove SIGCONT from all queues.
       */

      SignalRemoveFromQueue(sigmask(SIGCONT), &p->signal->sharedPending);
      t = p;
      do {
         SignalRemoveFromQueue(sigmask(SIGCONT), &t->pending);
         t = Task_NextThread(t);
      } while (t != p);
   } else if (sig == SIGCONT) {
      /*
       * Remove all stop signals from all queues,
       * and wake all threads p's thread group.
       */

      if (p->signal->groupStopCount > 0) {
         /*
          * p's thread group is in the middle of stoppping.
          * Halt the impending group stop. Pretend as though
          * the stop occurred and notify the parent. Note that
          * even though only some of the threads may have stopped,
          * that's okay, because we'll be continuing all of them
          * now anyway.
          */
         p->signal->groupStopCount = 0;
         p->signal->flags = SIGNAL_STOP_CONTINUED;
         RELEASE_SIGLOCK(p);
         SignalNotifyParentCldStop(p, CLD_STOPPED);
         ACQUIRE_SIGLOCK(p);

      }
      /*
       * Remove stops from all the signal queues.
       */
      SignalRemoveFromQueue(SIG_KERNEL_STOP_MASK, &p->signal->sharedPending);
      t = p;
      do {
         unsigned int state;
         SignalRemoveFromQueue(SIG_KERNEL_STOP_MASK, &t->pending);

         /*
          * If there is a handler for SIGCONT, we must make
          * sure that no thread returns to user mode before
          * we post the signal, in case it was the only
          * thread eligible to run the signal handler--then
          * it must not do anything between resuming and
          * running the handler.  With the TSF_SIGPENDING
          * flag set, the thread will pause and acquire the
          * siglock that we hold now and until we've queued
          * the pending signal.
          *
          * Wake up the stopped thread _after_ setting
          * TSF_SIGPENDING
          */
         state = TASK_STOPPED;
         if (sig_user_defined(t, SIGCONT) && !sigismember(&t->blocked, SIGCONT)) {
            /* Since t has expressed interest in handling the SIGCONT, we want it to
             * wake up and handle it even though it may not have been stopped by
             * a previous SIGSTOP. */

            /* Since we have a siglock on p, we should have t's siglock as well,
             * since all members of a thread group share a signal struct and hence
             * the same lock. */
            ASSERT_SIGLOCK_LOCKED(t);
            Task_SetSigPending(t, 0);
            state |= TASK_INTERRUPTIBLE;
         }

         Sched_WakeUpState(t, state);

         t = Task_NextThread(t);
      } while (t != p);

      /*
       * SIGNAL_STOP_STOPPED is set by the last thread to stop in
       * a thread group.
       */
      if (p->signal->flags & SIGNAL_STOP_STOPPED) {
         /*
          * We were in fact stopped, and are now continued.
          * Notify the parent with CLD_CONTINUED.
          */
         p->signal->flags = SIGNAL_STOP_CONTINUED;
         p->signal->groupExitCode = 0;
         RELEASE_SIGLOCK(p);
         SignalNotifyParentCldStop(p, CLD_CONTINUED);
         ACQUIRE_SIGLOCK(p);
      } else {
         /*
          * XXX: We are not stopped, but there could be a stop
          * signal in the middle of being processed after
          * being removed from the queue.  Clear that too.
          *
          * How is this possible?
          */
         ASSERT_UNIMPLEMENTED(0);
         p->signal->flags = 0;
      }
   } else if (sig == SIGKILL) {
      /*
       * XXX:
       *
       * Here, the Linux kernel makes sure that any pending stop signal
       * already dequeued is undone by the wakeup for SIGKILL. Is
       * this necessary? I don't understand how this could happen.
       */
      p->signal->flags = 0;
   }
}

static void
SignalGroupCompleteSignal(int sig, struct Task *p)
{
   struct Task *t = NULL;

   ASSERT_SIGLOCK_LOCKED(p);

   D__;

   /*
    * Now find a thread we can wake up to take the signal off the queue.
    *
    * If the main thread wants the signal, it gets first crack.
    * Probably the least surprising to the average bear.
    */
   if (SignalWants(sig, p)) {
      D__;
      t = p;
   } else if (Task_IsThreadGroupEmpty(p)) {
      D__;
      /*
       * There is just one thread and it doesn't want the signal right
       * now. So just leave it alone -- It will eventually see the
       * signal in the queue anyway.
       */
      return;
   } else {
      D__;
      /*
       * Otherwise try to find a suitable thread.
       */
      struct Task *q;

      for (q = Task_NextThread(p); q != p; q = Task_NextThread(q)) {
         ASSERT(q);
         if (SignalWants(sig, q)) {
            t = q;
            break;
         }
      }

      if (!t) {
         /*
          * No thread in the group wants the signal.
          * No thread needs to be woken.
          * Any eligible threads will see
          * the signal in the queue soon.
          */
         return;
      }
   }

   D__;
   ASSERT(t);

   if (sig_fatal(p, sig) && !(p->signal->flags & SIGNAL_GROUP_EXIT) &&
         /* @t may be in a sys_rt_sigtimedwait(), in which case its
          * real block set is in @realBlocked. */
         !sigismember(&t->realBlocked, sig) &&
         (sig == SIGKILL || !(t->ptrace & PT_PTRACED))) {

      D__;
      /*
       * This signal will be fatal to the whole group.
       */
      if (!sig_kernel_coredump(sig)) {
         D__;
         /*
          * Start a group exit and wake everybody up.
          * This way we don't have other threads
          * running and doing things after a slower
          * thread has the fatal signal pending.
          */
         p->signal->flags = SIGNAL_GROUP_EXIT;
         p->signal->groupExitCode = sig;
         p->signal->groupStopCount = 0;
         t = p;
         do {
            sigaddset(&t->pending.signal, SIGKILL);
            Signal_WakeUp(t, 1);
         }
         while_each_thread(p, t);

         return;

      } else {
         /*
          * There will be a core dump.  We make all threads other
          * than the chosen one go into a group stop so that nothing
          * happens until it gets scheduled, takes the signal off
          * the shared queue, and does the core dump.  This is a
          * little more complicated than strictly necessary, but it
          * keeps the signal state that winds up in the core dump
          * unchanged from the death state, e.g. which thread had
          * the core-dump signal unblocked.
          */

         D__;
         SignalRemoveFromQueue(SIG_KERNEL_STOP_MASK, &t->pending);
         SignalRemoveFromQueue(SIG_KERNEL_STOP_MASK,
               &p->signal->sharedPending);
         p->signal->groupStopCount = 0;
         p->signal->groupExitTask = t;
         t = p;

         D__;

         do {
            p->signal->groupStopCount++;
            Signal_WakeUp(t, 0);
            t = Task_NextThread(t);
         } while (t != p);
         D__;
         if (t != current) {
            Sched_WakeUpProcess(p->signal->groupExitTask);
         }
         D__;

         return;
      }
   }

   /*
    * The signal is already in the shared-pending queue.
    * Tell the chosen thread to wake up and dequeue it.
    */
   Signal_WakeUp(t, sig == SIGKILL);
}


/*
 * Send a signal to a thread group. Because the signal goes in
 * the shared queue, any thread in the target thread group
 * may receive it -- whoever looks for it first.
 *
 * Thread groups differ from process groups. A process group
 * potentially consists of multiple thread groups.
 * A thread group is essentially what user-mode folk call a ``process''.
 */
static int
SignalGroupSendSigInfo(int sig, struct siginfo *info, struct Task *p)
{
   int ret = 0;
   ASSERT_SIGLOCK_LOCKED(p);

   D__;

   SignalHandleStopSignal(sig, p);

   if (LEGACY_QUEUE(&p->signal->sharedPending, sig)) {
      return ret;
   }

   ret = SignalSendSignal(sig, info, &p->signal->sharedPending);
   if (ret) {
      return ret;
   }

   D__;
   SignalGroupCompleteSignal(sig, p);

   return 0;
}

static INLINE int
SignalIsValid(ulong sig)
{
   return sig <= _NSIG ? 1 : 0;
}

static INLINE void
SignalWakeupParent(struct Task *parent)
{
   D__;
   Sched_WakeupSync(&parent->signal->waitChildExitQueue, TASK_INTERRUPTIBLE);
}

/*
 * Notify parent of death.
 * For stopped/continued status change, use NotifyParentCldStop instead.
 */
void
Signal_NotifyParent(struct Task *tsk, int sig)
{
   struct siginfo info;
   struct SigHand *psig;
   struct SyscallArgs args;

   ASSERT(!(tsk->state & (TASK_STOPPED | TASK_TRACED)));

   /*
    * If we are notifying the parent with signal, then
    * either we are being ptraced, or we are about to die (i.e.,
    * this is the thread-group leader and there is no other
    * thread in this group.
    */
   ASSERT(!(!tsk->ptrace &&
            (tsk->groupLeader != tsk || !Task_IsThreadGroupEmpty(tsk))));

   info.si_signo = sig;
   info.si_errno = 0;
   info.si_pid = tsk->pid;
   args.eax = SYS_getuid;
   /* XXX: non-determinism -- shouldn't make call during replay */
   info.si_uid = Task_RealSyscall(&args);

   /*
    * XXX: what info should we put here?
    * info.si_utime = FIGURETHISOUT;
    * info.si_stime = FIGURETHISOUT;
    */
   WARN_XXX(0);

   info.si_status = tsk->exitCode & 0x7f;
   if (tsk->exitCode & 0x80)
      info.si_code = CLD_DUMPED;
   else if (tsk->exitCode & 0x7f)
      info.si_code = CLD_KILLED;
   else {
      info.si_code = CLD_EXITED;
      info.si_status = tsk->exitCode >> 8;
   }

   /* Protects child/parent relationships. tsk->parent
    * is non-deterministic without this, for example,
    * the parent may change from underneath us. */
   ASSERT_TASKLIST_LOCKED();

   psig = tsk->parent->sigHand;
   ACQUIRE_SIGLOCK(tsk->parent);

   if (!tsk->ptrace && sig == SIGCHLD &&
         (psig->action[SIGCHLD-1].sa_handler == SIG_IGN ||
          (psig->action[SIGCHLD-1].sa_flags & SA_NOCLDWAIT))) {
      /*
       * We are exiting and our parent doesn't care.  POSIX.1
       * defines special semantics for setting SIGCHLD to SIG_IGN
       * or setting the SA_NOCLDWAIT flag: we should be reaped
       * automatically and not left for our parent's wait4 call.
       * Rather than having the parent do it as a magic kind of
       * signal handler, we just set this to tell do_exit that we
       * can be cleaned up without becoming a zombie.  Note that
       * we still call __wake_up_parent in this case, because a
       * blocked sys_wait4 might now return -ECHILD.
       *
       * Whether we send SIGCHLD or not for SA_NOCLDWAIT
       * is implementation-defined: we do (if you don't want
       * it, just use SIG_IGN instead).
       */

      /*
       * -1 indicates that the parent doesn't want to reap us.
       *  The code in ExitReleaseTask() checks for this value
       *  when reaping leader.
       */
      tsk->exitSignal = -1;
      if (psig->action[SIGCHLD-1].sa_handler == SIG_IGN) {
         sig = 0;
      }
   }

   if (SignalIsValid(sig) && sig > 0) {
      SignalGroupSendSigInfo(sig, &info, tsk->parent);
   }
   /*
    * Wake each thread in the parent that's blocked on
    * a wait().
    */
   SignalWakeupParent(tsk->parent);
   RELEASE_SIGLOCK(tsk->parent);
}

/*
 * Notify parent of stopped/continued status change.
 */
static void
SignalNotifyParentCldStop(struct Task *ts, int why)
{
   struct siginfo info;
   struct Task *parent;
   struct SigHand *sighand;

   DEBUG_MSG(5, "Notifying parent of stop/continue status change.\n");

   memset(&info, 0, sizeof(info));

   if (ts->ptrace & PT_PTRACED) {
      ASSERT_UNIMPLEMENTED(0);
      parent = NULL;
   } else {
      ts = ts->groupLeader;
      parent = ts->realParent;
   }

   {
      /*
       * XXX: ts->uid and other field are not correct.
       */
      info.si_signo = SIGCHLD;
      info.si_errno = 0;
      info.si_pid = ts->pid;
      info.si_uid = ts->uid;

      /*
       * XXX:
       * info.si_utime = FIGURETHISOUT;
       * info.si_stime = FIGURETHISOUT;
       */
      WARN_XXX(0);
      info.si_code = why;
   }

   info.si_code = why;
   switch (why) {
   case CLD_CONTINUED:
      info.si_status = SIGCONT;
      break;
   case CLD_STOPPED:
      info.si_status = ts->signal->groupExitCode & 0x7f;
      break;
   case CLD_TRAPPED:
      info.si_status = ts->exitCode & 0x7f;
   default:
      ASSERT(0);
   }

   /* Doesn't need to be locked, since the pointer never changes
    * once set. */
   sighand = parent->sigHand;

   /*
    * Send the parent a SIGCHLD.
    */
   ACQUIRE_SIGLOCK(parent);
   if (sighand->action[SIGCHLD-1].sa_handler != SIG_IGN &&
         !(sighand->action[SIGCHLD-1].sa_flags & SA_NOCLDSTOP)) {
      SignalGroupSendSigInfo(SIGCHLD, &info, parent);
   }
   SignalWakeupParent(ts->parent);
   RELEASE_SIGLOCK(parent);
}

void
Signal_ZapOtherThreads(struct Task *p)
{
   struct Task *t;

   ASSERT_SIGLOCK_LOCKED(p);
   /*
    * XXX: ASSERT_LOCKED(&taskListLock) needn't hold
    * since we zap only those tasks in the same thread
    * group. The thread group relationships are protected
    * by the siglock (since all threads shared the same
    * signal struct). Thus, we need only lock the siglock.
    */

   p->signal->flags = SIGNAL_GROUP_EXIT;

   /*
    * XXX: What exactly does this do? I think it stops any
    * pending group stops.
    */
   p->signal->groupStopCount = 0;

   /* Remember that thread relationships are protected by
    * the siglock. */
   if (Task_IsThreadGroupEmpty(p)) {
      return;
   }

   for (t = Task_NextThread(p); t != p; t = Task_NextThread(t)) {
      if (t->exitState) {
         /*
          * Don't bother with already dead threads.
          */
         continue;
      }

      /*
       * We don't want to notify the parent, since we are
       * killed as part of a thread group due to another
       * thread doing an execve() or similar. So set the
       * exit signal to -1 to allow immediate reaping of
       * the process.  But don't detach the thread group
       * leader.
       */
      if (t != p->groupLeader) {
         t->exitSignal = -1;
      }

      /* Should trivially hold, since p is in the same thread
       * group as t (and hence shares the same lock). */
      ASSERT_SIGLOCK_LOCKED(t);
      /* Send the thread a SIGKILL; it will be handled before any
       * pending SIGSTOP */
      sigaddset(&t->pending.signal, SIGKILL);

      /*
       * Put t on the runqueue.
       */
      Signal_WakeUp(t, 1 /* means wakeup even if
                            stopped or being traced */);
   }
}

/* Test if 'sig' is valid signal. Use this instead of testing _NSIG directly */
static INLINE int
valid_signal(ulong sig)
{
   return sig <= _NSIG ? 1 : 0;
}

static int
SignalDoSigaction(int sig, struct sigaction *act, struct sigaction *oact)
{
   struct sigaction *k;
   sigset_t mask;

   if (!valid_signal(sig) || sig < 1 || (act && sig_kernel_only(sig))) {
      return -EINVAL;
   }

   k = &current->sigHand->action[sig-1];

   DEBUG_MSG(5, "current=0x%x signr=%d retaddr=0x%x\n", current, sig, __builtin_return_address(0));

   ACQUIRE_SIGLOCK(current);
   D__;

   if (Task_TestSigPending(current, 0)) {
      /*
       * If there might be a FATAL signal pending on multiple
       * threads, make sure we take it before changing the action.
       */
      RELEASE_SIGLOCK(current);
      return -ERESTARTNOINTR;
   }

   if (oact) {
      *oact = *k;
   }
   D__;

   if (act) {
      SigOps_DelSetMask(&act->sa_mask,
            sigmask(SIGKILL) | sigmask(SIGSTOP));
      *k = *act;
      D__;

      /*
       * POSIX 3.3.1.3:
       *  "Setting a signal action to SIG_IGN for a signal that is
       *   pending shall cause the pending signal to be discarded,
       *   whether or not it is blocked."
       *
       *  "Setting a signal action to SIG_DFL for a signal that is
       *   pending and whose default action is to ignore the signal
       *   (for example, SIGCHLD), shall cause the pending signal to
       *   be discarded, whether or not it is blocked"
       */
      if (act->sa_handler == SIG_IGN ||
            (act->sa_handler == SIG_DFL && sig_kernel_ignore(sig))) {
         struct Task *t = current;
         sigemptyset(&mask);
         sigaddset(&mask, sig);
         SignalRemoveFromQueueFull(&mask, &t->signal->sharedPending);
         do {
            SignalRemoveFromQueueFull(&mask, &t->pending);
            Signal_RecalcSigPending(t);
            t = Task_NextThread(t);
         } while (t != current);
      }
   }

   RELEASE_SIGLOCK(current);
   return 0;
}

SYSCALLDEF(sys_signal, int sig, sighandler_t handler)
{
   struct sigaction new_sa, old_sa;
   int ret;

   new_sa.sa_handler = handler;
   new_sa.sa_flags = SA_ONESHOT | SA_NOMASK;
   sigemptyset(&new_sa.sa_mask);

   ret = SignalDoSigaction(sig, &new_sa, &old_sa);

   return ret ? ret : (long) old_sa.sa_handler;
}


SYSCALLDEF(sys_sigaction, int sig, const struct old_sigaction __user *act,
      struct old_sigaction __user *oact)
{
   struct sigaction new_ka, old_ka;
   int ret;

   if (act) {
      old_sigset_t mask;
      if (/*!access_ok(VERIFY_READ, act, sizeof(*act)) ||*/
            __get_user(new_ka.sa_handler, &act->_sa_handler) ||
            __get_user(new_ka.sa_restorer, &act->sa_restorer)) {
         return -EFAULT;
      }
      __get_user(new_ka.sa_flags, &act->sa_flags);
      __get_user(mask, &act->sa_mask);
      SigOps_InitSet(&new_ka.sa_mask, mask);
   }

   ret = SignalDoSigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

   if (!ret && oact) {
      if (/*!access_ok(VERIFY_WRITE, oact, sizeof(*oact)) ||*/
            __put_user(old_ka.sa_handler, &oact->_sa_handler) ||
            __put_user(old_ka.sa_restorer, &oact->sa_restorer)) {
         return -EFAULT;
      }
      __put_user(old_ka.sa_flags, &oact->sa_flags);
      __put_user(old_ka.sa_mask.sig[0], &oact->sa_mask);
   }

   return ret;
}


SYSCALLDEF(sys_rt_sigaction, int sig, const struct sigaction __user *act,
      struct sigaction __user *oact, size_t sigsetsize)
{
   struct sigaction new_sa, old_sa;
   int ret = -EINVAL;

   if (sigsetsize != _NSIG_BYTES) {
      goto out;
   }

   if (act) {
      if (Task_CopyFromUser(&new_sa, act, sizeof(new_sa))) {
         return -EFAULT;
      }
   }

   ret = SignalDoSigaction(sig, act ? &new_sa : NULL, oact ? &old_sa : NULL);

   if (!ret && oact) {
      if (Task_CopyToUser(oact, &old_sa, sizeof(old_sa))) {
         return -EFAULT;
      }
   }

out:
   return ret;
}

/*
 * Effect the new process mask in the kernel.
 *
 * Needed by bash to deal with ioctl(0x5403) (TCSETSW) calls that induce
 * a SIGTTOU. If not blocked by the kernel, then inducing
 * ioctl itself will return -EINTR; SIGTTOU will be blocked;
 * and bash reexecutes the ioctl in the hope that it won't
 * return -EINTR the next time around.
 */
static void
SignalSetLinuxMask(sigset_t mask)
{
   int err;
   sigset_t blockables;

   SigOps_InitSet(&blockables, ~_ALWAYS_UNBLOCKED);
   SigOps_AndSets(&mask, &mask, &blockables);

   err = sigprocmask(SIG_SETMASK, &mask, NULL);
   ASSERT(!err);
}

static int
SignalSigProcMaskUnlocked(int how, const sigset_t *set,
      sigset_t *oldset)
{
   int error;

   ASSERT_SIGLOCK_LOCKED(current);

   if (oldset) {
      *oldset = current->blocked;
   }

   error = 0;
   switch (how) {
   case SIG_BLOCK:
      SigOps_OrSets(&current->blocked, &current->blocked, set);
      break;
   case SIG_UNBLOCK:
      SigOps_NandSets(&current->blocked, &current->blocked, set);
      break;
   case SIG_SETMASK:
      current->blocked = *set;
      break;
   default:
      error = -EINVAL;
   }

   Signal_RecalcSigPending(current);

#if UPDATE_LINUX_MASK
   SignalSetLinuxMask(current->blocked);
#endif

   DEBUG_MSG(5, "error=%d (0x%x)\n", error, error);
   return error;
}

/* Used by sys_pselect and sys_ppoll to change signal masks before
 * blocking, as well as by sys_sigprocmask and family. */
int
Signal_SigProcMask(int how, const sigset_t *set, sigset_t *oldset)
{
   int error;

   ACQUIRE_SIGLOCK(current);

   error = SignalSigProcMaskUnlocked(how, set, oldset);

   RELEASE_SIGLOCK(current);

   return error;
}

SYSCALLDEF(sys_rt_sigprocmask, int how, sigset_t __user *set,
      sigset_t __user *oset, size_t sigsetsize)
{
   int error = -EINVAL;
   sigset_t old_set, new_set;

   if (sigsetsize != _NSIG_BYTES) {
      goto out;
   }

   if (set) {
      error = -EFAULT;
      if (Task_CopyFromUser(&new_set, set, sizeof(*set))) {
         goto out;
      }
      SigOps_DelSetMask(&new_set, sigmask(SIGKILL) | sigmask(SIGSTOP));

      error = Signal_SigProcMask(how, &new_set, &old_set);

      if (error) {
         goto out;
      }
      if (oset) {
         goto set_old;
      }
   } else if (oset) {
      old_set = current->blocked;

set_old:
      error = -EFAULT;
      if (Task_CopyToUser(oset, &old_set, sizeof(*oset))) {
         goto out;
      }
   }
   error = 0;
out:
   return error;
}

/*
 * XXX: much of this function is a duplicate of sigprocmask() above.
 * Find a way to integrate the two despite the differences in sigset.
 */
SYSCALLDEF(sys_sigprocmask, int how, old_sigset_t __user *set,
      old_sigset_t __user *oset)
{
   int error;
   old_sigset_t old_set, new_set;

   if (set) {
      error = -EFAULT;
      if (Task_CopyFromUser(&new_set, set, sizeof(*set)))
         goto out;
      new_set &= ~(sigmask(SIGKILL) | sigmask(SIGSTOP));

      ACQUIRE_SIGLOCK(current);
      old_set = current->blocked.sig[0];

      error = 0;
      switch (how) {
      default:
         error = -EINVAL;
         break;
      case SIG_BLOCK:
         SigOps_AddSetMask(&current->blocked, new_set);
         break;
      case SIG_UNBLOCK:
         SigOps_DelSetMask(&current->blocked, new_set);
         break;
      case SIG_SETMASK:
         current->blocked.sig[0] = new_set;
         break;
      }

      Signal_RecalcSigPending(current);


      RELEASE_SIGLOCK(current);

      if (error)
         goto out;

#if UPDATE_LINUX_MASK
      SignalSetLinuxMask(current->blocked);
#endif

      if (oset)
         goto set_old;
   } else if (oset) {
      old_set = current->blocked.sig[0];
set_old:
      error = -EFAULT;
      if (Task_CopyToUser(oset, &old_set, sizeof(*oset)))
         goto out;
   }
   error = 0;
out:
   return error;

}


static long
SignalDoSigpending(sigset_t __user *set, ulong sigsetsize)
{
   long error = -EINVAL;
   sigset_t pending;

   if (sigsetsize > _NSIG_BYTES) {
      goto out;
   }

   /*
    * No need to check the Linux kernel's pending list, since all signals
    * are delivered to the kernel (which may choose to queue/block them).
    */

   ACQUIRE_SIGLOCK(current);
   SigOps_OrSets(&pending, &current->pending.signal, &current->signal->sharedPending.signal);
   RELEASE_SIGLOCK(current);

   /* Outside the lock because only this thread touches it.  */
   SigOps_AndSets(&pending, &current->blocked, &pending);

   error = -EFAULT;
   if (!Task_CopyToUser(set, &pending, sigsetsize)) {
      error = 0;
   }

   /*
    * Potential race:
    *
    * A new signal enters the signal queue after we've inspected
    * the pending set. Thus we would return a stale pending set
    * to the app.
    *
    * Current solution:
    *
    * Allow the returned set to be stale. The same race occurs in the
    * Linux kernel--a new signal could enter the shared signal pending
    * set after it has been read.
    *
    */

out:
   return error;
}

SYSCALLDEF(sys_rt_sigpending, sigset_t __user *set, size_t sigsetsize)
{
   return SignalDoSigpending(set, sigsetsize);
}

SYSCALLDEF(sys_sigpending, old_sigset_t __user *set)
{
   return SignalDoSigpending((sigset_t*)set, sizeof(*set));
}

int
SignalDoSigaltstack(const stack_t __user *uss, stack_t __user *uoss, ulong sp)
{
   stack_t oss;
   int error;

   if (uoss) {
      oss.ss_sp = (void*) current->sas_ss_sp;
      oss.ss_size = current->sas_ss_size;
      oss.ss_flags = sas_ss_flags(sp);
   }

   if (uss) {
      void *ss_sp;
      size_t ss_size;
      int ss_flags;

      error = -EFAULT;
      if (!UserMem_CheckProt((ulong)uss, sizeof(*uss), VERIFY_READ)
            || __get_user(ss_sp, &uss->ss_sp)
            || __get_user(ss_flags, &uss->ss_flags)
            || __get_user(ss_size, &uss->ss_size)) {
         goto out;
      }

      error = -EPERM;
      if (on_sig_stack(sp)) {
         goto out;
      }

      error = -EINVAL;

      /*
       *
       * Note - this code used to test ss_flags incorrectly
       *        old code may have been written using ss_flags==0
       *    to mean ss_flags==SS_ONSTACK (as this was the only
       *    way that worked) - this fix preserves that older
       *    mechanism
       */
      if (ss_flags != SS_DISABLE && ss_flags != SS_ONSTACK && ss_flags != 0)
         goto out;

      if (ss_flags == SS_DISABLE) {
         ss_size = 0;
         ss_sp = NULL;
      } else {
         error = -ENOMEM;
         if (ss_size < MINSIGSTKSZ)
            goto out;
      }

      current->sas_ss_sp = (ulong) ss_sp;
      current->sas_ss_size = ss_size;
   }

   if (uoss) {
      error = -EFAULT;
      if (Task_CopyToUser(uoss, &oss, sizeof(oss))) {
         goto out;
      }
   }

   error = 0;
out:
   return error;
}


/* We must virtualize any calls to sigaltstack since the kernel
 * has already set up an alternate stack for its needs. */
SYSCALLDEF(sys_sigaltstack, stack_t __user *uss, stack_t __user *uoss)
{
   return SignalDoSigaltstack(uss, uoss, Task_GetCurrentRegs()->R(esp));
}

static int
SignalRestoreSigContext(TaskRegs *regs, struct sigcontext __user *sc, int *peax)
{
   uint err = 0;

   /* Always make any pending restarted system calls return -EINTR */
   current->restartBlock.fn = do_no_restart_syscall;

#define COPY(x)     { \
   unsigned long tmp; \
   err |= __get_user(tmp, &sc->x); \
   if (!err) Task_WriteReg(regs, x, tmp); \
}

#define COPY_SEG(seg)                           \
{ unsigned short tmp;                       \
   err |= __get_user(tmp, &sc->seg);             \
   if (!err) Task_WriteReg(regs, seg, tmp); }

#define COPY_SEG_STRICT(seg)                        \
{ unsigned short tmp;                       \
   err |= __get_user(tmp, &sc->seg);             \
   if (!err) Task_WriteReg(regs, seg, (tmp|3)); }

#define FIX_EFLAGS  (X86_EFLAGS_AC | X86_EFLAGS_RF |         \
      X86_EFLAGS_OF | X86_EFLAGS_DF |         \
      X86_EFLAGS_TF | X86_EFLAGS_SF | X86_EFLAGS_ZF | \
      X86_EFLAGS_AF | X86_EFLAGS_PF | X86_EFLAGS_CF)

   COPY_SEG(gs);
   COPY_SEG(fs);
   COPY_SEG(es);
   COPY_SEG(ds);
   COPY_SEG_STRICT(ss);
   COPY_SEG_STRICT(cs);
   ASSERT(regs->R(cs) == __USER_CS);
   COPY(edi);
   COPY(esi);
   COPY(ebp);
   COPY(esp);
   COPY(ebx);
   COPY(edx);
   COPY(ecx);
   COPY(eip);

{
   /*
    * At CPL 3, modification of priviledged EFLAGS bits is ignored
    * by the processor.
    */
   unsigned int tmpflags;
   err |= __get_user(tmpflags, &sc->eflags);
   Task_WriteReg(regs, eflags, ((regs->R(eflags) & ~FIX_EFLAGS) |
            (tmpflags & FIX_EFLAGS)));
   current->orig_eax = -1;      /* disable syscall checks */
}

/*
 * XXX: I wanna get this right, so I'm going to defer
 * implementing this. 10/3/07.
 */
{
   struct _fpstate __user * buf;
   err |= __get_user(buf, &sc->fpstate);
#if 1
   ASSERT_UNIMPLEMENTED(!buf);
#else
   if (buf) {
      err |= restore_i387(buf);
   } else {
   }
#endif
}

err |= __get_user(*peax, &sc->eax);
return err;
}

SYSCALLDEF(sys_sigreturn)
{
   TaskRegs *regs = Task_GetCurrentRegs();
   struct sigframe __user *frame = (struct sigframe __user *)(regs->R(esp) - 8);
   sigset_t set;
   int eax;

   if (__get_user(set.sig[0], &frame->sc.oldmask)
         || (_NSIG_WORDS > 1
            && Task_CopyFromUser(&set.sig[1], &frame->extramask,
               sizeof(frame->extramask)))) {
      goto badframe;
   }

   SigOps_DelSetMask(&set, ~_BLOCKABLE);
   ACQUIRE_SIGLOCK(current);
#if UPDATE_LINUX_MASK
   SignalSigProcMaskUnlocked(SIG_SETMASK, &set, NULL);
#else
   current->blocked = set;
   Signal_RecalcSigPending(current);
#endif
   RELEASE_SIGLOCK(current);

   if (SignalRestoreSigContext(regs, &frame->sc, &eax)) {
      goto badframe;
   }
   return eax;

badframe:
   SignalForceSig(SIGSEGV, current);
   return 0;
}

SYSCALLDEF(sys_rt_sigreturn)
{

   TaskRegs *regs = Task_GetCurrentRegs();
   struct rt_sigframe __user *frame =
      (struct rt_sigframe __user *)(regs->R(esp) - 4);
   sigset_t set;
   int eax;

   if (Task_CopyFromUser(&set, &frame->uc.uc_sigmask, sizeof(set))) {
      goto badframe;
   }

   SigOps_DelSetMask(&set, ~_BLOCKABLE);
   ACQUIRE_SIGLOCK(current);
#if UPDATE_LINUX_MASK
   SignalSigProcMaskUnlocked(SIG_SETMASK, &set, NULL);
#else
   current->blocked = set;
   Signal_RecalcSigPending(current);
#endif
   RELEASE_SIGLOCK(current);

   if (SignalRestoreSigContext(regs, &frame->uc.uc_mcontext, &eax)) {
      goto badframe;
   }
   Debug_PrintContext(5, &frame->uc.uc_mcontext);

   if (SignalDoSigaltstack(&frame->uc.uc_stack, NULL, regs->R(esp)) == -EFAULT) {
      goto badframe;
   }

   return eax;

badframe:
   SignalForceSig(SIGSEGV, current);
   return 0;
}

static int
SignalSetupSigContext(struct sigcontext __user *scp, struct _fpstate __user *fpstate,
      TaskRegs *regs, ulong mask)
{

   int tmp = 0, err = 0;

   tmp = 0;
   err |= __put_user(regs->R(gs), (unsigned int __user *) & scp->gs);
   err |= __put_user(regs->R(fs), (unsigned int __user *) & scp->fs);
   err |= __put_user(regs->R(es), (unsigned int __user *) & scp->es);
   err |= __put_user(regs->R(ds), (unsigned int __user *) & scp->ds);
   err |= __put_user(regs->R(cs), (unsigned int __user *) & scp->cs);
   err |= __put_user(regs->R(ss), (unsigned int __user *) & scp->ss);

   err |= __put_user(regs->R(edi), &scp->edi);
   err |= __put_user(regs->R(esi), &scp->esi);
   err |= __put_user(regs->R(ebp), &scp->ebp);
   err |= __put_user(regs->R(esp), &scp->esp);
   err |= __put_user(regs->R(ebx), &scp->ebx);
   err |= __put_user(regs->R(edx), &scp->edx);
   err |= __put_user(regs->R(ecx), &scp->ecx);
   err |= __put_user(regs->R(eax), &scp->eax);
   err |= __put_user(current->trap_no, &scp->trapno);
   err |= __put_user(current->error_code, &scp->err);
   err |= __put_user(regs->R(eip), &scp->eip);
   /* eflags is encoded in vex state in a wierd way; we must
    * extract it using a vex routine. */
   tmp = LibVEX_GuestX86_get_eflags(regs);
   err |= __put_user(tmp, &scp->eflags);
   err |= __put_user(regs->R(esp), &scp->esp_at_signal);

   /*
    * XXX: I wanna get this right, so I'm going to defer
    * implementing this. 10/3/07.
    */
#if 1
   tmp = 0;
   WARN_XXX(!fpstate);
#else
   tmp = Task_Savei387(fpstate);
#endif
   if (tmp < 0) {
      err = 1;
   } else {
      /*
       * fpstate lives somewhere in the sigframe. Hook up
       * a pointer to it so it can be accessed from the sigcontext.
       */
      err |= __put_user(tmp ? fpstate : NULL, &scp->fpstate);
   }

   err |= __put_user(mask, &scp->oldmask);
   err |= __put_user(current->cr2, &scp->cr2);

   return err;
}

static INLINE void __user *
SignalGetFrame(struct sigaction* ka, TaskRegs* regs, size_t frame_size)
{

   ulong esp;

   /* Default to using normal stack. */
   esp = regs->R(esp);

   /* This is the X/Open sanctioned signal stack switching.  */
   if (ka->sa_flags & SA_ONSTACK) {
      /* If we're already on the signal stack, go with the current
       * esp so that we don't overwrite any active frames. */
      if (sas_ss_flags(esp) == 0) {
         /* XXX: catch calls to SYS_sigaltstack and set these values. */
         esp = current->sas_ss_sp + current->sas_ss_size;
      }
   }

   /*
    * XXX: Apparently, this never executes in user-mode.
    * See Linux kernel source.
    */
   /* This is the legacy signal stack switching. */
   /* XXX: we really ought to get these constants from kernel header files
    * somehow... */
   else if ((regs->R(ss) & 0xffff) != __USER_DS &&
         !(ka->sa_flags & SA_RESTORER) &&
         ka->sa_restorer) {
#if 0
      /* Legacy stack switching not supported until I figure out how it
       * is used. */
      esp = (ulong) ka->sa_restorer;
#else
      ASSERT_UNIMPLEMENTED(0);
#endif
   }

   esp -= frame_size;
   /* Align the stack pointer according to the i386 ABI,
    * i.e. so that on function entry ((sp + 4) & 15) == 0. */
   esp = ((esp + 4) & -16ul) - 4;

   return (void __user *) esp;
}

static int
SignalSetupFrame(int sig, struct sigaction *ka,
      sigset_t *mask, TaskRegs *regs)
{
   void __user *restorer;
   struct sigframe __user *frame;
   int err = 0;
   int usig;

   frame = SignalGetFrame(ka, regs, sizeof(*frame));

   if (!UserMem_CheckProt((ulong)frame, sizeof(*frame), VERIFY_WRITE)) {
      goto give_sigsegv;
   }

#if 0
   /* BUG: figure out what this does and enable it, if important. */
   usig = current_thread_info()->exec_domain
      && current_thread_info()->exec_domain->signal_invmap
      && sig < 32
      ? current_thread_info()->exec_domain->signal_invmap[sig]
      : sig;

   err = err |= __put_user(usig, &frame->sig);
   if (err)
      goto give_sigsegv;
#else
   usig = sig;
#endif

   err = __put_user(usig, &frame->sig);
   if (err) {
      goto give_sigsegv;
   }

   err = SignalSetupSigContext(&frame->sc, &frame->fpstate,
         regs, mask->sig[0]);
   if (err) {
      goto give_sigsegv;
   }

   if (_NSIG_WORDS > 1) {
      err = Task_CopyToUser(&frame->extramask, &mask->sig[1],
            sizeof(frame->extramask));
      if (err) {
         goto give_sigsegv;
      }
   }

   restorer = &Gate_vsigreturn;
   if (ka->sa_flags & SA_RESTORER) {
      /* Dietlibc's signal() wrapper uses this field... */
      restorer = ka->sa_restorer;
   }

   DEBUG_MSG(5, "restorer=0x%x\n", restorer);
   /* Set up to return from userspace. */
   err |= __put_user(restorer, &frame->pretcode);

   /*
    * This is movl $,%eax ; int $0x80
    *
    * WE DO NOT USE IT ANY MORE! It's only left here for historical
    * reasons and because gdb uses it as a signature to notice
    * signal handler stack frames.
    */
   err |= __put_user(0xb858, (short __user *)(frame->retcode + 0));
   err |= __put_user(SYS_sigreturn, (int __user *)(frame->retcode + 2));
   err |= __put_user(0x80cd, (short __user *)(frame->retcode + 6));

   if (err) {
      goto give_sigsegv;
   }

   /* Set up registers for signal handler */
   Task_WriteReg(regs, esp, (ulong) frame);
   Task_WriteReg(regs, eip, (ulong) ka->sa_handler);
   Task_WriteReg(regs, eax, (ulong) usig); /* BUG?: why does kernel use usig? */
   Task_WriteReg(regs, edx, 0);
   Task_WriteReg(regs, ecx, 0);

   return 0;

give_sigsegv:
   SignalForceSigSegv(sig, current);
   return -EFAULT;
}

static int
SignalSetupRTFrame(int signr, struct sigaction* ka,
      struct siginfo *info, sigset_t *mask, TaskRegs* regs)
{

   void __user *restorer;
   struct rt_sigframe __user *frame;
   int err = 0;
   int usig;

   D__;
   frame = SignalGetFrame(ka, regs, sizeof(*frame));

   if (!UserMem_CheckProt((ulong)frame, sizeof(*frame), VERIFY_WRITE)) {
      goto give_sigsegv;
   }

   WARN_XXX(0);
#if 0
   /* BUG: figure out what this does and enable it, if important. */
   usig = current_thread_info()->exec_domain
      && current_thread_info()->exec_domain->signal_invmap
      && sig < 32
      ? current_thread_info()->exec_domain->signal_invmap[sig]
      : sig;

   err = err |= __put_user(usig, &frame->sig);
   if (err)
      goto give_sigsegv;
#else
   usig = signr;
#endif

   err |= __put_user(usig, &frame->sig);
   err |= __put_user(&frame->info, &frame->pinfo);
   err |= __put_user(&frame->uc, &frame->puc);
   err |= Task_CopyToUser(&frame->info, info, sizeof(frame->info));
   if (err) {
      goto give_sigsegv;
   }

   /* Create the ucontext. */
   err |= __put_user(0, &frame->uc.uc_flags);
   err |= __put_user(0, &frame->uc.uc_link);
   err |= __put_user((void __user*)current->sas_ss_sp, &frame->uc.uc_stack.ss_sp);
   err |= __put_user(sas_ss_flags(regs->R(esp)),
         &frame->uc.uc_stack.ss_flags);
   err |= __put_user(current->sas_ss_size, &frame->uc.uc_stack.ss_size);
   err |= SignalSetupSigContext(&frame->uc.uc_mcontext, &frame->fpstate,
         regs, mask->sig[0]);
   Debug_PrintContext(5, &frame->uc.uc_mcontext);
   /* mask points to current->blocked, but we don't need to the siglock
    * because only current can change blocked. */
   err |= Task_CopyToUser(&frame->uc.uc_sigmask, mask, sizeof(*mask));
   if (err) {
      goto give_sigsegv;
   }

   /* Set up to return from userspace. */

   /* Design note: we could use our own version of
    * rt_sigreturn, but that would excecute in the kernel
    * code space. This means that signals would be queued
    * while it executes, but the only place signals are
    * flushed is on exit from the syscall trampoline. And
    * we don't want undelivered signals while exceuting app
    * code.
    *
    * -- this is no longer a concern, because signals
    * are delivered preemptively. */
   restorer = &Gate_vrt_sigreturn;
   if (ka->sa_flags & SA_RESTORER) {
      restorer = ka->sa_restorer;
   }
   err |= __put_user(restorer, &frame->pretcode);
   D__;

   /*
    * This is movl $,%eax ; int $0x80
    *
    * WE DO NOT USE IT ANY MORE! It's only left here for historical
    * reasons and because gdb uses it as a signature to notice
    * signal handler stack frames.
    */
   err |= __put_user(0xb8, (char __user *)(frame->retcode + 0));
   err |= __put_user(SYS_rt_sigreturn, (int __user *)(frame->retcode + 1));
   err |= __put_user(0x80cd, (short __user *)(frame->retcode + 5));

   if (err) {
      goto give_sigsegv;
   }

   /* Set up registers for signal handler */
   Task_WriteReg(regs, esp, (ulong) frame);
   Task_WriteReg(regs, eip, (ulong) ka->sa_handler);
   Task_WriteReg(regs, eax, (ulong) usig); /* BUG?: why does kernel use usig? */
   Task_WriteReg(regs, edx, (ulong) & frame->info);
   Task_WriteReg(regs, ecx, (ulong) & frame->uc);

   return 0;

give_sigsegv:
   SignalForceSigSegv(signr, current);
   return -EFAULT;
}

static int
SignalHandle(ulong signr, struct siginfo *info, struct sigaction *ka,
      sigset_t* oldset, TaskRegs *regs)
{
   int ret;
   /*
    * Are we from a system call?
    */
   if (current->orig_eax >= 0) {
      switch (regs->R(eax)) {
      case -ERESTART_RESTARTBLOCK:
      case -ERESTARTNOHAND:
         Task_WriteReg(regs, eax, -EINTR);
         break;
         /* sys_wait, for instance, makes use of this. */
      case -ERESTARTSYS:
         if (!(ka->sa_flags & SA_RESTART)) {
            Task_WriteReg(regs, eax, -EINTR);
            break;
         }
         /* fallthrough */
      case -ERESTARTNOINTR:
         Task_WriteReg(regs, eax, current->orig_eax);
         Task_WriteReg(regs, eip, regs->R(eip)-2);
         break;
      default:
         /* syscall was successful. */
         break;
      }
   }

   /*
    * Set up the stack frame.
    */
   if (ka->sa_flags & SA_SIGINFO) {
      D__;
      ret = SignalSetupRTFrame(signr, ka, info, oldset, regs);
   } else {
      D__;
      ret = SignalSetupFrame(signr, ka, oldset, regs);
   }
   D__;

   if (ret == 0) {
      /*
       * Block the signal within the signal handler, unless SA_NODEFER
       * was specified. Thus, by default, the handler doesn't have to
       * be signal reentrant.
       */
      sigset_t new_set;


      /*
       * XXX: atomic_mask_and_set_context()
       *
       * Why must the mask and set context be atomic? Suppose they
       * aren't. Then there are two options.
       *
       * 1. Set the mask and then set the context.
       *
       * Could get an unmasked signal before we're in the signal
       * context.
       *
       * 2. Set the context and then set the mask.
       *
       * Could get an unmasked signal between masking and the
       * jump to signal context. IOW, could get an unsmasked signal
       * before we're in the signal context.
       *
       * That's fine. Since we're still in the kernel when we get the
       * signal, tt will be queued and delivered at a later
       * time when the signal is not blocked.
       *
       * IOW, it's safe to install the new sigprocmask before we
       * jump to the signal context.
       */
      D__
         ACQUIRE_SIGLOCK(current);
      SigOps_OrSets(&new_set, &current->blocked, &ka->sa_mask);
      if (!(ka->sa_flags & SA_NODEFER)) {
         sigaddset(&new_set, signr);
      }
      SignalSigProcMaskUnlocked(SIG_SETMASK, &new_set, NULL);
      RELEASE_SIGLOCK(current);
      D__
   }
   D__;

   return ret;
}

/**
 * ffz - find first zero in word.
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
static INLINE ulong
ffz(ulong word)
{
   __asm__("bsfl %1,%0"
         : "=r"(word)
         : "r"(~word));
   return word;
}

/*
 * SignalSelectNext --
 *
 * Given the mask, find the first available signal that should be serviced.
 */
static int
SignalSelectNext(struct SigPending *pending, sigset_t *mask)
{
#define _NSIG_BPW   32
   ulong i, *s, *m, x;
   int sig = 0;

   s = pending->signal.sig;
   m = mask->sig;
   switch (_NSIG_WORDS) {
   default:
      for (i = 0; i < _NSIG_WORDS; ++i, ++s, ++m)
         if ((x = *s &~ *m) != 0) {
            sig = ffz(~x) + i * _NSIG_BPW + 1;
            break;
         }
      break;

   case 2:
      if ((x = s[0] &~ m[0]) != 0)
         sig = 1;
      else if ((x = s[1] &~ m[1]) != 0)
         sig = _NSIG_BPW + 1;
      else
         break;
      sig += ffz(~x);
      break;

   case 1:
      if ((x = *s &~ *m) != 0)
         sig = ffz(~x) + 1;
      break;
   }

   return sig;
}

static int
SignalCollect(int sig, struct SigPending *pending, siginfo_t *info)
{
   int stillPending = 0;
   struct SigQueue *q, *first = NULL;

   DEBUG_MSG(5, "sig=%d\n", sig);
   if (!sigismember(&pending->signal, sig)) {
      return 0;
   }

   list_for_each_entry(q, &pending->list, list) {
      if (q->info.si_signo == sig) {
         if (first) {
            /*
             * Are there multiple such signals? If there
             * are, then we won't clear the signal from the
             * pending set.
             */
            D__;
            stillPending = 1;
            break;
         }

         first = q;
      }
   }

   if (first) {
      D__;
      List_DelInit(&first->list);
      *info = first->info;
      SignalSigQueueFree(first);

      if (!stillPending) {
         D__;
         sigdelset(&pending->signal, sig);
      }
   } else {
      D__;
      /* Ok, it wasn't in the queue.  This must be
         a fast-pathed signal or we must have been
         out of queue space.  So zero out the info.
         */
      sigdelset(&pending->signal, sig);
      info->si_signo = sig;
      info->si_errno = 0;
      info->si_code = 0;
      info->si_pid = 0;
      info->si_uid = 0;
   }

   return 1;
}

static int
SignalDequeueHelper(struct SigPending *pending, sigset_t *mask, siginfo_t *info)
{
   D__;
   int sig = SignalSelectNext(pending, mask);

   DEBUG_MSG(5, "sig=%d\n", sig);

   if (!SignalCollect(sig, pending, info)) {
      sig = 0;
   }

   return sig;
}

static int
SignalDequeue(struct Task *tsk, sigset_t *mask, siginfo_t *info)
{
   int signr;

   ASSERT_SIGLOCK_LOCKED(tsk);

   signr = SignalDequeueHelper(&tsk->pending, mask, info);
   if (!signr) {
      signr = SignalDequeueHelper(&tsk->signal->sharedPending, mask, info);
   }
   DEBUG_MSG(5, "dequeued signr=%d\n", signr);
   Signal_RecalcSigPending(tsk);

   if (signr && unlikely(sig_kernel_stop(signr))) {
      ASSERT_SIGLOCK_LOCKED(tsk);
      if (!(tsk->signal->flags & SIGNAL_GROUP_EXIT)) {
         tsk->signal->flags |= SIGNAL_STOP_DEQUEUED;
      }
   }

   /* XXX: itimer/SIGALRM stuff */

   return signr;
}

void
SignalFinishStop(int stopCount)
{
   ASSERT(Task_GetCurrentState() == TASK_STOPPED);

   /*
    * If this is the last thread to stop, then notify
    * the parent.
    */
   if (stopCount == 0) {
      /*
       * XXX: What lock should we hold?
       */
      SignalNotifyParentCldStop(current, CLD_STOPPED);
   }

   ASSERT(Task_GetCurrentState() == TASK_STOPPED);

   /* NOTE: We don't put the task in TASK_INTERRUPTIBLE mode since
    * the task is stopped and thus shouldn't be woken up by signals.
    * This means that if a task outside the vkernel's domain sends
    * a SIGCONT, this task won't wakeup -- that's because we can't
    * intercept the kill(SIGCONT) and thus inform the vkernel scheduler
    * to scheudle this task again.  */
   Sched_Schedule();
}

static int
SignalDoStop(int signr)
{
   struct Signal *sig = current->signal;
   int stopCount;

   ASSERT_SIGLOCK_LOCKED(current);

   /* Chances are we are here because we dequeued a stop
    * signal. But in the unlikely event that the stop was
    * cancelled with a SIGCONT, then don't stop.
    *
    * The situation in which this could happen is if another
    * task acquired the siglock sends us a SIGCONT. */
   if (!likely(sig->flags & SIGNAL_STOP_DEQUEUED)) {
      return 0;
   }

   if (sig->groupStopCount > 0) {
      /*
       * There is a group stop in progress. We don't need to
       * start another one, even though this thread got a
       * stop signal.
       */
      stopCount = --sig->groupStopCount;
   } else {
      /*
       * There is no group stop already in progress.
       * We must initiate one now.
       */
      struct Task *t;

      sig->groupExitCode = signr;


      /*
       * Count how many threads we should stop.
       */
      stopCount = 0;
      for (t = Task_NextThread(current); t != current; t = Task_NextThread(t)) {
         /*
          * XXX: Why would any thread be stopped already?
          */
         if (!t->exitState &&
               !(t->state & (TASK_STOPPED | TASK_TRACED))) {
            stopCount++;
            Signal_WakeUp(t, 0);
         }
      }

      sig->groupStopCount = stopCount;
   }

   if (stopCount == 0) {
      current->signal->flags = SIGNAL_STOP_STOPPED;
   }
   current->exitCode = sig->groupExitCode;
   Task_SetCurrentState(TASK_STOPPED);

   /*
    * Don't hold the lock while scheduled out,
    * as we will be in SignalFinishStop().
    */
   RELEASE_SIGLOCK(current);

   SignalFinishStop(stopCount);

   return 1;
}

/*
 * A thread need not receive a stop signal in order to
 * take part in a group stop. If any member of the thread
 * group gets a stop signal, then all members must stop.
 */
static int
SignalHandleGroupStop()
{
   int stopCount;

   ASSERT_SIGLOCK_LOCKED(current);

   /*
    * Group stop is so we can do a core dump,
    * We are the initiating thread, so get on with it.
    */
   if (current->signal->groupExitTask == current) {
      current->signal->groupExitTask = NULL;
      return 0;
   }

   if (current->signal->flags & SIGNAL_GROUP_EXIT) {
      /*
       * Group stop is so another thread can do a core dump,
       * or else we are racing against a death signal.
       * Just punt the stop so we can get the next signal.
       */
      ASSERT_UNIMPLEMENTED(0);
      return 0;
   }
   /*
    * There is a group stop in progress. We stop even
    * though this task may not have received a stop signal
    * (it shouldn't), since all tasks within a thread group
    * must stop if any task in that group receives
    * a stop signal.
    */
   stopCount = --current->signal->groupStopCount;

   if (stopCount == 0) {
      current->signal->flags = SIGNAL_STOP_STOPPED;
   }
   current->exitCode = current->signal->groupExitCode;
   Task_SetCurrentState(TASK_STOPPED);

   /*
    * Don't hold the lock while scheduled out,
    * as we will be in SignalFinishStop().
    */
   RELEASE_SIGLOCK(current);

   SignalFinishStop(stopCount);

   return 1;
}

/* These can be the second arg to send_sig_info/send_group_sig_info.  */
#define SI_FROMUSER(siptr)  ((siptr)->si_code <= 0)
#define SI_FROMKERNEL(siptr)    ((siptr)->si_code > 0)

#if 1
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define SEND_SIG_PRIV   ((struct siginfo *) 1)
#define SEND_SIG_FORCED ((struct siginfo *) 2)
/*
 * Bad permissions for sending the signal
 */
static int check_kill_permission(int sig, struct siginfo *info UNUSED,
      struct Task *t UNUSED)
{
   int error = -EINVAL;

   D__;
   if (!valid_signal(sig)) {
      D__;
      return error;
   }

#if 0
   error = -EPERM;
   if ((info == SEND_SIG_NOINFO || (!is_si_special(info) && SI_FROMUSER(info)))
         && ((sig != SIGCONT) ||
            (current->signal->session != t->signal->session))
         && (current->euid ^ t->suid) && (current->euid ^ t->uid)
         && (current->uid ^ t->suid) && (current->uid ^ t->uid)
         /*&& !capable(CAP_KILL)*/) {
      return error;
   }

   error = security_task_kill(t, info, sig, 0);
   if (!error)
      audit_signal_info(sig, t); /* Let audit system see the signal */
#else
   WARN_XXX(0);
#endif

   return 0;
}

int group_send_sig_info(int sig, struct siginfo *info, struct Task *p)
{
   int ret;

   D__;
   ret = check_kill_permission(sig, info, p);

   if (!ret && sig) {
      ret = -ESRCH;
      DEBUG_MSG(5, "p->id=%d p->sigHand=0x%x", p->id, p->sigHand);
      ACQUIRE_SIGLOCK(p);
      ret = SignalGroupSendSigInfo(sig, info, p);
      RELEASE_SIGLOCK(p);
   }

   return ret;
}

/*
 * kill_pgrp_info() sends a signal to a process group: this is what the tty
 * control characters do (^C, ^Z etc)
 */

int __kill_pgrp_info(int sig, struct siginfo *info, struct Pid *pgrp)
{
   struct Task *p = NULL;
   int retval, success;

   ASSERT_TASKLIST_LOCKED();

   success = 0;
   retval = -ESRCH;
   do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
      int err = group_send_sig_info(sig, info, p);
      success |= !err;
      retval = err;
   }
   while_each_pid_task(pgrp, PIDTYPE_PGID, p);
   return success ? 0 : retval;
}

int kill_pgrp_info(int sig, struct siginfo *info, struct Pid *pgrp)
{
   int retval;

   ACQUIRE_TASKLISTLOCK();
   retval = __kill_pgrp_info(sig, info, pgrp);
   RELEASE_TASKLISTLOCK();

   return retval;
}

int __kill_pg_info(int sig, struct siginfo *info, pid_t pgrp)
{
   ASSERT_TASKLIST_LOCKED();

   if (pgrp <= 0)
      return -EINVAL;

   return __kill_pgrp_info(sig, info, Pid_Find(pgrp));
}

int
kill_pg_info(int sig, struct siginfo *info, pid_t pgrp)
{
   int retval;

   ACQUIRE_TASKLISTLOCK();
   retval = __kill_pg_info(sig, info, pgrp);
   RELEASE_TASKLISTLOCK();

   return retval;
}

int kill_pid_info(int sig, struct siginfo *info, struct Pid *pid)
{
   int error;
   struct Task *p;

   ACQUIRE_TASKLISTLOCK();
   p = Task_GetByPidType(pid, PIDTYPE_PID);
   error = -ESRCH;
   if (p)
      error = group_send_sig_info(sig, info, p);
   RELEASE_TASKLISTLOCK();
   return error;
}

int
kill_proc_info(int sig, struct siginfo *info, pid_t pid)
{
   int error;
   error = kill_pid_info(sig, info, Pid_Find(pid));
   return error;
}


static int
kill_something_info(int sig, struct siginfo *info, int pid)
{
   if (!pid) {
      return kill_pg_info(sig, info, Task_ProcessGroup(current));
   } else if (pid == -1) {
      int retval = 0, count = 0;
      struct Task * p;

      ACQUIRE_TASKLISTLOCK();
      for_each_process(p) {
         if (p->pid > 1 && p->tgid != current->tgid) {
            int err = group_send_sig_info(sig, info, p);
            ++count;
            if (err != -EPERM)
               retval = err;
         }
      }
      RELEASE_TASKLISTLOCK();
      return count ? retval : -ESRCH;
   } else if (pid < 0) {
      return kill_pg_info(sig, info, -pid);
   } else {
      return kill_proc_info(sig, info, pid);
   }
}
#endif

SYSCALLDEF(sys_kill, int pid, int sig)
{
   /* XXX: We must intercept sys_kill in order to handle
    * SIGCONT correctly -- we must wake up the target task
    * which is presumably stopped.
    *
    * We would like to allow signals to be sent to any task in
    * the system -- regardless of whether it's in the vkernel's
    * domain or not. If it's not in the vkernel's domain, we can
    * just make a Linux kill syscall. But what if pid == -1?
    * Then we would need to send the signal to everybody --
    * excpet we must send interally to those in the domain and
    * via Linux kill to those outside. But how do we know which
    * tasks are outside?
    *
    * We can do Linux kill with a pid=-1 and send internally
    * to vkernel tasks, but that will results in duplicates for
    * vkernel tasks.
    *
    * We could kill each and every non-vkernel task individually,
    * but how do enumerate them easily? We don't have access to
    * the Linux task lists.
    *
    * This would be easier if we could tell Linux to not send
    * to in-vkernel tasks.
    *
    * For right now, allow sending sigs to only in-vkernel tasks.
    */
#if 1
   struct siginfo info;

   DEBUG_MSG(5, "pid=%d sig=%d\n", pid, sig);
   info.si_signo = sig;
   info.si_errno = 0;
   info.si_code = SI_USER;
   info.si_pid = current->tgid;
   info.si_uid = current->uid;

   return kill_something_info(sig, &info, pid);
#else

   SyscallRet ret;

   DEBUG_MSG(5, "pid=%d sig=%d\n", pid, sig);

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = Task_GetCurrentRegs()->R(eax);
      args.ebx = pid;
      args.ecx = sig;
      ret = Task_RealSyscall(&args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(SysKill) {
            entryp->ret = ret;
         }
         END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(SysKill) {
         ret = entryp->ret;
      }
      END_WITH_LOG_ENTRY(0);
   }

   return ret;
#endif
}

static int
do_tkill(int tgid, int pid, int sig)
{
   int error;
   struct siginfo info;
   struct Task *p;

   error = -ESRCH;
   info.si_signo = sig;
   info.si_errno = 0;
#define SI_TKILL  -6      /* sent by tkill system call */
   info.si_code = SI_TKILL;
   info.si_pid = current->tgid;
   info.si_uid = current->uid;

   ACQUIRE_TASKLISTLOCK();
   p = Task_GetByPid(pid);
   if (p && (tgid <= 0 || p->tgid == tgid)) {
      error = check_kill_permission(sig, &info, p);
      /*
       * The null signal is a permissions and process existence
       * probe.  No signal is actually delivered.
       */
      if (!error && sig && p->sigHand) {
         ACQUIRE_SIGLOCK(p);
         SignalHandleStopSignal(sig, p);
         error = SignalSpecificSendSigInfo(sig, &info, p);
         RELEASE_SIGLOCK(p);
      }
   }
   RELEASE_TASKLISTLOCK();

   return error;
}


/**
 *  sys_tgkill - send signal to one specific thread
 *  @tgid: the thread group ID of the thread
 *  @pid: the PID of the thread
 *  @sig: signal to be sent
 *
 *  This syscall also checks the tgid and returns -ESRCH even if the PID
 *  exists but it's not belonging to the target process anymore. This
 *  method solves the problem of threads exiting and PIDs getting reused.
 */
SYSCALLDEF(sys_tgkill, int tgid, int pid, int sig)
{
   /* This is only valid for single tasks */
   if (pid <= 0 || tgid <= 0)
      return -EINVAL;

   return do_tkill(tgid, pid, sig);
}

/*
 *  Send a signal to only one task, even if it's a CLONE_THREAD task.
 */
SYSCALLDEF(sys_tkill, int pid, int sig)
{
   /* This is only valid for single tasks */
   if (pid <= 0)
      return -EINVAL;

   return do_tkill(0, pid, sig);
}

static void
SignalSuspendLoop()
{
   int isSigPending;

   do {
      Sched_ScheduleTimeout(NULL);
      isSigPending = Task_TestSigPending(current, 1);
   } while (!isSigPending);
}

long
sys_pause()
{
   SignalSuspendLoop();

   return -ERESTARTNOHAND;
}

static long
SignalDoSigsuspend(sigset_t newset)
{
   /*
    * Why must be acquire the siglock here? Because
    * we modify current->blocked and possibly sigpending.
    *
    * XXX: would we need to acquire the lock if we
    * were only reading those vars?
    */
   ACQUIRE_SIGLOCK(current);
   current->savedSigmask = current->blocked;
   current->blocked = newset;
   Signal_RecalcSigPending(current);
   RELEASE_SIGLOCK(current);

   SignalSuspendLoop();

   Task_SetCurrentFlag(TIF_RESTORE_SIGMASK);

   return -ERESTARTNOHAND;
}

SYSCALLDEF(sys_rt_sigsuspend, sigset_t __user *unewset, size_t sigsetsize)
{
   sigset_t newset;

   if (sigsetsize != _NSIG_BYTES) {
      return -EINVAL;
   }

   if (Task_CopyFromUser(&newset, unewset, sizeof(newset))) {
      return -EFAULT;
   }
   SigOps_DelSetMask(&newset, sigmask(SIGKILL) | sigmask(SIGSTOP));


   return SignalDoSigsuspend(newset);
}

SYSCALLDEF(sys_sigsuspend, int history0 UNUSED, int history1 UNUSED,
      old_sigset_t mask)
{
   sigset_t newset;

   mask &= _BLOCKABLE;

   SigOps_InitSet(&newset, mask);

   return SignalDoSigsuspend(newset);
}


#if 0
int copy_siginfo_to_user(siginfo_t __user *to, siginfo_t *from)
{
   int err;

#if 0
   if (!access_ok(VERIFY_WRITE, to, sizeof(siginfo_t)))
      return -EFAULT;
#endif
   if (!UserMem_CheckProt((ulong)to, sizeof(siginfo_t), VERIFY_WRITE))
      return -EFAULT;
   if (from->si_code < 0)
      return __Task_CopyToUser(to, from, sizeof(siginfo_t))
         ? -EFAULT : 0;
   /*
    * If you change siginfo_t structure, please be sure
    * this code is fixed accordingly.
    * It should never copy any pad contained in the structure
    * to avoid security leaks, but must copy the generic
    * 3 ints plus the relevant union member.
    */
   err = __put_user(from->si_signo, &to->si_signo);
   err |= __put_user(from->si_errno, &to->si_errno);
   err |= __put_user((short)from->si_code, &to->si_code);
   switch (from->si_code & __SI_MASK) {
   case __SI_KILL:
      err |= __put_user(from->si_pid, &to->si_pid);
      err |= __put_user(from->si_uid, &to->si_uid);
      break;
   case __SI_TIMER:
      err |= __put_user(from->si_tid, &to->si_tid);
      err |= __put_user(from->si_overrun, &to->si_overrun);
      err |= __put_user(from->si_ptr, &to->si_ptr);
      break;
   case __SI_POLL:
      err |= __put_user(from->si_band, &to->si_band);
      err |= __put_user(from->si_fd, &to->si_fd);
      break;
   case __SI_FAULT:
      err |= __put_user(from->si_addr, &to->si_addr);
#ifdef __ARCH_SI_TRAPNO
      err |= __put_user(from->si_trapno, &to->si_trapno);
#endif
      break;
   case __SI_CHLD:
      err |= __put_user(from->si_pid, &to->si_pid);
      err |= __put_user(from->si_uid, &to->si_uid);
      err |= __put_user(from->si_status, &to->si_status);
      err |= __put_user(from->si_utime, &to->si_utime);
      err |= __put_user(from->si_stime, &to->si_stime);
      break;
   case __SI_RT: /* This is not generated by the kernel as of now. */
   case __SI_MESGQ: /* But this is */
      err |= __put_user(from->si_pid, &to->si_pid);
      err |= __put_user(from->si_uid, &to->si_uid);
      err |= __put_user(from->si_ptr, &to->si_ptr);
      break;
   default: /* this is just in case for now ... */
      err |= __put_user(from->si_pid, &to->si_pid);
      err |= __put_user(from->si_uid, &to->si_uid);
      break;
   }
   return err;
}
#endif

SYSCALLDEF(sys_rt_sigtimedwait, const sigset_t __user *uthese,
      siginfo_t __user *uinfo,
      struct timespec __user *uts,
      size_t sigsetsize)
{
   int ret, sig;
   sigset_t these;
   struct timespec ts;
   siginfo_t info;
   int shouldBlock = 1, wasInterrupted = 0;

   /* XXX: Don't preclude handling different sized sigset_t's.  */
   if (sigsetsize != sizeof(sigset_t))
      return -EINVAL;

   if (Task_CopyFromUser(&these, uthese, sizeof(these)))
      return -EFAULT;

   /*
    * Invert the set of allowed signals to get those we
    * want to block.
    */
   SigOps_DelSetMask(&these, sigmask(SIGKILL) | sigmask(SIGSTOP));
   SigOps_NotSet(&these);

   if (uts) {
      if (Task_CopyFromUser(&ts, uts, sizeof(ts)))
         return -EFAULT;
      if (ts.tv_nsec >= 1000000000L || ts.tv_nsec < 0
            || ts.tv_sec < 0)
         return -EINVAL;
   }

   ACQUIRE_SIGLOCK(current);
   sig = SignalDequeue(current, &these, &info);
   if (!sig) {
      if (uts) {
         shouldBlock = (ts.tv_sec || ts.tv_nsec);
      }

      if (shouldBlock) {
         int isSigPending;

         /* Remember the real blocked set in case someone wants to
          * send us a potentially fatal signal. If the fatal signal
          * is blocked in the real blocked set, then it shouldn't result in
          * a group stop or exit. See SignalGroupCompleteSignal()
          * for details. */
         current->realBlocked = current->blocked;
         SigOps_AndSets(&current->blocked, &current->blocked, &these);
         Signal_RecalcSigPending(current);
         RELEASE_SIGLOCK(current);

         D__;

         do {
            wasInterrupted = Sched_ScheduleTimeout(uts ? &ts : NULL);

            /* We may be back prematurely due to a signal that was in
             * the blocked set. */
            isSigPending = Task_TestSigPending(current, 1);
         } while (!isSigPending);


         ACQUIRE_SIGLOCK(current);
         sig = SignalDequeue(current, &these, &info);
#if DEBUG
         if (wasInterrupted) {
            /* We may have gotten a signal that wasn't in the
             * signal set parameter, in which case, we should
             * return -EINTR. */
            ASSERT(sig || !sig);
         }
#endif
         current->blocked = current->realBlocked;
         SigOps_InitSet(&current->realBlocked, 0);
         Signal_RecalcSigPending(current);
      }
   }
   RELEASE_SIGLOCK(current);

   if (sig) {
      ret = sig;
      if (uinfo) {
         /* XXX: */
#if 0
         if (copy_siginfo_to_user(uinfo, &info))
            ret = -EFAULT;
#endif
         ASSERT_UNIMPLEMENTED(0);
      }
   } else {
      ret = -EAGAIN;
      if (wasInterrupted)
         ret = -EINTR;
   }

   return ret;
}


static int
SignalGetToDeliver(siginfo_t *info, struct sigaction *return_ka)
{
   int signr = 0;

relock:
   ACQUIRE_SIGLOCK(current);
   for (;;) {
      struct sigaction *ka;

      /* A group stop may have been initiated. If so, then deschedule
       * until everyone in the group has stopped. */
      if (unlikely(current->signal->groupStopCount > 0) &&
            SignalHandleGroupStop()) {
         /*
          * And we're back from being descheduled.
          */
         goto relock;
      }

      /* Don't need a mask since all received signals are allowed
       * by the process. The exception is right after a sigprocmask,
       */
      signr = SignalDequeue(current, &current->blocked, info);

      if (!signr) {
         break; /* will return 0 */
      }

      /*
       * XXX: ptrace
       */

      ka = &current->sigHand->action[signr-1];

      if (ka->sa_handler == SIG_IGN) {
         DEBUG_MSG(5, "User wants us to ignore it.\n");

         /* If current is ignoring sigchld, then child should not
          * have sent it. See ParentNotify() for details. */
         ASSERT(signr != SIGCHLD);
         continue;
      }

      if (ka->sa_handler != SIG_DFL) {
         /* Run the handler.  */
         *return_ka = *ka;

         if (ka->sa_flags & SA_ONESHOT) {
            ka->sa_handler = SIG_DFL;
         }

         break; /* will return non-zero "signr" value */
      }

      /*
       * Now we are doing the default action for this signal.
       * For example, a SIGCONT without a handler should just
       * wake this task up and let it continue execution.
       */
      if (sig_kernel_ignore(signr)) { /* Default is nothing. */
         DEBUG_MSG(5, "Default action is to ignore.\n");
         continue;
      }

      if (sig_kernel_stop(signr)) {
         DEBUG_MSG(5, "Got a stop signal.\n");
         /*
          * XXX: handle orphaned process group
          */
         if (signr != SIGSTOP) {
            WARN_XXX(0);
         }

         if (SignalDoStop(signr)) {
            /*
             * And we're back from being descheduled.
             */
            goto relock;
         }

         /*
          * XXX: We will be here if the stop was dequeued
          * due to a SIGCHLD removing it from the queue.
          */
         ASSERT_UNIMPLEMENTED(0);
         continue;
      }

      RELEASE_SIGLOCK(current);

      if (sig_kernel_coredump(signr)) {
         /*
          * XXX: Anything else is fatal, maybe with a core dump.
          *
          * SignalDoCoreDump(signr, regs);
          */

         WARN_XXX(0);
      }

      /*
       * Death signals, no core dump.
       */
      Exit_DoGroupExit(signr);
      NOTREACHED();
   }

   RELEASE_SIGLOCK(current);

   return signr;
}

SYSCALLDEF(sys_restart_syscall)
{
   struct RestartBlockStruct *restart = &current->restartBlock;

   D__;
   ASSERT(restart);
   ASSERT(restart->fn);

   return restart->fn(restart);
}

long do_no_restart_syscall(struct RestartBlockStruct *param UNUSED)
{
   return -EINTR;
}

/*
 *-----------------------------------------------------------------------
 * SignalDo --
 *
 * Summary:
 *    Process a queued signal, depending on what's specified in its
 *    sigaction. If it should be handled, then we change context to
 *    that of the handler.
 *
 * Results:
 *    Signal num that was handled, 0 if no signal was handled (e.g.,
 *    all signals were ignored).
 *
 * Side effects:
 *    Lots. Task user context will be modified to that of signal handler
 *    is the main one.
 *
 *-----------------------------------------------------------------------
 */
static int
SignalDo(TaskRegs *regs)
{
   struct siginfo info;
   int signr = 0;
   struct sigaction ka;
   sigset_t *oldset;

   /* If we are going to handle a signal, we want to
    * ensure that the saved sigmask gets restored on
    * return from the signal handler. */
   if (Task_TestFlag(current, TIF_RESTORE_SIGMASK)) {
      oldset = &current->savedSigmask;
   } else {
      oldset = &current->blocked;
   }

   DEBUG_MSG(5, "checking signals\n");
   /*
    * Possible race and why it's not a problem:
    *
    * A signal could arrive after we performed the check but
    * while we're still in the kernel.
    *
    * That's not a problem because it'll be queued and will be
    * delivered either in a subsequent syscall or via preemptive
    * delivery (whichever happens first).
    */
   signr = SignalGetToDeliver(&info, &ka);

   /* If we get here, then the signal wasn't fatal. */

   /* We need to run a handler for this signal. */
   if (signr > 0) {
      D__;
      if (SignalHandle(signr, &info, &ka, oldset, regs) == 0) {
         /* a signal was successfully delivered; the saved
          * sigmask will have been stored in the signal frame,
          * and will be restored by sigreturn, so we can simply
          * clear the TIF_RESTORE_SIGMASK flag */
         Task_ClearCurrentFlag(TIF_RESTORE_SIGMASK);
      }
      D__;

      return 1;
   }

   /*
    * We didn't invoke a signal handler for any signals -- either they were
    * ignored or their default action was taken. Regardless, we must cope
    * with the possibility that the signal interrupted a system call.
    * The way we cope depends on the system call. Some syscalls (e.g.,
    * sys_select, sys_poll, sys_nanosleep) may require that the syscall
    * be restarted (e.g., by returning -ERESTARTNOHAND. But most
    * syscalls aren't sensitive to signals and thus return a non-restart
    * code indicating that no restarting need be done.
    *
    * If we didn't enter to handle a syscall, then no restarting need take
    * place. Recall that we may have entered the vkernel due to reasons other
    * than a syscall. For example, we may have entered due to a preemption
    * or perhaps due to a PMI notification signal, or perhaps due to
    * a notification trap.
    */

   if (current->orig_eax >= 0) {
      /*
       * Restart the system call -- no handlers presents.
       */
      switch (regs->R(eax)) {
         /* For example, current may receive SIGCHLD from the death of
          * its child. But if current was ignoring SIGCHLD, and current was
          * executing a sys_read/write or sys_futex or the like, then
          * that syscall should be restarted. This is Linux behavior, so
          * we must emulate. */
      case -ERESTARTNOHAND:
      case -ERESTARTSYS:
      case -ERESTARTNOINTR:
         Task_WriteReg(regs, eax, current->orig_eax);
         Task_WriteReg(regs, eip, regs->R(eip)-2);
         break;
      case -ERESTART_RESTARTBLOCK:
         /* Needded only for sys_nanosleep() as far as I can tell:
          *
          * sys_nanosleep() shouldn't be restarted with
          * the original sleep value. It should be restarted with
          * a sleep time that compenstates for the time already slept.
          * This compensation is handled by a callback. */
         Task_WriteReg(regs, eax, SYS_restart_syscall);
         Task_WriteReg(regs, eip, regs->R(eip) - 2);
         break;
      default:
         /* syscall was successful. */
         break;
      }
   }

   /* if no signals were handled, then we just put the saved sigmask
    * back -- this happens, for example, when we're done with a sys_sigsuspend,
    * and also on our way out from sys_pselect. */
   if (Task_TestFlag(current, TIF_RESTORE_SIGMASK)) {
      Task_ClearCurrentFlag(TIF_RESTORE_SIGMASK);
      Signal_SigProcMask(SIG_SETMASK, &current->savedSigmask, NULL);
   }

   return 0;
}

/*
 *-----------------------------------------------------------------------
 *
 * SignalHandleSnoop --
 *
 * Summary:
 *    We induce artificial synchronization, at a periodic time interval,
 *    to aid garbage collection during race detection.
 *
 *-----------------------------------------------------------------------
 */
static SHAREDAREA DECLARE_ORDERED_LOCK(snoopLock);

static void
SignalHandleSnoop()
{
   DEBUG_MSG(5, "Snoop event.\n");
   /* All tasks will synch through this variable. */
   ORDERED_LOCK(&snoopLock);
   ORDERED_UNLOCK(&snoopLock);
}

/*
 *-----------------------------------------------------------------------
 *
 * Signal_OnResumeUserMode --
 *
 * Summary:
 *
 *    In non-replay mode, deliver pending signals if there are any.
 *    If replay mode, look ahead in the log to see if there is an
 *    upcoming non-deterministic event. If so, request a notification
 *    for that event. For example, if we look ahead and see that there
 *    is a preemption signal (or a racing read event) coming up,
 *    install a notification for it.
 *
 * Invoked right before handing control to the user-mode dispatch
 * That's the ideal place to setup alter the task context for the
 * signal stack setup, if there are any signals.
 *
 *-----------------------------------------------------------------------
 */

void ASMLINKAGE
Signal_OnResumeUserMode()
{
   int signalHandled;
   TaskRegs *regs = Task_GetCurrentRegs();
#if DEBUG
   int isCallOrPreempt =
      Task_TestFlag(current, TIF_CALL_MASK | TIF_PREEMPT);

   /* Only preemptions and syscalls are deterministically replayed.
    * And thus if we have signals to deliver, then they should be delivered
    * only at these points, since during replay we may enter the kernel
    * for other reasons (e.g., event notifications and pmi interrupts). */
   /* NOTE: isSyscall is also set when the task is born, since it just
    * came out of an sys_execve. */
   ASSERT(isCallOrPreempt);
#endif

   D__;

#if 0
   /* Too expensive to do sys_sigpending() after every syscall. Besides,
    * the user mask (actually, the drain mask) is enabled while
    * making a blocking call, so that is an opportunity for signals
    * to arrive.
    *
    * We should check at every preemption though in case the app is
    * in busy-wait. It may expect a SIGINT for termination, for instance. */
   if (Task_TestFlag(current, TIF_PREEMPT)) {
      /* Ask Linux for signals. We must do this periodically in order
       * to be responsive to terminal signals (e.g., Ctrl+C), for instance. */
      SignalDrainPending();
   }
#endif
   /* XXX: may get a signal while we're dequeing. Need some
    * atomic XCHG action here. */
   Signal_ProcessQueuedSignals();

   /*
    * Linux calls do_signal() while TSF_SIGPENDING is set.
    * We mimic that behavior.
    */
   while (Task_TestSigPending(current, 1 /* use siglock */) ||
         Task_TestFlag(current, TIF_RESTORE_SIGMASK)) {
      signalHandled |= SignalDo(regs);
   }

   ASSERT(SignalIsValidLinuxMask());
   DEBUG_MSG(5, "Exit kernel: eip=0x%x esp=0x%x\n",
         regs->R(eip), regs->R(esp));

   return;
}

static struct Exception*
SignalSearchExceptionTable(const struct sigcontext *scp) {
   const struct Exception *ex;
   extern int __StartExceptionTable, __StopExceptionTable;

   /*
    * XXX: sort the table and make this a binary search
    * as done in the Linux kernel.
    */

   for (ex = (const struct Exception*)&__StartExceptionTable;
         ex != (const struct Exception*)&__StopExceptionTable; ex++) {
      if (ex->addr == scp->eip) {
         DEBUG_MSG(5, "lookup for EIP 0x%x (CR2 0x%x) a success\n", scp->eip,
               scp->cr2);
         return (struct Exception*)ex;
      }
   }

   DEBUG_MSG(5, "lookup for 0x%x a failure\n", scp->eip);
   return NULL;
}


static INLINE int
SignalIsKernelCrash(int signr, ulong eip)
{
   return Signal_IsCrashSig(signr) && Task_IsAddrInKernel(eip);
}


/*
 *-----------------------------------------------------------------------
 *
 * SignalWork --
 *
 * Summary:
 *    Queue incoming, non-preemption, asynchronous signals for
 *    delivery on exit from vkernel. Record that they occurred,
 *    so we can replay them.
 *
 *-----------------------------------------------------------------------
 */
static void
SignalWork(int signr, siginfo_t *si)
{
#if DEBUG
   /* The user-mode preemption handler deals with these. */
   ASSERT(Signal_IsPreemptSig(si) || !Signal_IsPreemptSig(si));
   ASSERT(!Signal_IsTimerSig(si));
   /* IPIs shouldn't be logged -- they are used internally to
    * improve responsiveness. */
   ASSERT(!Signal_IsIPISig(si));
   ASSERT(VCPU_IsLocked(curr_vcpu));
#endif

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(Signal) {
         memcpy(&entryp->si, si, sizeof(*si));
         /* No need to log execution context -- these signals
          * arrive only at drainage points within the vkernel. */
      }
      END_WITH_LOG_ENTRY(0);
   }

   if (SignalIsFromVkernel(si)) {
      ASSERT(Signal_IsSnoopSig(si));

      SignalHandleSnoop();
   } else {
      /* NOTE: you *can* get Linux signals in the vkernel -- e.g.,
       * you can get a SIGINT while you're blocked on a syscall
       * in TASK_INTERRUPTIBLE mode. */
      /* By queuing the signal, we guarantee that it will eventually
       * become visible to the application (unless it's SIG_IGN, of
       * course). */

      /* XXX: should we send to the group for all signals? clearly,
       * tty sigs should be sent to the group, but what about timer
       * sigs?
       *
       * o mysqld's call to sys_rt_sigtimedwait relies on QUIT signal
       * showing up on shared pending queue
       *
       * */
      ACQUIRE_SIGLOCK(current);
      SignalGroupSendSigInfo(signr, si, current);
      //SignalSpecificSendSigInfo(signr, si, current);
      RELEASE_SIGLOCK(current);
   }
}

static void
SignalReplaySignals()
{
   DECLARE_LOG_ENTRY_POINTER(Signal, peekp);

   while (PEEK_LOG_ENTRY(Signal, peekp)
         /*
          * Signals (with the exception of Preemptions) are
          * delivered only while inside the vkernel.
          * &&
          Task_IsAddrInKernel(peekp->uc.uc_mcontext.eip)
          */
         ) {

      /* Timer-preemption signals are logged/replayed by the preemption
       * module. */
      ASSERT(!Signal_IsTimerSig(&peekp->si));
      ASSERT_COULDBE(Signal_IsCrashSig(peekp->si.si_signo));

      DO_WITH_LOG_ENTRY(Signal) {
         SignalWork(entryp->si.si_signo, &entryp->si);
      }
      END_WITH_LOG_ENTRY(0);
   }
}

#if 0
/*
 *-----------------------------------------------------------------------
 *
 * SignalDrainPending --
 *
 * Summary:
 *    In the vkernel signalling scheme, most Linux signals are delivered
 *    to user-space only at well define drainage points denoted by
 *    calls to this function.
 *    This ensures that signal delivery is synchronous, which really
 *    makes it easier to reason about race conditions.
 *
 *-----------------------------------------------------------------------
 */
static void
SignalDrainPending()
{
   DEBUG_MSG(5, "draining signals\n");

   if (!VCPU_IsReplaying()) {
      /* CAREFUL: We could use sigpending()/sigsuspend() to drain signals.
       * But this can race when there are multiple threads.
       * Specifically, sigpending() says yes, there is a signal.
       * But when we sigsuspend, there is no signal, because another
       * thread already dequeued it. */

      int signo;
      sigset_t drainset;
      siginfo_t si;

      /* With a 0 timeout, sys_sigtimedwait() will return immediately
       * if no signals are pending. */
      struct timespec timeout = { .tv_sec = 0, .tv_nsec = 0 };

      /* Linux will invert the drain set to get the draink mask
       * in sys_rt_sigtimedwait(). Hence we invert it here. */
      SigOps_InitSet(&drainset, ~SIG_DRAIN_MASK);

      while ((signo =
               syscall(SYS_rt_sigtimedwait, &drainset, &si, &timeout,
                  sizeof(sigset_t))) > 0) {
         SignalQueue(&si);
      }

      ASSERT(signo == -EAGAIN);

      /* We don't want subsequent blocking syscalls to -EINTR for
       * no reason (which it will if TIF_INTR_PENDING flag is set;
       * see rsyscall.S). After all, if we did get some signals, they
       * will be delivered on the way out of ther vkernel. */
      Task_ClearCurrentFlag(TIF_INTR_PENDING);

      ASSERT(SigOps_IsMask(sigMask));

   } else {
      SignalReplaySignals();
   }
}
#endif

/*
 *-----------------------------------------------------------------------
 *
 * Signal_ProcessQueuedSignals --
 *
 * Summary:
 *
 *    We can't process signals while blocked in a Linux syscall.
 *    The reason is that we don't have the VCPU lock at that point
 *    and thus writing to the log (necessary for recording signal)
 *    is prohibited for fear of races. Hence we queue signals and
 *    process them after we've acquired the VCPU lock. This
 *    function does that processing.
 *
 *-----------------------------------------------------------------------
 */
void
Signal_ProcessQueuedSignals()
{
   ASSERT(VCPU_IsLocked(curr_vcpu));


   if (!VCPU_IsReplaying()) {
      struct LinuxSignal *sigp, *tmp;
      sigset_t mask, oldmask;

      SigOps_InitSet(&mask, ~0);
      SigOps_SetMask(&mask, &oldmask);
      list_for_each_entry_safe(sigp, tmp, &current->sigq, list) {
         ASSERT(!Signal_IsIPISig(&sigp->si));

         DEBUG_MSG(5, "sigp->signr=%d\n", sigp->signr);

         SignalWork(sigp->signr, &sigp->si);
         List_Del(&sigp->list);
         SharedArea_Free(sigp, sizeof(*sigp));
      }

      Task_ClearCurrentFlag(TIF_INTR_PENDING);
      SigOps_SetMask(&oldmask, NULL);
   } else {
      SignalReplaySignals();
   }

}

/*
 *-----------------------------------------------------------------------
 *
 * SignalQueue --
 *
 * Summary:
 *
 *    We can't process Linux signals as soon we get them while blocked
 *    in a syscall. That's because
 *    we get them when we don't have the VCPU lock and hence when
 *    we aren't allowed to write to the VCPU log (for fear of races).
 *    If we can't write to the VCPU log, then we can't log the signal
 *    occurrence and details and hence can't provide replay.
 *
 *    We get around this by queuing Linux signals when they come in
 *    while blocked in on syscall.
 *    Later, once we've acquired the VCPU lock, we then process each
 *    signal. This is inefficient in that it requires copying signal
 *    context, which can be quite large, but what the hell, getting a Linux
 *    signal is expensive anyway.
 *
 *-----------------------------------------------------------------------
 */
void
Signal_Queue(const siginfo_t *si)
{
   int signr = si->si_signo;
   struct LinuxSignal *sigp;

   ASSERT(!VCPU_IsReplaying());
   ASSERT(Task_IsInTaskStack());
   ASSERT(!Signal_IsTimerSig(si));

   /* Setting this flag ensures that we don't block on any syscalls
    * while a signal is waiting to be processed. This can happen
    * if Linux delivers the signal right before we make the blocking
    * syscall. */
   Task_SetCurrentFlag(TIF_INTR_PENDING);

   if (!Signal_IsIPISig(si)) {
      DEBUG_MSG(5, "Queuing Linux signal: signr=%d\n", signr);

      /* The signal queue is task local, so no need for any locks.
       * We can't make it VCPU local, since multiple tasks assigned
       * to the same VCPU may be in interruptible state and hence
       * may receive signals from Linux.
       *
       * Also, the kernel mask is enabled within the signal handler,
       * so we needn't worry about signal handler reentrance. */

      sigp = SharedArea_Malloc(sizeof(*sigp));
      sigp->signr = signr;
      sigp->si = *si;

      List_AddTail(&sigp->list, &current->sigq);
   } else {
#if DEBUG
      /* IPIs shouldn't be logged and hence we don't queue them.
       * They are meant to achieve greater responsiveness -- by
       * kicking tasks blocked in IO syscalls. */

      int isIoPending = Task_TestFlag(current, TIF_IO_PENDING);
      DEBUG_MSG(5, "Got IPI.\n");

      /* TIF_IO_PENDING is cleared before the kernel mask is
       * reenabled, so this signal may have taken place before
       * or after the clearing (see Task_BlockingRealSyscall()). */
      ASSERT(isIoPending || !isIoPending);
#endif
   }
}

/*
 *-----------------------------------------------------------------------

 * Signal_EntryFromVK --
 *
 * Summary:
 *    The goal here is to filter out signals that SignalWork
 *    wasn't designed to handle. There are two types.
 *
 *    The first type is crash signals. These indicate a bug within
 *    the vkernel and thus we must gracefully terminate with
 *    useful debug info. Or could be crash generated by app.
 *
 *    The second type is exceptions. These typically occur when
 *    the vkernel does something impermissible (e.g., writes into
 *    unmapped memory during a syscall due to a bad argument) yet
 *    that can be recovered from. We recover by looking at the
 *    exception table entry corresponding to the PC of the
 *    exception.
 *
 *-----------------------------------------------------------------------
 */
void
Signal_EntryFromVK(siginfo_t *si, ucontext_t *uc)
{
   const int signr = si->si_signo;
   struct sigcontext *scp = &uc->uc_mcontext;

   ASSERT(signr < _NSIG);
   ASSERT(Task_IsInTaskStack());
   /* We've explicitly ignored SIGCHLD by setting SA_NOCLDWAIT.
    * The vkernel takes care of reaping dead children. */
   ASSERT(signr != SIGCHLD);

   /* User-mode crashes bring us here as well. */
   ASSERT(Task_IsAddrInKernel(scp->eip));

   /* The vkernel is non-preemptible. So preemption signals
    * should be blocked while we're in the kernel. Moroever,
    * preemption received in user-mode are handeld elsewhere. */
   if (Signal_IsTimerSig(si)) {
      return;
   }

   /*
    * Don't deliver the recently queued signal if we are in the
    * kernel, because we
    * want to avoid re-entering the kernel. Instead, we'll
    * deliver it:
    *
    * 1) on exit from the kernel syscall
    *
    * -- or --
    *
    * 2) when this handler gets called again when we're not in
    *    the kernel (namely, on a preemption signal)
    */
   struct Exception *fixup;

   if ((fixup = SignalSearchExceptionTable(scp))) {

      ASSERT(fixup);

      /* sigmask() produces only a 32-bit mask -- hopefully we
       * won't need to mask any of the real-time signals. */
      ASSERT_UNIMPLEMENTED(signr < 32);
      if (sigmask(signr) & fixup->sigmask) {
         /*
          * Looks like this signal applies for this exception.
          * Sigreturn to the fixup code.
          */
         scp->eip = fixup->fixup;
      }

      return;
   } else if (Signal_IsCrashSig(signr)) {
      /* NOTE: the exception table needs to be searched before
       * calling this, since the crash may need to be recovered
       * from (e.g., because it was generated by Task_CopyToUser()
       * and family). */
      SignalErrorHandler(signr, si, uc);
      NOTREACHED();
   } else {
      if (VCPU_IsReplaying()) {
         DEBUG_MSG(3, "ignoring since we are replaying\n");
         return;
      }
   }

   Signal_Queue(si);

   return;
}

static INLINE int
SignalIsProtFault(int nr, int code)
{
   int res = 0;

   if (nr == SIGSEGV) {
      ASSERT(code == SEGV_MAPERR ||
             code == SEGV_ACCERR);

      res = code == SEGV_ACCERR;
   }

   return res;
}

void
Signal_SendFaultSig(siginfo_t *siP)
{
#if 0
   struct siginfo_t si;
   memset(&si, 0, sizeof(si));

   si->si_signo = nr;
   si->si_errno = 0;
   si->si_code = code;
   si->si_addr = (void*)addr;
#endif

   ACQUIRE_SIGLOCK(current);
   SignalSpecificSendSigInfo(siP->si_signo, siP, current);
   RELEASE_SIGLOCK(current);
}

/*
 *-----------------------------------------------------------------------
 * Signal_BlockingRealSyscall --
 *
 * Summary:
 *
 *    Make a Linux syscall that we expect will block. While
 *    blocked, permit signals to arrive and hence terminate the
 *    syscall. This ensures reponsiveness to SIGINTs, timers, IPI
 *    signals, etc.
 *
 *    After the syscall, restore our kernel mask.
 *
 *-----------------------------------------------------------------------
 */
SyscallRet
Signal_BlockingRealSyscall(const struct SyscallArgs *args)
{
   SyscallRet ret = -1;
#if DEBUG
   int state = Task_GetCurrentState();
   ASSERT(state == TASK_INTERRUPTIBLE);
   ASSERT(args);
#endif

   /* This may fire if we get a signal after the first check. */
#if 0
   ASSERT(Task_TestFlag(current, TIF_INTR_PENDING) ||
         !Task_TestFlag(current, TIF_INTR_PENDING));
#endif

   /* Should be set before we make the blocking call. */
   ASSERT(Task_TestFlag(current, TIF_IO_PENDING));


   ASSERT(SignalIsValidLinuxMask());
   ret = Task_BlockingRealSyscall(args);
   ASSERT(SignalIsValidLinuxMask());

   /* We may miss signals if we clear the flag here -- recall that
    * signals may come at any time now...so doing this doesn't make any
    * sense. */
#if 0
   /* Should be cleared only AFTER the kernel mask has been enabled
    * to ensure that flag isn't set again by an IPI straggler. */
   Task_ClearCurrentFlag(TIF_INTR_PENDING);
#endif

   return ret;
}


#if 0
/* For reference. */
struct sigcontext {
   unsigned short gs, __gsh;
   unsigned short fs, __fsh;
   unsigned short es, __esh;
   unsigned short ds, __dsh;
   unsigned long edi;
   unsigned long esi;
   unsigned long ebp;
   unsigned long esp;
   unsigned long ebx;
   unsigned long edx;
   unsigned long ecx;
   unsigned long eax;
   unsigned long trapno;
   unsigned long err;
   unsigned long eip;
   unsigned short cs, __csh;
   unsigned long eflags;
   unsigned long esp_at_signal;
   unsigned short ss, __ssh;
   struct _fpstate __user * fpstate;
   unsigned long oldmask;
   unsigned long cr2;
};
#endif

static void
SignalInstallStack(struct Task* ts)
{

   ASSERT(ts != NULL);

   /* expects lowest stack address */;
   ts->sigstack_ss.ss_sp = (void*)Task_GetStackBase(ts);
   ASSERT(VK_STACKSZ == sizeof(ts->stack.stack));
   /* +16, because Linux start sigframe such that esp+4 is 16-byte aligned. */
   ts->sigstack_ss.ss_size = VK_STACKSZ + sizeof(struct rt_sigframe) + 16;
   /* 0 --> SS_ONSTACK, but 1 would also work in newer kernels */
   ts->sigstack_ss.ss_flags = 0;

   /* Make sure the sigframe has the new stack set so than on sigreturn,
    * it will remain in effect (recall that sigreturn resets the
    * sigstack to that specified in the sigframe). */
   ts->stack.un.frame.uc.uc_stack = ts->sigstack_ss;

   DEBUG_MSG(5, "base=0x%x size=0x%x VK_STACKSZ=%d sizeof(TaskArchState)=%d\n",
         ts->sigstack_ss.ss_sp, ts->sigstack_ss.ss_size,
         VK_STACKSZ, sizeof(TaskArchState));

   ASSERT(ts->sigstack_ss.ss_sp);
#define MINSIGSTKSZ 2048
   ASSERT(ts->sigstack_ss.ss_size >= MINSIGSTKSZ);

   DEBUG_MSG(3, "Using alternate signal stack at 0x%x-0x%x.\n",
         Task_GetStackBase(ts),
         Task_GetStackBase(ts) + ts->sigstack_ss.ss_size
         );

   /* XXX: is this hack still needed? */
   /* Warning: There is a hack in return-to-user-mode-code
    * concerning the fact that sigreturn restores the pre-signal signal stack.
    Don't do anything fancy here to avoid screwing up the hack. */
   if (syscall(SYS_sigaltstack, &ts->sigstack_ss, NULL) != 0) {
      FATAL("Can't set signal stack for this task.\n");
   }
}

/*
 *-----------------------------------------------------------------------
 *
 * SignalInstallHandlers --
 *
 * Summary:
 *
 *    We intercept all signals (expcept SIGKILL and SIGSTOP which we
 *    aren't allowed to). There are two classes of signals: those
 *    that we receive while executing app code and those we receive
 *    while executing vkernel code.
 *
 *    App code signals:
 *       o SIGTRAP -- used for syscall, rdtsc, rdpmc interception
 *       o SIG_RESERVED_USER -- used for preemption timer
 *
 *    Vkernel signals:
 *       o all signals other than app code signals
 *       o caveat: allowed to arrive in vkernel only at selected drainage
 *         points to ensure determinism (see SignalDrainPending()).
 *
 *    Regardless of whether signal arrives in app-land or vkernel-land,
 *    the signal handler always executes on the vkernel stack (there
 *    is only one stack) and should never be intercepted first by
 *    the application.
 *
 *-----------------------------------------------------------------------
 */
#if DEBUG
static SHAREDAREA atomic_t sigInstallCallCount = ATOMIC_INIT(1);
#endif

void
SignalInstallHandlers()
{
   int i, ret;
   struct sigaction sa;

#if DEBUG
   DEBUG_MSG(3, "Installing covert signal handlers.\n");
   /* Should be called only once -- recall that threads share
    * their signal handler table, so if we change it for one
    * thread, it affects all threads. This can result in
    * hard-to-track bugs. */
   ASSERT(atomic_dec_and_test(&sigInstallCallCount));
#endif


   for (i = 1; i <= _NSIG; i++) {
      memset(&sa, 0x0, sizeof(sa));


      /* 
       * We need SA_SIGINFO, because we need to
       * record/replay signals in the same CPU context,
       * and knowing context also helps in debugging.
       *
       * We need SA_NODEFER, because to simplify coding,
       * we assume that any signal can come at any time
       * while in the vkernel unless explicitly blocked.
       *
       * WARNINGS:
       *    o Do not mask SIG_RESERVED_SERVER here since we may not
       *    restore the original sigmask---when don't do a sigreturn to
       *    return to BT mode execution.
       */
      sa.sa_flags = SA_SIGINFO | SA_NODEFER;

      switch (i) {
      case SIGKILL: /* Don't even try -- Linux won't let us. */
      case SIGSTOP: /* Don't even try. */
         continue;
         break;
      case SIGCHLD:
         /* We don't want to have to call Linux's sys_wait() on dead
          * children. Tell Linux to automatically reap them. */
         sa.sa_flags = SA_NOCLDWAIT | SA_NOCLDSTOP;
         sa.sa_sigaction = (void (*)(int, siginfo_t*, void*))
            SIG_IGN;
         break;
      default:
         if (Cap_Test(CAP_HARD_BRCNT)) {
            sa.sa_sigaction = (void (*)(int, siginfo_t*, void*))
               Gate_SignalHardBrCnt;
         } else {
            sa.sa_sigaction = (void (*)(int, siginfo_t*, void*))
               Gate_SignalSoftBrCnt;
         }
         SigOps_InitSet(&sa.sa_mask, 0);
         break;
      }

      /* Tell Linux to run signal handlers on the vkernel
       * stack rather than on the app stack -- the goal is
       * to avoid introducing nondeterminism into the app's
       * address space. */
      sa.sa_flags |= SA_ONSTACK;

      /* Linux won't let us catch SIGKILL and SIGSTOP; that's okay
       * since we don't rely on the Linux kernel's signal implementation. */
      /* Must use syscall here rather than's dietlibc's sigaction since
       * the latter doesn't work in the presence of alternate signal
       * stacks. */
      ASSERT(_NSIG / 8 == sizeof(sigset_t));
      if ((ret = syscall(SYS_rt_sigaction, i, &sa, NULL, _NSIG / 8)) != 0) {
         DEBUG_MSG(2, "rt_sigaction failed on sig %d=%s\n",
               i, sys_siglist[i]);

         ASSERT(0);
         continue;
      }
   }

   return;
}

#define TIMER_ON 0
#define PREEMPT_TIMER_ON 1
#define SNOOP_TIMER_ON 0

#if TIMER_ON
#if PREEMPT_TIMER_ON

static int
SignalInstallTimer(int whichClock, struct timespec ts, int sigev_signo,
      int sigev_value)
{
   int res;
   timer_t id = -1;
   struct sigevent ev;
   struct itimerspec its;

   memset(&ev, 0, sizeof(ev));
   ev.sigev_signo = sigev_signo;
   ev.sigev_value.sival_int = sigev_value;
   /* We need SIGEV_THREAD_ID for two reasons:
    *    o we want the preemption signal delivered to this
    *    task and no other
    *
    *    o without this flag, the default delivery target is
    *    the thread group leader. But he may be about to exit,
    *    in which case the sys_timer_create call will
    *    return -EINVAL, and we don't want to have to retry.
    */
   ev.sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
   ev._sigev_un._tid = gettid();

   res = syscall(SYS_timer_create, whichClock, &ev, &id);
   ASSERT_MSG(!res, "res=%d\n", res);
   ASSERT(id >= 0);

   its.it_interval = ts;
   its.it_value.tv_sec = 0;
   its.it_value.tv_nsec = 1;

   res = syscall(SYS_timer_settime, id, 0, &its, NULL);
   ASSERT(!res);

   return id;
}

/*
 *-----------------------------------------------------------------------
 *
 * SignalInstallPreemptTimer --
 *
 * Summary:
 *
 *    We perform preemptive scheduling using real-time timers and
 *    a designated signal.
 *
 *-----------------------------------------------------------------------
 */
static void
SignalInstallPreemptTimer()
{
   struct timespec ts;
   int whichClock;

   /*
    * CLOCK_THREAD_CPUTIME_ID because we don't want to
    * receive preemptions while blocked in Linux syscalls.
    *
    * Don't use CLOCK_REALTIME; see below.
    */
   whichClock = CLOCK_THREAD_CPUTIME_ID;
   /* CLOCK_REALTIME could cause receiver-livelock in apps like
    * tomcat -- we get preempted, then scheduled in, but as soon
    * as we return to app-space, we get preempted again, hence
    * won't make forward progress. */
   ASSERT(whichClock != CLOCK_REALTIME);

   /* Milliseconds to nanoseconds */
#define MS2NS(x) ((x) * 1000000)
   ts.tv_sec = 0;

   /* Setting the time-slice too low can result in many preemption
    * signals delivered while we're executing the vkernel.
    * These signals will then be delivered on return to user-level,
    * and that will lead to receiver-livelocok. */
#define TIMESLICE_LEN 300
   ts.tv_nsec = MS2NS(TIMESLICE_LEN);

   current->preemptTimerId =
      SignalInstallTimer(whichClock, ts, SIG_PREEMPT_TIMER, SIG_ID_PREEMPT);
}
#endif

#if SNOOP_TIMER_ON
/*
 *-----------------------------------------------------------------------
 *
 * SignalInstallSnoopTimer --
 *
 * Summary:
 *
 *    XXX: explain this better
 *
 *    Snoops are artificially induced synchronization points.
 *    They are needed to make a thread come out of the kernel
 *    and synchronize when they're making a blocking syscall.
 *    We use them to enforce an upper-bound on race-detection
 *    segment size.
 *-----------------------------------------------------------------------
 */
static void
SignalInstallSnoopTimer()
{
   struct timespec ts;
   int whichClock;

   /* We need to use the REALTIME clock, so we are interrupted even inside
    * syscalls. */
   //whichClock = CLOCK_THREAD_CPUTIME_ID;
   whichClock = CLOCK_REALTIME;


   ts.tv_sec = 0;
   /*
    * XXX: We need to be careful about selecting the snoop interval,
    * especially since it uses the REALTIME clock.
    *
    * o need <= 1000 ms to avoid out-of-memory problems
    * during race-detection. 3 secs, for example, causes
    * problem with apache.
    *
    * o 500 ms is good enough for most apps, but not Sun's Hotspot JVM,
    * which needs at most 100 ms (but probably even less) to avoid OOM.
    *
    * o Of course, we could increease the latency if we allowed
    * more memory for race detection.
    *
    * o But too low of a value may result in receiver livelock,
    * e.g., with libc test 2, since we're using a REALTIME clock.
    *
    * */
#define GOOD_ENOUGH_TO_RACE_DETECT_JVM 100
   ts.tv_nsec = MS2NS(GOOD_ENOUGH_TO_RACE_DETECT_JVM);

   current->snoopTimerId =
      SignalInstallTimer(whichClock, ts, SIGSNOOP, SIG_ID_SNOOP);
}
#endif
#endif

/*
 *-----------------------------------------------------------------------
 *
 * Signal_SelfInit() --
 *
 * Summary:
 *    Initializes the signal handling subsystem. This involves
 *    installing handlers for linux signals and creating timers
 *    for internal purposes (e.g., preemption).
 *
 *    Some key points about signal handling:
 *
 *    o We block most Linux signals for the majority of execution and
 *    deliver them only at designated drainage points (denoted by
 *    calls to SignalDrainPending()).
 *
 *    o All Linux signals are handled on the vkernel stack for the
 *    recipient thread. There is no separate signal stack. This means
 *    that if we get a signal while in app-code (the only valid
 *    one is a preempt signal), then Linux will switch to the vkernel
 *    stack for the thread to handle that signal.
 *
 *-----------------------------------------------------------------------
 */
void
Signal_SelfInit()
{
   DEBUG_MSG(5, "always_unblocked=0x%x blocked=0x%x\n",
         _ALWAYS_UNBLOCKED, current->blocked);

#if 0
   SigOps_Mask(~_ALWAYS_UNBLOCKED, NULL);
   ASSERT(SigOps_IsMask(~_ALWAYS_UNBLOCKED));
#endif

   SignalSetLinuxMask(current->blocked);

   SignalInstallStack(current);

#if TIMER_ON
   if (!VCPU_IsReplaying()) {
#if PREEMPT_TIMER_ON
      SignalInstallPreemptTimer();
#endif
#if SNOOP_TIMER_ON
      SignalInstallSnoopTimer();
#endif
   }
#endif
}

void
Signal_SelfExit()
{
#if TIMER_ON
   int err;

   D__;

   err = syscall(SYS_timer_delete, current->preemptTimerId);
   ASSERT(!err);
#if SNOOP_TIMER_ON
   err = syscall(SYS_timer_delete, current->snoopTimerId);
   ASSERT(!err);
#endif

   current->preemptTimerId = current->snoopTimerId = -1;
#endif
}

static int
Signal_Init()
{
   DEBUG_MSG(5, "Initializing signals\n");

   ASSERT(NSIG != _NSIG);
   ASSERT(_NSIG > NSIG);
   /* Must be different for signal masks to work. */
   ASSERT(SIG_RESERVED_USER != SIG_RESERVED_KERNEL);


   /* No need to call this on every fork. A copy is
    * inherited without CLONE_SIGHAND, and shared without.
    * Moreover, we don't let the app modify it. */
   SignalInstallHandlers();

   return 0;
}

/* CORE and not POSTCORE because we want to catch any ASSERTs
 * that fire during POSTCORE. */
CORE_INITCALL(Signal_Init);
