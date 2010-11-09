#include <errno.h>

#include "vkernel/public.h"
#include "private.h"

/*
 * A typical OS scheduler (such as the Linux scheduler) relies on
 * an idle task for important functions. The idle task simply spins
 * in a tight loop, and is ready to schedule in other tasks at
 * a moment's notice. This works because the idle tasks receives
 * interrupts while on the CPU and hence knows when other tasks
 * may be interested in the CPU. The idle task simplifies the
 * scheduler design because it provides an important invariant:
 * there is always at least 1 task on the runqueue. So if a task
 * wants to be scheduler, he need only place himself in the runqueue
 * and kick the active task.
 *
 * We don't use an idle task, mainly because it requires an
 * additional task per VCPU, and that is uncessary given that
 * a idle task less design is possible with slightly greater
 * complexity.
 *
 * Implications:
 *
 * o When all tasks on VCPU go to sleep, blocked in a waitqueue
 * or on io, somebody must be designated the guardian task --
 * the guy responsible for waking up previously blocked but now
 * ready tasks. This is typically the role of the idle task.
 *
 * o The guardian task may itself block on io, but nonetheless
 * must be at the head of the runqueue. So even though it may be
 * in TASK_INTERRUPTIBLE state, it is on the runqueue.
 *
 * o If any tasks finishes io and wants to be put on the runqueue
 * again, then it must notify the guardian task, via IPI, or
 * it will incur delays in scheduling.
 *
 * o If no one running on VCPU, task on remote VCPU schedules
 * new tasks in, not an idle thread (by cond_signalling us)
 *
 *
 * Tricky cases:
 *
 * o Everyone is blocking, either on io or waitpid, and guardian task
 *   exits. Another guardian must be selected, but who?
 *   - pick ony io-blocked task, but what if there are none? what if
 *     all blocked on waitpid?
 *
 * o XXX: when guardian gets woken up by ready task, ready task
 * won't be cond_signalled until guardian makes a syscall again.
 *    - we need a need_resched flag that is checked on exit from
 *    syscalls?
 *
 * o XXX: we use signals to break blocking tasks out of syscalls,
 * but this behavior depends on the device driver ... it needn't
 * checks for pending signals and return -EINTR, although I think
 * it is supposed to. We need a more robust mechanism.
 *
 * o XXX: receiver livelock -- thread can't make progress because
 * it constantly gets an IPI.
 */



#define ASSERT_RUNQUEUE_LOCKED(t) ORDERED_ASSERT_IS_LOCKED(&t->vcpu->queueLock)
#define ACQUIRE_RUNQUEUE_LOCK(t) ORDERED_LOCK(&t->vcpu->queueLock)
#define RELEASE_RUNQUEUE_LOCK(t) ORDERED_UNLOCK(&t->vcpu->queueLock)

/* XXX: Replace with real functions. */
#define VCPU(t) (t->vcpu)
#define RUNQ(t) (&t->vcpu->runq)

static INLINE int
SchedIsActive(struct Task *t)
{
   return t->array != NULL;
}


static INLINE int
SchedIsRunHead(struct Task *tsk)
{
   ASSERT(tsk->vcpu);

   return (tsk->vcpu->runq.list.next == &tsk->runList);
}

/*
 * Returns head of @t's run queue. Null if none.
 */
static struct Task*
SchedGetRunHeadUnlocked(struct Task *t) 
{
   struct Task *next;

   if (List_IsEmpty(&RUNQ(t)->list)) {
      next = NULL;
   } else {
      next = list_entry(RUNQ(t)->list.next, struct Task, runList);
   }

   return next;
}

static struct Task*
SchedGetRunHead(struct Task *t) 
{
   ASSERT_RUNQUEUE_LOCKED(t);

   return SchedGetRunHeadUnlocked(t);
}

/*
 * Returns head of the wait queue.
 */
static struct Task*
SchedGetBlockHead() 
{
   struct Task *next;
   struct VCPU *vcpu = curr_vcpu;
   struct BlockedQueue *blockq = &vcpu->blockq;

   ASSERT_RUNQUEUE_LOCKED(current);

   if (List_IsEmpty(&blockq->list)) {
      next = NULL;
   } else {
      next = list_entry(blockq->list.next, struct Task, blockList);
   }

   return next;
}

static void
SchedPrintRunQueue()
{
   struct Task *tsk;
   struct VCPU *vcpu = curr_vcpu;

   DEBUG_MSG(5, "Printing run queue.\n");
   list_for_each_entry(tsk, &vcpu->runq.list, runList) {
      DEBUG_MSG(5, "%d.0x%x\n", tsk->id, tsk);
   }
}

static void
SchedPrintBlockQueue()
{
   struct Task *tsk;
   struct VCPU *vcpu = curr_vcpu;

   DEBUG_MSG(5, "Printing block queue.\n");
   list_for_each_entry(tsk, &vcpu->blockq.list, blockList) {
      DEBUG_MSG(5, "%d.0x%x\n", tsk->id, tsk);
   }
}

static void
SchedSendIPI(struct Task *t)
{
   ASSERT(t != current);


   if (!VCPU_IsReplaying()) {
      DEBUG_MSG(5, "Considering sending IPI to t=%d.0x%x\n", t->id, t);

      /* CAREFUL: We check TIF_IO_PENDING to avoid a possible
       * livelock situation. If we send @t an IPI regardless
       * of whether it is pending IO or not, then we may cause
       * @t to bail on subsequent blocking syscalls (after
       * enabling the drain mask, @t will process our IPI and
       * then -EINTR on the syscall) and then wake another 
       * IO-blocked task by sending it an IPI.
       * But that task won't be able to make any blocking
       * syscalls because it needs to process its IPI, and 
       * so it sends an IPI to @t again, and so on endlessly. 
       *
       * How to trigger this:
       *
       * sh$ sleep 1000 & 
       * sh$ sleep 1000 &
       *
       * Of course, there won't be livelock even in the situation
       * above if we send the IPI only if @t is blocking or about
       * to block in a syscall.
       */
      if (Task_TestFlag(t, TIF_IO_PENDING)) {
         syscall(SYS_tkill, t->realPid, SIG_RESERVED_KERNEL);
         DEBUG_MSG(5, "Sent.\n");
      }
   } else {
      /* We don't call through to Linux for blocking syscalls
       * during replay, so an IPI does no good. */
   }
}

static void
SchedActivateTask(struct Task *t)
{
   ASSERT_RUNQUEUE_LOCKED(t);
   ASSERT(VCPU_IsLocked(curr_vcpu));

   DEBUG_MSG(5, "activating t=%d.0x%x\n", t->id, t);

   /*
    * t may already be in the run queue, perhaps
    * because it was woken up by some other thread,
    * or perhaps because we received a signal interrupt
    * (e.g., a SIGINT) while blocked on a syscall.
    */
   if (t->array) { goto out; }

   /* The Init in DelInit is deliberate: t may not be in
    * the block list, so we must be careful not to unlink
    * based on stale pointers. */
   List_DelInit(&t->blockList);

   List_AddTail(&t->runList, &RUNQ(t)->list);


   RUNQ(t)->count++;
   ASSERT(RUNQ(t)->count > 0);

   t->array = &RUNQ(t)->list;
out:
   return;
}

static void
SchedSnoozeTask(struct Task *t)
{
   struct VCPU *vcpu = Task_GetVCPU(t);
   struct BlockedQueue *blockq = &vcpu->blockq;

   ASSERT_RUNQUEUE_LOCKED(t);
   ASSERT(t == current);

   /* No one else other than @current can put us
    * in the block queue. But others can certainly
    * take us out (via wake-up). */
   ASSERT(VCPU_IsLocked(t->vcpu));


   List_AddTail(&t->blockList, &blockq->list);

   blockq->count++;
   ASSERT(blockq->count > 0);
}

static void
SchedDeactivateTask(struct Task *t)
{
   ASSERT_RUNQUEUE_LOCKED(t);
   ASSERT(VCPU_IsLocked(curr_vcpu));

   DEBUG_MSG(5, "t=0x%x\n", t);
   ASSERT(t->array != NULL);

   List_DelInit(&t->runList);
   RUNQ(t)->count--;
   ASSERT(RUNQ(t)->count >= 0);
   t->array = NULL;
}

static void
SchedDeactivateCurrent()
{
   struct Task *head;

   ASSERT_RUNQUEUE_LOCKED(current);

   head = list_entry(RUNQ(current)->list.next, struct Task, runList);
   ASSERT(head == current);

   SchedDeactivateTask(current);

   if (Task_GetCurrentState() == TASK_INTERRUPTIBLE) {
      /* Let other tasks know that it is okay for them to send us
       * IPIs -- we are indeed about to block on IO. We clear
       * this flag right after making the blocking syscall in
       * Task_BlockingRealSyscall(). */
      Task_SetCurrentFlag(TIF_IO_PENDING);
   }

   ASSERT(SchedGetRunHead(current) != current);
}

static int
SchedCondListen(struct Task *tsk)
{
   int waitVal;
   struct SynchCond *pcv = &tsk->schedCond;

   /* Indicate that @current is waiting for a cond_signal. */
   pcv->total_seq++;
   waitVal = pcv->wakeup_seq;
   ASSERT(waitVal >= 0);
   ASSERT(waitVal == pcv->total_seq - 1);

   DEBUG_MSG(8, "futex=0x%x *futex=%d\n", &pcv->wakeup_seq, waitVal);

   return waitVal;
}

/*
 * We could use SchedCondSignal, but that acquires the pcv->lock,
 * which is unecessary since the cvp is always protected by the
 * VCPU lock.
 */
static void
SchedCondSignal(struct Task *tsk)
{
   struct SynchCond *cvp = &tsk->schedCond;
   volatile uint *futex = &cvp->wakeup_seq;

   ASSERT(VCPU_IsLocked(Task_GetVCPU(tsk)));
   ASSERT(cvp->total_seq > cvp->wakeup_seq);

   (*futex)++;

   if (tsk != current) {
      Synch_FutexWake(futex, 1);
   }

   DEBUG_MSG(8, "futex=0x%x *futex=%d\n", futex, *futex);
}


static void
SchedContinue(struct Task *t, int isAlreadyActive)
{
   struct Task *head;

   ASSERT_RUNQUEUE_LOCKED(t);

   head = SchedGetRunHead(t);
   ASSERT(head);

   /* We shouldn't try for the VCPU lock if t is already active,
    * since we may be holding the task list lock and want
    * t's vcpu lock, while t may holds the vcpu lock and wants the
    * task list lock, hence creating deadlock. */
   if (t == head && !isAlreadyActive) {
#if DEBUG
      if (t->vcpu == current->vcpu) {
         ASSERT(current == &initTask);
      }
#endif

      /* Note that if @t is the init task, we already
       * have the vcpu lock, so this would be a recursive invocation. */
      VCPU_Lock(t->vcpu);

      VCPU_Activate(t->vcpu);

      /* t is the only task assigned to its VCPU. There is
       * no other task on it, not even an idle task.
       * Hence, no one else is going to handoff the VCPU to it,
       * so allow it to immediately grab the VCPU and go. */
      SchedCondSignal(t);

      VCPU_Unlock(t->vcpu);
   } else {
      if (t->vcpu != current->vcpu) {
         /* Tell the active thread on the remote VCPU to
          * schedule @t in. */
         ASSERT(head);
         SchedSendIPI(head);
      }
   }
}

/*
 * Meant to be called by @t's parent to put @t on its runqueue.
 */
void
Sched_WakeNewTask(struct Task *t)
{
   /*
    * Put the new task on the schedule wait queue before
    * putting it on the run list. This avoids the race where
    * the parent races ahead, signals the child, but because
    * the child wasn't in the wait queue, it misses the signal.
    */
   t->schedCond.wakeup_seq = 0;
   t->schedCond.total_seq = 1;
   t->schedCond.woken_seq = 0;
   /* without this, t won't be placed in the VCPU runqueue. */
   t->array = NULL; 

   ACQUIRE_RUNQUEUE_LOCK(t);

   ASSERT(t->state == TASK_RUNNING);

   SchedActivateTask(t);

   ASSERT(RUNQ(t)->count > 0);

   SchedContinue(t, 0 /* not already active */);

   RELEASE_RUNQUEUE_LOCK(t);
}



/* XXX: At some point, get rid of the Try...this simply wakes @t up. */
static void
SchedTryToWakeUp(struct Task *t, uint state)
{
   ASSERT(t != current);

   int tstate = Task_GetState(t);
   /*
    * By acquiring and releasing t's runqueue lock,
    * we establish a happens-before relationship between
    * current and t. This is essential for capturing
    * ordering between exit and wait, for example. */

   ASSERT_RUNQUEUE_LOCKED(t);
   ASSERT(VCPU_IsLocked(curr_vcpu));

   DEBUG_MSG(5, "t=%d.0x%x tstate=0x%x state=0x%x\n", t->id, t, tstate,
         state);
   if (tstate & state) {
      int isAlreadyActive = SchedIsActive(t);

      if (!isAlreadyActive) {
         D__;
         SchedActivateTask(t);
      } else {
         /* It's already awake. For example, Signal_NotifyParent
          * may wake up t for the SIGCHILD, and then once
          * more for the exit. */
      }

      if (t != current && (tstate == TASK_INTERRUPTIBLE)) {
         D__;
         /*
          * Tell t that it should wake up and prepare for running
          * on the VCPU. 
          *
          * No need to send an IPI to ourselves, since we're already
          * awake -- we must be awake for us to be calling this function.
          */
         SchedSendIPI(t);
      } else if (tstate == TASK_STOPPED || tstate & TASK_WAITQUEUE) {
         SchedContinue(t, isAlreadyActive);
      }
   }

   D__;

   ASSERT_RUNQUEUE_LOCKED(t);
}

void
Sched_WakeUpProcess(struct Task *t)
{
   ACQUIRE_RUNQUEUE_LOCK(t);

   SchedTryToWakeUp(t, TASK_STOPPED | TASK_INTERRUPTIBLE | 
         TASK_UNINTERRUPTIBLE | TASK_WAITQUEUE);

   RELEASE_RUNQUEUE_LOCK(t);
}

void
Sched_WakeUpState(struct Task *t, uint state)
{
   ACQUIRE_RUNQUEUE_LOCK(t);

   D__;

   SchedTryToWakeUp(t, state);

   RELEASE_RUNQUEUE_LOCK(t);
}

/*
 * Wakes everybody in the given waitqueue.
 */
void
Sched_WakeupSync(struct WaitQueueHead *q, uint mode)
{
   struct WaitQueue *curr;

   /* XXX: do we really need to acquire this lock? 
    * think about multi-VCPU races... */
   SYNCH_LOCK(&q->lock);
   list_for_each_entry(curr, &q->taskList, taskList) {
      struct Task *tsk = curr->priv;

      ASSERT(tsk);

      ACQUIRE_RUNQUEUE_LOCK(tsk);

      SchedTryToWakeUp(tsk, mode);

      RELEASE_RUNQUEUE_LOCK(tsk);
   }
   SYNCH_UNLOCK(&q->lock);
}


/*
 * During logging, make the syscall and wait for our turn on
 * the VCPU. Returns values returned by syscall.
 *
 * During replay, just wait for our turn. Returns -1.
 */
static INLINE long
SchedWaitWork(BlockFn fn, void *arg, int waitVal)
{
   long err = -1;
   long futex_res = -EWOULDBLOCK;
   struct SynchCond *pcv = &current->schedCond;
   volatile uint* futex = &pcv->wakeup_seq;
   int state = Task_GetCurrentState();

   DEBUG_MSG(8, "waitVal=%d\n", waitVal);
   ASSERT_COULDBE(arg == NULL);

   /* @current should've given up its VCPU lock. */
   //ASSERT(!VCPU_IsLockOwner(curr_vcpu));

#if DEBUG
   ASSERT(state != TASK_DEAD);
   if (!(state & (TASK_WAITQUEUE | TASK_STOPPED | TASK_RUNNING))) {
      ASSERT(state == TASK_INTERRUPTIBLE);
   }
#endif

   if (state == TASK_INTERRUPTIBLE && !VCPU_IsReplaying()) {
      ASSERT(arg);
      if (!fn) {
         err = Signal_BlockingRealSyscall((struct SyscallArgs*)arg);
      } else {
         sigset_t mask, orig;
         SigOps_InitSet(&mask, ~0);
         SigOps_SetMask(&mask, &orig);
         if (Task_TestFlag(current, TIF_INTR_PENDING)) {
            err = -EINTR;
         } else {
#if PRODUCT
#error "XXX"
            // XXX: major bug -- we may get IPI/signal before @fn makes
            // the syscall -- and we will hang
#else
            err = fn(arg);
#endif
         }
         Task_ClearCurrentFlag(TIF_IO_PENDING);
         SigOps_SetMask(&orig, NULL);
      }

      /* Note that we don't acquire the runqueue lock
       * here before reading the run queue head. Even though
       * this is a race, that's okay...this code is invoked
       * only during logging and doesn't need to be replayed. 
       * That's because during replay we don't block in
       * Linux syscalls -- we obtain their results from the log. */
      struct Task *head = SchedGetRunHeadUnlocked(current);
      if (head && head != current) {
         SchedSendIPI(head);
      }
   }


   /* Wait in the kernel until the value has changed (or there may be 
    * no waiting if the value has already changed, which is possible
    * if someone cond_signalled us before we got here, or if this
    * task cond_signalled itself). */

   if (*futex == waitVal) {
      do {
         futex_res = Synch_FutexWait(futex, waitVal);
         /* We may be interrupted by SIG_RESERVED_SERVER or a signal
          * from GDB. */
      } while (futex_res == -EINTR);
   }
   DEBUG_MSG(8, "futex_res=%d\n", futex_res);
   /* Either we never had to wait, or we waited and were woken. */
   ASSERT(-EWOULDBLOCK == -EAGAIN);
   ASSERT(futex_res == -EWOULDBLOCK || futex_res == 0);

   VCPU_Lock(curr_vcpu);

   /* Whoever signalled us should've incremented wakeup_seq. */
   ASSERT(pcv->wakeup_seq == pcv->total_seq);

   /* One more process woken up. 
    * XXX: not necessary so far as I can tell */
   pcv->woken_seq++;

   ASSERT(VCPU_IsLocked(curr_vcpu));
   ASSERT(SchedIsRunHead(current));

   return err;
}

static void
SchedWakeOneBlocked()
{
   struct Task *tsk;

   ASSERT_RUNQUEUE_LOCKED(current);

   /* XXX: for now, always pick a waiting task first,
    * but this may starve CPU intensive tasks... */
   tsk = SchedGetBlockHead();

   //SchedPrintBlockQueue();

   if (tsk) {
      DEBUG_MSG(5, "Snooze activate: %d.0x%x\n", tsk->id, tsk);
      ASSERT(tsk != current);

      /* XXX: check that next is in interruptible state */
      SchedTryToWakeUp(tsk, TASK_INTERRUPTIBLE);
   }

   //SchedPrintBlockQueue();
}

static void
SchedWakeAllReady()
{
   struct Task *tsk, *tmp;
   struct VCPU *vcpu = curr_vcpu;

   ASSERT_RUNQUEUE_LOCKED(current);

   /* We need safe-againt-deletion traversal since SchedActivate
    * will remove @tsk from the the block list. */
   list_for_each_entry_safe(tsk, tmp, &vcpu->blockq.list, blockList) {
      ASSERT(tsk != current);
      ASSERT(RUNQ(current) == RUNQ(tsk));
      ASSERT_RUNQUEUE_LOCKED(tsk);

      int isIoReady;

      DEBUG_MSG(5, "Snooze activate: %d.0x%x\n", tsk->id, tsk);

      if (!VCPU_IsReplaying()) {
         /* Before a task puts itself to sleep waiting for IO, it
          * sets it TIF_IO_PENDING flag. When it's done blocking
          * (perhaps becase there is data avaialable), it clears the 
          * TIF_IO_PENDING flag. Ofcourse, the moment at which
          * it stops blocking and sets TIF_IO_PENDING is non-deterministic.
          * And if we were to read that flag here, that read would
          * be a racing read. Hence, if we read TIF_IO_PENDING, then 
          * we must log it to ensure determinism. */
         isIoReady = !Task_TestFlag(tsk, TIF_IO_PENDING);

         if (VCPU_IsLogging()) {
            DO_WITH_LOG_ENTRY(JustRetval) {
               entryp->ret = isIoReady;
            } END_WITH_LOG_ENTRY(0);
         }
      } else {
         DO_WITH_LOG_ENTRY(JustRetval) {
            isIoReady = entryp->ret;
         } END_WITH_LOG_ENTRY(0);
      }

      if (isIoReady) {
         /* XXX: check that next is in interruptible state */
         SchedTryToWakeUp(tsk, TASK_INTERRUPTIBLE);
      } else {
         DEBUG_MSG(5, "Not ready.\n");
      }
   }
}

static struct Task *
SchedChooseNext()
{
   struct Task *next;
   int state = Task_GetCurrentState();

   ASSERT_RUNQUEUE_LOCKED(current);

   /* No waiting task, so the first guy on runqueue. */
   next = SchedGetRunHead(current);
   ASSERT(next || !next);

   /* Nobody else in the runqueue. Just
    * schedule @current again unless its is dead or stopped (kinda dead),
    * in which case it's waiting for someone else to wake it. 
    */
   if (!next && !Task_IsDescheduled(state)) {
      DEBUG_MSG(5, "No one else in runqueue, picking self.\n");
      next = current;
   }

   if (1) {
      /* If we die without designating the idle task, then there won't be
       * anyone to wake up io-blocked tasks. Of course, if there are
       * no io-blocked tasks at this point, then there are no remaining
       * tasks on the VCPU. We'll just have to live with that until
       * another VCPU schedules a task in. */
      if (!next) {
         ASSERT(Task_IsDescheduled(state));
         SchedWakeOneBlocked();
         next = SchedGetRunHead(current);
         ASSERT(next || !next);
      }
   }

   return next;
}

static void
SchedReschedCurrent(struct Task *next)
{
   int state = Task_GetCurrentState();

   ASSERT_RUNQUEUE_LOCKED(current);

   /* next == current clause: invariant -- anybody we schedule must
    * be put on the runqueue first, event if they are in interruptibe
    * state. Runqueue ordering ensures scheduling determinism. */
   if (next == current || state == TASK_RUNNING) {
      ASSERT(!Task_IsDescheduled(state));
      ASSERT((state & TASK_INTERRUPTIBLE) ||
             !(state & TASK_INTERRUPTIBLE));

      /* XXX: should not be in blocked queue. */
      SchedActivateTask(current);
   } else if (state == TASK_INTERRUPTIBLE &&
              !(state & TASK_WAITQUEUE)) {
      DEBUG_MSG(5, "Snoozing current.\n");
      SchedSnoozeTask(current);
      SchedPrintBlockQueue();
   } else {
      ASSERT(next || !next);
      ASSERT(next != current);
      ASSERT(state == TASK_DEAD ||
            /* Anyone can wake us by sending us a signal. */
            state == TASK_STOPPED ||
            /* Already in the waitqueue. So others know where
             * to look if they want to wake @current. */
            state & TASK_WAITQUEUE);
   }
}

static void
SchedDie()
{
   /* Now we are running concurrently with others in our
    * runqueue. So take care not to touch shared state. */

   /* No need to close or unmap any VCPU logs. They will 
    * be closed and unmapped when Linux frees the address 
    * space after we call sys_exit(). */

   DEBUG_MSG(5, "Terminating since in TASK_DEAD state.\n");

   /* Don't want a signal after we've given up our lock --
    * the parent will release our task struct and there won't
    * be a signal stack to deliver the signal on! */

   ASSERT(current->realPid == gettid());

   /* Say g'nite... */
   Exit_Die();

   NOTREACHED();
}


SyscallRet
Sched_BlockingRealSyscall(BlockFn fn, void *arg)
{
   int res = 0;
   int state = Task_GetCurrentState();
   struct Task *next;
   int waitVal;

   DEBUG_MSG(5, "current->state=0x%x (%d)\n", state, state);

   ASSERT_COULDBE(arg == NULL);
   ASSERT(VCPU_IsLocked(curr_vcpu));
   /* Must have one of these flags set. */ 
   ASSERT(Task_IsStateValid(state));
   ASSERT(SchedIsRunHead(current));

   /* The queue lock is intended to protect both the run and block
    * queue. Remote VCPUs may touch both (e.g., via SchedActivate)
    * when waking a task on current VCPU. */
   ACQUIRE_RUNQUEUE_LOCK(current);

   SchedDeactivateCurrent();

   SchedWakeAllReady();

   next = SchedChooseNext();
   ASSERT(next || !next);

   SchedReschedCurrent(next);

   SchedPrintRunQueue();

   RELEASE_RUNQUEUE_LOCK(current);

   DEBUG_MSG(5, "Switching to next=%d.0x%x (current=%d.0x%x)\n", 
         next ? next->id : 0, next, current->id, current);

   waitVal = SchedCondListen(current);


   if (next) {
      ASSERT(next == current || next != current);
      ASSERT(Task_GetVCPU(next) == Task_GetVCPU(current));

      SchedCondSignal(next);
      if (Task_IsDescheduled(state)) {
         ASSERT(next != current);
      }
   } else {
      ASSERT(Task_IsDescheduled(state));
      VCPU_Deactivate(curr_vcpu);
   }

   /* Relinquish VCPU control so that other tasks in this
    * VCPU can run. */
   VCPU_Unlock(curr_vcpu);

   if (state == TASK_DEAD) {
       if (current == childReaperTask) {
           extern void System_Shutdown();
           System_Shutdown();
       } else {
           SchedDie();
       }
   } else {
      res = SchedWaitWork(fn, arg, waitVal);
   }

   ASSERT(VCPU_IsLocked(curr_vcpu));


   Signal_ProcessQueuedSignals();

   Task_SetCurrentState(TASK_RUNNING);
   ASSERT(SchedIsRunHead(current));

   DEBUG_MSG(5, "And we're back: res=0x%x (%d) current=0x%x\n", 
         res, res, current);

   return res;
}

int
Sched_ScheduleTimeout(struct timespec *tsp)
{
   int err;
   struct SyscallArgs args;
   sigset_t unblockSet;

   ASSERT(tsp || !tsp);

   /* Linux sys_rt_sigtimedwait will unblock all bits set
    * in this set. But we don't want to unblock any signals,
    * we want to use the signal set enabled by 
    * Signal_BlockingSyscall(). */
   SigOps_InitSet(&unblockSet, 0);

   args.eax = SYS_rt_sigtimedwait;
   args.ebx = (ulong) &unblockSet;
   args.ecx = 0 /* siginfo_t *uinfo */;
   args.edx = (ulong) tsp;
   args.esi = sizeof(sigset_t);

   Task_SetCurrentState(TASK_INTERRUPTIBLE);
   err = Sched_BlockingRealSyscall(NULL, &args);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(JustRetval) {
         entryp->ret = err;
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   ASSERT(err == -EAGAIN || err == -EINTR);

   return (err == -EINTR);
}

void
Sched_Schedule()
{
#if DEBUG
   int state = Task_GetCurrentState();

   /* Can't pass in regs here since we need to know the futex
    * value to wait on. So we pass in null args, to indicate that
    * we want to wait on a futex with the appropriate arg. */

   DEBUG_MSG(5, "current->state=0x%x (%d)\n", state, state);
#endif

   Sched_BlockingRealSyscall(NULL, NULL);
}



/*
 * This should be called by the newly created task after it's done
 * with initializing itself.
 * 
 * XXX: move the synchronization body into synchops, but
 * without duplicating code.
 *
 * XXX: rename to ScheduleNewTask
 */
void
Sched_ScheduleFirstTime()
{
   int waitVal = 0;
#if DEBUG
   struct Task *t = current;
   /*
    * We should be in the run-queue; otherwise, no one will
    * know to wake us up from the following futex call.
    */
   ASSERT(Task_GetCurrentState() == TASK_RUNNING);
   ASSERT(SchedIsActive(t));

   DEBUG_MSG(5, "Scheduling for the first time.\n");
#endif

   SchedWaitWork(NULL, NULL, waitVal);

   ASSERT(VCPU_IsLocked(t->vcpu));

   DEBUG_MSG(5, "We've been scheduled: current=0x%x\n", t);
}

/* Assign t to a suitable runqueue. */
void
Sched_Fork(struct Task *t)
{
   int vcpu_id;

   /* Simple modulo assignment. */
   ASSERT_TASKLIST_LOCKED();

   ASSERT(totalClones > 0);
   vcpu_id = (totalClones - 1) % NR_VCPU;
   ASSERT(vcpu_id >= 0 && vcpu_id < NR_VCPU);

   DEBUG_MSG(5, "scheduling on VCPU %d (totalClones=%d)\n", 
         vcpu_id, totalClones);
   t->vcpu = VCPU_Ptr(vcpu_id);

   List_Init(&t->blockList);
   List_Init(&t->runList);
}

#if 0
static int get_user_cpu_mask(unsigned long __user *user_mask_ptr, unsigned len,
			     cpumask_t *new_mask)
{
	if (len < sizeof(cpumask_t)) {
		memset(new_mask, 0, sizeof(cpumask_t));
	} else if (len > sizeof(cpumask_t)) {
		len = sizeof(cpumask_t);
	}
	return Task_CopyFromUser(new_mask, user_mask_ptr, len) ? -EFAULT : 0;
}
#endif

/**
 * sys_sched_setaffinity - set the cpu affinity of a process
 * @pid: pid of the process
 * @len: length in bytes of the bitmask pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to the new cpu mask
 */
SYSCALLDEF(sys_sched_setaffinity, pid_t pid, unsigned int len,
				      unsigned long __user *user_mask_ptr)
{
#if 0
	cpumask_t new_mask;
	int retval;

	retval = get_user_cpu_mask(user_mask_ptr, len, &new_mask);
	if (retval)
		return retval;

   if (!VCPU_IsReplaying()) {
      retval = syscall(SYS_sched_setaffinity, pid, len, &new_mask);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = retval;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         retval = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return retval;
#else
   /* Don't call through -- we want the task to stay on the VCPU's
    * CPU in order to ensure CPUID determinism. */
   return 0;
#endif
}

/**
 * sys_sched_getaffinity - get the cpu affinity of a process
 * @pid: pid of the process
 * @len: length in bytes of the bitmask pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to hold the current cpu mask
 */
SYSCALLDEF(sys_sched_getaffinity, pid_t pid, unsigned int len,
				      unsigned long __user *user_mask_ptr)
{
	int ret;
	cpumask_t mask;

	if (len < sizeof(cpumask_t)) {
		return -EINVAL;
   }

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_sched_getaffinity, pid, len, &mask);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_sched_getaffinity) {
            entryp->ret = ret;
            entryp->mask = mask;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_sched_getaffinity) {
         ret = entryp->ret;
         mask = entryp->mask;
      } END_WITH_LOG_ENTRY(0);
   }

   if (ret < 0) {
      return ret;
   }

   if (Task_CopyToUser(user_mask_ptr, &mask, sizeof(cpumask_t))) {
      return -EFAULT;
   }

   return sizeof(cpumask_t);
}


long
sys_sched_yield(void)
{
   Sched_Schedule();
   return 0;
}

long
sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
{
   int ret;
   struct sched_param kparam;

   if (Task_CopyFromUser(&kparam, param, sizeof(*param))) {
      return -EFAULT;
   }

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_sched_setscheduler, pid, policy, &kparam);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

long
sys_sched_getscheduler(pid_t pid)
{
   int ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_sched_getscheduler, pid);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

long 
sys_sched_setparam(pid_t pid, struct sched_param __user *param)
{
	struct sched_param kparam;
	int retval;

	if (!param || pid < 0)
		return -EINVAL;
	if (Task_CopyFromUser(&kparam, param, sizeof(struct sched_param)))
		return -EFAULT;

   if (!VCPU_IsReplaying()) {
      retval = syscall(SYS_sched_setparam, pid, &kparam);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = retval;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         retval = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return retval;
}

long 
sys_sched_getparam(pid_t pid, struct sched_param __user *param)
{
	struct sched_param kparam;
	int retval = -EINVAL;

	if (!param || pid < 0)
      goto out;

   if (!VCPU_IsReplaying()) {
      retval = syscall(SYS_sched_getparam, pid, &kparam);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_sched_getparam) {
            entryp->ret = retval;
            entryp->param = kparam;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_sched_getparam) {
         retval = entryp->ret;
         kparam = entryp->param;
      } END_WITH_LOG_ENTRY(0);
   }

	/*
	 * This one might sleep, we cannot do it with a spinlock held ...
	 */
	retval = Task_CopyToUser(param, &kparam, sizeof(*param)) ? -EFAULT : 0;

out:
	return retval;
}

long
sys_sched_get_priority_max(int policy)
{
   long ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_sched_get_priority_max, policy);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

long
sys_sched_get_priority_min(int policy)
{
   long ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_sched_get_priority_min, policy);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

long
sys_sched_rr_get_interval(pid_t pid, struct timespec __user * interval)
{
	int retval;
   struct timespec kinterval;

   if (!VCPU_IsReplaying()) {
      retval = syscall(SYS_sched_rr_get_interval, pid, &kinterval);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_sched_rr_get_interval) {
            entryp->ret = retval;
            entryp->interval = kinterval;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_sched_rr_get_interval) {
         retval = entryp->ret;
         kinterval = entryp->interval;
      } END_WITH_LOG_ENTRY(0);
   }

	/*
	 * This one might sleep, we cannot do it with a spinlock held ...
	 */
	retval = Task_CopyToUser(interval, &kinterval, sizeof(kinterval)) ? -EFAULT : 0;

	return retval;
}
