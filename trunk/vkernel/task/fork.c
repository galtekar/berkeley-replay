/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/mman.h>

#include "private.h"

#include "vkernel/public.h"
#include "libcommon/public.h"

/* Used to serialize access to the exit stack. 
 * XXX: one day, this may become a bottleneck. */
volatile int exitLock = RW_LOCK_INIT;

/* This should NOT be in the SHAREDAREA, since the startup task
 * uses this task struct to set up the SHAREDAREA. */
ALIGN(TASK_SIZE) struct Task startupTask;

SHAREDAREA DECLARE_ORDERED_LOCK(taskListLock);

/* Big kernel lock. Used to protect various data. Should be avoided. */
SHAREDAREA DECLARE_ORDERED_LOCK(bkLock);

/* Used to emulate the hardware bus lock that is acquired by
 * hardware synchronization primitives (e.g., CAS, XCHG, TAS, etc..) */
SHAREDAREA DECLARE_ORDERED_LOCK(busLock);

/* Monotonic counter. Starts at 1 to account for first task. */
SHAREDAREA ulong        totalClones = 1; 

/* XXX: Does the child reaper ever change? If not, then
 * this pointer doesn't have to be in the shared area. */
SHAREDAREA struct Task  *childReaperTask = &initTask;

SHAREDAREA int nr_threads = 1; /* 1 for init */

/*
 * Access another tasks's state. Since the other
 * task may change state without locking, this routine
 * logs the t->state, hence ensuring deterministic replay. */
int
Task_GetState(struct Task *t)
{
   int val;

   /* If you want current's state, use
    * Task_GetCurrentState(). */
   if (t == current) {
      return Task_GetCurrentState(t);
   }

   if (!VCPU_IsReplaying()) {
      val = t->state;

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = val;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         val = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return val;
}

static void 
TaskPut(struct Task* tsk) 
{
   ASSERT(tsk != current);
   ASSERT(tsk->exitState & (EXIT_DEAD | EXIT_ZOMBIE));
   ASSERT(!atomic_read(&tsk->count));

   /* Check that auxiliary task state has been released
    * or at least put()ed. */
   ASSERT(tsk->mm || !tsk->mm);
   ASSERT(!Task_GetRegs(tsk)->guest_GDT);
   ASSERT(!tsk->files);
   ASSERT(!tsk->fs);
   ASSERT(!tsk->perfctr);
   ASSERT(!tsk->signal);
   ASSERT(!tsk->sigHand);

   SharedArea_Free(tsk, sizeof(*tsk));      

   DEBUG_MSG(5, "Deallocated task struct: current->realPid=%d\n",
         current->realPid);
}

void REGPARM(1)
Task_Put(struct Task* tsk)
{
   /* May be invoked by self to decrement ref count, but
    * shouldn't be invoked to deallocate. */
   ASSERT(tsk == current || tsk != current);

   /* May or may not be called from the exit stack. 
    * Parent may call it on child. */
   ASSERT(current == &startupTask || current != &startupTask);

   DEBUG_MSG(5, "current->realPid=%d current->id=%d gettid()=%d\n",
         current->realPid, current->id, gettid());


   if (atomic_dec_and_test(&tsk->count)) {
      /* Shouldn't be using the task (stack) we are about
       * to deallocate. */
      ASSERT(tsk != current);

      /* This can't be in ExitTaskRelease, since that would create
       * a race in which the parent would free the segevent
       * info, even though the task has yet to dequeue itself
       * from the runqueue (via a an ordered lock). 
       *
       * SegEvent_Exit(tsk);
       *
       */
      TaskPut(tsk);
      tsk = NULL;
   }
}


static int
TaskCopySigHand(ulong cloneFlags, struct Task *tsk)
{
   /*
    * AVOIDED RACE: Another task in the group may exit
    * and concurrently decrement the count and deallocate
    * current->sigHand.
    */
   ASSERT_TASKLIST_LOCKED();
   ASSERT_SIGLOCK_LOCKED(current);

   if (cloneFlags & (CLONE_SIGHAND | CLONE_THREAD)) {
      ASSERT(current->sigHand);
      tsk->sigHand = current->sigHand;
      tsk->sigHand->count++;
   } else {
      tsk->sigHand = (struct SigHand*) 
         SharedArea_Malloc(sizeof(*(tsk->sigHand)));
      ASSERT_UNIMPLEMENTED(tsk->sigHand);
      tsk->sigHand->count = 1;
      ORDERED_LOCK_INIT(&tsk->sigHand->sigLock, "signal");
      /*
       * AVOIDED RACE: Another sighand-sharing task may change the sigaction.
       */
      ASSERT_SIGLOCK_LOCKED(current);

      /* Child inherits copies of the sigaction. */
      memcpy(tsk->sigHand->action, current->sigHand->action, 
            sizeof(tsk->sigHand->action));

   }
   DEBUG_MSG(5, "current->sighand=0x%x tsk->sighand=0x%x\n",
         current->sigHand, tsk->sigHand);

   return 0;
}

static INLINE void
TaskInitSigPending(struct SigPending *sig)
{
   sigemptyset(&sig->signal);
   List_Init(&sig->list);
}

static int
TaskCopySignal(ulong cloneFlags, struct Task *tsk)
{
   /*
    * AVOIDED RACE: Another task in the group may die concurrently
    * and decrement count and deallocate current->signal
    * (see ExitSignal for more info).
    */
   ASSERT_TASKLIST_LOCKED();
   ASSERT_SIGLOCK_LOCKED(current);

   if (cloneFlags & CLONE_THREAD) {
      current->signal->count++;
   } else {
      struct Signal *sig;
      sig = (struct Signal*) SharedArea_Malloc(sizeof(*sig));
      ASSERT_UNIMPLEMENTED(sig);
      tsk->signal = sig;
      
      sig->count = 1;
      WaitQueue_InitHead(&sig->waitChildExitQueue);
      sig->flags = 0;
      sig->groupExitCode = 0;
      sig->groupStopCount = 0;
      sig->groupExitTask = NULL;
      TaskInitSigPending(&sig->sharedPending);

#if 0
      sig->leader = 0; /* session leadership doesn't inherit */
#endif
   }

   return 0;
}


static void
TaskSetupStack(struct Task* ts, struct CloneArgs *cloneArgs)
{
   TaskRegs *regs = Task_GetRegs(ts);

   Task_WriteReg(regs, eax, 0); /* child must return 0 */

   /*
    * sys_clone ensures that cloneArgs->stack contains
    * the user-mode esp at the time of the
    * fork/clone. 
    */
   Task_WriteReg(regs, esp, (ulong)cloneArgs->stack);
}

static struct Task* 
TaskDupTaskStruct(struct CloneArgs *cloneArgs)
{
   struct Task* ts;
   size_t size;

   size = sizeof(struct Task);

   D__;
   /* We use memalign so that the task struct can be obtained
    * from the task stack by masking the current stack address. */
	ts = (struct Task*) SharedArea_Memalign(TASK_SIZE, size);
	ASSERT_UNIMPLEMENTED(ts);
   ASSERT((ulong)ts % TASK_SIZE == 0);

   DEBUG_MSG(5, "ts=0x%x\n", ts);

   memcpy(ts, current, sizeof(*current));

   D__;
   ASSERT(cloneArgs);
   ts->cloneArgs = *cloneArgs;
   ts->cloneFutex = 0;

   /* One so that ts can do a Task_Put and the other for the waiter
    * (usually the parent). */
   atomic_set(&ts->count, 2);

   TaskSetupStack(ts, cloneArgs);

   DEBUG_MSG(3, "Task struct duplicate @ 0x%x:\n"
         "   flags=0x%x stack=0x%x ptid=0x%x tls=0x%x ctid=0x%x\n"
         , ts, 
         ts->cloneArgs.flags, 
         ts->cloneArgs.stack,
			ts->cloneArgs.ptid,
			ts->cloneArgs.tlsDesc,
			ts->cloneArgs.ctid);
   Debug_PrintTaskRegs(Task_GetRegs(ts));

   return ts;
}

SYSCALLDEF(sys_set_tid_address, int __user *tidptr)
{
   current->clearChildTID = tidptr;

   return current->pid;
}

static int
TaskCopyThread(struct Task *p, struct CloneArgs *cloneArgs)
{
   int err = 0;
   int cloneFlags = cloneArgs->flags;

   if (cloneFlags & CLONE_SETTLS) {
      /* XXX: we need to vet cloneArgs->tlsDesc here and
       * perform the clone only if we are sure the desc
       * is valid -- otherwise we won't know what to do when
       * the Linuxcall fails in Task_Start. */

      ASSERT_UNIMPLEMENTED(cloneArgs->tlsDescp);
      Task_InstallDescInGDT(p, &cloneArgs->tlsDesc);
   }

   return err;
}

/*
 * We assume that the child has already been created and is
 * awaiting notification. That means that we can't return
 * error codes here -- or we can, but cleaning up would be
 * messy so we avoid it. 
 */
static int
TaskCopyProcess(struct Task *p, struct CloneArgs *cloneArgs)
{
   int retval = 0;
   int cloneFlags = cloneArgs->flags;

   ASSERT_TASKLIST_LOCKED();

   /* 
    * The thread's ctid, though set here, may change via future
    * calls to set_tid_address syscall. 
    */
	p->setChildTID = (cloneFlags & CLONE_CHILD_SETTID) ? 
      cloneArgs->ctid : NULL;
   p->clearChildTID = (cloneFlags & CLONE_CHILD_CLEARTID) ? 
      cloneArgs->ctid : NULL;

   ASSERT(p->pid > 1); /* should be initialized */
   ASSERT(p->pid != current->pid);

   if (cloneFlags & CLONE_PARENT_SETTID) {
      ASSERT_UNIMPLEMENTED(cloneArgs->ptid);
      D__;
      ASSERT(p->pid);
      if (__put_user(p->pid, cloneArgs->ptid)) {
         ASSERT_UNIMPLEMENTED(0);
      }
   }

   /*
	 * sigaltstack should be cleared when sharing the same VM
	 */
	if ((cloneFlags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM) {
		p->sas_ss_sp = p->sas_ss_size = 0;
   }

   /* ok, now we should be set up.. */
	p->exitSignal = (cloneFlags & CLONE_THREAD) ? -1 : 
                   (cloneFlags & CSIGNAL);
   p->pdeathSignal = 0; /* can be set with sys_prctl */
	p->exitState = 0;

   totalClones++;
   p->id = totalClones;

   DEBUG_MSG(5, "p->id=%d p->pid=%d\n", p->id, p->pid);
   ASSERT(p->id > 1);

   Pid_Alloc(p->pid);

   p->tgid = p->pid;
   if (cloneArgs->flags & CLONE_THREAD) {
      p->tgid = current->tgid;
   }

   /* Copy all process information. */
   Files_Fork(cloneFlags, p);
   FileSys_Fork(cloneFlags, p);

   /*
    * Don't hold the siglock and try to acquire some other
    * lock (e.g., a file lock in the case of Files_Fork().
    * Will lead to deadlock, since another thread may hold
    * the file lock and try to acquire the siglock, for
    * example to read sigpending.
    */
   ACQUIRE_SIGLOCK(current);

   TaskCopySigHand(cloneFlags, p);
   TaskCopySignal(cloneFlags, p);

   if (cloneArgs->flags & (CLONE_PARENT | CLONE_THREAD)) {
      p->realParent = current->realParent;
   } else {
      p->realParent = current;
   }
   p->parent = p->realParent;

   p->groupLeader = p;
   List_Init(&p->threadGroup);
   List_Init(&p->children);
   List_Init(&p->sibling);
   
   List_Init(&p->sigq);

   Task_ClearSigPending(p, 0);
   TaskInitSigPending(&p->pending);


   if (cloneArgs->flags & CLONE_THREAD) {
      /* current and p should share the same signal lock. */
      ASSERT_SIGLOCK_LOCKED(current);
      ASSERT_SIGLOCK_LOCKED(p);
      p->groupLeader = current->groupLeader;

      List_AddTail(&p->threadGroup, &p->groupLeader->threadGroup);
   }

   D__;
   Task_AddParent(p);


   if (Task_IsThreadGroupLeader(p)) {
      ASSERT(!(cloneFlags & CLONE_THREAD));
      p->signal->pgrp = current->signal->pgrp;

      D__;
      Pid_Attach(p, PIDTYPE_PGID, Task_ProcessGroup(p));
      D__;
   }
   List_AddTail(&p->tasks, &initTask.tasks);

   Pid_Attach(p, PIDTYPE_PID, p->pid);
   nr_threads++;

   D__;

   RELEASE_SIGLOCK(current);


   Sched_Fork(p);
   Mem_Fork(p);
   BT_Fork(p);
   Module_Fork(p);
   BrCnt_Fork(p);
   VCPU_Fork(p);

   retval = TaskCopyThread(p, cloneArgs);
   ASSERT(!retval);

   return 0;
}

static int
TaskDoFork(struct Task *p, struct CloneArgs *cloneArgs)
{
   int err;

   ASSERT(cloneArgs);

   err = TaskCopyProcess(p, cloneArgs);
   if (err) {
      goto out;
   }

   if ((p->ptrace & PT_PTRACED) || (cloneArgs->flags & CLONE_STOPPED)) {
      ASSERT_UNIMPLEMENTED(0);
   }

   if (!(cloneArgs->flags & CLONE_STOPPED)) {
      Sched_WakeNewTask(p);
   } else {
      p->state = TASK_STOPPED;
      ASSERT_UNIMPLEMENTED(0);
   }

   if (cloneArgs->flags & CLONE_VFORK) {
      ASSERT_UNIMPLEMENTED(0);
   }

out:
   return err;
}

/*
 * The goal is to ensure that the clone parameters and conditions
 * are such that a call to Linux's sys_clone is guaranteed to succeed.
 */
static int
TaskVetClone(struct CloneArgs *cloneArgs)
{
   int err = 0, cloneFlags = cloneArgs->flags;

   if ((cloneFlags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS)) {
      /* XXX: should return with error code ... */
      ASSERT_UNIMPLEMENTED(0);
   }

   /*
    * Thread groups must share signals as well, and detached threads
    * can only be started up within the thread group.
    */
   if ((cloneFlags & CLONE_THREAD) && !(cloneFlags & CLONE_SIGHAND)) {
      ASSERT_UNIMPLEMENTED(0);
   }

   /*
    * Shared signal handlers imply shared VM. By way of the above,
    * thread groups also imply shared VM. Blocking this case allows
    * for various simplifications in other code.
    */
   if ((cloneFlags & CLONE_SIGHAND) && !(cloneFlags & CLONE_VM)) {
      ASSERT_UNIMPLEMENTED(0);
   }

   /*
    * Process group and session signals need to be delivered to just the
    * parent before the fork or both the parent and the child after the
	 * fork. Restart if a signal comes in before we add the new process to
	 * it's process group.
	 * A fatal signal pending means that current will exit, so the new
	 * thread can't slip out of an OOM kill (or normal SIGKILL).
 	 */
   ACQUIRE_SIGLOCK(current); 

   Signal_RecalcSigPending(current);
   if (Task_TestSigPending(current, 0)) {
      /* Restart the sys_clone -- signal handled or not. */
      err = -ERESTARTNOINTR;
      goto out;
   }

out:
   RELEASE_SIGLOCK(current);
   return err;
}


/*
 * Must call Linux's sys_clone first and then init the task struct.
 * That's because the task init routines need to know the pid of
 * the task. We could assign them ourselves, but that would break
 * Linux integration. So we use the kernel assigned pid. 
 *
 * Given this requirement, we must vet the clone args and return
 * error codes before creating the child. Otherwise, we would
 * have to destroy the child and I can't think of a clean way to
 * do that.
 *
 */
ulong 
Task_Clone(struct CloneArgs *cloneArgs, struct SyscallArgs *args)
{
   struct Task *tsk;
   struct SyscallArgs cloneRegs;
   int err, cloneFlags = cloneArgs->flags;

   Debug_PrintCloneArgs(cloneArgs);

   /* to protect signal/sighand counts and allocs */
   ACQUIRE_TASKLISTLOCK(); 

   err = TaskVetClone(cloneArgs);
   if (err) {
      goto out;
   }
   
   tsk = TaskDupTaskStruct(cloneArgs);

   /* Now modify the clone arguments to suit our tastes. */
   ASSERT(args->eax == SYS_clone || args->eax == SYS_fork ||
          args->eax == SYS_vfork);
   /* SYS_clone is more powerful than SYS_fork. It lets us set the
    * child_cleartid pointers and the starting stack pointer, to name
    * a few benefits. */
   cloneRegs.eax = SYS_clone;
   cloneRegs.ebx = cloneArgs->flags;

   /* We must emulate all these flags since Linux will place the real
    * Linux pid at the corresponding locations and that may result in
    * divergence during replay. */
   cloneRegs.ebx &= ~(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | 
                      CLONE_PARENT_SETTID);
   /* NOTE THAT: CLONE_THREAD --> CLONE_SIGHAND --> CLONE_VM. 
    *
    * We want to keep CLONE_THREAD (so that we don't have to emulate
    * thread behaviors such as detached exit), so we must keep CLONE_SIGHAND
    * as well. 
    */
  
   /* We emulate these. */
   cloneRegs.ebx &= ~(CLONE_FS | CLONE_FILES | CLONE_SYSVSEM);

   /* App may or may not want TLS setup for the child. Usually will want
    * it if the child is a pthread thread. */
   ASSERT(cloneRegs.ebx & CLONE_SETTLS || !(cloneRegs.ebx & CLONE_SETTLS));

   /* Allows us to easily close a Linux pipe opened by some other task
    * once all file objects referring to
    * to it have been destroyed. Without this, we would need to have
    * each task close the corresponding descriptor in a distributed
    * fashion -- not pretty. Without this, test 10 will not work
    * as expected. */
   cloneRegs.ebx |= CLONE_FILES;

   /* The child should start execution with esp pointing to
    * its TaskState. This ensures that any subsequent stack pushes
    * will not overwrite the TaskState, since the child will need it
    * to resume user-mode execution. */
   cloneRegs.ecx = (ulong)Task_GetRegs(tsk);

   /* We emulate this. */
   cloneRegs.edx = 0; /* parent_tidptr */

   /* We could have the child install its own task struct segment after it's
    * up and running, but then there would be a small window in which
    * segmentation isn't setup. On the other hand, if we do setup via clone,
    * then we can't install the app's TLS (if it wants one) in the clone
    * call --- and we must do that here, since the segment descriptor
    * may go away after we return from clone. */
   if (cloneFlags & CLONE_SETTLS) {
      cloneRegs.esi = (ulong)&cloneArgs->tlsDesc;
   } else {
      cloneRegs.esi = 0;
   }

   /* We emulate this. */
   cloneRegs.edi = 0; /* child_tidptr */


   tsk->realPid = Task_RealClone(&cloneRegs);
   DEBUG_MSG(5, "tsk->realPid=%d\n", tsk->realPid);
   ASSERT(!SYSERR(tsk->realPid));
   /* Only the parent returns here. The child awaits our go-ahead,
    * which we will give after we intialize it's task struct 
    * (which we can now do given that we know its pid). */
   ASSERT(current != tsk);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(sys_clone) {
         entryp->childPid = tsk->realPid;
      } END_WITH_LOG_ENTRY(0);

      tsk->pid = tsk->realPid;

   } else {
      DO_WITH_LOG_ENTRY(sys_clone) {
         tsk->pid = entryp->childPid;
      } END_WITH_LOG_ENTRY(0);
   }

   err = TaskDoFork(tsk, cloneArgs);
   DEBUG_MSG(5, "id=%d pid=%d realPid=%d\n", tsk->id, tsk->pid, tsk->realPid);
   ASSERT(tsk->id > 1);
   ASSERT(!err);

   err = tsk->pid;

   /* Okay. Signal the newly cloned child that is waiting to be born.
    * Now that we've initialized its pid, it is now free to begin 
    * user-space execution. */
   ASSERT(tsk->cloneFutex == 0);

   /* Condition variables are too weak -- child may not be in wait when
    * we signal it. We use futexes instead. */
   tsk->cloneFutex = 1;
   Synch_FutexWake(&tsk->cloneFutex, 1);

out:
   RELEASE_TASKLISTLOCK();
   /* Return child's replayed pid. */
   return err;
}


/*
 * Task_Start --
 *
 *    Performs initialization that must be done within the task's context
 *    and not the parent's context. For example, here we load the LDT with
 *    the task's TSS--this can't be done by the task's parent. We also setup
 *    the task's signal handler so that it can receive interrupts on
 *    it's own signal stack--again, something that cannot be done from
 *    within the parent's context.
 *
 *    o New task is not actually scheduled yet. So don't try to
 *    acquire any segment locks (those require the cpu lock).
 */
void
Task_Start()
{
   int err;

   ASSERT(current);
   ASSERT(PAGE_ALIGNED((ulong)current));

   /* Wait until parent has finished initializing our task struct,
    * which it can now do since it now knows the child's pid
    * (which it didn't before the clone). This is important --
    * anyone concurrently looking at a task's pid or realPid should get
    * a valid value. */

   /* RACE? What if parent sets cloneFutex after Linux
    * checks it in the futex_wait, but before it does the wait. 
    * This shouldn't be a problem if futex_wake and futex_wait
    * are serialized. They are, so no need to worry... */
   err = Synch_FutexWait(&current->cloneFutex, 0);
   ASSERT(err == -EWOULDBLOCK || err == 0);
   /* The kernel mask is enabled, so no non-crash sigs are permitted. */
   ASSERT(err != -EINTR);


   if (current->id != 1) {
      Task_DebugStart();
   } else {
      /* We already opened it at initialization. */
   }

   Debug_Mark();

   /* We could install the task segment in the clone (with CLONE_SETTLS),
    * but then we won't be able to install the libpthread TLS segment
    * using clone. Hence we install the task segment separately. */
   Task_SetupTLS(current);
   Debug_PrintTask(current);
   Debug_PrintCloneArgs(&current->cloneArgs);
   Debug_PrintTaskRegs(Task_GetCurrentRegs());
   Debug_Mark();

   BrCnt_SelfInit();
   VCPU_SelfInit();

   /* BUG: Isn't there a race here? This thread could get a
    * signal before installing the new stack, in which case
    * the signal handler would run in the parent thread's
    * signal stack.
    *
    * In 2.6.16 and up (possibly earlier), the child thread's
    * signal stack is reset on clone(). So if we do get a
    * signal in this interval, then it will run on the handler
    * stack. So no worries... */
   Signal_SelfInit();

   /* XXX: this should really be done in DoNotifyResume.. */
   if (current->id != 1)  {
      Sched_ScheduleFirstTime();
   } else {
      /* Already has the vcpu lock. */
   }

   /* ====== Now we have the VCPU lock. ====== */
   ASSERT(VCPU_IsLocked(current->vcpu));

   /* Corresponds to Linux's schedule_tail. We can set the child's 
    * tid only within its address space. */
   if (current->setChildTID) {
		/*
		 * We don't check the error code - if userspace has
		 * not set up a proper pointer then tough luck.
		 */
      DEBUG_MSG(5, "setChildTID=0x%x pid=%d\n", current->setChildTID,
            current->pid);
      __put_user((current->pid), current->setChildTID);
   }

   if (current->id == 1) {
      extern void System_StartThread();
      System_StartThread();
   }

   /* Do this after the call to System_StartThread so that current->pid 
    * is initialized for the first task. */
   Module_OnTaskStart();
}

void
Task_Exec()
{
   /* Free up non-vkernel TLS descriptors. */
   
   struct LinuxSegmentDesc info;
   int i, res;

   memset(&info, 0, sizeof(info));
   info.read_exec_only = 1;
   info.seg_not_present = 1;

   for (i = GDT_ENTRY_TLS_MIN; i <= GDT_ENTRY_TLS_MAX; i++) {
      /* Skip the vkernel TLS. */
      if (i == VK_TLS_ENTRY_NR) {
         continue;
      }
      info.entry_number = i;

      res = syscall(SYS_set_thread_area, &info);
      ASSERT(!res);
   }
}

static int
Task_Init()
{
   /* Stack should be the very first element in the 
    * task struct to ensure page alignment. */
   ASSERT(PAGE_ALIGNED((ulong)current));
   ASSERT((void*) current == (void*) current->stack.stack);

   return 0;
}

CORE_INITCALL(Task_Init);
