/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <errno.h>

#include "vkernel/public.h"

#include "private.h"

#define WNOHANG		0x00000001
#define WUNTRACED	   0x00000002
#define WSTOPPED	   WUNTRACED
#define WEXITED		0x00000004
#define WCONTINUED	0x00000008
#define WNOWAIT		0x01000000	/* Don't reap, just poll status.  */
#define __WNOTHREAD	0x20000000	/* Don't wait on children of other threads in this group */
#define __WALL	   	0x40000000	/* Wait on all children, regardless of type */
#define __WCLONE	   0x80000000	/* Wait only on non-SIGCHLD children */

SYSCALLDEF(sys_waitpid, pid_t pid, int __user *stat_addr, int options);

static long 
WaitDo(pid_t pid, int options, struct siginfo __user *infop,
      int __user *stat_addr, struct rusage __user *ru, int on_exit);

static int
ExitGetRUsage(struct Task *p, int who, struct rusage *r)
{
   D__;

   p = p;
   who = who;
   r = r;

   /* 
    * XXX: sys_getrsuage gets only current's rusage.
    *
    * Piece it together for task p using proc, or perhaps
    * have child go a Linux sys_getrusage before it dies
    * and put the result in its task struct -- we can read
    * it before freeing it...
    */
   ASSERT_UNIMPLEMENTED(0);

   return 0;
}

static void 
ExitUnhashProcess(struct Task *p)
{
   ASSERT_TASKLIST_LOCKED();

   nr_threads--;

   DEBUG_MSG(5, "nr_threads=%d\n", nr_threads);
   Pid_Detach(p, PIDTYPE_PID);

   ACQUIRE_SIGLOCK(p);
   /* XXX: Unlike Linux, we have each task detach it self, even if
    * it's not the thread-group leader. This ensures that the
    * global task list is always up to date and we don't deference
    * tasks that have been Task_Put()ed. */
   if (1 || Task_IsThreadGroupLeader(p)) {
      D__;
      Pid_Detach(p, PIDTYPE_PGID);

      List_Del(&p->tasks);
   }
   RELEASE_SIGLOCK(p);

   List_Del(&p->threadGroup);
   Task_RemoveParent(p);
}


static void
ExitSignal(struct Task *tsk)
{
   struct Signal *sig = tsk->signal;
   struct SigHand *sigHand = tsk->sigHand;

#if 0
   /* These are statically allocated and thus shouldn't be
    * freed. Init process shouldn't die anyway ... */
   ASSERT(sig != &initSignals);
   ASSERT(sigHand != &initSigHand);
#endif

   ASSERT(tsk != childReaperTask);

   ASSERT_TASKLIST_LOCKED();

   ExitUnhashProcess(tsk);


   /* sigHand->count is protected by the tasklist_lock,
    * so don't need the siglock (and we shouldn't hold it
    * while we free it!) */
   ASSERT_TASKLIST_LOCKED();
   sigHand->count--;
   sig->count--;

   DEBUG_MSG(5, "current->sighand=0x%x tsk->sighand=0x%x (%d)\n",
         current->sigHand, tsk->sigHand, tsk->sigHand->count);

   if (sigHand->count == 0) {
      ASSERT_KPTR(sigHand);
      ASSERT_MSG(sigHand != initTask.sigHand, 
            "This was statically allocated, so it shouldn't be freed.");
      SharedArea_Free(sigHand, sizeof(*sigHand));
   }

   /* XXX: is this necessary? don't think so... */
   //Task_ClearFlag(tsk, TIF_SIGPENDING);

   /* tsk is unhashed, so no one can send it a signal and thus
    * no need to grab the siglock. */
   Signal_FlushSigQueue(&tsk->pending);
   if (sig->count == 0) {
      Signal_FlushSigQueue(&sig->sharedPending);

      ASSERT_MSG(sig != initTask.signal, 
            "This was statically allocated, so it shouldn't be freed.");
      SharedArea_Free(sig, sizeof(*sig));
   }

   /* Make sure nobody dereferences these. */
   tsk->signal = NULL;
   tsk->sigHand = NULL;
}

/*
 * Called by WaitTaskZombie to release a child's state.
 * In the case that the child is the last member of its
 * thread group but not the leader, and the parent isn't
 * going to clean up after the leader, we have to do it here.
 * 
 */
static void
ExitTaskRelease(struct Task *p)
{
   struct Task *leader;
   int zapLeader;

   DEBUG_MSG(5, "Releasing ID: %d\n", p->id);

   ASSERT(p == current || p != current);
repeat:
   ASSERT_TASKLIST_LOCKED();

   ExitSignal(p);

   zapLeader = 0;
   leader = p->groupLeader;

   /*
    * If we are the last non-leader member of the thread
    * group, and the leader is zombie, then notify the
    * group leader's parent process. (if it wants notification.)
    *
    * We must do this because the zombie leader did not 
    * notify its parent when it died, since at that time
    * non-leader members were still alive. But now, the last
    * non-leader member is dead and so somebody has to tell
    * the parent about it.
    */ 
   if (leader != p && Task_IsThreadGroupEmpty(leader) && 
         leader->exitState == EXIT_ZOMBIE) {
      ASSERT(leader->exitSignal != -1);
      Signal_NotifyParent(leader, leader->exitSignal);

      /*
       * If we were the last child thread and the leader has
       * exited already, and the leader's parent ignores SIGCHLD,
       * then we are the one who should release the leader.
       *
       * do_notify_parent() will have marked it self-reaping in
       * that case.
       */
      zapLeader = (leader->exitSignal == -1);
   }

   /* Give modules a chance to cleanup their address-space private data. 
    * Hence do the Mem_Exit() last. */
   Module_Exit(p);
   BT_Exit(p);
   Mem_Exit(p);

   Task_Put(p);

   p = leader;
   if (unlikely(zapLeader)) {
      goto repeat;
   }
}

static INLINE void
ExitChooseNewParent(struct Task *p, struct Task *reaper)
{
   ASSERT_TASKLIST_LOCKED();

   //ASSERT(!(p == reaper || reaper->exitState));
   p->realParent = reaper;
}

static void
ExitReparentThread(struct Task *p, UNUSED struct Task *father, int traced)
{
   ASSERT_TASKLIST_LOCKED();

   /* We don't want people slaying init by sending it fatal signals
    * upon exiting. */
   if (p->exitSignal != -1) {
      p->exitSignal = SIGCHLD;
   }

   if (p->pdeathSignal) {
      /* Linux allows one to send an arbitrary signal to the parent
       * upon death. */
      ASSERT_UNIMPLEMENTED(0);
   }


   if (traced) {
      ASSERT_UNIMPLEMENTED(0);
   } else {
      p->ptrace = 0;
      Task_RemoveParent(p);
      p->parent = p->realParent;
      Task_AddParent(p);

      if (p->exitState == EXIT_ZOMBIE && p->exitSignal != -1 &&
            Task_IsThreadGroupEmpty(p)) {

         /* Child is a zombie and the original parent didn't clean
          * up after it. So now the new parent should be notified
          * so he can do something about it. */
         Signal_NotifyParent(p, p->exitSignal);

      } else if (Task_GetState(p) == TASK_TRACED) {
         ASSERT_UNIMPLEMENTED(0);
      }
   }

   /* XXX: Orphaned pgrp check. */
   WARN_XXX(0);
}

/*
 * When we die, we re-parent all our children.
 * Try to give them to another thread in our thread
 * group, and if no such member exists, give it to
 * the global child reaper process (ie "init")
 */
static void
ExitReparentChildren(struct Task *father)
{
   struct Task *reaper = father, *p, *safety;

   ASSERT_TASKLIST_LOCKED();

   /* First figure out who should be the new parent. */
   do {
      /* 
       * Select a father's sibling task as the new parent
       * of father's children.
       */
      reaper = Task_NextThread(reaper);

      if (reaper == father) {
         /* Looks like father is the only one in the 
          * thread group. Now our only option is to reparent
          * with init (i.e., childReaperTask). */
         reaper = childReaperTask; 
         break;
      }
   } while (reaper->exitState);


   /*
    * There are only two places where our children can be:
    *
    * - in our child list
    * - in our ptraced child list
    *
    * find and reparent them.
    */

   list_for_each_entry_safe(p, safety, &father->children, sibling) {
      /* XXX: When would father not be its child's parent? 
       * Is it a ptrace thing? */
      DEBUG_MSG(5, "p->pid=%d\n", p->pid);
      ASSERT_UNIMPLEMENTED(father == p->realParent);
      if (father == p->realParent) {
         ExitChooseNewParent(p, reaper);
         ExitReparentThread(p, father, 0 /* not traced */);
      } else {
         /*
          * XXX ptraced task
          */
         ASSERT_UNIMPLEMENTED(0);
      }

      /*
       * XXX if ptraced child is a  zombie...
       */
   }

   /*
    * XXX: reparent ptraced children
    */

   return;
}

static void
ExitNotify()
{
   int state, isThreadGroupEmpty;
   struct Task *tsk = current;

   ASSERT_TASKLIST_LOCKED();

   ACQUIRE_SIGLOCK(tsk);

   isThreadGroupEmpty = Task_IsThreadGroupEmpty(tsk);

   if (Task_TestSigPending(tsk, 0) && 
         !(tsk->signal->flags & SIGNAL_GROUP_EXIT) && 
         !isThreadGroupEmpty) {
      struct Task *t;
      /*
       * XXX: This occurs when there was a race between our exit
       * syscall and a group signal choosing us as the one to
       * wake up.  It could be that we are the only thread
       * alerted to check for pending signals, but another thread
       * should be woken now to take the signal since we will not.
       * Now we'll wake all the threads in the group just to make
       * sure someone gets all the pending signals.
       *
       * Easy to trigger, it seems, with a few dozen runs of
       * test_multiprocessing.py.
       */
      for (t = Task_NextThread(tsk); t != tsk; t = Task_NextThread(t)) {
         /* Since we're waking everyone up anyway, we don't need
          * to check for the PF_EXITING flags, and hence we do need
          * such a flag. Although, it would prevent unecessary IPIs. */
         if (!Task_TestSigPending(t, 0)) {
            Signal_RecalcSigPending(t);
            if (Task_TestSigPending(t, 0)) {
               Signal_WakeUp(t, 0);
            }
         }
      }
   }

   RELEASE_SIGLOCK(tsk);

   /* tsk is the parent -- we're going to reparent its children 
    * to another thread in tsk's thread group. If no other thread
    * exists, then we'll reparent to init. */
   ExitReparentChildren(tsk);

   /* XXX: check for orphan pgrp */
   WARN_XXX(0);

   /* XXX: exit signals are configurable, but needs vetting. */
   WARN_XXX(0);

   /* Observe that we don't notify the parent if the other group members are
    * still not dead (which includes zombie state). Note that some
    * thread in the group will notify the parent, since some thread
    * will observe an empty thread group. */
   if (tsk->exitSignal != -1 && isThreadGroupEmpty) {
      int sig = (tsk->parent == tsk->realParent ? tsk->exitSignal : SIGCHLD);
      DEBUG_MSG(5, "Notifying parent of death: signal=%d\n", sig);
      Signal_NotifyParent(tsk, sig);
   } else if (tsk->ptrace) {
      ASSERT_UNIMPLEMENTED(0);
      Signal_NotifyParent(tsk, SIGCHLD);
   }

   state = EXIT_ZOMBIE;
   DEBUG_MSG(5, "curr->exitSignal=%d parent->signal->flags=%d\n",
         tsk->parent->signal->flags);

   /* Should we go ahead and reap this task? */
   if ((tsk->exitSignal == -1 && (tsk->ptrace == 0)) ||
         /* XXX: Don't we need the siglock for this? */
         (tsk->parent->signal->flags & SIGNAL_GROUP_EXIT)) {
      DEBUG_MSG(5, "Moving to EXIT_DEAD state.\n");
      /*
       * The parent is likely ignoring SIGCHLD, in which case,
       * POSIX requires that we clean up after ourselves.
       */
      state = EXIT_DEAD;
   }
   tsk->exitState = state;

   /* XXX: ptrace cleanup. */
   WARN_XXX(0);

   if (state == EXIT_DEAD && tsk != childReaperTask) {
      /*
       * Any wait()ers will have been woken by the above call to
       * NotifyParent, and then will see this task in EXIT_DEAD state,
       * and thus will not attempt to release it.
       */

      /* Release will decrement tsk->usage by 1, but not enough
       * to free the task struct. That'll happen in the final
       * Schedule(). */
      ExitTaskRelease(tsk);
   }
}

static void
ExitKillAllTasks()
{
   struct Task *p = NULL;
   struct siginfo info;
   const int sig = SIGKILL;

   ASSERT_TASKLIST_LOCKED();

   info.si_signo = sig;
   info.si_errno = 0;
   info.si_code = SI_KERNEL;
   info.si_pid = current->tgid;
   info.si_uid = current->uid;
   extern int group_send_sig_info(int sig, struct siginfo *info, 
         struct Task *p);

   /* ----- Send everyone a kill signal and reap them ----- */

   for_each_process(p) {
      DEBUG_MSG(5, "Considering id %d pid %d\n", p->id, p->pid);
      /* Careful, some threads may have called do_group_exit
       * already. */
      if (p == current) continue;

      if (p->state != TASK_DEAD) {
         DEBUG_MSG(5, "Sending pid %d SIGKILL\n", p->pid);
         ASSERT(p->id != current->id);
         UNUSED int err = group_send_sig_info(sig, &info, p);
      } else {
         /* Caution: could still be a zombie; that's why we wait
          * on it below. */
      }

#if 1
#if 0 // This doesn't seem to be necessary
      ACQUIRE_SIGLOCK(p);
      /* threads are not waitable (they are detached).
       * We make them waitable by setting exit_signal to
       * SIGCHLD. */
      p->exitSignal = SIGCHLD;
      RELEASE_SIGLOCK(p);
#endif

      RELEASE_TASKLISTLOCK();
      //UNUSED int res = sys_waitpid(p->pid, NULL, __WALL);
      // WEXITED is important : reaps children that have already terminated.
      // This flag is needed to ensure that no-libc/48-zombie-exit passes.
      UNUSED int res = WaitDo(p->pid, __WALL | WEXITED, NULL, NULL, NULL, 1);
      // Could be dead already, p->pid may not a child, in which case 
      // expect -ECHILD
      ASSERT_MSG(res == p->pid || res == -ECHILD, "res=%d", res);
      DEBUG_MSG(5, "res=%d pid=%d\n", res, p->pid);
      ACQUIRE_TASKLISTLOCK();
#endif
   }

   /* ----- Now make sure everyone has completely finished ---- 
    * This ensures that everybody has called Module_Exit before we
    * exit. */

#if 1
   /* Don't use next_task(tsk) here since only the thread group leader
    * unhashes threads, so this may not be an accurate count of
    * live threads */
   while (nr_threads > 1) {
      ASSERT_TASKLIST_LOCKED();

      DEBUG_MSG(5, "nr_threads=%d\n", nr_threads);
      RELEASE_TASKLISTLOCK();
      Sched_Schedule();
      ACQUIRE_TASKLISTLOCK();
   }
#endif
   ASSERT_TASKLIST_LOCKED();
   /* Everybody else should be dead. */
   ASSERT_MSG(nr_threads == 1, "nr_threads=%d", nr_threads);
}

/* Job here is to run exit routines that task must personally run,
 * and cleanup state that parent won't be interested in.
 * Everything else will be done by parent when it reaps this task. */
static void
ExitDoExit(long code)
{
   struct Task *tsk = current;

   D__;

   DEBUG_MSG(5, "id %d tsk->sigHand=0x%x tsk->sigHand->sigLock=0x%x\n", 
         tsk->id, tsk->sigHand, &tsk->sigHand->sigLock);

   ACQUIRE_TASKLISTLOCK();

   if (tsk == childReaperTask) {
      /* Kill all tasks before taking down init. This is needed to
       * for several reasons: 
       *    - to report task deaths to the controller */
      ExitKillAllTasks();
   }

   ASSERT_TASKLIST_LOCKED();

#if 0
   /* Shutdown if init dies. */
   if (tsk == childReaperTask ) {
      Module_SelfExit();

#if 0
      /* A hack: but needed to report thread exists to controller. 
       * We'll have to redo this entire exit/signal/schedule
       * architecture with linux kernel support in the end, so no
       * point getting it right now. */
      t = tsk;
      do {
      } while_each_thread(tsk, t);
#endif
      Module_Exit(t);

      System_Shutdown();
      NOTREACHED();
   }
#endif
   if (tsk == childReaperTask) {
      /* We should've killed all other tasks in the system. */
      ASSERT(Task_IsThreadGroupEmpty(current));

      /* Init doesn't have a parent so we have to invoke this on it
       * self. */
      Module_Exit(tsk);
   }

   VCPU_SelfExit();

   Signal_SelfExit();

   if (current != childReaperTask) {
      /* XXX: if it weren't for this issue, we could call
       * Files_Exit and FileSys_Exit in ExitTaskRelease. That 
       * would be more consistent. */

      /* Exit_Files must be called on sys_exit rather than at 
       * reap time. This ensures that pipes are closed when
       * a task becomes a zomie and thus other endpoints can
       * deal take appropriate action before waiting for the
       * zombie to become reaped. This is the behavior that
       * Linux apps expect. */
      D__;
      Files_Exit(tsk);
      D__;
      FileSys_Exit(tsk);
   }
   D__;

   if (current != childReaperTask) {
      Mem_SelfExit();
   }

   /* XXX: modules (e.g., brkpt) need to clean up their mm data. */
   Module_OnTaskExit();

   /*
    * No need to lock exitCode since it's task-private.
    *
    * Tell the parent that current is exiting.
    */
   tsk->exitCode = code;
   ExitNotify();

   /* At this point, current->mm is invalid, since it may have
    * been freed by the parent. */
   ASSERT(tsk->mm || !tsk->mm);

   /*
    * Setting tsk->state to TASK_DEAD will prevent the task from
    * being scheduled. Note that it could still be a zombie.
    * We rely on this task's parent to free its task struct.
    */
   ASSERT(tsk == current);
   Task_SetCurrentState(TASK_DEAD);
   ASSERT(tsk->exitState == EXIT_DEAD || tsk->exitState == EXIT_ZOMBIE);

   RELEASE_TASKLISTLOCK();

   Sched_Schedule();
   NOTREACHED();
}

void
Exit_DoGroupExit(int exitCode)
{
   /* Thread relationships and signal flags are both
    * protected by the siglock. No need to acquire
    * the task list lock. */
   ACQUIRE_SIGLOCK(current);

   if (current->signal->flags & SIGNAL_GROUP_EXIT) {
      /*
       * A group exit is already in progress. Use the
       * exit code passed to the initiating task rather
       * than the one passed to this task.
       */
      exitCode = current->signal->groupExitCode;

   } else if (!Task_IsThreadGroupEmpty(current)) {
      /*
       * Initiate the group exit. The exit code
       * will be communicated to any wait()ing tasks.
       */
      current->signal->groupExitCode = exitCode;
      Signal_ZapOtherThreads(current);
   }
   RELEASE_SIGLOCK(current);

   ExitDoExit(exitCode);
   NOTREACHED();
}

static int
WaitIsEligibleChild(pid_t pid, int options, struct Task *p)
{
   DEBUG_MSG(5, "id=%d pid=%d options=%d p=0x%x exit_signal=%d\n", p->id, p->pid, options, p, p->exitSignal);

   if (pid > 0) {
      if (p->pid != pid) {
         /*
          * Pid of child doesn't match, so not eligible.
          */
         return 0;
      }
   } else if (!pid) {
      if (Task_ProcessGroup(p) != Task_ProcessGroup(current)) {
         /*
          * Child is not in the same process group.
          */
         return 0;
      }
   } else if (pid != -1) {
      if (Task_ProcessGroup(p) != -pid) {
         return 0;
      }
   }

   /*
    * These are those tasks that did a SA_NOCLDWAIT
    * on a SIGCHLD sigaction.
    */
   if (p->exitSignal == -1 && !p->ptrace) {
      D__;
      return 0;
   }

   /* Wait for all children (clone and not) if __WALL is set;
    * otherwise, wait for clone children *only* if __WCLONE is
    * set; otherwise, wait for non-clone children *only*.  (Note:
    * A "clone" child here is one that reports to its parent
    * using a signal other than SIGCHLD.) */
   if (((p->exitSignal != SIGCHLD) ^ ((options & __WCLONE) != 0))
         && !(options & __WALL)) {
      D__;
      return 0;
   }

   /*
    * Do not consider thread group leaders that are
    * in a non-empty thread group:
    *
    * By not reaping such tasks, we ensure that non-exited members of 
    * of the thread group have valid groupLeader pointers 
    * (despite the fact that the groupLeader points to a task
    * that is in exit state).
    */
#define thread_group_leader(p)	(p == p->groupLeader)
#define delay_group_leader(p) \
   (thread_group_leader(p) && !Task_IsThreadGroupEmpty(p))
   if (delay_group_leader(p)) {
      D__;
      return 2;
   }

   return 1;
}

static int
WaitNoReapCopyout(struct Task *p, pid_t pid, uid_t uid, int why, int status,
      struct siginfo __user *infop, struct rusage __user *rusagep)
{
   int retval = rusagep ? ExitGetRUsage(p, RUSAGE_BOTH, rusagep) : 0;

   if (!retval)
      retval = __put_user(SIGCHLD, &infop->si_signo);
   if (!retval)
      retval = __put_user(0, &infop->si_errno);
   if (!retval)
      retval = __put_user((short)why, &infop->si_code);
   if (!retval)
      retval = __put_user(pid, &infop->si_pid);
   if (!retval)
      retval = __put_user(uid, &infop->si_uid);
   if (!retval)
      retval = __put_user(status, &infop->si_status);
   if (!retval)
      retval = pid;
   return retval;
}



static int
WaitTaskStopped(struct Task *p, int delayedGroupLeader, int noreap,
      struct siginfo __user *info, int __user *statAddr,
      struct rusage __user *ru)
{
   int retval, exitCode;

   DEBUG_MSG(5, "task has stopped\n");

   ASSERT_TASKLIST_LOCKED();

   /* May not hold, since p->state is written to only with siglock held. */
   //ASSERT(p->state & TASK_STOPPED);

   /*
    * SignalNotifyParent...() should set this before waking
    * the parent, unless someone (this task or another in the thread group)
    * already called wait and reset it.
    */
   if (!p->exitCode) {
      /* Looks like someone (possibly this task in an earlier invocation 
       * of sys_wait) already stopped the task. */
      ASSERT_TASKLIST_LOCKED();
      return 0;
   }

   /*
    * Even though this thread is stopped and the leader,
    * there may be other threads in the group that haven't
    * stopped yet. In that case, we want to delay returning
    * from wait() until all members have stopped (b/c
    * that's the Linux wait() semantics).
    */
   if (delayedGroupLeader) {
      if (!(p->ptrace & PT_PTRACED)) {
         ASSERT(p->signal);
         if (p->signal->groupStopCount > 0) {
            /*
             * A group stop is in progress and this is the group leader.
             * We won't report until all threads have stopped.
             */
            ASSERT_TASKLIST_LOCKED();
            return 0;
         }
      } else {
         ASSERT_UNIMPLEMENTED(0);
      }
   }


   /* Usually, WNOWAIT is not specified, in which case we should 
    * reap the child. */
   if (unlikely(noreap)) {
      RELEASE_TASKLISTLOCK();

      pid_t pid = p->pid;
      uid_t uid = p->uid;
      int why = (p->ptrace & PT_PTRACED) ? CLD_TRAPPED : CLD_STOPPED;

      exitCode = p->exitCode;
      ASSERT_UNIMPLEMENTED(!(unlikely(!exitCode) || unlikely(p->exitState)));

      /* Observe that we do not set p->exitCode to 0 -- this makes it possible
       * to invoke sys_wait again on this stopped task to get info about
       * it. */

      return WaitNoReapCopyout(p, pid, uid, why, (exitCode << 8) | 0x7f,
            info, ru);
   }

   ASSERT_TASKLIST_LOCKED();

   /* XXX: should this be done via xchg like in Linux? I don't see a race ... */
   /* Set the exit code to 0 so that any subsequent calls to waits
    * won't see this as stopped again. */
   exitCode = p->exitCode;
   p->exitCode = 0;
   ASSERT(exitCode != 0);

   ASSERT_UNIMPLEMENTED(!(p->exitState));

   RELEASE_TASKLISTLOCK();

   retval = ru ? ExitGetRUsage(p, RUSAGE_BOTH, ru) : 0;
   if (!retval && statAddr)
      retval = __put_user((exitCode << 8) | 0x7f, statAddr);
   if (!retval && info)
      retval = __put_user(SIGCHLD, &info->si_signo);
   if (!retval && info)
      retval = __put_user(0, &info->si_errno);
   if (!retval && info)
      retval = __put_user((short)((p->ptrace & PT_PTRACED)
               ? CLD_TRAPPED : CLD_STOPPED), &info->si_code);
   if (!retval && info)
      retval = __put_user(exitCode, &info->si_status);
   if (!retval && info)
      retval = __put_user(p->pid, &info->si_pid);
   if (!retval && info)
      retval = __put_user(p->uid, &info->si_uid);
   if (!retval)
      retval = p->pid;

   ASSERT(retval);

   return retval;
}

static int
WaitTaskZombie(struct Task *p, int noreap, struct siginfo __user *infop,
      int __user *stat_addr, struct rusage __user *ru)
{
   int retval, status;

   /* We're still holding this from WaitDo(). */
   ASSERT_TASKLIST_LOCKED();

   if (noreap) {
      RELEASE_TASKLISTLOCK();
      ASSERT_UNIMPLEMENTED(0);
   }

   D__;
   /*
    * Unlike the Linux kernel, we don't use read locks, which means
    * that only one parent should see the child in a zombie state.
    */
   ASSERT(p->exitState == EXIT_ZOMBIE);
   p->exitState = EXIT_DEAD;

   if (p->exitSignal == -1 && p->ptrace == 0) {
      /*
       * This can only happen in a race with a ptraced thread
       * dying on another processor.
       */
      ASSERT_UNIMPLEMENTED(0);
   }

   if ((p->realParent == p->parent) && p->signal) {
      WARN_XXX(0);

      /* XXX: update resource counters. */
   }


   D__;
   retval = ru ? ExitGetRUsage(p, RUSAGE_BOTH, ru) : 0;
   D__;

   ACQUIRE_SIGLOCK(p);
   status = (p->signal->flags & SIGNAL_GROUP_EXIT)
      ? p->signal->groupExitCode : p->exitCode;
   RELEASE_SIGLOCK(p);
   if (!retval && stat_addr)
      retval = __put_user(status, stat_addr);
   if (!retval && infop)
      retval = __put_user(SIGCHLD, &infop->si_signo);
   if (!retval && infop)
      retval = __put_user(0, &infop->si_errno);
   D__;
   if (!retval && infop) {
      int why;

      if ((status & 0x7f) == 0) {
         why = CLD_EXITED;
         status >>= 8;
      } else {
         why = (status & 0x80) ? CLD_DUMPED : CLD_KILLED;
         status &= 0x7f;
      }
      retval = __put_user((short)why, &infop->si_code);
      if (!retval)
         retval = __put_user(status, &infop->si_status);
   }
   D__;
   if (!retval && infop)
      retval = __put_user(p->pid, &infop->si_pid);
   if (!retval && infop)
      retval = __put_user(p->uid, &infop->si_uid);
   if (retval) {
      /* 
       * Something went wrong. Go back to being a zombie.
       */
      p->exitState = EXIT_ZOMBIE;
      return retval;
   }
   D__;
   retval = p->pid;
   if (p->realParent != p->parent) {
      ASSERT_UNIMPLEMENTED(0);
   }
   D__;
   if (p != NULL) {
      D__;
      ExitTaskRelease(p);
   }

   /*
    * Now we are sure this task is interesting, and no other
    * thread can reap it because we set its state to EXIT_DEAD.
    *
    * Note: Linux release this lock much earlier, but we do it
    * here to protect ExitTaskRelease. We want the signal/sighand
    * cleanup to be protected by tasklistlock rather than by
    * atomic operations to make it easier to reason about
    * synchronization.
    */
   RELEASE_TASKLISTLOCK();

   D__;

   ASSERT(retval);
   return retval;
}

static int WaitTaskContinued(struct Task *p, int noreap, 
      struct siginfo __user *infop, int __user *stat_addr,
      struct rusage __user *ru)
{
   int retval;
   pid_t pid;
   uid_t uid;

   ASSERT_TASKLIST_LOCKED();

   ASSERT(p->signal);

   ACQUIRE_SIGLOCK(p);
   if (!(p->signal->flags & SIGNAL_STOP_CONTINUED)) {
      /* child is still alive, so keep waiting. */
      RELEASE_SIGLOCK(p);
      return 0;
   }
   if (!noreap)
      p->signal->flags &= ~SIGNAL_STOP_CONTINUED;
   RELEASE_SIGLOCK(p);

   pid = p->pid;
   uid = p->uid;
   RELEASE_TASKLISTLOCK();

   if (!infop) {
      retval = ru ? ExitGetRUsage(p, RUSAGE_BOTH, ru) : 0;
      if (!retval && stat_addr)
         retval = __put_user(0xffff, stat_addr);
      if (!retval)
         retval = p->pid;
   } else {
      retval = WaitNoReapCopyout(p, pid, uid, CLD_CONTINUED, SIGCONT,
            infop, ru);
      ASSERT(retval != 0);
   }

   return retval;
}

static int
WaitIsMyPtraceChild(struct Task *child)
{
   child = child;

   /* XXX: implement ptrace support. */
   WARN_XXX(0);
   return 0;
}

static long 
WaitDo(pid_t pid, int options, struct siginfo __user *infop,
      int __user *stat_addr, struct rusage __user *ru, int on_exit) 
{
   DECLARE_WAITQUEUE(wait, current, 0);
   struct Task *tsk;
   int flag, retval;

   DEBUG_MSG(5, "pid=%d options=0x%x\n", pid, options);

   /*
    * NOTE: Any thread in the parent can wait on a thread in the child
    * thread group. 
    */
   WaitQueue_Add(&current->signal->waitChildExitQueue, &wait);
repeat:
   flag = 0;
   /* Must set TASK_INTERRUPTIBLE, since we want to be woken up
    * for signals. Must set TASK_WAITQUEUE to indicate that
    * we are not blocking on IO. */
   Task_SetCurrentState(TASK_INTERRUPTIBLE | TASK_WAITQUEUE);

   /* Protects parent child relationships. We need it here since
    * we iterate though our children. */
   ACQUIRE_TASKLISTLOCK();
   tsk = current;
   do {
      struct Task *p;
      int ret, pstate;

      D__;
      list_for_each_entry(p, &tsk->children, sibling) {
         D__;
         ret = WaitIsEligibleChild(pid, options, p);
         if (!ret) { continue; }

         pstate = Task_GetState(p);

         DEBUG_MSG(5, "id=%d pid=%d p->state=%d is eligible child\n", 
               p->id, p->pid, pstate);

         /* Racing read --- p sets state concurrently, eg.
          * when stopping. The IPI it sends to @current usually provides 
          * ordering, but not always, since @current may wake up 
          * spuriously before the IPI is received and check p->state. 
          *
          * In general, p may change its state at any time without
          * consistent locking and because @current may be woken up 
          * spuriously, we must log p->state if we want determinism.
          */

         switch (pstate) {
            case TASK_TRACED:
                ASSERT_UNIMPLEMENTED(0);
                break;
            case TASK_STOPPED:
                flag = 1;
                /* If WUNTRACED and not ptraced cihld, then return for child stops. 
                 * If ptraced child, then return regardless of WUNTRACED. */
                if (!(options & WUNTRACED) && !WaitIsMyPtraceChild(p)) {
                    continue;
                }
                retval = WaitTaskStopped(p, ret == 2,
                        (options & WNOWAIT), infop, stat_addr, ru);
                ASSERT(retval != -EAGAIN);
                if (retval != 0) {
                    /* WaitTask... has released the lock. */
                    goto end;
                }
                break;
            default:
                /* When exiting (ie when it goes into TASK_DEAD state), 
                 * child holds the task list lock and and thus accesses to 
                 * p->state and p->exitState are serialized since we also 
                 * hold the task list lock.
                 */
                if (p->exitState == EXIT_DEAD) {
                    /*
                     * Nothing to clean up -- it's already dead.
                     */
                    DEBUG_MSG(5, "task is already dead\n");
                    continue;
                }

                if (p->exitState == EXIT_ZOMBIE) {
                    /*
                     * Eligible but we cannot release it yet.
                     */
                    DEBUG_MSG(5, "we have a zombie: ret=%d\n", ret);
                    if (ret == 2) {
                        goto check_continued;
                    }
                    D__;
                    if (!(options & WEXITED)) {
                       D__
                        continue;
                    }
                    D__
                    retval = WaitTaskZombie(p, (options & WNOWAIT),
                            infop, stat_addr, ru);
                    if (retval != 0) {
                        /* WaitTask... has released the lock. */
                        goto end;
                    }
                    break;
                }
check_continued:
                /* 
                 * It's running, not dead or zombie.
                 */
                flag = 1;
                if (!(options & WCONTINUED)) {
                    continue;
                }
                retval = WaitTaskContinued(p, (options & WNOWAIT),
                        infop, stat_addr, ru);

                if (retval != 0) { 
                    /* WaitTask... has released the lock. */
                    goto end; 
                }
                break;
            }
        }

        if (!flag) {
            /*
             * XXX: find eligible ptrace children
             */
        }

        D__;
        if (options & __WNOTHREAD) {
            D__;
            break;
        }
        tsk = Task_NextThread(tsk);
        ASSERT(tsk->signal == current->signal);
        D__;
    } while (tsk != current);

    RELEASE_TASKLISTLOCK();

    if (flag) {
        retval = 0;
        if (options & WNOHANG) {
            goto end;
        }
        retval = -ERESTARTSYS;
        if (!on_exit && Task_TestSigPending(current, 1)) {
            /*
             * Don't block while we have signals to deliver.
             * Could lead to deadlock if we do block.
             */
            goto end;
        }

        /*
         * XXX: We must have been woken up even before we defer to
         * the scheduler. In that case, the scheduler will
         * eventually schedule us back in.
         */
        if (on_exit) {
           Task_SetCurrentState(TASK_RUNNING);
        }
        Sched_Schedule();

        /*
         * XXX: We have been woken up. But note that this
         * doesn't mean the event we are interested has happened.
         * We could've been woken up spuriously by a signal from
         * the tty, for example, or by an IPI signal. Hence,
         * we must check for the status of our event, and thus
         * the repeat.
         */
        goto repeat;
    }

    /* There are no unwaited for children. */
    retval = -ECHILD; 
end:
    /* Must set state to TASK_RUNNING to deal with the case that
     * we never called Schedule(). */
    Task_SetCurrentState(TASK_RUNNING);
    WaitQueue_Remove(&current->signal->waitChildExitQueue, &wait);

    if (infop) {
        if (retval > 0) {
            retval = 0;
        } else {
            /*
             * For a WNOHANG return, clear out all the fields
             * we would set so the user can easily tell the
             * difference.
             */
            if (!retval)
                retval = __put_user(0, &infop->si_signo);
            if (!retval)
                retval = __put_user(0, &infop->si_errno);
            if (!retval)
                retval = __put_user(0, &infop->si_code);
            if (!retval)
                retval = __put_user(0, &infop->si_pid);
            if (!retval)
                retval = __put_user(0, &infop->si_uid);
            if (!retval)
                retval = __put_user(0, &infop->si_status);
        }
    }

    return retval;
}

SYSCALLDEF(sys_exit, int errorCode)
{
    ExitDoExit((errorCode & 0xff) << 8);

    NOTREACHED();

    return 0;
}

SYSCALLDEF(sys_exit_group, int errorCode)
{
    Exit_DoGroupExit((errorCode & 0xff) << 8);

    NOTREACHED();

    return 0;
}
/* First argument to waitid: */
#define P_ALL		0
#define P_PID		1
#define P_PGID		2
SYSCALLDEF(sys_waitid, int which, pid_t pid,
        struct siginfo __user *infop, int options,
        struct rusage __user *ru)
{
    long ret;

    if (options & ~(WNOHANG|WNOWAIT|WEXITED|WSTOPPED|WCONTINUED))
        return -EINVAL;
    if (!(options & (WEXITED|WSTOPPED|WCONTINUED)))
        return -EINVAL;

    switch (which) {
    case P_ALL:
        pid = -1;
        break;
    case P_PID:
        if (pid <= 0)
            return -EINVAL;
        break;
    case P_PGID:
        if (pid <= 0)
            return -EINVAL;
        pid = -pid;
        break;
    default:
        return -EINVAL;
    }

    ret = WaitDo(pid, options, infop, NULL, ru, 0);

    return ret;
}

SYSCALLDEF(sys_wait4, pid_t pid, int __user *stat_addr,
        int options, struct rusage __user *ru)
{
    long ret;

    if (options & ~(WNOHANG|WUNTRACED|WCONTINUED|
                __WNOTHREAD|__WCLONE|__WALL))
        return -EINVAL;
    ret = WaitDo(pid, options | WEXITED, NULL, stat_addr, ru, 0);

    return ret;
}

SYSCALLDEF(sys_waitpid, pid_t pid, int __user *stat_addr, int options)
{
    return sys_wait4(pid, stat_addr, options, NULL);
}
