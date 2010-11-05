/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <sys/time.h>
#include <errno.h>

#include "vkernel/public.h"

#include "private.h"

#define NSEC_PER_SEC	1000000000L

/*
 * Returns true if the timespec is norm, false if denorm:
 */
#define timespec_valid(ts) \
	(((ts)->tv_sec >= 0) && (((unsigned long) (ts)->tv_nsec) < NSEC_PER_SEC))

/*
 * Mode arguments of xxx_hrtimer functions:
 */
enum hrtimer_mode {
	HRTIMER_ABS,	/* Time value is absolute */
	HRTIMER_REL,	/* Time value is relative to now */
};

#if 0
SyscallRet
Sys_Nanosleep(const struct SyscallArgs *args, const void *auxArg)
{
   SyscallRet res;
#if 0
   struct timespec *rmtp = (struct timespec *) args->edx;
#endif

   res = Signal_BlockingRealSyscall(!VCPU_IsReplaying() ? args : NULL);

#if 0
   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(SysNanosleep) {
         entryp->ret = res;
         memcpy(&entryp->rmt, (void*)rmtp, sizeof(struct timespec));
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY(SysNanosleep) {
         res = entryp->ret;
         memcpy((void*)rmtp, &entryp->rmt, sizeof(struct timespec));
      } END_WITH_LOG_ENTRY(0);
   }
#endif

   return res;
}
#endif

static int
HrTimerDoNanosleep(struct timespec *rqtp, const enum hrtimer_mode mode, 
      const int which_clock)
{
   int ret;
   struct SyscallArgs args;

   /* rqtp points to kernel mem and we want it to be updated upon
    * return from syscall with time remaining. */
   args.eax = SYS_clock_nanosleep;
   args.ebx = which_clock;
   args.ecx = (mode == HRTIMER_ABS) ? TIMER_ABSTIME : 0; 
   args.edx = (ulong)rqtp;
   args.esi = (ulong)rqtp;


   /* We may be interrupted by an internal signal (e.g.,
    * a snoop signal or a kick signal). In that case,
    * restart the syscall -- don't let user-level know
    * that we've restarted it. */
   do {
      Task_SetCurrentState(TASK_INTERRUPTIBLE);

      /* XXX: u shouldn't be required to put the task back
       * on the runqueue when it fails with -EINTR. After all,
       * it might be a spurious wakeup and then we would end up
       * sleeping again. So all that work for nothing. */
      ret = Sched_BlockingRealSyscall(NULL, &args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(SysNanosleep) {
            entryp->ret = ret;
            memcpy(&entryp->rmt, (void*)rqtp, sizeof(struct timespec));
         } END_WITH_LOG_ENTRY(0);
      } else if (VCPU_IsReplaying()) {
         DO_WITH_LOG_ENTRY(SysNanosleep) {
            ret = entryp->ret;
            memcpy((void*)rqtp, &entryp->rmt, sizeof(struct timespec));
         } END_WITH_LOG_ENTRY(0);
      }
   } while (ret == -EINTR && !Task_TestSigPending(current, 1));


   ASSERT(!(ret == -EINTR) || Task_TestSigPending(current, 1));

   /* Return true iff signal pending. */
   return !(ret == -EINTR);
}

static long
HrTimerNanosleep(struct timespec *rqtp, struct timespec __user *rmtp,
      const enum hrtimer_mode mode, int which_clock);

static long
HrTimerNanosleepRestart(struct RestartBlockStruct *restart)
{
   struct timespec __user *rmtp;
   struct timespec tu;
   enum hrtimer_mode mode;
   int which_clock;

   tu.tv_sec = (time_t) restart->arg0;
   tu.tv_nsec = (long) restart->arg1;
   rmtp = (struct timespec __user *) restart->arg2;
   mode = (enum hrtimer_mode) restart->arg3;
   which_clock = (int) restart->arg4;

   return HrTimerNanosleep(&tu, rmtp, mode, which_clock);
}



static long
HrTimerNanosleep(struct timespec *rqtp, struct timespec __user *rmtp,
      const enum hrtimer_mode mode, int which_clock)
{
   struct RestartBlockStruct *restart;

   if (HrTimerDoNanosleep(rqtp, mode, which_clock)) {
      /* No signal pending. */
      return 0;
   }

   /* Sleep was interrupted by signal. */

   /* Absolute timers do not require that we compensate for the time already
    * slept before we restart. */
   if (mode == HRTIMER_ABS) {
      return -ERESTARTNOHAND;
   }

   /* Tell user-land how long we slept before getting the signal. */
   if (rmtp) {
      if (Task_CopyToUser(rmtp, rqtp, sizeof(*rmtp))) {
         return -EFAULT;
      }
   }

   /* 
    * ERESTART_RESTARTBLOCK:
    *
    * Will cause syscall to restart, if sigaction is either default or ignore.
    * If the sigaction is handle, then the syscall will be terminated. 
    *
    * If we restart, then we must compensate for time already slept.
    * The restart callback should take care of this.
    *
    */
   restart = &current->restartBlock;
   restart->fn = &HrTimerNanosleepRestart;
   restart->arg0 = rqtp->tv_sec;
   restart->arg1 = rqtp->tv_nsec;
   ASSERT(rmtp || !rmtp);
   restart->arg2 = (ulong) rmtp;
   restart->arg3 = (ulong) mode;
   restart->arg4 = (ulong) which_clock;

   return -ERESTART_RESTARTBLOCK;
}

long
sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp)
{
   struct timespec tu;

   D__;

   if (Task_CopyFromUser(&tu, rqtp, sizeof(tu))) {
      return -EFAULT;
   }

   if (!timespec_valid(&tu)) {
      return -EINVAL;
   }

   return HrTimerNanosleep(&tu, rmtp, HRTIMER_REL, CLOCK_MONOTONIC);
}


long
sys_time(time_t __user *tloc)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = SYS_time;
      args.ebx = 0;
      ret = Task_RealSyscall(&args);

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

   ASSERT(!SYSERR(ret));

   if (tloc) {
      if (__put_user(ret, tloc)) {
         ret = -EFAULT;
      }
   }

   return ret;
}

long
sys_stime(time_t __user *tptr)
{
   long err;
   time_t tmp;

   if (Task_CopyFromUser(&tmp, tptr, sizeof(*tptr))) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_stime, &tmp);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

out:
   return err;
}

long
sys_gettimeofday(struct timeval __user *tv, 
           struct timezone __user *tz)
{
   long err;
   struct timeval ktv;
   struct timezone ktz;

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_gettimeofday, &ktv, &ktz);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_gettimeofday) {
            entryp->ret = err;
            entryp->tv = ktv;
            entryp->tz = ktz;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_gettimeofday) {
         err = entryp->ret;
         ktv = entryp->tv;
         ktz = entryp->tz;
      } END_WITH_LOG_ENTRY(0);
   }

   /* What could possibly go wrong? .... */
   ASSERT(!err);

   if (tv && Task_CopyToUser(tv, &ktv, sizeof(ktv))) {
      err = -EFAULT;
      goto out;
   }

   if (tz && Task_CopyToUser(tz, &ktz, sizeof(ktz))) {
      err = -EFAULT;
      goto out;
   }

out:
   return err;
}

long
sys_alarm(uint seconds)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_alarm, seconds);

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
sys_setitimer(int which, struct itimerval __user *value, 
           struct itimerval __user *ovalue)
{
   struct itimerval set_buffer, get_buffer;
   int error;

   if (value) {
      if(Task_CopyFromUser(&set_buffer, value, sizeof(set_buffer)))
         return -EFAULT;
   } else {
      memset((char *) &set_buffer, 0, sizeof(set_buffer));
   }

   if (!VCPU_IsReplaying()) {
      error = syscall(SYS_setitimer, which, &set_buffer, 
            ovalue ? &get_buffer : NULL);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_itimer) {
            entryp->ret = error;
            entryp->ovalue = get_buffer;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_itimer) {
         error = entryp->ret;
         get_buffer = entryp->ovalue;
      } END_WITH_LOG_ENTRY(0);
   }

   if (error || !ovalue)
      return error;

   if (Task_CopyToUser(ovalue, &get_buffer, sizeof(get_buffer)))
      return -EFAULT; 

   return 0;
}

long
sys_getitimer(int which, struct itimerval __user *value)
{
	int error = -EFAULT;
	struct itimerval get_buffer;

   if (!value) goto out;

   if (!VCPU_IsReplaying()) {
      error = syscall(SYS_getitimer, which, &get_buffer);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_itimer) {
            entryp->ret = error;
            entryp->ovalue = get_buffer;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_itimer) {
         error = entryp->ret;
         get_buffer = entryp->ovalue;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!error &&
         Task_CopyToUser(value, &get_buffer, sizeof(get_buffer)))
      error = -EFAULT;

out:
   return error;
}


long
sys_clock_settime(const clockid_t which_clock, const struct timespec __user *tp)
{
	struct timespec new_tp;
   int error;

   /* XXX: make sure app doesn't mess with thread virtual time, since we
    * use it for preemptions... */
   WARN_UNIMPLEMENTED(0);

	if (Task_CopyFromUser(&new_tp, tp, sizeof (*tp))) {
		error = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      error = syscall(SYS_clock_settime, which_clock, &new_tp);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = error;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         error = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

out:
   return error;
}



static int
ClockGetTimeOrRes(const clockid_t which_clock, struct timespec __user *tp, 
                  int wantsTime)
{
	struct timespec kernel_tp;
	int error;

   if (!VCPU_IsReplaying()) {
      error = syscall(wantsTime ? SYS_clock_gettime : SYS_clock_getres, 
            which_clock, &kernel_tp);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_clock_gettimespec) {
            entryp->ret = error;
            entryp->ts = kernel_tp;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_clock_gettimespec) {
         error = entryp->ret;
         kernel_tp = entryp->ts;
      } END_WITH_LOG_ENTRY(0);
   }

	if (!error && Task_CopyToUser(tp, &kernel_tp, sizeof(kernel_tp))) {
		error = -EFAULT;
      goto out;
   }

out:
	return error;
}

long
sys_clock_gettime(const clockid_t which_clock, 
      struct timespec __user *tp)
{
   return ClockGetTimeOrRes(which_clock, tp, 1);
}

long
sys_clock_getres(const clockid_t which_clock, struct timespec __user *tp)
{
   return ClockGetTimeOrRes(which_clock, tp, 0);
}

long
sys_clock_nanosleep(const clockid_t which_clock, int flags,
		    const struct timespec __user *rqtp, struct timespec __user *rmtp)
{
   struct timespec tu;

   if (Task_CopyFromUser(&tu, rqtp, sizeof(tu))) {
      return -EFAULT;
   }

   /* XXX: this can be done by kernel, so we needn't do it. */
   if (!timespec_valid(&tu)) {
      return -EINVAL;
   }

   return HrTimerNanosleep(&tu, rmtp, (flags & TIMER_ABSTIME) ? 
                           HRTIMER_ABS : HRTIMER_REL, which_clock);
}
