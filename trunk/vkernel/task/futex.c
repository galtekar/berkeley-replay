/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

static int
FutexWait(u32 __user *uaddr, u32 val, struct timespec *timeout)
{
   SyscallRet res;
   struct SyscallArgs args;
   int wasInterrupted, isSignalPending;

   args.eax = SYS_futex;
   args.ebx = (ulong) uaddr;
   args.ecx = FUTEX_WAIT;
   args.edx = val;
   args.esi = (ulong) timeout;
   args.edi = 0;
   args.ebp = 0;

   do {
      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      res = Sched_BlockingRealSyscall(NULL, &args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = res;
         } END_WITH_LOG_ENTRY(0);
      } else if (VCPU_IsReplaying()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            res = entryp->ret;
         } END_WITH_LOG_ENTRY(0);
      }

      wasInterrupted = res == -EINTR;
      isSignalPending = Task_TestSigPending(current, 1);

   } while (wasInterrupted && !isSignalPending);

   /* NOTE: sys_futex is not restartable */
   return res == -EWOULDBLOCK ? 0 : res;
}

static int
FutexNonBlocking(u32 __user *uaddr, int op, u32 val, struct timespec *timeout, 
                 u32 __user *uaddr2, u32 val3)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);

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

static int
FutexWakeOp(u32 __user *uaddr, int op, u32 val, struct timespec *timeout, 
                 u32 __user *uaddr2, u32 val3)
{
   int ret;

   /* Must call through, even during replay, since WAKE_OP modifies
    * uaddr2. */
   ret = syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(JustRetval) {
         entryp->ret = ret;
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

static long
FutexDo(u32 __user *uaddr, int op, u32 val, struct timespec *timeout, 
        u32 __user *uaddr2, u32 val2, u32 val3)
{
   int ret;

   switch (op) {
   case FUTEX_WAIT:
      ret = FutexWait(uaddr, val, timeout);
      break;
   case FUTEX_WAKE:
      BKL_Lock();
      ret = FutexNonBlocking(uaddr, op, val, timeout, uaddr2, val3);
      BKL_Unlock();
      break;
   case FUTEX_REQUEUE:
      /* Like, FUTEX_WAKE, but automatically requeues those who
       * need to call futex_wait again. */
   case FUTEX_CMP_REQUEUE:
      BKL_Lock();
      /* Like above, but with a check before wakeup. */
      ret = FutexNonBlocking(uaddr, op, val, (struct timespec *)val2, 
            uaddr2, val3);
      BKL_Unlock();
      break;
   case FUTEX_WAKE_OP:
      /* XXX: must be order locked, otherwise we'll get divergences
       * at user-level when NR_VCPU > 1. */
      Bus_Lock();
      ret = FutexWakeOp(uaddr, op, val, timeout, uaddr2, val3);
      Bus_Unlock();
      break;
   case FUTEX_LOCK_PI:
   case FUTEX_UNLOCK_PI:
   case FUTEX_TRYLOCK_PI:
      /* XXX: These ops modify the userspace futex val and hence should
       * be emulated and order-locked. */
      ASSERT_UNIMPLEMENTED(0);
      ret = -EINVAL;
      break;
   case FUTEX_FD:
      ASSERT_UNIMPLEMENTED(0);
      ret = -EINVAL;
      break;
   default:
      //ASSERT_UNIMPLEMENTED(0);
      ret = -EINVAL;
      break;
   }

   return ret;
}


SYSCALLDEF(sys_futex, u32 __user *uaddr, int op, u32 val,
			  struct timespec __user *utime, u32 __user *uaddr2,
			  u32 val3)
{
	struct timespec t, *tp = NULL;
   u32 val2 = 0;

   DEBUG_MSG(5, "uaddr=0x%x op=%d val=%d utime=0x%x\n",
         uaddr, op, val, utime);

	if (utime && (op == FUTEX_WAIT || op == FUTEX_LOCK_PI)) {
		if (Task_CopyFromUser(&t, utime, sizeof(t)) != 0)
			return -EFAULT;
      tp = &t;
   }

	/*
	 * requeue parameter in 'utime' if op == FUTEX_REQUEUE.
	 */
	if (op == FUTEX_REQUEUE || op == FUTEX_CMP_REQUEUE)
		 val2 = (u32) (unsigned long) utime;

   return FutexDo(uaddr, op, val, tp, uaddr2, val2, val3);
}

SYSCALLDEF(sys_set_robust_list, ulong __user *head, size_t len)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_set_robust_list, head, len);

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

SYSCALLDEF(sys_get_robust_list, int pid, ulong __user **head_ptr,
		    size_t __user *len_ptr)
{
   SyscallRet ret;
   ulong khead_ptr, klen_ptr;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_get_robust_list, pid, &khead_ptr, &klen_ptr);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_get_robust_list) {
            entryp->ret = ret;
            entryp->head_ptr = khead_ptr;
            entryp->len_ptr = klen_ptr;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_get_robust_list) {
         ret = entryp->ret;
         khead_ptr = entryp->head_ptr;
         klen_ptr = entryp->len_ptr;
      } END_WITH_LOG_ENTRY(0);
   }

   if (SYSERR(ret)) {
      return ret;
   }

	if (__put_user(klen_ptr, len_ptr))
		return -EFAULT;

	return __put_user(khead_ptr, (ulong*)head_ptr);
}
