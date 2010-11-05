/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"

SYSCALLDEF(sys_personality, ulong personality)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_personality, personality);

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

   if (!SYSERR(ret)) {
      current->personality = ret;
   }

   return ret;
}
