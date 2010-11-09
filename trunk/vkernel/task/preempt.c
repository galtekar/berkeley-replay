#include "vkernel/public.h"
#include "private.h"

/*
 *-----------------------------------------------------------------------
 *
 * PreemptNotificationCallback --
 *
 * Summary:
 *
 *    Gets invoked by the event notification subsystem when there is a 
 *    preemption delivery event during replay. Our job here is
 *    to indicate that a preemption is in progress and get us into
 *    the vkernel to handle the preemption.
 *
 *-----------------------------------------------------------------------
 */
void
PreemptNotificationCallback(void *arg UNUSED) {
   DECLARE_LOG_ENTRY_POINTER(PreemptionTimer, peekTimer);
   DECLARE_LOG_ENTRY_POINTER(PreemptionFault, peekFault);
   struct ExecPoint *ep = NULL;

   ASSERT(VCPU_IsReplaying());

   /* No longer pending preemption since we've arrived at the
    * preemption point. */
   Task_ClearCurrentFlag(TIF_PREEMPT_PENDING);

   /* Note that we don't consume the preempt entry here. That's
    * done in PreemptDo, called right before resuming user-mode
    * execution. */

   /* By setting this flag, we let Signal_DoNotifyResume know
    * that it should try rescheduling. */
   if (PEEK_LOG_ENTRY(PreemptionTimer, peekTimer)) {
      Task_SetCurrentFlag(TIF_PREEMPT_TIMER);
      ep = &peekTimer->ep;
   } else if (PEEK_LOG_ENTRY(PreemptionFault, peekFault)) {
      Task_SetCurrentFlag(TIF_PREEMPT_FAULT);
      ep = &peekFault->ep;
   } 

   ASSERT(ep);
   ASSERT(ep->eip == curr_regs->R(eip));
   ASSERT(ep->brCnt == BrCnt_Get());
   DEBUG_MSG(5, "peekp->ep.brCnt=%llu BrCnt_Get()=%llu\n",
         ep->brCnt, BrCnt_Get());

   /* All event delivery happens in BT context due to
    * us coming out of DE and into BT to handle an early PMI. */

   /* XXX: What if the PMI is accurate? Won't we be in DE mode then? */
   ASSERT_UNIMPLEMENTED(Task_TestFlag(current, TIF_BT_MODE));
}

void ASMLINKAGE
Preempt_ScheduleUpcoming()
{
   DECLARE_LOG_ENTRY_POINTER(PreemptionTimer, peekTimer);
   DECLARE_LOG_ENTRY_POINTER(PreemptionFault, peekFault);
   struct ExecPoint *ep = NULL;

   /* XXX: do this check earlier. */
   if (!VCPU_IsReplaying()) {
      return;
   }

   if (Task_TestFlag(current, TIF_PREEMPT_PENDING)) {
      /* Looks like we've already requested notification for
       * a preemption and that preemption point hasn't been
       * reached yet. This could happen if we enter the kernel
       * after the initial notification request, but before the 
       * notification delivery -- as would happen on a PMI
       * signal. */
      ASSERT(PEEK_LOG_ENTRY(PreemptionTimer, peekTimer) ||
             PEEK_LOG_ENTRY(PreemptionFault, peekFault));

      return;
   }


   /* Only peek at this entry -- don't move to the next one,
    * since we'll need to look at this entry again when
    * we get to the preemption delivery point. */
   if (PEEK_LOG_ENTRY(PreemptionTimer, peekTimer)) {
      ep = &peekTimer->ep;
   } else if (PEEK_LOG_ENTRY(PreemptionFault, peekFault)) {
      ep = &peekFault->ep;
   }

   if (ep) {
      DEBUG_MSG(5, "Scheduling preemption for delivery.\n");

      ASSERT(peekTimer || peekFault);
      ASSERT(!(peekTimer && peekFault));
      ASSERT(!Task_IsAddrInKernel(ep->eip));
      ASSERT_MSG(ep->brCnt >= BrCnt_Get(), "target=%llu brCnt=%llu\n",
                 ep->brCnt, BrCnt_Get());

      Task_SetCurrentFlag(TIF_PREEMPT_PENDING);
      Brkpt_SetAbsolute(Bpk_Dynamic, ep, &PreemptNotificationCallback, NULL);
   } else {
      /* Not a preemption, so nothing to setup. */
   }
}

static void
PreemptDoTimer()
{
   if (!VCPU_IsReplaying()) {
      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(PreemptionTimer) {
            /* XXX: do we really need to log all regs? */
            entryp->ep.eip = curr_regs->R(eip);
            entryp->ep.ecx = curr_regs->R(ecx);
            entryp->ep.brCnt = BrCnt_Get();
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(PreemptionTimer) {
         /* Just consume the entry. */

         ASSERT(curr_regs->R(eip) == entryp->ep.eip);
         ASSERT(curr_regs->R(ecx) == entryp->ep.ecx);
         ASSERT(BrCnt_Get() == entryp->ep.brCnt);
      } END_WITH_LOG_ENTRY(0);
   }
}

static void
PreemptDoFault()
{
#if 0
   if (!VCPU_IsReplaying()) {
      siginfo_t *siP = current->frameP->pinfo;

      ASSERT_KPTR(siP);
      ASSERT(Signal_IsCrashSig(siP->si_signo));

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(PreemptionFault) {
            entryp->ep.eip = curr_regs->R(eip);
            entryp->ep.ecx = curr_regs->R(ecx);
            entryp->ep.brCnt = BrCnt_Get();
            entryp->faultInfo = *siP;
         } END_WITH_LOG_ENTRY(0);

         /* Sig already sent. */
      }
   } else {
      DO_WITH_LOG_ENTRY(PreemptionFault) {
         /* Just consume the entry. */
         ASSERT(curr_regs->R(eip) == entryp->ep.eip);
         ASSERT(curr_regs->R(ecx) == entryp->ep.ecx);
         ASSERT(BrCnt_Get() == entryp->ep.brCnt);

         /* Send sig using its original siginfo. */
         Signal_SendFaultSig(&entryp->faultInfo);
      } END_WITH_LOG_ENTRY(0);
   }
#else
   DO_WITH_LOG_ENTRY(PreemptionFault) {
      if (VCPU_IsLogging()) {
         siginfo_t *siP = current->frameP->pinfo;

         ASSERT_KPTR(siP);
         ASSERT(Signal_IsCrashSig(siP->si_signo));

         /* XXX: if we were in BT mode, then signal context is wrong. We
          * need to create the right signal frame. */

         entryp->ep.eip = curr_regs->R(eip);
         entryp->ep.ecx = curr_regs->R(ecx);
         entryp->ep.brCnt = BrCnt_Get();
         entryp->faultInfo = *siP;
      } else {
         /* Just consume the entry. */
         ASSERT(curr_regs->R(eip) == entryp->ep.eip);
         ASSERT(curr_regs->R(ecx) == entryp->ep.ecx);
         ASSERT(BrCnt_Get() == entryp->ep.brCnt);
      }

      /* Send sig using its original siginfo. */
      Signal_SendFaultSig(&entryp->faultInfo);
   } END_WITH_LOG_ENTRY(0);
#endif
}

static void
PreemptDo()
{
   DEBUG_MSG(3, "Preemption.\n");

   /* Fault signals, in addition to the timer signal, are treated
    * as preemptions due to their urgent nature. SIGSEGV or SIGBUS,
    * for example, must be handled immediately -- that's what many
    * apps expect. */

   /* Many preemptions are asynchronous -- our per-thread
    * timer, for example, and SIGXCPU, SIGPWR, and even
    * SIGBUS etc. Others, like SIGSEGV, are usually synchronous,
    * but may be sent from other tasks via sys_kill, and
    * received asynchronously while executing user-mode code.
    * Hence we log the reception context for all of them. */

   DEBUG_MSG(5, "mode=%d\n", VCPU_GetMode() & VCPU_MODE_SINGLESTEP);

#if DEBUG
#if 0
   if (VCPU_IsReplaying() &&
         (VCPU_GetMode() & VCPU_MODE_SINGLESTEP) &&
         (ssCheck.flags & CHECK_REGS)) {
#endif
      if (VCPU_IsReplaying() &&
            (VCPU_GetMode() & VCPU_MODE_SINGLESTEP)) {

         ASSERT_UNIMPLEMENTED(0);

         D__;

         DECLARE_LOG_ENTRY_POINTER(RegChk, regChkp);

         /* Peek ahead in the check log to see if there is a regchk
          * entry for this execution point. If so, we need to process
          * that before switching to the next thread. 
          *
          * XXX: this is a hack to deal with the fact that during
          * DE/SS logging, we may get either a SS trap or preemption
          * trap at the same execution point in a nondeterministic order */
         if (CHECK_PEEK_LOG_ENTRY(RegChk, regChkp)) {
            D__;
            if (regChkp->eip == curr_regs->R(eip) &&
                  regChkp->ecx == curr_regs->R(ecx) &&
                  regChkp->hdr.dbg.brCnt == BrCnt_Get()) {
               Check_DoRegs(curr_regs);
            }
         }
      }
#endif

      /* We assume that we get crashes only via signals. This is
       * unlike preemptions, which may happen via signal (from DE mode)
       * or via synchronous entrance (from BT mode). Hence the two
       * cases. */
      if (Task_TestFlag(current, TIF_PREEMPT_TIMER)) {
         PreemptDoTimer();
      } else if (Task_TestFlag(current, TIF_PREEMPT_FAULT)) {
         PreemptDoFault();
      } else {
         ASSERT(0);
      }

      Sched_Schedule();
   }

   void ASMLINKAGE
      Preempt_OnResumeUserMode()
      {
         ASSERT(TIF_PREEMPT == (TIF_PREEMPT_TIMER | TIF_PREEMPT_FAULT));
         ASSERT(Task_TestFlag(current, TIF_PREEMPT));
         ASSERT(Task_TestFlag(current, TIF_PREEMPT) != TIF_PREEMPT);
         ASSERT(!Task_IsAddrInKernel(curr_regs->R(eip)));

         PreemptDo();
      }
