/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

/*
 * Replayable Synchronization.
 *
 * Can't use it unless you have the VCPU lock and hence have
 * exclusive access to the VCPU log file.
 * Ensures there are no races on segment updates, for example,
 * when multiple tasks on the same VCPU update the vector clock
 * concurrently.
 */

SHAREDAREA int repSynchEnabled = 0;

void
RepSynch_LockInit(struct RepLockStruct *l, const char *idStr)
{
   Synch_LockInit(&l->sl);
   l->ticket = 0;
   WaitQueue_InitHead(&l->eventq);
#if DEBUG
   strncpy(l->idStr, idStr, sizeof(l->idStr));
#endif
}

void
RepSynch_Lock(struct RepLockStruct *l)
{
   Synch_Lock(&l->sl);

   if (!RepSynch_IsEnabled()) { return; }

   DEBUG_MSG(5, "Lock: l->id_str=%s l->ticket=%d\n", l->idStr, l->ticket);

   if (VCPU_IsReplaying()) {
      int ticket;
      DO_WITH_LOG_ENTRY(SegmentEvent) {
         ticket = entryp->ticket;
      
         DEBUG_MSG(5, "Logged: id_str=%s wait_ticket=%d\n", 
               entryp->idStr, ticket);
         ASSERT(strncmp(entryp->idStr, l->idStr, sizeof(entryp->idStr)) == 0);
      } END_WITH_LOG_ENTRY(0);


      if (l->ticket != ticket) {
         DECLARE_WAITQUEUE(wait, current, ticket);

         DEBUG_MSG(5, "waiting l->ticket=%d ticket=%d\n", 
               l->ticket, ticket);
         /* If NR_VCPU == 1 and scheduling is deterministic, 
          * then we should get our tickets right away -- 
          * otherwise we'll wait and there would be no one to 
          * wake us up. */
         ASSERT(NR_VCPU > 1);
         ASSERT(l->ticket <= ticket);

         /* Wait for your turn. */
         WaitQueue_Add(&l->eventq, &wait);

         Synch_CondWait(&wait.cond, &l->sl);

         WaitQueue_Remove(&l->eventq, &wait);
      } else {
         /* It's your turn; grab and go. */
      }

      if (VCPU_TestMode(VCPU_MODE_RACEDETECT)) {
         //SegEvent_Recv((ulong) l, l->idStr);
         //Module_OnSegRecv((ulong) l, l->idStr);
      }
   } else if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(SegmentEvent) {
#if DEBUG
         strncpy(entryp->idStr, l->idStr, sizeof(entryp->idStr));
#endif
         entryp->ticket = l->ticket;
      } END_WITH_LOG_ENTRY(0);
   }
}

void
RepSynch_Unlock(struct RepLockStruct *l)
{
   if (!RepSynch_IsEnabled()) { goto out; }

   ORDERED_ASSERT_IS_LOCKED(l);

   if (VCPU_IsReplaying())  {
      if (!List_IsEmpty(&l->eventq.taskList)) {
         struct WaitQueue *head;
         struct Task *t;

         head = list_entry(l->eventq.taskList.next, 
               struct WaitQueue, taskList);
         ASSERT(head);
         t = (struct Task*) head->priv;

         DEBUG_MSG(5, "head id=%d pid=%d priority=%d\n", 
               t->id, t->pid, head->priority);

         if (head->priority == l->ticket+1) {
            /* Somebody else is waiting for the event lock. */
            DEBUG_MSG(5, "signalling id=%d pid=%d\n", t->id, t->pid);
            ASSERT(t);
            Synch_CondSignal(&head->cond);
         }
      }

      if (VCPU_TestMode(VCPU_MODE_RACEDETECT)) {
         //SegEvent_Send((ulong) l, l->idStr);
#if PRODUCT
#error "XXX: call out to the module"
#endif
         //Module_OnSegSend((ulong) l, l->idStr);
      }
   }

   l->ticket++;
   DEBUG_MSG(5, "incrementing ticket for idStr=%s to %d\n", 
         l->idStr, l->ticket);
out:
   Synch_Unlock(&l->sl);
}
