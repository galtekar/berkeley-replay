/* From libcommon */
#include "syncops.h"
#include "sharedarea.h"
#include "fdops.h"

#include "replay.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

SHAREDAREA ReplayEventQueue *eventQueue = NULL;
SHAREDAREA SynchLock eventLock = SYNCH_UNLOCKED;
SHAREDAREA volatile ulong eventCount = 0;

int isReplaying = 0;

INLINE bool
Replay_IsReplaying() {
   return isReplaying;
}

INLINE bool
Replay_IsLogging() {
   return !isReplaying;
}

struct LogEntry {
   uint clock;
   uint dummy;
};

static void
ReplayInsertQueue(uint clock)
{
   current->ticket = clock;
   ASSERT_EVENTLOCK_LOCKED();
   eventQueue->push(current);
#if 0
   Synch_CondSignal(&eventQueue->cond);
#endif
}

void
Replay_Lock()
{
   ASSERT(current);

   Synch_SpinLock(&eventLock);

   DLOG("eventCount=%d\n", eventCount);
   if (Replay_IsReplaying()) {
      int res;
      /* XXX: we should pass the ticket value into the eventQueue
       * rather than store it in the thread descriptor */
      struct LogEntry e;
      res = safe_read(current->replayLogFd, (void*)&e, sizeof(e));
      if (res != sizeof(e)) {
         perror("read");
         DLOG("res=%d\n", res);
         ASSERT(0);
      }

      ASSERT(e.dummy == 0xdeadbeef);
      DLOG("e.clock=%d\n", e.clock);
      if (eventCount != e.clock) {
         /* Wait for your turn. */
         ReplayInsertQueue(e.clock);
         Synch_CondWait(&current->eventCond, &eventLock);
      } else {
         /* It's your turn; grab and go. */
      }
   } else {
      int res;
#if 0
      char outStr[256];
      snprintf(outStr, sizeof(outStr), "eventCount=%d\n", eventCount);
      //DLOG("writing to %d\n", current->replayLogFd);
      res = write(current->replayLogFd, outStr, strlen(outStr)+1);
      if (res == -1) {
         perror("write");
      }
      DLOG("wrote %d bytes\n", res);
#else
      struct LogEntry e;
      e.clock = eventCount;
      e.dummy = 0xdeadbeef;
      res = safe_write(current->replayLogFd, (void*)&e, sizeof(e));
      if (res != sizeof(e)) {
         perror("write");
         ASSERT(0);
      }
#endif

   } 
}

bool
Replay_IsLocked()
{
   return (eventLock == SPIN_LOCKED);
}

void
Replay_Unlock()
{
   ASSERT_EVENTLOCK_LOCKED();
   eventCount++;

   if (Replay_IsReplaying()) {
      Thread *t = NULL;

#if 0
      while (!eventQueue->size() || 
            (t = eventQueue->top())->ticket != eventCount) {

         Synch_CondWait(&eventQueue->cond, &eventLock);
         ASSERT(eventQueue->size());
      }
#endif
      ASSERT_EVENTLOCK_LOCKED();
      if (eventQueue->size() && 
            (t = eventQueue->top())->ticket == eventCount) {
         /* Somebody else is waiting for the event lock. */
         eventQueue->pop();
         ASSERT(t);
         Synch_CondSignal(&t->eventCond);
      }
   }

   Synch_SpinUnlock(&eventLock);
}

void
Replay_ThreadStart()
{
   ASSERT(current);

   char filename[256];
   snprintf(filename, sizeof(filename), "/tmp/sync.%d", current->cloneId);
   if (Replay_IsLogging()) {
      current->replayLogFd = open(filename, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
   } else {
      current->replayLogFd = open(filename, O_RDWR, S_IRUSR | S_IWUSR);
   }
   ASSERT(current->replayLogFd != -1);
}

void
Replay_Init(int isReplay)
{
   isReplaying = isReplay;

   if (Replay_IsReplaying()) {
      eventQueue = new ReplayEventQueue;
   }
}
