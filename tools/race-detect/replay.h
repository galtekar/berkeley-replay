#pragma once

#define EVENT_LOCK() Replay_Lock()
#define EVENT_UNLOCK() Replay_Unlock()
#define ASSERT_EVENTLOCK_LOCKED() ASSERT(Replay_IsLocked())

#include "syncops.h"
#include "thread.h"

#include <queue>

template <typename T> class SharedVector : public vector<T, SharedHeapAllocator<T> > {
};

class LogicalClockOrder {
   bool operator()( const Thread* &x, const Thread* &y ) { 
      return x->ticket < y->ticket;
   }
};

typedef priority_queue<Thread*, SharedVector<Thread*> > SharedThreadPq;

class ReplayEventQueue : public SharedThreadPq, public SharedHeap {
public:
   SynchLock lock;
   struct SynchCond cond;

   ReplayEventQueue() {
      Synch_SpinLockInit(&lock);
      Synch_CondInit(&cond);
   }
};

extern void Replay_Lock();
extern void Replay_Unlock();
extern bool Replay_IsLocked();
extern void Replay_ThreadStart();
extern void Replay_Init(int isReplayMode);
