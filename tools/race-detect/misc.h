#pragma once

#include "pin.H"

extern "C" {
#include "xed-interface.h"
}
#include "../InstLib/instlib.H"

#undef DEBUG
#define DEBUG 1

#define LOCK(l) Synch_Lock(l)
#define UNLOCK(l) Synch_Unlock(l)
#define ASSERT_IS_LOCKED(l) ASSERT(Synch_IsLocked(l))


#define MAX_THREADS 16

typedef int ThreadId;
typedef INT32 ShmId;

extern char* use_xed(ADDRINT pc, char* buf, size_t bufSz);

#define EVENT_LOCK() Synch_Lock(&eventLock)
#define EVENT_UNLOCK() Synch_Unlock(&eventLock)
#define ASSERT_EVENTLOCK_LOCKED() ASSERT(Synch_IsLocked(&eventLock))
extern struct SynchLock eventLock;
