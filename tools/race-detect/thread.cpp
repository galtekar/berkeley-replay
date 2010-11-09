#include "thread.h"

#include "debug.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

TLS_KEY infoKey;
int numThreads = 1; /* process-private (should not be in SHAREDAREA) */
extern SHAREDAREA SynchLock eventLock;
int isReplay = 0;
int isVkernelRunning = 0;

SHAREDAREA uint totalClones = 0;

/* Advanced to the next segment, which will have clock value TARGETCLOCK. */
void Thread::advanceSegment(VectorClock &targetClock) {
   /* WARNING: don't use the Segment copy constructor to
    * do a copy. That will copy the AccessMap! */

#if DEBUG
   if (cloneId > 0) {
      ASSERT_IS_LOCKED(&eventLock);
   }
#endif

   segPtr = new Segment(id);
  
   segPtr->update(targetClock);

   ASSERT(*segPtr == targetClock);
}

Thread::Thread(VectorClock &startClock, ThreadId _id, ThreadId _tid, ADDRINT _parentTid, ADDRINT _ctidAddr, PageTable *_ptPtr) {

   brCnt = 0;
   id = _id;
   tid = _tid;
   parentTid = _parentTid;
   ctidAddr = _ctidAddr;
   ptPtr = _ptPtr;
   cloneId = totalClones++;
   Btracer_ThreadStart(&bt);
   isInInst = 0;
   sysno = 0;
   dfp = NULL;


#if DEBUG
   if (cloneId > 0) {
      ASSERT_IS_LOCKED(&eventLock);
   }
#endif
   advanceSegment(startClock);
}

Thread::~Thread() {
   DLOG("~Thread: destructor (this=0x%lx)\n", (unsigned long)this);


   Btracer_ThreadEnd(&bt);
   // the current segment hasn't been placed in the segqueue
   // and thus is safe to delete (no one knows about it and thus
   // cannot possible be accessing it)
   ASSERT(segPtr);
   DLOG("Freeing segPtr\n");
   delete segPtr;
   segPtr = NULL;

   ASSERT(ptPtr);

   // last thread to exit deletes the page table
   // no lock on numThreads necessary, since the only time when
   // a zero is written to it is when the last thread is exiting
   if (numThreads == 0) {
      DLOG("Freeing the pagetable.\n");
      delete ptPtr;
      ptPtr = NULL;
   }
}

Segment* Thread::getSeg() const { ASSERT(segPtr); return segPtr; }

ThreadId Thread::getId() const { return id; }

ThreadId Thread::getTid() const { return tid; }

PageTable* Thread::getPt() const { return ptPtr; }
