#pragma once

#include <sstream>

#include "event.h"
#include "thread.h"

#include "channel.h"
#include "segmentqueue.h"
#include "misc.h"
#include "debug.h"
#include "syncops.h"

#include "replaycheck.h"



extern ChannelMap *chanMap;
extern SegmentQueue *segQueue;

class IdMap : public bitset<MAX_THREADS>, public SharedHeap {
public:
   /* Find first zero bit and set it. */
   int get() {
      for (int i = 0; i < MAX_THREADS; i++) {
         DEBUG_MSG(5, "i=%d\n", test(i));
         if (test(i) == false) {
            set(i, true);
            return i;
         }
      }
      ASSERT(count() == MAX_THREADS);
      /* XXX: need to expand the bit-set somehow. */
      ASSERT_UNIMPLEMENTED(0);
      return -1;
   }

   void put(int id) {
      ASSERT(test(id) == true);
      set(id, false);
   }
};

SHAREDAREA IdMap *idMap = NULL; 
SHAREDAREA ThreadMap *thrMap = NULL;


/*************************************************************/

template <class EventInterface, class MessageInterface>
          class SegmentEvent : public EventInterface,
                               public MessageInterface
{

private:

   void GarbageCollectSegmentQueue() {
      MaxVectorClock minVec;

      ASSERT_EVENTLOCK_LOCKED();

      ThreadMap::const_iterator it;
      for (it = thrMap->begin(); it != thrMap->end(); it++) {
         Thread *thrPtr = it->second;
         ASSERT(thrPtr);

         //DLOG("min of %d\n", thrPtr->getTid());
         /* Find component wise minimum among all threads. */
         minVec.minimize(*(thrPtr->getSeg()));
      }

      segQueue->garbageCollect(minVec);
   }

public:
   virtual void beforeEvent() {
      /* Default: do nothing. */
   }

   void before() {
      EVENT_LOCK();

      beforeEvent();

      DLOG("----------------------------------------\n");
      DLOG("SegmentEvent: %s\n", toStr().c_str());

      EventInterface::postBefore();
   }

   /* Should return true if we should start a new segment. 
    * False if we should stay in the same segment. */
   virtual bool afterEvent()=0;

   virtual void afterGC() {
      /* Default: do nothing */
   }

   void after() {
      bool shouldAdvance = afterEvent();

      if (shouldAdvance) {
         /* Get the segPtr before we advance to the next one. */
         Segment *segPtr = current->getSeg();
         ASSERT(segPtr);

         /* At this point, the queue should contain only
          * those segment that happened before or are parallel
          * with the current segment. */
         /* Once you've pushed the seg onto the pq,
          * then you can't modify it anymore, since others
          * will be concurrently reading it. */

         /* segQueue protected by eventlock. */
         ASSERT_EVENTLOCK_LOCKED();

         segQueue->insert(segPtr);

         VectorClock targetClock = MessageInterface::handle(*segPtr);

         current->advanceSegment(targetClock);
         ASSERT(segPtr != current->getSeg());


#if 1
         SegmentVec parSegs;
         segQueue->getParallelSegments(segPtr, parSegs);
         /* parSegs now contains the segments that are parallel
          * to the previous segment at the time it was pushed
          * to the segment queue. */

         /* XXX: This is expensive. Figure out how to do it
          * outside the eventLock without using garbage
          * collected segments (maybe mark for collection and
          * then delete after checking for races?). */
         segPtr->racesWith(parSegs);

         GarbageCollectSegmentQueue();

         afterGC();
#endif
      }


      DLOG("Clock: %s\n", current->getSeg()->toStr().c_str());
      ASSERT_EVENTLOCK_LOCKED();
      EVENT_UNLOCK();

   }

   virtual string toStr() const=0;
};

/*************************************************************/

class MessageHandler {
public:
   virtual VectorClock handle(VectorClock &currentClock)=0;

   virtual ~MessageHandler() { }
};

class ReceiveHandler : public MessageHandler {
protected:
   ChannelKeyVec recvVec;

   virtual void processMessage(Message *msgPtr) {
      /* Default: do nothing. */
   }

public:
   VectorClock handle(VectorClock &currentClock) {
      VectorClock targetClock(currentClock);

      for (ChannelKeyVec::iterator it = recvVec.begin(); it != recvVec.end(); it++) {
         ChannelKey key = *it;
         Channel *chanPtr = chanMap->lookupCreate(key);
         ASSERT(chanPtr);

         /* The channel's vc is the update of all the messages
          * that passed through the channel. */
         DLOG("Channel clock: %s\n", chanPtr->toStr().c_str());
         targetClock.update(*chanPtr);

         while (chanPtr->size()) {
            Message *msgPtr = chanPtr->receive();
            ASSERT(msgPtr);

            DLOG("Received: %s\n", msgPtr->toStr().c_str());
            processMessage(msgPtr);
            delete msgPtr;
            msgPtr = NULL;
         }
      }

      targetClock.advance();

      return targetClock;
   }
};

class SendHandler : public MessageHandler {
protected:
   Message *msgPtr;
   ChannelKeyVec sendVec;

   void prepareMessage(Message *_msgPtr) {
      msgPtr = _msgPtr;
   }

public:
   SendHandler() {
      msgPtr = NULL;
   }

   VectorClock handle(VectorClock &currentClock) {
      /* Key point: send the clock before you advance to the
       * next segment. */

      VectorClock targetClock(currentClock);

      if (!msgPtr) {
         msgPtr = new Message(currentClock);
      }

      for (ChannelKeyVec::iterator it = sendVec.begin(); it != sendVec.end(); it++) {
         ChannelKey key = *it;
         Channel *chnPtr = chanMap->lookupCreate(key);
         chnPtr->send(msgPtr);
      }

      targetClock.advance();

      return targetClock;
   }
};

class SendReceiveHandler : public SendHandler, public ReceiveHandler {
public:

   VectorClock handle(VectorClock &currentClock) {
      VectorClock targetClock = ReceiveHandler::handle(currentClock);
      SendHandler::handle(currentClock);

      return targetClock;
   }
};

/*************************************************************/

class SetTidAddressEvent : public SyscallEvent {
private:
   enum {CTIDADDR};

public:
   void after() {
      current->ctidAddr = arg(CTIDADDR);
   }

   string toStr() const {
      return "SetTidAddressEvent";
   }
};

class ThreadStartEvent : public SegmentEvent<NonSyscallEvent, ReceiveHandler> {
private:
   /* XXX: get rid of this if we don't end up using it */
   const bool isRootThread;

public:
   ThreadStartEvent(bool _isRootThread) : isRootThread(_isRootThread) {
   }

   void beforeEvent() {
      ASSERT(current);
      DLOG("ThreadStart: id=%d pinId=%d\n", current->getId(), PIN_ThreadId());
      ASSERT(current->getTid() == (ThreadId)PIN_GetTid());

   }

   bool afterEvent() {

      ChannelKey key(PIN_GetTid(), true);
      recvVec.push_back(key);

      return true;
   }

   string toStr() const {
      return "ThreadStartEvent";
   }
};

class FutexWaitEvent : public SegmentEvent<SyscallEvent, ReceiveHandler> {
private:
   enum {UADDR};

protected:
   void beforeEvent() {
      /* XXX: don't hold the lock while waiting on futex. 
       * -- rethink this*/

      EVENT_UNLOCK();
   }

   bool afterEvent() {
      EVENT_LOCK();
      /* Since we don't hold the lock before the futex,
       * the clock value we read here may not correspond to
       * the appropriate futex wake call, for example, if
       * multiple wake calls were made in parallel. 
       *
       * XXX: does this matter? as far as this thread is 
       * concerned, it could've been woken up by either */

      /* XXX: we need to do a UnlockPage(uAddr) here, but
       * this might deadlock. What do we do? */

      if (!SYSERR(retVal)) {
         ChannelKey key(Virt2Phys(arg(UADDR)), false);
         recvVec.push_back(key);

         return true;
      }

      return false;
   }

public:
   string toStr() const {
      return "FutexWaitEvent";
   }
};

class WaitidEvent : public SegmentEvent<SyscallEvent, ReceiveHandler> {
protected:
   bool waitId(ADDRINT tid) {
      EVENT_LOCK();

      DLOG("retVal=%d parentTid=%d\n", retVal, tid);

      if (!SYSERR(retVal)) {
         ChannelKey key(tid, true);
         recvVec.push_back(key);

         return true;
      }

      return false;
   }

   void beforeEvent() {
      /* XXX: don't hold the lock while waiting on futex. 
       * -- rethink this*/

      EVENT_UNLOCK();
   }

   bool afterEvent() {
      /* GetTid() because child send it's parent (us) the vector clock */
      return waitId(PIN_GetTid());
   }

public:
   string toStr() const {
      return "WaitidEvent";
   }
};

class WaitpidEvent : public WaitidEvent {
protected:
   bool afterEvent() {
      return waitId(PIN_GetTid());
   }

public:
   string toStr() const {
      return "WaitpidEvent";
   }
};

class Wait4Event : public WaitidEvent {
   bool afterEvent() {
      return waitId(PIN_GetTid());
   }

public:
   string toStr() const {
      return "Wait4Event";
   }
};

/*************************************************************/


class CloneEvent : public SegmentEvent<SyscallEvent, SendHandler> {
private:
   enum {FLAGS, NEWSP, PTIDPTR, ESI, CTIDPTR};

protected:
   bool DoClone(const bool isFork, const ADDRINT ctidPtr) {
      ASSERT_EVENTLOCK_LOCKED();

      if (!SYSERR(retVal)) {
         PageTable *ptPtr = current->getPt();
         ASSERT(ptPtr);

         if (isFork) {
            DLOG("CloneAfter: this is a fork\n");
            ptPtr = new PageTable(*ptPtr);
         } else {
            DLOG("CloneAfter: this is not a fork\n");
            // doing this in ThreadStart results in a window in which
            // numThreads == 0, and as a result, the page table may be
            // deallocated even though a thread is using it
            numThreads++; 
         }

         /* Setup the child thread's structures atomically
          * with its creation. This ensures that it is globally
          * visible after the clone event -- this is to ensure
          * that we don't incorrectly garbage collect segments
          * thinking that everyone (except the new thread)
          * knows about them. */

         /* Don't use a recycled id if a segment associated with that
          * id is still in the segment queue. Doing so may result
          * in missed segments. */
         int i = 0;
         ThreadId myId, idsConsidered[MAX_THREADS];
         do {
            idsConsidered[i] = myId = idMap->get();
            DLOG("considering myId=%d\n", myId);
            i++;
         } while (segQueue->isActive(myId));

         for (int j = 0; j < i-1; j++) {
            idMap->put(idsConsidered[j]);
         }

         VectorClock *startClock = current->getSeg();
         ASSERT(startClock);
         Thread *newThrPtr = new Thread(*startClock, myId, retVal, 
               PIN_GetTid(), ctidPtr, ptPtr);
         ASSERT(newThrPtr);

         DLOG("Inserting into threadmap: tid=%d\n", retVal);
         thrMap->insert(ThreadPair(retVal, newThrPtr));

         Btracer_Clone(newThrPtr);

         if (isFork) {
            ReplayCheck_Fork(newThrPtr);
         }

         ChannelKey key(retVal /*child's tid*/, true);
         sendVec.push_back(key);

         return true;
      }

      return false;
   }

public:
   bool afterEvent() {
      return DoClone(!(arg(FLAGS) & CLONE_VM), arg(CTIDPTR));
   }

   string toStr() const {
      return "CloneEvent";
   }
};

class ForkEvent : public CloneEvent {
public:
   bool afterEvent() {
      const bool isFork = true;
      return DoClone(isFork, 0);
   }

   string toStr() const {
      return "ForkEvent";
   }
};

class FutexWakeEvent : public SegmentEvent<SyscallEvent, SendHandler> {
private:
   enum {UADDR};

public:
   bool afterEvent() {

      /* XXX: what if no processes are woken up? should we still
       * send a message? 
       *
       *    -- why not? this will just capture the ordering between
       *    wake and wait, independetly of whether they succeeded or not.
       */

      ChannelKey key(arg(UADDR), false);
      sendVec.push_back(key);

      return true;
   }

   string toStr() const {
      return "FutexWakeEvent";
   }
};

class ExitEvent : public SegmentEvent<SyscallEvent, SendHandler> {

   bool afterEvent() {
      /* Send two messages: one on the mutex channel and the other
       * on the channel to the parent. This is so we can handle
       * the parent calling wait, waitpid, etc. */
      /* Also, sending to the parent means that he'll receive
       * word of our last segment on his next snoop event. And that
       * means he (or somebody else) will GC it eventually. */

      ChannelKey key1(Virt2Phys(current->ctidAddr), false), key2(current->parentTid, true);
      sendVec.push_back(key1);
      sendVec.push_back(key2);
     
      idMap->put(current->getId());

      numThreads--;

      return true;
   }

   void afterGC() {
      ASSERT_EVENTLOCK_LOCKED();
      /* The gc relies on our entry being in the thrMap to do
       * compute an accurate minVector. */
      thrMap->erase(PIN_GetTid());
   }

   string toStr() const {
      return "ExitEvent";
   }
};
/*************************************************************/

class AtomicEvent : public SegmentEvent<NonSyscallEvent, SendReceiveHandler> {
private:
   ADDRINT uAddr;

public:
   AtomicEvent(ADDRINT _uAddr) {
      uAddr = _uAddr;
   }

   bool afterEvent() {

      /* XXX: may race with a concurrent non-atomic access
       * to writeVaddr. So we must record the atomic-access
       * as well. */

      ChannelKey key(Virt2Phys(uAddr), false);
      sendVec.push_back(key);
      recvVec.push_back(key);

      return true;
   }

   string toStr() const {
      return "AtomicEvent";
   }
};

class SnoopEvent : public SegmentEvent<NonSyscallEvent, SendReceiveHandler> {
public:
   bool afterEvent() {
      /* NOTE: it's important that we receive from our own vector so that
       * we receive the latest vc info about child thread's that've exited. */
      for (ThreadMap::iterator it = thrMap->begin(); it != thrMap->end(); it++) {
         Thread *thr = it->second;

         ASSERT(thr);
         ChannelKey key(thr->getTid(), true);
         recvVec.push_back(key);
      }

      ChannelKey key(current->getTid(), true);
      sendVec.push_back(key);

      return true;
   }

   string toStr() const {
      return "SnoopEvent";
   }
};
