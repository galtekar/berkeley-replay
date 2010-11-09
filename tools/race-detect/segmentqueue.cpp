#include "segmentqueue.h"

#include "debug.h"

SegmentQueue::SegmentQueue() : activeIdSet(MAX_THREADS) {
}

/* Returns
 * all the segments in the queue that are parallel to segPtr 
 * (exclusive) in outVec. */
void SegmentQueue::getParallelSegments(Segment *segPtr, SegmentVec &outVec) {
   const_iterator it;

   ASSERT(segPtr);

   for (it = begin(); it != end(); it++) {
      Segment *segIt = *it;

      ASSERT(segIt);
      if (*segPtr || *segIt) {
         outVec.push_back(segIt);
      }
   }
}

void SegmentQueue::garbageCollect(VectorClock &garbageVec) {
   DLOG("GarbageVector: %s\n", garbageVec.toStr().c_str());

   int numDeletedSegs = 0;

   iterator sit = begin();
   while (sit != end()) {
      Segment *segPtr = *sit;
      ASSERT(segPtr);
      int id = segPtr->getId();

      //DLOG("Considering deletion: %s\n", segPtr->toStr().c_str());
      if ((*segPtr)[id] <= garbageVec[id]) {
         //DLOG("Deleting segment.\n");
         numDeletedSegs++;
         sit = remove(sit);
         delete segPtr;
         if (sit == end()) { /* damn stl hack */
            break;
         } else {
            continue;
         }
      }


      sit++;
   }
   DLOG("Deleted %d segments\n", numDeletedSegs);
}

void SegmentQueue::insert(Segment* const segPtr) {
   ASSERT(segPtr);

   const ThreadId id = segPtr->getId();

   activeIdSet[id]++;
   DLOG("insert: activeIdSet[%d]=%d\n", id, activeIdSet[id]);

   push_back(segPtr);
}

SegmentQueue::iterator SegmentQueue::remove(iterator it) {
   Segment *segPtr = *it;

   ASSERT(segPtr);

   activeIdSet[segPtr->getId()]--;

   return erase(it); 
}

#if 1
bool SegmentQueue::isActive(ThreadId id) const {
   DLOG("activeIdSet[%d]=%d\n", id, activeIdSet[id]);
   return (activeIdSet[id] > 0);
}
#endif

#if 0
ThreadId SegmentQueue::getInactiveId() {
   for (int i = 0; i < MAX_THREADS; i++) {
      if (activeIdSet[i] == 0) {
         return i;
      }
   }

   /* out of ids! */
   ASSERT(0);
   return -1;
}
#endif
