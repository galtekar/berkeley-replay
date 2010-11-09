#pragma once

#include <vector>
#include <list>

#include "sharedheap.h"
#include "segment.h"

class SegmentQueue : public list<Segment*, SharedHeapAllocator<Segment*> >, public SharedHeap {
private:
   vector<ulong, SharedHeapAllocator<ulong> > activeIdSet;

public:
   SegmentQueue();

   void getParallelSegments(Segment *segPtr, SegmentVec &outVec);

   void garbageCollect(VectorClock &garbageVec);

   void insert(Segment* const segPtr);

   SegmentQueue::iterator remove(iterator it);

   bool isActive(ThreadId id) const;
   //ThreadId getInactiveId();
};
