#pragma once

#include <map>
#include <vector>

#include "sharedheap.h"
#include "framepool.h"
#include "misc.h"

#include "debug.h"

#define MAX_SEGMENT_PAGES ((1UL << 31) >> PAGE_SHIFT) /* 2GB worth of pages */
#define OFFSET_INVALID MAX_SEGMENT_PAGES

class SharedSegment : public PageVector, public SharedHeap {
public:
   ShmId shmid;

   SharedSegment(const ShmId _shmid, size_type n) : PageVector(PAGE_NUM(n)) {
      ASSERT(PAGE_ALIGNED(n));
      Page szpg = PAGE_NUM(n);
      ASSERT(szpg < MAX_SEGMENT_PAGES);

      shmid = _shmid;
      DLOG("New sharedsegment for shmid %d.\n", shmid);
   }

   const_reference at(size_type n) const {
      ASSERT(n < MAX_SEGMENT_PAGES);
      return PageVector::at(n);
   }

   reference at(size_type n) {
      ASSERT(n < MAX_SEGMENT_PAGES);
      return PageVector::at(n);
   }

   size_t size_bytes() const {
      return size() * PAGE_SIZE;
   }
};

typedef pair<const ShmId, SharedSegment*> ShmPair;

class ShmSegMap : public map<ShmId, SharedSegment*, less<ShmId>, SharedHeapAllocator<ShmPair> >, public SharedHeap {

private:
   FramePool *fp;

public:
   ShmSegMap(FramePool *_fp);

   Page get(SharedSegment *sep, const Page pgoff);

   SharedSegment* get(const ShmId shmid, const Page pgoff, const size_t len);

   void put (SharedSegment *sep, const Page pgoff);

   void put(const ShmId shmid, const Page pgoff, const size_t len);

   SharedSegment* lookup(const ShmId shmid);

   void garbage_collect();
};
