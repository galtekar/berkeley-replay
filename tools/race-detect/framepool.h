#pragma once

#include <vector>

#include "misc.h"

#include "memops.h"
#include "sharedheap.h"

#define MAX_FRAMES MAX_PAGES
#define FRAME_INVALID 1

typedef vector<Page, SharedHeapAllocator<Page> > PageVector;
class FramePool : public PageVector, public SharedHeap {
private:
   SynchLock physMemLock;

public:
   FramePool();

   /* Allocates a physical frame */
   Page get();

   /* Increments ref count of specified physical frame. */
   Page get(Page frame);

   /* Decrement ref count of specified physical frame.
    * Becomes allocatable if refcount == 0. */
   ulong put(Page frame);

   ulong get_ref_count(Page frame);

   void lock();

   void unlock();
};
