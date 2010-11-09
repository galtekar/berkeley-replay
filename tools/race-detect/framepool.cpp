#include "framepool.h"

#include "debug.h"

#define ASSERT_MEM_LOCKED() ASSERT_IS_LOCKED(&physMemLock)

FramePool::FramePool() : PageVector(MAX_FRAMES) {
   /* 1 means available/free -- initially, all frames are available
    * for allocation */

   for (int i = 0; i < MAX_FRAMES; i++) {
      at(i) = 0;
   }

   /* first frame is not available for allocation -- it's
    * refcount is always 1. */
   at(0) = 1;

   /* second frame is not avaialble for allocation -- it's
    * index is used to mark unallocated pages. */
   at(1) = 1;

   ASSERT(size() == MAX_FRAMES);

   Synch_LockInit(&physMemLock);
}

/* Allocates a physical frame */
Page FramePool::get() {
   ASSERT_MEM_LOCKED();

   ASSERT(size() == MAX_FRAMES);

   /* find free frame and clear it */
   uint frame = 0;

   for (Page pn = 0; pn < MAX_FRAMES; pn++) {
      if (at(pn) == 0) {
         at(pn)++;
         frame = pn; 
         break;
      }
   }

   // XXX: what if out of frames?; could happen if lots of vm pages
   ASSERT(frame > 1); 
   return frame;
}

/* Increments ref count of specified physical frame. */
Page FramePool::get(Page frame) {
   ASSERT_MEM_LOCKED();
   ASSERT(frame > 1);
   ASSERT(frame < MAX_FRAMES);
   ASSERT(size() == MAX_FRAMES);

   // frame should already be allocated; all new allocations
   // must be done via the other get().
   ASSERT(at(frame) > 0);
   at(frame)++;
   ASSERT(at(frame) < UINT_MAX); // detect overflow

   return frame;
}

/* Decrement ref count of specified physical frame.
 * Becomes allocatable if refcount == 0. */
ulong FramePool::put(Page frame) {
   ASSERT_MEM_LOCKED();
   ASSERT(frame > 1);
   ASSERT(frame < MAX_FRAMES);
   ASSERT(size() == MAX_FRAMES);

   at(frame)--;
   ASSERT(at(frame) >= 0);

   return at(frame);
}

ulong FramePool::get_ref_count(Page frame) {
   ASSERT(size() == MAX_FRAMES);
   return at(frame);
}

void FramePool::lock() {
   //DLOG("lock: physMemLock=%d\n", physMemLock);
   LOCK(&physMemLock);
}

void FramePool::unlock() {
   //DLOG("unlock: physMemLock=%d\n", physMemLock);
   UNLOCK(&physMemLock);
}
