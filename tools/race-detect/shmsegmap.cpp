#include "shmsegmap.h"

#include "debug.h"

ShmSegMap::ShmSegMap(FramePool *_fp) {
   ASSERT(_fp);
   fp = _fp;
}

Page ShmSegMap::get(SharedSegment *ssp, const Page pgoff) {
   ASSERT(ssp);
   ASSERT(pgoff < MAX_SEGMENT_PAGES);
   ASSERT(pgoff >= 0);

   if (ssp->at(pgoff) != 0) {
      ssp->at(pgoff) = fp->get(ssp->at(pgoff));
   } else {
      ssp->at(pgoff) = fp->get();
   }

   return ssp->at(pgoff);
}

SharedSegment* ShmSegMap::get(const ShmId shmid, const Page pgoff, const size_t len) {

   SharedSegment *ssp = NULL;

   iterator it = find(shmid);
   if (it == end()) {
      /* XXX: if shmid is an inode, len shouldn't be assumed to be
       * it's length (i.e., the file's length). it's not, it the
       * length specified to the particular mmap call. */
      ssp = new SharedSegment(shmid, len);
      insert(ShmPair(shmid, ssp));
   } else {
      ssp = it->second;
   }
   ASSERT(ssp);

   // allocate a physical frame for each page in the range,
   // if it hasn't already been allocated
   FOR_ALL_PAGES_IN_RANGE(pgoff*PAGE_SIZE, len) {
      get(ssp, pn);
   } END_ALL_PAGES_IN_RANGE;

   return ssp;
}

void ShmSegMap::put(SharedSegment *ssp, const Page pgoff) {
   ASSERT(pgoff < MAX_SEGMENT_PAGES);
   ASSERT(pgoff >= 0);
   ASSERT(ssp);

   // if noone holds a reference after we do the ``put'', mark
   // it for garbage collection
   if (fp->put(ssp->at(pgoff)) == 0) {
      ssp->at(pgoff) = 0;
   }
}

void ShmSegMap::put(const ShmId shmid, const Page pgoff, const size_t len) {

   iterator it = find(shmid);
   ASSERT(it != end());

   SharedSegment *ssp = it->second;
   ASSERT(ssp);

   // decrement the ref count for each frame in range and if 0,
   // return to the frame pool
   FOR_ALL_PAGES_IN_RANGE(pgoff*PAGE_SIZE, len) {
      put(ssp, pn);   
   } END_ALL_PAGES_IN_RANGE;
}

SharedSegment* ShmSegMap::lookup(const ShmId shmid) {
   SharedSegment *ssp = NULL;

   iterator it = find(shmid);
   if (it != end()) {
      ssp = it->second;
   }

   return ssp;
}

void ShmSegMap::garbage_collect() {
   /* XXX: delete all segments with totalRefCount == 0; should
    * be called periodically */

   ASSERT(0);

#if 0
   int totalRefCount = 0;
   /* XXX: shouldn't have to scan all pages */
   FOR_ALL_PAGES_IN_RANGE(0*PAGE_SIZE, len) {
      totalRefCount += fp->get_ref_count(ssp->allocFrames[pn]);
   } END_ALL_PAGES_IN_RANGE;

   // if no frame is used, then deallocate shmid
   if (totalRefCount == 0) {
      erase(shmid);
      delete ssp;
      ssp = NULL;
   }
#endif
}
