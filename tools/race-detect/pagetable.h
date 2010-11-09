#pragma once

#include <vector>

#include "sharedheap.h"
#include "framepool.h"
#include "shmsegmap.h"

typedef struct PtEntryStruct {
   /* XXX: make these bits a function of page & address-space size */
   uint shared:1;
   uint frame:20;
   uint shmid:32;
   uint pgoff:32;
} PtEntry;

typedef vector<PtEntry, SharedHeapAllocator<PtEntry> > PtEntryVector;

/* Must be in the shared heap since parent creates child'
 * pt and sends him the pointer on a fork. */
class PageTable : public PtEntryVector, public SharedHeap {
private:

   FramePool *fp;
   ShmSegMap *sp;

   void init();

   void _deallocate(PtEntry* const pte);

public:
   PageTable(FramePool *_fp, ShmSegMap *_sp);

   /* essentially forks the page table */
   PageTable(const PageTable &rhs);

   ~PageTable();

   PtEntry lookup(const Page pn) const;

   ADDRINT virt2phys(const ADDRINT vaddr) const;

#if 0
   /* XXX: delete when ready. replaced by detect and
    * recovery mechanism. */
   void lock(const Page pn);

   void unlock(const Page pn);

   void lock(const ADDRINT start, const size_t len);

   void unlock(const ADDRINT start, const size_t len);
#endif

   ADDRINT find_free_block(const size_t bytes);

   bool is_region_free(Page start, Page region_size);

   void deallocate(const ADDRINT start, const size_t len);

   void allocate(const ADDRINT start, const size_t len, 
         const Page pgoff, bool shared, const ShmId shmid);

};
