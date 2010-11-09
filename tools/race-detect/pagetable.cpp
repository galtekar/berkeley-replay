#include "pagetable.h"

#include <sys/mman.h>

#include "memops.h"
#include "debug.h"

/* XXX: pages --> bytes for greater interface consistency */
bool PageTable::is_region_free(Page start, Page region_size) {
   /* is the region free? */
   for (Page pn = start; pn < start+region_size; pn++) {
      //DLOG("pn: %d --> %d\n", pn, at(pn).frame);
      if (at(pn).frame != 0) {
         return false;
      }
   }
   return true;
}

void PageTable::init() {
   /* init pt with the current vm mappings */
   /* no locks necesasry if done at process startup. */

   memregion_t regions[MAXREGIONS];
   int shouldIgnoreVDSO = 0;

   int numRegions = read_self_regions(regions, NULL, shouldIgnoreVDSO);

   for (int i = 0; i < numRegions; i++) {
      memregion_t *r = &regions[i];
      bool isShared = r->map_flags & MAP_SHARED;
      Page pgOff = PAGE_NUM(r->offset);

      /* No region should be mapped at 0x0. */
      ASSERT(r->start);

      DLOG("r->start=0x%x r->len=%d r->offset=%d shared=%d inode=%d\n", 
            r->start, r->len, pgOff,
            isShared, r->inode);
      allocate(r->start, r->len, pgOff,
            isShared, isShared ? r->inode : 0);
   }

   /* First page is not allocatable -- this is Linix VM policy. */
   at(0).frame = FRAME_INVALID;
}

PageTable::PageTable(FramePool *_fp, ShmSegMap *_sp) : PtEntryVector(MAX_PAGES) {
   ASSERT(_fp);
   fp = _fp;
   sp = _sp;

   DLOG("PageTable: constructor\n");
   fp->lock();

   init();

   fp->unlock();
   DLOG("PageTable: constructor end\n");
}

/* essentially forks the page table */
PageTable::PageTable(const PageTable &rhs) : PtEntryVector(MAX_PAGES) {

   DLOG("PageTable: copy constructor\n");
   fp = rhs.fp;
   sp = rhs.sp;
   ASSERT(fp);
   ASSERT(sp);

   fp->lock();

   ASSERT(rhs.size() == MAX_PAGES);
   for (Page i = 0; i < MAX_PAGES; i++) {
      if (rhs[i].frame && rhs[i].frame != FRAME_INVALID) {
         operator[](i) = rhs[i];

         if (rhs[i].shared) {
#if 1
            /* use the same frame number, but increcrement its ref count */
            operator[](i).frame = fp->get(rhs[i].frame);
#endif
         } else {
#if 1
            /* get a new frame, since the page is not shared */
            operator[](i).frame = fp->get();
#endif
         }
#if 0
         DLOG("copied: pn=%d frame=%d rhs.frame=%d shared=%d\n", i,
               at(i).frame, rhs[i].frame, at(i).shared);
#endif

      }
   }

   at(0).frame = FRAME_INVALID;

   fp->unlock();
}

PageTable::~PageTable() {
   fp->lock();

   /* this will cover up to the last page. */
   size_t len = (MAX_PAGES-2)*PAGE_SIZE; 

   /* first page should've never been allocated -- so it's safe to skip */
   deallocate(PAGE_SIZE, len);

   fp->unlock();
}

PtEntry PageTable::lookup(const Page pn) const {
   return at(pn);
}

ADDRINT PageTable::virt2phys(const ADDRINT vaddr) const {
   PtEntry pte = lookup(PAGE_NUM(vaddr));

   if (pte.frame <= 1) {
      DLOG("BUG: Accessed page without associated frame: vaddr=0x%x pte.frame=%d\n", vaddr, pte.frame);
   }
   ADDRINT paddr = (pte.frame << PAGE_SHIFT) | PAGE_OFFSET(vaddr);

   return paddr;
}

void PageTable::_deallocate(PtEntry* const pte) {
      ASSERT(pte->frame);

#if 0
      DLOG("_deallocate: shared: %d shmid: %d pgoff: %d\n", pte->shared,
            pte->shmid, pte->pgoff);
#endif

      /* don't check pte->shared, since that may be an anonymous mapping 
       * that doesn't have an entry in the shared segment map */
      if (pte->shmid) {
         /* This page corresponds to a shared segment or shared
          * mmaped file (i.e., MAP_SHARED). */
         ASSERT(pte->frame);

         SharedSegment *seg = sp->lookup(pte->shmid);
         ASSERT(seg);

         sp->put(seg, pte->pgoff);
      } else {
         /* Frame without an associated inode/shmid. */
         fp->put(pte->frame);
      }

      memset(pte, 0, sizeof(PtEntry));
}

void PageTable::deallocate(const ADDRINT start, const size_t len) {

   FOR_ALL_PAGES_IN_RANGE(start, len) {
      /* XXX: use valid_frame macro for this check */
      if (at(pn).frame) {
         _deallocate(&at(pn));
      }
   } END_ALL_PAGES_IN_RANGE;
}

void PageTable::allocate(const ADDRINT start, const size_t len, 
                              const Page pgoff, bool shared, const ShmId shmid) {
   SharedSegment *ssp = NULL;

   if (shmid) {
      /* This will allocate a SharedSegment for this shmid 
       * if it hasn't been done already. */
      ssp = sp->get(shmid, pgoff, len);
   }

#if 0
   DLOG("allocate: start=0x%x len=%d shared=%d shmid=%d\n",
         start, len, shared, shmid);
#endif

   FOR_ALL_PAGES_IN_RANGE(start, len) {

      /* what if the page already has a frame
       * allocated? -- delloacate existing page and then
       * allocate it. */
      if (at(pn).frame) {
         ASSERT(at(pn).frame != FRAME_INVALID);
         _deallocate(&at(pn));
      }

      Page pidx = pgoff + (pn - startPage);

      if (shmid) {
         ASSERT(shared);
         ASSERT(pgoff != OFFSET_INVALID);
         ASSERT(ssp);

         at(pn).frame = sp->get(ssp, pidx);
      } else {
         at(pn).frame = fp->get();
      }

      at(pn).shared = shared;
      at(pn).shmid = shmid;
      at(pn).pgoff = (pgoff == OFFSET_INVALID) ? OFFSET_INVALID : pidx;

   } END_ALL_PAGES_IN_RANGE;
}

ADDRINT PageTable::find_free_block(const size_t bytes) {

   ASSERT(bytes > 0);
   ASSERT(PAGE_ALIGNED(bytes));
   Page rounded_pgsize = POW2_ALIGN(PAGE_NUM(bytes));

   /* Find a region of free (zero) pages of @bytes bytes and
    * allocate them (set them to one).  Only consider regions of length
    * a power (@pg_order) of two, aligned to that power of two, which
    * makes the search algorithm much faster. */
   ASSERT(rounded_pgsize > 0);
   Page pn;

   for (pn = 0; pn < MAX_PAGES; pn += rounded_pgsize) {
      if (is_region_free(pn, rounded_pgsize)) {
         break;
      }
   }

   /* First page is not allocatable. */
   ASSERT(pn != 0);

   /* XXX: can't find a good spot -- most likely due to fragementation.
    * hope this doesn't happen, but deal with it when it does */
   ASSERT(pn < MAX_PAGES);

   return (pn * PAGE_SIZE);
}
