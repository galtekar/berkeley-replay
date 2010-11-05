/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

/*
 * Summary:
 *
 * What memory locations/regions should be the targets of loads and
 * stores with symbolic pointers?
 */

// XXX: unimplemented, due to several barries
//    - OOM due to byte-level taint mapping; we'll probably need a
//    multilevel taint lookup table
#define CONSIDER_ALL_WRITABLE_PAGES 0

#if MAX_NR_VCPU > 1 && PRODUCT
#error "XXX: needs to be locked"
#else
struct VirtRange ptrRegions[MAX_PTR_REGIONS] = { {0} };
int nrPtrRegions = 0;
#endif

static int
cgFindFreeRegionSlot()
{
   int i;

   for (i = 0; i < MAX_PTR_REGIONS; i++) {
      struct VirtRange *rP = &ptrRegions[i];
      if (rP->start == 0) {
         return i;
      }
   }

   return -1;
}

int
Cgen_AddPtrRegion(const ulong start, const size_t len)
{
#if MAX_NR_VCPU > 1 && PRODUCT
#error "XXX: needs to be locked"
#endif
   int err = 0;

   DEBUG_MSG(5, "start=0x%x:0x%x len=%lu\n", start, start+len, len);

   const int id = cgFindFreeRegionSlot();

   if (id >= 0) {
      ptrRegions[id].start = start;
      ptrRegions[id].len = len;
      nrPtrRegions++;
   } else {
      err = -1;
   }

   return err;
}

int
Cgen_RmPtrRegion(const int id)
{
#if MAX_NR_VCPU > 1 && PRODUCT
#error "XXX: needs to be locked"
#endif
   int err = 0;

   ASSERT_MSG(id >= 0 && id < MAX_PTR_REGIONS, "id=%d", id);

   if (ptrRegions[id].start) {
      DEBUG_MSG(5, "start=0x%x len=%lu\n", ptrRegions[id].start,
            ptrRegions[id].len);
      ptrRegions[id].start = 0;
      nrPtrRegions--;
   } else {
      err = -1;
   }

   return err;
}

#if 0
static int
cgRmPtrRegionByRange(const ulong start, const size_t len)
{
   int err = -1, i;

   DEBUG_MSG(5, "start=0x%x:0x%x len=%lu\n", start, start+len, len);

   for (i = 0; i < MAX_PTR_REGIONS; i++) {
      const struct VirtRange *rP = &ptrRegions[i];
      if (rP->start == start && rP->len == len) {
         return Cgen_RmPtrRegion(i);
      }
   }
  
   return err;
}
#endif

#if CONSIDER_ALL_WRITABLE_PAGES
static void
cgPtrVmaIterCb(const struct VmaStruct *vmaP, void *dataP)
{
   if (vmaP->prot & PROT_WRITE) {
      Cgen_AddPtrRegion(vmaP->start, vmaP->len);
   }
}
#endif


void
cgPtr_OnVmaEvent(const VmaEventKind evk, const struct VmaStruct *vmaP,
                 const ulong istart, const size_t ilen)
{
   ASSERT_KPTR(vmaP);
   ASSERT(PAGE_ALIGNED(vmaP->start));
   ASSERT(PAGE_ALIGNED(vmaP->len));

   DEBUG_MSG(5, "vmk=0x%x (0x%x, %lu) istart=0x%x ilen=%lu\n", evk, 
         vmaP->start, vmaP->len, istart, ilen);

#if 0
   /* XXX: Unmaps may be subranges of previously mapped ranges, and this
    * has been tracked carefully. Too much work. */
#error "XXX: unimplemented"
   ulong start = vmaP->start;
   size_t len = vmaP->len;

   switch (evk) {
   case Vek_Map:
   case Vek_PostProtect:
      if (vmaP->prot & PROT_WRITE) {
         int id = Cgen_AddPtrRegion(start, len);
         ASSERT(id >= 0);
      }
      break;
   case Vek_Unmap:
      start = istart;
      len = ilen;
   case Vek_PreProtect:
      if (vmaP->prot & PROT_WRITE) {
         int err = cgRmPtrRegionByRange(start, len);
         ASSERT(!err);
      }
      break;
   default:
      break;
   }
#elif CONSIDER_ALL_WRITABLE_PAGES
   // Above clause doesn't work yet; this is a quick workaround
   memset(ptrRegions, 0, sizeof(ptrRegions));
   nrPtrRegions = 0;

   Vma_Iterate(&cgPtrVmaIterCb, NULL);
#endif
}
