#include "vkernel/public.h"
#include "private.h"

static INLINE u64
GlobalAddrFromVmaOff(const struct VmaStruct *vma_ptr, const ulong vma_off, const int is_read)
{
   u64 gaddr;

   ASSERT(vma_off < vma_ptr->len);
   ASSERT_KPTR(vma_ptr->mm);

   /* Accesses to SHARED memory mapped files are equivalent to reads and
    * writes from/to from the file.
    *
    * XXX: Accesses to PRIVATE memory mapped files are equivalent to
    * an access from the file on first page access, and reads/writes to the
    * private page on subsequent accesses.
    */

   if (vma_ptr->file && (vma_ptr->flags & MAP_SHARED)) {
      struct InodeStruct *inode = File_Inode(vma_ptr->file);
      u32 off = (vma_ptr->pgoff * PAGE_SIZE) + vma_off;

      gaddr = GlobalAddr_MakeInodeAddr(inode, off);
   } else {
      /* XXX: first access to private map should be mapped as access to
       * underlying file. */
      ASSERT(!(vma_ptr->flags & MAP_SHARED));
      D__;
      gaddr = GlobalAddr_MakeMemAddr(vma_ptr->mm, vma_ptr->start+vma_off);
   }
   DEBUG_MSG(5, "gaddr=0x%llx\n", gaddr);

   return gaddr;
}

#if 0
/*
 * Returns the global address of the memory object being accessed 
 * at virtual address byte @vaddr. The object being accessed depends
 * on the kind of access, hence the @is_read parm.
 *
 * XXX: Function is potentially called for every memory read and
 * write. It has to be fast.
 */
static INLINE int
GlobalAddrFromVirtUnlocked(struct MmStruct *mm_ptr, GAddr *gaddr_ptr,
                           const ulong vaddr, const int is_read)
{
   ASSERT_UPTR((void*)vaddr);
   ASSERT(vaddr >= PAGE_SIZE);
   ASSERT(Vma_IsLocked(mm_ptr));

   struct VmaStruct *vma_ptr = mm_ptr->cached_vma;


   /* Observation: consecutive calls to this function tend to refer to
    * the same vma. So check the previously cached vma first. */
   if (!(vma_ptr && Vma_Intersects(vma_ptr, vaddr, 1, NULL))) {
      vma_ptr = Vma_Find(mm_ptr, vaddr);
      mm_ptr->cached_vma = vma_ptr;
   }

   WARN_MSG(
         vma_ptr,
         "Couldn't find vma for vaddr 0x%x on a %s.\n",
         vaddr, is_read ? "read" : "write"
         );

   if (vma_ptr) {
      *gaddr_ptr = GlobalAddrFromVmaOff(vma_ptr, vaddr - vma_ptr->start,
         is_read);
      return 0;
   } else {
      return -1;
   }
}

#if DEBUG
static INLINE void
DebugCheckContiguousGaddrRange(u64 *gAddrA, size_t len)
{
   int i;
   for (i = 0; i < len; i++) {
      ASSERT(gAddrA[0] == gAddrA[i] - i);
   }
}
#endif


size_t
GlobalAddr_FromRange(struct MmStruct *mm_ptr, u64 *gAddrA, 
                     const ulong vaddr, const size_t len, 
                     const int is_read)
{
   ASSERT_KPTR(gAddrA);

   size_t i, nr_addrs_translated = 0;
   /*
    * Why do we need to acquire the vmaLock? Because there could
    * be a concurrent memory-mapping modification -- another thread
    * may be removing or adding a mapping. There are two cases:
    *
    * 1. The other thread concurrently adds/removes a mapping
    *    unrelated to this access.
    *
    *    In this case, we still need the vmaLock to ensure that
    *    we don't see that vma data-structures in an inconsistent 
    *    state.
    *
    * 2. The other thread concurrently removes the mapping
    *    at which @vaddr lies. 
    *
    *    This case is more complicated -- see design notes above, but
    *    in short, we employ a barrier/IPI concoction to ensure that 
    *    access-update races are serialized -- which means that
    *    we get determinism here.
    *
    */

   UNORDERED_LOCK(&mm_ptr->vmaLock);

   for (i = 0; i < len; i++) {
      if (GlobalAddrFromVirtUnlocked(mm_ptr, &gAddrA[i], vaddr+i, 
               is_read)) {
         break;
      } else {
         nr_addrs_translated++;
      }
   }

   UNORDERED_UNLOCK(&mm_ptr->vmaLock);
   return nr_addrs_translated;
}
#endif

size_t
GlobalAddr_FromRange2(struct MmStruct *mm_ptr, 
                      struct GAddrRange *rangeA, 
                      int *maxNrRangesP, const ulong vaddr, 
                      const size_t len, const int is_read)
{
   /* XXX: avoid Find using a cache? */
   int i = 0;
   struct VmaStruct int_vma;
   const int maxNr = *maxNrRangesP;
   size_t nr_addrs_translated = 0;

   ASSERT(maxNr > 0);

   UNORDERED_LOCK(&mm_ptr->vmaLock);

   /* XXX: would caching vma_ptr help? */
   struct VmaStruct *vma_ptr = Vma_Find(mm_ptr, vaddr);

   while (vma_ptr && Vma_Intersects(vma_ptr, vaddr, len, &int_vma) && 
          i < maxNr) {

      DEBUG_MSG(5, "vma: start=0x%x len=%d\n", vma_ptr->start, vma_ptr->len);
      ASSERT(int_vma.start >= vma_ptr->start);
      const size_t vma_off = int_vma.start - vma_ptr->start; 
      GAddr range_start = GlobalAddrFromVmaOff(vma_ptr, vma_off, is_read);
      size_t range_len = int_vma.len;

      rangeA[i].start = range_start;
      rangeA[i].len = range_len;
      ASSERT(vaddr <= GlobalAddr_GetVAddr(range_start) &&
            GlobalAddr_GetVAddr(range_start) <= vaddr+len);
      DEBUG_MSG(5, "%d: 0x%llx %d\n", i, range_start, range_len);

      vma_ptr = Vma_NextNoWrap(vma_ptr);
      i++;
      nr_addrs_translated += range_len;
   }

   UNORDERED_UNLOCK(&mm_ptr->vmaLock);

   *maxNrRangesP = i;

   ASSERT(*maxNrRangesP > 0);
   ASSERT(*maxNrRangesP <= maxNr);

   return nr_addrs_translated;
}


#if 0
void
GlobalAddr_FromVma(struct MmStruct *mm_ptr, u64 *gAddrA, 
                   const struct VmaStruct *vma_ptr, const ulong off, 
                   const size_t len, const int is_read)
{
   ASSERT_KPTR(gAddrA);

   size_t i;

   UNORDERED_LOCK(&mm_ptr->vmaLock);

   for (i = 0; i < len; i++) {
      gAddrA[i] = GlobalAddrFromVmaOff(vma_ptr, off+i, is_read);
   }

   UNORDERED_UNLOCK(&mm_ptr->vmaLock);
}
#endif

#if 0
#error "XXX: should return error code on bad translation"
u64
GlobalAddr_FromVirt(struct MmStruct *mm_ptr, const ulong vaddr, 
                    const int is_read)
{
   u64 gaddr;

   GlobalAddr_FromRange(mm_ptr, &gaddr, vaddr, 1, is_read);

   return gaddr;
}
#endif
