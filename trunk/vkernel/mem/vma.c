#include "vkernel/public.h"
#include "private.h"

/* 
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * === Why shadow the kernel's memory mappings? ===
 *
 * o We need to associate each mapped page with a globally unique sharing
 * identifier (not to be confused with the frame number corresponding to
 * physical memory used within the kernel). Two virtual pages that refer
 * to the same physical page have the same sharing id (but they may not
 * have the same frame number, since one or both of those virtual pages may
 * not be mapped yet). Keeping track of this sharing id requires that
 * we maintain shadow mappings.
 *
 * o Linux may not place regions outside the vkernel area as we desire.
 * In that case, we need to pick a suitable region. But what region is
 * suitable? We can use proc/maps to figure this out, but that's too slow.
 * Linux vma support functions can handle this stuff, and so a kernel
 * module may seem appropriate here, but some platforms don't
 * support (or are unwilling to use) kernel modules (e.g., PlanetLab).
 *
 *
 * === How do we replay concurrent accesses to the TLB? === 
 *
 * o This is an important question -- we must ensure that accesses
 * are made to the same location and same file object, whether they
 * are shared memory segments, files, or anonymous mappings. 
 * Without this, we cannot deterministically detect races, since 
 * accesses may be to different objects during replay.
 *
 * o In the easy case, multiple threads concurrently update the page
 * table via mmap()/mprotect()/munmap()/shmat(), etc.. We serialize
 * these updates via the current->mm->vmaLock, which is an ordered
 * lock and hence will be acquired in the same order during replay.
 *
 * o The more challenging case is when some threads read the
 * page table and others concurrently update it. For example,
 * thread 1 reads from memory location a, while another thread tries
 * to munmap(page_at(a)). The ordering in which these operations
 * occurs determines whether thread 1 SIGSEGVs or not and hence
 * must be deterministic. More importantly, the ordering
 * determines whether there is a race or not.
 *
 * A simple solution is to synchronize access to the VMA list
 * before the mapping change and each access, and then to replay 
 * the ordering of synchronization. But doing this is prohibitive, 
 * since it requires logging a logical clock value for each access 
 * (and also for each PTE change), not to mention that we must
 * instrument every read and write during logging.
 *
 * This is the best approach I have so far:
 *
 * Another approach is to serialize accesses with respect 
 * to VMA list changes, but not with respect to other accesses.
 * We can do this by stopping all other threads (via IPI) when a thread 
 * initiates a VMA list change (e.g., via mmap, munmap, shmat, 
 * shmdt). We then let the intiating thread change the mapping and 
 * signal the others when it is done -- ie., a barrier. 
 * During replay, we require that all threads stop and wait for the 
 * VMA change before continuing. 
 *    o Stopping threads is expensive, but we need only stop each
 *    VCPU -- that doesn't sound as bad for small VCPU counts
 *
 * XXX: Here's an approach that doesn't work:
 *
 * A more practical, but more tricky approach is to detect conflicting 
 * TLB accesses and enforce an ordering. We can detect conflicts
 * by removing access permissions on the new mapping for all VCPUs 
 * (via mmap(PROT_NONE)). The first task on any VCPU to access
 * pages in the mapping will each then fault, log the fault occurrence,
 * and acqiure the vmaLock before restoring permissions and continuing. 
 * Since we logged the fault's execution point, we can ensure that
 * the fault occurs during replay. And because we acquired the vmaLock
 * within the fault handler, we are guaranteed that, during replay, 
 * concurrent accesses will occur after the mapping update.
 *
 * XXX: but what if the concurrent access occurred before the update,
 * but during replay, happens after? how do we enforce the original 
 * ordering in that case?
 *
 *
 * ----------------------------------------------------------------------------
 */

#define MAP_TYPE     0x0f		/* Mask for type of mapping */
#define MAP_GROWSUP	0x0200	/* register stack-like segment */
#define SHMLBA       PAGE_SIZE
#define SHM_EXEC	   0100000	/* execution access */

static INLINE void
VmaCleanseArgs(int *prot) {
   /* Cleanse prot: OpenJDK may ask for a 0x1000007 prot, where the
    * higher order bit doesn't mean anything -- could be a bug. But
    * mprotect must work regardles. */
   *prot = *prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
}

void
Vma_Print(const struct VmaStruct *vma)
{
   DEBUG_MSG(1, "start=0x%x len=%lu pgoff=%d prot=0x%x file=0x%x (%s)\n",
         vma->start, vma->len, vma->pgoff, vma->prot, vma->file, 
         vma->file ? File_Dentry(vma->file)->name : "NONE");

   if (!vma->file) {
      ASSERT(vma->pgoff == PAGE_NUM(vma->start));
   }
}

void
Vma_PrintAll()
{
   struct VmaStruct *vma;

   ASSERT(Vma_IsLocked(current->mm));

   list_for_each_entry(vma, &current->mm->vmaList, list) {
      Vma_Print(vma);
   }
}

void
Vma_Iterate(VmaIterCB cb, void *dataP)
{
   ASSERT_KPTR(cb);

   struct VmaStruct *vma;

   UNORDERED_LOCK(&current->mm->vmaLock);

   list_for_each_entry(vma, &current->mm->vmaList, list) {
      cb(vma, dataP);
   }

   UNORDERED_UNLOCK(&current->mm->vmaLock);
}

static INLINE int
VmaIsSubsetEq(const struct VmaStruct *vma, ulong start, size_t len)
{
   return (start <= vma->start) && ((vma->start+vma->len) <= (start+len));
}


/* Does @vma intersect the range [start, start+len)? */
int
Vma_Intersects(const struct VmaStruct *vma, ulong start, size_t len, 
      /* XXX: ivma should really be a range, not a full-gledged vmastruct
       */
               struct VmaStruct *ivma)
{
   int res = 0;
   ulong ivma_start = 0, ivma_len = 0;

   ASSERT(vma);
   ASSERT(ivma || !ivma);
   ASSERT(vma->len);

   res = MemOps_Intersects(vma->start, vma->len, start, len, 
            &ivma_start, &ivma_len);

   if (ivma) {
      ivma->start = ivma_start;
      ivma->len = ivma_len;

      if (res) {
         ASSERT(VmaIsSubsetEq(ivma, vma->start, vma->len));
      }
   }

   DEBUG_MSG(7, "irange:0x%x,0x%x vma: 0x%x,0x%x ivma: 0x%x,0x%x res=%d\n",
         start, len, vma->start, vma->len, ivma_start, ivma_len, res);

   return res;
}

struct VmaStruct*
VmaAlloc()
{
   struct VmaStruct *vma;

   vma = SharedArea_Malloc(sizeof(*vma));

   memset(vma, 0, sizeof(*vma));

   return vma;
}

void
VmaFree(struct VmaStruct *vma)
{
   /* Must be unlinked before it can be freed. */
   ASSERT(vma->mm == NULL);
   SharedArea_Free(vma, sizeof(*vma));
}

/* Insert vma into the vma list sorted by region range. */
static void
VmaLink(struct MmStruct *mm, struct VmaStruct *nvma)
{
   struct VmaStruct *vma;
   struct ListHead *targetHead = &mm->vmaList;

#if DEBUG
   /* XXX: enable this assert once we've locked 
    * tsk->mm on fork. */
   //   ASSERT(Vma_IsLocked(mm));
   ASSERT(nvma);
   ASSERT(nvma->len);
   ASSERT(nvma->start >= PAGE_SIZE);
   if (!(nvma->extraFlags & MAP_EXTRA_PERMANENT)) {
      ASSERT(nvma->start <= __LINUX_KERNEL_START);
   }
#endif

   list_for_each_entry(vma, &mm->vmaList, list) {
      ASSERT(vma->mm == mm);

      if (nvma->start < vma->start) {
         ASSERT((nvma->start+nvma->len) <= vma->start);
         targetHead = &vma->list;
         break;
      } 
   }

   /* Make nvma targetHead's predecessor. Note that
    * if nvma is the largest element, then this is 
    * equivlanet to inserting nvma at the end of the list. */
   List_AddTail(&nvma->list, targetHead);

   nvma->mm = mm;
   ASSERT(nvma->mm);
}

/* Unlink but don't free the vma. */
static void
VmaUnlink(struct VmaStruct *vma)
{
   ASSERT(vma);
   ASSERT(Vma_IsLocked(vma->mm));

   /* Invalidate the cached vma -- since it's about
    * to be unlinked we can't use it to speed lookups. */
   if (vma->mm->cached_vma == vma) {
      vma->mm->cached_vma = NULL;
   }

   List_Del(&vma->list);
   vma->mm = NULL;
}

/* Find first vma intersecting (i.e., not necessarily starting at) 
 * the given range. Null if no such vma. */
struct VmaStruct *
Vma_FindIntersect(struct MmStruct *mm_ptr, ulong start, size_t len)
{
   struct VmaStruct *vma;

   ASSERT(Vma_IsLocked(mm_ptr));

   list_for_each_entry(vma, &mm_ptr->vmaList, list) {
      if (Vma_Intersects(vma, start, len, NULL)) {
         mm_ptr->cached_vma = vma;
         ASSERT(vma->mm);
         return vma;
      }
   }

   return NULL;
}

/* Find first vma at or immediately after addr (i.e., a vma such that 
 * addr < vm_end). Null if no such vma.  */
struct VmaStruct *
Vma_Find(const struct MmStruct *mm_ptr, ulong addr)
{
   struct VmaStruct *vma;

   ASSERT(Vma_IsLocked(mm_ptr));

   list_for_each_entry(vma, &mm_ptr->vmaList, list) {
      if (addr < vma->start+vma->len) {
         return vma;
      }
   }

   return NULL;
}

#if 0
/* XXX: Return true iff to-be-allocated vma [addr, addr+len] can
 * be merged with its predecessor, successor, or both. */
static int
VmaMerge(struct VmaStruct *prev, ulong addr, size_t len)
{
   /* XXX: this is really an optimization -- defer implementating
    * until all major functionality is in place. 
    *
    * This is tricky, since you must do this for mmaps
    * and mprotects. In the latter case, the vma already
    * exists. */

   return 0;
}
#endif

/* 
 * Make a hole in the VMA range [istart, istart+ilen],
 * possibly splitting the VMA in the process.
 *
 * Returns number of fragments created as a result of the split.
 * (0 fragments <==> entire vma, 1 fragment <=> shrink vma, 
 *  2 fragments <=> split vma). 
 */
static int
VmaSplit(struct VmaStruct *vma, ulong istart, ulong ilen)
{
   struct VmaStruct *nvma = NULL;
   int splitCount = 0;
   ulong vma_start, vma_end, iend;

   ASSERT(vma);

   vma_start = vma->start;
   vma_end = vma->start + vma->len;
   iend = istart + ilen;

   ASSERT(PAGE_ALIGNED(istart));
   ASSERT(PAGE_ALIGNED(ilen));
   ASSERT(PAGE_ALIGNED(iend));
   ASSERT(PAGE_ALIGNED(vma_start));
   ASSERT(PAGE_ALIGNED(vma_end));

  
   ASSERT(istart >= vma_start);
   ASSERT(vma_end >= iend);

   if ((istart - vma_start) && (vma_end - iend)) {
      /* Split -- shrink vma and create new fragment (nvma). */
      splitCount = 2;

      vma->len = istart - vma_start;

      nvma = VmaAlloc();
      *nvma = *vma;
      nvma->start = iend;
      nvma->len = vma_end - iend;
      ASSERT(nvma->start > vma_start);
      nvma->pgoff = vma->pgoff + PAGE_NUM(nvma->start - vma_start);

      if (nvma->file) {
         File_GetFile(nvma->file);
      }
      VmaLink(vma->mm, nvma);
      if (nvma->ops && nvma->ops->open) {
         nvma->ops->open(nvma);
      }
   } else if (istart - vma_start) {
      /* Shink: chop off the bottom of the vma. */
      splitCount = 1;

      vma->len = istart - vma_start;
   } else if (vma_end - iend) {
      /* Shrink: chop off the top of the vma. */
      splitCount = 1;

      vma->start = iend;
      vma->len = vma_end - iend;
      vma->pgoff = vma->pgoff + PAGE_NUM(vma->start - vma_start);
   } else {
      /* Entire vma intersects. Action depends on whether we want
       * to unmap the vma or change protections. */ 
      splitCount = 0;
   }

   return splitCount;
}

/*
 * This gets called on the mm free path and on the munmap path,
 * which makes it an ideal place to invoke unmap callbacks.
 * Note that we don't Linux munmap the vma even though this
 * is invoked on the mm free path --- there is no need since the
 * address space is about to be destroyed anyway.
 */
static void
VmaDoUnmap(struct VmaStruct *vma, ulong istart, size_t ilen)
{
   int splitCount;

   ASSERT(Vma_IsLocked(vma->mm));

   Vma_Print(vma);

   /* Unmap callbacks want to know when a vma is being unmapped
    * for various purposes. 
    *
    * XXX: should roll TrnsTab callback into BT callback.
    * */
   TrnsTab_OnVmaUnmap(vma, istart, ilen);
   Module_OnVmaEvent(Vek_Unmap, vma, istart, ilen);

   splitCount = VmaSplit(vma, istart, ilen);

   if (!splitCount) {
      /* Entire vma lies in region. Unmap all of it. */
      if (vma->ops && vma->ops->close) {
         vma->ops->close(vma);
      }

      VmaUnlink(vma);
      if (vma->file) {
         File_Put(vma->file);
      }
      VmaFree(vma);
      vma = NULL;
   } else  {
      /* vma shrunk. new vma fragment created (if splitCount == 2). 
       * Nothing to do, since there is now a hole at
       * [ivma.start, ivma.start+ivma.len] as desired:
       *    - No need to call vma->ops->close, since
       *    vma is still open (but shrunk). */
   }
}

static int
VmaUnmapHelper(ulong start, size_t len)
{
   int err = 0, res;
   struct VmaStruct *vma, *tmp, ivma;

   ASSERT(Vma_IsLocked(current->mm));

   vma = Vma_FindIntersect(current->mm, start, len);

   list_for_each_entry_safe_from(vma, tmp, &current->mm->vmaList, list) {
      if (!Vma_Intersects(vma, start, len, &ivma)) {
         break;
      }

      if (vma->extraFlags & MAP_EXTRA_PERMANENT) {
         /* The VDSO is an example of this type of mapping. We can't
          * unmap it at CPL 3 so we leave it there. */
         continue;
      }


      VmaDoUnmap(vma, ivma.start, ivma.len);
      vma = NULL;

      /* munmapping each region, rather than the entire [start, start+len]
       * range ensures that user-mode never unmaps vkernel pages. */
      /* Note that unmap will work for both shmsegs and anonymous mapping. */
      res = syscall(SYS_munmap, ivma.start, ivma.len);
      ASSERT(!SYSERR(res));

#if 0
      /* XXX: We can't move the sys_munmap out of this loop, but is
       * there any harm in moving the trap_deinstrument out of the loop? */
      Trap_UnMap(ivma.start, ivma.len);
#endif
   }

   return err;
}


int
Vma_UnMap(ulong addr, size_t len)
{
   int err = 0;

   if ((addr & ~PAGE_MASK) || addr > __LINUX_KERNEL_START || 
         len > __LINUX_KERNEL_START-addr) {
      err = -EINVAL;
      goto out;
   }

   len = PAGE_ALIGN(len);

   if (!PAGE_ALIGNED(len) || len == 0) {
      err = -EINVAL;
      goto out;
   }

   /* Linux returns 0 even if no regions were unmapped. */
   err = VmaUnmapHelper(addr, len);

out:
   return err;
}

int
Vma_Protect(ulong start, size_t len, int prot)
{
   int err = 0, res, splitCount;
   struct VmaStruct *vma, *tmp, ivma;

   VmaCleanseArgs(&prot);

   DEBUG_MSG(5, "start=0x%x len=0x%x (%d) prot=0x%x\n",
         start, len, len, prot);

   ASSERT(Vma_IsLocked(current->mm));


   if (!PAGE_ALIGNED(start)) {
      err = -EINVAL;
      goto out;
   }

   if (!len) {
      /* You would think this should be an error, but Linux doesn't. */
      err = 0;
      goto out;
   }

   len = PAGE_ALIGN(len);

   if ((start+len) <= start) {
      err = -ENOMEM;
      goto out;
   }


   vma = Vma_FindIntersect(current->mm, start, len);

   /* Use safe traversal, since VmaSplit may unlink elements. */
   list_for_each_entry_safe_from(vma, tmp, &current->mm->vmaList, list) {
      ulong vma_start, vma_pgoff;

      if (!Vma_Intersects(vma, start, len, &ivma)) {
         break;
      }

      if (vma->prot == prot) {
         /* No need to split. */
         continue;
      }

      /* VmaSplit will will adjust vma to accomodate the split, so save
       * current values -- we'll need them below. */
      vma_start = vma->start;
      vma_pgoff = vma->pgoff;

      Module_OnVmaEvent(Vek_PreProtect, vma, 0, 0);

      splitCount = VmaSplit(vma, ivma.start, ivma.len);

      DEBUG_MSG(5, "splitCount=%d ivma: 0x%x,0x%x\n", splitCount, 
            ivma.start, ivma.len);
      if (splitCount == 0) {
         /* Entire vma changed protections. Note that we needn't call close
          * since, unlike the unmap case, the vma still exists (but with
          * different protections). */
         vma->prot = prot;
      } else {
         /* XXX: we should try to merge vmas, in case the protection change
          * wasn't really a change at all. */
         /* Protection change applied to only a part of the vma. So the vma 
          * had to be shrunk, and possiblly a new vma fragment was created 
          * (if splitCount == 2). Must allocate new region in the hole at
          * [ivma.start, ivma.start+ivma.len] with desired protection. */
         struct VmaStruct *pvma;

         pvma = VmaAlloc();
         *pvma = *vma;
         pvma->start = ivma.start;
         pvma->len = ivma.len;
         pvma->prot = prot;

         ASSERT(pvma->start >= vma_start);
         pvma->pgoff = vma_pgoff + PAGE_NUM(pvma->start - vma_start);
         if (pvma->file) {
            File_GetFile(pvma->file);
         }
         VmaLink(current->mm, pvma);

         Module_OnVmaEvent(Vek_PostProtect, pvma, 0, 0);
      }
      Module_OnVmaEvent(Vek_PostProtect, vma, 0, 0);


      /* Mprotecting each region, rather than the entire [start, start+len]
       * range ensures that user-mode never changes protections on
       * vkernel pages. */
      ASSERT_UNIMPLEMENTED(!(prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC)));
      res = syscall(SYS_mprotect, ivma.start, ivma.len, prot);
      DEBUG_MSG(5, "ivma: start=0x%x len=0x%x (%d) prot=0x%x res=%d\n",
            ivma.start, ivma.len, ivma.len, prot, res);
      ASSERT(!SYSERR(res));
   }

out:
   return err;
}

static int
VmaIsShmThatStartedAt(const struct VmaStruct *vma, ulong addr)
{
   return (vma->file && 
           Inode_GetMajor(File_Inode(vma->file)) == InodeMajor_Shm &&
           Inode_GetMinor(File_Inode(vma->file)) == InodeMinor_ShmNamed &&
           (PAGE_NUM((vma->start - addr)) == vma->pgoff));
}

int
Vma_ShmDt(ulong addr)
{
   int err = -EINVAL;
   struct VmaStruct *vma, *tmp, *found = NULL;

   ulong shmSize;

   ASSERT(Vma_IsLocked(current->mm));

   if (!PAGE_ALIGNED(addr)) {
      goto out;
   }

   /* Recall that vmas, even those representing shm segments,
    * can be split. This happens, for example, when a shm vma
    * is partially munmapped/mprotected. Linux behavior is such 
    * that, upon sys_shmdt, all fragments of the original shm segment 
    * are detached. The main challenge here, unlike that of munmap, 
    * is to determine the size of the attach point of original 
    * shm segment and deallocate all shm vmas in that range. */

   vma = Vma_Find(current->mm, addr);

   /* To find the size of the shared segment, we must find a fragment of it. */
   list_for_each_entry_from(vma, &current->mm->vmaList, list) {
      /* Would this fragment have started at addr? */
      if (VmaIsShmThatStartedAt(vma, addr)) {
         struct ShmStruct *shmp;

         shmp = ShmFs_GetStruct(File_Inode(vma->file));
         ASSERT(!IS_ERR(shmp));

         shmSize = shmp->size;

         ASSERT(VmaIsSubsetEq(vma, addr, shmp->size));
         found = vma;
         break;
      }
   }


   vma = found;
   list_for_each_entry_safe_from(vma, tmp, &current->mm->vmaList, list) {
      if (!VmaIsSubsetEq(vma, addr, shmSize)) {
         break;
      }

      if (VmaIsShmThatStartedAt(vma, addr)) {
         err = VmaUnmapHelper(vma->start, vma->len);
      }
   }

out:
   return err;
}

/* Returns the address of a @allocBytes contiguous free region
 * in the range [start, start+len]. */
static ulong
Vma_FindFreeArea(ulong start, size_t len, ulong allocBytes)
{
   ulong addr = -ENOMEM;
   ulong freeStart, rangeEnd = start+len;
   struct VmaStruct *vma;

   ASSERT(allocBytes);

   if (allocBytes > len) {
      goto out;
   }

   D__;
   vma = Vma_FindIntersect(current->mm, start, len);
   if (!vma) {
      /* No vmas in the region -- we're good to go. */
      D__;
      addr = start;
      goto out;
   }

   Vma_Print(vma);

   if (vma->start < start) {
      freeStart = vma->start + vma->len;
      //vma = list_entry(vma->list.next, struct VmaStruct, list);
      vma = Vma_Next(vma);
   } else {
      freeStart = start;
   }

   /* Find a hole of @allocBytes between the vmas in the
    * specified region. */
   DEBUG_MSG(5, "Trying to find a hole of %d bytes.\n",
         allocBytes);
   list_for_each_entry_from(vma, &current->mm->vmaList, list) {
      ulong vma_end = vma->start + vma->len;

      Vma_Print(vma);

      D__;

      if (!Vma_Intersects(vma, start, len, NULL)) {
         break;
      }

      ASSERT(vma->start >= freeStart);
      if (vma->start - freeStart >= allocBytes) {
         addr = freeStart;
         goto out;
      } else {
         freeStart = vma_end;
      }
   } 

   /* vma is not in range, but there is a hole
    * in [freeStart, rangeEnd]. */

   if (freeStart < rangeEnd) {
      if (rangeEnd - freeStart >= allocBytes) {
         addr = freeStart;
         goto out;
      }
   } else {
      /* Here if last intersecting vma exceeds rangeEnd. */
   }

out:
   DEBUG_MSG(5, "addr=0x%x (%d)\n", addr, addr);
   return addr;
}

/* 
 * -----------------------------------------------------------------------
 * VmaGetUnmappedArea --
 *
 *    Choose a suitable starting address for a region of the specified
 *    size. Try to meet the start preference, but if the preference falls 
 *    inside kernel memory, suggest an alternative allocation that doesn't.
 *    Of course, if MAP_FIXED is used, then we must deny requests that 
 *    overlap with the vkernel.
 *
 * Results:
 *    Address of allocatable region.
 *
 * Side effects:
 *    None. Does not allocate the region -- that's up to the caller.
 * -----------------------------------------------------------------------
 */
static ulong
VmaGetUnmappedArea(ulong startPref, size_t len, int flags)
{
   ulong addr = startPref;
   struct VmaStruct tmpvma = { .start = startPref, .len = len };

   ASSERT(Vma_IsLocked(current->mm));

   /* BUG: MAP_FIXED with NULL start_pref should cause failure. */

   DEBUG_MSG(5, "start_pref=0x%x len=%d MAP_FIXED=%d\n",
         startPref, len, flags & MAP_FIXED);

   /* If the app insists on allocating in the arena, we must deny its
    * request. If the preference, on the other hand, is just a hint, then
    * we can pick something else. The goal is to adhere to mmap semantics. */

   if (startPref && Vma_Intersects(&tmpvma, __IMAGE_START, 
            __IMAGE_END - __IMAGE_START, NULL)) {
      if (flags & MAP_FIXED) {
         DEBUG_MSG(2, "App insists on allocating in vkernel arena.\n");
         addr = -EINVAL; goto out;
      } else {
         /* Let Region_FindFree() pick a region outside kernel space. */
         addr = 0;
      }
   }

   if (!(flags & MAP_FIXED)) {
      if (addr) {
         /* Try to find a spot within the preference zone. */
         addr = Vma_FindFreeArea(startPref, len, len);

         if (!SYSERR(addr)) {
            D__;
            ASSERT(addr == startPref);
            goto out;
         } else {
            ASSERT(addr == -ENOMEM);
            D__;

            /* Couldn't meet the preference, most likely because it was
             * occupied. We should default to finding
             * just some region.*/
         }
      }

      /* Find any spot before the arena, but leave the 1st page unmapped. */
      addr = Vma_FindFreeArea(PAGE_SIZE, __IMAGE_START - PAGE_SIZE, len);
      if (SYSERR(addr)) {
         ASSERT(addr == -ENOMEM);
         /* Don't try to find free space after the vkernel area -- there
          * is none. Te vkernel should be at the end of the address space,
          * and thus nothing can be mapped there. This makes
          * clearing the address space much simpler since we just
          * need one call to munmap. */
         goto out;
      }
   } else {
      /* If star pref is null, then MAP_FIXED shouldn't be set. 
       * Emulate the kernel's response. */
      if (!startPref) { addr = -EINVAL; goto out; }

      /* MAP_FIXED requests unconditionally get what they want (so long
       * as a preference is specified), and even if the region is already
       * mapped. The dynamic linker does this, for instance. 
       * So no need to look for a free region. */
      ASSERT(addr == startPref);
   }

out:
   DEBUG_MSG(5, "addr=0x%x (%d)\n", addr, addr);
   return addr;
}

static INLINE int
VmaMaybeExecutable(int flags) {
   /*
    * Executable code (e.g., shared liraries) is usually
    * backed by a file and MAP_PRIVATE (meaning writes to
    * the file don't affect the original file).
    */
   return !(flags & MAP_ANONYMOUS) && !(flags & MAP_SHARED);
}

ulong
Vma_Map(struct FileStruct *filp, ulong start, size_t len, int prot, 
        int flags, ulong pgoff)
{
   int err;
   ulong addr;
   struct VmaStruct *vma = NULL;

   VmaCleanseArgs(&prot);

   /* The final flags depend on other characteristics of the
    * mapping (e.g., if the file is not writeable then it cannot
    * be shared). We want to describe this while keeping the original
    * flags in tact. */
   int vmaFlags = flags;

	DEBUG_MSG(5, "addr=0x%x bytes=0x%x prot=0x%x flags=0x%x off=%d\n",
			start, len, prot, flags, pgoff);

   ASSERT(Vma_IsLocked(current->mm));

   if (filp) {
      if (!filp->f_op || !filp->f_op->mmap) {
         addr = -ENODEV;
         goto out;
      }
   }

   /*
    * Does PROT_READ imply PROT_EXEC? That depends on the
    * current OS ``personality''. 
    */
   if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC)) {
      /* XXX: if filp, must make sure file is not on fs mounted MNT_NOEXEC */
      ASSERT_UNIMPLEMENTED(0);
      prot |= PROT_EXEC;
   }

   if (!len) {
      addr = -EINVAL;
      goto out;
   }

   len = PAGE_ALIGN(len);
   if (!len || len > __LINUX_KERNEL_START) {
      addr = -ENOMEM;
      goto out;
   }

   /* XXX: why do we need this check? 5understand it... */
   if ((pgoff + (PAGE_NUM(len))) < pgoff) {
      addr = -EOVERFLOW;
      goto out;
   }

	addr = VmaGetUnmappedArea(start, len, flags);
   if (SYSERR(addr)) {
      goto out;
   }
   ASSERT_MSG(PAGE_ALIGNED(addr), "addr=0x%x len=%d flags=0x%x\n", 
         addr, len, flags);

   /* Do not permit prot that conflicts with file open mode. */
   if (filp) {
      switch (flags & MAP_TYPE) {
      case MAP_SHARED:
         if ((prot & PROT_WRITE) && !(filp->accMode & FMODE_WRITE)) {
            addr = -EACCES;
            goto out;
         }

#if 0
         /* XXX: How do we tell if the inode is append-only or not? */
         if (IS_APPEND(filp->inode) && (filp->accMode & FMODE_WRITE)) {
            addr = -EACCES;
            goto out;
         }
#endif

         if (!(filp->accMode & FMODE_WRITE)) {
            vmaFlags &= ~MAP_SHARED;
         }

         
         
         /* Fall through. */
      case MAP_PRIVATE:
         if (!(filp->accMode & FMODE_READ)) {
            addr = -EACCES;
            goto out;
         }
         break;
      default:
         /* MAP_ANONYMOUS not valid when a file is attached to the vma. */
         addr = -EINVAL;
         goto out;
         break;
      }
   } else {
      switch (flags & MAP_TYPE) {
      case MAP_SHARED:
         pgoff = 0;
         break;
      case MAP_PRIVATE:
         pgoff = PAGE_NUM(addr);
         break;
      default:
         addr = -EINVAL;
         goto out;
         break;
      }
   }

   /* Point of no return. Unmap any existing regions that overlap
    * with the vma we want to allocate. This is what Linux does and
    * so we must emulate. */
   if (Vma_FindIntersect(current->mm, addr, len)) {
      VmaUnmapHelper(addr, len);
   }

   /* XXX: Try to merge with the previous region. This is helpful for the
    * brk region, for instance. */
#if 0
   if (!filp && !(vmaFlags & MAP_SHARED) &&
         VmaMerge(prev, addr, len)) {
      goto out;
   }
#endif

   vma = VmaAlloc();

   vma->start =   addr;
   vma->len =     len;
   vma->prot =    prot;
   vma->flags =   vmaFlags;
   vma->pgoff =   pgoff;
   vma->file =    NULL;

   if (filp) {
      ASSERT(!(vma->flags & MAP_ANONYMOUS));

      if (vmaFlags & (MAP_GROWSDOWN | MAP_GROWSUP /* only on ia64 */)) {
         addr = -EINVAL;
         goto out_free;
      }

      /* XXX: deprecated, but Linux still has legacy support... */
      WARN_XXX(vma->flags & MAP_DENYWRITE);
      

      vma->file = File_GetFile(filp);
      ASSERT(vma->file);

   } else if (flags & MAP_SHARED) {
      ASSERT(Vma_IsLocked(current->mm));

      err = ShmFs_CreateAnonymous(vma);
      if (SYSERR(err)) {
         addr = err;
         goto out_free;
      }
      ASSERT(vma->file);
   }

   if (vma->file) {
      ASSERT(vma->file->f_op->mmap);

      err = vma->file->f_op->mmap(vma->file, vma);
      ASSERT_UNIMPLEMENTED(!err);
   } else {
      ASSERT(vma->flags & MAP_ANONYMOUS);
      /* Shared memory is always associated with a file struct. */
      ASSERT(!(vma->flags & MAP_SHARED));
      D__;
      Vma_Print(vma);
      err = syscall(SYS_mmap2, vma->start, vma->len, vma->prot,
            vma->flags, -1, 0);
      ASSERT(!SYSERR(err));
   }

   /* Unlike Linux, mmap callbacks shouldn't modify the starting address. */
   ASSERT(addr == vma->start);
   ASSERT(pgoff == vma->pgoff);
   ASSERT(vmaFlags == vma->flags);
   VmaLink(current->mm, vma);

   Module_OnVmaEvent(Vek_Map, vma, 0, 0);

#if 0
   /*
    * Note that we don't check for PROT_EXEC. That's because it may
    * not be present if the dynamic linker wants to perform
    * relocation (ld-2.7.so contains 11 relocations)--that section
    * is initially mapped without PROT_EXEC, and changed to PROT_EXEC
    * once relocations are performed.
    *
    * XXX: for now, check for PROT_EXEC --- this ensures that we don't
    * try and insert traps into data segments (which happens for
    * tests/8-rep without this hack).
    */
//#error "Can't check PROT_EXEC -- ld does relocations"
   if (VmaMaybeExecutable(flags)/* && (vma->prot & PROT_EXEC)*/) {
      ASSERT(filp);

      struct DentryStruct *dentryp = File_Dentry(filp);

       /* Prepare the region for trap insertion. */
      err = syscall(SYS_mprotect, vma->start, vma->len, PROT_WRITE | PROT_READ);
      ASSERT(!SYSERR(err));

      /* XXX: note that concurrent task can start executing code and
       * bypass syscalls before they are instrumented ... The cleanest
       * fix seems to be to get rid of trap-based syscall interception. */
      WARN_XXX(0);

		Trap_Map((void*)vma->start, vma->len, dentryp->name);
      err = syscall(SYS_mprotect, vma->start, vma->len, vma->prot);
      ASSERT(!SYSERR(err));
   }
#endif

   ASSERT(vma->mm == current->mm);
   goto out;

out_free:
   ASSERT(vma);
   VmaFree(vma);
out:
   return addr;
}

static int
VmaMove(struct VmaStruct *vma, ulong addr, ulong old_len, 
        ulong new_addr, ulong new_len)
{
   int err = 0, res;
   struct VmaStruct ivma, *nvma;

   /* Effect the move in the shadow and real pagetable.
    * Ordering shouldn't matter. */

   nvma = VmaAlloc();
   *nvma = *vma;
   nvma->start = new_addr;
   nvma->len = new_len;
   if (!nvma->file) {
      /* The pgoff of non-file-backed vmas is the pgoff of
       * the vma in the address space. Since we are about
       * to move the vma, we need to update that pgoff as well. */
      nvma->pgoff = PAGE_NUM(nvma->start);
   }

   res = Vma_Intersects(vma, addr, old_len, &ivma);
   ASSERT(res);

   VmaDoUnmap(vma, ivma.start, ivma.len);
   vma = NULL;

   VmaLink(current->mm, nvma);

   res = syscall(SYS_mremap, addr, old_len, new_len, 
         MREMAP_FIXED | MREMAP_MAYMOVE, new_addr);
   ASSERT(res == new_addr);

   return err;
}

static int
VmaAdjust(struct VmaStruct *vma, ulong end)
{
   int err; 
   ulong new_len = end - vma->start;

   ASSERT(new_len >= 0);

   /* Only permit growing the vma for now. */
   ASSERT(vma->start+vma->len <= end);

   err = syscall(SYS_mremap, vma->start, vma->len, new_len, 0, 0);
   if (err != -EAGAIN) {
      ASSERT_MSG((ulong)err == vma->start, "err=%d\n", err);
      vma->len = new_len;

      err = 0;
   } else {
      /* EAGAIN: could happen if we try to grow a locked
       * page beyond the system rlimit on locked pages. */
   }

   return err;
}

ulong
Vma_ReMap(ulong addr, ulong old_len, ulong new_len, ulong flags, ulong new_addr)
{
   ulong err = -EINVAL;
   struct VmaStruct *vma;

   ASSERT(Vma_IsLocked(current->mm));

	if (flags & ~(MREMAP_FIXED | MREMAP_MAYMOVE))
		goto out;

	if (addr & ~PAGE_MASK)
		goto out;

	old_len = PAGE_ALIGN(old_len);
	new_len = PAGE_ALIGN(new_len);

	/*
	 * We allow a zero old-len as a special case
	 * for DOS-emu "duplicate shm area" thing. But
	 * a zero new-len is nonsensical.
	 */
	if (!new_len)
		goto out;

	/* new_addr is only valid if MREMAP_FIXED is specified */
	if (flags & MREMAP_FIXED) {
		if (new_addr & ~PAGE_MASK)
			goto out;
		if (!(flags & MREMAP_MAYMOVE))
			goto out;

		if (new_len > __IMAGE_START || new_addr > __IMAGE_START - new_len)
			goto out;

		/* Check if the location we're moving into overlaps the
		 * old location at all, and fail if it does.
		 */
		if ((new_addr <= addr) && (new_addr+new_len) > addr)
			goto out;

		if ((addr <= new_addr) && (addr+old_len) > new_addr)
			goto out;

      err = VmaUnmapHelper(new_addr, new_len);
		if (err)
			goto out;
	}

	/*
	 * Always allow a shrinking remap: that just unmaps
	 * the unnecessary pages..
	 * do_munmap does all the needed commit accounting
	 */
	if (old_len >= new_len) {
		err = VmaUnmapHelper(addr+new_len, old_len - new_len);
		if (err && old_len != new_len)
			goto out;
		err = addr;
		if (!(flags & MREMAP_FIXED) || (new_addr == addr))
			goto out;
		old_len = new_len;
	}

	/*
	 * Ok, we need to grow..  or relocate.
	 */
	err = -EFAULT;
	vma = Vma_Find(current->mm, addr);
	if (!vma || vma->start > addr)
		goto out;

   ASSERT(vma->start == addr);
#if 0
   /* XXX */
	if (is_vm_hugetlb_page(vma)) {
		ret = -EINVAL;
		goto out;
	}
#endif

	/* We can't remap across vm area boundaries */
	if (old_len > (vma->start+vma->len) - addr)
		goto out;
#if 0
   /* XXX */
	if (vma->vm_flags & (VM_DONTEXPAND | VM_PFNMAP)) {
		if (new_len > old_len)
			goto out;
	}

	if (!may_expand_vm(mm, (new_len - old_len) >> PAGE_SHIFT)) {
		ret = -ENOMEM;
		goto out;
	}
#endif

	/* old_len exactly to the end of the area..
	 * And we're not relocating the area.
	 */
	if (old_len == (vma->start+vma->len) - addr &&
	    !((flags & MREMAP_FIXED) && (addr != new_addr)) &&
	    (old_len != new_len || !(flags & MREMAP_MAYMOVE))) {
		unsigned long max_addr = __IMAGE_START;
      /* XXX: pull this out to "isTail" */
		if (vma->list.next != &current->mm->vmaList)
			max_addr = Vma_Next(vma)->start;
		/* can we just expand the current mapping? */
		if (max_addr - addr >= new_len) {

			err = VmaAdjust(vma, addr + new_len);
         if (!err) {
            err = addr;
         } 
         goto out;
      }
	}

	/*
	 * We weren't able to just expand or shrink the area,
	 * we need to create a new one and move it..
	 */
	err = -ENOMEM;
	if (flags & MREMAP_MAYMOVE) {
		if (!(flags & MREMAP_FIXED)) {
			unsigned long map_flags = 0;
			if (vma->flags & MAP_SHARED)
				map_flags |= MAP_SHARED;

         new_addr = VmaGetUnmappedArea(0, new_len, map_flags);
			err = new_addr;
			if (new_addr & ~PAGE_MASK)
				goto out;
		}

      err = VmaMove(vma, addr, old_len, new_addr, new_len);
      ASSERT(!err);

      err = new_addr;
	}
   

out:
   return err;
}

int
Vma_ShmAt(struct FileStruct *filp, ulong start, int shmflg, ulong *raddr)
{
   int err = 0, prot, mapFlags = MAP_SHARED;
   size_t size;
   struct ShmStruct *shmp;

   ASSERT(raddr);
   ASSERT(filp);
   ASSERT(Vma_IsLocked(current->mm));

   if (start) {
      if (start & (SHMLBA-1)) {
         if (shmflg & SHM_RND) {
            /* Round down to the nearest SHMLBA boundary. */
            start &= ~(SHMLBA-1);
         } else {
            if (!PAGE_ALIGNED(start)) {
               err = -EINVAL;
               goto out;
            }
         }
      }

      mapFlags |= MAP_FIXED;
   } else {
      if ((shmflg & SHM_REMAP)) {
         err = -EINVAL;
         goto out;
      }
   }

   if (shmflg & SHM_RDONLY) {
      prot = PROT_READ;
   } else {
      prot = PROT_READ | PROT_WRITE;
   }

   if (shmflg & SHM_EXEC) {
      /* XXX: What if segment contains code? Should we instrument (again)?
       * If we do that, what race conditions might occur? */
      ASSERT_UNIMPLEMENTED(0);
      prot |= PROT_EXEC;
   }

   shmp = ShmFs_GetStruct(File_Inode(filp));
   ASSERT(!IS_ERR(shmp));
   size = shmp->size;

   if (start && !(shmflg & SHM_REMAP)) {
      if (Vma_FindIntersect(current->mm, start, size)) {
         err = -EINVAL;
         goto out;
      }

      /* XXX: make sure the stack has enough space to grow */
      WARN_XXX(0);
   }

   *raddr = Vma_Map(filp, start, size, prot, mapFlags, 0);

   if (SYSERR((int)*raddr)) {
      err = (int)*raddr;
   }

out:
   return err;
}



/*
 * Returns 1 iff region has @prot permissions.
 */
int
Vma_CheckProt(ulong start, size_t len, int prot)
{
   int okay = 1;
   struct VmaStruct *vma;

   ASSERT(Vma_IsLocked(current->mm));

   DEBUG_MSG(5, "start=0x%x len=%d\n", start, len);

   vma = Vma_FindIntersect(current->mm, start, len);
   DEBUG_MSG(5, "intersect\n");
   Vma_Print(vma);

   DEBUG_MSG(5, "scanning region\n");
   list_for_each_entry_from(vma, &current->mm->vmaList, list) {
      if (!Vma_Intersects(vma, start, len, NULL)) {
         break;
      }

      Vma_Print(vma);
      okay &= ((vma->prot & prot) ? 1 : 0);
   }

   return okay;
}

struct DentryStruct *
Vma_GetExecDentry()
{
   struct VmaStruct *vma;
   struct DentryStruct *dentryp = NULL;

   Vma_Lock();

   list_for_each_entry(vma, &current->mm->vmaList, list) {
      if (vma->flags & MAP_EXECUTABLE) {
         ASSERT_KPTR(vma->file);
         dentryp = Dentry_Get(vma->file->dentry);
         ASSERT(Dentry_Inode(dentryp)->count > 0);
         break;
      }
   }

   Vma_Unlock();

   return dentryp;
}

static void
VmaInit(struct Task *tsk)
{
   ORDERED_LOCK_INIT(&tsk->mm->vmaLock, "vma");
   List_Init(&tsk->mm->vmaList);
}


void
Vma_Fork(struct Task *tsk)
{
   struct VmaStruct *vma;

   if (Task_IsThread(tsk)) {
      goto out;
   }

   /* New address space -- copy the vma list. */
   ASSERT(tsk->mm);
   ASSERT(current->mm != tsk->mm);

   VmaInit(tsk);

   /* No need to acquire @tsk's vma lock -- there is no one else
    * sharing its address space yet. */
   Vma_Lock();

   /* We copy all VMAs to the child, even those mappings forced upon
    * us by Linux (e.g., vdso, stack), in order to make sure
    * that all the vma->mm's are updated to tsk->mm, hence indicating
    * a change of ownership. */
   list_for_each_entry(vma, &current->mm->vmaList, list) {
      struct VmaStruct *nvma;

      nvma = VmaAlloc();
      *nvma = *vma;
      ASSERT(vma->mm == current->mm);

      if (nvma->file) {
         File_GetFile(nvma->file);
      }

      VmaLink(tsk->mm, nvma);

      /* Needed, for instance, to increment shmseg attach counts. */
      if (nvma->ops && nvma->ops->open) {
         nvma->ops->open(nvma);
      }

      Module_OnVmaFork(tsk, nvma);
   }

   Vma_Unlock();

out:
   return;
}

/* XXX: on-demand instrumentation -- may not be necessary if we
 * rely on kernel support. */
#if 0
void
Vma_ExecFault(ulong faultAddr)
{
   Vma_Lock();

   vma = Vma_Find(faultAddr);

   if ((vma->prot & PROT_EXEC) && !vma->wasInstrumented) {
      vma->wasInstrumented = 1;  

       /* Prepare the region for trap insertion. */
      err = syscall(SYS_mprotect, vma->start, vma->len, PROT_WRITE | PROT_READ);
      Trap_Instrument(vma);
      err = syscall(SYS_mprotect, vma->start, vma->len, vma->prot);
   }


   Vma_Unlock();
}
#endif

static int
Vma_Init()
{
   int i, n;
   memregion_t *rlist;
   memregion_extra_t *elist;
   struct VmaStruct *vma;
   size_t rlist_size = sizeof(memregion_t) * MAXREGIONS;
   size_t elist_size = sizeof(memregion_extra_t) * MAXREGIONS;

   VmaInit(current);

   /* 
    * Linux gives us an address space with at least two regions that
    * are unremovable (or at least, hard to remove). These regions
    * include:
    *    o VDSO [vdso] -- for syscalls
    *    o stack [stack]
    *    o no SIGSEGV zone at page 0xfffe000 -- doesn't show
    *      up in the Linux vma list, but accesses to it are ignored
    *      if the VDSO isn't mapped there
    *
    * Some of these mappings (e.g., the VDSO) may show
    * up anywhere in the address space, even within the 1st 3GB.
    *
    * We represent these special regions as VMAs to ensure that we 
    * don't allocate over them (since such allocations would fail) and
    * We make them MAP_EXTRA_PERMANENT so that attempts to VmaUnMap them 
    * will fail.
    *
    * The address space also contains the vkernel image. We must
    * take care not to place app mappings there. We ensure this by
    * never placing the vkernel image mapping in the vma list, hence
    * it will never be unmapped. 
    */

   rlist = SharedArea_Malloc(rlist_size);
   elist = SharedArea_Malloc(elist_size);

   n = read_self_regions(rlist, elist, 0);

   /* The vkernel occupies one vma, so must be at least 1. */
   ASSERT(n > 0);

   for (i = 0; i < n; i++) {
      memregion_t *reg = &rlist[i];
      struct VmaStruct tmpvma = { .start = reg->start, .len = reg->len };

      DEBUG_MSG(5, "start=0x%x len=%lu\n", reg->start, reg->len);

      if (!Vma_Intersects(&tmpvma, __IMAGE_START, 
               __IMAGE_END - __IMAGE_START, NULL)) {

         vma = VmaAlloc();
         vma->start = reg->start;
         vma->len = reg->len;
         vma->prot = reg->prot;
         vma->flags = reg->map_flags;
         vma->extraFlags = MAP_EXTRA_PERMANENT;
         vma->file = NULL;
         vma->pgoff = PAGE_NUM(vma->start);
         VmaLink(current->mm, vma);

         /* XXX: modules interested in this event may not be registered
          * yet and so will not receive this event. Same below. */
         Module_OnVmaEvent(Vek_Map, vma, 0, 0);
      }
   }

   /* Add a mapping for the VDSO no-SIGSEGV zone at 0xffffe000.
    * The kernel ignored accesses to this page even though there
    * is no Linux vma there -- but we need to treat this as a valid
    * access for race detection. */
   vma = VmaAlloc();
   vma->start = 0xffffe000;
   vma->len = PAGE_SIZE;
   vma->prot = PROT_READ | PROT_WRITE | PROT_EXEC;
   vma->flags = MAP_ANONYMOUS;
   vma->extraFlags = MAP_EXTRA_PERMANENT;
   vma->file = NULL;
   vma->pgoff = PAGE_NUM(vma->start);
   VmaLink(current->mm, vma);
   Module_OnVmaEvent(Vek_Map, vma, 0, 0);

   SharedArea_Free(rlist, rlist_size);
   SharedArea_Free(elist, elist_size);

   return 0;
}

/* FS comes after Bt, and should be inited after modules are inited
 * because we want them to receive map events. */
FS_INITCALL(Vma_Init);

/* At the very least, we must put file descriptors so that
 * rfds are closed. 
 *
 * Must be called by @current to avoid concurrent races on 
 * closing file descriptors. */
void
Vma_SelfExit(struct Task *tsk)
{
   struct VmaStruct *vma, *tmp;

   ASSERT(tsk == current);

   Vma_Lock();

   list_for_each_entry_safe(vma, tmp, &tsk->mm->vmaList, list) {
      /* 
       * Can't just call VmaUnlink since we must release backing
       * state (e.g., file descriptors) and must invoke
       * module callback, if there are any requested. 
       */
      VmaDoUnmap(vma, vma->start, vma->len);
   }

   Vma_Unlock();
}
