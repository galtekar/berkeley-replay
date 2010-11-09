#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#define _GNU_SOURCE
#include <sys/shm.h>
#include <sys/ipc.h>
#include <errno.h>
#include <string.h>

#include "memops.h"
#include "shmalloc.h"
#include "sharedarea.h"
#include "syncops.h"
#include "debug.h"
#include "misc.h"
#include "bitops.h"

#define MAX_SA_SIZE (1 << 28)
#define MAX_SHARED_AREA_PAGES (MAX_SA_SIZE >> PAGE_SHIFT)

typedef struct SharedAreaDescStruct {
   /* Bitmap of mapped shared area heap pages. Used for determining
    * where to place shared area heap allocations. */
   struct Region heapRegion;
} SharedAreaDesc;

/* Used to test the integrity of the shared area. This value should
 * never be overwritten. */
DEBUG_ONLY(static SHAREDAREA volatile int sharedAreaTest = 0xdeadbeef;)

/* These symbols must be defined in a linker script used with
 * the final executable. They should point to the start of the
 * static shared area segment and the dynamic (heap) segment,
 * respectively. */
extern ulong __sharedarea_start, __sharedarea_end, __sharedarea_heap_start;

static SHAREDAREA ulong heapBitmap[MAX_SHARED_AREA_PAGES / (sizeof(ulong)*8)] = { 0, };
static SHAREDAREA SharedAreaDesc sdesc = {
   .heapRegion = { 
      .bitmap = heapBitmap,
      /* XXX: should be modified to be actual size of shared area
       * rather than max, since RegionFindFree relies on it to be
       * accurate. */
      .pageLen = MAX_SHARED_AREA_PAGES,
      .lock = SYNCH_LOCK_INIT,
      /* Should never mmap an already mapped region in the
       * sharedarea. */
      .canRemap = 0,
   },
};

static const ulong shmStart = (ulong)&__sharedarea_start;
static const ulong saEnd = (ulong)&__sharedarea_end;
static const ulong shmHeapStart = (ulong)&__sharedarea_heap_start;
static size_t shmSize;
static size_t heapSize;
#define NUM_HEAP_PAGES PAGE_NUM(heapSize)

static int isInitialized = 0;
static int useSafeMalloc = 0;

void
SharedArea_Init(size_t sa_size, int safeMalloc)
{
   int err;
   ulong staticShmSize, shmEnd;
   void *tmpAddr, *addr;


   /* XXX: bug -- pageLen should be precise, or Region_FindFree
    * may allocate to non shared area pages. */
   ASSERT_UNIMPLEMENTED(sa_size != MAX_SHARED_AREA_PAGES);
   useSafeMalloc = (safeMalloc ? 1 : 0);
   /* XXX: this feature is broken and too slow and wasteful of memory
    * to be very useful */
   ASSERT_UNIMPLEMENTED(!useSafeMalloc);

   ASSERT(sa_size <= MAX_SA_SIZE);
   ASSERT(PAGE_ALIGNED(sa_size));

   shmSize = sa_size;
   shmEnd = shmStart + shmSize;
   staticShmSize = saEnd - shmStart;
   heapSize = shmEnd - shmHeapStart;

   ASSERT(shmHeapStart > shmStart);
   ASSERT(staticShmSize < shmSize); /* heap space > 0 */
   ASSERT(PAGE_ALIGNED(shmStart));
   ASSERT(PAGE_ALIGNED(shmEnd));
   ASSERT(PAGE_ALIGNED(shmSize));
   ASSERT(PAGE_ALIGNED(heapSize));
   ASSERT(PAGE_ALIGNED(saEnd));
   ASSERT(PAGE_ALIGNED(staticShmSize));

   /* Save contents of the initialized shared area segment
    * so that we can restore it after we've mapped in the shared 
    * segment. This is the trick that makes the static 
    * SHAREDAREA work. */
   tmpAddr = mmap(NULL, staticShmSize, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   ASSERT(tmpAddr != MAP_FAILED);
   memcpy(tmpAddr, (void*)shmStart, staticShmSize);

   err = munmap((void*)shmStart, sa_size);
   ASSERT(!err);
   addr = mmap((void*)shmStart, sa_size, PROT_READ | PROT_WRITE,
         MAP_ANONYMOUS | MAP_SHARED, -1, 0);
   DEBUG_MSG(7, "SharedArea starts at 0x%x, heap at 0x%x.\n", addr,
         shmHeapStart);
   if (addr != (void*)shmStart) {
      /* Potential conflict from existing mapping (maybe the vkernel). */
      FATAL("could not map sharedarea at 0x%x:%d.\n",
            shmStart, sa_size);
   }
   ASSERT(addr == (void*)shmStart);

   /* Restore the contents of the shared area initialized data segment. */
   memcpy((void*)shmStart, tmpAddr, staticShmSize);
   munmap(tmpAddr, staticShmSize);
   /* Verify that the static shared area contents have been restored
    * after we remmaped the pages into shared memory. */
   ASSERT(sharedAreaTest == 0xdeadbeef);

   /* Do any sdesc initialization here. */
   sdesc.heapRegion.pageLen = PAGE_NUM(heapSize);

   if (useSafeMalloc) {
      DEBUG_MSG(3, "using safe-allocator for all allocations.\n");
   }

   isInitialized = 1;
}



#if 0
/* XXX: this is buggy -- don't use it; use MMap/Munmap instead */
ulong
SharedArea_SbrkCallback(long incr)
{
   ulong ret, curr;

   ASSERT_UNIMPLEMENTED(0);
   ASSERT_IS_LOCKED(&sdesc.lock);

   curr = sdesc.brk;

   if (incr == 0) {
      ret = curr;
      goto out;
   }

   if (!(curr + incr >= shmStart &&
            curr + incr < shmStart + shmSize)) {
      ASSERT(0);
      ret = (ulong)-1;
      goto out;
   }

   /* 
    *     * Note that we don't mmap in any memory. That's because
    *         * the entire shared area is already mapped. We're just
    *             * keeping track of the used portion. 
    *                 */

   ret = curr + incr;
   sdesc.brk = ret;

out:
   return ret;
}
#endif

ulong
SharedArea_Mmap(void *addr, size_t len)
{
   ulong startAddr, finalAddr;

   ASSERT(isInitialized);

   ASSERT(!addr); /* the allocator should let us decide where to map it */

   startAddr = Region_Get(&sdesc.heapRegion, len);

   finalAddr = startAddr + shmHeapStart;

   DEBUG_MSG(8, "ret=0x%x addr=0x%x len=%d\n", finalAddr, addr, len);

   return finalAddr;
}

int
SharedArea_Munmap(void *addr, size_t len)
{
   ulong start;

   ASSERT(isInitialized);


   DEBUG_MSG(8, "SharedArea_Munmap: addr=0x%lx len=%d\n", addr, len);

   ASSERT(shmHeapStart);
   start = (ulong)addr - shmHeapStart;
   Region_Put(&sdesc.heapRegion, start, len);

   return 0;
}

/* Used only by the heap-protection feature (i.e., useSafeMalloc). */
struct header {
   char* start;
   size_t len;
   size_t bytes; /* num of bytes requested */
};

void*
SharedArea_Malloc(size_t bytes)
{
   char *retptr;

   DEBUG_MSG(8, "bytes=%d\n", bytes);

   if (useSafeMalloc) {
      char *footer, *ptr;
      struct header *hdrp;
      size_t allocSize = PAGE_SIZE + PAGE_ALIGN(bytes) + PAGE_SIZE;
      ASSERT(PAGE_ALIGNED(allocSize));
      ptr = (void*)SharedArea_Mmap(NULL, allocSize);

      mprotect(ptr, allocSize, PROT_READ | PROT_WRITE);

      /* Store the size of the allocation in the header page
       * and read/write protect it. */
      hdrp = (struct header*)ptr;
      hdrp->start = ptr;
      hdrp->len = allocSize;
      hdrp->bytes = bytes;


      mprotect(hdrp, PAGE_SIZE, PROT_NONE);

      footer = ptr + allocSize - PAGE_SIZE;

      retptr = footer - bytes;

      /* read/write protect the footer. */
      mprotect(footer, PAGE_SIZE, PROT_NONE);
   } else {
      retptr = dlmalloc(bytes);
   }

   ASSERT(retptr);

   return retptr;
}

void*
SharedArea_Memalign(size_t alignment, size_t bytes)
{
   void *retptr;

   /* SharedArea_Mmap() will by default align to @bytes if
    * it is a power of 2. */
   ASSERT(POW2_ALIGNED(alignment));
   ASSERT(PAGE_ALIGNED(alignment));
   ASSERT(bytes <= alignment);
   ASSERT(alignment >= PAGE_SIZE);

   DEBUG_MSG(6, "aligned=%d bytes=%d\n", alignment, bytes);

   if (useSafeMalloc) {
      char *footer, *ptr;
      struct header *hdrp;
      size_t allocSize = 3*alignment;
      ASSERT(PAGE_ALIGNED(allocSize));
      ptr = (void*)SharedArea_Mmap(NULL, allocSize);

      mprotect(ptr, allocSize, PROT_READ | PROT_WRITE);

      /* Store the size of the allocation in the header page
       * and read/write protect it. */
      hdrp = (struct header*)(ptr + allocSize - 2*alignment - PAGE_SIZE);
      hdrp->start = ptr;
      hdrp->len = allocSize;
      hdrp->bytes = bytes;


      mprotect(ptr, alignment, PROT_NONE);

      footer = ptr + allocSize - alignment;

      retptr = footer - alignment;

      /* read/write protect the footer. */
      mprotect(footer, alignment, PROT_NONE);
   } else {
      retptr = dlmemalign(alignment, bytes);
   }

   return retptr;
}

void*
SharedArea_Realloc(void *oldmem, size_t bytes)
{
   ASSERT_UNIMPLEMENTED(!useSafeMalloc);

   return dlrealloc(oldmem, bytes);
}

void
SharedArea_Free(void *ptr, size_t bytes)
{
   /* Check that we are indeed deallocating a heap object, rather than
    * a static sharedarea object. */
   ASSERT_MSG((ulong)&__sharedarea_heap_start <= (ulong)ptr,
          "heap_start=0x%x ptr=0x%x", &__sharedarea_heap_start, ptr);

   if (useSafeMalloc) {
      ulong aligned = (ulong)ptr & PAGE_MASK;
      struct header *hdrp = (struct header*)(aligned - PAGE_SIZE);
      void* start;
      size_t len;

      mprotect(hdrp, PAGE_SIZE, PROT_READ | PROT_WRITE);
      ASSERT(hdrp->start);
      ASSERT(hdrp->len);
      if (bytes) {
         ASSERT(hdrp->bytes == bytes); /* sanity check */
      }
      ASSERT(PAGE_ALIGNED(hdrp->len));
      mprotect(hdrp->start, hdrp->len, PROT_READ | PROT_WRITE);

      /* Remove read/write protection so that stray accesses can
       * be detected ASAP. */
      start = hdrp->start;
      len = hdrp->len;
      //mprotect(hdrp->start, hdrp->len, PROT_NONE);

      SharedArea_Munmap(start, len);
   } else {
      dlfree(ptr);
   }
}
