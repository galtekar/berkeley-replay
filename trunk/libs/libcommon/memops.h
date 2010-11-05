#pragma once

#define PAGE_SHIFT 12 /* corresponds to 4K page size */
#ifndef PAGE_SIZE
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#endif
#define PAGE_MASK (~(PAGE_SIZE-1))

#ifndef __ASSEMBLER__
#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <ctype.h>
#include <sys/types.h>

#include "syncops.h"
#include "misc.h"
#include "arch.h"

#define MAX_PAGES (0x1 << ((sizeof(ulong)*8)-PAGE_SHIFT))
   /* Rounds up. */
#define PAGE_ALIGN(x) (((x) - 1 + PAGE_SIZE) & PAGE_MASK)
   /* Rounds down. */
#define PAGE_START(_v) ((_v) & ~(unsigned long)(PAGE_SIZE-1))
#define PAGE_NUM(x) ((x) >> PAGE_SHIFT)
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define PAGE_ALIGNED(x) (PAGE_OFFSET((ulong)(x)) == 0)
#define SHOR(v, o) ((v) | ((v) >> (o)))
#ifdef __x86__
#define POW2_ROUND_UP(v) (SHOR(SHOR(SHOR(SHOR(SHOR(((v)-1), 1), 2), 4), 8), 16) + 1)
#define LOG2(v) (v == 0 ? 0 : __ffs(POW2_ROUND_UP(v)))
#else
#error "XXX: needs to be adjusted"
#endif
#define POW2_ALIGNED(v) (!(v & (v-1)) && v)

typedef unsigned long Page;

#define FOR_ALL_PAGES_IN_RANGE(start, len) \
{ \
      const ulong end = (start)+(len); \
      const Page startPage = PAGE_NUM((start)); \
      const Page endPage = PAGE_NUM(end); \
      Page pn; \
      ASSERT(PAGE_ALIGNED(start)); \
      ASSERT(PAGE_ALIGNED(end)); \
      ASSERT((start) < end); \
      for (pn = startPage; pn < endPage; pn++)

#define END_ALL_PAGES_IN_RANGE }


#define REGION_IGNORE 1
#define REGION_SHMAT 2

/* FIXME: Perhaps we should have a richer model of
	memory to cope with these hacks for pages with
	special semantics.*/
enum {
	MAXREGIONS =   4096,    /* Maximum num of
										noncontiguous memory
										regions */
	VDSO_PAGE_HACK = 0xffff0000     /* we do not ckpt any
										     for syscall trap (i.e., the VDSO) */
};

/* Essential info about each memory map that is saved along
 * with each checkpoint. */
typedef struct memregion {
   ulong start;
	size_t len;

	/* BUG: all of these flags should be merged into one word to be
	 * more compact. */
	unsigned prot;  /* bitmask of PROT_* */
	unsigned map_flags;  /* MAP_ANONYMOUS, MAP_SHARED, MAP_PRIVATE, etc. */

	unsigned priv_flags; /* REGION_IGNORE */

	ulong offset;

	char dev[6];

	ino_t inode;
} memregion_t;

/* BUG: This should be a union for shmats and mmaps. */
typedef struct memregion_extra {

	char pathname[PATH_MAX];
} memregion_extra_t;

/* Returns first MAX_REGIONS regions in the address map. */
extern int read_self_regions(memregion_t *regions, 
		memregion_extra_t* extra_info /* optional -- pass NULL if you don't want it*/,
      int ignoreVDSO);

/* ---------------------------------------------------------------------- */

/* XXX: should be in separate file, perhaps renamed to ``BitRegion'' */
struct Region {
   ulong *bitmap;
   size_t pageLen;
   struct SynchLock lock;
   int canRemap;
};

extern Page Region_FindFreeBlock(struct Region *r, size_t len);

extern void Region_GetByAddr(struct Region *r, ulong addr, size_t len);

extern ulong Region_Get(struct Region *r, size_t len);

extern void Region_Put(struct Region *r, ulong addr, size_t len);

static INLINE int
MemOps_Intersects(ulong a_start, size_t a_len, ulong b_start, size_t b_len,
                  ulong *i_start, ulong *i_len)
{
   int res = 0;
   ulong vma_end = a_start+a_len;
   ulong range_end = b_start+b_len;
   ulong ivma_start = 0, ivma_len = 0;

   ASSERT(a_len);

   if (a_start <= b_start && b_start < vma_end) {
      ivma_start = b_start;
      ivma_len = MIN(range_end, vma_end) - b_start;

      res = 1;
   } else if (b_start <= a_start && a_start < range_end) {
      ivma_start = a_start;
      ivma_len = MIN(range_end, vma_end) - a_start;

      res = 1;
   } else {
      /* Does not intersect. */
      res = 0;
   }

   if (i_start) *i_start = ivma_start;
   if (i_len) *i_len = ivma_len;

   return res;
}


#ifdef __cplusplus
}
#endif
#endif /* __ASSEMBLER */
