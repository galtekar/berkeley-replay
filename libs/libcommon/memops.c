#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#include "misc.h"
#include "memops.h"
#include "debug.h"
#include "syncops.h"
#include "bitops.h"

/* BUG: This is too big. Figure out a way to do dynamic allocation. */
/* Stack is too small to accomodate typical proc/maps info. 
 * That's why we are allocating space in the data segment. */
#define MAX_MAP_SIZE 4096*100
static char maps[MAX_MAP_SIZE];
char pathname[PATH_MAX];

static void parse_region(const char *buf, memregion_t *r, 
		memregion_extra_t* e) {
	/* XXX: Consider parsing this with sscanf and the MAPS_LINE_FORMAT
		in linux/fs/proc/array.c. */
	/* THIS FUNCTION AND ITS CALLEES MAY NOT CALL strtok */
	char *p;
	ulong endaddr;


	ASSERT(r);

	memset(r, 0x0, sizeof(memregion_t));

	r->start = strtoul(buf, &p, 16);
	p++;  /* skip '-' */
	endaddr = strtoul(p, &p, 16);
	r->len = endaddr - r->start;
	p++;  /* skip ' ' */


	while (*p != ' ') {
		switch (*p++) {
			case 'r':
				r->prot |= PROT_READ;
				break;
			case 'w':
				r->prot |= PROT_WRITE;
				break;
			case 'x':
				r->prot |= PROT_EXEC;
				break;
			case '-':
				break;
			case 'p':
				r->map_flags |= MAP_PRIVATE;
				break;
			case 's': /* "may share" */
				r->map_flags |= MAP_SHARED;
				break;
			default:
				/* Unrecognized */
				printf("unrecognized attribute '%c'\n", *p);
				while(1);
				ASSERT(0);
		}
	}

	p++; /* skip ' ' */

	r->offset = strtoul(p, &p, 16);
	p++; /* skip ' ' */

	sscanf(p, "%s %lu %s", r->dev, &r->inode, pathname);


	if (r->inode == 0) { r->map_flags |= MAP_ANONYMOUS; }
	if ((r->map_flags & MAP_SHARED) && (strstr(pathname, "SYSV"))) {
		/* Shmat-attached shared segment. */
		r->priv_flags |= REGION_SHMAT;
	}

	if (e) {
		strncpy(e->pathname, pathname, sizeof(e->pathname));
	}
}

int read_self_regions(memregion_t *regions, memregion_extra_t *extra_info, int ignoreVDSO) {

	int fd;
	char *p = NULL, *pp = NULL;
	int ret, n;
	int nread;
	memregion_t procmaps;

	fd = open("/proc/self/maps", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open /proc/self/maps for reading\n");
		return -1;
	}

	procmaps.len = sizeof(maps);
	ASSERT(procmaps.len > 0);

	procmaps.start = (ulong)maps;

	/* Zero to ensure there is always a nul following the data */
	memset((void*)procmaps.start, 0x0, procmaps.len);
	p = (char*)procmaps.start;
	nread = 0;

	while (1) {
		if (nread >= procmaps.len) {
			FATAL("memory map limit exceeded\n");
			ASSERT(0);
		}
		ret = read(fd, p, 1024);
		if (ret < 0) {
			FATAL("cannot read from /proc/self/maps\n");
			ASSERT(0);
		}

		ASSERT(ret < procmaps.len);

		if (ret == 0)
			break;

		p += ret;
		nread += ret;
	}


	pp = (char*)procmaps.start;
#if 0
	if (strlen(pp) == 0) {
		printf("OH OH!\n");
		getchar();
	}
#endif

	/* Don't use strtok since its not thread-safe. */
	p = strsep(&pp, "\n");
	n = 0;
	/*printf("\n======================\n");
	fflush(stdout);*/
	while (pp) {
		ASSERT(n < MAXREGIONS);

		//printf("%s\n", p);
		parse_region(p, &regions[n], extra_info ? &extra_info[n] : NULL);

		p = strsep(&pp, "\n");

      if (ignoreVDSO) {
         /* Ignore regions above the VDSO page. 
          * XXX: BUG: the VDSO can be anywhere in the address space. 
          * 
          * pre 2.6.16, the VDSO is readable and writeable and can
          * be removed, so we can checkpoint it along with other regions.
          * 
          * At 2.6.16, it's fixed at the end of the address space and
          * we can't unmap it. So this may not be a problem. 
          *
          * At 2.6.18, it's map addr is randomized and usually not at
          * the very end of the address space. 
          *
          * XXX: identify the vdso by it's name ([vdso]) rather than
          * hardcoding its location with VDSO_PAGE_HACK. */
         ASSERT_UNIMPLEMENTED(0);

         if (regions[n].start >= VDSO_PAGE_HACK) {
            continue;
         }
      }


		++n;
	}
	/*printf("\n======================\n");
	fflush(stdout);*/


	/* Make sure no new mapping have popped up. This used to
	 * happen in some older 2.6 kernels. */
	ret = read(fd, (void*)procmaps.start, procmaps.len);
	ASSERT(0 == ret);

	close(fd);

	return n;
}

static int
RegionIsFree(struct Region *r, ulong startPage, ulong region_size_in_pages)
{
   Page pn;

   ASSERT(SYNCH_IS_LOCKED(&r->lock));
   ASSERT(startPage < r->pageLen);

   Page endPage = startPage+region_size_in_pages;
   for (pn = startPage; pn < endPage; pn++) {
      int val = Bit_Test(pn, r->bitmap);
      if (val) {
         return 0;
      }
   }
   return 1;
}

/* Find a region of free (zero) pages of @bytes bytes and
 * allocate them (set them to one).  Only consider regions of length
 * a power (@pg_order) of two, aligned to that power of two, which
 * makes the search algorithm much faster. */
Page
Region_FindFreeBlock(struct Region *r, size_t len)
{
   Page pn;
   ASSERT(SYNCH_IS_LOCKED(&r->lock));
   ASSERT(len > 0);
   ASSERT(PAGE_ALIGNED(len));
   Page rounded_pgsize = POW2_ROUND_UP(PAGE_NUM(len));

   ASSERT(rounded_pgsize > 0);

   for (pn = 0; pn < r->pageLen && (pn+rounded_pgsize) <= r->pageLen; pn += rounded_pgsize) {
      /* This shouldn't fire because we check for this in the loop. */
      ASSERT((pn + rounded_pgsize) <= r->pageLen);
      if (RegionIsFree(r, pn, rounded_pgsize)) {
         DEBUG_MSG(6, "Region at page %d sized %d pages is free.\n", pn,
               rounded_pgsize);
         goto out;
      }
   }

   /* XXX: No free space remaining -- most likely due to fragementation,
    * hope this doesn't happen, but deal with it when it does */
   FATAL("Out of memory.\n");

out:
   return pn;
}

void
RegionGetPages(struct Region *r, ulong addr, size_t len)
{
   ASSERT(PAGE_ALIGNED(addr));
   ASSERT(PAGE_ALIGNED(len));
   ASSERT(SYNCH_IS_LOCKED(&r->lock));

   FOR_ALL_PAGES_IN_RANGE(addr, len) {
      int oldVal;
      ASSERT(pn < r->pageLen);
      oldVal = Bit_TestSet(pn, r->bitmap);
#if DEBUG
      if (r->canRemap) {
         ASSERT(oldVal || !oldVal);
      } else {
         ASSERT(!oldVal);
      }
#endif

   } END_ALL_PAGES_IN_RANGE;
}

void
Region_GetByAddr(struct Region *r, ulong addr, size_t len)
{
   SYNCH_LOCK(&r->lock);
   RegionGetPages(r, addr, len);
   SYNCH_UNLOCK(&r->lock);
}

ulong
Region_Get(struct Region *r, size_t len)
{
   Page startPage;
   ulong startAddr;

   ASSERT(PAGE_ALIGNED(len));
   ASSERT(len);

   SYNCH_LOCK(&r->lock);

   startPage = Region_FindFreeBlock(r, len);
   startAddr = startPage * PAGE_SIZE;

   RegionGetPages(r, startAddr, len);

   SYNCH_UNLOCK(&r->lock);

   DEBUG_MSG(6, "ret=0x%x len=%d\n", startAddr, len);

   return startAddr;
}

void
Region_Put(struct Region *r, ulong startAddr, size_t len)
{
   ASSERT(PAGE_ALIGNED(startAddr));
   ASSERT(len);

   DEBUG_MSG(6, "addr=0x%lx len=%d\n", startAddr, len);

   SYNCH_LOCK(&r->lock);

   FOR_ALL_PAGES_IN_RANGE(startAddr, len) {
      int oldVal;
      ASSERT(pn < r->pageLen);
      oldVal = Bit_TestClear(pn, r->bitmap);
      /* XXX: is it okay to unmap unmapped pages? 
       * Permit it for the moment, to allow us to
       * munmap all user mapping with one sys_munmap call. */
      //ASSERT(oldVal);
   } END_ALL_PAGES_IN_RANGE;

   SYNCH_UNLOCK(&r->lock);
}
