#include "sys.h"
#include "ckptimpl.h"
#include "ckpt.h"

#define MAX_IGNORED_REGIONS 256

static memregion_t ignored_regions[MAX_IGNORED_REGIONS];
static int num_ignored_regions = 0;

void ckpt_mask_region(const void* addr, size_t size) {
	assert(num_ignored_regions < MAX_IGNORED_REGIONS);

	ignored_regions[num_ignored_regions].addr = (unsigned long) addr;
	ignored_regions[num_ignored_regions].len = size;

	num_ignored_regions++;

}

void ckpt_unmask_region(const void* addr, size_t size) {

	return;
}

/* debugging */
void
print_regions(const memregion_t *regions, int num_regions, const char *msg)
{
	int i;

	fprintf(stdout, "CKPT-DEBUG REGION DUMP: %s\n", msg); 
	for (i = 0; i < num_regions; i++) {
		fprintf(stdout,
			"CKPT-DEBUG %08lx - %08lx  %c%c%c%c   %8ld bytes",
			regions[i].addr, regions[i].addr + regions[i].len,
			(regions[i].flags & PROT_READ  ? 'r' : '-'),
			(regions[i].flags & PROT_WRITE ? 'w' : '-'),
			(regions[i].flags & PROT_EXEC  ? 'x' : '-'),
			(regions[i].map_flags & MAP_SHARED ? 's' : 'p'),
			regions[i].len);
		if (regions[i].flags & REGION_HEAP) {
			fprintf(stdout, "\t[heap]");
		}

		fprintf(stdout, "\n");
	}
}

static void 
parse_region(const char *buf, memregion_t *r) {
	/* Consider parsing this with sscanf and the MAPS_LINE_FORMAT
	   in linux/fs/proc/array.c. */
	/* THIS FUNCTION AND ITS CALLEES MAY NOT CALL strtok */
	char *p;
	unsigned long endaddr;
	unsigned long b;
	r->addr = strtoul(buf, &p, 16);
	p++;  /* skip '-' */
	endaddr = strtoul(p, &p, 16);
	r->len = endaddr - r->addr;
	p++;  /* skip ' ' */
	r->flags = 0;
	r->map_flags = 0;
	while (*p != ' ')
		switch (*p++) {
			case 'r':
				r->flags |= PROT_READ;
				break;
			case 'w':
				r->flags |= PROT_WRITE;
				break;
			case 'x':
				r->flags |= PROT_EXEC;
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
				assert(0);
		}

	/* Find the end of the heap. */
	b = (unsigned long)sbrk(0);

	/* Are we looking at the heap? */
	if (b > r->addr && b <= r->addr+r->len)
		r->flags |= REGION_HEAP;
}

/* Linux /proc/self/maps, as of 2.2, is spooky.  We read it in one
	slurp in the hopes of getting an accurate reading of the address
	space organizaion.  When we've read it in more than one piece,
	(e.g., with stdio), we've seen it list pages that aren't really
	allocated.  We're not sure what the real problem is, but we don't
	seem to have problems if we use one slurp. */
	int
read_self_regions(memregion_t *regions, int *num_regions, 
		int should_ignore_shared_memory)
{
	int fd;
	char *p;
	int ret, n;
	int nread;
	char procmaps[100 * PAGE_SIZE];


	fd = open("/proc/self/maps", O_RDONLY);
	if (0 > fd) {
		fprintf(stderr, "cannot open /proc/self/maps for reading\n");
		return -1;
	}

	/* Zero to ensure there is always a nul following the data */
	memset(procmaps, 0x0, sizeof(procmaps));
	p = procmaps;
	nread = 0;

	while (1) {
		if (nread >= sizeof(procmaps)) {
			fprintf(stderr, "memory map limit exceeded\n");
			return -1;
		}
		ret = read(fd, p, PAGE_SIZE);
		if (0 > ret) {
			fprintf(stderr, "cannot read from /proc/self/maps\n");
			return -1;
		}
		if (ret == 0)
			break;

		p += ret;
		nread += ret;
	}

	/* We assume ALL of the map data can be read into procmaps in
		one slurp.  If this fails, it is POSSIBLE that the size of
		the map is larger than procmaps.  */
	assert(sizeof(procmaps) > ret);
	p = strtok(procmaps, "\n");
	n = 0;
	while (p) {
		assert(n < MAXREGIONS);
		parse_region(p, &regions[n]);
		p = strtok(NULL, "\n");
		if (regions[n].addr >= VDSO_PAGE_HACK)
			continue;

		/* Ignore shared regions if requested. liblog slave processes
		 * will make this request so that during replay, responsibility
		 * of restoring the shared memory segment lies solely with
		 * the checkpoint master process. */
		if (regions[n].map_flags & MAP_SHARED && should_ignore_shared_memory) {
			continue;
		}

		/* If the address of this regions is in the list of regions we
		 * are supposed to ignore, then go to the next iteration. */
		if (addr_in_regions(regions[n].addr, ignored_regions, 
					num_ignored_regions)) {
			continue;
		}

		++n;
	}

	*num_regions = n;

	ret = read(fd, procmaps, sizeof(procmaps));
	assert(0 == ret);  /* See above assert */

	close(fd);


	return 0;
}

int
addr_in_regions(unsigned long addr,
		const memregion_t *regions,
		int num_regions) {
	int i;
	for (i = 0; i < num_regions; i++) {
		if (regions[i].addr <= addr
				&& addr < regions[i].addr + regions[i].len)
			return 1;
	}
	return 0;
}

/* FIXME: This seems to work, but the mprotect manpage says that we
	are forbidden from setting PROT_WRITE on pages that are backed by
	files for which we don't have write permission.  Perhaps we should
	jump to the safe library first, unmap everything, and mmap fresh
	pages? */
int
set_writeable(const memregion_t *regions,
		int num_regions) {
	int i;
	for (i = 0; i < num_regions; i++)
		if (0 > mprotect((void*)regions[i].addr,
					regions[i].len,
					PROT_WRITE|(regions[i].flags&(~REGION_HEAP)))) {
			perror("mprotect");
			return -1;
		}
	return 0;
}

int
restore_mprotect(const memregion_t *orig, int num_orig) {
	int i;
	for (i = 0; i < num_orig; i++)
		if (0 > mprotect((void *)orig[i].addr,
					orig[i].len,
					orig[i].flags&(~REGION_HEAP))) {
			perror("mprotect");
			return -1;
		}
	return 0;
}

int
map_orig_regions(const struct ckpt_restore *restbuf) {
	int i;

	/* Regions for this process */
	memregion_t regions[MAXREGIONS];
	int num_regions;

	/* It doesn't matter whether we ignore shared memory regions
	 * or not since there shouldn't be any shared memory regions
	 * at this point in execution. */
	if (0 > read_self_regions(regions, &num_regions, 0)) {
		fprintf(stderr, "cannot read my memory map\n");
		return -1;
	}

	/* First the brk, so we don't interfere with other ckpt
		pages between the current brk (at low address)
		and the new brk. This is important because the brk()
	   system call will fail if the new brk regions intersects
	   an existing mapping. See kernel source for details. */
	for (i = 0; i < restbuf->head.num_regions; i++) {
		if (!(restbuf->orig_regions[i].flags & REGION_HEAP))
			continue;

#if DEBUG
		printf("Found the heap! (start=0x%x len=%d head.brk=0x%x)\n",
				restbuf->orig_regions[i].addr, restbuf->orig_regions[i].len,
				restbuf->head.brk);
#endif

		/* Observe that this code executes only if there was a heap region
		 * in the original address space. */
		if ((unsigned long)sbrk(0) < restbuf->head.brk
				&& 0 > syscall(SYS_brk, ((void*)restbuf->head.brk))) {
			perror("brk");
			fprintf(stderr, "Failed to restore the brk to 0x%lx\n", restbuf->head.brk);
			return -1;
		}
		break;
	}

	for (i = 0; i < restbuf->head.num_regions; i++) {
		unsigned long addr;

		if (restbuf->orig_regions[i].flags & REGION_HEAP)
			continue; /* already done */

		for (addr = restbuf->orig_regions[i].addr;
				addr < (restbuf->orig_regions[i].addr
					+ restbuf->orig_regions[i].len);
				addr += PAGE_SIZE) {

			/* PROBLEM: This code says that if a memory region is
			 * already allocated, and that same memory region is found
			 * in the checkpoint image, then there is no need to mmap()
			 * it in again. This is genereally correct, but doesn't work
			 * if shared memory regions from the checkpoint image overlap
			 * with regions that are already allocated. In such a case,
			 * those regions would not be marked shared.
			 * FIX: One solution is to mark the region as shared if there 
			 * is an overlap, but the BSD mmap() facility doesn't allow us 
			 * to do that without first destroying the segment. And since 
			 * the overlapped segment is obviously in use at the moment, we 
			 * cannot unmap it and remap it as shared at this point. Thus, 
			 * this operation is deferred to continuesafe() in safe.c. */
			if (! addr_in_regions(addr, regions, num_regions)) {
				void *rv;
				int prot = PROT_READ|PROT_WRITE|PROT_EXEC; 
				int flags = MAP_FIXED|MAP_ANON;

				/* Made it so that we restore the map flags (i.e.,
				 * MAP_PRIVATE, MAP_SHARED) accurately. */
				flags |= restbuf->orig_regions[i].map_flags;

				/* FIXME: hack to find the stack (newer versions
				 * of the Linux kernel tell you where the stack
				 * and heap lie in /proc/maps). */
				if (addr > STACKHACK)
					flags |= MAP_GROWSDOWN;

				rv = mmap((void*) addr, PAGE_SIZE, prot, flags|MAP_FIXED, 0, 0);
				if (MAP_FAILED == rv) {
					fprintf(stderr,
							"mmap() could not restore page at 0x%08lx\n",
							addr);
					perror("mmap");
					return -1;
				}

			}

		}
	}

	return 0;
}

static unsigned long
find_new_stack(unsigned long num_pages,
		const memregion_t *verboten,
		int num_verboten) {
	unsigned long ret;
	int i;

	/* Find (NUM_PAGES + 2) free pages in the address space
		represented by VERBOTEN.  Set RET to the address of the
		second page.  The two page padding (unallocated) will cause
		stack underflow or overflow to generate a segfault. */
	/* Start from high mem to avoid allocating new stack
		between old brk and new brk. */
	for (i = num_verboten-1; i > 0; i--) {
		if (PAGE_SIZE * (2 + num_pages)
				<= verboten[i].addr - (verboten[i-1].addr + verboten[i-1].len)) {
			ret = verboten[i-1].addr + verboten[i-1].len + PAGE_SIZE;
			goto foundstack;
		}
	}
	fprintf(stderr, "cannot find a new stack\n");
	return -1UL;
foundstack:
	/* Allocate the new stack */
	if (MAP_FAILED == mmap((void*) ret, num_pages * PAGE_SIZE,
				PROT_READ|PROT_WRITE|PROT_EXEC,
				MAP_PRIVATE|MAP_ANON|MAP_FIXED,
				0, 0)) {
		perror("mmap");
		return -1UL;
	}

	/* Return the highest 4-byte aligned address in the new stack 
		minus a buffer for any functions that might return */
	return ret + num_pages * PAGE_SIZE - 4 - 16;
}

int
call_with_new_stack(unsigned long num_pages,
		const memregion_t *verboten,
		int num_verboten,
		void(*fn)(void *), void *arg) {
	unsigned long stack_base;

	stack_base = find_new_stack(num_pages, verboten, num_verboten);
	if (-1UL == stack_base) {
		return -1;
	}

	/* This is simpler that using setjmp/longjmp to manipulate
	 * the stack pointer. Also, JB_SP is not defined on all
	 * Fedora systems (Core 5 in particular). */
	asm volatile ("movl %0, %%esp" : : "r" (stack_base));
	fn(arg);

	return 0;
}


/* FIXME: ORIG was obtained before the ckpt was taken.  We may have
	added stack pages to call this function.  These pages would not be
	in ORIG, but they would be found when read_self_regions is called.
	So, they'll be unmapped, and this function will crash. 
FIXME: For now, we do not unmap segments above STACKHACK.
 */
int
unmap_ifnot_orig(const memregion_t *orig, int num_orig) {
	memregion_t curr[MAXREGIONS];
	unsigned long addr;
	int i, num_curr;

	/* In our restart scheme, only the checkpoint master process is aware
	 * of shared regions. Slave processes are not. The danger here,
	 * however, is that the slave process will attempt to unmap the
	 * shared region because it thinks that region was not part of the
	 * map found in the checkpoint image. But this is undesirable, and is
	 * a side-effect of the fact that only the master process knows about
	 * the shared memory regions. To fix this, we will ignore shared
	 * memory regions in this call to read_self_regions(), thereby 
	 * ensuring that the following code will not unmap any shared memory
	 * pages. */
	if (0 > read_self_regions(curr, &num_curr, 1))
		return -1;

	for (i = 0; i < num_curr; i++)
		for (addr = curr[i].addr;
				addr < (curr[i].addr + curr[i].len);
				addr += PAGE_SIZE)
			if (!addr_in_regions(addr, orig, num_orig)
					&& addr < STACKHACK)
				if (0 > munmap((void*)addr, PAGE_SIZE)) {
					perror("munmap");
					return -1;
				}

	return 0;
}
