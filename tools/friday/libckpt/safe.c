#include "sys.h"
#include "ckptimpl.h"

#define DEBUG 0

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

static struct ckpt_restore safe_cr;
static memregion_t safe_regions[MAXREGIONS];
static int safe_num_regions;

static void
die()
{
	*((int *)0) = 0;
}

void
tls_restore(struct ckpt_header *h)
{
	if (0 > syscall(SYS_set_thread_area, &h->tls))
		die();
	asm("movw %w0,%%gs" :: "q" (h->gs));
	return;
}

int
xread(int sd, void *buf, size_t len)
{
	char *p = (char *)buf;
	size_t nrecv = 0;
	ssize_t rv;
	while (nrecv < len) {
		rv = read(sd, p, len - nrecv);
		if (0 > rv)
			return -1;
		if (0 == rv)
			return 0;
		nrecv += rv;
		p += rv;
	}
	return nrecv;
}

/**
 * Iterate over the restored region map, remapping pages as "shared"
 *   when necessary.
 * This call is necessary because the bootstrap and restored memory
 *   regions may overlap, and we cannot convert a page to shared state
 *   without destroying its contents, so the earlier call to
 *   map_orig_regions() is insufficient.
 */
static int remap_shared_regions( struct ckpt_restore *cr,
		memregion_t *regions, int num_regions )
{
	int i,j,ret;
	unsigned long start_addr;
	unsigned long end_addr;
	void * mapped;
	size_t length;
	int prot = PROT_READ|PROT_WRITE;
	int flags = MAP_ANON;

	/* Scan the region maps in parallel, looking for overlap. */
	for( i=0,j=0; i<cr->head.num_regions && j<num_regions; ) {
		if( DEBUG ) {
			printf( "orig[%d]: %lx-%lx \t new[%d]: %lx-%lx\n",
					i, cr->orig_regions[i].addr, (cr->orig_regions[i].addr +
						cr->orig_regions[i].len),
					j, regions[j].addr, (regions[j].addr + regions[j].len));
		}
		if( (cr->orig_regions[i].addr <
					(regions[j].addr + regions[j].len)) &&
				(regions[j].addr < (cr->orig_regions[i].addr +
										  cr->orig_regions[i].len)) ) {
			// Some overlap!
			if( DEBUG ) {
				printf( "orig map_flags: %x \t new map_flags: %x\n",
						cr->orig_regions[i].map_flags, regions[j].map_flags );
			}
			if( cr->orig_regions[i].map_flags != regions[j].map_flags ) {
				if( DEBUG ) printf( "Flags do not match!\n" );
				start_addr = MAX( cr->orig_regions[i].addr, regions[j].addr );
				end_addr = MIN( (cr->orig_regions[i].addr + cr->orig_regions[i].len),
						(regions[j].addr + regions[j].len) );
				length = end_addr - start_addr;
				if( DEBUG ) printf( "overlap: %lx-%lx (%x)\n", start_addr, end_addr, length );
				ret = munmap( (void*)start_addr, length );
				if( DEBUG ) printf( "munmap returned: %d\n", ret );
				mapped = mmap( (void*)start_addr, length, prot,
						(flags | cr->orig_regions[i].map_flags), 0, 0 );
				if( DEBUG ) printf( "mmap returned: %p vs %p\n", mapped, (void*)start_addr );

			} else {
				if( DEBUG ) printf( "Flags match!\n" );	
			}
		}
		/* Now advance one of the region maps */
		if( (cr->orig_regions[i].addr + cr->orig_regions[i].len)
				<= (regions[j].addr + regions[j].len) ) {
			++i;	// orig_regions[i] ends first
		} else {
			++j;	// regions[j] ends first
		}    
	}
	return 0;
}

	void
continuesafe(struct ckpt_restore *cr,
		memregion_t *regions, int num_regions)
{
	int i;

	/* Copy parameters to safe memory region */
	safe_cr = *cr;
	safe_num_regions = num_regions;
	for( i = 0; i < safe_num_regions; ++i ) {
		safe_regions[i] = regions[i];
	}

	/* Remap any pages that should be shared */
	remap_shared_regions( &safe_cr, safe_regions, safe_num_regions );

	cr = NULL; /* This pointer is in unsafe memory */
	for (i = 0; i < safe_cr.head.num_regions; i++) {
		/*printf("addr=0x%lx len=%d flags=0x%x map_flags=0x%x\n", safe_cr.orig_regions[i].addr,
				safe_cr.orig_regions[i].len, safe_cr.orig_regions[i].flags,
				safe_cr.orig_regions[i].map_flags);*/
		if (safe_cr.orig_regions[i].len
				!= xread(safe_cr.fd,
					(void *)safe_cr.orig_regions[i].addr,
					safe_cr.orig_regions[i].len))
			return;

		/* Restore the region's original permissions, now that we are
		 * done restoring its contents. */
		mprotect(safe_cr.orig_regions[i].addr, safe_cr.orig_regions[i].len,
				safe_cr.orig_regions[i].flags);
	}

	close(safe_cr.fd);

#if 0
	/* geels 7/26/2005:
	 * This code seems unnecessary and incorrect. */

	/* copy the command */
	p = (char *)safe_cr.argv0;
	q = safe_cr.head.cmd;
	while (*q)
		*p++ = *q++;
	*p = '\0';
#endif
	/* restoring tls here restores ability to call
		the libc tls-based system call trap (through
		GS register) ... which the code after longjmp
		expects to use. */
	tls_restore(&safe_cr.head);

	longjmp(safe_cr.head.jbuf, 1);
	die();
}
