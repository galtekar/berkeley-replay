#include "sys.h"
#include "ckptimpl.h"
#include "ckpt.h"

#define DEBUG 1

/* The number of pages we allocate to the new stack allocated
 * by call_with_new_stack(). */
#define NUM_STACK_PAGES 10000

/* WARNING!: Don't put any variables on the heap! We reset brk()
 * at somepoint doing restart, which means that some of those
 * variables may become inaccessible. Thus, it's best to pass
 * all info on the stack. */

typedef struct rarg {
	char tmpl[1024];
	struct ckpt_restore globalrestbuf;
} rarg_t;

static int
open_ckpt_file(struct ckpt_restore *cr, char* ckpt_filename)
{
	int ret;

	cr->fd = open(ckpt_filename, O_RDONLY);

	if(cr->fd < 0){
		libckpt_fatal("cannot open checkpoint: %s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	ret = xread(cr->fd, &cr->head, sizeof(cr->head));
	if (sizeof(cr->head) != ret) {
		libckpt_fatal("cannot read checkpoint file's header\n");
		ret = -1;
		goto out;
	}

	ret = xread(cr->fd, cr->orig_regions,
		    sizeof(memregion_t) * cr->head.num_regions);
	if (sizeof(memregion_t) * cr->head.num_regions != ret) {
		libckpt_fatal("cannot read checkpoint file's memory map\n");
		ret = -1;
		goto out;
	}

	ret = 0; /* All's well */
out:
	if (ret && cr->fd >= 0)
		/* Normally leave it open; we still need to read the pages */
		close(cr->fd);
	return ret;
}

static void
close_ckpt_file(struct ckpt_restore *cr)
{
	close(cr->fd);
}

static int
load_safe_restart_code(void **f, char *libname)
{
	void *hdl = NULL;
	void *fn;
	char* error;

#if 0
	{
		char *s = NULL;

		s = getenv("LD_LIBRARY_PATH");

		printf("s=%s\n", s);
	}
#endif

	dlerror();
	hdl = dlopen(libname, RTLD_LAZY);
	if(!hdl){
		libckpt_fatal("cannot load restart helper code (%s): %s\n",
				libname, dlerror());
		return -1;
	}

	dlerror();

	fn = dlsym(hdl, "continuesafe");
	if ((error = dlerror()) != NULL) {
		libckpt_fatal(
			"restart: missing symbols in restart library: %s\n",
			error);
		return -1;
	}
	*f = fn;
	return 0;
}

/* This function expects to be called on a fresh stack */
static void continue_restart(void *arg)
{
	void *funcp;
	char* libname;
	rarg_t my_arg_copy;

	void (*continuesafe)(struct ckpt_restore *,
			     memregion_t *regions, int num_regions);
	memregion_t _regions[MAXREGIONS];
	int _num_regions;

	/* Copy the argument pointed to by arg (which lies on the
	 * original stack) to this stack, which is newly created.
	 * We do this because the original stack is no longer stable. */
	memcpy(&my_arg_copy, arg, sizeof(rarg_t));
	libname = my_arg_copy.tmpl;

	if (0 > map_orig_regions(&my_arg_copy.globalrestbuf)) {
		libckpt_fatal("error blocking regions of ckpt\n");
		return;
	}

	if (0 > load_safe_restart_code(&funcp, libname)) {
		libckpt_fatal("cannot load safe restart code\n");
		return;
	}

	/* Loading the library may grow the heap.  Undo that. */
	/* CAUTION: This may render some libckpt globals inaccessible.
	 * Thus, it's best to always use the stack for parameter passing. */
	/* NOTE: We invoke the brk() syscall directly, rather than going
	 * through libc, because we want to avoid the additional checks that
	 * libc does. If we do use the libc call, then an error may be
	 * returned. */
	if (0 > syscall(SYS_brk, (void*)my_arg_copy.globalrestbuf.head.brk)) {
		perror("brk");
		libckpt_fatal("cannot restore brk to 0x%x\n", 
				my_arg_copy.globalrestbuf.head.brk);
		return;
	}

	/* Reread the current memory map so we can remap additonal
	 * shared regions. It shouldn't matter whether or not we
	 * ignore shared regions here, since remap_shared_regions()
	 * is indifferent. */
	if (0 > read_self_regions(_regions, &_num_regions, 0)) {
		libckpt_fatal("cannot read my memory map\n");
		return;
	}

	continuesafe = (void(*)(struct ckpt_restore*,
				memregion_t *regions,
				int num_regions))funcp;
	continuesafe(&my_arg_copy.globalrestbuf, _regions,
		     _num_regions);  /* Does not return */
	libckpt_fatal("unexpected return from safe restart code\n");
}

/* Compare two memregion_t structures. */
static int
mcmp(const void *ap, const void *bp)
{
	memregion_t *a = (memregion_t *)ap;
	memregion_t *b = (memregion_t *)bp;
	unsigned long a_addr = a->addr;
	unsigned long b_addr = b->addr;
	unsigned long a_len = a->len;
	unsigned long b_len = b->len;

	if (a_addr < b_addr)
		return -1;
	if (a_addr > b_addr)
		return 1;
	if (a_len < b_len)
		return -1;
	if (a_len > b_len)
		return 1;
	return 0;
}

/* If regions intersect they will be merged into one.
   The state of the flags is undefined in that case. */
static void
munion(memregion_t *a, int lena,
       memregion_t *b, int lenb,
       memregion_t *c, int *lenc)
{
	int i, lent;
	memregion_t t[lena + lenb];
	memregion_t *tp, *end, *cp;

	if (lena + lenb == 0) {
		*lenc = 0;
		return;
	}

	/* Copy all regions into one buffer */
	lent = 0;
	for (i = 0; i < lena; i++)
		t[lent++] = a[i];
	for (i = 0; i < lenb; i++)
		t[lent++] = b[i];

	/* Sort by start address */
	qsort(t, lent, sizeof(memregion_t), mcmp);

	/* Fold overlapping regions */
	tp = t;
	cp = c;
	end = &t[lent];
	while (tp < end) {
		memregion_t *np = tp + 1;

		while (np < end
		       && tp->addr + tp->len >= np->addr) {
			if (np->addr + np->len > tp->addr + tp->len)
				tp->len = np->addr + np->len - tp->addr;
			++np;
		}
		*cp++ = *tp;
		tp = np;
	}
	*lenc = cp - &c[0];
}

/* Outputs interesting information about the checkpoint file. */
void ckpt_info( char *ckpt_filename ) {
	memregion_t selfregions[MAXREGIONS];
	int num_selfregions;
	memregion_t verboten[MAXREGIONS];
	int num_verboten;

	rarg_t arg;

	if (0 > open_ckpt_file(&arg.globalrestbuf, ckpt_filename)) {
		libckpt_fatal("error reading the checkpoint file\n");
		return;
	}

	print_regions(arg.globalrestbuf.orig_regions,
			arg.globalrestbuf.head.num_regions,
			"ORIG-REGIONS");

	/* We shouldn't ignore shared memory segments here since we
	 * need to set all mapped pages writeable. */
	if (0 > read_self_regions(selfregions, &num_selfregions, 0)) {
		libckpt_fatal("cannot read my memory map\n");
		return;
	}

	if (0 > set_writeable(selfregions, num_selfregions)) {
		libckpt_fatal("cannot set my memory to writable\n");
		return;
	}

	munion(arg.globalrestbuf.orig_regions,
			arg.globalrestbuf.head.num_regions,
			selfregions,
			num_selfregions,
			verboten,
			&num_verboten);

	close_ckpt_file(&arg.globalrestbuf);
}

/* Overwrites the current process address space with the address space
 * and data contained within the checkpoint file. Resumes execution at the
 * point where the checkpoint was taken. */
void ckpt_restart( char *ckpt_filename ) {
	memregion_t selfregions[MAXREGIONS];
	int num_selfregions;
	memregion_t verboten[MAXREGIONS];
	int num_verboten;
	rarg_t arg;

	/* unpack restart helper code */
	strcpy( arg.tmpl, "librestart.so" );

	arg.globalrestbuf.fd = -1;

	if (0 > open_ckpt_file(&arg.globalrestbuf, ckpt_filename)) {
		libckpt_fatal("error reading the checkpoint file\n");
		return;
	}

	/* We shouldn't ignore shared memory segments here since we
	 * need to set all mapped pages writeable. */
	if (0 > read_self_regions(selfregions, &num_selfregions, 0)) {
		libckpt_fatal("cannot read my memory map\n");
		return;
	}

	if (0 > set_writeable(selfregions, num_selfregions)) {
		libckpt_fatal("cannot set my memory to writable\n");
		return;
	}

	munion(arg.globalrestbuf.orig_regions,
			arg.globalrestbuf.head.num_regions,
			selfregions,
			num_selfregions,
			verboten,
			&num_verboten);

#if 0
	{
		char *s = NULL;

		s = getenv("LD_LIBRARY_PATH");

		printf("s=%s\n", s);
	}
#endif

	call_with_new_stack(NUM_STACK_PAGES, verboten, num_verboten,
			continue_restart, &arg);

	/* We should not be here */
	close_ckpt_file(&arg.globalrestbuf);
}
