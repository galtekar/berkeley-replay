/*
stream logic:

open file/service stream
open elf stream
write ckpt
close elf stream
close file/service stream
*/

#include "sys.h"
#include "ckpt.h"
#include "ckptimpl.h"

#include "timings.h"

enum {
	MAX_CALLBACKS = 1000
};
static fn_t on_preckpt[MAX_CALLBACKS];
static void *on_preckpt_arg[MAX_CALLBACKS];
static unsigned num_on_preckpt;
static fn_t on_postckpt[MAX_CALLBACKS];
static void *on_postckpt_arg[MAX_CALLBACKS];
static unsigned num_on_postckpt;
static fn_t on_restart[MAX_CALLBACKS];
static void *on_restart_arg[MAX_CALLBACKS];
static unsigned num_on_restart;

static struct ckptfdtbl *fdtbl;

void
ckpt_on_preckpt(fn_t f, void *arg)
{
	if (num_on_preckpt >= MAX_CALLBACKS) {
		fprintf(stderr, "Warning: too many pre-ckpt callbacks\n");
		return;
	}
	on_preckpt[num_on_preckpt] = f;
	on_preckpt_arg[num_on_preckpt++] = arg;
}

void
ckpt_on_postckpt(fn_t f, void *arg)
{
	if (num_on_postckpt >= MAX_CALLBACKS) {
		fprintf(stderr, "Warning: too many post-ckpt callbacks\n");
		return;
	}
	on_postckpt[num_on_postckpt] = f;
	on_postckpt_arg[num_on_postckpt++] = arg;
}

void
ckpt_on_restart(fn_t f, void *arg)
{
	if (num_on_restart >= MAX_CALLBACKS) {
		fprintf(stderr, "Warning: too many restart callbacks\n");
		return;
	}
	on_restart[num_on_restart] = f;
	on_restart_arg[num_on_restart++] = arg;
}

static int
ckpt_save(int fd,
	  struct ckpt_header *head,
	  memregion_t *regions)
{

	int i, len;

	// First, checkpoint header.
	len = sizeof(struct ckpt_header);
	if( len != write( fd, head, len ) ) {
	      libckpt_fatal("cannot write checkpoint header\n");
	      return -1;
	}

	// Next, memory region list.
	len = (head->num_regions * sizeof(memregion_t));
	if( len != write( fd, regions, len ) ) {
	      libckpt_fatal("cannot write checkpoint memory region list\n");
	      return -1;
	}

	// Then each memory region (may zero out some).
	for (i = 0; i < head->num_regions; i++) {
		int written;
		len = regions[i].len;

		/* Make sure we the region is readable. Some regions, for example
		 * one that belongs to libc 2.3.5 in Fedora Core 3, may not be
		 * readable for some odd reason. */
		mprotect((void*)regions[i].addr, len, PROT_READ | regions[i].flags);

		/* Write the region to the file. */
		written = write( fd, (void*)regions[i].addr, len );

		/* Restore the region's original permissions. */
		mprotect((void*)regions[i].addr, len, regions[i].flags);

		if( written == -1 ) {	// Cannot read this segment?
			perror( "ckpt_save");

			char zeroes[len];
			memset( zeroes, 0, len);

			libckpt_warning("can't save region 0x%x-0x%x, saving zeros\n",
					regions[i].addr, regions[i].addr+len);
			written = write( fd, zeroes, len);
			if( written != len ) {
				libckpt_fatal("cannot write checkpoint region contents\n");
				return -1;
			}
		}
	}

	return 0;
}

static int getcmd(char *cmd, int max)
{
	int fd;
	int rv;

	fd = open("/proc/self/cmdline", O_RDONLY);

	if (0 > fd)
		return -1;
	rv = read(fd, cmd, max);
	close(fd);

	/* During replay, rv may be 0. */
	if (0 > rv)
		return -1;
	if (rv >= max)
		cmd[max-1] = '\0';
	else
		cmd[rv] = '\0';
	return 0;
}

	void
tls_save(struct ckpt_header *h)
{
	int gs;

	h->tls.entry_number = 6;  /* magic:
										  see linux/include/asm-i386/segment.h */

	/* Get the TLS segment descriptor from the kernel, who will get the
	 * appropriate entry from the LDT. */
	if (0 > syscall(SYS_get_thread_area, &h->tls)) {
		libckpt_fatal("cannot get tls segment\n");
		exit(1);
	}

	/* Save the TLS segmentation register. */
	asm("movw %%gs,%w0" : "=q" (gs));

	/* Why is this necessary? */
	h->gs = gs&0xffff;

	return;
}

	int
ckpt_ckpt(char *name, int options)
{
	struct ckpt_header head;
	memregion_t regions[MAXREGIONS];
	int fd;
	int i;
	/* int gdb_go = 1; */

	for (i = 0; i < num_on_preckpt; i++)
		on_preckpt[i](on_preckpt_arg[i]);

	if(name == NULL)
		name = ckpt_ckptname();

	if (0 > getcmd(head.cmd, sizeof(head.cmd))) {
		libckpt_fatal("cannot read my commandline arguments\n");
		return -1;
	}

	fd = ckpt_open_stream(name);
	if (0 > fd) {
		libckpt_fatal("cannot obtain a checkpoint stream\n");
		return -1;
	}

	/* All processes other than the master process should ignore
	 * shared memory regions, thereby avoiding writing out
	 * unnecessary copies of those shared memory regions. We need
	 * only 1 copy and we keep that in the master process's
	 * checkpoint. */

	__START_CKPT_TIMER(_read_self_regions);
	if (0 > read_self_regions(regions, &head.num_regions, 
				options & IGNORE_SHAREDMEM)) {
		libckpt_fatal("cannot read my memory map\n");
		return -1;
	}
	__STOP_CKPT_TIMER(_read_self_regions);

	if (0 == setjmp(head.jbuf)) {
		/* Checkpoint */
		head.brk = (unsigned long) sbrk(0);
		tls_save(&head);

		__START_CKPT_TIMER(_ckpt_save);
		if (0 > ckpt_save(fd, &head, regions)) {
			libckpt_fatal("cannot save the ckpt image\n");
			return -1;
		}
		__STOP_CKPT_TIMER(_ckpt_save);

		ckpt_close_stream(fd);

		if (!ckpt_shouldcontinue())
			_exit(0); /* do not call atexit functions */

		for (i = 0; i < num_on_postckpt; i++)
			on_postckpt[i](on_postckpt_arg[i]);

		fdtbl = NULL;

		return 0;
	}

	/* Restart */
	if (0 > unmap_ifnot_orig(regions, head.num_regions)) {
		libckpt_fatal("cannot purge restart code from address space\n");
		return -1;
	}

	if (0 > restore_mprotect(regions, head.num_regions)) {
		libckpt_fatal("cannot restore address space protection\n");
	}

	for (i = num_on_restart-1; i >= 0; i--)
		on_restart[i](on_restart_arg[i]);

	fdtbl = NULL;

	if( DEBUG ) printf( "Leaving ckpt_ckpt()\n" );
	return 1;
}

	static void
unlinklib()
{
	char *p;
	p = getenv("LD_PRELOAD");
	if(p == NULL)
		return;
	if(strstr(p, "tmplibckpt") == NULL)
		return;
	unlink(p);
	unsetenv("LD_PRELOAD");
}

	void
ckpt_init()
{
	unlinklib();
	ckpt_initconfig();
}
