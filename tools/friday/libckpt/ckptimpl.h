/*
 * The name of this structure varies among Linux versions.
 * It was `modify_ldt_ldt_s' on some, then changed to
 * `user_desc'.  Always in /usr/include/asm/ldt.h.
 * We re-define it so that we don't have to figure out
 * the right name.
 */
struct linux_ldt{
	unsigned int  entry_number;
	unsigned long base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit:1;
	unsigned int  contents:2;
	unsigned int  read_exec_only:1;
	unsigned int  limit_in_pages:1;
	unsigned int  seg_not_present:1;
	unsigned int  useable:1;
};

/* FIXME: Perhaps we should have a richer model of
   memory to cope with these hacks for pages with
   special semantics.*/
enum {
	DEBUG =		0,
	STACKHACK =	0xbf000000,	/* how we guess which pages are
					   part of the stack */
	VDSO_PAGE_HACK =	0xffff0000,	/* we do not ckpt any
					   pages above this address;
					   they are managed by kernel
					   for syscall trap (i.e., the VDSO) */
	MAXREGIONS =	4096,		/* Maximum num of
					   noncontiguous memory
					   regions */
	REGION_HEAP =	0x8,		/* Memory region is for heap;
					   not equal to any PROT_* */
};

struct ckpt_header {
	char cmd[1024];    /* command name for ps and /proc */
	int num_regions;
	jmp_buf jbuf;
	unsigned long brk;

	/* thread-local storage state */
	struct linux_ldt tls; /* tls segment descriptor */
	unsigned long gs;            /* gs register */
};

typedef
struct memregion{
	unsigned long addr;
	unsigned long len;
	unsigned flags;  /* bitmask of PROT_* and REGION_HEAP */
	unsigned map_flags;	/* MAP_SHARED, MAP_PRIVATE, etc. */
} memregion_t;

struct ckpt_restore{
	int fd;
	struct ckpt_header head;
	memregion_t orig_regions[MAXREGIONS];
};

/* ckpt.c */
void ckpt_init();

/* mem.c */
void heap_extension(memregion_t *region);
int read_self_regions(memregion_t *regions, int *num_regions, 
		int should_ignore_shared_memory);
void print_regions(const memregion_t *regions, int num_regions, const char *msg);
int map_orig_regions(const struct ckpt_restore *restbuf);
int addr_in_regions(unsigned long addr, const memregion_t *regions, int num_regions);
int set_writeable(const memregion_t *regions, int num_regions);
int restore_mprotect(const memregion_t *orig, int num_orig);
int call_with_new_stack(unsigned long num_pages,
			const memregion_t *verboten,
			int num_verboten,
			void(*fn)(void *), void *arg);
int unmap_ifnot_orig(const memregion_t *orig, int num_orig);

/* util.c */
int xwrite(int sd, const void *buf, size_t len);
int xread(int sd, void *buf, size_t len);
void call_if_present(char *name, char *lib);
void libckpt_fatal(char *fmt, ...);
void libckpt_warning(char *fmt, ...);
void *xmalloc(size_t size);
char *xstrdup(char *s);
int ckpt_mapsig(char *s);


/* config.c */
void ckpt_initconfig();
int ckpt_shouldcontinue();
char *ckpt_ckptname();


/* uri.c */
int ckpt_open_stream(char *name);
void ckpt_close_stream(int fd);
