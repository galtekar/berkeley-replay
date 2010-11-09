/* A simple and very inefficient, yet transparent to the application 
 * (thus talloc, tfree) memory allocator. It allocated at page 
 * granularity. */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>

#include <sys/syscall.h>
#include <unistd.h>

#include "libc_pointers.h"
#include "gcc.h"
#include "errops.h"
#include "logreplay.h"

#include "tmalloc.h"

#define MAX_MALLOC_SLOTS (8192*10)

#define DEBUG 0

#include "debug.h"


/* TODO: Make this code thread-safe! */

typedef struct malloc_entry {
	void* start;
	size_t size;
	int is_used;
} malloc_entry_t;

static malloc_entry_t malloc_table[MAX_MALLOC_SLOTS];

static int is_initialized = 0;

static void init_tmalloc() {
	if (!is_initialized) {
		memset(malloc_table, 0x0, sizeof(malloc_entry_t)*MAX_MALLOC_SLOTS);

		is_initialized = 1;
	}
}

static malloc_entry_t* get_free_slot() {
	int i;

	/* Find the first unused slot in the table. */
	for (i = 0; i < MAX_MALLOC_SLOTS; i++) {
		if (!malloc_table[i].is_used) {
			return &malloc_table[i];
		}
	}

	/* Don't call fatal() here, since it may allocate memory,
	 * and then we would end up in an infinite loop. */
	lprintf("tmalloc: no open slots, try increasing MAX_MALLOC_SLOTS.\n");

	/* Looks like we couldn't find a slot. */
	return NULL;
}

static malloc_entry_t* find_entry(void* start) {
	int i;

	for (i = 0; i < MAX_MALLOC_SLOTS; i++) {
		if (malloc_table[i].start == start) {
			return &malloc_table[i];
		}
	}

	return NULL;
}

HIDDEN int is_tblock(void* ptr) {
	return find_entry(ptr) != NULL;
}

HIDDEN void tfree(void* start) {
	malloc_entry_t* slot = NULL;

	DEBUG_MSG(6, "tfree: ptr=0x%x\n", start);

	init_tmalloc();

	if (start) {
		slot = find_entry(start);

		if (slot) {
			/* NOTE: Sriram's app crashes if we uncomment this. */
			//syscall(SYS_munmap, slot->start, slot->size);

			/* Open up the slot for future allocations. */
			slot->is_used = 0;
		}
	}
}

/* For now, we don't support mapping shared pages with tmalloc. 
 * This is because Planetlab (kernel 2.6.12, glibc 2.3.3) doesn't like 
 * it when we allocate shared pages with the mmap2 system call. Don't
 * know why that is, so I'm avoiding it. If you need to allocate
 * a shared page, do it with a call to glibc's mmap. */
HIDDEN void* tmalloc(size_t size) {
	void* mem = NULL;
	malloc_entry_t* free_slot = NULL;

	DEBUG_MSG(6, "tmalloc: size=%d\n", size);

	init_tmalloc();

	if (size == 0) return NULL;


	if ((free_slot = get_free_slot()) != NULL) {
		/* We can't simply reuse an existing slot, since the
		 * mapping may not be valid anymore. This is because
		 * libckpt may have not included it as part of the checkpoint.
		 * This may be because libckpt itself calls tmalloc when
		 * writing out the checkpoint. Thus, during replay, it seems
		 * as though this slot is already mapped in, but it isn't,
		 * thereby causing a crash. */
#if 0
			/* If the glove fits, wear it. */
			if (size < free_slot->size) {
				DEBUG_MSG("tmalloc: found a slot that fits (slot size=%d)\n",
						free_slot->size);

				mem = free_slot->start;

				assert(mem != NULL);
			} else
#endif
			{
				/* Make the slot bigger. */
				DEBUG_MSG(6, "tmalloc: found a small slot, making it bigger\n");

				/* If it was previously allocated, deallocate it. */
				if (free_slot->start) {
					syscall(SYS_munmap, free_slot->start, free_slot->size);
				}

				/* Allocate a bigger slot. */
				/* We invoke mmap using syscall rather calling the libc pointer
				 * because the libc pointer may not be initialized at this
				 * point. */
				mem = (void*) syscall(SYS_mmap2, (void*)0x0, size, 
						PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

				if (mem != MAP_FAILED) {
					free_slot->start = mem;
					free_slot->size = size;
					free_slot->is_used = 1;
				} else {
					mem = NULL;
					free_slot->is_used = 0;
				}
			}
	} 

	DEBUG_MSG(6, "tmalloc: ret=0x%x\n", mem);

	return mem;
}

HIDDEN void* tcalloc(size_t nmemb, size_t size) {
	void* ret = NULL;
	int final_size = nmemb * size;

	DEBUG_MSG(6, "tcalloc: nmemb=%d, size=%d\n", nmemb, size);

	init_tmalloc();

	ret = tmalloc(final_size);

	if (ret) {
		memset(ret, 0x0, final_size);
	}

	return ret;
}

HIDDEN void *trealloc(void *ptr, size_t size) {
	void* ret = NULL;
	malloc_entry_t* m = NULL;

	DEBUG_MSG(6, "trealloc: ptr=0x%x, size=%d\n", ptr, size);

	init_tmalloc();

	if (size) {
		if (ptr) {
			m = find_entry(ptr);

			if (m) {
				ret = tmalloc(size);

				if (ret) {
					memcpy(ret, ptr, m->size);
					tfree(ptr);
				}
			}
		} else {
			ret = tmalloc(size);
		} 
	} else {
		tfree(ptr);
	}

	return ret;
}
