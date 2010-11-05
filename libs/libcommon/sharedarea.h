#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "syncops.h"
#include "sys/types.h"

/* Must be called before accessing shared area variables. */
extern void SharedArea_Init(size_t sa_size, int useSafeMalloc);

/* Static -- Data segment allocation. */
#define SHAREDAREA      __attribute__ ((section (".sharedarea")))
#define PROCESSAREA /* use to denote NOT SHAREDAREA */

/* Dynamic -- Heap-allocation (based on Doug Lea's malloc). */
extern void* SharedArea_Malloc(size_t bytes);
extern void* SharedArea_Memalign(size_t alignment, size_t bytes);
extern void* SharedArea_Realloc(void *oldmem, size_t bytes);
extern void  SharedArea_Free(void *p, size_t bytes);

/* Dynamic -- Heap-allocation (page granularity). */
extern unsigned long SharedArea_Mmap(void *addr, size_t len);
extern int SharedArea_Munmap(void *addr, size_t len);

#if 0
/* XXX: finish implementation at some point -- this will improve
 * allocator efficiency (by how much?). */
extern unsigned long SharedArea_SbrkCallback(long incr);
#endif

#ifdef __cplusplus
}
#endif
