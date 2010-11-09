#ifndef __TMALLOC_H
#define __TMALLOC_H

#define TMALLOC_NOSHARED 0
#define TMALLOC_SHARED 1

/* Is this a tmalloced block? */
extern int is_tblock(void* ptr);

/* Allocates SIZE bytes of memory on the heap. Newly allocated
 * memory will be uninitialized. */
extern void* tmalloc(size_t size);

/* Changes  the  size of the memory block pointed to by ptr to
	size bytes.  The contents will be unchanged to the minimum of the  old
	and  new  sizes; newly allocated memory will be uninitialized.
*/
extern void *trealloc(void *ptr, size_t size);

/* Allocates SIZE bytes of memory on the heap and initializes it. */
extern void* tcalloc(size_t nmemb, size_t size);

/* Deallocates the object allocated with address starting at START. */
extern void tfree(void* start);

#endif
