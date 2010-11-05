/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
//#include "libcommon/sharedarea.h"
//#include "libcommon/debug.h"
#include "vkernel/public.h"

/*
 *-----------------------------------------------------------------------
 * Kernel memory allocation routines --
 *
 * Summary:
 *    
 *    Synonyms for SharedArea_*. We need them to intercept malloc/free/etc.
 *    calls made from libraries that we link with (e.g., dietlibc,
 *    or libperfctr). We intercept these calls so that they do not
 *    mmap memory outside of the kernel's area in the memory space.
 *    This helps avoid address-space non-determinism.
 *
 *-----------------------------------------------------------------------
 */



void* malloc(size_t bytes) {
   void *retptr;

   retptr = SharedArea_Malloc(bytes);

   return retptr;
}

void* realloc(void* oldmem, size_t bytes) {
   return SharedArea_Realloc(oldmem, bytes);
}

void* calloc(size_t n_elements, size_t elem_size) {
   void *retptr;
   size_t sz = n_elements * elem_size;

   retptr = malloc(sz);
   
   if (retptr) {
      memset(retptr, 0, sz);
   }

   return retptr;
}

void* memalign(size_t alignment, size_t bytes) {
   void *retptr;

   retptr = SharedArea_Memalign(alignment, bytes);

   return retptr;
}

void free(void *ptr) {
   ASSERT_KPTR(ptr);
   SharedArea_Free(ptr, 0 /* don't do a sanity check on allocation size */);
}
