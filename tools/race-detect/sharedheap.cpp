#include "sharedheap.h"

void* SharedHeap::operator new(size_t sz) {
   void *ptr;

   ptr = SharedArea_Malloc(sz);

   if (!ptr) {
      throw std::bad_alloc();
   }

#if 0
   DLOG("New: %d bytes at 0x%lx\n", sz, (ulong)ptr);
#endif

   return ptr;
}

void SharedHeap::operator delete(void *p) {
   // C says okay to delete NULL pointer
   SharedArea_Free(p, 0);

#if 0
   DLOG("Free: 0x%lx\n", (ulong)p);
#endif
}
