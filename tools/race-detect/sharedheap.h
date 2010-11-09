#pragma once

#include <iostream>
#include <exception>

#include "misc.h"
#include "memops.h"
#include "sharedarea.h"

#define CALL_MMAP(s) SharedArea_Mmap(0, PAGE_ALIGN(s), 0, 0, 0, 0)
#define CALL_MUNMAP(p, s) SharedArea_Munmap((p), PAGE_ALIGN(s))

class SharedHeap {
public:
   void* operator new(size_t sz); 

   void operator delete(void *p);
};

template <typename T> class SharedHeapAllocator {
public:
   typedef T   value_type;
   typedef value_type* pointer;
   typedef const value_type* const_pointer;
   typedef value_type& reference;
   typedef const value_type& const_reference;
   typedef size_t size_type;
   typedef ptrdiff_t difference_type;
   
   template <typename U> struct rebind { typedef SharedHeapAllocator<U> other; };

   SharedHeapAllocator() {}
   SharedHeapAllocator(const SharedHeapAllocator&) {}
   template <typename U> SharedHeapAllocator(const SharedHeapAllocator<U>&) {}
   ~SharedHeapAllocator() {}

   pointer address(reference x) const { return &x; }
   const_pointer address(const_reference x) const { return &x; }

   pointer allocate(size_type count) {
      void *ptr = SharedArea_Malloc(count * sizeof(T));

      if (!ptr) {
         throw std::bad_alloc();
      }

      return static_cast<pointer>(ptr);
   }

   void deallocate(pointer p, size_type count) {
      // C says okay to delete NULL pointer
      SharedArea_Free(p, sizeof(T) * count);
   }

   size_type max_size() const {
      return static_cast<size_type>(-1) / sizeof(value_type);
   }

   void construct(pointer p, const value_type& x) {
      new(p) value_type(x);
   }

   void destroy(pointer p) { p->~value_type(); }

private:
   void operator=(const SharedHeapAllocator&); // disable =
};

#if 0
/* XXX: for void types */
template<> class SharedHeapAllocator<void> {
   typedef void value_type;
   typedef void* pointer;
   typedef const void* const_pointer;

   template <class U>
      struct rebind { typedef SharedHeapAllocator<U> other; }
};
#endif

template <typename T>
inline bool operator==(const SharedHeapAllocator<T>&, 
      const SharedHeapAllocator<T>&) {
   return true;
}

template <typename T>
inline bool operator!=(const SharedHeapAllocator<T>&,
      const SharedHeapAllocator<T>&) {
   return false;
}
