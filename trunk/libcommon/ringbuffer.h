#pragma once

#include <sys/types.h>

typedef struct {
#define RING_BUF_SIZE 4096
   ssize_t head_idx, tail_idx;
   ssize_t size;
   ssize_t capacity;
   char buf[RING_BUF_SIZE];
} ring_buffer_t;

extern ring_buffer_t *
RingBuffer_Alloc();

extern void
RingBuffer_Free(ring_buffer_t *rb_ptr);

extern void
RingBuffer_Queue(ring_buffer_t *rb_ptr, const char *buf, const size_t len);

extern void
RingBuffer_Dequeue(ring_buffer_t *rb_ptr, char *buf, const size_t len);

static INLINE ssize_t
RingBuffer_GetCount(ring_buffer_t *rb_ptr)
{
   return rb_ptr->size;
}
