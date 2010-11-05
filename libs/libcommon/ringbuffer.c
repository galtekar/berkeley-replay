#include "public.h"

#include "ringbuffer.h"

ring_buffer_t *
RingBuffer_Alloc()
{
   /* We know that KFS's cptokfs client program does MSG_PEEKs of this
    * size. Other programs may do larger peeks, so watch out. */
#if RING_BUF_SIZE < 1024
#error "XXX: RING_BUF_SIZE must be at least 1024."
#endif
   ASSERT(RING_BUF_SIZE >= 1024);

   ring_buffer_t *rb_ptr;

   rb_ptr = malloc(sizeof(*rb_ptr));
   rb_ptr->head_idx = rb_ptr->tail_idx = 0;
   rb_ptr->size = 0;
   rb_ptr->capacity = RING_BUF_SIZE;

   return rb_ptr;
}

void
RingBuffer_Free(ring_buffer_t *rb_ptr)
{
   free(rb_ptr);
}

#if DEBUG
static void
RingBufferCheckInvariants(const ring_buffer_t *rb_ptr)
{
   ASSERT(rb_ptr->buf);
   ASSERT(rb_ptr->capacity > 0);
   ASSERT(rb_ptr->size >= 0 && rb_ptr->size <= rb_ptr->capacity);
   ASSERT(rb_ptr->tail_idx >= 0 && rb_ptr->tail_idx < rb_ptr->capacity);
   ASSERT(rb_ptr->head_idx >= 0 && rb_ptr->head_idx < rb_ptr->capacity);
}
#endif

void
RingBuffer_Queue(ring_buffer_t *rb_ptr, const char *buf, const size_t len)
{
   ssize_t rem_count = len;


#if DEBUG
   RingBufferCheckInvariants(rb_ptr);
#endif

   if (rb_ptr->size + len > rb_ptr->capacity) {
      // Won't fit in the buffer, return error
      ASSERT_UNIMPLEMENTED_MSG(0, "Try increasing capacity, currently %d",
            rb_ptr->capacity);
   }


   while (rem_count > 0) {
      // Careful not to exceed the end of the physical buffer
      ssize_t wlen = MIN(rem_count, rb_ptr->capacity - rb_ptr->tail_idx);
      ASSERT(wlen >= 0 && wlen <= rb_ptr->capacity);

      memcpy(&rb_ptr->buf[rb_ptr->tail_idx], buf, wlen);
      rb_ptr->tail_idx = (rb_ptr->tail_idx + wlen) % rb_ptr->capacity;
      rem_count -= wlen;
   }

   rb_ptr->size += len;
   DEBUG_MSG(5, "queue(%d) : count=%d\n", len, rb_ptr->size);
}

#if 0
ssize_t
RingBuffer_Recv(int fd, size_t rem_count, int msg_flags)
{
   ssize_t res;

   res = recv(fd, ptr, rem_count, msg_flags);
}
#endif

void
RingBuffer_Dequeue(ring_buffer_t *rb_ptr, char *buf, const size_t len)
{
   ssize_t rem_count = len;

#if DEBUG
   RingBufferCheckInvariants(rb_ptr);
#endif

   if (len > rb_ptr->size) {
      // Not enough data in buffer
      ASSERT_UNIMPLEMENTED(0);
   }

   while (rem_count > 0) {
      ssize_t rlen = MIN(rem_count, rb_ptr->capacity - rb_ptr->head_idx);
      memcpy(buf, &rb_ptr->buf[rb_ptr->head_idx], rlen);
      rb_ptr->head_idx = (rb_ptr->head_idx + rlen) % rb_ptr->capacity;
      rem_count -= rlen;
   }

   rb_ptr->size -= len;
   DEBUG_MSG(5, "dequeue(%d) : count=%d\n", len, rb_ptr->size);
}
