#include <sys/socket.h>
#include <string.h>

#include "public.h"

struct IoVec *
IovOps_Alloc()
{
   struct IoVec *vec_ptr = malloc(sizeof(*vec_ptr));

   List_Init(&vec_ptr->iov_list);
   vec_ptr->len = 0;
   vec_ptr->capacity = 0;

   return vec_ptr;
}

static void
IovOpsDelBuffer(struct IoBuffer *buf_ptr, struct IoVec *vec_ptr)
{
   vec_ptr->len--;
   vec_ptr->capacity -= buf_ptr->len;

   List_Del(&buf_ptr->list);
   free(buf_ptr);
}

void
IovOps_Free(struct IoVec *vec_ptr)
{
   struct IoBuffer *buf_ptr, *dummy_ptr;

   list_for_each_entry_safe(buf_ptr, dummy_ptr, &vec_ptr->iov_list, list) {
      IovOpsDelBuffer(buf_ptr, vec_ptr);
   }
   free(vec_ptr);
   vec_ptr = NULL;
}

void
IovOps_AddBuffer(struct IoVec *vec_ptr, char *buf, const size_t buf_len)
{
   ASSERT(vec_ptr->len >= 0);
   ASSERT(buf);
   ASSERT(buf_len >= 0);

   struct IoBuffer *buf_ptr = malloc(sizeof(*buf_ptr));
   buf_ptr->base = buf;
   buf_ptr->len = buf_len;
   List_AddTail(&buf_ptr->list, &vec_ptr->iov_list);

   vec_ptr->len++;
   vec_ptr->capacity += buf_len;
}

struct IoVec *
IovOps_Make(const struct iovec *iov_buf, const int iovlen)
{
   int i;
   struct IoVec *vec_ptr = IovOps_Alloc();

   for (i = 0; i < iovlen; i++) {
      IovOps_AddBuffer(vec_ptr, iov_buf[i].iov_base, iov_buf[i].iov_len);
   }

   return vec_ptr;
}

struct IoVec *
IovOps_Dup(const struct IoVec *iov_ptr)
{
   struct IoVec *vec_ptr = IovOps_Alloc();
   struct IoBuffer *buf_ptr = NULL;

   list_for_each_entry(buf_ptr, &iov_ptr->iov_list, list) {
      IovOps_AddBuffer(vec_ptr, buf_ptr->base, buf_ptr->len);
   }

   return vec_ptr;
}


size_t
IovOps_GetCapacity(const struct IoVec *vec_ptr)
{
#if 0 // The slow way; but useful for debugging
   struct IoBuffer *buf_ptr;
   size_t capacity = 0;

   ASSERT(vec_ptr->len >= 0);

   list_for_each_entry(buf_ptr, &vec_ptr->iov_list, list) {
      ASSERT(buf_ptr->len > 0);
      capacity += buf_ptr->len;
   }

   return capacity;
#else
   return vec_ptr->capacity;
#endif
}

void
IovOps_TruncateHead(struct IoVec *vec_ptr, size_t nr_trunc_bytes)
{
   struct IoBuffer *buf_ptr, *dummy_ptr;
   size_t bytes_so_far = 0;
   DEBUG_ONLY(size_t original_capacity = IovOps_GetCapacity(vec_ptr);)

   ASSERT(vec_ptr->len >= 0);
   ASSERT(nr_trunc_bytes <= original_capacity);

   list_for_each_entry_safe(buf_ptr, dummy_ptr, &vec_ptr->iov_list, list) {
      if ((bytes_so_far + buf_ptr->len) <= nr_trunc_bytes) {
         bytes_so_far += buf_ptr->len;
         IovOpsDelBuffer(buf_ptr, vec_ptr);
      } else {
         /* Partial remove. Update the current entry and bail. */
         const size_t bytes_removed = (nr_trunc_bytes - bytes_so_far);
         buf_ptr->base += bytes_removed;
         buf_ptr->len -= bytes_removed;
         vec_ptr->capacity -= bytes_removed;
         break;
      }
   }

   ASSERT(IovOps_GetCapacity(vec_ptr) == (original_capacity -
         nr_trunc_bytes));
}

void
IovOps_TruncateTail(struct IoVec *vec_ptr, size_t nr_trunc_bytes)
{
   struct IoBuffer *buf_ptr, *dummy_ptr;
   ssize_t bytes_to_keep = IovOps_GetCapacity(vec_ptr) - nr_trunc_bytes;
   size_t bytes_so_far = 0;
   int do_delete = 0;

   DEBUG_MSG(5, "bytes_to_keep=%d nr_trunc_bytes=%d\n", bytes_to_keep,
         nr_trunc_bytes);

   ASSERT(bytes_to_keep >= 0);
   ASSERT(vec_ptr->len >= 0);

   list_for_each_entry_safe(buf_ptr, dummy_ptr, &vec_ptr->iov_list, list) {
      if (do_delete) {
         IovOpsDelBuffer(buf_ptr, vec_ptr);
         buf_ptr = NULL;
      } else if ((bytes_so_far + buf_ptr->len) > bytes_to_keep) {
         /* Partial remove. Update the current entry and delete the
          * rest. */
         const size_t bytes_to_remove = ((bytes_so_far + buf_ptr->len) - 
               bytes_to_keep);
         do_delete = 1;
         buf_ptr->len -= bytes_to_remove;
         vec_ptr->capacity -= bytes_to_remove;
      } else {
         ASSERT(buf_ptr);
         bytes_so_far += buf_ptr->len;
      }
   }

   ASSERT(IovOps_GetCapacity(vec_ptr) == bytes_to_keep);
}

/* Returns a new iovec that points to the last totalBytes-usedBytes 
 * portion of input iovec. */
ulong
Iov_TruncateFirstNBytes(const struct iovec *vec, ulong vlen, 
      struct iovec *newVec, ulong *newVecLen, size_t usedBytes)
{
   int i, j;
   size_t sum = 0;
   size_t newVecBytes = 0;

   DEBUG_MSG(5, "vlen=%d usedBytes=%d\n", vlen, usedBytes);
   ASSERT(vlen > 0);

   *newVecLen = 0;

   /* Where should we start truncating? */
   for (i = 0; i < vlen; i++) {

      DEBUG_MSG(5, "vec[%d].len=%d\n", i, vec[i].iov_len);

      if (usedBytes <= sum + vec[i].iov_len) {
         break;
      }

      sum += vec[i].iov_len;
   }

   DEBUG_MSG(5, "i=%d\n", i);

   if (i < vlen) {

      for (j = i; j < vlen; j++) {
         newVec[j-i].iov_base = vec[j].iov_base;
         newVec[j-i].iov_len = vec[j].iov_len;
         (*newVecLen)++;

         DEBUG_MSG(5, "j-i=%d new_base=0x%x new_len=%d\n",
               j-i, newVec[j-i].iov_base, newVec[j-i].iov_len);
         newVecBytes += vec[j].iov_len;
      }

      ASSERT(usedBytes >= sum);
      ASSERT(usedBytes <= sum + vec[i].iov_len);

      /* The truncated region could end in the middle of an iovec. */
      newVec[0].iov_base = vec[i].iov_base + (usedBytes - sum);
      newVec[0].iov_len = (sum + vec[i].iov_len) - usedBytes;
   } else {
      ASSERT(*newVecLen == 0);
   }

   return newVecBytes;
}

void
Iov_FirstNbytes(const struct iovec *vec, ulong vlen, struct iovec *newVec, ulong *newVecLen,
      ulong nBytes)
{
   int i;
   ulong sum = 0;

   DEBUG_MSG(5, "vlen=%d\n", vlen);

   for (i = 0; i < vlen; i++) {
      DEBUG_MSG(5, "vec[%d].len=%d\n", i, vec[i].iov_len);
      newVec[i] = vec[i];

      if (nBytes < sum + vec[i].iov_len) {
         break;
      }

      sum += vec[i].iov_len;
   }

   if (i < vlen) {
      newVec[i].iov_len = nBytes - sum;
      *newVecLen = i+1;
   } else {
      *newVecLen = i;
   }
}
