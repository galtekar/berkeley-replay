#pragma once

struct IoVec {
   struct ListHead iov_list;
   int len;
   size_t capacity;
};

struct IoBuffer {
   char *base;
   size_t len;
   struct ListHead list;
};


extern struct IoVec *
IovOps_Alloc();

extern struct IoVec *
IovOps_Make(const struct iovec *iov_ptr, const int iovlen);

extern struct IoVec *
IovOps_Dup(const struct IoVec *iov_ptr);

extern void
IovOps_Free(struct IoVec *iov_ptr);

extern void
IovOps_AddBuffer(struct IoVec *iov_ptr, char *buf_ptr, 
                 const size_t buf_len);

extern size_t
IovOps_GetCapacity(const struct IoVec *iov_ptr);

extern void
IovOps_TruncateHead(struct IoVec *iov_ptr, size_t nr_trunc_bytes);

extern void
IovOps_TruncateTail(struct IoVec *iov_ptr, size_t nr_trunc_bytes);


/* XXX: these should be retired at some point. */
extern ulong   Iov_TruncateFirstNBytes(const struct iovec *vec, ulong vlen, 
                  struct iovec *newVec, ulong *newVecLen, size_t usedBytes);

extern void    Iov_FirstNbytes(const struct iovec *vec, ulong vlen, 
                  struct iovec *newVec, ulong *newVecLen, ulong nBytes);
