#include "vkernel/public.h"
#include "private.h"

#include <errno.h>

int
no_llseek(UNUSED struct FileStruct *filp, UNUSED loff_t offset, 
          UNUSED int origin, loff_t *result)
{
	return -ESPIPE;
}

static INLINE loff_t 
FilePosRead(struct FileStruct *filp)
{
   ASSERT(filp->pos >= 0);

   return filp->pos;
}

static INLINE void 
FilePosWrite(struct FileStruct *filp, loff_t pos)
{
   ASSERT(pos >= 0);

   filp->pos = pos;
}

static int
VFS_llseek(struct FileStruct *filp, loff_t offset, int origin, loff_t *result)
{
   int err;

	int (*fn)(struct FileStruct *, loff_t, int, loff_t *);

   fn = no_llseek;
   if (filp->f_op && filp->f_op->llseek) {
      fn = filp->f_op->llseek;
   }

	err = fn(filp, offset, origin, result);
   if (!SYSERR(err)) {
      ASSERT(File_IsLocked(filp));
      ASSERT(*result >= 0);
      FilePosWrite(filp, *result);
   }

   DEBUG_MSG(5, "err=%d result=%lld\n", err, *result);

   return err;
}

loff_t
File_Seek(struct FileStruct *filp, loff_t offset, uint origin)
{
   loff_t err, result;

   /* Ensures that updates to filp->pos are deterministic. */
   File_Lock(filp);

   err = -EINVAL;
   if (origin <= 2) {
      err = VFS_llseek(filp, offset, origin, &result);

      if (!SYSERR(err)) {
         err = result;
      }
   }

   File_Unlock(filp);

   return err;
}

long
sys_lseek(uint vfd, off_t offset, uint origin)
{
   off_t err = -EBADF;
   struct FileStruct *filp;

   filp = File_Get(vfd);
   if (filp) {
      err = File_Seek(filp, offset, origin);
      File_Put(filp);
   }

   return err;
}

long
sys_llseek(uint fd, ulong offset_high,
           ulong offset_low, loff_t __user * result,
           uint origin)
{
   int retval;
   struct FileStruct *filp;
   loff_t offset = -1;

   retval = -EBADF;
   filp = File_Get(fd);
   if (!filp) {
      goto out;
   }

   retval = -EINVAL;
   if (origin > 2) {
      goto out_putf;
   }

   File_Lock(filp);

   retval = VFS_llseek(filp, ((loff_t) offset_high << 32) |
                  offset_low, origin, &offset);

   File_Unlock(filp);

   if (offset >= 0) {
      ASSERT(!SYSERR(retval));
      retval = -EFAULT;
      if (!Task_CopyToUser(result, &offset, sizeof(offset))) {
         retval = 0;
      }
   }
out_putf:
   File_Put(filp);
out:
   return retval;
}

static INLINE int
WasInterrupted(int err)
{
   switch (err) {
   case -EINTR:
   case -ERESTARTSYS:
   case -ERESTARTNOHAND:
      return 1;
   default:
      return 0;
   };
}

/*
 * Called by socket send/recv and read/write code.
 *
 * @flags -- used by sockets for MSG_DONWAIT, MSG_WAITALL, etc.
 */
ssize_t
VFS_io(const int ioReqFlags, struct FileStruct *filp, struct msghdr *kmsgp, int flags, 
       loff_t *pos)
{
   long error;
   ulong usedBytes = 0, newVecSz, dataSz;
   int wasInterrupted = -1, isSignalPending = -1;
   struct msghdr __kmsg;
   struct iovec *iov;

   ASSERT(filp);
   ASSERT(kmsgp);
   ASSERT(kmsgp->msg_iov);
   ASSERT(kmsgp->msg_iovlen > 0);
   /* Sockets don't use pos. */
   ASSERT(pos || !pos);
   /* Ensures that accesses to filp->flags and filp->pos will 
    * be deterministic. */
   ASSERT(File_IsLocked(filp));

   if (!filp->f_op || !filp->f_op->io) {
      error = -EINVAL;
      goto out;
   }

   __kmsg = *kmsgp;

   /* XXX: find a way to avoid dynamic allocation, for efficiency. */
   dataSz = newVecSz = sizeof(struct iovec) * kmsgp->msg_iovlen;
   iov = __kmsg.msg_iov = SharedArea_Malloc(newVecSz);

   ASSERT(File_IsLocked(filp));


   do {
      D__;
      Iov_TruncateFirstNBytes(kmsgp->msg_iov, kmsgp->msg_iovlen, 
            __kmsg.msg_iov, (ulong*)&__kmsg.msg_iovlen, usedBytes);

#if DEBUG
      /* Could be 0 if usedBytes covers the entire input iovec. */
      ASSERT(__kmsg.msg_iovlen <= kmsgp->msg_iovlen);

      if (usedBytes == 0) {
         uint i;

         ASSERT(kmsgp->msg_iovlen == __kmsg.msg_iovlen);
         for (i = 0; i < kmsgp->msg_iovlen; i++) {
            ASSERT(__kmsg.msg_iov[i].iov_base == kmsgp->msg_iov[i].iov_base);
            ASSERT(__kmsg.msg_iov[i].iov_len == kmsgp->msg_iov[i].iov_len);
         }
      }

      DEBUG_MSG(5, "__kmsg.msg_iovlen=%d\n", __kmsg.msg_iovlen);
#endif

      File_Unlock(filp);
      /* XXX: order io with inode lock? this will serialize file
       * access unecessarily ... if there are indeed racing
       * accesses, we will detect and compute... */

      if (VCPU_IsLogging()) {
         TokenBucket_Fill(&filp->classTB);

         if (filp->channel_kind != Chk_Control &&
             filp->channel_kind != Chk_Data) {
            /* Channel type is not set in stone, so determine what it is
             * dynamically. */
            filp->channel_kind = TokenBucket_IsConsumable(&filp->classTB, 
                  0) ? Chk_MaybeControl : Chk_MaybeData;
         }
      }

      
      error = filp->f_op->io(ioReqFlags, filp, &__kmsg, flags, pos ? *pos : -1);
      File_Lock(filp);

      if (!SYSERR(error)) {
         ASSERT(error >= 0);
         if (VCPU_IsLogging()) {
            TokenBucket_Consume(&filp->classTB, error);
         }
         usedBytes += error;

         /* Pwrite/read shouldn't change/advance the file pointer. */
         if (pos && *pos != -1) {
            loff_t tmppos;
            tmppos = FilePosRead(filp);
            tmppos += error;
            FilePosWrite(filp, tmppos); 
         }
      } 

      wasInterrupted = WasInterrupted(error);
      isSignalPending = Task_TestSigPending(current, 1);
   } while (wasInterrupted && !isSignalPending);

   ASSERT(iov == __kmsg.msg_iov);
   ASSERT(dataSz == newVecSz);
   SharedArea_Free(__kmsg.msg_iov, newVecSz);

   /* If we break out of the loop to handle a signal, we should still 
    * report the number of bytes we have read thus far. This may be 
    * short of the expected count, but applications in general will
    * retry. */

   /* Careful, a 0 return value is reserved for end-of-filp (EOF). 
    * Also, -EINTR allowed only if no data has been read. Must
    * report non-zero read data (a short byte count) even if 
    * interrupted by signal. */
   if (SYSERR(error) || 
         (wasInterrupted && isSignalPending && usedBytes == 0)) {
      ASSERT(error < 0);
   } else {
      error = usedBytes;
   }

out:
   DEBUG_MSG(5, "error=%d\n", error);
   return error;
}

static ssize_t
FileIo(const int ioReqFlags, struct FileStruct *filp, const struct iovec *kvec, 
      const ulong nr_segs, loff_t pos)
{
   ssize_t ret;
   struct msghdr kmsg;

   ASSERT(pos >= -1);

   kmsg.msg_name = NULL;
   kmsg.msg_namelen = 0;
   kmsg.msg_iov = (struct iovec*) kvec;
   kmsg.msg_iovlen = nr_segs;
   kmsg.msg_control = NULL;
   kmsg.msg_controllen = 0;
   kmsg.msg_flags = 0;

   /* Ensure that accesses through the same filp object are deterministic.
    * This isn't required if read/writes are logged, since the same data will
    * be returned during replay regardless of any races on the filp offset.
    * But if the read/writes actually operate on the underlying fd during
    * replay, then without this lock, the read/write may be to
    * non-deterministic offsets. We lock regardless because we don't know
    * what the VFS callback will do. */

//#error "deadlock if we schedule out (on blocking io) while hold the lock"
   File_Lock(filp);

   /* Note that this doesn't protect access to data in the underlying
    * inode. We delegate the responsibility for locking to the VFS
    * callback. */

   ret = VFS_io(ioReqFlags, filp, &kmsg, 0, &pos);

   File_Unlock(filp);

   return ret;
}

ssize_t
File_KernRead(struct FileStruct *filp, void *buf, size_t len, loff_t pos)
{
   ssize_t ret;
   struct iovec vec = { .iov_base = (char*) buf, .iov_len = len };

   ret = FileIo(IOREQ_READ | IOREQ_KERN, filp, &vec, 1, pos);

   DEBUG_MSG(5, "ret=%d\n", ret);

   return ret;
}

ssize_t
File_KernWrite(struct FileStruct *filp, void *buf, size_t len, loff_t pos)
{
   ssize_t ret;
   struct iovec vec = { .iov_base = (char*) buf, .iov_len = len };

   ret = FileIo(0 | IOREQ_KERN, filp, &vec, 1, pos);

   return ret;
}


static ssize_t
FileDoIo(const int ioReqFlags, const int fd, const struct iovec *kvec, 
      const ulong nr_segs, loff_t pos)
{
   struct FileStruct *filp;
   ssize_t err = -EBADF;

   DEBUG_MSG(5, "ioReqFlags=%d fd=%d kvec=0x%x nr_segs=%d\n",
         ioReqFlags, fd, kvec, nr_segs);

   filp = File_Get(fd);

   if (filp) {
      err = FileIo(ioReqFlags, filp, kvec, nr_segs, pos);
      File_Put(filp);
   }

   return err;
}

static ssize_t
FileDoIoVec(const int ioReqFlags, int fd, const struct iovec __user *uvector, 
            ulong nr_segs)
{
   ssize_t ret;
   struct iovec *iov = NULL;
   size_t vecsz = nr_segs * sizeof(struct iovec);

   /*
	 * SuS says "The readv() function *may* fail if the iovcnt argument
	 * was less than or equal to 0, or greater than {IOV_MAX}.  Linux has
	 * traditionally returned zero for zero segments, so...
	 */
	ret = 0;
	if (nr_segs == 0) {
		goto out;
   }

   iov = SharedArea_Malloc(vecsz);

   if (Task_CopyFromUser(iov, uvector, vecsz)) {
      ret = -EFAULT;
      goto out;
   }

   ret = FileDoIo(ioReqFlags, fd, iov, nr_segs, -1);

out:
   if (iov) {
      SharedArea_Free(iov, vecsz);
   }

   return ret;
}


long
sys_read(uint fd, char __user * buf, size_t count)
{
   ASSERT_COULDBE(count == 0); // True for Hypertable client

   struct iovec vec = { .iov_base = (char*) buf, .iov_len = count };

   return FileDoIo(IOREQ_READ, fd, &vec, 1, -1);
}

long
sys_write(uint fd, const char __user * buf, size_t count)
{
   struct iovec vec = { .iov_base = (char*) buf, .iov_len = count };

   return FileDoIo(0, fd, &vec, 1, -1);
}

long
sys_readv(uint fd, const struct iovec __user *vec, ulong vlen)
{
   return FileDoIoVec(IOREQ_READ, fd, vec, vlen);
}


long
sys_writev(uint fd, const struct iovec __user *vec, ulong vlen)
{
   return FileDoIoVec(0, fd, vec, vlen);
}

long
sys_pread64(uint fd, char __user *buf, size_t count, loff_t pos)
{
   struct iovec vec = { .iov_base = (char*) buf, .iov_len = count };

   if (pos < 0) { 
      return -EINVAL;
   }

   return FileDoIo(IOREQ_READ, fd, &vec, 1, pos);
}

long
sys_pwrite64(uint fd, const char __user *buf, size_t count, 
             loff_t pos)
{
   struct iovec vec = { .iov_base = (char*) buf, .iov_len = count };

   if (pos < 0) { 
      return -EINVAL;
   }

   return FileDoIo(0, fd, &vec, 1, pos);
}


long
sys_sendfile(int out_fd, int in_fd, off_t __user *offset, size_t count)
{
   long err;
   off_t koffset = 0;

   /* XXX: need to do File_Get() */
   ASSERT_UNIMPLEMENTED(0);

   /* XXX: on replay must emulate sendfile behavior using
    * primitive reads and writes. */
   ASSERT_UNIMPLEMENTED(NR_VCPU == 1);


   if (offset && Task_CopyFromUser(&koffset, offset, sizeof(*offset))) {
      err = -EFAULT;
      goto out;
   }


   if (!VCPU_IsReplaying()) {

      err = syscall(SYS_sendfile, out_fd, in_fd, &koffset, count);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_sendfile) {
            entryp->ret = err;
            entryp->offset = koffset;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_sendfile) {
         err = entryp->ret;
         koffset = entryp->offset;
      } END_WITH_LOG_ENTRY(0);
   }

   if (offset && Task_CopyToUser(offset, &koffset, sizeof(*offset))) {
      err = -EFAULT;
      goto out;
   }

out:
   return err;
}

long
sys_sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count)
{
   long err;
   loff_t koffset = 0;
   struct FileStruct *filpOut, *filpIn;

   /* XXX: on replay must emulate sendfile behavior using
    * primitive reads and writes. */
   ASSERT_UNIMPLEMENTED(NR_VCPU == 1);

   if (offset && Task_CopyFromUser(&koffset, offset, sizeof(*offset))) {
      err = -EFAULT;
      goto out;
   }

   err = -EBADF;
   filpOut = File_Get(out_fd);
   if (!filpOut) {
      goto out;
   }

   err = -EBADF;
   filpIn = File_Get(in_fd);
   if (!filpIn) {
      goto out_putf_out;
   }

   File_Lock(filpOut);
   File_Lock(filpIn);

   if (!VCPU_IsReplaying()) {

      err = syscall(SYS_sendfile64, filpOut->rfd, filpIn->rfd, &koffset, count);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_sendfile64) {
            entryp->ret = err;
            entryp->offset = koffset;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_sendfile64) {
         err = entryp->ret;
         koffset = entryp->offset;
      } END_WITH_LOG_ENTRY(0);
   }
   File_Unlock(filpOut);
   File_Unlock(filpIn);

   if (offset && Task_CopyToUser(offset, &koffset, sizeof(*offset))) {
      err = -EFAULT;
      goto out_putf;
   }

out_putf:
   File_Put(filpIn);
out_putf_out:
   File_Put(filpOut);
out:
   return err;
}
