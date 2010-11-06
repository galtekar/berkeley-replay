#include <dirent.h>
#include "vkernel/public.h"

/* XXX: scheduling out while hold parent lock will
 * result in deadlock -- for now assume that open
 * will not block (this is not always the case (e.g., FIFO
 * opens), but we'll deal with it this later. */
#if 0
static SyscallRet
ReadDetOpen(const struct SyscallArgs *args, const void *auxArg)
{
   SyscallRet ret;

   ret = Signal_BlockingRealSyscall(!VCPU_IsReplaying() ? args : NULL);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(JustRetval) {
         entryp->ret = ret;
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

int
ReadDet_open(const char *name, int flags, int mode)
{
   int err;
   int wasInterrupted, isSignalPending;
   struct SyscallArgs args = {
      .eax = SYS_open,
      .ebx = (ulong) name,
      .ecx = flags,
      .edx = mode,
   };

   DEBUG_MSG(5, "eax=%d ebx=0x%x ecx=0x%x edx=0x%x\n", 
         args.eax, args.ebx, args.ecx, args.edx);


   do {
      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      err = Sched_BlockingRealSyscall(&args, NULL, &ReadDetOpen);

      wasInterrupted = (err == -EINTR);
      isSignalPending = Task_TestSigPending(current, 1);

   } while (wasInterrupted && !isSignalPending);

   return err;
}
#else
int
ReadDet_open(const char *name, int flags, int mode)
{
   int err;

   if (!VCPU_IsReplaying()) {
      /* XXX: this may block, but don't schedule out
       * for now -- at least, not while we're holding
       * the parent lock, since then another task may
       * try to acquire it and deadlock. This has to
       * be fixed at some point, but is not an immediate
       * problem. */
      err = syscall(SYS_open, name, flags, mode);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return err;
}
#endif

int
ReadDet_setfl(int fd, int arg)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = SYS_fcntl64;
      args.ebx = fd;
      args.ecx = F_SETFL;
      args.edx = arg;
      ret = Task_RealSyscall(&args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}


int 
ReadDet_fsync(int fd, int datasync)
{
   SyscallRet ret;
   int sysno = datasync ? SYS_fdatasync : SYS_fsync;


   if (!VCPU_IsReplaying()) {

      ASSERT(fd >= 0);
      ret = syscall(sysno, fd);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

int
ReadDet_ftruncate64(int fd, loff_t length)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_ftruncate64, fd, length);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

/* @offset is a 64-bit offset value (unlike off_t which is 32-bits) */
long
ReadDet_llseek(int fd, loff_t offset, int origin, loff_t *result)
{
   long ret;
   ulong offset_high, offset_low;

   ASSERT(result);

   /* sizeof(loff_t) == 64, so we gotta to break it up before sending
    * it to Linux. */
   offset_high = (offset >> 32) & 0xFFFFFFFFLL;
   offset_low = offset & 0xFFFFFFFFLL;

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = SYS__llseek;
      args.ebx = fd;
      args.ecx = offset_high;
      args.edx = offset_low;
      args.esi = (ulong)result;
      args.edi = origin;
      ret = Task_RealSyscall(&args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_llseek) {
            entryp->ret = ret;
            entryp->off = *result;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_llseek) {
         ret = entryp->ret;
         *result = entryp->off;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

int
ReadDet_readdir(int fd, void *buf, filldir_t filler, size_t size)
{
   struct dirent64 *__dents = SharedArea_Malloc(size);
   SyscallRet ret;
   int count, error;
   struct dirent64 *dentp;


   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = SYS_getdents64;
      args.ebx = fd;
      args.ecx = (ulong)__dents;
      args.edx = size;
      ret = Task_RealSyscall(&args);

      DEBUG_MSG(5, "ret=%d size=%d\n", ret, size);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY_DATA(JustRetval, (SYSERR(ret) ? 0 : ret)) {
            entryp->ret = ret;
            if (!SYSERR(ret)) {
               memcpy(datap, (void*)__dents, ret);
            }
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
         if (!SYSERR(ret)) {
            memcpy((void*)__dents, datap, ret);
         }
      } END_WITH_LOG_ENTRY(SYSERR(ret) ? 0: ret);
   }

   if (SYSERR(ret)) {
      goto out;
   }

   for (dentp = __dents, count = 0; count < ret; 
        count += dentp->d_reclen,
        dentp = (struct dirent64*)((char*)dentp + dentp->d_reclen)) {

      error = filler((void*)buf, dentp->d_name, strlen(dentp->d_name),
            dentp->d_off, dentp->d_ino, dentp->d_type);

      if (error) {
         /* Should set ret to a reasonable error value. */
         ASSERT_UNIMPLEMENTED(0);
         goto out;
      }
   }

   ASSERT(count == ret);

out:
   SharedArea_Free(__dents, size);

   return ret;
}

static void
WrapOnTagRecv(const char *tagBuf, size_t tagLen)
{
   ASSERT(sizeof(struct MsgTag) == tagLen);

   const struct MsgTag *tagP = (const struct MsgTag *) tagBuf;

   /* Logical clock receiver-side update. */
   curr_vcpu->vclock = MAX(curr_vcpu->vclock, tagP->vclock) + 1;

   /* XXX: replace with Module_OnTagRecv() callback */
   extern void Server_OnTagRecv(const char *, size_t);
   Server_OnTagRecv(tagBuf, tagLen);

   DEBUG_MSG(5, "msg_idx=%llu new vclock=%llu\n", tagP->msg_idx, curr_vcpu->vclock);
   DEBUG_HEXDUMP(5, "uuid", (char*)&tagP->uuid, sizeof(tagP->uuid));
}

static void
WrapOnTagSend(const char *tagBuf, size_t tagLen)
{
   ASSERT(sizeof(struct MsgTag) == tagLen);

   UNUSED const struct MsgTag *tagP = (const struct MsgTag *) tagBuf;

   ASSERT(tagP->vclock - curr_vcpu->vclock >= 0);

   DEBUG_MSG(5, "msg_idx=%llu new vclock=%llu\n", tagP->msg_idx, curr_vcpu->vclock);
   DEBUG_HEXDUMP(5, "uuid", (char*)&tagP->uuid, sizeof(tagP->uuid));
}

static size_t
WrapOnMakeTag(char *tagBuf, size_t bufLen)
{
   ASSERT(sizeof(struct MsgTag) <= bufLen);

   struct MsgTag *tagP = (struct MsgTag *) tagBuf;

   tagP->vclock = curr_vcpu->vclock;
   tagP->msg_idx = curr_vcpu->msg_idx++;
   memcpy(tagP->uuid, curr_vcpu->uuid, sizeof(tagP->uuid));

#if DEBUG
   int i;
   for (i = 0; i < 4; i++) {
      DEBUG_MSG(6, "%d\n", tagP->uuid[i]);
   }
   DEBUG_MSG(6, "msg_idx=%d\n", tagP->msg_idx);
#endif

   return sizeof(*tagP);
}

static INLINE void
WrapSetDefaultChunkBuf(ssize_t err, tsock_chunk_t *chunk_buf, int *nr_chunks_ptr)
{
   chunk_buf[0].data_off = 0;
   chunk_buf[0].tag_buf[0] = 0;
   chunk_buf[0].tag_len = 0;

   if (err > 0) {
      *nr_chunks_ptr = 1;
   } else {
      *nr_chunks_ptr = 0;
   }
}

static ssize_t
WrapDoSysWrite(const struct FileStruct *filP, const struct msghdr *msgP, 
      const int flags, const loff_t pos, tsock_chunk_t *chunk_buf, 
      int *nr_chunks_ptr)
{
   ASSERT(!VCPU_IsReplaying());
   ASSERT_KPTR(chunk_buf);
   ASSERT_KPTR(nr_chunks_ptr);
   ASSERT(*nr_chunks_ptr == MAX_NR_CHUNKS);
   ASSERT(MAX_NR_CHUNKS > 0);

   tsock_chunk_t *chunk_ptr = &chunk_buf[0];
   chunk_ptr->tag_len = 0; // for non-tagged lines

   ssize_t err;
   struct InodeStruct *inoP = File_Inode(filP);
   const InodeMajor major = Inode_GetMajor(inoP);
   switch (major) {
   case InodeMajor_Sock:
   case InodeMajor_Pipe:
      {
         /* The line is potentially tagged, so invoke TSock_Send. */
         tsock_socket_info_t *s_info = NULL;
         char *tag_ptr = chunk_ptr->tag_buf;
         size_t *tag_len_ptr = &chunk_ptr->tag_len;

         *tag_len_ptr = WrapOnMakeTag(tag_ptr, TSOCK_MAX_TAG_LEN);
         ASSERT_UNIMPLEMENTED(*tag_len_ptr >= 0 && 
               *tag_len_ptr <= TSOCK_MAX_TAG_LEN);

         if (major == InodeMajor_Sock) {
            struct SockStruct *sockP = Sock_GetStruct(inoP);
            s_info = &sockP->tsock;
         } else {
            ASSERT(major == InodeMajor_Pipe);
            struct PipeStruct *pipeP = Pipe_GetStruct(inoP);
            const int idx = filP->accMode & FMODE_WRITE ? 1 : 0;
            s_info = &pipeP->tsock[idx];
         }
         /* XXX: If tag is not sent, then it will not be logged; is this 
          * what we want? */
         DEBUG_ONLY(UNUSED const size_t tag_len = *tag_len_ptr;)
         err = TSock_Send( s_info, msgP, flags, tag_ptr, tag_len_ptr );
         ASSERT(*tag_len_ptr == 0 || *tag_len_ptr == tag_len);
      } 
      break;
   default:
      {
         /* The line is definitely not tagged. Just call through to
          * Linux. */
         if (pos >= 0) {
            ASSERT(msgP->msg_iovlen == 1);
            err = SysOps_pwrite64(filP->rfd, msgP->msg_iov->iov_base, 
                  msgP->msg_iov->iov_len, pos);
         } else {
            ASSERT(pos == -1);
            /* Note that we use writev rather than write; that's
             * because we may be invoked on the fast logging path.
             * Since the message contents aren't logged on this path,
             * we don't flatten the vector as we do when logging on
             * the slow path (where we copy message into the log first
             * and then sys_write it). */
            ASSERT(msgP->msg_iov->iov_len >= 0);
            err = SysOps_writev(filP->rfd, msgP->msg_iov, msgP->msg_iovlen);
         }
      }
      break;
   }

   if (err > 0) {
      *nr_chunks_ptr = 1; // each send is exactly one chunk
   } else {
      *nr_chunks_ptr = 0;
   }

   DEBUG_MSG(5, "err=%d\n", err);
   return err;
}

static ssize_t
WrapDoSysRead(const struct FileStruct *filP, struct msghdr *msgP, 
      const int flags, const loff_t pos, tsock_chunk_t *chunk_buf,
      int *nr_chunks_ptr)
{
   ssize_t err;
   struct InodeStruct *inoP = File_Inode(filP);

   ASSERT(!VCPU_IsReplaying());
   ASSERT(*nr_chunks_ptr == MAX_NR_CHUNKS);

   const InodeMajor major = Inode_GetMajor(inoP);
   switch (major) {
   case InodeMajor_Sock:
   case InodeMajor_Pipe:
      {
         tsock_socket_info_t *s_info = NULL;
         if (major == InodeMajor_Sock) {
            struct SockStruct *sockP = Sock_GetStruct(inoP);
            s_info = &sockP->tsock;
         } else {
            ASSERT(major == InodeMajor_Pipe);
            struct PipeStruct *pipeP = Pipe_GetStruct(inoP);
            const int idx = filP->accMode & FMODE_WRITE ? 1 : 0;
            s_info = &pipeP->tsock[idx];
         }
         err = TSock_Recv(s_info, msgP, flags, chunk_buf, nr_chunks_ptr);
         ASSERT(err > 0 || *nr_chunks_ptr == 0);
      }
      break;
   default:
      {
         if (pos >= 0) {
            ASSERT(msgP->msg_iovlen == 1);
            err = SysOps_pread64(filP->rfd, msgP->msg_iov->iov_base, 
                  msgP->msg_iov->iov_len, pos);
         } else {
            ASSERT(pos == -1);
            ASSERT(msgP->msg_iov->iov_len >= 0);
            err = SysOps_readv(filP->rfd, msgP->msg_iov, msgP->msg_iovlen);
         }
         WrapSetDefaultChunkBuf(err, chunk_buf, nr_chunks_ptr);
      }
      break;
   }

   ASSERT_MSG(*nr_chunks_ptr >= 0 && *nr_chunks_ptr <= MAX_NR_CHUNKS,
         "nr_chunks=%d", *nr_chunks_ptr);

   DEBUG_MSG(5, "nr_chunks=%d err=%d\n", *nr_chunks_ptr, err);
   return err;
}

static ssize_t
WrapDoSysIO(const int ioReqFlags, const struct FileStruct *filP, 
      struct msghdr *msgP, const int flags, const loff_t pos, 
      tsock_chunk_t *chunk_buf, int *nr_chunks_ptr)
{
   const int is_read = (ioReqFlags & IOREQ_READ);
   ssize_t err;

   ASSERT(!VCPU_IsReplaying());
   ASSERT(*nr_chunks_ptr == MAX_NR_CHUNKS);

   if (is_read) {
      err = WrapDoSysRead(filP, msgP, flags, pos, chunk_buf, 
            nr_chunks_ptr);
   } else {
      err = WrapDoSysWrite(filP, msgP, flags, pos, chunk_buf, 
            nr_chunks_ptr);
   }

   ASSERT(*nr_chunks_ptr <= MAX_NR_CHUNKS);
   return err;
}

static ssize_t
WrapSlowRead(
        TYPE_EXPANDED(sys_io) *entryP, 
        const int ioReqFlags,
        const struct FileStruct *filP, 
        const int fd, 
        struct msghdr *kmsgP, 
        struct msghdr *lmsgP,
        const int flags, 
        int ioflags, 
        const loff_t pos)
{
    ssize_t err;
    const int isKernReq = ioReqFlags & IOREQ_KERN;

    ASSERT(isKernReq || !isKernReq);

    /* ----- Slow path: copy from Linux into log file first ----- */

    if (VCPU_IsLogging()) {
        err = WrapDoSysRead(filP, lmsgP, flags, pos, entryP->chunk_buf,
                            &entryP->nr_chunks);

        kmsgP->msg_namelen = entryP->msg_namelen = lmsgP->msg_namelen;
        kmsgP->msg_controllen = entryP->msg_controllen = lmsgP->msg_controllen;
        kmsgP->msg_flags = entryP->msg_flags = lmsgP->msg_flags;
        entryP->ret = err;
        entryP->loggedContentLen = SYSERR(err) ? 0 : err;
    } else {
        ASSERT(VCPU_IsReplaying());
        kmsgP->msg_namelen = entryP->msg_namelen;
        kmsgP->msg_controllen = entryP->msg_controllen;
        kmsgP->msg_flags = entryP->msg_flags;
        err = entryP->ret;
    }

    ASSERT(entryP->loggedContentLen >= 0);

    /* ----- Copy from log file to destination buffer -----
     *
     * This has to be done while we hold the log entry. Otherwise, the
     * log may rotate and our pointers to the entry will no longer be
     * valid. */

    if (!SYSERR(err)) {
        if (isKernReq) {
            /* ----- Destination is in vkernel space. ----- */

            ASSERT_UNIMPLEMENTED(!(ioflags & IOF_SOCK));
            ASSERT_UNIMPLEMENTED(!kmsgP->msg_name);
            ASSERT_UNIMPLEMENTED(!kmsgP->msg_control);

            Task_IovCopyToKernel(kmsgP->msg_iov, kmsgP->msg_iovlen, 
                    lmsgP->msg_iov->iov_base, err);
        } else {
            /* ----- Destination is in user space ----- */

            /* XXX: We should copy to user-space just like control and iovdata,
             * to be consistent. */
            if (lmsgP->msg_name && kmsgP->msg_namelen > 0) {
                ASSERT_KPTR(kmsgP->msg_name);
                memcpy(kmsgP->msg_name, lmsgP->msg_name, kmsgP->msg_namelen);
            }

            if (lmsgP->msg_control && kmsgP->msg_controllen > 0) {
                if (copy_to_user(kmsgP->msg_control, lmsgP->msg_control,
                            kmsgP->msg_controllen)) {
                    err = -EFAULT;
                    ASSERT_UNIMPLEMENTED(0);
                    goto out;
                }
            }

            if (entryP->loggedContentLen > 0) {
                if (copy_to_user_iov(kmsgP->msg_iov, kmsgP->msg_iovlen, 
                            lmsgP->msg_iov->iov_base, entryP->loggedContentLen)) {
                    err = -EFAULT;
                    ASSERT_UNIMPLEMENTED(0);
                    goto out;
                }
                /* XXX: clear the remaining unlogged portion, to make
                 * debugging easier/more predictable. */
            } else {
                /* EOF (0) or errors are valid. */
            }
        }
   }

out:
   return err;
}

static ssize_t
WrapSlowWrite(
      TYPE_EXPANDED(sys_io) *entryP,
      const int ioReqFlags,
      const struct FileStruct *filP, 
      int fd, 
      struct msghdr *kmsgP, 
      struct msghdr *lmsgP,
      const int flags, 
      int ioflags, 
      const loff_t pos)
{
   ssize_t err = 0;

#if DEBUG
   /* Vkernel shouldn't make any writes... */
   int isKernReq = ioReqFlags & IOREQ_KERN;
   ASSERT(!isKernReq);
#endif

   if (VCPU_IsLogging()) {
      /* ----- Slow path: copy from user into log, then to kernel ----- */

      if (lmsgP->msg_name && kmsgP->msg_namelen) {
         /* XXX: CopyFromUser should get info from log on replay. */
         ASSERT_KPTR(kmsgP->msg_name);
         memcpy(lmsgP->msg_name, kmsgP->msg_name, kmsgP->msg_namelen);
      }

      if (lmsgP->msg_control && kmsgP->msg_controllen) {
         if (copy_from_user(lmsgP->msg_control, kmsgP->msg_control,
                  kmsgP->msg_controllen)) {
            err = -EFAULT;
            ASSERT_UNIMPLEMENTED(0);
            goto out;
         }
      }

      const size_t reqBytes = lmsgP->msg_iov->iov_len;
      if (reqBytes > 0) {
         if (copy_from_user_iov(lmsgP->msg_iov->iov_base, 
                  kmsgP->msg_iov, kmsgP->msg_iovlen, reqBytes)) {
            err = -EFAULT;
            ASSERT_UNIMPLEMENTED(0);
            goto out;
         }
      }

      err = WrapDoSysWrite(filP, lmsgP, flags, pos, entryP->chunk_buf, 
                           &entryP->nr_chunks);
      entryP->ret = err;

      /* Note that we log the entire buffer, regardless of how
       * much was actually transferred to the kernel. The
       * state of the userspace buffer is a valuable output clue, 
       * and thus should be considered in its entirety for inference. */
      entryP->loggedContentLen = reqBytes;
   } else {
      ASSERT(VCPU_IsReplaying());
      err = entryP->ret;
   }

   ASSERT(entryP->nr_chunks >= 0);
   ASSERT(entryP->chunk_buf[0].tag_len >= 0);
   if (entryP->chunk_buf[0].tag_len) {
      WrapOnTagSend(entryP->chunk_buf[0].tag_buf, 
            entryP->chunk_buf[0].tag_len);
   }

out:
   /* XXX: ``man'' triggers this; it also tries to issue tty ioctls on
    * disk files, so something funny is going on in that app--but
    * then we could be confusing it :-(. */
   ASSERT_COULDBE(SYSERR(err));

   return err;
}

static INLINE size_t
CountIovBytes(const struct iovec *vecA, const int vecLen)
{
   int i;
   size_t count = 0;

   for (i = 0; i < vecLen; i++) {
      ssize_t len = vecA[i].iov_len;

      ASSERT(len >= 0);

      count += len;
   }

   return count;
}

#if 0
static void
WrapModuleUserCopyIov(const int isFrom,
                         struct CopySource *csP,
                         const char *logDataP,
                         const size_t loggedLen,
                         const struct iovec *vec, 
                         const ulong vlen, 
                         const ulong lenBytes)
{
   int i = 0;
   size_t nrBytesDone = 0;

   ASSERT_COULDBE(logDataP == NULL);
   ASSERT(loggedLen >= 0);

   while (nrBytesDone < lenBytes) {
      /* 
       * We shouldn't have received more bytes than the iov can support.
       */
      ASSERT(i < vlen);

      const size_t nrBytesToDo = MIN(lenBytes - nrBytesDone, vec[i].iov_len);

      if (logDataP && loggedLen > nrBytesDone) {
         csP->logDataP = logDataP + nrBytesDone;
         csP->loggedLen = MIN(loggedLen - nrBytesDone, nrBytesToDo);
      } else {
         csP->logDataP = NULL;
         csP->loggedLen = 0;
      }

      Module_OnUserCopy(isFrom, csP, vec[i].iov_base, nrBytesToDo);
      nrBytesDone += nrBytesToDo;
      i++;
   }
}
#endif


/*
 * Summary:
 *    Determine if we need to log the data, and then log it.
 *
 *    Two are two paths: the fast and the slow.
 *
 *    The fast path: channel isn't logged (perhaps because it has a high
 *    data-rate), in which case we transfer data directly from kernel to 
 *    userspace buffer (or vice versa for reads), just like a native 
 *    execution.
 *
 *    The slow path: channel is logged, in which case we transfer data to
 *    the VCPU log buffer, and then to userspace. Why copy first to the
 *    log buffer you ask? Because we want to avoid the race where the
 *    data we ultimately log is different that the data the app ends up
 *    seeing, due to a concurrent modification of the userspace buffer
 *    by another thread.
 *
 * XXX:
 *    The entire name and control buffers may not be used, in which case 
 *    we're wasting the intermediate log space.
 *
 *    Parameters must be same during replay (controllen, namelen, etc.)
 *    to ensure that logs are read correctly.
 *
 *    We assume that I/O syscall we make (namely, sys_recvmsg) won't 
 *    block. If it does, then we may deadlock since we hold the VCPU
 *    lock, hence preventing other tasks on the VCPU from accessing the
 *    log. This assumption should hold because, we call this function
 *    only if the kernel tells us that there is data on this channel.
 *    But this needs to be verified.
 *
 *    The performance overhead of the above mechanism is high: it
 *    requires a call to select before the sys_read. We'll probably need
 *    kernel mods to optimize this.
 */
static ssize_t
WrapDoTransferWork(
      const int ioReqFlags, 
      const struct FileStruct *filP, 
      const int fd /* XXX : get rid of this? */, 
      struct msghdr *kmsgP, 
      const int flags, 
      const int ioflags, /* XXX: do we need this given filP? */
      const loff_t pos)
{
   ASSERT_KPTR_NULL(kmsgP->msg_name);
   ASSERT_UPTR_NULL(kmsgP->msg_control);
   ASSERT_KPTR(kmsgP->msg_iov);

   ssize_t err;
   const int is_read = ioReqFlags & IOREQ_READ;
   const int isKernReq = ioReqFlags & IOREQ_KERN;
   size_t loggedBytes;

   if (VCPU_IsLogging()) {
      ASSERT(fd >= 0);
   }

   const size_t reqBytes = CountIovBytes(kmsgP->msg_iov, 
         kmsgP->msg_iovlen);
   const size_t maxBytes = reqBytes + kmsgP->msg_namelen + 
      kmsgP->msg_controllen;

   DEBUG_MSG(5, "reqBytes=%lu maxBytes=%lu\n", reqBytes, maxBytes);
   ASSERT_COULDBE(reqBytes == 0); // True for hypertable client

   /* XXX: only one chunk entry needed for sends, but received may
    * need multiple. Log entry is sized for the receive. This is
    * wasteful of log space on sends. Perhaps use different log entries, 
    * or make the chunk length variable?
    */
   /* XXX: don't need to reserve maxBytes if on the fast path */
   /* XXX: sys_io logs more than necessary, if this is a write. */
   const int wantsRateLimiting = 0;
   DO_WITH_LOG_ENTRY_DATA_RESERVE(sys_io, maxBytes, wantsRateLimiting) {
      ASSERT_COULDBE(!wantsRateLimiting || datap == NULL);

      const int couldBeDataChannel = filP->channel_kind == Chk_Data ||
         filP->channel_kind == Chk_MaybeData;

      /* XXX: if log bandwidth available, give priority to
       * control plane flows, but log all if possible. 
       * Currently, data plane flows
       * may be dropped even if log bandwidth available. */
#if PRODUCT
#error "XXX: enable fast path, currently broken"
#endif
      const int useFastPath = wantsRateLimiting && 
         ((VCPU_IsLogging() && !isKernReq && 
         !kmsgP->msg_name && !kmsgP->msg_control &&
         couldBeDataChannel) || !datap);

      const char *dataStartP = datap;
      char *logNameP = NULL, *logControlP = NULL, *logBodyP = NULL;

      // XXX: Tsockets looks at this to determine the maximum chunk buf
      // len; ideally we should support an arbitrary number of chunks
      if (VCPU_IsLogging()) {
         entryp->nr_chunks = MAX_NR_CHUNKS;
         // We want to be able to have a sense of real time during
         // replay, so we record the wall clock
         curr_vcpu->wall_clock = entryp->wall_time = get_sys_micros();
      } else {
         ASSERT(VCPU_IsReplaying());
         ASSERT(entryp->nr_chunks <= MAX_NR_CHUNKS);
         curr_vcpu->wall_clock = entryp->wall_time;
      }

      if (VCPU_IsLogging() && useFastPath) {
         ASSERT_COULDBE(datap == NULL);
         DEBUG_MSG(5, "Fast path: skip logging, just transfer data\n");
         /* ----- Fast path: copy from user directly into kernel ----- */
         err = WrapDoSysIO(ioReqFlags, filP, kmsgP, flags, pos,
                  entryp->chunk_buf, &entryp->nr_chunks);
         entryp->ret = err;
         entryp->loggedContentLen = 0;
         env.is_value_det = 0;
      } else {
         DEBUG_MSG(5, "Slow path: log, then copy to/form userspace\n");
         ASSERT(VCPU_IsLogging() || VCPU_IsReplaying());
         ASSERT_KPTR(datap);

         /* ----- Slow path: we need to log the io data ----- */

         /* ----- Get pointers into the log entry ----- */

         /* XXX: For reads, the name and control data may be less than,
          * than msg_namelen and msg_controllen, respectively. But to
          * keep things simple, we allocate space for the maximum. */
         if (kmsgP->msg_name) {
            ASSERT(kmsgP->msg_namelen >= 0);
            ASSERT(ioflags & IOF_SOCK);
            logNameP = datap;
            datap += kmsgP->msg_namelen;
         } else {
            ASSERT(!kmsgP->msg_namelen);
         }

         if (kmsgP->msg_control) {
            ASSERT(kmsgP->msg_controllen >= 0);
            ASSERT(ioflags & IOF_SOCK);
            logControlP = datap;
            datap += kmsgP->msg_controllen;
         } else {
            ASSERT(!kmsgP->msg_controllen);
         }

         logBodyP = datap;

         ASSERT_KPTR_NULL(logNameP);
         ASSERT_KPTR_NULL(logControlP);
         ASSERT_KPTR(logBodyP);

         struct iovec lmsg_iov = { 
            .iov_base = logBodyP, .iov_len = reqBytes,
         };
         struct msghdr lmsg = {
            .msg_name = logNameP, 
            .msg_namelen = kmsgP->msg_namelen,
            .msg_control = logControlP, 
            .msg_controllen = kmsgP->msg_controllen,
            .msg_iov = &lmsg_iov, 
            .msg_iovlen = 1, 
            .msg_flags = kmsgP->msg_flags 
         };

         if (is_read) {
            err = WrapSlowRead(entryp, ioReqFlags, filP, fd, kmsgP, 
                  &lmsg, flags, ioflags, pos);
         } else {
            err = WrapSlowWrite(entryp, ioReqFlags, filP, fd, kmsgP, 
                  &lmsg, flags, ioflags, pos);
         }

         datap += entryp->loggedContentLen;
      }

      /* ---- Notify modules interested in the I/O event ----- */
      /* XXX: move to a new function */
#if DEBUG
      ASSERT(entryp->nr_chunks >= 0);
      if (err > 0) {
         ASSERT(entryp->nr_chunks > 0);
      } else {
         ASSERT(entryp->nr_chunks == 0);
      }
#endif

      if (!isKernReq && err > 0) {
         int i;
         struct CopySource cs = { 
            .tag = Sk_SysIO,
            .Un.SysIO.filP = filP,
            .Un.SysIO.msg_flags = flags,
            .logDataP = NULL, // default, true for fastpath
            .loggedLen = 0,
            .Un.SysIO.chunk_ptr = NULL, // to be filled in below
         };

         ASSERT_KPTR(kmsgP->msg_iov);
         ASSERT_COULDBE(logBodyP == NULL); // true on fastpath
         ASSERT(entryp->nr_chunks > 0);

         DEBUG_MSG(5, "Transfer: nr_chunks=%d\n", entryp->nr_chunks);

         for (i = 0; i < entryp->nr_chunks; i++) {
            const tsock_chunk_t *chunk_ptr = &entryp->chunk_buf[i];
            const tsock_chunk_t *next_chunk_ptr = 
               ((i+1) < entryp->nr_chunks) ? &entryp->chunk_buf[i+1] :
               NULL;
            const size_t chunk_len = next_chunk_ptr ? 
               next_chunk_ptr->data_off - chunk_ptr->data_off :
               err - chunk_ptr->data_off;
            ASSERT_MSG(chunk_ptr->data_off >= 0, "data_off=%d", 
                  chunk_ptr->data_off);
            ASSERT_MSG(chunk_len > 0, "chunk_len=%d", chunk_len);
            struct IoVec *iov_ptr = IovOps_Make(kmsgP->msg_iov,
                  kmsgP->msg_iovlen);

            IovOps_TruncateHead(iov_ptr, chunk_ptr->data_off);
            IovOps_TruncateTail(iov_ptr, IovOps_GetCapacity(iov_ptr) -
                  chunk_len);

            ASSERT(IovOps_GetCapacity(iov_ptr) == chunk_len);

            cs.Un.SysIO.chunk_ptr = chunk_ptr;
            if (logBodyP) {
               cs.logDataP = logBodyP + chunk_ptr->data_off;
               cs.loggedLen = chunk_len;
            }
            ASSERT_COULDBE(chunk_len != cs.loggedLen);
            if (is_read) {

               // We need to invoke OnTagRecv here rather than in
               // WrapSlowRead, since that is only called on the slow
               // path. We may receive tagged message on the fast path
               // as well.
               // XXX: is there a reason to invoke OnTagRecv for all
               // read chunks? why not just invoke it for the last 
               // read chunk?
               // XXX: should be invoked via the OnUserCopy
               // callback, so this is just a temporary hack
               // XXX: we invoke this after delivering the message
               // to user-land, when really, we should do it
               // before...if the sending tasks inspects our state
               // before the send, it should see that we haven't
               // gotten the message...
               if (chunk_ptr->tag_len) {
                  WrapOnTagRecv(chunk_ptr->tag_buf, chunk_ptr->tag_len);
               }
            }
            // Must come after tag recv, to ensure that distributed
            // replay respects causal ordering of messages
            Module_OnUserCopy(!is_read, &cs, iov_ptr, chunk_len);

            // XXX: must be called after Module_OnUserCopy to ensure
            // that it runs after formgen's callback, which untaints
            // logged bytes. Server_OnUserCopy may decide to taint
            // those bytes and we don't want that taint to get lost.
            
            extern void
               Server_OnUserCopy(const int is_write,
                     const struct CopySource *cs_ptr,
                     const struct IoVec *iov_ptr, 
                     const size_t total_len);
            Server_OnUserCopy(!is_read, &cs, iov_ptr, chunk_len);

            IovOps_Free(iov_ptr);
         }

#if 0
         if (kmsgP->msg_control) {
            ASSERT_KPTR_NULL(logControlP);
            ASSERT(kmsgP->msg_controllen > 0);
            cs.logDataP = logControlP;
            cs.loggedLen = kmsgP->msg_controllen;
            Module_OnUserCopy(!is_read, &cs, kmsgP->msg_control,
                  kmsgP->msg_controllen);
         }
#else
#if PRODUCT
#error "XXX: need to invoke modules on control data as well"
         // sshd uses this in interactive/shell mode, don't know why
#else
         ASSERT_UNIMPLEMENTED(!kmsgP->msg_control);
#endif
#endif
      }

      ASSERT_COULDBE(SYSERR(err));

      /* ----- Done, now advance to the next log entry. ----- */
      loggedBytes = (size_t)(datap) - (size_t)(dataStartP);

      ASSERT_MSG(loggedBytes <= maxBytes, 
            "err=%d loggedBytes=%lu maxBytes=%lu\n",
            err, loggedBytes, maxBytes);
   } END_WITH_LOG_ENTRY(loggedBytes);

   return err;
}

/* XXX: shouldn't this belong in fs/read_write.c? It's generic, and
 * makes VFS calls, so it doesn't make sense to make it part of the
 * VFS. */
int
ReadDet_io(
      const int ioReqFlags, 
      const struct FileStruct *filP, 
      const int fd /* XXX : get rid of this? */, 
      struct msghdr *kmsgp, 
      const int flags, 
      const int ioflags, /* XXX: do we need this given filP? */
      const loff_t pos)
{
   int err = 0;
   const int is_read = ioReqFlags & IOREQ_READ;
#if MAX_NR_VCPU > 1 && PRODUCT
   /* XXX: read needs to be protected by lock. */
   ASSERT_UNIMPLEMENTED_MSG(NR_VCPU == 1,
         "access to file flags needs to be locked to ensure "
         "determinism");
#error "XXX"
#endif
   const int is_blocking = !(filP->flags & O_NONBLOCK);

#if DEBUG
   if (VCPU_IsLogging()) {
      ASSERT(fd >= 0);
   } else {
      /* 
       * XXX:
       *
       * ASSERT(fd >= -1) fails, because we try to reopen files during
       * replay, but in some cases they may not exist anymore, in which
       * case we get an error code < -1. This happened with Hypertable's
       * kill-server.sh script, after starting the master with
       * start-master.sh. 
       */
      ASSERT(fd < 0 || fd >= 0);
   }
#endif

   if (filP->f_op->select) {
      err = filP->f_op->select(filP, is_read, is_blocking);
      if (!is_blocking) {
         ASSERT_MSG(err == 0 || err == 1, "err=%d", err);
         if (err == 0) {
            err = -EAGAIN;
            goto out;
         } 
      }
   }

   DEBUG_MSG(5, "is_blocking=%d is_read=%d err=%d\n", 
         is_blocking, is_read, err);
   if (!SYSERR(err)) {
      err = WrapDoTransferWork(ioReqFlags, filP, fd, kmsgp, flags, 
               ioflags, pos);
   }

out:
   return err;
}

static int
ReadDetGetLock(int fd, uint cmd, void *l)
{
   SyscallRet ret;
   size_t argSz =
      (cmd == F_GETLK ? sizeof(struct flock) : sizeof(struct flock64));

   ASSERT(cmd == F_GETLK || cmd == F_GETLK64);

   if (!VCPU_IsReplaying()) {
      ASSERT(fd >= 0);
      ret = syscall(SYS_fcntl64, fd, cmd, l);

      if (VCPU_IsLogging()) {

         DO_WITH_LOG_ENTRY_DATA(JustRetval, argSz) {
            entryp->ret = ret;
            memcpy(datap, l, argSz);
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
         memcpy(l, datap, argSz);
      } END_WITH_LOG_ENTRY(argSz);
   }

   return ret;
}

static int
ReadDetSetLock(int fd, uint cmd, const void *l)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ASSERT(fd >= 0);
      ret = syscall(SYS_fcntl64, fd, cmd, l);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

static int
ReadDetSetLockWait(int fd, uint cmd, const void *l)
{
   SyscallRet res;
   struct SyscallArgs args;
   int wasInterrupted, isSignalPending;

   args.eax = SYS_fcntl64;
   args.ebx = fd;
   args.ecx = cmd;
   args.edx = (ulong) l;

#if DEBUG
   if (VCPU_IsLogging()) {
      ASSERT(fd >= 0);
   } else {
      ASSERT(fd >= -1);
   }
#endif

   do {

      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      res = Sched_BlockingRealSyscall(NULL, &args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = res;
         } END_WITH_LOG_ENTRY(0);
      } else if (VCPU_IsReplaying()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            res = entryp->ret;
         } END_WITH_LOG_ENTRY(0);
      }

      wasInterrupted = res == -EINTR;
      isSignalPending = Task_TestSigPending(current, 1);

   } while (wasInterrupted && !isSignalPending);

   return res;
}


int
ReadDet_lock(int fd, uint cmd, void *l)
{
   switch (cmd) {
   case F_GETLK:
   case F_GETLK64:
      return ReadDetGetLock(fd, cmd, l);
   case F_SETLK:
   case F_SETLK64:
      return ReadDetSetLock(fd, cmd, l);
   case F_SETLKW:
   case F_SETLKW64:
      return ReadDetSetLockWait(fd, cmd, l);
   default:
      ASSERT(0);
      break;
   }

   return -1;
}

int
ReadDet_flock(int fd, uint cmd)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ASSERT(fd >= 0);

      /* XXX: Need to schedule out if we block... */
      ASSERT_UNIMPLEMENTED(cmd & LOCK_NB);

      ret = syscall(SYS_flock, fd, cmd);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

int
ReadDet_pipe(int *fds)
{
   int res;

   if (!VCPU_IsReplaying()) {
      res = syscall(SYS_pipe, fds);

      /* the rfds may be used during replay by the epoll and select/poll
       * code to perform deterministic rfd<-->vfd translation. So we must
       * log them. */
      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_pipe) {
            entryp->ret = res;
            entryp->fds[0] = fds[0];
            entryp->fds[1] = fds[1];
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(sys_pipe) {
         res = entryp->ret;
         fds[0] = entryp->fds[0];
         fds[1] = entryp->fds[1];
      } END_WITH_LOG_ENTRY(0);
   }

   return res;
}

int
ReadDet_epoll_create(int size) 
{
   int res;

   if (!VCPU_IsReplaying()) {

      res = syscall(SYS_epoll_create, size);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = res;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         res = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return res;
}

int
ReadDet_epoll_ctl(int epollFd, int op, int fd, struct epoll_event *kevent)
{
   int err;

   DEBUG_MSG(5, "efd=%d fd=%d op=%d\n", epollFd, fd, op);

   if (!VCPU_IsReplaying()) {

      err = syscall(SYS_epoll_ctl, epollFd, op, fd, kevent);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   if (DEBUG) {
      if (err) {
         DEBUG_MSG(5, "err=%d\n", err);
         ASSERT(err == -EPERM || err == -ENOMEM);
      }
   }

   return err;
}

int
ReadDetEpollWaitLogResults(int numevents, struct epoll_event *events)
{
   size_t eventArraySz = 0;
   int i;

   if (VCPU_IsLogging()) {
      if (!SYSERR(numevents)) {
         eventArraySz = numevents * sizeof(struct epoll_event);
      } 

      DO_WITH_LOG_ENTRY_DATA(JustRetval, eventArraySz) {
         entryp->ret = numevents;

         if (!SYSERR(numevents)) {
            struct epoll_event *parray = (struct epoll_event*) datap;
            for (i = 0; i < numevents; i++) {
               parray[i] = events[i];
            }
         }
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY(JustRetval) {
         numevents = entryp->ret;

         if (!SYSERR(numevents)) {
            struct epoll_event *parray = (struct epoll_event*) datap;
            for (i = 0; i < numevents; i++) {
               events[i] = parray[i];
            }

            eventArraySz = numevents * sizeof(struct epoll_event);
         }
      } END_WITH_LOG_ENTRY(eventArraySz);
   }

   return numevents;
}

/*
 * OUT:
 *
 *    @vevents: buffer to place rfd->vfd translated events 
 *
 * RETURNS:
 *
 *    # of vfd events (which <= # rfd events)
 */
int
ReadDet_epoll_wait(struct EpollStruct *ep, struct epoll_event *vevents, 
      int maxevents, int timeout)
{
   int error, revCount;
   int wasInterrupted, isSignalPending;
   struct epoll_event *revents;
   struct SyscallArgs args;

   /* # of rfd events is at most the number of vfd events. */
   size_t evSz = sizeof(struct epoll_event) * maxevents;

   revents = SharedArea_Malloc(evSz);

   args.eax = SYS_epoll_wait;
   args.ebx = ep->fd;
   args.ecx = (ulong) revents;
   args.edx = maxevents;
   args.esi = timeout;

   do {
      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      revCount = Sched_BlockingRealSyscall(NULL, &args);

      revCount = ReadDetEpollWaitLogResults(revCount, revents);

      DEBUG_MSG(5, "revCount=%d\n", revCount);

      wasInterrupted = (revCount == -EINTR);
      isSignalPending = Task_TestSigPending(current, 1);

      /* If we're interrupted by an internal signal, then
       * we need to try again. The fd_sets shouldn't be
       * altered, however, so there is no need to reload
       * them. */

   } while (wasInterrupted && !isSignalPending);

   if (revCount == -EINTR) {
      error = revCount;
   } else if (revCount == 0) {
      /* Timed out before anything happened. */
      error = 0;
   } else {
      int vevCount;

      /* Note that we check sigpending after making the Linux syscall. */
      ASSERT(isSignalPending || !isSignalPending);
      ASSERT(revCount > 0);

      vevCount = Epoll_RealToVirt(ep, vevents, maxevents, revents, revCount);

      error = vevCount;
   }

   SharedArea_Free(revents, evSz);
   revents = NULL;

   return error;
}

int
ReadDet_eventfd2(unsigned int count_initval, int flags)
{
   int res;

   if (!VCPU_IsReplaying()) {
      res = syscall(SYS_eventfd2, count_initval, flags);
      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = res;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         res = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return res;
}
