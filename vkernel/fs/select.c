#include "vkernel/public.h"
#include "private.h"

/* 
 * DESIGN NOTES: 
 *
 * We cannot emulate sys_select with sys_poll, or sys_select/sys_poll with
 * epoll. That's because sys_poll and sys_epoll may not be avaialable in all
 * Linux versions, and we want to retain high compatability. 
 */

/*
 * How many longwords for "nr" bits?
 */
#define FDS_BITPERLONG	(8*sizeof(long))
#define FDS_LONGS(nr)	(((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define FDS_BYTES(nr)	(FDS_LONGS(nr)*sizeof(long))


struct SelectArgs {
   const tsock_socket_info_t *s_info;
   int is_read;
};

static int
SelectTaggedWork(void *arg)
{
   struct SelectArgs *arg_p = (struct SelectArgs *)arg;

   // Must use TSock_Select rather than sys_select, since TSock may
   // maintain its own (user-level) data queues.
   sigset_t mask;
   SigOps_InitSet(&mask, 0);
   return TSock_Pselect(arg_p->s_info, arg_p->is_read, NULL, &mask);
}

int
Select_DefaultTaggedFop(const tsock_socket_info_t *s_info, const int is_read, 
             const int should_block)
{
   int err;
   if (should_block) {
      do {
         // XXX: optimization: no need to schedule out if data is
         // waiting
         struct SelectArgs args = { .s_info = s_info, .is_read = is_read };
         Task_SetCurrentState(TASK_INTERRUPTIBLE);
         err = Sched_BlockingRealSyscall(&SelectTaggedWork, &args);
         Log_ReplayInt((uint*)&err);
      } while (err == -EINTR && !Task_TestSigPending(current, 1));
   } else {
      // No need to schedule out since blocking is disabled
      struct timeval timeout = { .tv_sec = 0, .tv_usec = 0 };
      if (!VCPU_IsReplaying()) {
         err = TSock_Pselect(s_info, is_read, &timeout, NULL);
      } 
      Log_ReplayInt((uint*)&err);
      ASSERT(err == 0 || err == 1);
   }
   DEBUG_MSG(5, "err=%d\n", err);
   return err;
}

int
Select_DefaultUntaggedFop(const struct FileStruct *filP, const int is_read,
               const int should_block)
{
   int err;
   fd_set fds;
   const int fd = !VCPU_IsReplaying() ? filP->rfd : 0;
   const int fd_count = fd+1;

   FD_ZERO(&fds);
   FD_SET(fd, &fds);

   if (should_block) {
      do {
         struct SyscallArgs args = { 
            .eax = SYS_select,
            .ebx = fd_count,
            .ecx = is_read ? (ulong)&fds : 0,
            .edx = is_read ? 0 : (ulong)&fds,
            .esi = 0,
            .edi = 0
         };
         Task_SetCurrentState(TASK_INTERRUPTIBLE);
         err = Sched_BlockingRealSyscall(NULL, &args);
         Log_ReplayInt((uint*)&err);
      } while (err == -EINTR && !Task_TestSigPending(current, 1));
   } else {
      struct timeval timeout = { .tv_sec = 0, .tv_usec = 0 };
      err = SysOps_select(fd_count, is_read ? &fds : NULL, 
            is_read ? NULL : &fds, NULL, &timeout);
      ASSERT_MSG(err == 0 || err == 1, "err=%d", err);
      Log_ReplayInt((uint*)&err);
   }

   return err;
}

static INLINE int 
SelectGetFdSet(ulong nr, fd_set __user * ufdset, fd_set *fdset)
{
	nr = FDS_BYTES(nr);
	if (ufdset)
		return Task_CopyFromUser(fdset, ufdset, nr) ? -EFAULT : 0;

	memset(fdset, 0, nr);

	return 0;
}

static INLINE ulong
SelectSetFdSet(ulong nr, fd_set __user *ufdset, fd_set *fdset)
{
	if (ufdset)
		return Task_CopyToUser(ufdset, fdset, FDS_BYTES(nr));
	return 0;
}

/*
 * @n : highest-number fd in user-set plus 1
 */
static int
SelectVirtToReal(uint n, fd_set *rp, fd_set __user *uvp, fd_set *vp, 
                 int *max)
{
   int error = 0;
   uint vfd;
   struct FilesStruct *files = current->files;
   struct FdTableStruct *fdt = current->files->fdt;
   uint maxFds;

   ASSERT(rp);
   ASSERT(vp);
   ASSERT(max);

   *max = 0;

   if (!uvp) { goto out; }

   if ((error = SelectGetFdSet(n, uvp, vp))) {
      goto out;
   }

   FD_ZERO(rp);

   Files_Lock(files);

   /* Access to fdt->maxFds must be protected by files->lock. */
   maxFds = MIN(n, fdt->maxFds);
   //maxFds = fdt->maxFds;

   for (vfd = 0; vfd < maxFds; vfd++) {
      struct FileStruct *filp;

      if (!FD_ISSET(vfd, vp)) { continue; }

      /* Ensure that the file object is not deallocated while
       * we're inspecting it. */
      filp = File_GetUnlocked(vfd);

      /* The user may specify invalid vfds, or some vfds
       * may have been concurrently closed before we acquired
       * the files->lock. */
      if (filp) {
         ASSERT(filp->orig_rfd >= 0);

         /* XXX: fdsets can refer to only the first FD_SETSIZE fds.
          * Since we're using CLONE_FILES, it's likely we'll hit this
          * limit soon, in which case, we may have to emulate select
          * with sys_poll. */
         ASSERT_UNIMPLEMENTED(filp->orig_rfd < FD_SETSIZE);
         DEBUG_MSG(5, "orig_rfd=%d\n", filp->orig_rfd);

         FD_SET(filp->orig_rfd, rp);
         *max = MAX(*max, filp->orig_rfd);

         /* File_Put doesn't acquire the files lock, so it needn't
          * have an unlocked version. */
         File_Put(filp);
      } else {
         error = -EBADF;
         goto unlock_out;
      }
   }

unlock_out:
   Files_Unlock(files);
   D__;
out:
   return error;
}

/*
 * @n : highest-number fd in user-set plus 1
 */
static int
SelectRealToVirt(int n, fd_set __user *uvp, fd_set *rp, fd_set *vp, 
                 int *count)
{
   int error = 0;
   uint vfd;
   fd_set __uv;
   struct FilesStruct *files = current->files;
   struct FdTableStruct *fdt = current->files->fdt;
   uint maxFds;

   ASSERT(rp);

   if (!uvp) { goto out; }

   FD_ZERO(&__uv);

   /* XXX: what if a vfd --> rfd mapping changes while waiting
    * in the select? Or if rfd gets closed? */

   Files_Lock(files);

   /* Access to fdt->maxFds protected by files->lock. */
   maxFds = MIN(n, fdt->maxFds);
   //maxFds = fdt->maxFds;

   for (vfd = 0; vfd < maxFds; vfd++) {
      struct FileStruct *filp;

      if (!FD_ISSET(vfd, vp)) { continue; }

      /* Ensure that the file object is not deallocated while
       * we're inspecting it. */
      filp = File_GetUnlocked(vfd);
      /* The user may specify invalid vfds, or some vfds
       * may have been concurrently closed before we acquired
       * the files->lock. */
      if (filp) {
         ASSERT(filp->orig_rfd >= 0);
         if (FD_ISSET(filp->orig_rfd, rp)) { 
            DEBUG_MSG(5, "Setting vfd %d, corresponds to orig_rfd %d.\n", 
                  vfd, filp->orig_rfd);
            FD_SET(vfd, &__uv);
            (*count)++;
         }
         /* File_Put doesn't acquire the files lock, so it needn't
          * have an unlocked version. */
         File_Put(filp);
      } else {
         /* XXX: should we just ignore and continue instead? Since 
          * VirtToReal would've vetted the vfds already, 
          * being here can only mean that the file was
          * concurrently closed. */
         ASSERT_UNIMPLEMENTED(0);
         error = -EBADF;
         goto unlock_out;
      }
   }

   /* Careful: some apps (e.g., ssh) don't allocate an entire fd_set.
    * They allocate just enough to hold @n bits. */
   if (SelectSetFdSet(n, uvp, &__uv)) {
      error = -EFAULT;
      goto unlock_out;
   }

unlock_out:
   Files_Unlock(files);
out:
   return error;
}

static int
PollVirtToReal(struct pollfd *rfds, struct pollfd __user *ufds, uint nfds)
{
   int i, error = 0;
   struct FileStruct *filp;
   struct FilesStruct *files = current->files;

   ASSERT(ufds || !ufds);
   ASSERT(rfds);

   /* Use rfds are temporary storage for the ufds. We'll overwrite the ufds
    * with the corresponding rfds below. */
   if (Task_CopyFromUser(rfds, ufds, sizeof(struct pollfd)*nfds)) {
      error = -EFAULT;
      goto out;
   }

   Files_Lock(files);

   for (i = 0; i < nfds; i++) {
      int vfd = rfds[i].fd;

      /* Ensure that the file object is not deallocated while
       * we're inspecting it. */
      filp = File_GetUnlocked(vfd);

      /* The user may specify invalid vfds, or some vfds
       * may have been concurrently closed before we acquired
       * the files->lock. */
      if (filp) {
         ASSERT(filp->orig_rfd >= 0);

         DEBUG_MSG(5, "name=%s\n", Dentry_Name(File_Dentry(filp)));
         rfds[i].fd = filp->orig_rfd;

         /* File_Put doesn't acquire the files lock, so it needn't
          * have an unlocked version. */
         File_Put(filp);
      } else {
         error = -EBADF;
         goto unlock_out;
      }
   }

unlock_out:
   Files_Unlock(files);
out:
   return error;
}


/* Returns number of revents which have non-zero value. */
static int
PollRealToVirt(struct pollfd __user *ufds, struct pollfd *rfds, uint nfds)
{
   int i, nonzero = 0, error = 0;

   ASSERT(ufds || !ufds);
   ASSERT(rfds);
   ASSERT(nfds >= 0);

   /* Note that rfds[i] = FileObject(ufds[i])->rfd. Hence no scan of the
    * file table is required, and hence no locks need be acquired. */
   for (i = 0; i < nfds; i++) {
      /* Only revents were modified. */
      if (Task_CopyToUser(&ufds[i].revents, &rfds[i].revents, 
               sizeof(rfds[i].revents))) {
         error = -EFAULT;
         goto out;
      }

      if (rfds[i].revents) {
         nonzero++;
      }
   }

   error = nonzero;

out:
   return error;
}

static int
Linux_select(int res, const struct SyscallArgs *args)
{
   fd_set *inp = (fd_set*)args->ecx, *outp = (fd_set*)args->edx, 
          *exp = (fd_set*)args->esi;
   struct timespec *tsp = args->eax == SYS_pselect6 ? 
      (struct timespec *)args->edi : NULL;
   struct timeval *tvp = args->eax == SYS_select ? 
      (struct timeval *)args->edi : NULL;

   ASSERT(!(tsp && tvp));

   DEBUG_MSG(5, "eax=%d (%d) ebx=%d ecx=0x%x, edx=0x%x esi=0x%x edi=0x%x\n", 
         args->eax, SYS_select, args->ebx, args->ecx, args->edx ,args->esi,
         args->edi);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(sys_select) {
         entryp->ret = res;
         if (tsp) { entryp->ts = *tsp; }
         if (tvp) { entryp->tv = *tvp; }
         if (!SYSERR(res)) {
            if (inp) entryp->in = *inp;
            if (outp) entryp->out = *outp;
            if (exp) entryp->ex = *exp;
         }
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY(sys_select) {
         res = entryp->ret;
         if (tsp) { *tsp = entryp->ts; }
         if (tvp) { *tvp = entryp->tv; }
         if (!SYSERR(res)) {
            if (inp) *inp = entryp->in;
            if (outp) *outp = entryp->out;
            if (exp) *exp = entryp->ex;
         }
      } END_WITH_LOG_ENTRY(0);
   }

   return res;
}

static int
Linux_ppoll(int res, const struct SyscallArgs *args)
{
   struct pollfd *fds = (struct pollfd*)args->ebx;
   uint nfds = args->ecx;
   struct timespec *tsp = (struct timespec *)args->edx;
   uint i;

   size_t fdArraySz = nfds*sizeof(struct pollfd);

   ASSERT(fds);
   ASSERT(nfds >= 0);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY_DATA(sys_poll, fdArraySz) {
         entryp->ret = res;
         if (tsp) { entryp->ts = *tsp; }
         if (!SYSERR(res)) {
            struct pollfd *parray = (struct pollfd*) datap;
            for (i = 0; i < nfds; i++) {
               parray[i] = fds[i];
            }
         }
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY_DATA(sys_poll, fdArraySz) {
         res = entryp->ret;
         if (tsp) { *tsp = entryp->ts; }
         if (!SYSERR(res)) {
            struct pollfd *parray = (struct pollfd*) datap;
            for (i = 0; i < nfds; i++) {
               fds[i] = parray[i];
            }
         }
      } END_WITH_LOG_ENTRY(0);
   }

   return res;
}

int
Select_WaitLoop(struct SyscallArgs *args, SelectCallback cb)
{
   SyscallRet fdCount;
   int wasInterrupted, isSignalPending;

   do {

      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      fdCount = Sched_BlockingRealSyscall(NULL, args);
      DEBUG_MSG(5, "fdCount=%d\n", fdCount);

      fdCount = cb(fdCount, args);

      wasInterrupted = (fdCount == -EINTR);
      isSignalPending = Task_TestSigPending(current, 1);

      /* If we're interrupted by an internal signal, then
       * we need to try again. The fd_sets shouldn't be 
       * altered, however, so there is no need to reload
       * them. */

   } while (wasInterrupted && !isSignalPending);

   if (fdCount <= 0 && isSignalPending) {
      if (fdCount == 0) {
         /* Sleep time out. */
      } else {
         /* Interrupted by IPI. */
         ASSERT(fdCount == -EINTR);
      }

      /* We want sys_select to be automatically restarted if there is no
       * handler for the signal that interrupted us. */
      fdCount = -ERESTARTNOHAND;
   } else {
      /* If some fds changed state, then we must report it even if we
       * have a pending signal. This is Linux behavior, so we must 
       * emulate it. */
      ASSERT(isSignalPending || !isSignalPending);
   }

   DEBUG_MSG(5, "out fdCount=%d\n", fdCount);
   ASSERT_MSG(fdCount == -ERESTARTNOHAND || fdCount >= 0,
         "fdCount=%d\n", fdCount);
   return fdCount;
}

static int
PselectDo(int n, fd_set __user *inp, fd_set __user *outp, 
          fd_set __user *exp, struct timespec __user *tsp, 
          struct timeval __user *tvp, sigset_t *ksigmaskp, 
          UNUSED size_t sigsetsize)
{
	int error;
   fd_set rin, rout, rex;
   fd_set vin, vout, vex;
   struct SyscallArgs args;
   sigset_t sigsaved;
   int maxin = 0, maxout = 0, maxex = 0;

   struct timespec __ts;
   struct timeval __tv;

   ASSERT(!(tvp && tsp));

   if (tsp) {
      if (Task_CopyFromUser(&__ts, tsp, sizeof(*tsp))) {
         return -EFAULT;
      }
   } else if (tvp) {
      if (Task_CopyFromUser(&__tv, tvp, sizeof(*tvp))) {
         return -EFAULT;
      }

      DEBUG_MSG(5, "sec=%ld usec=%ld\n", __tv.tv_sec, __tv.tv_usec);
   } 


   if ((error = SelectVirtToReal(n, &rin, inp, &vin, &maxin))) 
      { goto out; }
   if ((error = SelectVirtToReal(n, &rout, outp, &vout, &maxout))) 
      { goto out; }
   if ((error = SelectVirtToReal(n, &rex, exp, &vex, &maxex))) 
      { goto out; }

   if (ksigmaskp) {
      SigOps_DelSetMask(ksigmaskp, sigmask(SIGKILL)|sigmask(SIGSTOP));
      Signal_SigProcMask(SIG_SETMASK, ksigmaskp, &sigsaved);
   }


   /* Pselect is not avaialable on pre 2.6.16 kernels. Hence we do not
    * emulate select with pselect in order to retain compatibility. */
   args.eax = tvp ? SYS_select : SYS_pselect6;
   args.ebx = MAX(MAX(maxin, maxout), maxex) + 1;
   DEBUG_MSG(5, "maxin=%d maxout=%d maxex=%d ebx=%d\n", maxin, maxout, 
         maxex, args.ebx);
   args.ecx = (ulong) (inp ? &rin : NULL);
   args.edx = (ulong) (outp ? &rout : NULL);
   args.esi = (ulong) (exp ? &rex : NULL);
   if (tvp) {
      args.edi = (ulong) &__tv;
   } else if (tsp) {
      args.edi = (ulong) &__ts;
   } else {
      args.edi = 0;
   }
   /* This is the signal mask. It isn't used by SYS_select, but is by 
    * SYS_pselect. */
   /* We emulate the signal masking within the vkernel, so no need
    * to ask Linux to do it. */
   args.ebp = 0;


   error = Select_WaitLoop(&args, &Linux_select);

   if (error >= 0) {
      int count = 0;

      D__;

      /* Convert from real to virtual and copy to userspace. */
      if ((error = SelectRealToVirt(n, inp, &rin, &vin, &count))) 
         { goto out; }
      if ((error = SelectRealToVirt(n, outp, &rout, &vout, &count))) 
         { goto out; }
      if ((error = SelectRealToVirt(n, exp, &rex, &vex, &count))) 
         { goto out; }

      error = count;

      if (error == 0) {
         /* Timed out before any fds were ready. */

         /* Must still call SelectRealToVirt to zero-out user-space
          * fdsets. */
      }
   } else {
      D__;
      ASSERT(error == -ERESTARTNOHAND);
   }


   if (tsp || tvp) {
      int failure = 0;

      D__;

      if (current->personality & STICKY_TIMEOUTS) {
         goto sticky;
      }

      /* Note that, without the STICKY_TIMEOUTS persona, we write the timeout 
       * to userspace regardless of whether the select succeeded on not. 
       * This emulates the Linux select, which writes the timeval 
       * regardless of success or failure. */
      ASSERT(SYSERR(error) || !SYSERR(error));

      if (tsp) {
         D__;
         failure = Task_CopyToUser(tsp, &__ts, sizeof(__ts));
      } else if (tvp) {
         D__;
         failure = Task_CopyToUser(tvp, &__tv, sizeof(__tv));
      } 

      if (failure) {
sticky:
         /*
			 * If an application puts its timeval in read-only
			 * memory, we don't want the Linux-specific update to
			 * the timeval to cause a fault after the select has
			 * completed successfully. However, because we're not
			 * updating the timeval, we can't restart the system
			 * call.
			 */
         if (error == -ERESTARTNOHAND) {
            error = -EINTR;
         }
      }
   }

   if (error == -ERESTARTNOHAND) {
      /*
       * Don't restore the signal mask yet. Let do_signal() deliver
       * the signal on the way back to userspace, before the signal
       * mask is restored.
       */
      if (ksigmaskp) {
         memcpy(&current->savedSigmask, &sigsaved,
               sizeof(sigsaved));
         Task_SetCurrentFlag(TIF_RESTORE_SIGMASK);
      }
   } else if (ksigmaskp) {
      Signal_SigProcMask(SIG_SETMASK, &sigsaved, NULL);
   }

out:
   DEBUG_MSG(5, "error=%d\n", error);
   return error;
}


SYSCALLDEF(sys_pselect6, int n, fd_set __user *inp, fd_set __user *outp,
	fd_set __user *exp, struct timespec __user *tsp, void __user *sig)
{
	size_t sigsetsize = 0;
	sigset_t __user *sigmaskp = NULL;
	sigset_t ksigmask, *ksigmaskp = NULL;

	if (sig) {
		if (!UserMem_CheckProt((ulong)sig, sizeof(void *)+sizeof(size_t), 
               VERIFY_READ)
		    || __get_user(sigmaskp, (sigset_t __user * __user *)sig)
		    || __get_user(sigsetsize,
				(size_t __user *)(sig+sizeof(void *))))
			return -EFAULT;
	}

   if (sigmaskp) {
      if (sigsetsize != sizeof(sigset_t))
         return -EINVAL;
      if (Task_CopyFromUser(&ksigmask, sigmaskp, sizeof(ksigmask)))
         return -EFAULT;

      ksigmaskp = &ksigmask;
   }

   return PselectDo(n, inp, outp, exp, tsp, NULL, ksigmaskp, sigsetsize);
}

SYSCALLDEF(sys_select, int n, fd_set __user *inp, fd_set __user *outp,
			  fd_set __user *exp, struct timeval __user *tvp)
{
   D__;
   return PselectDo(n, inp, outp, exp, NULL, tvp, NULL, 0);
}

struct sel_arg_struct {
	unsigned long n;
	fd_set __user *inp, *outp, *exp;
	struct timeval __user *tvp;
};

SYSCALLDEF(sys_old_select, struct sel_arg_struct __user *arg)
{
	struct sel_arg_struct a;

	if (Task_CopyFromUser(&a, arg, sizeof(a)))
		return -EFAULT;

	return sys_select(a.n, a.inp, a.outp, a.exp, a.tvp);
}


static int
PollDo(struct pollfd __user *ufds, uint nfds, struct timespec __user *tsp, 
       long timeout_ms, sigset_t *ksigmaskp, UNUSED size_t sigsetsize)
{
   int error;
   struct SyscallArgs args;
   struct timespec __ts, *timeout = tsp;
   struct timespec msts;
   size_t rfdSize = sizeof(struct pollfd) * nfds;
   sigset_t sigsaved;

   struct pollfd *rfds = SharedArea_Malloc(rfdSize);

   ASSERT(!(tsp && timeout_ms));

   if (tsp) {
      if (Task_CopyFromUser(&__ts, tsp, sizeof(*tsp))) {
         error = -EFAULT;
         goto out;
      }

      timeout = &__ts;
   } else if (timeout_ms >= 0) {
      msts.tv_sec = timeout_ms / 1000;
      msts.tv_nsec = (timeout_ms % 1000) * 1000000;

      timeout = &msts;
   }

   if (timeout_ms < 0) {
      ASSERT(!timeout);
   }

   if ((error = PollVirtToReal(rfds, ufds, nfds))) {
      goto out;
   }

   if (ksigmaskp) {
      SigOps_DelSetMask(ksigmaskp, sigmask(SIGKILL)|sigmask(SIGSTOP));
      Signal_SigProcMask(SIG_SETMASK, ksigmaskp, &sigsaved);
   }

   args.eax = SYS_ppoll;
   args.ebx = (ulong)rfds;
   args.ecx = (ulong)nfds;
   args.edx = (ulong)timeout;
   args.esi = 0; /* sigmask */
   args.edi = 0; /* sigsetsize */

   error = Select_WaitLoop(&args, &Linux_ppoll);

   if (error >= 0) {
      /* Must zero-out revents on timeout (error == 0). */

      int nonzero;
      if ((nonzero = PollRealToVirt(ufds, rfds, nfds))) {
         error = nonzero;
         goto out;
      }

      /* Unlike select, the return value of sys_(p)poll is
       * the number of vfds on which an event occurred. */
      ASSERT(nonzero == error);

      if (error == 0) {
         /* Timed out before any fds were ready. */
         ASSERT(nonzero == 0);
      }
   } else {
      /* Interrupted by signal. */
      ASSERT(error == -ERESTARTNOHAND);
   }

   if (tsp) {
      if (current->personality & STICKY_TIMEOUTS) {
         goto sticky;
      }

      /* Note that, without the STICKY_TIMEOUTS persona, we write the timeout 
       * to userspace regardless of whether the select succeeded on not. 
       * This emulates the Linux select, which writes the timeval regardless of 
       * success or failure. */
      ASSERT(SYSERR(error) || !SYSERR(error));

      if (Task_CopyToUser(tsp, &__ts, sizeof(__ts))) {
sticky:
         /*
          * If an application puts its timeval in read-only
          * memory, we don't want the Linux-specific update to
          * the timeval to cause a fault after the select has
          * completed successfully. However, because we're not
          * updating the timeval, we can't restart the system
          * call.
          */
         if (error == -ERESTARTNOHAND) {
            error = -EINTR;
         }
      }
   }

   if (error == -ERESTARTNOHAND) {
      /*
       * Don't restore the signal mask yet. Let do_signal() deliver
       * the signal on the way back to userspace, before the signal
       * mask is restored.
       */
      if (ksigmaskp) {
         memcpy(&current->savedSigmask, &sigsaved,
               sizeof(sigsaved));
         Task_SetCurrentFlag(TIF_RESTORE_SIGMASK);
      }
   } else if (ksigmaskp) {
      Signal_SigProcMask(SIG_SETMASK, &sigsaved, NULL);
   }

out:
   SharedArea_Free(rfds, rfdSize);
   return error;
}

SYSCALLDEF(sys_ppoll, struct pollfd __user *ufds, unsigned int nfds,
      struct timespec __user *tsp, const sigset_t __user *sigmaskp,
      size_t sigsetsize)
{
   SyscallRet ret;
   sigset_t ksigmask, *ksigmaskp = NULL;

   if (sigmaskp) {
      if (sigsetsize != sizeof(sigset_t))
         return -EINVAL;
      if (Task_CopyFromUser(&ksigmask, sigmaskp, sizeof(ksigmask)))
         return -EFAULT;

      ksigmaskp = &ksigmask;
   }

   ret = PollDo(ufds, nfds, tsp, 0, ksigmaskp, sigsetsize);

   return ret;
}

SYSCALLDEF(sys_poll, struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs)
{
   /* If timeout_msecs < 0, then block indefinitely. */
   return PollDo(ufds, nfds, NULL, timeout_msecs, NULL, 0);
}
