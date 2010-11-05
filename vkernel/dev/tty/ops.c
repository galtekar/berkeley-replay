#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include "vkernel/public.h"
#include "private.h"

/*
 * XXX:
 *    o make sure input ioctl args are copied into vkernel first
 *    o return efault if copy_user goes wrong in ioctls
 */

/* Inode ops. */

/* File and directory operations. */

static long
RdTty_lstat(struct DentryStruct *dentryp, struct kstat64 *statp)
{
   int err;

   err = ReadDet_lstat(dentryp->name, statp);

   return err;
}

static long
RdTty_access(struct DentryStruct *dentryp, int mode)
{
   return ReadDet_access(Dentry_Name(dentryp), mode);
}

/* Directory operations. */


/* File ops. */

static void
RdTty_release(struct FileStruct *filp)
{
   int err;

   ASSERT(filp->rfd >= 0);
   err = SysOps_Close(filp->rfd);
   if (err) {
      DEBUG_MSG(5, "err=%d\n", err);
   }
   ASSERT(!err);
}

/* XXX: Explain why we store the rfd in the filp -- so we don't
 * have to emulate asynch notif and non-blocking comm. */
static int
RdTty_open(struct FileStruct *filp, int mode)
{
   int err;
   struct DentryStruct *dentryp = filp->dentry;

   /* XXX: would this every block?---opening disk files or pipes could
    * block---if so we need to make a sched call here. */
   filp->orig_rfd = err = ReadDet_open(dentryp->name, filp->flags, mode);

   if (VCPU_IsReplaying()) {
      /* XXX: this doesn't work when done over an ssh connection */
      filp->rfd = syscall(SYS_open, dentryp->name, filp->flags, mode);
#if DEBUG
      if (!SYSERR(err)) {
         ASSERT_MSG(!SYSERR(filp->rfd), "tty_name=%s rep_err=%d", 
               dentryp->name, filp->rfd);
      }
#endif
   } else {
      filp->rfd = filp->orig_rfd;
   }

   return err;
}

static SyscallRet
tcgets(uint fd, uint cmd, struct termios __user* arg)
{
   int err;
   struct termios tios;

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = Task_GetCurrentRegs()->R(eax);
      args.ebx = fd;
      args.ecx = cmd;
      args.edx = (ulong)&tios;
      err = Task_RealSyscall(&args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(SysIoctl_tcgets) {
            entryp->ret = err;
            entryp->tios = tios;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(SysIoctl_tcgets) {
         err = entryp->ret;
         tios = entryp->tios;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!err && Task_CopyToUser(arg, &tios, sizeof(tios))) {
      err = -EFAULT;
      goto out;
   }

out:
   return err;
}

static SyscallRet
tiocgpgrp(uint fd, uint cmd, pid_t __user *p)
{
   int err;
   pid_t __pid;

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = Task_GetCurrentRegs()->R(eax);
      args.ebx = fd;
      args.ecx = cmd;
      args.edx = (ulong)&__pid;
      err = Task_RealSyscall(&args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(SysIoctl_tiocgpgrp) {
            entryp->ret = err;
            entryp->pid = __pid;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(SysIoctl_tiocgpgrp) {
         err = entryp->ret;
         __pid = entryp->pid;
      } END_WITH_LOG_ENTRY(0);
   }


   if (!err && Task_CopyToUser(p, &__pid, sizeof(__pid))) {
      err = -EFAULT;
      goto out;
   }

out:
   return err;
}

static SyscallRet
tiocspgrp(uint fd, uint cmd, pid_t __user *p)
{
   int err;
   pid_t __pid;

   if (Task_CopyFromUser(&__pid, p, sizeof(__pid))) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = Task_GetCurrentRegs()->R(eax);
      args.ebx = fd;
      args.ecx = cmd;
      args.edx = (ulong)&__pid;
      err = Task_RealSyscall(&args);

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

out:
   return err;
}

static SyscallRet
tiocgwinsz(uint fd, uint cmd, struct winsize __user * arg)
{
   int err;
   struct winsize __winsz;

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = Task_GetCurrentRegs()->R(eax);
      args.ebx = fd;
      args.ecx = cmd;
      args.edx = (ulong)&__winsz;
      err = Task_RealSyscall(&args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(SysIoctl_tiocgwinsz) {
            entryp->ret = err;
            entryp->winsz = __winsz;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(SysIoctl_tiocgwinsz) {
         err = entryp->ret;
         __winsz = entryp->winsz;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!err && Task_CopyToUser(arg, &__winsz, sizeof(__winsz))) {
      err = -EFAULT;
      goto out;
   }

out:
   return err;
}

static SyscallRet
tiocswinsz(uint fd, uint cmd, struct winsize __user * arg)
{
   int err;
   struct winsize __winsz;

   if (Task_CopyFromUser(&__winsz, arg, sizeof(__winsz))) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = Task_GetCurrentRegs()->R(eax);
      args.ebx = fd;
      args.ecx = cmd;
      args.edx = (ulong)&__winsz;
      err = Task_RealSyscall(&args);

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

out:
   return err;
}

static SyscallRet
tioclinux(uint fd, uint cmd, char __user * arg)
{
   int err;
   char type;

   if (Task_CopyFromUser(&type, arg, sizeof(type))) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = Task_GetCurrentRegs()->R(eax);
      args.ebx = fd;
      args.ecx = cmd;
      args.edx = (ulong)arg;
      err = Task_RealSyscall(&args);

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

out:
   return err;
}


static SyscallRet
tiosettoval(uint fd, uint cmd, void __user * arg)
{
   int err;

#if PRODUCT
#error "XXX"
#else
   /* XXX: copy in the arg for formgen -- but size depends on cmd.
    * This will take some work. */
   WARN_XXX(0);
#endif

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_ioctl, fd, cmd, (ulong)arg);

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

static SyscallRet
tcxonc(uint fd, uint cmd, void __user * arg)
{
   int err;
   ulong karg;

   if (Task_CopyFromUser(&karg, arg, sizeof(karg))) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = Task_GetCurrentRegs()->R(eax);
      args.ebx = fd;
      args.ecx = cmd;
      args.edx = (ulong)&karg;
      err = Task_RealSyscall(&args);

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

out:
   return err;
}

static SyscallRet
tcflsh(uint fd, uint cmd, void __user * arg)
{
   int err;
   ulong karg;

   if (Task_CopyFromUser(&karg, arg, sizeof(karg))) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_ioctl, fd, cmd, &karg);

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

out:
   return err;
}

static SyscallRet
tioint(uint fd, uint cmd, uint __user *p)
{
   int err, kval;

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_ioctl, fd, cmd, (ulong) &kval);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_ioctl_int) {
            entryp->ret = err;
            entryp->val = kval;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_ioctl_int) {
         err = entryp->ret;
         kval = entryp->val;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!err && Task_CopyToUser(p, &kval, sizeof(kval))) {
      err = -EFAULT;
      goto out;
   }
out:
   return err;
}

static int
RdTtyIoctl(struct FileStruct *filp, uint cmd, ulong arg)
{
   int ret = 0, fd;

   fd = filp->rfd;

   DEBUG_MSG(5, "file=0x%x rfd=%d cmd=0x%x arg=0x%x\n", filp, fd, cmd, arg);

   /* We don't call through to the Linux syscall during replay,
    * so fd need not be valid during replay. */
   if (!VCPU_IsReplaying()) {
      ASSERT(fd >= 0);
   }


   switch (cmd) {
   case TCGETS:
      ret = tcgets(fd, cmd, (struct termios __user *)arg);
      break;
   case TCSETSF:
   case TCSETSW:
   case TCSETS:
   case TCSETAF:
   case TCSETAW:
   case TCSETA:
      ret = tiosettoval(fd, cmd, (void __user *)arg);
      break;
   case TIOCGPGRP:
      ret = tiocgpgrp(fd, cmd, (pid_t __user *)arg);
      break;
   case TIOCSPGRP:
      ret = tiocspgrp(fd, cmd, (pid_t __user *)arg);
      break;
   case TIOCGWINSZ:
      ret = tiocgwinsz(fd, cmd, (struct winsize __user *)arg);
      break;
   case TIOCSWINSZ:
      ret = tiocswinsz(fd, cmd, (struct winsize __user *)arg);
      break;
   case TIOCLINUX:
      ret = tioclinux(fd, cmd, (char __user *) arg);
      break;
   case TCXONC:
      ret = tcxonc(fd, cmd, (struct winsize __user *)arg);
      break;
   case TCFLSH:
      ret = tcflsh(fd, cmd, (void __user *) arg);
      break;
   case TIOCGPTN:
      ret = tioint(fd, cmd, (uint __user *) arg);
      break;
   case TIOCSPTLCK:
      ret = tiosettoval(fd, cmd, (void __user*) arg);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   return ret;
}


static int
RdTty_ioctl(struct FileStruct *filp, uint cmd, ulong arg)
{
   int err = 0;

   err = RdTtyIoctl(filp, cmd, arg);

   return err;
}

static ssize_t
RdTty_io(
      const int ioReqFlags, 
      const struct FileStruct *filp, 
      struct msghdr *kmsgp, 
      const int flags UNUSED, 
      loff_t pos)
{
   ssize_t err;

   ASSERT(filp->rfd >= 0);
   ASSERT(kmsgp);

   err = ReadDet_io(ioReqFlags, filp, filp->rfd, kmsgp, 0, 0, pos);

#if DEBUG
   if (err > 0) {
      const uint MAXSTR = 256;
      char str[MAXSTR];
      int dlen = kmsgp->msg_iov[0].iov_len;
      int slen = MIN(MAXSTR-1, dlen);
      memcpy(str, kmsgp->msg_iov[0].iov_base, slen);
      str[slen] = 0;

      DEBUG_MSG(5, "data_str=%s ...\n", str);
   }
#endif

   /* User probably wants to see the original output
    * on the tty during replay. */
   if (session.opt_tty_replay && !(ioReqFlags & IOREQ_READ) && VCPU_IsReplaying() && !SYSERR(err)) {
      int sysres;
      ulong newVecLen;
      struct iovec *newVec;
      ulong newVecSz = sizeof(struct iovec) * kmsgp->msg_iovlen;

      /* Print out only as much as was printed in log-mode. */
      newVec = SharedArea_Malloc(newVecSz);
      Iov_FirstNbytes(kmsgp->msg_iov, kmsgp->msg_iovlen, newVec, 
            &newVecLen, err);

      sysres = syscall(SYS_writev, filp->rfd, newVec, newVecLen);

#if DEBUG
      if (sysres != err) {
         /* XXX: is it possible that not all requested bytes were 
          * written out? We may be interrupted by a replay-mode signal... */
         DEBUG_MSG(5, "msg_iovlen=%d rfd=%d newVecLen=%d sysres=%d err=%d\n", 
               kmsgp->msg_iovlen, filp->rfd, newVecLen, sysres, err);
         ASSERT_UNIMPLEMENTED(0);
      }
#endif
      SharedArea_Free(newVec, newVecSz);
   }

   /* See resolution of BUG #5 for why -ERESTARTSYS is needed here. */
   return err == -EINTR ? -ERESTARTSYS : err;
}

static int
RdTty_fsync(struct FileStruct *filp, int datasync)
{
   return ReadDet_fsync(filp->rfd, datasync);
}

static int
RdTty_setfl(struct FileStruct *filp, int flags)
{
   return ReadDet_setfl(filp->rfd, flags);
}

static long
RdTty_fstat(struct FileStruct *filp, struct kstat64 *statp)
{
   return ReadDet_fstat(filp->rfd, statp);
}

const struct FileOps RdTty_Fops = {
   .open =        &RdTty_open,
   .release =     &RdTty_release,
   .llseek =      &no_llseek,
   .io =          &RdTty_io,
   .ioctl =       &RdTty_ioctl,
   .fsync =       &RdTty_fsync,
   .setfl =       &RdTty_setfl,
   .fstat =       &RdTty_fstat,
   .select =      &Select_DefaultUntaggedFop,
};

const struct InodeOps RdTty_Iops = {
   .lstat =        &RdTty_lstat,
   .access =       &RdTty_access,
};
