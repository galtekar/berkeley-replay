#include <stdio.h>
#include <assert.h>
#include <sys/mman.h>
#include <limits.h>
#include <unistd.h>
#include <elf.h>

#include "vkernel/public.h"
#include "private.h"


SYSCALLDEF(sys_default, struct SyscallArgs args)
{
	int ret;
   const int sysno = args.eax;

   ASSERT(0 <= sysno && sysno < NR_SYSCALLS);

   WARN_UNIMPLEMENTED_MSG(0, "unimplemented sysno %d (%s)", sysno,
         get_syscall_name(sysno));

   ret = Task_RealSyscall(&args);

   return ret;
}

SYSCALLDEF(sys_deprecated, struct SyscallArgs args)
{
   int ret;
   const int sysno = args.eax;

   ASSERT(0 <= sysno && sysno < NR_SYSCALLS);

   ASSERT_UNIMPLEMENTED_MSG(0, "sysno=%s (%d)\n", 
         get_syscall_name(sysno), sysno);

   ret = Task_RealSyscall(&args);

   return ret;
}

SYSCALLDEF(sys_sysinfo, struct sysinfo __user *info)
{
   SyscallRet ret;
   struct sysinfo kinfo;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_sysinfo, &kinfo);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_sysinfo) {
            entryp->ret = ret;
            entryp->info = kinfo;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_sysinfo) {
         ret = entryp->ret;
         kinfo = entryp->info;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!SYSERR(ret) && Task_CopyToUser(info, &kinfo, sizeof(*info))) {
      ret = -EFAULT;
      goto out;
   }

out:
   return ret;
}

SYSCALLDEF(sys_newuname, struct new_utsname __user *name)
{
   SyscallRet ret;
   struct new_utsname localName;
   struct SyscallArgs args;
   TaskRegs *regs = Task_GetCurrentRegs();

   args.eax = regs->R(eax);
   args.ebx = (ulong)&localName;

   if (!VCPU_IsReplaying()) {
      ret = Task_RealSyscall(&args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(SysNewuname) {
            entryp->ret = ret;
            if (!ret) {
               memcpy(&entryp->name, &localName, sizeof(localName));
            }
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
         DO_WITH_LOG_ENTRY(SysNewuname) {
            ret = entryp->ret;
            D__;
            if (!ret) {
               D__;
               memcpy(&localName, &entryp->name, sizeof(localName));
            }
         } END_WITH_LOG_ENTRY(0);
   }

   DEBUG_MSG(5, "%s %s %s %s %s\n",
         localName.sysname, localName.nodename, localName.release,
         localName.version, localName.machine);

   if (ret == 0 && Task_CopyToUser(name, &localName, sizeof(localName))) {
      ret = -EFAULT;
      goto out;
   }

out:
   return ret;
}

SYSCALLDEF(sys_getrlimit, uint resource, struct rlimit __user *rlim)
{
   SyscallRet ret;
   struct rlimit __rlim;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_ugetrlimit, resource, &__rlim);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(SysGetrlimit) {
            entryp->ret = ret;
            entryp->rlim = __rlim;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(SysGetrlimit) {
         ret = entryp->ret;
         __rlim = entryp->rlim;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!SYSERR(ret) && Task_CopyToUser(rlim, &__rlim, sizeof(__rlim))) {
      ret = -EFAULT;
      goto out;
   }

out:
   return ret;
}

SYSCALLDEF(sys_setrlimit, uint resource, struct rlimit __user *rlim)
{
   int err;
   struct rlimit krlim;

   if (Task_CopyFromUser(&krlim, rlim, sizeof(krlim))) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_setrlimit, resource, &krlim);

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

SYSCALLDEF(sys_getrusage, int who, struct rusage __user *ru)
{
   int err;
   struct rusage kru;

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_getrusage, who, &kru);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(SysGetrusage) {
            entryp->ret = err;
            entryp->rusage = kru;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(SysGetrusage) {
         err = entryp->ret;
         kru = entryp->rusage;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!err && Task_CopyToUser(ru, &kru, sizeof(kru))) {
      err = -EFAULT;
      goto out;
   }

out:
   return err;
}

static int
SysGetNumGroups(int gidsetsize, kgid_t *kgroups)
{
   int ngroups;
   size_t bytes;

   if (!VCPU_IsReplaying()) {
      ngroups = syscall(SYS_getgroups32, gidsetsize, kgroups);
      ASSERT(ngroups >= 0);

      DEBUG_MSG(5, "ngroups=%d\n", ngroups);

      if (VCPU_IsLogging()) {
         bytes = (ngroups > 0 && kgroups) ? sizeof(kgid_t)*ngroups : 0;

#if DEBUG
         DEBUG_MSG(5, "bytes=%d\n", bytes);
         if (kgroups) {
            int i;
            for (i = 0; i < ngroups; i++) {
               DEBUG_MSG(5, "%lu\n", kgroups[i]);
            }
         }
#endif
         DO_WITH_LOG_ENTRY_DATA(JustRetval, bytes) {
            entryp->ret = ngroups;
            if (bytes) {
               memcpy(datap, (void*) kgroups, bytes);
            }
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ngroups = entryp->ret;
         ASSERT(ngroups >= 0);

         bytes = (ngroups > 0 && kgroups) ? sizeof(kgid_t)*ngroups : 0;

         if (bytes) {
            memcpy((void*)kgroups, datap, bytes);
         }
      } END_WITH_LOG_ENTRY(bytes);
   }

   return ngroups;
}

/* export the group_info to a user-space array */
static int 
groups_to_user(kgid_t __user *grouplist, kgid_t *kgroups, int ngroups)
{
   ASSERT(ngroups >= 0);

   if (Task_CopyToUser(grouplist, kgroups, sizeof(kgid_t)*ngroups))
      return -EFAULT;

	return 0;
}

SYSCALLDEF(sys_getgroups, int gidsetsize, kgid_t __user *grouplist)
{
   int err, ngroups;
   kgid_t *kgroups;
   size_t kgsz;

   if (gidsetsize < 0) {
      err = -EINVAL;
      goto out;
   }

   err = SysGetNumGroups(0, NULL);
   ASSERT(err >= 0);
   if (err == 0) {
      goto out;
   }

   if (!gidsetsize) {
      goto out;
   }

   ngroups = err;

   /* Don't allocate gidsetsize elements, since that comes from
    * userland and could be a large, potentially bogus value. 
    * Hence the two calls to SysGetNumGroups. */
   kgsz = sizeof(kgid_t) * ngroups;
   kgroups = SharedArea_Malloc(kgsz);

   err = SysGetNumGroups(ngroups, kgroups);
   ASSERT(err == ngroups);

   if (ngroups > gidsetsize) {
      err = -EINVAL;
      goto out_free;
   }

   if (groups_to_user(grouplist, kgroups, ngroups)) {
      err = -EFAULT;
      goto out_free;
   }

   ASSERT(err == ngroups);

out_free:
   ASSERT(kgsz);
   SharedArea_Free(kgroups, kgsz);
out:
   return err;
}

#define KNGROUPS_MAX    65536	/* supplemental group IDs are available */
SYSCALLDEF(sys_setgroups, int gidsetsize, kgid_t __user *grouplist)
{
   int err;
   kgid_t *kgroups = NULL;
   size_t kgsz = 0;

   if ((unsigned)gidsetsize > KNGROUPS_MAX) {
      err = -EFAULT;
      goto out;
   }

   kgsz = sizeof(kgid_t) * gidsetsize;
   ASSERT(kgsz >= 0);
   ASSERT_COULDBE(kgsz == 0); // sshd does this, for example
   if (kgsz) {
      kgroups = SharedArea_Malloc(kgsz);
      if (!kgroups) {
         err = -ENOMEM;
         goto out;
      }

      err = Task_CopyFromUser(kgroups, grouplist, kgsz);
      if (err) {
         err = -EFAULT;
         goto free_out;
      }
   }

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_setgroups32, gidsetsize, kgroups);

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

free_out:
   if (kgroups) {
      ASSERT(kgsz);
      SharedArea_Free(kgroups, kgsz);
   }
out:
   return err;
}

SYSCALLDEF(sys_getpriority, int which, int who)
{
   int err;

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_getpriority, which, who);

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

SYSCALLDEF(sys_setpriority, int which, int who, int niceval)
{
   int err;

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_setpriority, which, who, niceval);

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

static int
SysSetName(int isDomainName, char __user *name, int len)
{
   int err;
   char kname[__NEW_UTS_LEN];

   if (len < 0 || len > __NEW_UTS_LEN) {
      err = -EINVAL;
      goto out;
   }

   if (Task_CopyFromUser(kname, name, len)) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      err = syscall(isDomainName ? SYS_setdomainname : SYS_sethostname, 
                  kname, len);

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

SYSCALLDEF(sys_sethostname, char __user *name, int len)
{
   return SysSetName(0, name, len);
}

SYSCALLDEF(sys_setdomainname, char __user *name, int len)
{
   return SysSetName(1, name, len);
}


long
sys_times(struct tms __user * ubuf)
{
   int err;
   struct tms kbuf;

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_times, &kbuf);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_times) {
            entryp->ret = err;
            entryp->buf = kbuf;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_times) {
         err = entryp->ret;
         kbuf = entryp->buf;
      } END_WITH_LOG_ENTRY(0);
   }

   if (ubuf) {
      if (Task_CopyToUser(ubuf, &kbuf, sizeof(*ubuf)))
         return -EFAULT;
   }

   return err;
}
