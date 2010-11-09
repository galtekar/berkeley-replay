#include "vkernel/public.h"

long
ReadDet_stat(const char *path, struct kstat64 *statp)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_stat64, path, statp);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_stat64) {
            entryp->ret = ret;
            entryp->stat = *statp;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_stat64) {
         ret = entryp->ret;
         *statp = entryp->stat;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

long
ReadDet_lstat(const char *path, struct kstat64 *statp)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_lstat64, path, statp);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_stat64) {
            entryp->ret = ret;
            entryp->stat = *statp;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_stat64) {
         ret = entryp->ret;
         *statp = entryp->stat;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

long
ReadDet_fstat(int fd, struct kstat64 *statp)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_fstat64, fd, statp);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_stat64) {
            entryp->ret = ret;
            entryp->stat = *statp;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_stat64) {
         ret = entryp->ret;
         *statp = entryp->stat;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

long
ReadDet_statfs(const char *path, struct statfs64 *statp)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = SYS_statfs64;
      args.ebx = (ulong)path;
      args.ecx = sizeof(*statp);
      args.edx = (ulong)statp;
      ret = Task_RealSyscall(&args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_statfs64) {
            entryp->ret = ret;
            entryp->stat = *statp;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_statfs64) {
         ret = entryp->ret;
         *statp = entryp->stat;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

int
ReadDet_readlink(const char *path, char *buf, int bufsize)
{
   int err;

   DEBUG_MSG(5, "path=%s bufsize=%d\n", path, bufsize);

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_readlink, path, buf, bufsize);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_readlink) {
            entryp->ret = err;
            if (err >= 0) {

               ASSERT(err <= bufsize);

               /* Doesn't null-terminate output string, so must
                * copy by length. */
               memcpy(entryp->link, buf, err);
            }
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_readlink) {
         err = entryp->ret;

         if (err >= 0) {
            memcpy(buf, entryp->link, err);
         }
      } END_WITH_LOG_ENTRY(0);
   }

   return err;
}

int  
ReadDet_lgetxattr(const char *path, char *kname, void *kvalue, 
                  size_t size)
{
   SyscallRet ret;
   int sysno = SYS_lgetxattr;


   if (!VCPU_IsReplaying()) {

      ret = syscall(sysno, path, kname, kvalue, size);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_getxattr) {
            entryp->ret = ret;
            memcpy(entryp->value, kvalue, size);
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_getxattr) {
         ret = entryp->ret;
         memcpy(kvalue, entryp->value, size);
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

int 
ReadDet_lsetxattr(const char *path, char *kname, void *kvalue, size_t size, 
                 int flags)
{
   SyscallRet ret;
   int sysno = SYS_lsetxattr;


   if (!VCPU_IsReplaying()) {

      ret = syscall(sysno, path, kname, kvalue, size, flags);

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
ReadDet_llistxattr(const char *path, char *klist, size_t size)
{
   SyscallRet ret;
   int sysno = SYS_llistxattr;


   if (!VCPU_IsReplaying()) {

      ret = syscall(sysno, path, klist, size);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY_DATA(JustRetval, SYSERR(ret) ? 0 : size) {
            entryp->ret = ret;
            if (!SYSERR(ret)) {
               memcpy(datap, klist, size);
            }
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
         if (!SYSERR(ret)) {
            memcpy(klist, datap, size);
         }
      } END_WITH_LOG_ENTRY(SYSERR(ret) ? 0 : size);
   }

   return ret;
}

int
ReadDet_lremovexattr(const char *path, char *kname)
{
   SyscallRet ret;
   int sysno = SYS_lremovexattr;


   if (!VCPU_IsReplaying()) {

      ret = syscall(sysno, path, kname);

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
ReadDet_chmod(const char *path, mode_t mode)
{
   SyscallRet ret;


   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_chmod, path, mode);

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
ReadDet_lchown(const char *path, uid_t uid, gid_t gid)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_lchown32, path, uid, gid);

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
ReadDet_access(const char *path, int mode)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_access, path, mode);

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
ReadDet_link(const char *path1, const char *path2, int flags)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_link, path1, path2, flags);

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
ReadDet_rename(const char *path1, const char *path2)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_rename, path1, path2);

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
ReadDet_symlink(const char *path1, const char *path2)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_symlink, path1, path2);

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
ReadDet_unlink(const char *path)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_unlink, path);

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
ReadDet_mkdir(const char *path, int mode)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_mkdir, path, mode);

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
ReadDet_rmdir(const char *path)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_rmdir, path);

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
ReadDet_mknod(const char *path, int mode, unsigned dev)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_mknod, path, mode, dev);

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
ReadDet_utimes(const char *path, struct timeval *ktimes)
{
   SyscallRet ret;

   ASSERT(ktimes || !ktimes);

   if (!VCPU_IsReplaying()) {

      ret = syscall(SYS_utimes, path, ktimes);

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
ReadDet_chdir(const char *path)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = SYS_chdir;
      args.ebx = (ulong)path;
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
ReadDet_truncate64(const char * path, loff_t length)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_truncate64, path, length);

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

