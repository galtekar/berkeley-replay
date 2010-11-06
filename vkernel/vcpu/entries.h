/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
/* NOTE: We may include this multiple times in a file, potentially after
 * redefining LOGENTRYDEF. For example, we do this to associate integer ids
 * with each log entry type. */

LOGENTRYDEF(Rotate,
   char dummy;
)

LOGENTRYDEF(ValInt,
   uint val;
)

LOGENTRYDEF(ValLong,
   ulong val;
)

LOGENTRYDEF(ValLongLong,
   ullong val;
)

LOGENTRYDEF(JustRetval,
   SyscallRet ret;
)

/* Asynch. events. */

LOGENTRYDEF(Signal,
   siginfo_t si;

   /* Don't need to log the ucontext_t since all Linux
    * signals arrive at set drainage points within the vkernel. 
    * Preemption, on the other hand, need their execution
    * context logged since they are permitted any time in user-mode. 
    *
    * ucontext_t uc;
    */
)

LOGENTRYDEF(PreemptionTimer,
   struct ExecPoint ep;
)

LOGENTRYDEF(PreemptionFault,
   struct ExecPoint ep;
   siginfo_t faultInfo;
)

/* Blocking events. */

LOGENTRYDEF(sys_select,
   SyscallRet ret;
   fd_set in, out, ex;
   struct timespec ts;
   struct timeval tv;
)

LOGENTRYDEF(sys_poll,
   SyscallRet ret;
   struct timespec ts;
)


LOGENTRYDEF(SysNanosleep,
   SyscallRet ret;
   struct timespec rmt; /* time remaining */
)

/* Non-blocking events. */

LOGENTRYDEF(RDTSC,
   uint64_t time;
)

LOGENTRYDEF(SysNewuname,
   SyscallRet ret;
   struct new_utsname name;
)

LOGENTRYDEF(sys_sysinfo,
   SyscallRet ret;
   struct sysinfo info;
)

#include <termios.h>
LOGENTRYDEF(SysIoctl_tcgets,
   SyscallRet ret;
   struct termios tios;
)

// XXX: consolidate with sys_ioctl_int?
LOGENTRYDEF(SysIoctl_tiocgpgrp,
   SyscallRet ret;
   pid_t pid;
)

LOGENTRYDEF(sys_ioctl_int,
   SyscallRet ret;
   uint val;
)

LOGENTRYDEF(SysIoctl_tiocgwinsz,
   SyscallRet ret;
   struct winsize winsz;
)

/* For sys_stat64, sys_lstat64, and sys_fstat64 */
LOGENTRYDEF(sys_stat64,
   SyscallRet ret;
   struct kstat64 stat;
)

#include <sys/vfs.h>
LOGENTRYDEF(sys_statfs64,
   SyscallRet ret;
   struct statfs64 stat;
)

LOGENTRYDEF(sys_llseek,
   SyscallRet ret;
   loff_t off;
)

LOGENTRYDEF(sys_readlink,
   SyscallRet ret;
   char link[PATH_MAX];
)


LOGENTRYDEF(SysGetrlimit,
   SyscallRet ret;
   struct rlimit rlim;
)

LOGENTRYDEF(SysGetrusage,
   SyscallRet ret;
   struct rusage rusage;
)


LOGENTRYDEF(sys_clone,
   pid_t childPid;
)

LOGENTRYDEF(sys_pipe,
   SyscallRet ret;
   int fds[2];
)

LOGENTRYDEF(init,
   pid_t initPid;
   uid_t initUid;
   char initCwd[PATH_MAX];
)

LOGENTRYDEF(sys_gettimeofday,
   SyscallRet ret;
   struct timeval tv;
   struct timezone tz;
)

/* One log entry for getresuid, getresgid, etc.. */
LOGENTRYDEF(sys_getresid,
   uid_t rid, eid, sid;
)

/* One log entry for setitimer/getitimer. */
LOGENTRYDEF(sys_itimer,
   SyscallRet ret;
   struct itimerval ovalue;
)

LOGENTRYDEF(sys_get_robust_list,
   SyscallRet ret;
   ulong head_ptr, len_ptr;
)

LOGENTRYDEF(sys_socketpair,
   SyscallRet ret;
   int rfd[2];
)

LOGENTRYDEF(sys_sock_getname,
   SyscallRet ret;

   char addr[MAX_SOCK_ADDR];
   int len;
)

LOGENTRYDEF(sys_sock_accept,
   SyscallRet ret;

   char addr[MAX_SOCK_ADDR];
   int len;
)

LOGENTRYDEF(sys_clock_gettimespec,
   SyscallRet ret;
   struct timespec ts;
)

LOGENTRYDEF(sys_sock_sockopt,
   SyscallRet ret;

   char optval[MAX_OPTVAL_SIZE];
   int optlen;
)

LOGENTRYDEF(sys_getxattr,
   SyscallRet ret;
   char value[XATTR_SIZE_MAX];
)

#define MAX_NR_CHUNKS 20

LOGENTRYDEF(sys_io,
   ssize_t ret;
   tsock_chunk_t chunk_buf[MAX_NR_CHUNKS];
   int nr_chunks;
   uint64_t wall_time;

   size_t loggedContentLen;
   size_t msg_namelen;
   size_t msg_controllen;
   int msg_flags; 
#if DEBUG
   void * msg_name;
   void * msg_control;
#endif
)

#if 0
LOGENTRYDEF(sys_write,
   ssize_t ret;
   size_t loggedContentLen;

#if DEBUG
   void * msg_name;
   void * msg_control;
#endif
)
#endif

LOGENTRYDEF(sys_sendfile,
   long ret;
   off_t offset;
)

LOGENTRYDEF(sys_sendfile64,
   long ret;
   loff_t offset;
)

LOGENTRYDEF(sys_sched_getaffinity,
   SyscallRet ret;
   cpumask_t mask;
)

LOGENTRYDEF(sys_sched_getparam,
   SyscallRet ret;
   struct sched_param param;
)

LOGENTRYDEF(sys_sched_rr_get_interval,
   SyscallRet ret;
   struct timespec interval;
)

LOGENTRYDEF(sys_times,
   SyscallRet ret;
   struct tms buf;
)

LOGENTRYDEF(RdPipeIoctl_FIONREAD,
   SyscallRet ret;
   int count;
)

LOGENTRYDEF(RegisterState,
   /* intentionally left empty, variable length data. */
)

LOGENTRYDEF(VclockState,
   uint64_t vclock;
)

/* Lock events. */

LOGENTRYDEF(SegmentEvent,
#if DEBUG
   char idStr[64];
#endif
   ulong ticket;
)

LOGENTRYDEF(CopyToUser,
   ulong ret;
#if DEBUG
   const void __user *toP;
   size_t n;
   size_t nrBytesCopied;
#endif
)

LOGENTRYDEF(CopyFromUser,
   ulong ret;
#if DEBUG
   const void __user *fromP;
   size_t n;
#endif
)


/* ----- Branch check module ----- */

LOGENTRYDEF(BrChkMispredict,
   u64 brCnt;
)

LOGENTRYDEF(BrChkIndirectJumpMispredict,
   u64 brCnt;
   ulong actualTarget;
)

#if DEBUG
LOGENTRYDEF(BrChkPrediction,
   ulong pred;
)

LOGENTRYDEF(BrChkOutcome,
   ulong outcome;
)
#endif



/* ---------- Check module ---------- */

LOGENTRYDEF(CheckHeader,
   int properties;
)

LOGENTRYDEF(RegChk,
   ulong eax, ecx, edx, ebx, esp, ebp, esi, edi, eip;
   ulong eflags /* aka, dep1 */, dep2, ndep;
   ushort cs, ds, es, fs, gs, ss;
)

LOGENTRYDEF(LoadChk,
   /* intentionally empty, entry is all variable data */
)

LOGENTRYDEF(StoreChk,
   /* intentionally empty, entry is all variable data */
)

/* ---------- Cgen module ---------- */

LOGENTRYDEF(cg,
   )
