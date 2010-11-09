#include "vkernel/macros.h"
#include "libcommon/syscallids.h"

VARIABLE(sys_call_table)
	.long sys_restart_syscall //sys_restart_syscall	/* 0 - old "setup()" system call, used for restarting */
	.long sys_exit //sys_exit
	.long sys_fork //sys_fork
	.long sys_read //sys_read
	.long sys_write //sys_write
	.long sys_open //sys_open		/* 5 */
	.long sys_close //sys_close
	.long sys_waitpid //sys_waitpid
	.long sys_creat //sys_creat
	.long sys_link //sys_link
	.long sys_unlink //sys_unlink	/* 10 */
	.long sys_execve //sys_execve
	.long sys_chdir //sys_chdir
	.long sys_time //sys_time
	.long sys_mknod //sys_mknod
	.long sys_chmod //sys_chmod		/* 15 */
	.long sys_deprecated //sys_lchown16
	.long sys_default //sys_ni_syscall	/* old break syscall holder */
	.long sys_deprecated //sys_stat
	.long sys_lseek //sys_lseek
	.long sys_getpid	/* 20 */
	.long sys_default //sys_mount
	.long sys_default //sys_oldumount
	.long sys_default //sys_setuid16
	.long sys_default //sys_getuid16
	.long sys_stime //sys_stime		/* 25 */
	.long sys_default //sys_ptrace
	.long sys_alarm //sys_alarm
	.long sys_deprecated //sys_fstat
	.long sys_pause //sys_pause
	.long sys_utime //sys_utime		/* 30 */
	.long sys_default //sys_ni_syscall	/* old stty syscall holder */
	.long sys_default //sys_ni_syscall	/* old gtty syscall holder */
	.long sys_access //sys_access
	.long sys_default //sys_nice
	.long sys_default //sys_ni_syscall	/* 35 - old ftime syscall holder */
	.long sys_default //sys_sync
	.long sys_kill //sys_kill
	.long sys_rename //sys_rename
	.long sys_mkdir //sys_mkdir
	.long sys_rmdir //sys_rmdir		/* 40 */
	.long sys_dup //sys_dup
	.long sys_pipe //sys_pipe
	.long sys_times //sys_times
	.long sys_default //sys_ni_syscall	/* old prof syscall holder */
	.long sys_brk //sys_brk		/* 45 */
	.long sys_default //sys_setgid16
	.long sys_default //sys_getgid16
	.long sys_signal //sys_signal
	.long sys_default //sys_geteuid16
	.long sys_default //sys_getegid16	/* 50 */
	.long sys_default //sys_acct
	.long sys_default //sys_umount	/* recycled never used phys() */
	.long sys_default //sys_ni_syscall	/* old lock syscall holder */
	.long sys_ioctl //sys_ioctl
	.long sys_fcntl //sys_fcntl		/* 55 */
	.long sys_default //sys_ni_syscall	/* old mpx syscall holder */
	.long sys_setpgid //sys_setpgid
	.long sys_default //sys_ni_syscall	/* old ulimit syscall holder */
	.long sys_deprecated //sys_olduname
	.long sys_umask //sys_umask		/* 60 */
	.long sys_default //sys_chroot
	.long sys_default //sys_ustat
	.long sys_dup2 //sys_dup2
	.long sys_getppid//sys_getppid
	.long sys_getpgrp //sys_getpgrp	/* 65 */
	.long sys_setsid //sys_setsid
	.long sys_sigaction //sys_sigaction
	.long sys_default //sys_sgetmask
	.long sys_default //sys_ssetmask
	.long sys_default //sys_setreuid16	/* 70 */
	.long sys_default //sys_setregid16
	.long sys_sigsuspend //sys_sigsuspend
	.long sys_sigpending //sys_sigpending
	.long sys_sethostname //sys_sethostname
	.long sys_setrlimit //sys_setrlimit	/* 75 */
	.long sys_default //sys_old_getrlimit
	.long sys_getrusage //sys_getrusage
	.long sys_gettimeofday //sys_gettimeofday
	.long sys_default //sys_settimeofday
	.long sys_default //sys_getgroups16	/* 80 */
	.long sys_default //sys_setgroups16
	.long sys_old_select //old_select
	.long sys_symlink //sys_symlink
	.long sys_deprecated //sys_lstat
	.long sys_readlink //sys_readlink	/* 85 */
	.long sys_default //sys_uselib
	.long sys_default //sys_swapon
	.long sys_default //sys_reboot
	.long sys_old_readdir //sys_old_readdir
	.long sys_mmap //old_mmap		/* 90 */
	.long sys_munmap //sys_munmap
	.long sys_truncate //sys_truncate
	.long sys_ftruncate //sys_ftruncate
	.long sys_fchmod //sys_fchmod
	.long sys_deprecated //sys_fchown16	/* 95 */
	.long sys_getpriority //sys_getpriority
	.long sys_setpriority //sys_setpriority
	.long sys_default //sys_ni_syscall	/* old profil syscall holder */
	.long sys_statfs //sys_statfs
	.long sys_fstatfs //sys_fstatfs	/* 100 */
	.long sys_default //sys_ioperm
	.long sys_socketcall //sys_socketcall
	.long sys_default //sys_syslog
	.long sys_setitimer //sys_setitimer
	.long sys_getitimer //sys_getitimer	/* 105 */
	.long sys_newstat //sys_newstat
	.long sys_newlstat //sys_newlstat
	.long sys_deprecated //sys_newfstat
	.long sys_default //sys_uname
	.long sys_default //sys_iopl		/* 110 */
	.long sys_default //sys_vhangup
	.long sys_default //sys_ni_syscall	/* old "idle" system call */
	.long sys_default //sys_vm86old
	.long sys_wait4 //sys_wait4
	.long sys_default //sys_swapoff	/* 115 */
	.long sys_sysinfo //sys_sysinfo
	.long sys_ipc //sys_ipc
	.long sys_fsync //sys_fsync
	.long sys_sigreturn //sys_sigreturn
	.long sys_clone //sys_clone		/* 120 */
	.long sys_setdomainname //sys_setdomainname
	.long sys_newuname //sys_newuname
	.long sys_modify_ldt //sys_modify_ldt
	.long sys_default //sys_adjtimex
	.long sys_mprotect //sys_mprotect	/* 125 */
	.long sys_sigprocmask //sys_sigprocmask
	.long sys_default //sys_ni_syscall	/* old "create_module" */
	.long sys_default //sys_init_module
	.long sys_default //sys_delete_module
	.long sys_default //sys_ni_syscall	/* 130:	old "get_kernel_syms" */
	.long sys_default //sys_quotactl
	.long sys_getpgid //sys_getpgid
	.long sys_fchdir //sys_fchdir
	.long sys_default //sys_bdflush
	.long sys_default //sys_sysfs		/* 135 */
	.long sys_personality //sys_personality
	.long sys_default //sys_ni_syscall	/* reserved for afs_syscall */
	.long sys_default //sys_setfsuid16
	.long sys_default //sys_setfsgid16
	.long sys_llseek //sys_llseek	/* 140 */
	.long sys_getdents //sys_getdents
	.long sys_select //sys_select
	.long sys_flock //sys_flock
	.long sys_msync //sys_msync
	.long sys_readv //sys_readv		/* 145 */
	.long sys_writev //sys_writev
	.long sys_getsid //sys_getsid
	.long sys_fdatasync //sys_fdatasync
	.long sys_default //sys_sysctl
	.long sys_mlock //sys_mlock		/* 150 */
	.long sys_munlock //sys_munlock
	.long sys_mlockall //sys_mlockall
	.long sys_munlockall //sys_munlockall
	.long sys_sched_setparam //sys_sched_setparam
	.long sys_sched_getparam //sys_sched_getparam   /* 155 */
	.long sys_sched_setscheduler //sys_sched_setscheduler
	.long sys_sched_getscheduler //sys_sched_getscheduler
	.long sys_sched_yield //sys_sched_yield
	.long sys_sched_get_priority_max //sys_sched_get_priority_max
	.long sys_sched_get_priority_min //sys_sched_get_priority_min  /* 160 */
	.long sys_sched_rr_get_interval //sys_sched_rr_get_interval
	.long sys_nanosleep //sys_nanosleep
	.long sys_mremap //sys_mremap
	.long sys_default //sys_setresuid16
	.long sys_default //sys_getresuid16	/* 165 */
	.long sys_default //sys_vm86
	.long sys_default //sys_ni_syscall	/* Old sys_query_module */
	.long sys_poll //sys_poll
	.long sys_default //sys_nfsservctl
	.long sys_default //sys_setresgid16	/* 170 */
	.long sys_default //sys_getresgid16
	.long sys_default //sys_prctl
	.long sys_rt_sigreturn //sys_rt_sigreturn
	.long sys_rt_sigaction //sys_rt_sigaction
	.long sys_rt_sigprocmask //sys_rt_sigprocmask	/* 175 */
	.long sys_rt_sigpending //sys_rt_sigpending
	.long sys_rt_sigtimedwait
	.long sys_default //sys_rt_sigqueueinfo
	.long sys_rt_sigsuspend //sys_rt_sigsuspend
	.long sys_pread64 //sys_pread64	/* 180 */
	.long sys_pwrite64 //sys_pwrite64
	.long sys_deprecated //sys_chown16
	.long sys_getcwd //sys_getcwd
	.long sys_default //sys_capget
	.long sys_default //sys_capset	/* 185 */
	.long sys_sigaltstack //sys_sigaltstack
	.long sys_sendfile //sys_sendfile
	.long sys_default //sys_ni_syscall	/* reserved for streams1 */
	.long sys_default //sys_ni_syscall	/* reserved for streams2 */
	.long sys_vfork //sys_vfork		/* 190 */
	.long sys_getrlimit
	.long sys_mmap2 //sys_mmap2
	.long sys_truncate64 //sys_truncate64
	.long sys_ftruncate64 //sys_ftruncate64
	.long sys_stat64 //sys_stat64	/* 195 */
	.long sys_lstat64 //sys_lstat64
	.long sys_fstat64 //sys_fstat64
	.long sys_lchown //sys_lchown
	.long sys_getuid //sys_getuid
	.long sys_getgid //sys_getgid	/* 200 */
	.long sys_geteuid //sys_geteuid
	.long sys_getegid //sys_getegid
	.long sys_setreuid //sys_setreuid
	.long sys_setregid //sys_setregid
	.long sys_getgroups //sys_getgroups	/* 205 */
	.long sys_setgroups //sys_setgroups
	.long sys_fchown //sys_fchown
	.long sys_setresuid //sys_setresuid
	.long sys_getresuid //sys_getresuid
	.long sys_setresgid //sys_setresgid	/* 210 */
	.long sys_getresgid //sys_getresgid
	.long sys_chown //sys_chown
	.long sys_setuid //sys_setuid
	.long sys_setgid //sys_setgid
	.long sys_setfsuid //sys_setfsuid	/* 215 */
	.long sys_setfsgid //sys_setfsgid
	.long sys_default //sys_pivot_root
	.long sys_default //sys_mincore
	.long sys_madvise //sys_madvise
	.long sys_getdents64	/* 220 */
	.long sys_fcntl64
	.long sys_default //sys_ni_syscall	/* reserved for TUX */
	.long sys_default //sys_ni_syscall
	.long sys_gettid //sys_gettid
	.long sys_default //sys_readahead	/* 225 */
	.long sys_setxattr //sys_setxattr
	.long sys_lsetxattr //sys_lsetxattr
	.long sys_fsetxattr //sys_fsetxattr
	.long sys_getxattr //sys_getxattr
	.long sys_lgetxattr //sys_lgetxattr	/* 230 */
	.long sys_fgetxattr //sys_fgetxattr
	.long sys_listxattr //sys_listxattr
	.long sys_llistxattr //sys_llistxattr
	.long sys_flistxattr //sys_flistxattr
	.long sys_removexattr //sys_removexattr	/* 235 */
	.long sys_lremovexattr //sys_lremovexattr
	.long sys_fremovexattr //sys_fremovexattr
	.long sys_tkill //sys_tkill
	.long sys_sendfile64 //sys_sendfile64
	.long sys_futex //sys_futex		/* 240 */
	.long sys_sched_setaffinity //sys_sched_setaffinity
	.long sys_sched_getaffinity //sys_sched_getaffinity
	.long sys_set_thread_area //sys_set_thread_area
	.long sys_get_thread_area //sys_get_thread_area
	.long sys_default //sys_io_setup	/* 245 */
	.long sys_default //sys_io_destroy
	.long sys_default //sys_io_getevents
	.long sys_default //sys_io_submit
	.long sys_default //sys_io_cancel
	.long sys_default //sys_fadvise64	/* 250 */
	.long sys_default //sys_ni_syscall
	.long sys_exit_group //sys_exit_group
	.long sys_default //sys_lookup_dcookie
	.long sys_epoll_create //sys_epoll_create
	.long sys_epoll_ctl //sys_epoll_ctl	/* 255 */
	.long sys_epoll_wait //sys_epoll_wait
 	.long sys_default //sys_remap_file_pages
 	.long sys_set_tid_address //sys_set_tid_address
 	.long sys_default //sys_timer_create
 	.long sys_default //sys_timer_settime		/* 260 */
 	.long sys_default //sys_timer_gettime
 	.long sys_default //sys_timer_getoverrun
 	.long sys_default //sys_timer_delete
 	.long sys_clock_settime //sys_clock_settime
 	.long sys_clock_gettime //sys_clock_gettime		/* 265 */
 	.long sys_clock_getres //sys_clock_getres
 	.long sys_clock_nanosleep //sys_clock_nanosleep
	.long sys_statfs64 //sys_statfs64
	.long sys_fstatfs64 //sys_fstatfs64
	.long sys_tgkill //sys_tgkill	/* 270 */
	.long sys_utimes //sys_utimes
 	.long sys_default //sys_fadvise64_64
	.long sys_default //sys_ni_syscall	/* sys_vserver */
	.long sys_default //sys_mbind
	.long sys_default //sys_get_mempolicy
	.long sys_default //sys_set_mempolicy
	.long sys_default //sys_mq_open
	.long sys_default //sys_mq_unlink
	.long sys_default //sys_mq_timedsend
	.long sys_default //sys_mq_timedreceive	/* 280 */
	.long sys_default //sys_mq_notify
	.long sys_default //sys_mq_getsetattr
	.long sys_default //sys_kexec_load
	.long sys_waitid //sys_waitid
	.long sys_default //sys_ni_syscall		/* 285 */ /* available */
	.long sys_default //sys_add_key
	.long sys_default //sys_request_key
	.long sys_default //sys_keyctl
	.long sys_default //sys_ioprio_set
	.long sys_default //sys_ioprio_get		/* 290 */
	.long sys_default //sys_inotify_init
	.long sys_default //sys_inotify_add_watch
	.long sys_default //sys_inotify_rm_watch
	.long sys_default //sys_migrate_pages
	.long sys_openat //sys_openat		/* 295 */
	.long sys_mkdirat //sys_mkdirat
	.long sys_mknodat //sys_mknodat
	.long sys_fchownat //sys_fchownat
	.long sys_futimesat //sys_futimesat
	.long sys_fstatat64 //sys_fstatat64		/* 300 */
	.long sys_unlinkat //sys_unlinkat
	.long sys_renameat //sys_renameat
	.long sys_linkat //sys_linkat
	.long sys_symlinkat //sys_symlinkat
	.long sys_readlinkat //sys_readlinkat		/* 305 */
	.long sys_fchmodat //sys_fchmodat
	.long sys_faccessat //sys_faccessat
	.long sys_pselect6 //sys_pselect6
	.long sys_ppoll //sys_ppoll
	.long sys_default //sys_unshare		/* 310 */
	.long sys_set_robust_list //sys_set_robust_list
	.long sys_get_robust_list //sys_get_robust_list
	.long sys_default //sys_splice
	.long sys_default //sys_sync_file_range
	.long sys_default //sys_tee			/* 315 */
	.long sys_default //sys_vmsplice
	.long sys_default //sys_move_pages
	.long sys_default //sys_getcpu
	.long sys_default //sys_epoll_pwait
	.long sys_default //sys_utimensat		/* 320 */
	.long sys_default //sys_signalfd
	.long sys_default //sys_timerfd_create
	.long sys_eventfd //sys_eventfd
	.long sys_default //sys_fallocate
	.long sys_default //sys_timerfd_settime	/* 325 */
	.long sys_default //sys_timerfd_gettime
	.long sys_default //sys_signalfd4
	.long sys_eventfd2 //sys_eventfd2
	.long sys_default //sys_epoll_create1
	.long sys_default //sys_dup3			/* 330 */
	.long sys_default //sys_pipe2
	.long sys_default //sys_inotify_init1
END(sys_call_table)

/* Make sure to update all constants if new entries get added to the table. */
.ifne (. - sys_call_table) - (NR_SYSCALLS * 4)
.err
.endif
