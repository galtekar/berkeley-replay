#pragma once

/* Stuff that is found in Linux kernel headers. */
/* XXX: AT some point, we should consider merging with kernel tree somehow.
 * Many kernel headers seem to be independent of kernel mode structs. */

/* XXX: we should just include linux/include/linux/limits.h" */
#define XATTR_NAME_MAX   255  /* # chars in an extended attribute name */
#define XATTR_SIZE_MAX 65536  /* size of an extended attribute value (64k) */
#define XATTR_LIST_MAX 65536  /* size of extended attribute namelist (64k) */

struct __old_kernel_stat {
   unsigned short st_dev;
   unsigned short st_ino;
   unsigned short st_mode;
   unsigned short st_nlink;
   unsigned short st_uid;
   unsigned short st_gid;
   unsigned short st_rdev;
   unsigned long  st_size;
   unsigned long  st_atime;
   unsigned long  st_mtime;
   unsigned long  st_ctime;
};

/* 
 * CAREFUL!: dietlibc's stat64 and Linux's stat64 are not the same.
 * kstat64 and Linux's stat64 should be the same. Always use
 * kstat64.
 */

/* This matches struct stat64 in glibc2.1, hence the absolutely
 * insane amounts of padding around dev_t's.
 */
struct kstat64 {
   unsigned long long	st_dev;
   unsigned char	__pad0[4];

   unsigned long	__st_ino;

   unsigned int	st_mode;
   unsigned int	st_nlink;

   unsigned long	st_uid;
   unsigned long	st_gid;

   unsigned long long	st_rdev;
   unsigned char	__pad3[4];

   long long	st_size;
   unsigned long	st_blksize;

   unsigned long long	st_blocks;	/* Number 512-byte blocks allocated. */

   unsigned long	st_atime;
   unsigned long	st_atime_nsec;

   unsigned long	st_mtime;
   unsigned int	st_mtime_nsec;

   unsigned long	st_ctime;
   unsigned long	st_ctime_nsec;

   unsigned long long	st_ino;
};


extern int 
Linux_cp_new_stat(struct kstat64 *kstat, struct stat __user *statbuf);


#define  MAX_NON_LFS ((1UL<<31) - 1)


/* Set the One Shot behaviour for the target file descriptor */
#define EPOLLONESHOT (1 << 30)

#if 0
/* Valid opcodes to issue to sys_epoll_ctl() */
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3


/* Set the Edge Triggered behaviour for the target file descriptor */
#define EPOLLET (1 << 31)

/* 
 * On x86-64 make the 64bit structure have the same alignment as the
 * 32bit structure. This makes 32bit emulation easier.
 */
#ifdef __x86_64__
#define EPOLL_PACKED __attribute__((packed))
#else
#define EPOLL_PACKED
#endif

struct epoll_event {
   __u32 events;
   __u64 data;
} EPOLL_PACKED;
#endif

/* XXX: use the value from the kernel */
#define AT_VECTOR_SIZE  44 /* Size of auxiliary table.  */

#if USING_DIET_LIBC
#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#define S_IRWXUGO	(S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IRUGO		(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO		(S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO		(S_IXUSR|S_IXGRP|S_IXOTH)
#endif

#define MODE_PERM(m) (m & S_IRWXUGO)


#define MAX_SOCK_ADDR	128		/* 108 for Unix domain - 
                                    16 for IP, 16 for IPX,
                                    24 for IPv6,
                                    about 80 for AX.25 
                                    must be at least one bigger than
                                    the AF_UNIX size (see net/unix/af_unix.c
                                    :unix_mkname()).  
                                    */

// XXX: we may need to increase size; sshd passes in 200 bytes
// this was 32 originally...odd...why does linux need so little space?
#define MAX_OPTVAL_SIZE 256

/* XXX: we should get this from some header file, ideally
 * Linux's */
#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/

#define AT_FDCWD -100
#define AT_SYMLINK_NOFOLLOW	0x100   /* Do not follow symbolic links.  */
#define AT_REMOVEDIR		0x200   /* Remove directory instead of
                                   unlinking file.  */

#define MAJOR(dev)	((dev)>>8)
#define MINOR(dev)	((dev) & 0xff)
#define MKDEV(ma,mi)	((ma)<<8 | (mi))

typedef int __kernel_key_t;
typedef unsigned int	__kernel_uid32_t;
typedef unsigned int	__kernel_gid32_t;
typedef long		__kernel_time_t;
typedef unsigned short	__kernel_mode_t;
typedef __kernel_uid32_t		kuid_t;
typedef __kernel_gid32_t		kgid_t;
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define BITS_PER_BYTE           8
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]
typedef struct cpumask { DECLARE_BITMAP(bits, 64); } cpumask_t;

struct ipc64_perm
{
   __kernel_key_t		key;
   __kernel_uid32_t	uid;
   __kernel_gid32_t	gid;
   __kernel_uid32_t	cuid;
   __kernel_gid32_t	cgid;
   __kernel_mode_t		mode;
   unsigned short		__pad1;
   unsigned short		seq;
   unsigned short		__pad2;
   unsigned long		__unused1;
   unsigned long		__unused2;
};

struct semid64_ds {
   struct ipc64_perm sem_perm;		/* permissions .. see ipc.h */
   __kernel_time_t	sem_otime;		/* last semop time */
   unsigned long	__unused1;
   __kernel_time_t	sem_ctime;		/* last change time */
   unsigned long	__unused2;
   unsigned long	sem_nsems;		/* no. of semaphores in array */
   unsigned long	__unused3;
   unsigned long	__unused4;
};


#define MADV_DONTFORK	10		/* don't inherit across fork */

#define __NEW_UTS_LEN 64

/* XXX: taken from Linux kernel. We should compile against
 * the kernel headers at some point rather than copy-and-paste. */
struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

#include <sys/i386-ioctl.h>

#define FIBMAP	   _IO(0x00,1)	/* bmap access */
#define FIGETBSZ   _IO(0x00,2)	/* get the block size used for bmap */

/* Stolen from linux-2.6.16/include/asm-i386/segment.h. */
#define GDT_ENTRY_TLS_ENTRIES 3
#define GDT_ENTRY_TLS_MIN  6
#define GDT_ENTRY_TLS_MAX  (GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES - 1)

#define GDT_ENTRY_DEFAULT_USER_CS	14
#define __USER_CS (GDT_ENTRY_DEFAULT_USER_CS * 8 + 3)
#define GDT_ENTRY_DEFAULT_USER_DS	15
#define __USER_DS (GDT_ENTRY_DEFAULT_USER_DS * 8 + 3)

/* Scheduler. */
struct sched_param {
	int sched_priority;
};


/*
 * How these fields are to be accessed.
 */
#define si_pid		_sifields._kill._pid
#define si_uid		_sifields._kill._uid
#define si_tid		_sifields._timer._tid
#define si_overrun	_sifields._timer._overrun
#define si_sys_private  _sifields._timer._sys_private
#define si_status	_sifields._sigchld._status
#define si_utime	_sifields._sigchld._utime
#define si_stime	_sifields._sigchld._stime
#define si_value	_sifields._rt._sigval
#define si_int		_sifields._rt._sigval.sival_int
#define si_ptr		_sifields._rt._sigval.sival_ptr
#define si_addr		_sifields._sigfault._addr
//#ifdef __ARCH_SI_TRAPNO
//#define si_trapno	_sifields._sigfault._trapno
//#endif
#define si_band		_sifields._sigpoll._band
#define si_fd		_sifields._sigpoll._fd

#define __SI_MASK	0xffff0000u
#define __SI_KILL	(0 << 16)
#define __SI_TIMER	(1 << 16)
#define __SI_POLL	(2 << 16)
#define __SI_FAULT	(3 << 16)
#define __SI_CHLD	(4 << 16)
#define __SI_RT		(5 << 16)
#define __SI_MESGQ	(6 << 16)
#define __SI_CODE(T,N)	((T) | ((N) & 0xffff))


/* ioctl()'s for the random number generator */

/* Get the entropy count. */
#define RNDGETENTCNT	_IOR( 'R', 0x00, int )

/* Add to (or subtract from) the entropy count.  (Superuser only.) */
#define RNDADDTOENTCNT	_IOW( 'R', 0x01, int )

/* Get the contents of the entropy pool.  (Superuser only.) */
#define RNDGETPOOL	_IOR( 'R', 0x02, int [2] )

/* 
 * Write bytes into the entropy pool and add to the entropy count.
 * (Superuser only.)
 */
#define RNDADDENTROPY	_IOW( 'R', 0x03, int [2] )

/* Clear entropy count to 0.  (Superuser only.) */
#define RNDZAPENTCNT	_IO( 'R', 0x04 )

/* Clear the entropy pool and associated counters.  (Superuser only.) */
#define RNDCLEARPOOL	_IO( 'R', 0x06 )

struct sigframe
{
	char __user *pretcode;
	int sig;
	struct sigcontext sc;
	struct _fpstate fpstate;
	unsigned long extramask[_NSIG_WORDS-1];
	char retcode[8];
};

struct rt_sigframe 
{
	char __user *pretcode;
	int sig;
	struct siginfo __user *pinfo;
	void __user *puc;
	struct siginfo info;
	struct ucontext uc;
	struct _fpstate fpstate;
	char retcode[8];
};

struct __sysctl_args {
	int __user *name;
	int nlen;
	void __user *oldval;
	size_t __user *oldlenp;
	void __user *newval;
	size_t newlen;
	unsigned long __unused[4];
};

/* Since ~2.6.30... */
#define F_SETOWN_EX	15

#define F_OWNER_TID	0
#define F_OWNER_PID	1
#define F_OWNER_PGRP	2
struct f_owner_ex {
	int	type;
	pid_t	pid;
};


#ifndef O_CLOEXEC
#define O_CLOEXEC	02000000	/* set close_on_exec */
#endif
