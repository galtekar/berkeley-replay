#ifndef LIBCOMMON_SYSCALL
#define LIBCOMMON_SYSCALL

#ifdef __cplusplus
extern "C" {
#endif

#include "syscallids.h"
#include "compiler.h"

//#include "linux.h"

#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

/* Handy macro to test syscall return values for errors. */
#define SYSERR(r) unlikely((-4096 < ((signed)r)) && (((signed)r) < 0))

extern long __syscall(int sysno, ...);

#define syscall __syscall

extern char* get_syscall_name(int sysno);

struct SyscallArgs {
   /* Ordering matters -- it should be the order in which
    * syscall args are passed to syscall handler, which
    * means that EAX must be last. */
   ulong ebx;
   ulong ecx;
   ulong edx;
   ulong esi;
   ulong edi;
   ulong ebp;
   ulong eax;
};

static INLINE struct SyscallArgs
SysOps_ArgEnc(int sysno, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6)
{
   struct SyscallArgs a;

   a.eax = sysno;
   a.ebx = a1;
   a.ecx = a2;
   a.edx = a3;
   a.esi = a4;
   a.edi = a5;
   a.ebp = a6;

   return a;
}

static INLINE int
SysOps_Open(const char *filename, const int flags, const int mode)
{
   return syscall(SYS_open, filename, flags, mode);
}

static INLINE int
SysOps_Close(int fd)
{
   return syscall(SYS_close, fd);
}

#define SEMOP		      1
#define SEMGET		      2
#define SEMCTL		      3
#define SEMTIMEDOP	   4
#define MSGSND		      11
#define MSGRCV		      12
#define MSGGET		      13
#define MSGCTL		      14
#define SHMAT		      21
#define SHMDT		      22
#define SHMGET		      23
#define SHMCTL		      24

/* Argument ordering for IPC syscalls is convoluted. Here are
 * some helper routines. */
static INLINE int
SysOps_ShmGet(key_t key, size_t size, int shmflg)
{
   return syscall(SYS_ipc, SHMGET, key, size, shmflg);
}

#ifndef IPC_64
#define IPC_64  0x0100  /* New version */
#endif

static INLINE int
SysOps_ShmCtl64(int shmid, int cmd, struct shmid_ds *ubuf)
{
   return syscall(SYS_ipc, SHMCTL, shmid, cmd | IPC_64, 0, ubuf);
}

static INLINE int
SysOps_ShmAt(int shmid, void *shmaddr, int shmflg, ulong *raddr)
{
   return syscall(SYS_ipc, SHMAT, shmid, shmflg, raddr, shmaddr);
}

static INLINE int
SysOps_ShmDt(void *shmaddr)
{
   return syscall(SYS_ipc, SHMDT, 0, 0, 0, shmaddr);
}

static INLINE int
SysOps_SemGet(key_t key, int nsems, int semflg)
{
   return syscall(SYS_ipc, SEMGET, key, nsems, semflg);
}

/* arg for semctl system calls. */
union semun {
	int val;			/* value for SETVAL */
	void  *buf;	/* buffer for IPC_STAT & IPC_SET */
	unsigned short *array;	/* array for GETALL & SETALL */
	struct seminfo *__buf;	/* buffer for IPC_INFO */
	void *__pad;
};

static INLINE int
SysOps_SemCtl64(int semid, int semnum, int cmd, union semun arg)
{
   return syscall(SYS_ipc, SEMCTL, semid, semnum, cmd | IPC_64, &arg);
}

static INLINE long
SysOps_pread64(int fd, void *buf, size_t count, loff_t offset)
{
   return syscall(SYS_pread64, fd, (ulong) buf, count,
      (ulong) (offset & 0xFFFFFFFF), (ulong) ((offset >> 32) & 0xFFFFFFFF));
}

static INLINE long
SysOps_pwrite64(int fd, void *buf, size_t count, loff_t offset)
{
   return syscall(SYS_pwrite64, fd, (ulong) buf, count,
      (ulong) (offset & 0xFFFFFFFF), (ulong) ((offset >> 32) & 0xFFFFFFFF));
}

static INLINE long
SysOps_read(int fd, void *buf, size_t count)
{
   return syscall(SYS_read, fd, buf, count);
}

static INLINE long
SysOps_write(int fd, void *buf, size_t count)
{
   return syscall(SYS_write, fd, buf, count);
}

static INLINE long
SysOps_readv(int fd, const struct iovec *iov, int iovcnt) 
{
   return syscall(SYS_readv, fd, iov, iovcnt);
}

static INLINE long
SysOps_writev(int fd, const struct iovec *iov, int iovcnt) 
{
   return syscall(SYS_writev, fd, iov, iovcnt);
}

/* XXX: use the defs in linux.h */

#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/

static INLINE long
SysOps_socket(int family, int type, int protocol)
{
   ulong s[3] = { family, type, protocol };

   return syscall(SYS_socketcall, SYS_SOCKET, (ulong) s);
}

static INLINE long
SysOps_connect(const int fd, const struct sockaddr *uservaddr, int addrlen)
{
   ulong s[3] = { fd, (ulong) uservaddr, addrlen };

   return syscall(SYS_socketcall, SYS_CONNECT, (ulong) s);
}

static INLINE long
SysOps_bind(const int fd, const struct sockaddr *addr, const int addrlen)
{
   ulong s[3] = { fd, (ulong) addr, addrlen };

   return syscall(SYS_socketcall, SYS_BIND, (ulong) s);
}

static INLINE long
SysOps_sendmsg(const int fd, const struct msghdr *msgP, const int flags)
{
   ulong s[3] = { fd, (ulong) msgP, flags };

   return syscall(SYS_socketcall, SYS_SENDMSG, (ulong) s);
}

static INLINE long
SysOps_recvmsg(const int fd, struct msghdr *msgP, const int flags)
{
   ulong s[3] = { fd, (ulong) msgP, flags };

   return syscall(SYS_socketcall, SYS_RECVMSG, (ulong) s);
}

static INLINE long
SysOps_recvfrom(const int fd, char *buf, const size_t buf_len, 
                const int flags, struct sockaddr *from, socklen_t *from_len)
{
   ulong s[6] = { fd, (ulong) buf, buf_len, flags, (ulong) from, 
      (ulong) from_len };

   return syscall(SYS_socketcall, SYS_RECVFROM, (ulong) s);
}

static INLINE long
SysOps_send(int fd, const void *buf, size_t len, int flags)
{
   ulong s[4] = { fd, (ulong) buf, len, flags };

   return syscall(SYS_socketcall, SYS_SEND, (ulong) s);
}

static INLINE long
SysOps_recv(int fd, void *buf, size_t len, int flags)
{
   ulong s[4] = { fd, (ulong) buf, len, flags };

   return syscall(SYS_socketcall, SYS_RECV, (ulong) s);
}

static INLINE long
SysOps_select(int n, fd_set *inp, fd_set *outp,
              fd_set *exp, struct timeval *tvp)
{
   /* Make sure you're using the new select, not the old one. */
   //ASSERT(SYS_select == 142);

   return syscall(SYS_select, n, inp, outp, exp, tvp);
}

static INLINE long
SysOps_pselect(int n, fd_set *inp, fd_set *outp,
              fd_set *exp, struct timeval *tvp, sigset_t *sigmask)
{
   struct sixth_arg {
      sigset_t *sigmaskp;
      size_t sigsetsize;
   };
   struct sixth_arg arg6 = { .sigmaskp = sigmask, 
      .sigsetsize = sizeof(*sigmask) };
   return syscall(SYS_pselect6, n, inp, outp, exp, tvp, &arg6);
}

static INLINE long
SysOps_ptrace(int req, int pid, void *addr, void *data_ptr)
{
   return syscall(SYS_ptrace, req, pid, addr, data_ptr);
}

static INLINE long
SysOps_modify_ldt(int func, void *ptr, unsigned long bytecount)
{
   return syscall(SYS_modify_ldt, func, ptr, bytecount);
}

static INLINE long
SysOps_ioctl(int fd, int cmd, void *arg)
{
   return syscall(SYS_ioctl, fd, cmd, arg);
}


#ifdef __cplusplus
}
#endif

#endif
