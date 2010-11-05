#include "vkernel/public.h"
#include "private.h"


/* 
 * ----------------------------------------
 *
 * Sock ops.
 *
 * ----------------------------------------
 */

/* XXX: need to do arg count checking -- syscall expecting n args should
 * get precisely n args. */
static int
LogSyscall(int logRes)
{
   int res = logRes;

   if (!VCPU_IsReplaying()) {

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = logRes;
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         res = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }
   DEBUG_MSG(5, "res=%d\n", res);

   return res;
}

#define LOG_CALL_RESULT(call)  \
({  \
   int res = 0; \
   if (!VCPU_IsReplaying()) { \
      res = call; \
   } \
   res = LogSyscall(res); \
   res; \
})

static void
RdSockTsockOpen(struct SockStruct *sockp, const int isPair)
{
   ASSERT(!VCPU_IsReplaying());
   //ASSERT_UNIMPLEMENTED(sockp->protocol == 0);

   int protocol;

   switch (sockp->family) {
   case PF_INET:
   case PF_INET6:
   case PF_UNIX:
      /* XXX: how do we handle port numbers for these? */
      //WARN_UNIMPLEMENTED(0);
   /* wget uses NETLINK/ROUTE (I think for BSD socket compatibility) */
   case PF_NETLINK: 
      {
         switch (sockp->type) {
         case SOCK_DGRAM:
            protocol = TSOCK_PROTOCOL_UDP;
            break;
         case SOCK_STREAM:
            protocol = TSOCK_PROTOCOL_TCP;
            break;
         case SOCK_RAW:
            protocol = TSOCK_PROTOCOL_RAW;
            break;
         case SOCK_RDM:
            protocol = TSOCK_PROTOCOL_RDM;
            break;
         case SOCK_SEQPACKET:
            protocol = TSOCK_PROTOCOL_SEQPACKET;
            break;
         case SOCK_PACKET:
            protocol = TSOCK_PROTOCOL_PACKET;
            break;
         default:
            ASSERT_UNIMPLEMENTED(0);
            break;
         }
      }
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   if (!VCPU_IsReplaying()) {
       /* Socketpair fds are accessible only within the vkernel domain
        * (creator and descendants) so we can be sure that both endpoints
        * are vkernel tasks, and hence definitely tagged. */
      ASSERT(protocol > 0);
      TSock_Open(&sockp->tsock, sockp->fd, TSOCK_FAMILY_SOCKET, protocol,
            isPair ? TSOCK_PEER_TAGS : TSOCK_PEER_UNKNOWN );
   }
}

static int      
RdSock_socket(struct SockStruct *sockp)
{
   int err;
   ulong args[3];


   args[0] = sockp->family;
   args[1] = sockp->type;
   args[2] = sockp->protocol;

   DEBUG_MSG(5, "family=0x%x type=0x%x protocol=0x%x\n",
         args[0], args[1], args[2]);

   sockp->orig_fd = err = LOG_CALL_RESULT(syscall(SYS_socketcall, SYS_SOCKET, 
            args));

   if (VCPU_IsReplaying()) {
      sockp->fd = -1;
   } else {
      sockp->fd = sockp->orig_fd;
      RdSockTsockOpen(sockp, 0);
   }

   return err;
}

static int      
RdSock_socketpair(struct SockStruct *sock1, struct SockStruct *sock2)
{
   int err, rfd[2];
   ulong args[4];

   ASSERT(sock1->family == sock2->family);
   ASSERT(sock1->type == sock2->type);
   ASSERT(sock1->protocol == sock2->protocol);

   args[0] = sock1->family;
   args[1] = sock1->type;
   args[2] = sock1->protocol;
   args[3] = (ulong) rfd;

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_socketcall, SYS_SOCKETPAIR, args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_socketpair) {
            entryp->ret = err;
            entryp->rfd[0] = rfd[0];
            entryp->rfd[1] = rfd[1];
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_socketpair) {
         err = entryp->ret;
         rfd[0] = entryp->rfd[0];
         rfd[1] = entryp->rfd[1];
      } END_WITH_LOG_ENTRY(0);
   }

   sock1->orig_fd = rfd[0];
   sock2->orig_fd = rfd[1];
   if (VCPU_IsReplaying()) {
      sock1->fd = -1;
      sock2->fd = -1;
   } else {
      sock1->fd = sock1->orig_fd;
      sock2->fd = sock2->orig_fd;
      RdSockTsockOpen(sock1, 1);
      RdSockTsockOpen(sock2, 1);
   }

   return err;
}

struct AcceptRetStruct {
   int *klen;
   struct sockaddr *kaddr;
};


#if PRODUCT
#error "XXX"
// XXX: should call TSock_Accept, which should register new
// connection's port.
#endif
static int      
RdSock_accept(struct SockStruct *sockp, struct SockStruct *asockp,
      struct sockaddr *kpeer_sockaddr, int *kpeer_addrlen)
{
   int err;
   ulong args[3] = { sockp->fd, (ulong) kpeer_sockaddr, 
      (ulong) kpeer_addrlen };
   struct SyscallArgs sa = { .eax = SYS_socketcall, .ebx = SYS_ACCEPT, 
      .ecx = (ulong)args };
   /* XXX: we no longer need this. Just use args directly. */
   struct AcceptRetStruct ar = { .kaddr = kpeer_sockaddr, 
      .klen = kpeer_addrlen };

   /* XXX: should be in ReadDet_accept() */
   do {
      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      err = Sched_BlockingRealSyscall(NULL, &sa);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_sock_accept) {
            entryp->ret = err;
            if (!SYSERR(err)) {
               entryp->len = *(ar.klen);
               memcpy(entryp->addr, ar.kaddr, *(ar.klen));
            }
         } END_WITH_LOG_ENTRY(0);
      } else if (VCPU_IsReplaying()) {
         DO_WITH_LOG_ENTRY(sys_sock_accept) {
            err = entryp->ret;
            if (!SYSERR(err)) {
               *(ar.klen) = entryp->len;
               memcpy(ar.kaddr, entryp->addr, *(ar.klen));
            }
         } END_WITH_LOG_ENTRY(0);
      }
   } while (err == -EINTR && !Task_TestSigPending(current, 1));

   asockp->orig_fd = err;
   if (VCPU_IsReplaying()) {
      asockp->fd = -1;
   } else {
      asockp->fd = asockp->orig_fd;
      RdSockTsockOpen(asockp, 0);
   }

   /* See BUG #5 */
   return err == -EINTR ? -ERESTARTSYS : err;
}


static int      
RdSock_bind(struct SockStruct *sockp, const struct sockaddr *kmyaddrp, 
      int addrlen)
{
   int err;

   err = LOG_CALL_RESULT(TSock_Bind(&sockp->tsock, kmyaddrp, addrlen));

   return err;
}
#if 0
static int      
RdSock_bind(struct SockStruct *sockp, const struct sockaddr *kmyaddrp, 
      int addrlen)
{
   int err;
   ulong args[3] = { sockp->fd, (ulong)kmyaddrp, addrlen };

   // XXX: replace with a TSock_Bind call, which is a cleaner
   // abstraction.
   err = LOG_SYSCALL(SYS_socketcall, SYS_BIND, args);

   if (!VCPU_IsReplaying() && !SYSERR(err)) {
      TSock_Register(&sockp->tsock, "bind");
   }

   return err;
}
#endif

static int      
RdSock_listen(struct SockStruct *sockp, int backlog)
{
   int err;
   ulong args[2] = { sockp->fd, backlog };

   // XXX: do we need to do anything here with tagging here?
   // Presumably the socket port should already be registested via a
   // preceding sys_bind() call.
   // ASSERT(Tsock_PortIsRegistered(s_info));
   err = LOG_CALL_RESULT(syscall(SYS_socketcall, SYS_LISTEN, args));

   return err;
}

struct ConnectArgs {
   tsock_socket_info_t *s_info;
   const struct sockaddr *remote_addr_p;
   const int addr_len;
};


static int
TSockConnectWork(void *arg)
{
   const struct ConnectArgs *arg_p = (struct ConnectArgs *)arg;

   return TSock_Connect(arg_p->s_info, arg_p->remote_addr_p, arg_p->addr_len);
}

static int      
RdSock_connect(struct SockStruct *sockp, struct sockaddr *kservaddrp, 
      int addr_len)
{
   int err;
   struct ConnectArgs args = { .s_info = &sockp->tsock,
      .remote_addr_p = kservaddrp, .addr_len = addr_len };

   do {
      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      err = Sched_BlockingRealSyscall(&TSockConnectWork, &args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      } else if (VCPU_IsReplaying()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            err = entryp->ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } while (err == -EINTR && !Task_TestSigPending(current, 1));

   /* See BUG #5 */
   return err == -EINTR ? -ERESTARTSYS : err;
}

#if 0
static int      
RdSock_connect(struct SockStruct *sockp, struct sockaddr *kservaddrp, 
      int addrlen)
{
   int err;
   ulong args[3] = { sockp->fd, (ulong) kservaddrp, addrlen };
   struct SyscallArgs sa = { .eax = SYS_socketcall, 
      .ebx = SYS_CONNECT, .ecx = (ulong)args };

   do {
      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      err = Sched_BlockingRealSyscall(NULL, &sa);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      } else if (VCPU_IsReplaying()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            err = entryp->ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } while (err == -EINTR && !Task_TestSigPending(current, 1));

   if (!SYSERR(err)) {
      // We need to open here rather than on sys_socket, because a socket 
      // fd may change association multiple times.

      if (!VCPU_IsReplaying()) {
         RdSockTsockOpen(sockp, 0);
         TSock_OnConnect(sockp->tsock, kservaddrp, addrlen);
      }
   }

   /* See BUG #5 */
   return err == -EINTR ? -ERESTARTSYS : err;
}
#endif

static int      
RdSock_shutdown(struct SockStruct *sockp, int how)
{
   ulong args[2] = { sockp->fd, how };

   return LOG_CALL_RESULT(syscall(SYS_socketcall, SYS_SHUTDOWN, args));
}


static int
RdSock_getname(struct SockStruct *sockp, struct sockaddr * kaddr, int * klen, 
      int wantsPeerName)
{
   int res;
   ulong args[3] = { sockp->fd, (ulong) kaddr, (ulong) klen };

   ASSERT(kaddr);
   ASSERT(klen);

   if (!VCPU_IsReplaying()) {
      res = syscall(SYS_socketcall, 
            wantsPeerName ? SYS_GETPEERNAME : SYS_GETSOCKNAME, args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_sock_getname) {
            entryp->ret = res;
            entryp->len = *klen;
            memcpy(entryp->addr, kaddr, *klen);
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(sys_sock_getname) {
         res = entryp->ret;
         *klen = entryp->len;
         memcpy(kaddr, entryp->addr, *klen);
      } END_WITH_LOG_ENTRY(0);
   }

   return res;
}

static int
RdSock_sockopt(struct SockStruct *sockp, int level, int optname, 
      char *koptval, int *koptlen, int isGet)
{
   int res;
   ulong args[5] = { sockp->fd, level, optname, (ulong) koptval, 
      (ulong) (isGet ? (ulong) koptlen : *koptlen) };

   ASSERT(koptval);
   ASSERT(koptlen);

   if (!VCPU_IsReplaying()) {
      res = syscall(SYS_socketcall, 
            isGet ? SYS_GETSOCKOPT : SYS_SETSOCKOPT, args);
      

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_sock_sockopt) {
            entryp->ret = res;
            entryp->optlen = *koptlen;
            ASSERT(*koptlen <= sizeof(entryp->optval));
            memcpy(entryp->optval, koptval, *koptlen);
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(sys_sock_sockopt) {
         res = entryp->ret;
         *koptlen = entryp->optlen;
         ASSERT(*koptlen <= sizeof(entryp->optval));
         memcpy(koptval, entryp->optval, *koptlen);
      } END_WITH_LOG_ENTRY(0);
   }

   return res;
}


const struct SockOps RdSock_Sops = {
   .socket =      &RdSock_socket,
   .bind =        &RdSock_bind,
   .connect =     &RdSock_connect,
   .listen =      &RdSock_listen,
   .accept =      &RdSock_accept,
   .socketpair =  &RdSock_socketpair,
   .getname =     &RdSock_getname,
   .sockopt =     &RdSock_sockopt,
   .shutdown =    &RdSock_shutdown,
};

/* 
 * ----------------------------------------
 *
 * Inode ops.
 *
 * ----------------------------------------
 */

static long
RdSock_lookup(struct InodeStruct *dir, struct DentryStruct *dentryp)
{
   /* We don't expect lookups of socks, so this is a no-op. */
   return -ENOENT;
}

static long
RdSock_create(struct InodeStruct *dir, struct DentryStruct *dentryp, 
      int mode, void *data)
{
   int err = 0;
   struct SockStruct *sockp = (struct SockStruct *)data;
   struct InodeStruct *inodp;

   /* We assume that the sockp has been initialized already. */
   ASSERT(sockp->orig_fd >= 0);
   if (!VCPU_IsReplaying()) {
      ASSERT(sockp->orig_fd == sockp->fd);
   }

   inodp = Inode_Get(dir->sb, dentryp->name, sockp->ino);
   inodp->data = data;
   ASSERT(sockp->ops);

   /* Make sure we aren't grabbing some existing inode. 
    * This inode should be brand new (and the INode_Get
    * should've missed in the inode cache). */
   ASSERT(inodp->count == 1);

   Dentry_Instantiate(dentryp, inodp);

   return err;
}

static long
RdSock_lstat(struct DentryStruct *dentry, struct kstat64 *statp)
{
   const struct SockStruct *sockp;

   sockp = Sock_GetStruct(Dentry_Inode(dentry));
   ASSERT(!IS_ERR(sockp));

   return ReadDet_fstat(sockp->fd, statp);
}

/* 
 * ----------------------------------------
 *
 * File ops.
 *
 * ----------------------------------------
 */

static int
RdSock_open(struct FileStruct *filp, int mode)
{
   const struct SockStruct *sockp;

   sockp = Sock_GetStruct(File_Inode(filp));
   ASSERT(!IS_ERR(sockp));

   /* Deterministic epoll rfd<-->vfd translation relies on filp->orig_rfd
    * being filled in. */

   filp->orig_rfd = sockp->orig_fd;
   filp->rfd = sockp->fd;

   return 0;
}

static void
RdSock_release(struct FileStruct *filp)
{
#if DEBUG
   ASSERT(filp->orig_rfd >= 0);
   if (VCPU_IsReplaying()) {
      ASSERT(filp->rfd == -1);
   }
#endif
}

static ssize_t
RdSock_io(const int ioReqFlags,
      const struct FileStruct *filp, struct msghdr *kmsgp, 
      const int flags, loff_t pos)
{
   long err;
   const struct SockStruct *sockp;

   sockp = Sock_GetStruct(File_Inode(filp));
   ASSERT(!IS_ERR(sockp));

   err = ReadDet_io(ioReqFlags, filp, sockp->fd, kmsgp, flags, IOF_SOCK, pos);

   /* See BUG #5 */
   return err == -EINTR ? -ERESTARTSYS : err;
}

static int 
RdSock_fsync(struct FileStruct *filp, int datasync)
{
   const struct SockStruct *sockp;

   sockp = Sock_GetStruct(File_Inode(filp));
   ASSERT(!IS_ERR(sockp));

   return ReadDet_fsync(sockp->fd, datasync);
}

static int
RdSock_setfl(struct FileStruct *filp, int flags)
{
   const struct SockStruct *sockp;

   sockp = Sock_GetStruct(File_Inode(filp));
   ASSERT(!IS_ERR(sockp));

   return ReadDet_setfl(sockp->fd, flags);
}

static long
RdSock_fstat(struct FileStruct *filp, struct kstat64 *statp)
{
   const struct SockStruct *sockp;

   sockp = Sock_GetStruct(File_Inode(filp));
   ASSERT(!IS_ERR(sockp));

   return ReadDet_fstat(sockp->fd, statp);
}

static int
RdSock_select(const struct FileStruct *filP, const int is_read, 
      const int should_block)
{
   const struct SockStruct *sockp = Sock_GetStruct(File_Inode(filP));
   ASSERT(!IS_ERR(sockp));

   return Select_DefaultTaggedFop(&sockp->tsock, is_read, should_block);
}

static const struct FileOps RdSock_Fops = {
   .open =     &RdSock_open,
   .release =  &RdSock_release,
   .llseek =   &no_llseek,
   .io =       &RdSock_io,
   .fsync =    &RdSock_fsync,
   .setfl =    &RdSock_setfl,
   .fstat =    &RdSock_fstat,
   .select =   &RdSock_select,
};

static const struct InodeOps RdSock_Iops = {
   .lookup =   &RdSock_lookup,
   .create =   &RdSock_create,
   .lstat =    &RdSock_lstat,
};

int
RdSock_no_open(struct FileStruct *filp, int mode)
{
   return -ENXIO;
}

/* Used for open()s on SOCK files. */
const struct FileOps BadSock_Fops = {
   .open = RdSock_no_open,
};

/* 
 * ----------------------------------------
 *
 * Superblock ops.
 *
 * ----------------------------------------
 */

struct InodeStruct *
SockFs_alloc_inode(struct SuperBlockStruct *sb)
{
   struct InodeStruct *inodp;

   inodp = Inode_GenericAlloc(sb);
   inodp->i_op = &RdSock_Iops;
   inodp->f_op = &RdSock_Fops;
   inodp->major = InodeMajor_Sock;

   return inodp;
}

void
SockFs_free_inode(struct InodeStruct *inodp)
{
   ASSERT(inodp);
   struct SockStruct *sockp;

   sockp = Sock_GetStruct(inodp);
   ASSERT(!IS_ERR(sockp));

   /* Note that we free in the destory callback, yet the sock
    * struct was not allcoated in the create callback. This
    * is because we chose to initialize the sock struct (establish
    * the real sock fd) before creating the inode. */
   Sock_Free(sockp);

   Inode_GenericFree(inodp);
}

void
SockFs_drop_inode(struct InodeStruct *inodp)
{
   int err;
   struct SockStruct *sockp;

   sockp = Sock_GetStruct(inodp);
   ASSERT(!IS_ERR(sockp));

   ASSERT(sockp->orig_fd >= 0);
   if (!VCPU_IsReplaying()) {
      ASSERT(sockp->fd == sockp->orig_fd);
      ASSERT(sockp->fd >= 0);
      err = SysOps_Close(sockp->fd);
      ASSERT(!SYSERR(err));

      TSock_Close(&sockp->tsock);
   } else {
      ASSERT(sockp->fd == -1);
   }
}

static struct SuperBlockOps SockFs_SbOps = {
   .alloc_inode =    &SockFs_alloc_inode,
   .free_inode =     &SockFs_free_inode,
   .drop_inode =     &SockFs_drop_inode,
};

SHAREDAREA struct SuperBlockStruct *sbSock = NULL;

struct SuperBlockStruct *
SockFs_GetSb()
{
   return SuperBlock_AllocPseudo("sockfs", &SockFs_SbOps);
}

static int
SockFs_Init()
{
   DEBUG_MSG(5, "SockFs\n");

   if (!VCPU_IsReplaying()) {
       TSock_Init(session.opt_enable_ipc_tagging);
   }
   sbSock = SockFs_GetSb();
   return 0;
}

FS_INITCALL(SockFs_Init);
