#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "vkernel/public.h"
#include "vkernel/fs/private.h"
#include "private.h"

/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[18]={AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
				AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
				AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)};
#undef AL

/**
 *	move_addr_to_kernel	-	copy a socket address into kernel space
 *	@uaddr: Address in user space
 *	@kaddr: Address in kernel space
 *	@ulen: Length in user space
 *
 *	The address is copied into kernel space. If the provided address is
 *	too long an error code of -EINVAL is returned. If the copy gives
 *	invalid addresses -EFAULT is returned. On a success 0 is returned.
 */

static int 
move_addr_to_kernel(void __user *uaddr, int ulen, void *kaddr)
{
	if(ulen<0||ulen>MAX_SOCK_ADDR)
		return -EINVAL;
	if(ulen==0)
		return 0;

   if(Task_CopyFromUser(kaddr,uaddr,ulen))
      return -EFAULT;

	return 0;
}

/**
 *	move_addr_to_user	-	copy an address to user space
 *	@kaddr: kernel space address
 *	@klen: length of address in kernel
 *	@uaddr: user space address
 *	@ulen: pointer to user length field
 *
 *	The value pointed to by ulen on entry is the buffer length available.
 *	This is overwritten with the buffer space used. -EINVAL is returned
 *	if an overlong buffer is specified or a negative buffer size. -EFAULT
 *	is returned if either the buffer or the length field are not
 *	accessible.
 *	After copying the data up to the limit the user specifies, the true
 *	length of the data is written over the length limit the user
 *	specified. Zero is returned for a success.
 */
 
static int 
move_addr_to_user(void *kaddr, int klen, void __user *uaddr, int __user *ulen)
{
	int err;
	int len;

	if((err=__get_user(len, ulen)))
		return err;
	if(len>klen)
		len=klen;
	if(len<0 || len> MAX_SOCK_ADDR)
		return -EINVAL;
	if(len)
	{
      D__;
		if(Task_CopyToUser(uaddr,kaddr,len))
			return -EFAULT;
	}
   D__;
	/*
	 *	"fromlen shall refer to the value before truncation.."
	 *			1003.1g
	 */
	return __put_user(klen, ulen);
}


/* Could be static but not to be consistent with Sock_Free. */
struct SockStruct*
Sock_Alloc(int family, int type, int protocol)
{
   struct SockStruct *sockp;

   sockp = SharedArea_Malloc(sizeof(*sockp));

   sockp->family = family;
   sockp->type = type;
   sockp->protocol = protocol;
   sockp->fd = -1;
   sockp->ops = &RdSock_Sops;

   return sockp;
}

/* Not static b/c called when inode is dropped (in drop_inode VFS op). */
void
Sock_Free(struct SockStruct *sockp)
{
   memset(sockp, 0, sizeof(*sockp));
   sockp->fd = -1;

   SharedArea_Free(sockp, sizeof(*sockp));
}

struct SockStruct *
Sock_GetStruct(struct InodeStruct *inodp)
{
   struct SockStruct *sockp;

   ASSERT(inodp);

   if (Inode_GetMajor(inodp) != InodeMajor_Sock) {
      sockp = ERR_PTR(-ENOTSOCK);
      goto out;
   }

   sockp = (struct SockStruct *) inodp->data;
   ASSERT(sockp);

out:
   return sockp;
}

/* 
 * Opens a new socket and returns a vfd for it. 
 * We expect sockp to be initialized with a valid file-descriptor.
 * This allows us to avoid blocking within the VFS create()
 * callback (which we don't want to do because we are the
 * parent lock while doing so).
 */

/* 0 is invalid, and 1 is reserved for the root inode. */
static SHAREDAREA uint sockGen = 2;

static int
SockOpen(struct SockStruct *sockp)
{
   int err;
   struct DentryStruct *root = sbSock->root, *dentryp;
   struct FileStruct *filp;
   char name[32];

#if DEBUG
   ASSERT(sockp->orig_fd >= 0);
   if (!VCPU_IsReplaying()) {
      ASSERT(sockp->fd == sockp->orig_fd);
   }
#endif

   Inode_Lock(root->inode);

   sockp->ino = sockGen++;

   snprintf(name, sizeof(name), "socket:%lu", sockp->ino);
   dentryp = Dentry_Open(root, name, O_CREAT | O_EXCL);
   if (IS_ERR(dentryp)) {
      err = PTR_ERR(dentryp);
      goto out;
   }

   err = VFS_create(root->inode, dentryp, 0, (void*) sockp);
   if (err) {
      goto out_putd;
   }

   filp = File_DentryOpen(dentryp, O_RDWR, 0);
   if (IS_ERR(filp)) {
      err = PTR_ERR(filp);
      goto out_putd;
   }

   err = File_GetUnusedFd();
   if (err < 0) {
      goto out_putf;
   }

   File_FdInstall(err, filp);

   goto out_putd;

out_putf:
   File_Close(filp);
out_putd:
   /* The sock struct will be freed by drop_inode superblock op,
    * if the File_DentryOpen failed. */
   Dentry_Put(dentryp);
out:
   Inode_Unlock(root->inode);
   return err;
}

/*
 * Socket pairs are different from pipes in that they aren't backed up by
 * an inode. If task 1 writes A into a socketpair fd 0 and then reads from the same
 * fd, then it will not necesarily read A again. But if task 2 read from fd 1
 * then he will see A. Thus we handle socketpairs just like we handle
 * sockets rather than pipes.
 */
static int
SockOpenPair(struct SockStruct *sock1, struct SockStruct *sock2, int *fd)
{
   int err;

   ASSERT(sock1 && sock2);
   ASSERT(fd);

   err = SockOpen(sock1);
   if (err < 0) {
      goto out;
   }
   fd[0] = err;

   err = SockOpen(sock2);
   if (err < 0) {
      goto out;
   }
   fd[1] = err;

   ASSERT(fd[0] != fd[1]);

   err = 0;

out:
   return err;
}



int
Sock_socket(struct SockStruct *sockp)
{
	int err;

	if (!sockp->ops || !sockp->ops->socket) {
      D__;
		err = -EINVAL;
		goto out;
	}

   err = sockp->ops->socket(sockp);

out:
	return err;
}

static long 
sys_socket(int family, int type, int protocol)
{
   int err;
   struct SockStruct *sockp;

   sockp = Sock_Alloc(family, type, protocol);

   err = Sock_socket(sockp);
   if (err < 0) {
      goto error_out;
   }

   err = SockOpen(sockp);
   if (err < 0) {
      goto error_out;
   }

   return err;

error_out:
   Sock_Free(sockp);
   sockp = NULL;
   return err;
}

static long
Sock_socketpair(struct SockStruct *sock1p, struct SockStruct *sock2p)
{
	int err;

	if (!sock1p->ops || !sock1p->ops->socketpair) {
		err = -EINVAL;
		goto out;
	}

   err = sock1p->ops->socketpair(sock1p, sock2p);

out:
	return err;

}

static long 
sys_socketpair(int family, int type, int protocol, int __user *usockvec)
{
   int err;
   int fd[2] = { -1, -1};
   struct SockStruct *sock1, *sock2;

   sock1 = Sock_Alloc(family, type, protocol);
   sock2 = Sock_Alloc(family, type, protocol);

   err = Sock_socketpair(sock1, sock2);
   if (err < 0) {
      goto error_out;
   }

   err = SockOpenPair(sock1, sock2, fd);
   if (err < 0) {
      goto error_out;
   }

   DEBUG_MSG(5, "fd[0]=%d fd[1]=%d\n", fd[0], fd[1]);

   ASSERT(fd[0] != fd[1]);
   ASSERT(fd[0] != -1);
   ASSERT(fd[1] != -1);

   err = __put_user(fd[0], &usockvec[0]); 
   if (err) {
      goto close_out;
   }

   err = __put_user(fd[1], &usockvec[1]);
   if (err) {
      goto close_out;
   }

   return err;
close_out:
   sys_close(fd[0]);
   sys_close(fd[1]);
error_out:
   Sock_Free(sock1);
   Sock_Free(sock2);
   return err;
}

static long
Sock_bind(struct SockStruct *sockp, const struct sockaddr *kmyaddrp, int addrlen)
{
	int err;

	if (!sockp->ops || !sockp->ops->bind) {
		err = -EINVAL;
		goto out;
	}

   err = sockp->ops->bind(sockp, kmyaddrp, addrlen);

out:
	return err;
}


static long
sys_bind(int fd, const struct sockaddr __user *umyaddr, int addrlen)
{
	struct FileStruct *filp;
	int err = -EBADF;
	char address[MAX_SOCK_ADDR] = { 0 };
   struct SockStruct *sockp;

	filp = File_Get(fd);
   if (!filp) {
      goto out;
   }

   sockp = Sock_GetStruct(File_Inode(filp));
   if (IS_ERR(sockp)) {
      err = PTR_ERR(sockp);
      goto out_putf;
   }

   if ((err = move_addr_to_kernel((struct sockaddr __user *)umyaddr, addrlen, address)) >= 0) {
      err = Sock_bind(sockp, (struct sockaddr *)address, addrlen);
   }

out_putf:
   File_Put(filp);
out:
   return err;
}

static long
Sock_connect(struct SockStruct *sockp, struct sockaddr *kservaddrp, int addrlen)
{
   int err;
   int wasInterrupted = -1, isSignalPending = -1;

	if (!sockp->ops || !sockp->ops->connect) {
		err = -EINVAL;
		goto out;
	}

   do {
      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      err = sockp->ops->connect(sockp, kservaddrp, addrlen);

      wasInterrupted = (err == -EINTR);
      isSignalPending = Task_TestSigPending(current, 1);
   } while (wasInterrupted && !isSignalPending);

out:
	return err;
}

static long
sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
	int err = -EBADF;
	char address[MAX_SOCK_ADDR] = { 0 };
	struct FileStruct *filp;
   struct SockStruct *sockp;

	filp = File_Get(fd);
   if (!filp) {
      goto out;
   }

   sockp = Sock_GetStruct(File_Inode(filp));
   if (IS_ERR(sockp)) {
      err = PTR_ERR(sockp);
      goto out_putf;
   }

   if ((err = move_addr_to_kernel(uservaddr, addrlen, address)) >= 0) {
#if DEBUG
      struct sockaddr_un * sa = (struct sockaddr_un *) address;
      if (sa->sun_family == AF_UNIX) {
         DEBUG_MSG(5, "sun_path=%s\n", sa->sun_path);
      }
#endif
      err = Sock_connect(sockp, (struct sockaddr *)address, addrlen);
   }

out_putf:
   File_Put(filp);
out:
   return err;
}

static long
Sock_listen(struct SockStruct *sockp, int backlog)
{
   int err;

	if (!sockp->ops || !sockp->ops->listen) {
		err = -EINVAL;
		goto out;
	}

   err = sockp->ops->listen(sockp, backlog);

out:
	return err;
}

static long 
sys_listen(int fd, int backlog)
{
	int err = -EBADF;
   struct FileStruct *filp;
   struct SockStruct *sockp;

   filp = File_Get(fd);
   if (!filp) {
      goto out;
   }

   sockp = Sock_GetStruct(File_Inode(filp));
   if (IS_ERR(sockp)) {
      err = PTR_ERR(sockp);
      goto out_putf;
   }

   err = Sock_listen(sockp, backlog);

out_putf:
   File_Put(filp);
out:
	return err;
}

static long
Sock_accept(struct SockStruct *sockp, struct SockStruct *asockp, 
            struct sockaddr *kpeer_sockaddr, int *kpeer_addrlen)
{
	int err;

	if (!sockp->ops || !sockp->ops->accept) {
		err = -EINVAL;
		goto out;
	}

   err = sockp->ops->accept(sockp, asockp, kpeer_sockaddr, kpeer_addrlen);

out:
   return err;
}

static long 
sys_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
{
   int err = -EBADF, vfd = -1;
	struct FileStruct *filp;
   struct SockStruct *sockp, *asockp;
   int len = MAX_SOCK_ADDR;
   char address[MAX_SOCK_ADDR] = { 0 };

   DEBUG_MSG(5, "upeer_sockaddr=0x%x upeer_addrlen=0x%x\n", 
         upeer_sockaddr, upeer_addrlen);

	filp = File_Get(fd);

   if (!filp) {
      goto out;
   }

   sockp = Sock_GetStruct(File_Inode(filp));
   if (IS_ERR(sockp)) {
      err = PTR_ERR(sockp);
      goto out_putf;
   }

   asockp = Sock_Alloc(sockp->family, sockp->type, sockp->protocol);

   err = Sock_accept(sockp, asockp, (struct sockaddr*)address, &len);
   if (err < 0) {
      goto out_frees;
   }

   err = SockOpen(asockp);
   if (err < 0) {
      goto out_frees;
   }
   vfd = err;

   if (upeer_sockaddr) {
      err = move_addr_to_user(address, len, upeer_sockaddr, upeer_addrlen);
      if (err < 0) {
         goto out_close;
      }
   }

   err = vfd;

   goto out_putf;

out_close:
   sys_close(vfd);
out_frees:
   Sock_Free(asockp);
out_putf:
   File_Put(filp);
out:
	return err;
}

static int
SockIO(int isRead, int fd, struct msghdr *kmsgp, unsigned flags)
{
   struct FileStruct *filp;
   ssize_t err = -EBADF;

   filp = File_Get(fd);
   if (filp) {

      /* XXX: must we order accesses though the file object for sockets? */
      File_Lock(filp);

      /* Will invoke filp->f_op->io. */
      err = VFS_io(isRead ? IOREQ_READ : 0, filp, kmsgp, 
            flags, NULL);

      File_Unlock(filp);

      File_Put(filp);
   }

   return err;
}

static long
sys_sendto(int fd, void __user * buff, size_t len, unsigned flags,
      struct sockaddr __user *addr, int addr_len)
{
   int err;
   char address[MAX_SOCK_ADDR] = { 0 };
   struct msghdr kmsg;
   struct iovec vec = { .iov_base = (char*) buff, .iov_len = len };

   kmsg.msg_name = NULL;
   kmsg.msg_namelen = 0;
   kmsg.msg_iov = &vec;
   kmsg.msg_iovlen = 1;
   kmsg.msg_control = NULL;
   kmsg.msg_controllen = 0;
   kmsg.msg_flags = 0;
	if (addr) {
		err = move_addr_to_kernel(addr, addr_len, address);
		if (err < 0)
			goto out;
		kmsg.msg_name=address;
		kmsg.msg_namelen=addr_len;
	}

   err = SockIO(0, fd, &kmsg, flags);

out:
   return err;
}

static long
sys_send(int fd, void __user * buff, size_t len, uint flags)
{
   return sys_sendto(fd, buff, len, flags, NULL, 0);
}

#if 1
static int
CopyMsgHdrFromUser(struct msghdr *kmsgP, const struct msghdr __user *umsgP)
{
   int err = 0, nrSegs;
   size_t vecSz;
   struct iovec *iovP;

   ASSERT_KPTR(kmsgP);

   if (Task_CopyFromUser(kmsgP, umsgP, sizeof(*umsgP))) {
      err = -EFAULT;
      goto out;
   }

   nrSegs = kmsgP->msg_iovlen;
   ASSERT_UNIMPLEMENTED(nrSegs > 0);
   vecSz = nrSegs * sizeof(struct iovec);

   iovP = malloc(vecSz);

   ASSERT_UNIMPLEMENTED(kmsgP->msg_iov);
   if (Task_CopyFromUser(iovP, kmsgP->msg_iov, vecSz)) {
      err = -EFAULT;
      goto out;
   }

   kmsgP->msg_iov = iovP;
   ASSERT_KPTR(kmsgP->msg_iov);

out:
   return err;
}

static void
FreeMsgHdr(struct msghdr *kmsgP)
{
   ASSERT_KPTR(kmsgP);
   ASSERT_KPTR(kmsgP->msg_iov);
   ASSERT(kmsgP->msg_iovlen > 0);

   free(kmsgP->msg_iov);
   kmsgP->msg_iov = NULL;
}
#endif

static long 
sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
   int err;
   struct msghdr kmsg;
   char address[MAX_SOCK_ADDR] = { 0 };
   struct sockaddr __user *addr;

   if ((err = CopyMsgHdrFromUser(&kmsg, msg))) {
      goto out;
   }

   addr = kmsg.msg_name;

	if (addr) {
		err = move_addr_to_kernel(addr, kmsg.msg_namelen, address);
		if (err < 0)
			goto out;
		kmsg.msg_name=address;
	}


   err = SockIO(0, fd, &kmsg, flags);

   FreeMsgHdr(&kmsg);

out:
   return err;
}

static long 
sys_recvfrom(int fd, void __user * ubuf, size_t size, unsigned flags,
			    struct sockaddr __user *addr, int __user *addr_len)
{
   /* Only a portion of this buffer may be used, meaning the rest will
    * be non-deterministic. By zeroing, we make it entirely
    * deterministic and that makes our determinism checks in CopyToUser
    * happy. */
	char address[MAX_SOCK_ADDR] = { 0 };
   struct msghdr kmsg;
   struct iovec vec = { .iov_base = (char*) ubuf, .iov_len = size };
   int err;

   kmsg.msg_name = address;
   kmsg.msg_namelen = MAX_SOCK_ADDR;
   kmsg.msg_iov = &vec;
   kmsg.msg_iovlen = 1;
   kmsg.msg_control = NULL;
   kmsg.msg_controllen = 0;
   kmsg.msg_flags = 0;

   err = SockIO(1, fd, &kmsg, flags);

   if(err >= 0 && addr != NULL) {
      int err2;
      D__;
      err2 = move_addr_to_user(address, kmsg.msg_namelen, addr, addr_len);
      D__;
      if(err2<0)
         err=err2;
   }

   return err;
}

static long 
sys_recv(int fd, void __user * ubuf, size_t size, uint flags)
{
	return sys_recvfrom(fd, ubuf, size, flags, NULL, NULL);
}

static long 
sys_recvmsg(int fd, struct msghdr __user *msg, unsigned int flags)
{
   int err;
#if 0
   err = SockIO(1, fd, msg, flags);
#else
   char address[MAX_SOCK_ADDR] = { 0 };
   struct msghdr kmsg;
   struct sockaddr __user *addr;
   int __user *addr_len;

   if ((err = CopyMsgHdrFromUser(&kmsg, msg))) {
      goto out;
   }

   addr = kmsg.msg_name;
   addr_len = (int __user *)&msg->msg_namelen;

   kmsg.msg_name = address;
   kmsg.msg_namelen = MAX_SOCK_ADDR;

   err = SockIO(1, fd, &kmsg, flags);

   if (err < 0) {
      goto free_out;
   }

   if(addr != NULL) {
      int err2;
      err2 = move_addr_to_user(address, kmsg.msg_namelen, addr, addr_len);
      if(err2<0) {
         err=err2;
         goto free_out;
      }
   }

   if (__put_user(kmsg.msg_flags, &msg->msg_flags)) {
      err = -EFAULT;
      goto free_out;
   }

   if (__put_user(kmsg.msg_controllen, &msg->msg_controllen)) {
      err = -EFAULT;
      goto free_out;
   }

free_out:
   FreeMsgHdr(&kmsg);
out:
#endif
   return err;
}


static long
Sock_shutdown(struct SockStruct *sockp, int how)
{
	int err;

	if (!sockp->ops || !sockp->ops->shutdown) {
		err = -EINVAL;
		goto out;
	}

   err = sockp->ops->shutdown(sockp, how);

out:
	return err;
}


static long 
sys_shutdown(int fd, int how)
{
   int err = -EBADF;
   struct FileStruct *filp;
   struct SockStruct *sockp;

   filp = File_Get(fd);
   if (!filp) {
      goto out;
   }

   sockp = Sock_GetStruct(File_Inode(filp));
   if (IS_ERR(sockp)) {
      err = PTR_ERR(sockp);
      goto out_putf;
   }

   /* Note that shutdown down the connection does NOT entail 
    * closing the fd. */
   err = Sock_shutdown(sockp, how);

out_putf:
   File_Put(filp);
out:
   return err;
}


static long
Sock_getname(struct SockStruct *sockp, struct sockaddr * kaddr, int * klen, 
             int wantsPeerName)
{
	int err;

	if (!sockp->ops || !sockp->ops->getname) {
		err = -EINVAL;
		goto out;
	}

   err = sockp->ops->getname(sockp, kaddr, klen, wantsPeerName);

out:
	return err;
}


static long
SockGetName(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len, 
            int wantsPeerName)
{
	int err = -EBADF, len = MAX_SOCK_ADDR;
   char address[MAX_SOCK_ADDR] = { 0 };
	struct FileStruct *filp;
   struct SockStruct *sockp;

	filp = File_Get(fd);
   if (!filp) { 
      goto out; 
   }

   sockp = Sock_GetStruct(File_Inode(filp));
   if (IS_ERR(sockp)) {
      err = PTR_ERR(sockp);
      goto out_putf;
   }

   err = Sock_getname(sockp, (struct sockaddr *)address, &len, wantsPeerName);
   if (SYSERR(err)) {
      goto out_putf;
   }

   err = move_addr_to_user(address, len, usockaddr, usockaddr_len);

out_putf:
   File_Put(filp);
out:
   return err;
}

static long
sys_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
   return SockGetName(fd, usockaddr, usockaddr_len, 0);
}

static long
sys_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
   return SockGetName(fd, usockaddr, usockaddr_len, 1);
}

static long
Sock_sockopt(struct SockStruct *sockp, int level, int optname, char *koptval, 
               int *koptlen, int isGet)
{
	int err;

	if (!sockp->ops || !sockp->ops->sockopt) {
		err = -EINVAL;
		goto out;
	}

   err = sockp->ops->sockopt(sockp, level, optname, koptval, koptlen, isGet);

out:
	return err;
}

static long
SockOpt(int fd, int level, int optname, char *koptval, int *koptlen, int isGet)
{
	int err = -EBADF;
	struct FileStruct *filp;
   struct SockStruct *sockp;

	filp = File_Get(fd);
   if (!filp) { 
      goto out; 
   }

   sockp = Sock_GetStruct(File_Inode(filp));
   if (IS_ERR(sockp)) {
      err = PTR_ERR(sockp);
      goto out_putf;
   }

   err = Sock_sockopt(sockp, level, optname, koptval, koptlen, isGet);

out_putf:
   File_Put(filp);
out:
   return err;
}

static long 
sys_setsockopt(int fd, int level, int optname, char __user *optval, int optlen)
{
   int err, koptlen;
   char koptval[MAX_OPTVAL_SIZE];

   koptlen = optlen;

   ASSERT_UNIMPLEMENTED(koptlen <= sizeof(koptval));

   if (Task_CopyFromUser(koptval, optval, koptlen)) {
      err = -EFAULT;
      goto out;
   }

   err = SockOpt(fd, level, optname, koptval, &koptlen, 0);

out:
   return err;
}

static long 
sys_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
   int err, koptlen;
   char koptval[MAX_OPTVAL_SIZE]; 

   if (__get_user(koptlen, optlen)) {
      err = -EFAULT;
      goto out;
   }
   if (koptlen < 0) {
      err = -EINVAL;
      goto out;
   }

   ASSERT_UNIMPLEMENTED_MSG(koptlen <= sizeof(koptval), "koptlen=%d", koptlen);

   err = SockOpt(fd, level, optname, koptval, &koptlen, 1);
   if (SYSERR(err)) {
      goto out;
   }

   ASSERT(koptlen >= 0);
   // Careful: the following put_user must happen even if koptlen ==
   // 0.
   ASSERT_COULDBE(koptlen == 0);
   if (Task_CopyToUser(optval, koptval, koptlen) ||
         __put_user(koptlen, optlen)) {

      err = -EFAULT;
      goto out;
   }

out:
   return err;
}

SYSCALLDEF(sys_socketcall, int call, ulong __user *args)
{
   ulong a[6];
   ulong a0, a1;
   int err;

   if(call<1||call>SYS_RECVMSG)
      return -EINVAL;

   if (Task_CopyFromUser(a, args, nargs[call])) {
      return -EFAULT;
   }

   DEBUG_MSG(5, "call=%d\n", call);

   a0 = a[0];
   a1 = a[1];

	switch(call) 
	{
		case SYS_SOCKET:
			err = sys_socket(a0,a1,a[2]);
			break;
		case SYS_BIND:
			err = sys_bind(a0,(struct sockaddr __user *)a1, a[2]);
			break;
		case SYS_CONNECT:
         /* Blocking call -- may return -EINTR */
			err = sys_connect(a0, (struct sockaddr __user *)a1, a[2]);
			break;
		case SYS_LISTEN:
			err = sys_listen(a0,a1);
			break;
		case SYS_ACCEPT:
         /* Blocking call -- may return -EINTR */
			err = sys_accept(a0,(struct sockaddr __user *)a1, (int __user *)a[2]);
			break;
		case SYS_GETSOCKNAME:
			err = sys_getsockname(a0,(struct sockaddr __user *)a1, (int __user *)a[2]);
			break;
		case SYS_GETPEERNAME:
			err = sys_getpeername(a0, (struct sockaddr __user *)a1, (int __user *)a[2]);
			break;
		case SYS_SOCKETPAIR:
			err = sys_socketpair(a0,a1, a[2], (int __user *)a[3]);
			break;
		case SYS_SEND:
			err = sys_send(a0, (void __user *)a1, a[2], a[3]);
			break;
		case SYS_SENDTO:
			err = sys_sendto(a0,(void __user *)a1, a[2], a[3],
					 (struct sockaddr __user *)a[4], a[5]);
			break;
		case SYS_RECV:
			err = sys_recv(a0, (void __user *)a1, a[2], a[3]);
			break;
		case SYS_RECVFROM:
			err = sys_recvfrom(a0, (void __user *)a1, a[2], a[3],
					   (struct sockaddr __user *)a[4], (int __user *)a[5]);
			break;
		case SYS_SENDMSG:
			err = sys_sendmsg(a0, (struct msghdr __user *) a1, a[2]);
			break;
		case SYS_RECVMSG:
			err = sys_recvmsg(a0, (struct msghdr __user *) a1, a[2]);
			break;
		case SYS_SHUTDOWN:
			err = sys_shutdown(a0,a1);
			break;
		case SYS_SETSOCKOPT:
			err = sys_setsockopt(a0, a1, a[2], (char __user *)a[3], a[4]);
			break;
		case SYS_GETSOCKOPT:
			err = sys_getsockopt(a0, a1, a[2], (char __user *)a[3], (int __user *)a[4]);
			break;
		default:
         ASSERT_UNIMPLEMENTED(0);
			err = -EINVAL;
			break;
	}

	return err;
}
