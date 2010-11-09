#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>
#include <assert.h>
#include <errno.h>
#include <syscall.h>
#include <signal.h>
#include <pthread.h>

#define __USE_GNU
#include <ucontext.h>

#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#include "libc_pointers.h"
#include "logger.h"
#include "log.h"
#include "sendlog.h"
#include "lwrap_sigs.h"
#include "lwrap.h"
#include "timers.h"

#include "logreplay.h"
#include "fast_logging.h"
#include "misc.h"
#include "errops.h"
#include "hexops.h"
#include "msg_coding.h"
#include "cosched.h"
#include "structops.h"

#define DEBUG 0
#define MAX_LENGTH 1024

int log_getsockopt(int  s, int level, int optname, void *optval, 
				   socklen_t *optlen) {
	int ret;
	int optval_int = 0;

	__CALL_LIBC(ret, getsockopt, s, level, optname, optval, optlen);

	if (optval) {
		switch (optname) {
		case SO_REUSEADDR:
			optval_int = *((int*)optval);
			break;
		default:
			fatal("unwrapped socket option\n");
			assert(0);
			break;
		}
	}

	advance_vclock();

	if (!LOG( __GETSOCKOPT_PAT, ret,
								optval_int, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getsockopt\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setsockopt(int s, int  level,  int  optname,  
				   const  void  *optval, socklen_t optlen) {
	int ret;

	__CALL_LIBC(ret, setsockopt, s, level, optname, optval, optlen);

	advance_vclock();

	if (!LOG( __SETSOCKOPT_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "setsockopt\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct protoent* log_getprotoent(void) {
	struct protoent* ret;
	struct protoent_flat flat;
	char flat_str[(sizeof(struct protoent_flat)*2) + 1];

	__CALL_LIBC(ret, getprotoent);

	advance_vclock();

	if (ret) {
		struct_encode_protoent(ret, &flat);
		hex_encode(&flat, flat_str, sizeof(struct protoent_flat));
	} else {
		strcpy(flat_str, "NULL");
	}

	if (!LOG( __GETPROTOENT_PAT, (long)ret,
								flat_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getprotoent\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct protoent* log_getprotobyname(const char *name) {
	struct protoent* ret;
	struct protoent_flat flat;
	char flat_str[(sizeof(struct protoent_flat)*2) + 1];

	__CALL_LIBC(ret, getprotobyname, name);

	advance_vclock();

	if (ret) {
		struct_encode_protoent(ret, &flat);
		hex_encode(&flat, flat_str, sizeof(struct protoent_flat));
	} else {
		strcpy(flat_str, "NULL");
	}

	if (!LOG( __GETPROTOBYNAME_PAT, (long)ret,
								flat_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getprotobyname\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct protoent* log_getprotobynumber(int proto) {
	struct protoent* ret;
	struct protoent_flat flat;
	char flat_str[(sizeof(struct protoent_flat)*2) + 1];

	__CALL_LIBC(ret, getprotobynumber, proto);

	advance_vclock();

	if (ret) {
		struct_encode_protoent(ret, &flat);
		hex_encode(&flat, flat_str, sizeof(struct protoent_flat));
	} else {
		strcpy(flat_str, "NULL");
	}

	if (!LOG( __GETPROTOBYNUMBER_PAT, (long)ret,
								flat_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getprotobynumber\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

void log_setprotoent(int stayopen) {
	/* Simply call through. During replay, we will not call through. */
	__INTERNAL_CALL_LIBC_1(setprotoent, stayopen);
}

void log_endprotoent(void) {
	/* Simply call through. During replay, we will not call through. */
	__INTERNAL_CALL_LIBC_1(endprotoent);
}

struct servent *log_getservent(void) {
	struct servent* ret;
	struct servent_flat flat;
	char flat_str[(sizeof(struct servent_flat)*2) + 1];


	__CALL_LIBC(ret, getservent);

	advance_vclock();

	if (ret) {
		struct_encode_servent(ret, &flat);
		hex_encode(&flat, flat_str, sizeof(struct servent_flat)); 
	} else {
		strcpy(flat_str, "NULL");
	}


	if (!LOG( __GETSERVENT_PAT, (long)ret,
								flat_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getservent\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct servent *log_getservbyname(const char *name, const char *proto) {
	struct servent* ret;
	struct servent_flat flat;
	char flat_str[(sizeof(struct servent_flat) * 2) + 1];

	printf("gh0\n");
	__CALL_LIBC(ret, getservbyname, name, proto);

	advance_vclock();

	if (ret) {
		struct_encode_servent(ret, &flat);
		hex_encode(&flat, flat_str, sizeof(struct servent_flat));
	} else {
		strcpy(flat_str, "NULL");
	}

	if (!LOG( __GETSERVBYNAME_PAT, (long)ret,
								flat_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getservbyname\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct servent *log_getservbyport(int port, const char *proto) {
	struct servent* ret;
	struct servent_flat flat;
	char flat_str[(sizeof(struct servent_flat) * 2) + 1];

	__CALL_LIBC(ret, getservbyport, port, proto);

	advance_vclock();

	if (ret) {
		struct_encode_servent(ret, &flat);
		hex_encode(&flat, flat_str, sizeof(struct servent_flat));
	} else {
		strcpy(flat_str, "NULL");
	}

	if (!LOG( __GETSERVBYPORT_PAT, (long)ret,
								flat_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getservbyport\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

void log_setservent(int stayopen) {
	/* Simply call through. During replay, we will not call through. */
	__INTERNAL_CALL_LIBC_1(setservent, stayopen);
}

void log_endservent(void) {
	/* Simply call through. During replay, we will not call through. */
	__INTERNAL_CALL_LIBC_1(endservent);
}

#if 1
struct hostent* log_gethostbyname(const char *name) {
	struct hostent* ret;
	struct hostent_flat flat;
	char flat_str[(sizeof(struct hostent_flat) * 2) + 1];

	__CALL_LIBC(ret, gethostbyname, name);

	advance_vclock();

	if (ret) {
		struct_encode_hostent(ret, &flat);
		hex_encode(&flat, flat_str, sizeof(struct hostent_flat));
	} else {
		strcpy(flat_str, "NULL");
	}

	if (!LOG( __GETHOSTBYNAME_PAT, (long)ret,
								flat_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "gethostbyname");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}
#endif

int log_listen(int s, int backlog) {
	int ret;

	__CALL_LIBC(ret, listen, s, backlog);

	advance_vclock();

	if (!LOG( __LISTEN_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "listen\n");
	}

	if( 0 == ret ) {
		// We are now accepting tagged connections on this socket.
		// Register with the logger so that our peers can learn this.
		register_socket( s, "listen" );
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_accept(int s, struct sockaddr *addr, socklen_t *addrlen) {
	int ret;
	const int MAX_ADDR_SIZE = 256;
	char addr_ascii[MAX_ADDR_SIZE];
	uint16_t port;
	struct sockaddr_in *sin;

	__CALL_LIBC(ret, accept, s, addr, addrlen);

	/* Get source address in ASCII/readable format. */
	sin = (struct sockaddr_in *)addr;
	assert( sin->sin_family == AF_INET );
	strncpy( addr_ascii, inet_ntoa(sin->sin_addr), MAX_ADDR_SIZE-1);
	addr_ascii[MAX_ADDR_SIZE-1] = 0;
	port = ntohs(sin->sin_port);

	advance_vclock();

	if (!LOG( __LOG_ACCEPT_PAT, ret,
								addr_ascii, port, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "accept\n");
	}

	POST_WRAPPER_CLEANUP();

	/* Mark this file descriptor as a network socket */
	set_socket_state( ret, LIBLOG_SOCKET_TCP );

	/* FIXME -- should send vclock on connect, read on accept
	   Blocking on accept is bad; try rpc to source? */

	return ret;
}

int log_connect(int  sockfd,  const  struct sockaddr *serv_addr, socklen_t
				addrlen) {

	int ret;

	__CALL_LIBC(ret, connect, sockfd, serv_addr, addrlen);

	advance_vclock();

	if (!LOG( __CONNECT_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "connect\n");
	}

	/* If successful, check remote peer for tag readiness */
	if( (ret==0) &&
		should_send_tagged( sockfd, serv_addr, addrlen ) ) {
		/* should_send_tagged() will save the answer for the
		   duration of the connection. */

		/* FIXME -- should send vclock on connect (if TCP), read on accept */
	}

	POST_WRAPPER_CLEANUP();


	return ret;
}

int log_bind(int sockfd, const struct sockaddr* my_addr, socklen_t addrlen) {
	int ret;

	__CALL_LIBC(ret, bind, sockfd, my_addr, addrlen);


	advance_vclock();

	if (!LOG( __BIND_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "bind\n");
	}

	if( 0 == ret ) {
		/* If this socket is SOCK_DGRAM, we can now receive tagged
		   messages here.  Register with the logger. */
		register_socket( sockfd, "bind" );
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_pipe(int filedes[2]) {
	int ret;

	__CALL_LIBC(ret, pipe, filedes);


	advance_vclock();

	if (!LOG( __PIPE_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "pipe\n");
	}

	set_socket_state( filedes[0], LIBLOG_SOCKET_PIPE_STREAM );
	set_socket_state( filedes[1], LIBLOG_SOCKET_PIPE_STREAM );

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_socketpair(int domain, int type, int protocol, int sv[2]) {
	int ret;

	__CALL_LIBC(ret, socketpair, domain, type, protocol, sv);

	advance_vclock();

	if (!LOG( __SOCKETPAIR_PAT, ret,
								domain, type, protocol, sv[0], sv[1], _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "socketpair\n");
	}
	switch( type ) {
	case SOCK_DGRAM:
	  set_socket_state( sv[0], LIBLOG_SOCKET_PIPE_DGRAM );
	  set_socket_state( sv[1], LIBLOG_SOCKET_PIPE_DGRAM );
	  break;
	case SOCK_STREAM:
	  set_socket_state( sv[0], LIBLOG_SOCKET_PIPE_STREAM );
	  set_socket_state( sv[1], LIBLOG_SOCKET_PIPE_STREAM );
	  break;
	default:
		fatal("Unknown socket type %d\n", type );
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_socket(int domain, int type, int protocol) {
	int ret;

	__CALL_LIBC(ret, socket, domain, type, protocol);

	advance_vclock();

	/* Mark this file descriptor as a network socket */
	switch( type ) {
	case SOCK_DGRAM:
		set_socket_state( ret, LIBLOG_SOCKET_UDP );
		break;
	case SOCK_STREAM:
		set_socket_state( ret, LIBLOG_SOCKET_TCP );
		break;
	case SOCK_RAW:
		set_socket_state( ret, LIBLOG_SOCKET_RAW );
		break;
	default:
		fatal("Unknown socket type %d\n", type );
	}

	if (!LOG( __SOCKET_PAT, ret,
								domain, type, protocol, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "socket\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_select(int   n,   fd_set   *readfds,  fd_set  *writefds,  fd_set
			   *exceptfds, struct timeval *timeout) {

	int ret;

#if DEBUG
	dprintf("calling log_select()\n");
#endif

	/* Call the libc select function. */
	__ASYNC_CALL(ret, select, n, readfds, writefds, exceptfds, timeout);

	advance_vclock();

	assert(_shared_info != NULL);
	assert(_shared_info->num_active_threads > 0);

	__START_WRAPPER_TIMER(__LIBC_TIMER(select), _shm_write);
	GET_SHM_CHUNK(select);
	e->ret = ret;
	if (readfds) memcpy(&e->readfds, readfds, sizeof(fd_set));
	if (writefds) memcpy(&e->writefds, writefds, sizeof(fd_set));
	if (exceptfds) memcpy(&e->exceptfds, exceptfds, sizeof(fd_set));
	if (timeout) memcpy(&e->timeout, timeout, sizeof(struct timeval));
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(select), _shm_write);

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_poll(struct pollfd *ufds, nfds_t nfds, int timeout) {
	int ret;
	char flat_str[(sizeof(struct pollfd) * nfds * 2) + 1];

	__ASYNC_CALL(ret, poll, ufds, nfds, timeout);

	advance_vclock();

	assert(ufds != NULL);

	hex_encode(ufds, flat_str, sizeof(struct pollfd) * nfds);

	if (!LOG( __POLL_PAT, ret,
					flat_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"poll\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

ssize_t log_recvfrom(int s, void *buf, size_t len, int flags,
		struct sockaddr *from, socklen_t *fromlen) {

	ssize_t ret;
	tag_t tag;

	__START_WRAPPER_TIMER(__LIBC_TIMER(recvfrom), _other);
	if( should_recv_tagged( s ) ) {
		/* Remove the metadata tags added at the source */
		ret = recv_wrapped_msg( s, buf, len, flags, from, fromlen,
				tag.tag_str, &tag.vclock );
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(recvfrom), _other);
	} else {
		/* Not a network socket.  Just call the libc function. */
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(recvfrom), _other);
		__START_WRAPPER_TIMER(__LIBC_TIMER(recvfrom), _call_libc);
		__CALL_LIBC(ret, recvfrom, s, buf, len, flags, from, fromlen);
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(recvfrom), _call_libc);
		strncpy( tag.tag_str, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN );
		tag.vclock = 0;
	}

	/* Require vclock on receiver to be greater than on sender, to
	// enforce the happens-before relationship. */
	// FIXME -- Trust problem:  What happens if a
	//  single clock shoots vclock ahead?
	// FIXME -- log difference here, for clock skew debugging
	advance_vclock();
	if( _shared_info->vclock <= tag.vclock ) {
		_shared_info->vclock = tag.vclock+1;
	}

	__START_WRAPPER_TIMER(__LIBC_TIMER(recvfrom), _shm_write);
	GET_SHM_CHUNK_DATA(recvfrom, ret);
	e->ret = ret;
	e->from = *from;
	strcpy(e->tag.tag_str, tag.tag_str);
	e->tag.vclock = tag.vclock;
	if (ret > 0) {
		memcpy(dptr, buf, ret);
	}
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(recvfrom), _shm_write);

	POST_WRAPPER_CLEANUP();

	return ret;
}

ssize_t log_recv(int s, void *buf, size_t len, int flags) {
	ssize_t ret;
	tag_t tag;

#if 1
	//Need to allow for more space!
	if( should_recv_tagged( s ) ) {
		/* Remove the metadata tags added at the source */
		ret = recv_wrapped_msg( s, buf, len, flags, NULL, NULL,
				tag.tag_str, &tag.vclock );
	} else {
		/* Not a network socket.  Just call the libc function. */
		__CALL_LIBC(ret, recv, s, buf, len, flags);
		strncpy( tag.tag_str, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN );
		tag.vclock = 0;
	}
#else
		__CALL_LIBC(ret, recv, s, buf, len, flags);
		strncpy( tag.tag_str, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN );
		tag.vclock = 0;
#endif

#if 1
	/* Require vclock on receiver to be greater than on sender, to
	// enforce the happens-before relationship. */
	// FIXME -- Trust problem:  What happens if a
	//  single clock shoots vclock ahead?
	// FIXME -- log difference here, for clock skew debugging
	advance_vclock();
	if( _shared_info->vclock <= tag.vclock ) {
		_shared_info->vclock = tag.vclock + 1;
	}

	__START_WRAPPER_TIMER(__LIBC_TIMER(recv), _shm_write);
	GET_SHM_CHUNK_DATA(recv, ret);
	e->ret = ret;
	strcpy(e->tag.tag_str, tag.tag_str);
	e->tag.vclock = tag.vclock;
	if (ret > 0) {
		memcpy(dptr, buf, ret);
	}
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(recv), _shm_write);

	POST_WRAPPER_CLEANUP();
#endif

	return ret;
}

ssize_t log_sendto(int  socket,  const  void *msg, size_t len, int flags, const
		struct sockaddr *to, socklen_t tolen) {

	ssize_t ret;

	__START_WRAPPER_TIMER(__LIBC_TIMER(sendto), _other);
	if(should_send_tagged( socket, to, tolen )) {
		/* Add metadata tags */
		ret = send_wrapped_msg( socket, msg, len, flags, to, tolen,
				_private_info.tag_str, _shared_info->vclock );
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(sendto), _other);
	} else {
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(sendto), _other);

		/* Not a network socket.  Just call the libc function. */
		__START_WRAPPER_TIMER(__LIBC_TIMER(sendto), _call_libc);
		__CALL_LIBC(ret, sendto, socket, msg, len, flags, to, tolen );
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(sendto), _call_libc);
	}


#if 1
	/* Determine the ASCII/readable version of the destination address
	 * so that we can log it. */
	assert( to->sa_family == AF_INET );

	advance_vclock();

	__START_WRAPPER_TIMER(__LIBC_TIMER(sendto), _shm_write);
	GET_SHM_CHUNK(sendto);
	e->ret = ret;
	e->to = *to;
	strcpy(e->tag.tag_str, _private_info.tag_str);
	e->tag.vclock = _shared_info->vclock;
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(sendto), _shm_write);
#endif

	POST_WRAPPER_CLEANUP();

	return ret;
}

ssize_t log_send(int socket, const void *msg, size_t len, int flags) {
	ssize_t ret;

#if DEBUG
	dprintf("calling log_send()\n");
#endif

	/* Create the tag we are going to append. */
	advance_vclock();

	if( should_send_tagged( socket, NULL, 0 ) ) {
		/* Add metadata tags */

		/* BUG: Does send_wrapper_msg send make an errno entry? */
		ret = send_wrapped_msg( socket, msg, len, flags, NULL, 0,
				_private_info.tag_str, _shared_info->vclock );
	} else {
		/* Not a network socket.  Just call the libc function. */
		__CALL_LIBC(ret, send, socket, msg, len, flags );
	}

#if 1
	/* Update to account for send() latency. */
	advance_vclock();

	__START_WRAPPER_TIMER(__LIBC_TIMER(send), _shm_write);
	GET_SHM_CHUNK_DATA(send, ret);
	e->ret = ret;
	strcpy(e->tag.tag_str, _private_info.tag_str);
	e->tag.vclock = _shared_info->vclock;
	if (ret > 0) {
		memcpy(dptr, msg, ret);
	}
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(send), _shm_write);
#endif

	POST_WRAPPER_CLEANUP();

	return ret;
}

ssize_t log_read(int fd, void* buf, size_t count) {
	ssize_t ret;
	tag_t tag;

	/* Use runtime field-width parameters */

#if 1
	/* Call the libc recvfrom function. */
	if( should_recv_tagged( fd ) ) {
		/* Remove the metadata tags added at the source */
		ret = recv_wrapped_msg( fd, buf, count, 0, NULL, NULL,
				tag.tag_str, &tag.vclock );
	} else {
		/* Not a network socket.  Just call the libc function. */
		__CALL_LIBC(ret, read, fd, buf, count);
		strncpy( tag.tag_str, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN );
		tag.vclock = 0;
	}
#else
		__CALL_LIBC(ret, read, fd, buf, count);
		strncpy( tag.tag_str, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN );
		tag.vclock = 0;
#endif

#if 1
	/* Require vclock on receiver to be greater than on sender, to
	// enforce the happens-before relationship. */
	// FIXME -- Trust problem:  What happens if a
	//  single clock shoots vclock ahead?
	// FIXME -- log difference here, for clock skew debugging
	advance_vclock();
	if( _shared_info->vclock <= tag.vclock ) {
		_shared_info->vclock = tag.vclock + 1;
	}

	__START_WRAPPER_TIMER(__LIBC_TIMER(read), _shm_write);
	GET_SHM_CHUNK_DATA(read, ret);
	e->ret = ret;
	strcpy(e->tag.tag_str, tag.tag_str);
	e->tag.vclock = tag.vclock;
	if (ret > 0) {
		memcpy(dptr, buf, ret);
	}
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(read), _shm_write);

	POST_WRAPPER_CLEANUP();
#endif

	return ret;
}

ssize_t log_write(int fd, const void* buf, size_t count) {
	ssize_t ret;

	__CALL_LIBC(ret, write, fd, buf, count );

	advance_vclock();

	if (!LOG( __WRITE_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"write\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}
