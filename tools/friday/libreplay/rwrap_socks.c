#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <syscall.h>
#include <signal.h>

#include <sys/select.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#include "logreplay.h"
#include "errops.h"
#include "misc.h"
#include "hexops.h"
#include "patterns.h"
#include "tmalloc.h"
#include "structops.h"
#include "libc_pointers.h"

#include "replay.h"
#include "util.h"

#define MAX_LENGTH 1024

#define CHECK_FOR_INCONSISTENCY 0

//extern int vfscanf(FILE *stream, const char *format, va_list ap);
//

int replay_getsockopt(int  s, int level, int optname, void *optval,       
				   socklen_t *optlen) {
	int ret;
	int optval_int = 0;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETSOCKOPT_PAT, &ret,
					&optval_int, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore getsockopt\n" );
	}

	if (optval) {
		*(int*)optval = optval_int;
	}

	TRAP();
	
	return ret;
}

int replay_setsockopt(int s, int  level,  int  optname,       
				   const  void  *optval, socklen_t optlen) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETSOCKOPT_PAT, 
								   &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setsockopt\n" );
	}

	TRAP();
	
	return ret;
}

static struct protoent* static_protoent = NULL;
#define PROTOENT_NUM_ALIASES 10
static void alloc_static_protoent() {
	char *mem;
	int i = 0;

	if (!static_protoent) {
		mem = tmalloc(4096);

		static_protoent = (struct protoent*) mem; mem += sizeof(struct protoent);
		static_protoent->p_name = mem; mem += MAX_STRING_SIZE;
		static_protoent->p_aliases = (char**) mem; mem += (sizeof(char*) * PROTOENT_NUM_ALIASES);

		for (i = 0; i < PROTOENT_NUM_ALIASES; i++) {
			static_protoent->p_aliases[i] = mem; mem += MAX_STRING_SIZE;
		}
	}
}

struct protoent * replay_getprotoent(void) {
	struct protoent* ret;
	char flat_str[(sizeof(struct protoent_flat) * 2) + 1];
	struct protoent_flat flat;

	alloc_static_protoent();

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETPROTOENT_PAT,
				       (long*)&ret, flat_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore getprotoent\n" );
	}

	if (ret) {
		hex_decode(flat_str, &flat, sizeof(flat));
		assert(flat.num_p_aliases < PROTOENT_NUM_ALIASES);
		struct_decode_protoent(static_protoent, &flat);
	}

	TRAP();
	
	return ret ? static_protoent : NULL;
}

struct protoent * replay_getprotobyname(const char *name) {
	struct protoent* ret;
	char flat_str[(sizeof(struct protoent_flat) * 2) + 1];
	struct protoent_flat flat;

	alloc_static_protoent();

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETPROTOBYNAME_PAT,
					(long*)&ret, flat_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore getprotobyname\n" );
	}

	if (ret) {
		hex_decode(flat_str, &flat, sizeof(flat));
		assert(flat.num_p_aliases < PROTOENT_NUM_ALIASES);
		struct_decode_protoent(static_protoent, &flat);
	}

	TRAP();
	
	return ret ? static_protoent : NULL;
}

struct protoent * replay_getprotobynumber(int proto) {
	struct protoent* ret;
	char flat_str[(sizeof(struct protoent_flat) * 2) + 1];
	struct protoent_flat flat;

	alloc_static_protoent();

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETPROTOBYNUMBER_PAT,
					(long*)&ret, flat_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore getprotobynumber\n" );
	}

	if (ret) {
		hex_decode(flat_str, &flat, sizeof(flat));
		assert(flat.num_p_aliases < PROTOENT_NUM_ALIASES);
		struct_decode_protoent(static_protoent, &flat);
	}

	TRAP();
	
	return ret ? static_protoent : NULL;
}

void replay_setprotoent(int stayopen) {
	/* Do nothing because the real function tries to manipulate files
	 * that may not be available during replay. */
}

void replay_endprotoent(void) {
	/* Do nothing because the real function tries to manipulate files
	 * that may not be available during replay. */
}

static struct servent* static_servent = NULL;
#define SERVENT_NUM_ALIASES 10
static void alloc_static_servent() {
	char *mem;
	int i = 0;

	if (!static_servent) {
		mem = tmalloc(4096);

		static_servent = (struct servent*) mem; mem += sizeof(struct servent);
		static_servent->s_name = mem; mem += MAX_STRING_SIZE;
		static_servent->s_aliases = (char**) mem; mem += (sizeof(char*) * SERVENT_NUM_ALIASES);

		for (i = 0; i < SERVENT_NUM_ALIASES; i++) {
			static_servent->s_aliases[i] = mem; mem += MAX_STRING_SIZE;
		}

		static_servent->s_proto = mem; mem += MAX_STRING_SIZE;
	}
}

struct servent *replay_getservent(void) {
	struct servent* ret;
	char flat_str[(sizeof(struct servent_flat) * 2) + 1];
	struct servent_flat flat;

	alloc_static_servent();

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETSERVENT_PAT,
					(long*)&ret, flat_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore getservent\n" );
	}

	if (ret) {
		hex_decode(flat_str, &flat, sizeof(flat));
		assert(flat.num_s_aliases < SERVENT_NUM_ALIASES);
		struct_decode_servent(static_servent, &flat);
	}

	TRAP();
	
	return ret ? static_servent : NULL;
}

struct servent *replay_getservbyname(const char *name, const char *proto) {
	struct servent* ret;
	char flat_str[(sizeof(struct servent_flat) * 2) + 1];
	struct servent_flat flat;

	alloc_static_servent();

	
	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETSERVBYNAME_PAT,
					(long*)&ret, flat_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore getservbyname\n" );
	}

	if (ret) {
		hex_decode(flat_str, &flat, sizeof(flat));
		assert(flat.num_s_aliases < SERVENT_NUM_ALIASES);
		assert(static_servent != NULL);
		struct_decode_servent(static_servent, &flat);
	}

	TRAP();
	
	return ret ? static_servent : NULL;
}

struct servent *replay_getservbyport(int port, const char *proto) {
	struct servent* ret;
	char flat_str[(sizeof(struct servent_flat) * 2) + 1];
	struct servent_flat flat;

	alloc_static_servent();

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETSERVBYPORT_PAT,
					(long*)&ret, flat_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore getservbyport\n" );
	}

	if (ret) {
		hex_decode(flat_str, &flat, sizeof(flat));
		assert(flat.num_s_aliases < SERVENT_NUM_ALIASES);
		struct_decode_servent(static_servent, &flat);
	}

	TRAP();
	
	return ret ? static_servent : NULL;
}

void replay_setservent(int stayopen) {
	/* Do nothing because the real function tries to manipulate files
	 * that may not be available during replay. */
}

void replay_endservent(void) {
	/* Do nothing because the real function tries to manipulate files
	 * that may not be available during replay. */
}

static struct hostent* static_hostent = NULL;
#define HOSTENT_NUM_ALIASES 10
#define HOSTENT_NUM_H_ADDR_LIST 10
static void alloc_static_hostent() {
	char *mem;
	int i = 0;

	if (!static_hostent) {
		/* TODO: Don't guess what the size should be! */
		mem = tmalloc(4096*8);

		static_hostent = (struct hostent*) mem; mem += sizeof(struct hostent);
		static_hostent->h_name = mem; mem += MAX_STRING_SIZE;
		static_hostent->h_aliases = (char**) mem; mem += (sizeof(char*) * HOSTENT_NUM_ALIASES);
		static_hostent->h_addr_list = (char**) mem; mem += (sizeof(char*) * HOSTENT_NUM_H_ADDR_LIST);

		for (i = 0; i < HOSTENT_NUM_ALIASES; i++) {
			static_hostent->h_aliases[i] = mem; mem += MAX_STRING_SIZE;
		}

		for (i = 0; i < HOSTENT_NUM_H_ADDR_LIST; i++) {
			static_hostent->h_addr_list[i] = mem; mem += MAX_STRING_SIZE;
		}
	}
}

#if 1
struct hostent* replay_gethostbyname(const char* name) {
	struct hostent* ret;
	char flat_str[(sizeof(struct hostent_flat) * 2) + 1];
	struct hostent_flat flat;

	alloc_static_hostent();

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETHOSTBYNAME_PAT,
					(long*)&ret, flat_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore gethostbyname\n" );
	}

	if (ret) {
		hex_decode(flat_str, &flat, sizeof(flat));
		assert(flat.num_h_aliases < HOSTENT_NUM_ALIASES);
		assert(static_hostent != NULL);
		struct_decode_hostent(static_hostent, &flat);
	}

	TRAP();
	
	return ret ? static_hostent : NULL;
}
#endif

int replay_listen(int s, int backlog) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __LISTEN_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore listen\n" );
	}

	TRAP();
	
	return ret;
}

int replay_accept(int s, struct sockaddr *addr, socklen_t *addrlen) {
	int ret;
	const int MAX_ADDR_SIZE = 256;
	char addr_ascii[MAX_ADDR_SIZE];
	uint16_t port;
	struct sockaddr_in *sin;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __REPLAY_ACCEPT_PAT,
				       &ret, addr_ascii, &port,
					&_shared_info->vclock ) != 4) ) {
		stop_replay( "could not restore accept\n" );
	}

	/* Parse source address, buf. */
	if( ret > 0 ) { 
		memset( addr, 0, sizeof(struct sockaddr ));
		/* FIXME: not always AF_INET? */
		addr->sa_family = AF_INET;
		sin = (struct sockaddr_in *)addr;
		assert( *addrlen >= sizeof(struct sockaddr_in));

		*addrlen = sizeof(struct sockaddr_in);

		if( ! inet_aton( addr_ascii, &(sin->sin_addr) ) ) {
			stop_replay( "could not parse peer address\n" );
		}
		sin->sin_port = ntohs(port);
	}

	TRAP();

	return ret;
}

int replay_connect(int  sockfd,  const  struct sockaddr *serv_addr, socklen_t
       addrlen) {

	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __CONNECT_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore connect\n" );
	}

	TRAP();

	return ret;
}

int replay_bind(int sockfd, struct sockaddr* my_addr, socklen_t addrlen) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __BIND_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore bind\n" );
	}

	TRAP();

	return ret;
}

int replay_pipe(int filedes[2]) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __PIPE_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore pipe\n" );
	}

	TRAP();

	return ret;
}

int replay_socketpair(int domain, int type, int protocol, int sv[2]) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SOCKETPAIR_PAT, &ret,
					&domain, &type, &protocol, &sv[0], &sv[1],
					&_shared_info->vclock ) != 7) ) {
		stop_replay( "could not restore socketpair\n" );
	}

	TRAP();

	return ret;
}

int replay_socket(int domain, int type, int protocol) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SOCKET_PAT, &ret,
					&domain, &type, &protocol,
					&_shared_info->vclock ) != 5) ) {
		stop_replay( "could not restore socket\n" );
	}

	TRAP();

	return ret;
}

int replay_select(int   n,   fd_set   *readfds,  fd_set  *writefds,  fd_set
		*exceptfds, struct timeval *timeout) {

	int ret;
	char readfds_hex_str[(sizeof(fd_set) * 2) + 1];
	char writefds_hex_str[(sizeof(fd_set) * 2) + 1];
	char exceptfds_hex_str[(sizeof(fd_set) * 2) + 1];
	char timeout_hex_str[(sizeof(struct timeval) * 2) + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SELECT_PAT, &ret, 
		readfds_hex_str, writefds_hex_str, exceptfds_hex_str, timeout_hex_str,
				&errno, &_shared_info->vclock ) != 7) ) {
		printf("%s\n", libreplay_io_buf);
		stop_replay( "could not restore select\n" );
	}

#if 0
	printf("read=%s write=%s except=%s timeout=%s errno=%d vc=%llu\n",
		readfds_hex_str, writefds_hex_str, exceptfds_hex_str, timeout_hex_str,
		errno, _shared_info->vclock);
#endif


	if (readfds)
		hex_decode(readfds_hex_str, readfds, sizeof(fd_set));
	if (writefds) 
		hex_decode(writefds_hex_str, writefds, sizeof(fd_set));
	if (exceptfds) 
		hex_decode(exceptfds_hex_str, exceptfds, sizeof(fd_set));
	if (timeout)
		hex_decode(timeout_hex_str, timeout, sizeof(struct timeval));

	TRAP();


	return ret;
}

int replay_poll(struct pollfd *ufds, unsigned int nfds, int timeout) {
	int ret;
	char flat_str[(sizeof(struct pollfd) * nfds * 2) + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __POLL_PAT,
				       &ret, flat_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore poll\n" );
	}

	hex_decode(flat_str, ufds, sizeof(struct pollfd) * nfds);

	TRAP();

	return ret;
}

ssize_t replay_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr
		*from, socklen_t *fromlen) {

	ssize_t ret;
	char buf_ascii[2*len+1];
	char addr_ascii[LOG_BUF_SIZE];
	uint16_t port;
	struct sockaddr_in *sin;
	tag_t tag;

#if DEBUG
	dprintf("calling replay_recvfrom()\n");
#endif

	

	if( ! LOG_TO_BUF() ||    
			(7 != sscanf( libreplay_io_buf, __REPLAY_RECVFROM_PAT, &ret, 
						addr_ascii, &port, buf_ascii, tag.tag_str,
						  &tag.vclock, &_shared_info->vclock )) ) {
		stop_replay( "could not restore recvfrom\n" );
	}

	/* Parse source address, buf. */
	if( ret > 0 ) { 
		memset( from, 0, sizeof(struct sockaddr ));
		from->sa_family = AF_INET;
		sin = (struct sockaddr_in *)from;
		assert( *fromlen >= sizeof(struct sockaddr_in));

		*fromlen = sizeof(struct sockaddr_in);

		if( ! inet_aton( addr_ascii, &(sin->sin_addr) ) ) {
			stop_replay( "could not parse inbound address\n" );
		}
		sin->sin_port = htons(port);

		/* Parse message contents. */
		hex_decode(buf_ascii, buf, ret);
	}

	TRAP();

	return ret;
}

ssize_t replay_recv(int s, void *buf, size_t len, int flags) {

	ssize_t ret;
	char buf_ascii[2*len+1];
	tag_t tag;

	

	if( ! LOG_TO_BUF() ||    
			(5 != sscanf( libreplay_io_buf, __REPLAY_RECV_PAT, &ret, 
						buf_ascii, tag.tag_str,
						  &tag.vclock, &_shared_info->vclock )) ) {
		stop_replay( "could not restore recv\n" );
	}

	/* Parse source address, buf. */
	if( ret > 0 ) { 
		/* Parse message contents. */
		hex_decode(buf_ascii, buf, ret);
	}

	TRAP();

	return ret;
}

ssize_t replay_sendto(int  socket,  const  void *msg, size_t len, 
		int flags, const struct sockaddr *to, socklen_t tolen) {

	ssize_t ret;
	uint16_t port;
	struct in_addr ia;
	const struct sockaddr_in *sin;
	char addr_ascii[LOG_BUF_SIZE];
	tag_t tag;

#if DEBUG
	dprintf("calling replay_sendto()\n");
#endif

	

	if( ! LOG_TO_BUF() ||
			(6 != sscanf( libreplay_io_buf, __REPLAY_SENDTO_PAT, &ret, addr_ascii, 
						  &port, tag.tag_str, &tag.vclock, 
						  &_shared_info->vclock ))) {
		stop_replay( "could not restore sendto\n" );
	}

	assert( to->sa_family == AF_INET );
	sin = (const struct sockaddr_in *)to;

	/* Match address with that specified during execution. They should
	 * be identical. */
	if (!inet_aton(addr_ascii, &ia)) {
		fatal("inet_aton failed\n");
	}

	if (ia.s_addr != sin->sin_addr.s_addr) {
		printf("logged: %s\n", inet_ntoa(ia));
		printf("replay: %s\n", inet_ntoa(sin->sin_addr));
		stop_replay( "inconsistent sendto outbound address\n" );
	}

	/* Match the port with that specified during execution. They should
	 * be identical. */
	if( sin->sin_port != htons(port) ) {
		stop_replay( "inconsistent sendto outbound port\n" );
	}

#if CHECK_FOR_INCONSISTENCY
	/* Match message contents with that of the original execution.
	 * They should be identical. */
	{
		char send_data[len];
		char msg_ascii[2*len + 1];
		char new_ascii[2*len + 1];
		int d;

		hex_encode((char*)msg, msg_ascii, len);

		hex_encode(send_data, new_ascii, len);

		if ((d = memcmp(send_data, msg, len)) != 0) {
			flag_inconsistent_replay("inconsistent sendto data: d=%d\n", d);
		}
	}
#endif

	TRAP();

	return ret;
}

ssize_t replay_send(int  socket,  const  void *msg, size_t len, int flags) {

	ssize_t ret;
	char buf_ascii[2*len+1];
	tag_t tag;

	

	if( ! LOG_TO_BUF() ||
			(5 != sscanf( libreplay_io_buf, __REPLAY_SEND_PAT, &ret,
						  buf_ascii, tag.tag_str, &tag.vclock, 
						  &_shared_info->vclock ))) {
		stop_replay( "could not restore send\n" );
	}

#if CHECK_FOR_INCONSISTENCY
	/* Match message contents with that of the original execution.
	 * They should be identical. */
	{
		char send_data[len];

		hex_decode(buf_ascii, send_data, len);
		if (memcmp(send_data, msg, len) != 0) {
			flag_inconsistent_replay("inconsistent send data\n");
		}
	}
#endif

	TRAP();

	return ret;
}

ssize_t replay_read(int fd, void* buf, size_t count) {
	ssize_t ret;
	tag_t tag;
	char read_hex_str[(count)*2 + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __REPLAY_READ_PAT, 
			&ret, read_hex_str, tag.tag_str,
			&tag.vclock, &_shared_info->vclock ) != 5) ) {
		stop_replay( "could not restore read\n" );
	}

	if( strcmp( NO_HEX_DATA, read_hex_str ) != 0 && ret > 0) {
		hex_decode(read_hex_str, buf, ret);
	}

	TRAP();

	return ret;
}

ssize_t replay_write(int fd, const void* buf, size_t count) {
  	ssize_t ret, new_ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __WRITE_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore write\n" );
	}

	if( fd == STDERR_FILENO || fd == STDOUT_FILENO ) {
	  	__INTERNAL_CALL_LIBC_2(new_ret, write, fd, buf, count );
		assert(new_ret == ret);
	}

	TRAP();

	return ret;
}
