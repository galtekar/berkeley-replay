/* Routines to communicate with the logger process. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ckpt.h>
#include <assert.h>
#include <sys/time.h>	// timeval, gettimeofday
#include <sys/select.h>	// select
#include <fcntl.h>	// fcntl, F_GETFL, F_SETFL, O_NDELAY

#include "libc_pointers.h"
#include "log.h"
#include "logger.h"

#include "clock.h"
#include "misc.h"
#include "errops.h"
#include "netops.h"
#include "gcc.h"
#include "tmalloc.h"

#define malloc UNDEFINED


#define DEBUG 0

#define QUERY_TIMEOUT_S	2
#define CACHE_HT_SIZE 	101	// Do not resize table for now.
#define CACHE_TTL_REPLY	(30*1000000)	// 30 seconds for valid reply.
// 5 minutes if no response from remote machine (no logger)
#define CACHE_TTL_NO_REPLY	(300*1000000)


static int _logger_port = 0;	// The global well-known port.


// We cache query results in a local hashtable.  Each entry records
// its timeout (in cpu microseconds).  Stale entries are purged from
// a hash table chain during lookup.
typedef struct query_cache_entry {
  uint64_t timeout_us;	// Use get_cpu_micros()

  int query_result;	// boolean
  
  // The parameters to cache_{insert/lookup}
  struct in_addr addr;
  int port;
  char * protocol;	

  // Use same pointers for free list and hash table chain.
  LIST_ENTRY( query_cache_entry ) entries;

} query_cache_entry;

typedef LIST_HEAD( query_list, query_cache_entry ) query_list;

static int cache_initialized = FALSE;
// Simple bucket-chain hash table
static query_list query_table[CACHE_HT_SIZE];
// Avoid some malloc calls:
static query_list query_free_list;


static void cache_init()
{
  int i;
  for( i=0; i<CACHE_HT_SIZE; ++i ) {
    LIST_INIT( &query_table[i] );
  }
  LIST_INIT( &query_free_list );
  cache_initialized = TRUE;
}

/*
 * Simple hash function: <addr,port,protocol> -> unsigned int
 */
static unsigned hash_func( const struct in_addr addr,
			   int port, char* protocol )
{
  unsigned int val = 0;
  val = (unsigned)protocol[0];  // Only check first byte of protocol string
  val ^= (unsigned)addr.s_addr;
  val ^= (unsigned)port;
  return val;
}

/**
 * Inserts a query result into cache for a <addr,port,protocol> tuple.
 * Result remains valid until get_cpu_micros() exceeds timeout.
 * This function assumes that duplicate tuples are not inserted;
 *   caller should always check cache_lookup first.
 */
static void cache_insert( const struct in_addr addr,
			  int port, char* protocol,
			  int result, int64_t timeout_us )
{
  unsigned table_index;
  query_cache_entry * qce;
  if( DEBUG ) lprintf( "cache_insert( %s, %d, %s, %d, %llu )\n",
		       inet_ntoa(addr), port, protocol,
		       result, timeout_us );

  if( ! cache_initialized ) cache_init();
  // Get a new struct.
  qce = query_free_list.lh_first;
  if( qce != NULL ) {	// list was not empty
    if( DEBUG ) lprintf( "Found qce %p on free list\n", qce );
    LIST_REMOVE( qce, entries );
  } else {
    qce = (query_cache_entry*)tmalloc(sizeof(query_cache_entry));
    if( DEBUG ) lprintf( "malloc'd qce %p\n", qce );
  }

  // Fill in struct.
  qce->timeout_us = timeout_us;
  qce->query_result = result;
  qce->addr = addr;
  qce->port = port;
  qce->protocol = protocol;	// Assumes string is persistent.
  // In fact, we ensure below that protocol string is a literal.

  // Then insert into hash table.
  table_index = hash_func(addr, port, protocol) % CACHE_HT_SIZE;
  if( DEBUG ) lprintf( "table_index: %d\n", table_index );
  LIST_INSERT_HEAD( &query_table[table_index], qce, entries );
  return;
}

/**
 * Returns TRUE if the query cache has a valid entry for this
 * <addr,port,protocol> tuple.  If so, the query result is stored in
 * *result. 
 */
static int cache_lookup( int *result, const struct in_addr addr,
			 int port, char* protocol, uint64_t now_us )
{
  unsigned table_index;
  query_cache_entry *qce, *qce_next;
  if( DEBUG ) lprintf( "cache_lookup( %s, %d, %s, %llu )\n",
		       inet_ntoa(addr), port, protocol, now_us );

  if( ! cache_initialized ) cache_init();  
  table_index = hash_func(addr, port, protocol) % CACHE_HT_SIZE;
  if( DEBUG ) lprintf( "table_index: %d\n", table_index );

  // Now scan this chain, purging any stale entries along the way.
  if( DEBUG ) lprintf( "now_us: %llu\n", now_us );
  for( qce = query_table[table_index].lh_first; qce != NULL;
       qce = qce_next ) {
    // Store next explicitly so we can remove qce.
    qce_next = qce->entries.le_next;
    if( DEBUG ) lprintf( "scanning: %s, %d, '%s'\n",
			 inet_ntoa(qce->addr), qce->port, qce->protocol );
    if( now_us > qce->timeout_us ) {
      if( DEBUG ) lprintf( "Timed out: %llu > %llu\n", now_us, qce->timeout_us );
      LIST_REMOVE( qce, entries );
      LIST_INSERT_HEAD( &query_free_list, qce, entries );
      
    } else if( (qce->addr.s_addr == addr.s_addr) &&
	       (qce->port == port ) &&
	       (0 == strcmp(qce->protocol, protocol)) ) {
      *result = qce->query_result;
      return TRUE;
    }
  }
  return FALSE;
}

/* Sends a message (hdr + data) to the log server. */
void HIDDEN send_to_server(LogMsgHdr* hdr, char* data, size_t data_size)  {
	size_t total_size = sizeof(LogMsgHdr) + data_size;
	char buf[total_size];

	/* TODO: avoid copying by using sendmsg()!! */

	/* Make a single message. */
	memcpy(buf, hdr, sizeof(LogMsgHdr));

	if (data && data_size) {
		memcpy(buf+sizeof(LogMsgHdr), data, data_size);
	}
	barf(_private_info.socket_fd, buf, total_size);
}


void HIDDEN send_new_log_msg(int64_t vclock) {
	LogMsgHdr msg;
	char filename[PATH_MAX];
	char base_name[PATH_MAX];

	/* Construct the filename of the log. We need to tell the logger
	 * what it is. */
	construct_log_filename_base(_private_info.log_path, _private_info.log_prefix,
		_private_info.tag_str, _private_info.orig_pgid,
		_private_info.log_epoch, vclock, base_name, sizeof(base_name));
	snprintf(filename, sizeof(filename),
		"%s.log", base_name);
	strncpy(_private_info.log_name, filename,
		sizeof(_private_info.log_name) );

	msg.type = MSG_LOG_CREATE;
	msg.src_pid = _private_info.orig_pid;
	msg.src_pgid = _private_info.orig_pgid;
	msg.vclock = vclock;
	msg.data_size = strlen(filename) + 1;

	send_to_server(&msg, filename, msg.data_size);

	/* Get the shared memory id from the log server. We will need
	 * to attach it to our address space later. This doubles as an
	 * ACK. */
	if (snarf(_private_info.socket_fd, &_shared_info->shmid, 
			sizeof(long), 0) <= 0) {
		fatal("can't get shared segment id from server\n");
	}

	if (snarf(_private_info.socket_fd, &_shared_info->shmsize,
		sizeof(long), 0) <= 0) {
		fatal("can't get shared segment size from server\n");
	}
}

void HIDDEN send_log_entry_msg(char *log_str, int64_t vclock) {
	LogMsgHdr msg;

	msg.type = MSG_LOG_ENTRY;
	msg.src_pid = _private_info.orig_pid;
	msg.src_pgid = _private_info.orig_pgid;
	msg.vclock = vclock;
	msg.data_size = strlen(log_str) + 1;

	send_to_server(&msg, log_str, msg.data_size);
}

void HIDDEN send_log_close_msg(char* log_str, int64_t vclock) {
	LogMsgHdr msg;

	msg.type = MSG_LOG_CLOSE;
	msg.src_pid = _private_info.orig_pid;
	msg.src_pgid = _private_info.orig_pgid;
	msg.vclock = vclock;
	msg.data_size = strlen(log_str) + 1;

	send_to_server(&msg, log_str, msg.data_size);
}

void HIDDEN send_log_flush_msg(int64_t vclock) {
	LogMsgHdr msg;

	msg.type = MSG_LOG_FLUSH;
	msg.src_pid = _private_info.orig_pid;
	msg.src_pgid = _private_info.orig_pgid;
	msg.vclock = vclock;
	msg.data_size = 0;

#if DEBUG
	printf("sending log flush msg\n");
#endif

	send_to_server(&msg, NULL, msg.data_size);

	/* Get the shared memory id from the log server. We will need
	 * to attach it to our address space. This doubles as an
	 * ACK. */
	snarf(_private_info.socket_fd, &_shared_info->shmid, sizeof(long), 0);
	snarf(_private_info.socket_fd, &_shared_info->shmsize,
		sizeof(long), 0);
}

/* Connects to the logger process and returns a process id. Since we
 * are using UDP, there is no formal ``connection'' taking place, just
 * some socket initialization. */
int HIDDEN connect_to_logger(in_addr_t logger_addr, int logger_port) {
	struct sockaddr_in sout;
	int out_sock;
	int ret;

	_logger_port = logger_port-1;	// Save this info for later.
	
	memset(&sout, 0x0, sizeof(sout));
	sout.sin_family = AF_INET;
	sout.sin_port = htons(logger_port);
	sout.sin_addr.s_addr = htonl(logger_addr);

	__INTERNAL_CALL_LIBC_2(out_sock, socket, PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (out_sock < 0) {
		perror("socket");
		fatal("socket failed\n");
	}

	__INTERNAL_CALL_LIBC_2(ret, connect, out_sock, (struct sockaddr*)&sout, sizeof(sout));
	if (ret < 0) {
		perror("connect");
		fatal("can't connect to the log server %s:%d\n", 
				inet_ntoa(sout.sin_addr), logger_port);
	}

	return out_sock;
}

/** Informs the local logger that we are ready for tagged messages on
    a specified port. 
*/
HIDDEN void register_port( int port, char* protocol )
{
  LogMsgHdr msg;
  char port_and_prot[32];

  if( DEBUG ) lprintf( "liblog client #%d registering port (%d,%s)\n",
		       _private_info.orig_pgid, port, protocol );
  
  sprintf( port_and_prot, PORT_PROT_FMT, port, protocol );

  msg.type = MSG_PORT_REGISTER;
  msg.src_pid = _private_info.orig_pid;
  msg.src_pgid = _private_info.orig_pgid;
  msg.vclock = 0;	// Ignored at logger?
  msg.data_size = strlen(port_and_prot) + 1;

  send_to_server(&msg, port_and_prot, msg.data_size);
}

/** Informs the local logger that we have closed a registered socket.
    Returns TRUE.
*/
HIDDEN void unregister_port( int port, char* protocol )
{
  LogMsgHdr msg;
  char port_and_prot[32];

  if( DEBUG ) lprintf( "liblog client #%d UNregistering port (%d,%s)\n",
		       _private_info.orig_pgid, port, protocol );
  
  sprintf( port_and_prot, PORT_PROT_FMT, port, protocol );

  msg.type = MSG_PORT_UNREGISTER;
  msg.src_pid = _private_info.orig_pid;
  msg.src_pgid = _private_info.orig_pgid;
  msg.vclock = 0;	// Ignored at logger?
  msg.data_size = strlen(port_and_prot) + 1;

  send_to_server(&msg, port_and_prot, msg.data_size);
}

/**
 * Helper for query_remote_logger below.
 * is_read should be TRUE if fd is for reading, FALSE if for writing.
 * Returns TRUE when fd becomes ready, or FALSE if timed out.
 */
static int select_wrapper( struct timeval deadline, int fd, int is_read )
{
  int ret;
  struct timeval now, timeout;
  fd_set fds;
  int fd_count;

  fd_count = fd+1;
  while( TRUE ) {
    __INTERNAL_CALL_LIBC_2( ret, gettimeofday, &now, NULL );
    assert( ret == 0 );
    if( timercmp( &deadline, &now, < ) ) {	// timed out.
      return FALSE;
    }
    timersub( &deadline, &now, &timeout );
    if (DEBUG) lprintf( "Setting timeout to %ld, %ld\n", timeout.tv_sec, timeout.tv_usec );
    
    FD_ZERO( &fds );
    FD_SET( fd, &fds );
    // We cannot release the scheduling lock while we wait.
    //  Could we instead make the entire call to query_remote_logger async?
    __INTERNAL_CALL_LIBC_2( ret, select, fd_count,
			    (is_read ? &fds : NULL),
			    (is_read ? NULL : &fds),
			    NULL, &timeout );
    if( ret < 0 ) {
      assert( errno == EINTR );
      continue;
    } else if( ret == 0 ) {
      return FALSE;
    } else {
      assert( (ret == 1) && (FD_ISSET( fd, &fds)) );
      return TRUE;
    }
  }
}


/** Queries a remote logger regarding the status of a port on that
    machine.
    Returns TRUE iff the RPC succeeds and returns TRUE.
    See QUERY_TIMEOUT_S.
    The port argument should be the port in question; the remote
      logger is assumed to be listening on a globally known port.
    Only logger_addr should use network byte order.
*/
HIDDEN int query_remote_logger( const struct in_addr logger_addr,
				int port, char* protocol )
{
  int query_result;
  int fd, ret, len;
  int flags;
  char query_buf[MAX_PORT_QUERY_MSG_LEN];
  char rep_buf[MAX_PORT_QUERY_REP_LEN];
  struct sockaddr_in sin;
  struct timeval deadline;
  uint64_t now_us;

  if( DEBUG ) lprintf( "liblog client #%d querying %s: (%d,%s)\n",
		       
		       _private_info.orig_pgid, inet_ntoa(logger_addr), port, protocol );

  // Cache assumes protocol argument string is literal.
  if( 0 == strcmp( protocol, PROT_STR_UDP ) ) {
    protocol = PROT_STR_UDP;
  } else if(  0 == strcmp( protocol, PROT_STR_TCP ) ) {
    protocol = PROT_STR_TCP;
  }
  assert( (protocol == PROT_STR_UDP) || (protocol == PROT_STR_TCP) );

  // Check cache
  now_us = get_cpu_micros();	// cache uses cpu time instead.
  if( cache_lookup( &query_result, logger_addr, port, protocol, now_us ) ) {
    if( DEBUG ) lprintf( "query cache had: %d\n", query_result );
    fd = -1;	// So we don't close it during cleanup.
    goto query_over;
  }
  else if( DEBUG ) lprintf( "query cache missed.\n" );

  // Start the timer.
  __INTERNAL_CALL_LIBC_2( ret, gettimeofday, &deadline, NULL );
  assert( ret == 0 );
  deadline.tv_sec += QUERY_TIMEOUT_S;
  
  // Open a socket to the remote logger.
  __INTERNAL_CALL_LIBC_2( fd, socket, PF_INET, SOCK_STREAM, 0 );
  assert( fd >= 0 );

  // Make it non-blocking so we can control the connect timeout.
  __INTERNAL_CALL_LIBC_2( flags, fcntl, fd, F_GETFL );
  if( DEBUG ) lprintf( "fcntl F_GETFL: 0x%x\n", flags );
  __INTERNAL_CALL_LIBC_2( ret, fcntl, fd, F_SETFL, flags|O_NDELAY );
  assert( 0 == ret );
  
  memset( &sin, 0, sizeof(sin) );
  sin.sin_family = AF_INET;
  sin.sin_addr = logger_addr;
  sin.sin_port = htons( _logger_port );	// Allow variable ports someday?

  __INTERNAL_CALL_LIBC_2( ret, connect, fd, (const struct sockaddr*)&sin, sizeof(sin) );
    
  if( (ret == -1) && (errno != EINPROGRESS) ) {
    int e = errno;
    if (DEBUG) lprintf( "connect failed, errno=%d (%s)\n", e, strerror(e) );
    if( (e == ECONNREFUSED) || (e == ETIMEDOUT) ) {
      query_result = FALSE;
      cache_insert( logger_addr, port, protocol, query_result,
		    now_us + CACHE_TTL_NO_REPLY );
      goto query_over;
    } else {
      fatal( "Query connection failed with errno %d: '%s'\n", e, strerror(e) );
    }
  }
  assert( (ret == 0) || ((ret==-1) && (errno==EINPROGRESS)) );

  // Wait for connect to finish:
  if( ! select_wrapper( deadline, fd, FALSE /* not read */ ) ) {
    query_result = FALSE;
    cache_insert( logger_addr, port, protocol, query_result,
		  now_us + CACHE_TTL_NO_REPLY );
    goto query_over;
  }
  // Ready to send (unless connect failed).
  len = sprintf( query_buf, PORT_QUERY_MSG_FMT, inet_ntoa(logger_addr), port, protocol );
  assert( len > 0 );
  len++;	// Count final NIL
  
  if (DEBUG) lprintf( "Sending '%s'\n", query_buf );
  __INTERNAL_CALL_LIBC_2( ret, send, fd, query_buf, len, 0 );
  if( ret != len ) {
    assert( ret != EAGAIN );	// Handle later?
    if (DEBUG) lprintf( "Only sent %d != %d bytes, errno=%d\n", ret, len, errno );
    query_result = FALSE;
    cache_insert( logger_addr, port, protocol, query_result,
		  now_us + CACHE_TTL_NO_REPLY );
    goto query_over;
  }
  // Send worked. Now wait for response.
  int read = 0;
  while( select_wrapper( deadline, fd, TRUE /* is read */ ) ) {
    // Ready to read at least some bytes.
    __INTERNAL_CALL_LIBC_2( len, recv, fd, &rep_buf[read], MAX_PORT_QUERY_REP_LEN-len, 0 );
    
    if (DEBUG) lprintf("recv returned %d\n", len );
    
    if( len < 0 ) {
      query_result = FALSE;
      cache_insert( logger_addr, port, protocol, query_result,
		    now_us + CACHE_TTL_NO_REPLY );
      goto query_over;
    }
    // Something read.  Check reply.
    char reply[MAX_PORT_QUERY_REP_LEN];
    read += len;
    rep_buf[read] = '\0';	// Safe for sscanf?
    // TODO: does this assume readable text?
    if( 1 == sscanf( rep_buf, PORT_QUERY_REP_FMT, reply ) ) {
      if( 0 == strcmp( reply, "TRUE" ) ) {
	query_result = TRUE;
	cache_insert( logger_addr, port, protocol, query_result,
		      now_us + CACHE_TTL_REPLY );
	goto query_over;
      } else if( 0 == strcmp( reply, "FALSE" ) ) {
	query_result = FALSE;
	cache_insert( logger_addr, port, protocol, query_result,
		      now_us + CACHE_TTL_REPLY );
	goto query_over;
      }
    }
    // assume we haven't received all of the boolean string yet. 
    if (DEBUG) lprintf("recv returned so far: '%s'\n", rep_buf );
  }
  // end while loop: must have timed out.
  query_result = FALSE;

 query_over:
  if( fd >= 0 ) {
    __INTERNAL_CALL_LIBC_1( close, fd );
  }
  if (DEBUG) lprintf("query_remote_logger returns:%d\n", query_result );
  return query_result;
}
