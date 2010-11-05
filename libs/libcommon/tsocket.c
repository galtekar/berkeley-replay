#include "public.h"

#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/ioctl.h>

// Useful for isolating bugs
#define TSOCK_ENABLED 1

#if PRODUCT && TSOCK_ENABLED != 1
#error "Must ship with Tsockets enabled"
#endif

// XXX: find the true maximum, this is just a guess
#define MAX_SOCKADDR_SIZE 256

#define PROT_CHAR_UDP	'U'
#define PROT_CHAR_TCP	'T'

#if 1
#define timercmp(a,b,CMP) (((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_usec CMP (b)->tv_usec) : ((a)->tv_sec CMP (b)->tv_sec))
#define timerclear(x) ((x)->tv_sec=(x)->tv_usec=0)
#define timeradd(a,b,x) do { (x)->tv_sec=(a)->tv_sec+(b)->tv_sec; if (((x)->tv_usec=(a)->tv_usec+(b)->tv_usec)>=1000000) { ++(x)->tv_sec; (x)->tv_usec-=1000000; } } while (0)
#define timersub(a,b,x) do { (x)->tv_sec=(a)->tv_sec-(b)->tv_sec; if (((x)->tv_usec=(a)->tv_usec-(b)->tv_usec)<0) { --(x)->tv_sec; (x)->tv_usec+=1000000; } } while (0)
#define timerisset(x) ((x)->tv_sec || (x)->tv_usec)
#endif

// In sharedarea, in case we need to re-connect at some point
static SHAREDAREA int _serv_sock = -1, _query_port = -1;


#define QUERY_TIMEOUT_S	2
#define CACHE_HT_SIZE 	101	// Do not resize table for now.
#define CACHE_TTL_REPLY	(30*1000000)	// 30 seconds for valid reply.
// 5 minutes if no response from remote machine (no pserv)
#define CACHE_TTL_NO_REPLY	(300*1000000)

#define PORT_REG_FMT "cccL"
#define PORT_QUERY_MSG_FMT "cccL"
#define PORT_QUERY_REP_FMT "c"

#define MAX_PORT_QUERY_MSG_LEN 256
#define MAX_PORT_QUERY_REP_LEN 1

// We cache query results in a local hashtable.  Each entry records
// its timeout (in cpu microseconds).  Stale entries are purged from
// a hash table chain during lookup.
typedef struct query_cache_entry {
   uint64_t timeout_us;	// Use get_cpu_micros()

   int query_result;	// boolean

   // The parameters to cache_{insert/lookup}
   struct in_addr addr;
   tsock_port_info_t port_info;

   struct MapField map;

} query_cache_entry;

SHAREDAREA static struct MapStruct *query_cache_map = NULL;
SHAREDAREA static int cache_initialized = FALSE;
SHAREDAREA static struct SynchLock cache_lock = SYNCH_LOCK_INIT;

static int is_tagging_enabled = TRUE;

/************************************************************
 * Methods
 ************************************************************/

static INLINE int
TSockIsEnabled()
{
#if PRODUCT
   ASSERT(is_tagging_enabled == TRUE);
#endif
   return TSOCK_ENABLED && is_tagging_enabled;
}

static void 
print_buf( char const * prefix, char const * buf, size_t buf_len )
{
#if DEBUG
   char hex_buf[2*MAX(0,buf_len)+1]; // +1 for null-terminator
   if( buf_len <= 0 ) {
      hex_buf[0] = '\0';
   } else {
      hex_encode(hex_buf, sizeof(hex_buf), buf, buf_len );
   }
   DEBUG_MSG(5, "%s[%d]: <%s>\n", prefix, buf_len, hex_buf );
#endif
}

static void 
cache_init()
{
   query_cache_map = Map_Create(0);
   cache_initialized = TRUE;
}

/*
 * Simple hash function: <addr,port,protocol> -> unsigned int
 */
static unsigned hash_func( const struct in_addr addr,
      const tsock_port_info_t *p_info )
{
   unsigned int val = 0;

   val = (unsigned)p_info->protocol;  
   val ^= (unsigned)p_info->family;
   val ^= (unsigned)addr.s_addr;
   val ^= *((unsigned*)p_info->port_addr);

   return val;
}

/**
 * Inserts a query result into cache for a <addr,family,port,protocol> tuple.
 * Result remains valid until get_cpu_micros() exceeds timeout.
 * This function assumes that duplicate tuples are not inserted;
 *   caller should always check cache_lookup first.
 */
static void cache_insert( const struct in_addr addr, 
                          const tsock_port_info_t *p_info,
                          const int result, const int64_t timeout_us )
{
   ulong hash_key;
   query_cache_entry * qce;

   DEBUG_MSG( 5, "cache_insert( %s, %s, %c, %d, %llu )\n",
         inet_ntoa(addr), p_info->port_addr, p_info->protocol,
         result, timeout_us );

   SYNCH_LOCK(&cache_lock);

   if( ! cache_initialized ) cache_init();

   qce = (query_cache_entry*) malloc(sizeof(query_cache_entry));

   // Then insert into hash table.
   hash_key = hash_func(addr, p_info);
   DEBUG_MSG( 5, "hash_key: %d\n", hash_key );

   // Fill in struct.
   Map_NodeInit(&qce->map, hash_key);
   qce->timeout_us = timeout_us;
   qce->query_result = result;
   qce->addr = addr;
   qce->port_info = *p_info;

   Map_Insert( query_cache_map, map, hash_key, qce );

   SYNCH_UNLOCK(&cache_lock);

   return;
}

/**
 * Returns TRUE if the query cache has a valid entry for this
 * <addr,port,protocol> tuple.  If so, the query result is stored in
 * *result. 
 *
 * We also remove stale entries while doing the lookup.
 */
static int 
cache_lookup( int *result, const struct in_addr addr, 
              const tsock_port_info_t *p_info, uint64_t now_us )
{
   unsigned hash_key;
   query_cache_entry *qce;
   int res = FALSE;

   DEBUG_MSG( 5, "cache_lookup( %s, %s, %c, %llu )\n",
         inet_ntoa(addr), p_info->port_addr, p_info->protocol, now_us );

   Synch_Lock(&cache_lock);

   if( ! cache_initialized ) cache_init();  

   hash_key = hash_func(addr, p_info);
   DEBUG_MSG( 5, "hash_key: %d\n", hash_key );

   DEBUG_MSG( 5, "now_us: %llu\n", now_us );

   // Now do the lookup
   if ((qce = Map_Find(query_cache_map, map, hash_key, qce))) {
      if( now_us <= qce->timeout_us ) {
         if( (qce->addr.s_addr == addr.s_addr) &&
            qce->port_info.port_addr_len == p_info->port_addr_len &&
            (memcmp(qce->port_info.port_addr, p_info->port_addr, 
                    p_info->port_addr_len) ) && 
            (qce->port_info.family == p_info->family) &&
            (qce->port_info.protocol == p_info->protocol)) {
            *result = qce->query_result;
            res = TRUE;
            goto out;
         }
      } else {
         // Looks like we have stale entries; purge them
         MAP_FOR_EACH_ENTRY_SAFE_DO(query_cache_map, map, qce) {
            if( now_us > qce->timeout_us ) {
               DEBUG_MSG( 5, "Timed out: %llu > %llu\n", now_us, 
                     qce->timeout_us );

               Map_Remove( query_cache_map, map, qce );
            }
         } END_MAP_FOR_EACH_ENTRY_SAFE;
      }
   }

out:
   Synch_Unlock(&cache_lock);
   return res;
}


/* Connects to the port server process and returns a process id. */
static int 
connect_to_registration_server(const in_addr_t pserv_addr, const int reg_port) 
{
   struct sockaddr_in sout;
   int out_sock;
   int ret;

   memset(&sout, 0x0, sizeof(sout));
   sout.sin_family = AF_INET;
   sout.sin_port = htons(reg_port);
   sout.sin_addr.s_addr = htonl(pserv_addr);

   out_sock = SysOps_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
   if (out_sock < 0) {
      FATAL("socket failed\n");
   }

   ret = SysOps_connect(out_sock, (struct sockaddr*)&sout, sizeof(sout));
   if (ret < 0) {
      FATAL("can't connect to the port registration server %s:%d\n", 
            inet_ntoa(sout.sin_addr), reg_port);
   }

   return out_sock;
}

#define MAX_BUF 256
static void 
TSockDoRegisterWork( const int do_register, const tsock_port_info_t *p_info)
{
   uchar buf[MAX_BUF];
   ssize_t len, res;

   ASSERT(_serv_sock >= 0);
   DEBUG_MSG( 5, "%s port (%c,%c,%s,%d)\n", 
         do_register ? "registering" : "unregistering", p_info->family, 
         p_info->protocol, p_info->port_addr, p_info->port_addr_len );

   ASSERT(p_info->port_addr_len <= sizeof(p_info->port_addr));
   len = NetOps_Pack(buf, sizeof(buf), PORT_REG_FMT, 
            do_register ? 'R' : 'U', p_info->family, p_info->protocol, 
            p_info->port_addr_len);
   ASSERT(len > 0 && len <= sizeof(buf));
   res = NetOps_SendAll(_serv_sock, buf, len, 0);
   ASSERT(res == len);
   res = NetOps_SendAll(_serv_sock, p_info->port_addr, p_info->port_addr_len, 
            0);
   ASSERT(res == p_info->port_addr_len);

   // Must wait for ack to avoid a distributed race condition.
   // See details in TSock_Connect().
   //
   // XXX: is this still needed if we switch to a shared-memory
   // registration architecture?
   ASSERT(sizeof(buf) >= 1);
   res = NetOps_ReadAll( _serv_sock, buf, 1, 0 );
   ASSERT( res == 1 );
   ASSERT(buf[0] == 'S'); // Expect success 'S', not failure 'F'
}

static void 
TSockRegisterPort( const tsock_port_info_t *p_info )
{
   TSockDoRegisterWork(1, p_info);
}

static void 
TSockUnregisterPort( const tsock_port_info_t *p_info )
{
   TSockDoRegisterWork(0, p_info);
}

#if DEBUG
static void
TSockVerifyDesc(tsock_socket_info_t *s_info)
{
   ASSERT(s_info->fd >= 0);
   ASSERT(s_info->family > 0);
   ASSERT(s_info->protocol > 0);
   ASSERT(s_info->peer_info > 0);
}
#endif

/**
 * Helper for TSockQueryRemotePortServer below.
 * is_read should be TRUE if fd is for reading, FALSE if for writing.
 * Returns TRUE when fd becomes ready, or FALSE if timed out.
 */
static int 
select_wrapper( struct timeval deadline, const int fd, const int is_read )
{
   int err;
   struct timeval now, timeout;
   fd_set fds;
   int fd_count;

   fd_count = fd+1;
   while( TRUE ) {
      err = gettimeofday( &now, NULL );
      ASSERT( err == 0 );
      if( timercmp( &deadline, &now, < ) ) {	// timed out.
         return FALSE;
      }
      timersub( &deadline, &now, &timeout );

      DEBUG_MSG( 5, "Setting timeout to %ld, %ld\n", timeout.tv_sec, 
            timeout.tv_usec );

      FD_ZERO( &fds );
      FD_SET( fd, &fds );
      // We cannot release the scheduling lock while we wait.
      //  Could we instead make the entire call to TSockQueryRemotePortServer async?
      err = SysOps_select( fd_count,
            (is_read ? &fds : NULL),
            (is_read ? NULL : &fds),
            NULL, &timeout );
      if( err < 0 ) {
         ASSERT( err == -EINTR );
         continue;
      } else if( err == 0 ) {
         return FALSE;
      } else {
         ASSERT( (err == 1) && (FD_ISSET( fd, &fds)) );
         return TRUE;
      }
   }
}


/** Queries a remote port server regarding the status of a port on that
  machine.
  Returns TRUE iff the RPC succeeds.
  See QUERY_TIMEOUT_S.
  The port argument should be the port in question; the remote
  port server is assumed to be listening on a globally known port.
  Only pserv_addr should use network byte order.
  */
static int 
TSockQueryRemotePortServer(const struct in_addr pserv_addr, 
                           const tsock_port_info_t *p_info)
{
   int query_result;
   int fd, ret, err, len;
   int flags;
   char query_buf[MAX_PORT_QUERY_MSG_LEN];
   char rep_buf[MAX_PORT_QUERY_REP_LEN];
   struct sockaddr_in sin;
   struct timeval deadline;
   uint64_t now_us;

   ASSERT(p_info->family );
   ASSERT(p_info->protocol );
   ASSERT(p_info->port_addr_len > 0 );

   DEBUG_MSG( 5, "querying %s: (%c,%c,%s)\n", inet_ntoa(pserv_addr), 
         p_info->family, p_info->protocol, 
         p_info->port_addr );

   ASSERT( (p_info->protocol == PROT_CHAR_UDP) || 
           (p_info->protocol == PROT_CHAR_TCP) );

   // Check cache
   now_us = get_sys_micros();	
   if( cache_lookup( &query_result, pserv_addr, p_info, now_us ) ) {
      DEBUG_MSG( 5, "query cache had: %d\n", query_result );
      fd = -1;	// So we don't close it during cleanup.
      goto query_over;
   } else {
      DEBUG_MSG( 5, "query cache missed.\n" );
   }

   // Start the timer.
   ret = gettimeofday( &deadline, NULL );
   ASSERT( ret == 0 );
   deadline.tv_sec += QUERY_TIMEOUT_S;

   // Open a socket to the remote pserv.
   fd = socket( PF_INET, SOCK_STREAM, 0 );
   ASSERT( fd >= 0 );

   // Make it non-blocking so we can control the connect timeout.
   flags = fcntl( fd, F_GETFL );
   DEBUG_MSG( 5, "fcntl F_GETFL: 0x%x\n", flags );
   ret = fcntl( fd, F_SETFL, flags|O_NDELAY );
   ASSERT( 0 == ret );

   memset( &sin, 0, sizeof(sin) );
   sin.sin_family = AF_INET;
   sin.sin_addr = pserv_addr;
   sin.sin_port = htons( _query_port );	// Allow variable ports someday?

   // Don't use dietlibc's connect, since that uses 'errno' to report
   // error -- its not task safe
   err = SysOps_connect( fd, (const struct sockaddr*)&sin, sizeof(sin) );

   if( (err < 0) && (err != -EINPROGRESS) ) {
      DEBUG_MSG( 5, "connect failed, err=%d (%s)\n", err, strerror(err) );
      if( (err == -ECONNREFUSED) || (err == -ETIMEDOUT) ) {
         query_result = FALSE;
         cache_insert( pserv_addr, p_info, query_result, 
            now_us + CACHE_TTL_NO_REPLY );
         goto query_over;
      } else {
         FATAL( "Query connection failed with err %d: '%s'\n", err, 
               strerror(err) );
      }
   }
   ASSERT( (err == 0) || ((err < 0) && (err==-EINPROGRESS)) );

   // Wait for connect to finish:
   if( ! select_wrapper( deadline, fd, FALSE /* not read */ ) ) {
      query_result = FALSE;
      cache_insert( pserv_addr, p_info, query_result, 
         now_us + CACHE_TTL_NO_REPLY );
      goto query_over;
   }

   // Ready to send (unless connect failed).
   len = NetOps_Pack(query_buf, sizeof(query_buf), PORT_QUERY_MSG_FMT, 
            'P', p_info->family, p_info->protocol, p_info->port_addr_len);
   ASSERT( len > 0 );

   if (DEBUG) print_buf( "Sending", query_buf, len );
   err = NetOps_SendAll( fd, query_buf, len, 0 );
   if( err != len ) {
      ASSERT( err != EAGAIN );	// Handle later?
      DEBUG_MSG( 5, "Only sent %d != %d bytes\n", err, len );
      query_result = FALSE;
      cache_insert( pserv_addr, p_info, query_result,
         now_us + CACHE_TTL_NO_REPLY );
      goto query_over;
   }

   err = NetOps_SendAll(fd, p_info->port_addr, p_info->port_addr_len, 0);
   // XXX: check for error?

   // Send worked. Now wait for response.
   if ( select_wrapper( deadline, fd, TRUE /* is read */ ) ) {
      // Ready to read at least some bytes.
      len = recv( fd, rep_buf, MAX_PORT_QUERY_REP_LEN, 0 );

      DEBUG_MSG( 5, "recv returned %d\n", len );

      if( len < 0 ) {
         query_result = FALSE;
         /* XXX: consolidate all these cache_insert calls */
         cache_insert( pserv_addr, p_info, query_result,
            now_us + CACHE_TTL_NO_REPLY );
         goto query_over;
      }
      char rep_res = 0;
      size_t rep_len;
      rep_len = NetOps_Unpack(rep_buf, sizeof(rep_buf), "c", &rep_res);
      ASSERT( rep_len == 1 );

      if( rep_res == 'T' ) {
         query_result = TRUE;
         cache_insert( pserv_addr, p_info, query_result,
               now_us + CACHE_TTL_REPLY );
         goto query_over;
      } else {
#if DEBUG
         if (rep_res != 'F') {
            DEBUG_MSG( 5, "invalid reply '%c', assuming false\n", rep_res);
         }
#endif
         query_result = FALSE;
         cache_insert( pserv_addr, p_info, query_result,
               now_us + CACHE_TTL_REPLY );
         goto query_over;
      } 
      // assume we haven't received all of the boolean string yet. 
      DEBUG_MSG( 5, "recv returned so far: '%s'\n", rep_buf );
   }
   // end while loop: must have timed out.
   query_result = FALSE;

query_over:
   if( fd >= 0 ) {
      close( fd );
   }
   DEBUG_MSG( 5, "TSockQueryRemotePortServer returns:%d\n", query_result );
   return query_result;
}


/*************************************************************/

/**
 * Creates a tsock_port_info_t struct.
 */
static tsock_port_info_t * 
new_registered_info( tsock_port_info_t *pi )
{
   tsock_port_info_t * rp =
      (tsock_port_info_t*) malloc(sizeof(tsock_port_info_t));
   memcpy(rp, pi, sizeof(*rp));
   return rp;
}

static int
TSockMakePortInfoFromSockAddr(tsock_socket_info_t *s_info, 
      const struct sockaddr *sa_ptr, const size_t socklen, 
      tsock_port_info_t *p_info)
{
   ASSERT(socklen > 0);
   ASSERT(sizeof(p_info->port_addr) == UNIX_PATH_MAX);

   int is_supported = FALSE;

   switch (sa_ptr->sa_family) {
   // IPv4 and IPv6 have different descriptors, hence the distinct
   // clauses
   case AF_INET:
      {
         const struct sockaddr_in *sin_ptr = (struct sockaddr_in*)sa_ptr;
         const int port = ntohs(sin_ptr->sin_port);
         const int res = snprintf(p_info->port_addr, 
               sizeof(p_info->port_addr), "%d", port);
         ASSERT(res > 0 && res < sizeof(p_info->port_addr));
         p_info->port_addr_len = res + 1;
         p_info->family = '4';
         is_supported = TRUE;
      }
      break;
   case AF_INET6:
      {
         const struct sockaddr_in6 *sin_ptr = (struct sockaddr_in6*)sa_ptr;
         const int port = ntohs(sin_ptr->sin6_port);
         const int res = snprintf(p_info->port_addr, 
               sizeof(p_info->port_addr), "%d", port);
         ASSERT(res > 0 && res < sizeof(p_info->port_addr));
         p_info->port_addr_len = res + 1;
         p_info->family = '6';
         is_supported = TRUE;
      }
      break;
   case AF_UNIX:
      {
         const struct sockaddr_un *sun_ptr = (struct sockaddr_un*)sa_ptr;
         ASSERT(socklen > sizeof(sa_family_t));
         // This should be a named socket, not unamed (i.e.,
         // socketpair)
         ASSERT(socklen != sizeof(sa_family_t));
         ASSERT(sun_ptr->sun_family == AF_UNIX);
         ASSERT(sizeof(sun_ptr->sun_path) == UNIX_PATH_MAX);

         if (sun_ptr->sun_path[0] == 0 && 
             socklen == sizeof(struct sockaddr_un)) {
            // Abstract address; starts with a null bytes, *all*
            // reamining bytes define the name of the socket
            size_t len = sizeof(sun_ptr->sun_path);
            memcpy(p_info->port_addr, &sun_ptr->sun_path[1], len-1);
            p_info->port_addr_len = len-1;
            p_info->family = 'A'; // Abstract
         } else {
            // Non-abstract address (i.e., pathname). sun_path is a
            // null-terminated string.
            size_t len = strlen(sun_ptr->sun_path);
            ASSERT(len > 0 && len <= sizeof(sun_ptr->sun_path));
            strncpy(p_info->port_addr, sun_ptr->sun_path, 
                  sizeof(p_info->port_addr));
            p_info->port_addr_len = len+1;
            // Empty strings are not valid pathnames
            ASSERT(strlen(p_info->port_addr) > 0);
            ASSERT(strlen(p_info->port_addr) < UNIX_PATH_MAX);
            p_info->family = 'C'; // Concrete
         }
         is_supported = TRUE;
      }
      break;
   case AF_NETLINK:
      // ssh client uses this, not sure why, perhaps to inspect kernel routing
      // tables?
      ASSERT(AF_ROUTE == AF_NETLINK);
      ASSERT(is_supported == FALSE);
      break;
   case AF_UNSPEC:
      // Bug; should be handled by upper layers (e.g., TSock_Connect)
      ASSERT(0);
      break;
   default:
      // if this fires, then add sa_famility to the unsupported list
      // OR actually implement support for it
      ASSERT_UNIMPLEMENTED_MSG(0, "sa_family=%d", sa_ptr->sa_family);
      ASSERT(is_supported == FALSE);
      break;
   }

   if (is_supported) {
      switch( s_info->protocol ) {
      case TSOCK_PROTOCOL_UDP:
      case TSOCK_PROTOCOL_TCP: {
         p_info->protocol = (s_info->protocol == TSOCK_PROTOCOL_UDP) ? 
            PROT_CHAR_UDP : PROT_CHAR_TCP;
         ASSERT(is_supported == TRUE);
         break;
      }
      case TSOCK_PROTOCOL_RAW:
      case TSOCK_PROTOCOL_RDM:
      case TSOCK_PROTOCOL_SEQPACKET:
      case TSOCK_PROTOCOL_PACKET:
         p_info->protocol = 0;
         is_supported = FALSE;
         break;
      default:
         ASSERT_UNIMPLEMENTED(0);
         break;
      }
   }
  
#if DEBUG
   if (is_supported) {
      ASSERT(p_info->port_addr_len > 0);
      ASSERT(p_info->port_addr_len <= sizeof(p_info->port_addr));
   }
#endif
   DEBUG_MSG(5, "is_supported=%d\n", is_supported);

   return is_supported;
}

/**
 * Calls through to TSockRegisterPort(). Assumes that tsocket has been
 * bound already (via a call to TSock_Bind()).
 */
void 
TSockRegister( tsock_socket_info_t *s_info )
{
   int res;

   ASSERT(TSockIsEnabled());
   DEBUG_ONLY(TSockVerifyDesc(s_info));
   ASSERT( s_info->family == TSOCK_FAMILY_SOCKET );

   if (s_info->registered_info == NULL) {
      char addr_buf[MAX_SOCKADDR_SIZE];
      socklen_t sock_len = sizeof(addr_buf);
      res = getsockname( s_info->fd, (struct sockaddr*)addr_buf, &sock_len );
      ASSERT( res == 0 );
      tsock_port_info_t port_info;
      if (TSockMakePortInfoFromSockAddr(s_info, (struct sockaddr*)addr_buf, 
               sock_len, &port_info)) {
         DEBUG_MSG( 5, 
               "Registering port (%c, %c, %s), socket type %d\n",
               port_info.family, port_info.protocol, port_info.port_addr, 
               s_info->protocol );
         ASSERT(s_info->registered_info == NULL);

         switch( s_info->protocol ) {
         case TSOCK_PROTOCOL_UDP:
         case TSOCK_PROTOCOL_TCP: {
            TSockRegisterPort( &port_info );
            s_info->registered_info = new_registered_info( &port_info );
            break;
         }
         case TSOCK_PROTOCOL_RAW:
         case TSOCK_PROTOCOL_RDM:
         case TSOCK_PROTOCOL_SEQPACKET:
         case TSOCK_PROTOCOL_PACKET:
            // For now, assume raw sockets are untagged.
            ASSERT(s_info->registered_info == NULL);
            break;
         default:
            ASSERT_UNIMPLEMENTED_MSG(0, "protocol=0x%x\n", 
                  s_info->protocol);
            break;
         }
      }
   } else {
      // Do nothing. Possible if user issues multiple bind calls.
   }
   return;
}

/**
 * Returns TRUE iff fd is a valid UDP or TCP socket and the remote
 * peer is a logging process that understands msg tags.
 *
 * Functions that operate on a connected socket and do not provide an
 *  explicit remote address (e.g. send,write) should provide to=NULL,
 * to_len = 0.
 */
static int 
TSockShouldSendTagged( tsock_socket_info_t *s_info, const struct sockaddr *to,
      const int to_len )
{
   int remote_accepts_tags = FALSE;
   const struct sockaddr_in *sin = (const struct sockaddr_in*)to;
   socklen_t sock_len = to_len;

#if DEBUG
   ASSERT( s_info->fd >= 0 );
   if (to) {
      ASSERT(to->sa_family != AF_UNSPEC);
   }
#endif

   switch( s_info->protocol ) {
   case TSOCK_PROTOCOL_UDP:
      // XXX: UDP implementation is unfinished/untested; so just say
      // that line is not tagged
      ASSERT(remote_accepts_tags == FALSE);
      break;
   case TSOCK_PROTOCOL_TCP: 
      {
         int should_do_query = FALSE, res;
         char addr_buf[MAX_SOCKADDR_SIZE];

         // Network message.  Is it a connected socket?
         if ( to==NULL ) {
            switch ( s_info->peer_info ) {
            case TSOCK_PEER_TAGS:
               remote_accepts_tags = TRUE;
               ASSERT(should_do_query == FALSE);
               break;
            case TSOCK_PEER_UNKNOWN:
               ASSERT(s_info->family == TSOCK_FAMILY_SOCKET);
               sin = (const struct sockaddr_in*)addr_buf;
               sock_len = sizeof(addr_buf);
               res = getpeername( s_info->fd, (struct sockaddr*)&addr_buf, 
                     &sock_len);
               ASSERT(sock_len > 0 && sock_len <= MAX_SOCKADDR_SIZE);
               if (res == 0) {
                  should_do_query = TRUE;
               } else {
                  // Probably not connected; send should fail
               }
               break;
            case TSOCK_PEER_NO_TAGS:
               ASSERT(should_do_query == FALSE);
               ASSERT(remote_accepts_tags == FALSE);
               break;
            default:
               ASSERT(0);
               break;
            }
         } else {
            ASSERT_COULDBE( s_info->protocol == TSOCK_PROTOCOL_TCP );
            ASSERT( s_info->family != TSOCK_FAMILY_PIPE );
            should_do_query = TRUE;
         }

         if (should_do_query) {
            ASSERT(sin);
            ASSERT(sock_len > 0);
            // New destination; find out whether it accepts tags.

            tsock_port_info_t port_info;
            if (TSockMakePortInfoFromSockAddr(s_info, (struct sockaddr*)sin, 
                     sock_len, &port_info)) {
               ASSERT_UNIMPLEMENTED_MSG( sin->sin_family == AF_INET ||
                     sin->sin_family == AF_INET6 || sin->sin_family == AF_UNIX,
                     "sin_family=%d", sin->sin_family );

               if (sin->sin_family == AF_UNIX) {
                  struct in_addr local_addr;
                  local_addr.s_addr = NetOps_GetLocalAddr();
                  remote_accepts_tags =
                     TSockQueryRemotePortServer( local_addr, &port_info );
               } else {
                  remote_accepts_tags =
                     TSockQueryRemotePortServer( sin->sin_addr, &port_info );
               }
            } else {
               remote_accepts_tags = FALSE;
            }

            // Save for duration of connection.
            s_info->peer_info = ( remote_accepts_tags ? TSOCK_PEER_TAGS : 
                  TSOCK_PEER_NO_TAGS );
         }
      }
      break;
   case TSOCK_PROTOCOL_RAW:
#if PRODUCT
#error "XXX"
      // XXX: used by ssh, not sure why
      ASSERT_UNIMPLEMENTED(0);
#else
      // assume untagged operation for now
      ASSERT(remote_accepts_tags == False);
      s_info->peer_info = TSOCK_PEER_NO_TAGS;
#endif
      break;
   default:
      // XXX: RDM, etc., or not an internet socket.
      // Figure out how to safely tag these at some point
      ASSERT_UNIMPLEMENTED(0);
      break;
   }
   DEBUG_MSG( 5, "should_send_tagged( %d ) <%d,%d,%d> : %d\n", s_info->fd,
         s_info->family, s_info->protocol, s_info->peer_info,
         remote_accepts_tags );

   return remote_accepts_tags;
}

/**
 * Returns TRUE iff fd is a valid UDP or TCP socket and the sender may
 * have added a tag to the message.
 */
static int 
TSockShouldRecvTagged( tsock_socket_info_t *s_info )
{
   int res = FALSE;
   ASSERT( s_info->fd >= 0 );
   DEBUG_MSG(5, "should_recv_tagged( %d ) <%d,%d,%d>\n", s_info->fd,
         s_info->family, s_info->protocol, s_info->peer_info );

   switch( s_info->protocol ) {
   case TSOCK_PROTOCOL_UDP:
      // No way to know sender in advance.  Look for tag.
      // res = TRUE
      res = FALSE; // XXX: currently not tested, so don't bother looking for tag

      break;
   case TSOCK_PROTOCOL_TCP:
      res = ( (s_info->peer_info == TSOCK_PEER_UNKNOWN) ||
            (s_info->peer_info == TSOCK_PEER_TAGS) );
      break;
   default:
#if PRODUCT
#error "XXX"
#endif
      // XXX: RAW, RDM, etc., or not an internet socket.
      // Figure out how to safely tag these at some point
      break;
   }     
   
   DEBUG_MSG(5, "should_recv_tagged: %d\n", res );

   return res;
}

/**
 * Resets a metadata struct.
 */
static void 
erase_md( tsock_msg_metadata * md )
{
   md->msg_len = 0;
   md->tag_len = 0;
   memset( md->tag, 0, TSOCK_MAX_TAG_LEN );
}

/**
 * Creates a tsock_tcp_state_t struct.
 */
static tsock_tcp_state_t * 
new_tcp_info()
{
   tsock_tcp_state_t * ts = (tsock_tcp_state_t*)malloc(sizeof(tsock_tcp_state_t));
   ts->bytes_left = 0;
   erase_md( &(ts->md) );
   ts->md_len = 0;
   memset( ts->md_buf, 0, TSOCK_MAX_METADATA_LEN );
   return ts;
}

/**
 * initializes a single tsock_socket_info_t.
 */
void 
TSockInitDesc( tsock_socket_info_t *s_info )
{
   s_info->fd = -1;
   s_info->family = 0;
   s_info->protocol = 0;
   s_info->peer_info = TSOCK_PEER_UNKNOWN;
   s_info->tcp_state = NULL;
   s_info->registered_info = NULL;
   s_info->peek_buf = NULL; // Lazily allocated on first use
   s_info->nr_b2b_peeks = 0;
}

/**
 * XXX: Replace with TSock_Socket, TSock_Pipe, TSock_Socketpair, etc...
 *
 * Called from sys_socket(), etc. to mark UDP/TCP sockets.
 */
void
TSock_Open( tsock_socket_info_t *s_info, const int fd, 
            const tsock_family_t family, const tsock_protocol_t protocol, 
            const tsock_peer_info_t peer_info )
{
   DEBUG_MSG(5, "set_socket_state( %d, %d )\n", fd, protocol);

   TSockInitDesc(s_info);

   ASSERT(s_info->fd == -1); // desc should be fresh
   s_info->fd = fd;
   s_info->family = family;
   s_info->protocol = protocol;
   s_info->peer_info = peer_info;

   switch (s_info->family) {
   case TSOCK_FAMILY_PIPE:
      // Both endpoints must be in the vkernel domain
      ASSERT(peer_info == TSOCK_PEER_TAGS);
      ASSERT(protocol == TSOCK_PROTOCOL_TCP);
      break;
   case TSOCK_FAMILY_SOCKET:
      ASSERT_COULDBE(peer_info == TSOCK_PEER_TAGS); // true for socketpairs
      break;
   default:
      ASSERT(0);
      break;
   }

   switch (s_info->protocol) {
   case TSOCK_PROTOCOL_TCP:
      // Need extra struct for tracking stream metadata:
      s_info->tcp_state = new_tcp_info();
      break;
   case TSOCK_PROTOCOL_UDP:
      // No state needs to be tracked
      break;
   default:
#if PRODUCT
#error "XXX"
      // Implement the rest eventually, but don't complain; just
      // don't tunnel these channels.
      ASSERT_UNIMPLEMENTED(0);
#endif
      break;
   }

   DEBUG_MSG(5, "new state[%d]: <%d,%d,%d,%p>\n", s_info->fd,
         s_info->family,
         s_info->protocol,
         s_info->peer_info,
         s_info->tcp_state );
   DEBUG_ONLY(TSockVerifyDesc(s_info));
}

/**
 * Called from log_*close().
 * Resets a single tsock_socket_info_t.
 */
void 
TSock_Close( tsock_socket_info_t *s_info )
{
   tsock_port_info_t * rp;

   DEBUG_ONLY(TSockVerifyDesc(s_info));
   DEBUG_MSG(5, "clear_socket_state( %d )\n", s_info->fd );  

   // clean up tcp_state
   if (s_info->tcp_state) {
      free(s_info->tcp_state);
      s_info->tcp_state = NULL;
   }

   // then clean up port info
   rp = s_info->registered_info;
   if (rp) {
      TSockUnregisterPort( rp );
      free( rp );
      s_info->registered_info = NULL;
   }

   if (s_info->peek_buf) {
      RingBuffer_Free(s_info->peek_buf);
      s_info->peek_buf = NULL;
   }

   // then reset everything.  
   TSockInitDesc(s_info);
}

static ssize_t
TSockSysRecvMsg( const tsock_socket_info_t *s_info, 
      struct msghdr *msg_p, const int msg_flags )
{
   ssize_t err;

   // We can't use recvmsg on pipes--kernel will give us a -ENOTSOCK error
   // code.
   switch (s_info->family) {
   case TSOCK_FAMILY_PIPE:
      err = SysOps_readv( s_info->fd, msg_p->msg_iov, msg_p->msg_iovlen );
      break;
   case TSOCK_FAMILY_SOCKET:
      // CAUTION: very important that you use SysOps_sendmsg rather
      // than dietlibc's sendmsg. The latter returns -1 on failure
      // rather than the kernel error code. This broke cptokfs on large
      // file transfers, for example, because the expected error code
      // -EAGAIN wasn't being returned, hence confusing it.
      err = SysOps_recvmsg( s_info->fd, msg_p, msg_flags );
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   return err;
}

static ssize_t
TSockSysRecv( const tsock_socket_info_t *s_info, char *buf, 
              const size_t buf_len, const int msg_flags, 
              struct sockaddr *from, socklen_t *from_len )
{
   ssize_t err;

   // We can't use recvmsg on pipes--kernel will give us a -ENOTSOCK error
   // code.
   switch (s_info->family) {
   case TSOCK_FAMILY_PIPE:
      ASSERT(!from);
      err = SysOps_read( s_info->fd, buf, buf_len );
      break;
   case TSOCK_FAMILY_SOCKET:
      // CAUTION: very important that you use SysOps_sendmsg rather
      // than dietlibc's sendmsg. The latter returns -1 on failure
      // rather than the kernel error code. This broke cptokfs on large
      // file transfers, for example, because the expected error code
      // -EAGAIN wasn't being returned, hence confusing it.
      err = SysOps_recvfrom( s_info->fd, buf, buf_len, msg_flags, from, from_len );
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   return err;
}

#if PRODUCT
#error "XXX: doesn't work with back-to-back MSG_PEEK requests"
#else
// If MSG_PEEK is specified in @msg_flags, then all data is
// queued/copied into a peek buffer (as well as @buf). 
// Subsequent non-peeked receives dequeue data from the peek buffer
// first before dequeueing data from the kernel buffer.
//
// We know of at least one app that uses MSG_PEEK: KFS client
// 'cptokfs'.
static ssize_t
TSockPeekableRecv( tsock_socket_info_t *s_info, char *buf, 
                   const size_t buf_len, const int msg_flags,
                   struct sockaddr *from, socklen_t *from_len )
{
   const int msg_flags_no_peek = msg_flags & ~MSG_PEEK;
   ssize_t len = 0;

   if (msg_flags & MSG_PEEK) {
      len = TSockSysRecv(s_info, buf, buf_len, msg_flags_no_peek,
               from, from_len);
      if (len > 0) {
         // Enqueue received data into the peek buf.
         // Here we lazily create the peek buf (i.e., on first
         // use), to be memory efficient
         if (!s_info->peek_buf) {
            s_info->peek_buf = RingBuffer_Alloc();
         }
         RingBuffer_Queue(s_info->peek_buf, buf, len);
      }
   } else {
      size_t queue_count = s_info->peek_buf ? 
         RingBuffer_GetCount(s_info->peek_buf) : 0;
      size_t deq_count = MIN(buf_len, queue_count);

      // Dequeue from the peek buf first
      if (queue_count > 0) {
         ASSERT(s_info->peek_buf);
         RingBuffer_Dequeue(s_info->peek_buf, buf, deq_count);
      }

      DEBUG_MSG(5, "got %d of %d bytes from queue\n", queue_count, buf_len);

      len += deq_count;

      // If user wants more, then dequeue from the real buffer
      // (i.e., that in the kernel)
      if (deq_count < buf_len) {
         ssize_t res;
         res = TSockSysRecv(s_info, buf+deq_count, buf_len - deq_count, 
                  msg_flags_no_peek, from, from_len);
         DEBUG_MSG(5, "got %d bytes from kernel\n", res);
         if (res > 0) {
            len += res;
         } else {
            if (len == 0) {
               len = res;
            } else {
               // There was some data in the peek buffer; we need
               // to return that before reporting the error/eof
               ASSERT(len > 0);
            }
         }
      }
   }

   return len;
}
#endif

#if 0
static ssize_t
TSockPeekableRecv2( tsock_socket_info_t *s_info, char *buf, 
                   const size_t buf_len, const int msg_flags,
                   struct sockaddr *from, socklen_t *from_len )
{
   const int msg_flags_no_peek = msg_flags & ~MSG_PEEK;
   const int is_peek = msg_flags & MSG_PEEK;
   ssize_t len = 0, ring_count, rem_count;

   if (is_peek) {
      // Try to get the requested amount @buf_len into the peek
      // buffer, if it isn't there already.
      if (!s_info->peek_buf) {
         s_info->peek_buf = RingBuffer_Alloc();
      }

      ring_count = RingBuffer_GetCount(s_info->peek_buf);
      rem_count = buf_len - ring_count;
      if (rem_count > 0) {
         // Not enough data in the ring buffer to satisfy request.
         // Try to load in more data.
         len = RingBuffer_Recv(s_info->fd, rem_count, msg_flags_no_peek);
         if (len <= 0) {
            return len;
         }
      }
   }

   // Service as much of the request as possible from the peek buffer 
   // first, if there is one.
   ring_count = s_info->peek_buf ? 
      RingBuffer_GetCount(s_info->peek_buf) : 0;
   ssize_t deq_count = MIN(buf_len, ring_count);

   if (ring_count > 0) {
      ASSERT(s_info->peek_buf);
      if (is_peek) {
         RingBuffer_Peek(s_info->peek_buf, buf, deq_count);
      } else {
         RingBuffer_Dequeue(s_info->peek_buf, buf, deq_count);
      }
   }

   len += deq_count;
   ssize_t rem_count = buf_len - deq_count;
   ASSERT(rem_count >= 0);

   // If we couldn't service the entire request from the peek
   // buffer, then ask the kernel for more data.
   if (rem_count > 0) {
      ssize_t res;
      res = recvfrom(s_info->fd, buf+deq_count, rem_count,
            msg_flags_no_peek, from, from_len);
      if (res > 0) {
         len += res;
      } else {
         if (len == 0) {
            len = res;
         } else {
            // There was some data in the peek buffer; we need
            // to return that before reporting the error/eof
            ASSERT(len > 0);
         }
      }
   }

   return len;
}

static ssize_t
TSockPeekableRecv3( tsock_socket_info_t *s_info, char *buf, 
                   const size_t buf_len, const int msg_flags,
                   struct sockaddr *from, socklen_t *from_len )
{
   const int msg_flags_no_peek = msg_flags & ~MSG_PEEK;
   ssize_t len = 0;

   if (msg_flags & MSG_PEEK) {
      len = recvfrom(s_info->fd, buf, buf_len, msg_flags_no_peek,
               from, from_len);
      if (len > 0) {
         // Enqueue received data into the peek buf.
         // Here we lazily create the peek buf (i.e., on first
         // use), to be memory efficient
         if (!s_info->peek_buf) {
            s_info->peek_buf = RingBuffer_Alloc();
         }
         RingBuffer_Queue(s_info->peek_buf, buf, len);
      }
   } else if (new_gen) {
      size_t queue_count = s_info->peek_buf ? 
         RingBuffer_GetCount(s_info->peek_buf) : 0;
      size_t deq_count = MIN(buf_len, queue_count);

      // Dequeue from the peek buf first
      if (queue_count > 0) {
         ASSERT(s_info->peek_buf);
         RingBuffer_Dequeue(s_info->peek_buf, buf, deq_count);
      }

      len += deq_count;

      // If user wants more, then dequeue from the real buffer
      // (i.e., that in the kernel)
      if (deq_count < buf_len) {
         ssize_t res;
         res = recvfrom(s_info->fd, buf+deq_count, buf_len - deq_count, 
                  msg_flags_no_peek, from, from_len);
         if (res > 0) {
            len += res;
         } else {
            if (len == 0) {
               len = res;
            } else {
               // There was some data in the peek buffer; we need
               // to return that before reporting the error/eof
               ASSERT(len > 0);
            }
         }
      }
   }

   return len;
}
#endif

/* Checks for data available to be read on socket like select, but takes 
 * our user-land peek buffer into account as well. */
int
TSock_IsDataAvailable( const tsock_socket_info_t *s_info, int flags )
{
   int is_data_in_peek_buf = s_info->peek_buf && 
      RingBuffer_GetCount(s_info->peek_buf) != 0;

   int res, data_is_waiting;
   fd_set readfds;
   struct timeval timeout = { .tv_sec = 0, .tv_usec = 0 };
   FD_ZERO(&readfds);
   FD_SET(s_info->fd, &readfds);
   res = select(s_info->fd+1, &readfds, NULL, NULL, &timeout);
   ASSERT( res == 0 || res == 1 );
   data_is_waiting = (res == 1);

   return (!(flags & MSG_PEEK) && is_data_in_peek_buf) || data_is_waiting;
}

static void
TSockAddChunkToBuf(const tsock_msg_metadata *md_ptr, 
                     tsock_chunk_t *chunk_buf,
                     int *nr_chunks_ptr, const int max_nr_chunks, 
                     const size_t data_off)
{
   ASSERT(*nr_chunks_ptr >= 0);
   ASSERT(max_nr_chunks > 0);
   ASSERT_UNIMPLEMENTED_MSG(*nr_chunks_ptr < max_nr_chunks,
         "nr_chunks=%d max_nr_chunks=%d", *nr_chunks_ptr, max_nr_chunks);

   tsock_chunk_t *chunk_ptr = &chunk_buf[*nr_chunks_ptr];

   if (md_ptr) {
      ASSERT(sizeof(chunk_ptr->tag_buf) >= md_ptr->tag_len);
      memcpy(chunk_ptr->tag_buf, md_ptr->tag, md_ptr->tag_len);
      chunk_ptr->tag_len = md_ptr->tag_len;
   } else {
      chunk_ptr->tag_len = 0;
   }
   chunk_ptr->data_off = data_off;

   (*nr_chunks_ptr)++;
}

/**
 * Pack metadata into a byte array.
 * Returns the number of bytes written.
 *
 * Metadata Format:
 * 4B Magic (Mostly a sanity check)
 * 4B Message Length (does not include metadata length)
 * 1B Tag length
 * *B Tag (No NUL termination, truncated at TSOCK_MAX_TAG_LEN)
 */
static size_t 
TSockWriteMetaData( char * buf, size_t buf_len, size_t data_len, 
      char const * tag, size_t tag_len )
{
   char *buf_p = buf;

   ASSERT( buf_len >= TSOCK_MAX_METADATA_LEN );

   // First add the Magic
   // TODO: consider replacing magic with checksum.
   *(uint32_t*)buf_p = htonl(TSOCK_MAGIC_CODE_WORD);
   buf_p += sizeof(uint32_t);

   // Then the original message length (4-byte field).
   *(uint32_t*)buf_p = htonl(data_len);
   buf_p += sizeof(uint32_t);

   // Now add the tag, with 1-byte length field.
   ASSERT(tag_len <= TSOCK_MAX_TAG_LEN);
   *buf_p++ = tag_len;
   memcpy( buf_p, tag, tag_len );
   buf_p += tag_len;

   if (DEBUG) print_buf( "metadata", buf, buf_p-buf );

   return (buf_p - buf);
}

/**
 * Reads metadata from byte array into metadata struct.
 * May not read tag if provided array is too short.
 * If at least core metadata (all but tag) was read successfully,
 * return the length of the entire metadata, including tag.
 * Otherwise, return one of the LL_MD_* codes on failure.
 */
static int 
TSockReadMetaData( tsock_msg_metadata *md, char const * buf, size_t buf_len )
{
   uint8_t tag_len;
   size_t md_len;
   uint32_t net_magic = htonl(TSOCK_MAGIC_CODE_WORD);
   char const *buf_p = buf;
   ASSERT( md != NULL );

   if (DEBUG) print_buf( "reading metadata", buf, buf_len );

   // Check magic word (or as many bytes as are available).
   DEBUG_MSG(5, "Magic: 0x%x vs. 0x%x\n", *((uint32_t*)buf_p), net_magic );
   if( 0 != memcmp( buf_p, &net_magic, MIN(buf_len, sizeof(uint32_t)) ) ) {
      return LL_MD_NOT_MAGIC;
   }

   // LL_MD_NOT_MAGIC takes precedence over LL_MD_TRUNCATED.
   if( buf_len < sizeof(uint32_t) ) return LL_MD_TRUNCATED;
   buf_p += sizeof(uint32_t);

   // Now check for rest of core metadata (all but tag)
   if( buf_len < TSOCK_MIN_METADATA_LEN ) return LL_MD_TRUNCATED;

   // Then the original message length (4-byte field).
   md->msg_len = ntohl(*(uint32_t*)buf_p);
   buf_p += sizeof(uint32_t);

   // Now the tag length.
   md->tag_len = tag_len = *(uint8_t*)buf_p;
   if( tag_len > TSOCK_MAX_TAG_LEN ) return LL_MD_INVALID;
   ++buf_p;

   // Compute total metadata length.
   md_len = TSOCK_MIN_METADATA_LEN + tag_len;

   DEBUG_MSG(5, "read_metadata: md_len=%d, buf_len=%d\n", md_len, buf_len );
   // Read the tag in, if available. Otherwise, wait for later.
   if( md_len <= buf_len ) {
      memcpy( md->tag, buf_p, tag_len );
      buf_p += tag_len;
   }
   ASSERT( (buf_p - buf) <= buf_len );
   return md_len;
}


/**
 * Receives and decodes a single datagram.
 * Assumes that fd is a UDP socket.
 * Returns the length of the decoded message.
 */
static ssize_t 
TSockRecvDatagram( tsock_socket_info_t *s_info, struct msghdr *msg_ptr,
      int flags, tsock_chunk_t *chunk_buf, int *nr_chunks_ptr )
{
   /* XXX: not going to fit in our stack. */
   ASSERT_UNIMPLEMENTED(0);
   char wrapped_buf[TSOCK_MAX_DATAGRAM_LEN];
   size_t to_read;
   ssize_t bytes_read;
   tsock_msg_metadata md;
   size_t md_len;
   char *buf = msg_ptr->msg_iov->iov_base;
   size_t buf_len = msg_ptr->msg_iov->iov_len;
   const int chunk_buf_len = *nr_chunks_ptr;

   DEBUG_MSG( 5, "recv_wrapped_datagram( %d )\n", s_info->fd );
   ASSERT( s_info->fd >= 0 );
   ASSERT( nr_chunks_ptr );
   // Default
   *nr_chunks_ptr = 0;

   // Have not tested flags:
   ASSERT( (flags == 0) || (flags == MSG_DONTWAIT) );
   to_read = MIN(TSOCK_MAX_DATAGRAM_LEN,	// Do not read more than
         (buf_len+TSOCK_MAX_METADATA_LEN));	// necessary.
   bytes_read = SysOps_recvfrom( s_info->fd, wrapped_buf, to_read, flags, 
         msg_ptr->msg_name, &msg_ptr->msg_namelen );
   DEBUG_MSG( 5, "recvfrom returned %d\n", bytes_read );  
   ASSERT( (bytes_read < 0) || ((size_t)bytes_read <= to_read) );

   if( bytes_read >= 0 ) {
      // Try to parse prepended metadata tag
      int rm_ret = TSockReadMetaData( &md, wrapped_buf, bytes_read );
      DEBUG_MSG( 5, "read_metadata(1) returned %d\n", rm_ret );        
      switch( rm_ret ) {
      case LL_MD_NOT_MAGIC:
      case LL_MD_TRUNCATED:
      case LL_MD_INVALID:
         // Any failure to parse metadata is assumed to mean that the
         // message is not tagged.  This assumption fails if the metadata
         // was merely truncated; we hope that case is uncommon, and that
         // the application can handle the occasional gibberish packet.
         if (DEBUG) print_buf( "Assuming not tagged:", wrapped_buf, bytes_read );
         // TODO: postpone this copy until we have the global scheduler
         // lock, to avoid race conditions.
         memcpy( buf, wrapped_buf, bytes_read );      
         break;

      default:
         // Valid metadata.  Return value is length.
         md_len = rm_ret;
         if( md_len > bytes_read ) {	// Tag truncated, no app data.
            bytes_read = 0;
         } else {
            bytes_read -= md_len;	// Hide metadata from app.
            // TODO: We could avoid this copy if we fix the length of the tag
            // field, so we could use a fixed length iovec to read the metadata.
            memcpy( buf, &wrapped_buf[md_len], bytes_read );
            if (DEBUG) print_buf( "Decoded app msg", buf, bytes_read );
            TSockAddChunkToBuf(&md, chunk_buf, nr_chunks_ptr, 
                  chunk_buf_len, 0);
         }
         break;
      }
   }
   return bytes_read;
}


/**
 * Reads the next chunk of metadata from a TCP stream.
 * buf_len is the number of application bytes requested.  We should
 *   never read more than that from the stream until we are sure that
 *   the stream is tagged.
 * Returns 0 normally, < 0 on error.  If metadata is completely read
 * and parsed, s_info->bytes_left is set to nonzero.
 */
static ssize_t 
TSockReadStreamMetaData( tsock_socket_info_t *s_info, int buf_len, 
      const int flags)
{
   ASSERT( s_info->tcp_state->bytes_left == 0 );	// Not in a data chunk.
   size_t to_read;  
   ssize_t bytes_read;
   size_t full_md_len;
   int rm_ret;
   tsock_msg_metadata scratch_md;	// Don't want to modify
   // s_info->tcp_state->md unless we're sure.

   DEBUG_MSG(5, "read_stream_metadata( %d )\n", s_info->fd );
   ASSERT (s_info->fd >= 0 );

   /* Phase 1: Make sure we can read the length fields. */
   // How much more to read?
   while( s_info->tcp_state->md_len < TSOCK_MIN_METADATA_LEN ) {
      to_read = TSOCK_MIN_METADATA_LEN-s_info->tcp_state->md_len;
      if( (s_info->peer_info == TSOCK_PEER_UNKNOWN) && (to_read > buf_len) ) {
         // The stream might not be tagged.  Be careful not to read too
         //  much.  We'll loop if necessary.

         // FIXME -- if we loop here, we're assuming the tag
         // exists.  Might as well kick to_read all the way
         // up, right? 
         to_read = buf_len;
      } // else, read the whole tag.

      DEBUG_MSG(5, " have %d/%d, need %d, flags=0x%x\n", 
            s_info->tcp_state->md_len,
            TSOCK_MIN_METADATA_LEN, to_read, flags );
      bytes_read = TSockPeekableRecv(s_info, 
            &(s_info->tcp_state->md_buf[s_info->tcp_state->md_len]),
            to_read, flags, NULL, NULL );

      ASSERT( (bytes_read < 0) || ((size_t)bytes_read <= to_read) );
      DEBUG_MSG(5, "bytes_read=%d\n", bytes_read);
      if( bytes_read < 0 ) {
         return bytes_read;	// socket failure, or empty.
      }

      //ASSERT(bytes_read > 0);
      // else, at least some read. 
      s_info->tcp_state->md_len += bytes_read;

      if( s_info->tcp_state->md_len < TSOCK_MIN_METADATA_LEN ) {
         // Not done yet; check what we have so far.
         rm_ret = TSockReadMetaData( &scratch_md, s_info->tcp_state->md_buf, 
               s_info->tcp_state->md_len );    
         DEBUG_MSG(5, "read_metadata(2) returned %d\n", rm_ret );

         switch( rm_ret ) {
         case LL_MD_NOT_MAGIC:
         case LL_MD_INVALID:
            // As with datagrams, we assume that a parse failure means the
            // message is not tagged.
            ASSERT( s_info->peer_info == TSOCK_PEER_UNKNOWN );
            if (DEBUG) print_buf( "Assuming not tagged:", s_info->tcp_state->md_buf, s_info->tcp_state->md_len );      
            // Signal caller to recover read bytes, reset state:
            s_info->peer_info = TSOCK_PEER_NO_TAGS;
            return 0;
            break;
         case LL_MD_TRUNCATED:
            if( bytes_read < to_read ) {
               return 0;	// No error, but drained for now
            } else {
               continue;	// Just a small buf_len.  Keep trying.
            }
            break;
         default:
            FATAL( "Should not reach this case" );
         }
      }	// else, loop condition should drop out.
   }

   /* Phase 2: Finish reading (variable-length) tag */
   ASSERT( s_info->tcp_state->md_len >= TSOCK_MIN_METADATA_LEN );

   rm_ret = TSockReadMetaData( &scratch_md, s_info->tcp_state->md_buf, 
         s_info->tcp_state->md_len );
   DEBUG_MSG(5, "read_metadata(3) returned %d\n", rm_ret );          
   switch( rm_ret ) {
   case LL_MD_NOT_MAGIC:
   case LL_MD_INVALID:
      // As with datagrams, we assume that a parse failure means the
      // message is not tagged.


      // There's a bug if we can't parse the metadata header of a
      // tagged socket.
      ASSERT_MSG( s_info->peer_info == TSOCK_PEER_UNKNOWN,
            "peer_info=0x%x", s_info->peer_info );

      if (DEBUG) print_buf( "Assuming not tagged:", s_info->tcp_state->md_buf,
            s_info->tcp_state->md_len );      
      // Signal caller to recover read bytes, reset state:
      s_info->peer_info = TSOCK_PEER_NO_TAGS;
      return 0;
      break;
   case LL_MD_TRUNCATED:
      FATAL( "Should not reach this case." );
      return 0;	// To calm compiler warnings.
      break;

   default:
      // Valid metadata.  Return value is length.    
      full_md_len = rm_ret;
      // Mark this as known tagged.
      ASSERT( s_info->peer_info != TSOCK_PEER_NO_TAGS );
      // Or else why did we even check for tags?
      if( s_info->peer_info == TSOCK_PEER_UNKNOWN ) {
         DEBUG_MSG(5, "Marking stream as tagged.\n" );
         s_info->peer_info = TSOCK_PEER_TAGS;
      }

      to_read = (full_md_len - s_info->tcp_state->md_len);
      ASSERT( to_read > 0 );	// Must still read tag.

      bytes_read = TSockPeekableRecv( s_info,
            &(s_info->tcp_state->md_buf[s_info->tcp_state->md_len]),
            to_read, flags, NULL, NULL );


      ASSERT( (bytes_read < 0) || ((size_t)bytes_read <= to_read) );
      if( bytes_read < 0 ) {
         return bytes_read;	// socket failure
      }
      s_info->tcp_state->md_len += bytes_read;
      if( full_md_len == s_info->tcp_state->md_len ) {
         // Finally have full metadata in buffer.  
         // Read everything, including tag, into real struct.  Cannot fail:
         const size_t UNUSED res = TSockReadMetaData( &(s_info->tcp_state->md), 
               s_info->tcp_state->md_buf,
               s_info->tcp_state->md_len );
         ASSERT(full_md_len == res);
         // Reset counters, switch to phase 2.
         s_info->tcp_state->bytes_left = s_info->tcp_state->md.msg_len;
         s_info->tcp_state->md_len = 0;
      }	// else we'll try again later.
      return 0;
   }
}

/**
 * Reads application data from the TCP stream until buffer is full or
 * we hit next chunk of metadata.
 */
static ssize_t 
TSockReadStreamData( tsock_socket_info_t *s_info, char * buf, size_t buf_len,
      const int flags, struct sockaddr *from, socklen_t *from_len)
{
   size_t to_read;
   ssize_t bytes_read;

   ASSERT( s_info->tcp_state->bytes_left > 0 );
   ASSERT( s_info->fd >= 0 );

   DEBUG_MSG(5, "read_stream_data( %d, %d )\n", s_info->fd, 
         s_info->tcp_state->bytes_left );

   // Do not read more than necessary.
   to_read = MIN(buf_len, s_info->tcp_state->bytes_left);	

   bytes_read = TSockPeekableRecv(s_info, buf, to_read, flags, from, 
         from_len);
   ASSERT( (bytes_read < 0) || ((size_t)bytes_read <= to_read) );

   if( bytes_read > 0 ) {
      s_info->tcp_state->bytes_left -= bytes_read;
   } 

   DEBUG_MSG(5, "bytes_read=%d bytes_left=%d\n", bytes_read,
         s_info->tcp_state->bytes_left);
   return bytes_read;
}

/**
 * Receives and decodes a single message from a stream. The challenge
 * here is that the message may contain multiple send chunks or a portion 
 * of one. 
 *
 * Assumes that fd is a TCP socket.
 * Returns the length of the decoded message.
 * Return the metadata for each (partial) chunk that was received.
 */
static ssize_t 
TSockRecvStream( tsock_socket_info_t * s_info, struct msghdr * msg_ptr,
      const int flags, tsock_chunk_t *chunk_buf, const int chunk_buf_len,
      int * nr_chunks_ptr )
{
   /*
    * This message may consume bytes that were sent by multiple calls to
    * send_wrapped_msg().  We therefore need to be careful about
    * extracting the metadata.
    */
   size_t bytes_read_total = 0; // # of data (non-metadata) bytes read

   ASSERT(chunk_buf_len > 0);

   /* XXX: could be >= 0 since we may be invoked on
    * the receive fastpath, in which case we may be passed in
    * multicomponent iovec rather than a 1-component iovec pointing
    * to the log entry. */
   ASSERT_UNIMPLEMENTED_MSG(msg_ptr->msg_iovlen == 1, "%d", msg_ptr->msg_iovlen);
   char *buf = msg_ptr->msg_iov->iov_base;
   const size_t buf_len = msg_ptr->msg_iov->iov_len;

   DEBUG_MSG(5, "recv_wrapped_stream( %d )[%d]\n", s_info->fd, buf_len );

#if DEBUG
   // Have not tested all flags.
   const int tested_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
   ASSERT_UNIMPLEMENTED_MSG( !(flags & ~tested_flags),
         "flags=0x%x", flags);
#endif

   /* The following loop should alternate phases.  Every other iteration,
    * read_stream_metadata() should set bytes_left to the size of the
    * next data chunk; on the following iteration read_stream_data()
    * should empty that data and reset bytes_left.  If the phase does
    * not switch after read_stream_*(), the underlying socket must be
    * (possibly temporarily) drained; just return early.
    */
   while( bytes_read_total < buf_len ) {
      DEBUG_MSG(5, "bytes_read_total=%d\n", bytes_read_total);

      if( s_info->tcp_state->bytes_left == 0 ) {	// Start new send() chunk.
         DEBUG_MSG(5, "starting new chunk\n");
         const ssize_t rsm_ret = TSockReadStreamMetaData( s_info, 
               (buf_len-bytes_read_total), flags );
         // 0 indicates no problems, not EOF
         // If there is EOF, then that would show up as invalid medata
         ASSERT(rsm_ret < 0 || rsm_ret == 0);

         if( rsm_ret < 0 ) {
            // FIXME: Socket error, but perhaps some bytes already
            // received?  Should they be returned first?
            return rsm_ret;
         } else if( s_info->peer_info != TSOCK_PEER_TAGS ) {
            // Stream is not tagged after all.
            ASSERT( bytes_read_total == 0 );	// Should be first try.
            TSockAddChunkToBuf(NULL, chunk_buf, nr_chunks_ptr, 
                  chunk_buf_len, bytes_read_total);

            memcpy( &(buf[bytes_read_total]), s_info->tcp_state->md_buf,
                  s_info->tcp_state->md_len );
            bytes_read_total = s_info->tcp_state->md_len;
            s_info->tcp_state->md_len = 0;	// Reset for possible reuse?

            /* XXX: we should consume more bytes rather than
             * return; though correct, this is a significant
             * deviation from the default Linux behavior -- to see
             * the difference try test/no-libc/38-socketpair with
             * and without. */
            ASSERT(bytes_read_total >= 0);
            // could've gotten err or EOF on metadata read, hence
            // causing md_len to be 0
            ASSERT_COULDBE(bytes_read_total == 0); 
            return bytes_read_total;
         } else if( s_info->tcp_state->bytes_left == 0 ) {	// Stream drained.
            return bytes_read_total;
         } // else:
         // Metadata complete. 
      } else {	// Finish last send() chunk
         const size_t rem_bytes = buf_len - bytes_read_total;

         DEBUG_MSG(5, "finish send chunk (%d, %d)\n", s_info->tcp_state->bytes_left, rem_bytes);

         const ssize_t bytes_read =
            TSockReadStreamData( s_info, &(buf[bytes_read_total]),
                  rem_bytes, flags, msg_ptr->msg_name,
                  &msg_ptr->msg_namelen);

         if( bytes_read < 0 ) {
            return bytes_read;
         } else {
            if (bytes_read > 0) {
               TSockAddChunkToBuf(&s_info->tcp_state->md, chunk_buf, 
                     nr_chunks_ptr, chunk_buf_len, bytes_read_total);
            }

            bytes_read_total += bytes_read;
            if( s_info->tcp_state->bytes_left > 0 ) {	// recv() could not finish chunk.
               return bytes_read_total;
            }
         }
      }

#if PRODUCT
#error "XXX: call to sys_select bad for performance"
#else
      /* To accomodate the vkernel scheduler, we must be careful
       * not to block while receiving message tags and body. Recall
       * that we are holding the VCPU lock (so that we can write to the
       * log file). Hence other tasks cannot run on this VCPU while we
       * continue to hold it. So we must
       * first check if there is data waiting, and call sys_recv only
       * if that is the case, hence avoiding blocking/deadlock.
       *
       * XXX: we shouldn't need this select once we get rid of our
       * user-land scheduler, and move to the kernel based
       * scheduler. 
       *
       * XXX: another solution might be to have higher layers pass in a
       * count of the receive buffer and attempt to dequeue only that
       * much. We wouldn't need this check if the count is accurate.
       * */
      if (!TSock_IsDataAvailable(s_info, flags)) {
         // We can't block so bail out
         // XXX: what if bytes_read_total == 0? In that case, we
         // shouldn't bail. Once way to resolve this is to never invoke
         // TSock_Recv unless we can be sure than bytes_read_total > 0.
         return bytes_read_total;
      }
#endif
   }
   ASSERT( bytes_read_total <= buf_len );
   return bytes_read_total;
}

/**
 * Receives and decodes a single message from a stream.
 * Assumes that fd is a UDP or TCP socket.
 * Sets tag and vclock to metadata from message, or something
 *   reasonable if that fails.
 * Returns the length of the decoded message.
 */
ssize_t 
TSock_Recv( tsock_socket_info_t * s_info, struct msghdr * msg_ptr,
      const int flags, tsock_chunk_t *chunk_buf, int *nr_chunks_ptr )
{
   DEBUG_ONLY(TSockVerifyDesc(s_info));
   ASSERT(chunk_buf);
   ASSERT(nr_chunks_ptr);
   // A 0 buffer count is valid in Linux
   ASSERT_UNIMPLEMENTED(msg_ptr->msg_iovlen > 0);

   ssize_t res;
   const int chunk_buf_len = *nr_chunks_ptr;
   ASSERT(chunk_buf_len > 0);
   *nr_chunks_ptr = 0;

   DEBUG_MSG(5, "recv_wrapped_msg( %d, %s )\n", s_info->fd,
         flags & MSG_PEEK ? "peek" : "dequeue");
   /* We use different methods for receiving messages on UDP and TCP
    * sockets, because the operating system treats the buffer length
    * field differently, and because TCP may require extra work to
    * extract the message metadata.
    */
   /* FIXME -- To allow for non-logged senders, include
    * TSOCK_PROTOCOL_*_NEW state, and revert to ..._OTHER state if first
    * packet does not include MAGIC. */
   if (TSockIsEnabled() && TSockShouldRecvTagged(s_info)) {
      if ( s_info->protocol == TSOCK_PROTOCOL_UDP ) {
         res = TSockRecvDatagram( s_info, msg_ptr, flags, chunk_buf,
                  nr_chunks_ptr );
         // XXX: Add chunks to buf
         ASSERT_UNIMPLEMENTED(0);
      } else {
         ASSERT_UNIMPLEMENTED( s_info->protocol == TSOCK_PROTOCOL_TCP );
         tsock_tcp_state_t tcp_state_ckpt;
         tsock_peer_info_t peer_info_ckpt = 0;

         if (flags & MSG_PEEK) {
            // Checkpoint current TCP state, we'll need to undo the changes 
            // we are about to make, since we just peeking, and not
            // actually dequeueing the message.
            tcp_state_ckpt = *s_info->tcp_state;
            peer_info_ckpt = s_info->peer_info;
            s_info->nr_b2b_peeks++;
            // XXX: back-to-back MSG_PEEK requests not yet supported.
            // We haven't encounter this in an app yet. KFS's cptokfs
            // comes close in its use of MSG_PEEK, though.
            // See no-libc/43-recv-peek for an example that triggers
            // this.
            ASSERT_UNIMPLEMENTED(s_info->nr_b2b_peeks < 2);
         } else {
            s_info->nr_b2b_peeks = 0;
         }

         res = TSockRecvStream( s_info, msg_ptr, flags, chunk_buf,
                  chunk_buf_len, nr_chunks_ptr );
         if (res > 0) {
            DEBUG_MSG(8, "received data=%s\n", msg_ptr->msg_iov[0].iov_base);
         }

         if (flags & MSG_PEEK) {
            s_info->peer_info = peer_info_ckpt;
            *s_info->tcp_state = tcp_state_ckpt;
         }
      }
      ASSERT(res > 0 || *nr_chunks_ptr == 0);
   } else {
      /* Channel isn't tagged, so we assume there is just one
       * chunk. We'll treat the entire message as one chunk (albeit
       * without a tag). */
      res = TSockSysRecvMsg( s_info, msg_ptr, flags );
      if (res > 0) {
         TSockAddChunkToBuf(NULL, chunk_buf, nr_chunks_ptr, 
               chunk_buf_len, 0);
      }
      ASSERT(res > 0 || *nr_chunks_ptr == 0);
   }

   return res;
}

ssize_t
TSockSysSend( const tsock_socket_info_t *s_info, const struct msghdr *msg_ptr,
              const int flags )
{
   ssize_t err;

   // We can't use sendmsg on pipes--kernel will give us a -ENOTSOCK error
   // code.
   switch (s_info->family) {
   case TSOCK_FAMILY_PIPE:
      err = SysOps_writev( s_info->fd, msg_ptr->msg_iov, msg_ptr->msg_iovlen );
      break;
   case TSOCK_FAMILY_SOCKET:
      // CAUTION: very important that you use SysOps_sendmsg rather
      // than dietlibc's sendmsg. The latter returns -1 on failure
      // rather than the kernel error code. This broke cptokfs on large
      // file transfers, for example, because the expected error code
      // -EAGAIN wasn't being returned, hence confusing it.
      err = SysOps_sendmsg( s_info->fd, msg_ptr, flags );
      break;
   default:
      ASSERT_UNIMPLEMENTED_MSG(0, "family=%d", s_info->family);
      break;
   }
   return err;
}

// How much space is free in the kernel send buffer for the given tsocket?
static size_t
TSockGetAvailSendQueueSpace(const tsock_socket_info_t *s_info)
{
   int used_nr_bytes = 0, avail_nr_bytes;

   ASSERT_UNIMPLEMENTED_MSG(s_info->protocol == TSOCK_PROTOCOL_UDP ||
         s_info->protocol == TSOCK_PROTOCOL_TCP, "protocol=%d", 
         s_info->protocol);
   UNUSED int res = SysOps_ioctl(s_info->fd, 
         s_info->family == TSOCK_FAMILY_PIPE ? 
         FIONREAD : SIOCOUTQ, &used_nr_bytes);
   ASSERT_MSG(res == 0, "family=%d protocol=%d res=%d", 
         s_info->family, s_info->protocol, res);

   if (s_info->family == TSOCK_FAMILY_PIPE) {
#define MAX_PIPE_BYTES 4096*12
      // XXX: Kernel apparently rounds available write space down to
      // the nearest page boundary, hence the PAGE_START(). But I'm not
      // sure why this is needed. This could potentially severly limit
      // tsocket pipe bandwidth.
      avail_nr_bytes = PAGE_START(MAX(0, MAX_PIPE_BYTES - used_nr_bytes));
   } else {
      ASSERT(s_info->family == TSOCK_FAMILY_SOCKET);
      // Kernel doubles the available queue space for bookkeeping
      // overhead (see man socket(7)); we get back this doubled space, 
      // so divide by 2 to get actual queue limit
      int doubled_queue_space = 0;
      socklen_t opt_len = sizeof(doubled_queue_space);
      // XXX: avoid the syscall by watching calls to getsockopt
      res = getsockopt(s_info->fd, SOL_SOCKET, SO_SNDBUF, 
            &doubled_queue_space, &opt_len);
      ASSERT(res == 0);
      int max_queue_space = doubled_queue_space / 2;
      avail_nr_bytes = max_queue_space - used_nr_bytes;
   }

   DEBUG_MSG(5, "used_nr_bytes=%d avail_nr_bytes=%d\n", 
         used_nr_bytes, avail_nr_bytes);
   ASSERT(avail_nr_bytes >= 0);

   return avail_nr_bytes;
}

/**
 * Tags and sends a message.
 * Prepends up to TSOCK_MAX_METADATA bytes; This should lower
 *   effective MTU for UDP sockets.
 * Returns the number of bytes from the original message that are sent.
 */
static ssize_t 
TSockSendTaggedWork( tsock_socket_info_t *s_info, const struct msghdr *msg_ptr,
      const int flags, const void * tag, const size_t tag_len,
      const size_t avail_bytes )
{
   char metadata_buf[TSOCK_MAX_METADATA_LEN];
   struct msghdr msg_hdr;
   struct iovec iov[2];	// Always one for metadata, one for original msg.

   DEBUG_ONLY(TSockVerifyDesc(s_info));
   /* XXX: could be >= 0 since we may be invoked on
    * the receive fastpath, in which case we may be passed in
    * multicomponent iovec rather than a 1-component iovec pointing
    * to the log entry. */
   ASSERT_UNIMPLEMENTED_MSG(msg_ptr->msg_iovlen == 1, "%d", 
         msg_ptr->msg_iovlen);
   ASSERT(avail_bytes > TSOCK_MAX_METADATA_LEN);

   const size_t payload_len = msg_ptr->msg_iov->iov_len;
   const size_t payload_bytes_to_send = 
      MIN(avail_bytes-TSOCK_MAX_METADATA_LEN, payload_len);

#if DEBUG
   // We haven't tested all flags.
   const int tested_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
   ASSERT_UNIMPLEMENTED_MSG( !(flags & ~tested_flags),
         "flags=0x%x", flags);
#endif

   // FIXME: for connected TCP sockets, skip tag, magic, compress vclock.
   // For all, drop tag?  How is it helping?  Pull peer IP from socket.
   // For UDP, do we use length?

   // First write metadata into second buffer.
   const size_t metadata_len = TSockWriteMetaData( metadata_buf, 
         TSOCK_MAX_METADATA_LEN, payload_bytes_to_send, tag, tag_len);
   // XXX: Would be nice to check this for UDP sockets, and break
   // up message (assigning multiple unique ids) as necessary.
   //ASSERT( metadata_len + buf_len <= TSOCK_MAX_DATAGRAM_LEN );

   // Next assemble the iovec for a gather.
   ASSERT(msg_ptr->msg_iov);
   ASSERT(msg_ptr->msg_iovlen == 1);
   iov[0].iov_base = metadata_buf;
   iov[0].iov_len = metadata_len;
   /* XXX: iovec could have multiple components, see above */
   iov[1].iov_base = msg_ptr->msg_iov[0].iov_base;	
   iov[1].iov_len = payload_bytes_to_send;
   ASSERT(iov[1].iov_base);
   ASSERT(iov[1].iov_len > 0);
   ASSERT(iov[0].iov_len + iov[1].iov_len <= avail_bytes);

   // Finally build the msghdr struct.
   msg_hdr = *msg_ptr;
   msg_hdr.msg_iov = iov;
   msg_hdr.msg_iovlen = 2;

   const ssize_t bytes_sent = TSockSysSend( s_info, &msg_hdr, flags );
   if( bytes_sent < 0 ) {
      DEBUG_MSG(5, "Send failure (%d)\n", bytes_sent);
      return bytes_sent;	// Failure.
   } else {
      const size_t payload_bytes_sent = MAX( 0, (bytes_sent-metadata_len) );
      DEBUG_MSG(5, "Sent %d (%d) bytes\n", bytes_sent, payload_bytes_sent);

      // XXX: this gets triggered in KFS's chunkserver when cptokfs
      // transfers in large files. We need to handle this, but
      // currently, I'm unsure how to. We could implement a two-phase
      // send loop like we do for recvs. The other option is to obtain
      // some sort of guarantee that the requested chunk will be sent
      // through.
      // update: triggers in scp/ssh too, but for pipes: they don't
      // support SIOCOUTQ, unfortunately, so I don't know of a way to
      // gauge its queue size.
      // It's likely this will only trigger under high load/bt mode
      DEBUG_MSG(5, "family=%d protocol=%d\n", s_info->family,
            s_info->protocol);
      if (DEBUG) {
         int opt_val = 0;
         UNUSED int res = SysOps_ioctl(s_info->fd, 
               s_info->family == TSOCK_FAMILY_PIPE ? 
               FIONREAD : SIOCOUTQ, &opt_val);
         ASSERT_MSG(res == 0, "res=%d errno=%d", res, errno);
         DEBUG_MSG(5, "opt_val=%d req_len=%d\n", opt_val, 
               payload_bytes_to_send);
      }
      ASSERT_UNIMPLEMENTED_MSG(payload_bytes_sent == payload_bytes_to_send,
            "bytes_sent=%d bytes_to_send=%d", payload_bytes_sent, 
            payload_bytes_to_send);
      ASSERT(payload_bytes_sent > 0);
      // Hide metadata from app.
      return payload_bytes_sent;
   }
}


/**
 * Tags and sends a message.
 */
static ssize_t 
TSockSendTagged( tsock_socket_info_t *s_info, const struct msghdr *msg_ptr,
      const int flags, const void * tag, const size_t tag_len )
{
   DEBUG_ONLY(TSockVerifyDesc(s_info));
   // We need to ensure that the payload size we place in the metadata
   // matches the number of bytes actually sent out on the wire. It may
   // not if the write in short. When this happen, the
   // the receiver will look for the next metadata header
   // in the wrong place in the byte stream and get confused.
   while (TRUE) {
      // XXX: avoid syscall by requiring as a parameter?
      const size_t avail_queue_bytes = TSockGetAvailSendQueueSpace(s_info);
#if 0
      if (avail_queue_bytes <= TSOCK_MAX_METADATA_LEN) {
         if (1 /*s_info->is_blocking*/) {
            /* XXX: problem -- we shouldn't block while holding the
             * vcpu lock; this will result in deadlock -- others do not
             * get a chance to drain the channel */
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(s_info->fd, &fds);
            while (TRUE) {
               int res = SysOps_select(s_info->fd + 1, NULL, &fds, NULL, NULL);
               if (res < 0) {
                  ASSERT(res == -EINTR);
                  continue;
               } else {
                  ASSERT(res == 1);
                  ASSERT(FD_ISSET(s_info->fd, &fds));
                  break;
               }
            }
         } else {
            return -EAGAIN;
         }
      } else {
         ASSERT(avail_queue_bytes > TSOCK_MAX_METADATA_LEN);
         return TSockSendTaggedWork(s_info, msg_ptr, flags, tag, tag_len,
            avail_queue_bytes);
      }
#else
      // It's the resonsibility of higher layers to ensure that this
      // property is met.
      ASSERT(avail_queue_bytes > TSOCK_MAX_METADATA_LEN);
      return TSockSendTaggedWork(s_info, msg_ptr, flags, tag, tag_len,
            avail_queue_bytes);
#endif
   }
}

ssize_t 
TSock_Send( tsock_socket_info_t *s_info, const struct msghdr *msg_ptr,
      const int flags, void * tag, size_t *tag_len_ptr )
{
   ssize_t err;

   // A 0 buffer count is valid in Linux
   ASSERT_UNIMPLEMENTED(msg_ptr->msg_iovlen > 0);
   DEBUG_ONLY(TSockVerifyDesc(s_info));

   if (TSockIsEnabled() && TSockShouldSendTagged( s_info, msg_ptr->msg_name, 
            msg_ptr->msg_namelen )) {
      err = TSockSendTagged( s_info, msg_ptr, flags, tag, *tag_len_ptr );
   } else {
      err = TSockSysSend( s_info, msg_ptr, flags );
      // Indicates to user that outbound message was NOT tagged
      *tag_len_ptr = 0;
   }
   if (err > 0) {
      DEBUG_MSG(8, "sent data=%s\n", msg_ptr->msg_iov[0].iov_base);
   }

   DEBUG_MSG(5, "err=%d\n", err);
   return err;
}

static int
TSockBindWork(tsock_socket_info_t *s_info, const struct sockaddr *addr, 
      const int addr_len) 
{
   int err;

   err = SysOps_bind(s_info->fd, addr, addr_len);

   DEBUG_MSG(5, "err=%d\n", err);
   if (TSockIsEnabled() && err >= 0) {
      TSockRegister(s_info);
   }

   return err;
}

int
TSock_Bind(tsock_socket_info_t *s_info, const struct sockaddr *addr, 
      const int addr_len) 
{
#if PRODUCT
#error "XXX: check that addr doesn't conflict with bdr abstract naming"
#endif
   return TSockBindWork(s_info, addr, addr_len);
}

static int
TSockIsBound(const tsock_socket_info_t *s_info, struct sockaddr *sa_p,
      socklen_t *sock_len_p)
{
   UNUSED int res = getsockname( s_info->fd, sa_p, sock_len_p);
   DEBUG_MSG(5, "res=%d sock_len=%d\n", res, *sock_len_p);
   ASSERT(res == 0);

   int is_bound = 0;

   switch (sa_p->sa_family) {
   case AF_UNIX:
      is_bound = *sock_len_p > sizeof(sa_family_t);
      break;
   case AF_INET:
      {
         struct sockaddr_in *sin4_p = (struct sockaddr_in*) sa_p;
         is_bound = sin4_p->sin_port > 0;
         break;
      }
   case AF_INET6:
      {
         struct sockaddr_in6  *sin6_p = (struct sockaddr_in6*) sa_p;
         is_bound = sin6_p->sin6_port > 0;
         break;
      }
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   return is_bound;
}

static void
TSockPreConnectBind(tsock_socket_info_t *s_info, struct sockaddr *sa_p)
{
   struct sockaddr_storage bind_sa;
   socklen_t bind_sa_len = 0;

   ASSERT_UNIMPLEMENTED(s_info->protocol == TSOCK_PROTOCOL_UDP ||
         s_info->protocol == TSOCK_PROTOCOL_TCP);
   memset(&bind_sa, 0, sizeof(bind_sa));

   switch (sa_p->sa_family) {
   case AF_UNIX:
      {
         // This end of the socket is unnamed. But we need a
         // name to register with the portserver and for remote
         // peers to query. So we'll choose a name for this end from 
         // the abstract unix-domain name space.
         //
         // XXX: hide this name from clients in subsequent
         // sys_getsockname/sys_getpeername requests.
         struct sockaddr_un *un_p = (struct sockaddr_un*) &bind_sa;
         bind_sa_len = sizeof(*un_p);
         un_p->sun_family = sa_p->sa_family;
         un_p->sun_path[0] = 0;
         struct stat sbuf;
         UNUSED int res = fstat(s_info->fd, &sbuf);
         ASSERT(res == 0);
         res = snprintf(un_p->sun_path+1, UNIX_PATH_MAX-1, "bdr:unnamed:%lu",
               sbuf.st_ino);
         ASSERT(res > 0);
         break;
      }
   case AF_INET:
      {
         struct sockaddr_in *sin4_p = (struct sockaddr_in*) &bind_sa;
         bind_sa_len = sizeof(*sin4_p);
         sin4_p->sin_family = sa_p->sa_family;
         sin4_p->sin_port = htons(0);
         sin4_p->sin_addr.s_addr = INADDR_ANY;
         break;
      }
   case AF_INET6:
      {
         struct sockaddr_in6 *sin6_p = (struct sockaddr_in6*) 
            &bind_sa;
         bind_sa_len = sizeof(*sin6_p);
         sin6_p->sin6_family = sa_p->sa_family;
         sin6_p->sin6_port = htons(0);
         memcpy(&sin6_p->sin6_addr, &in6addr_any, sizeof(in6addr_any));
         break;
      }
   default:
      ASSERT_UNIMPLEMENTED_MSG(0, "family=%d", sa_p->sa_family);
      break;
   }
   ASSERT(bind_sa_len > 0);
   int res = TSockBindWork(s_info, (struct sockaddr*)&bind_sa, 
         bind_sa_len);
   // XXX: This could fail, if we run out of ports
   ASSERT_UNIMPLEMENTED_MSG(res == 0, "res=%d", res);
}

// See if remote, accepting socket is a tsocket line, and if so, 
// assumes that the accepted connection is also tagged.
// Function must be invoked at connect time or otherwise, there is a
// chance the line will be incorrectly marked as untagged. This
// happens if the connecting socket writes data first, as is sometimes
// the case. If the accepint sockets writes data first, then we will
// detect that tsocket magic and correctly mark the tag, but this
// cannot be relied upon in all apps.
int
TSock_Connect(tsock_socket_info_t *s_info, const struct sockaddr *servaddr, 
      const int addr_len)
{
   int err = 0;

   DEBUG_ONLY(TSockVerifyDesc(s_info));
   ASSERT(s_info->family == TSOCK_FAMILY_SOCKET);

   if (TSockIsEnabled()) {
      if (servaddr->sa_family != AF_UNSPEC) {
         char addr_buf[MAX_SOCKADDR_SIZE];
         socklen_t sock_len = sizeof(addr_buf);
         struct sockaddr *sa_p = (struct sockaddr*)addr_buf;

         const int is_already_bound = TSockIsBound(s_info, sa_p, &sock_len);

         // First bind, so that we register the port on this end of the 
         // connection. This is important, because once the other side
         // accepts, it may start writing, and at that point, it will
         // want to know if outgoing messages should be tagged. So the
         // local portserver better be aware of this binding by that
         // time, or the line will be incorrectly deemed untagged.
         if (!is_already_bound) {
            TSockPreConnectBind(s_info, sa_p);
         } else {
            // Somebody already called sys_bind() successfully on this
            // fd. Hence line should already be registered.
            // ASSERT(IsLineRegistered());
         }

         // XXX: explain why we must do this before the connect
         // Determine if line should be tagged and cache result. We must
         // determine this now using the remote accept socket's address,
         // rather than on first write. This avoids the race where we
         // query the remote portserver but get a negative result because
         // the other end hasn't had a chance to register the accepted
         // connection port.
         TSockShouldSendTagged(s_info, servaddr, addr_len);
      }
   }

   // Connect regardless of whether line is tagged or not
   err = SysOps_connect(s_info->fd, servaddr, addr_len);

   if (TSockIsEnabled() && err == 0) {
      if (servaddr->sa_family == AF_UNSPEC) {
         // manpage connect(2) says: ``Connectionless sockets may dissolve
         // the association by connecting to an address with the  sa_family  
         // member of sockaddr set to AF_UNSPEC (supported on Linux since 
         // kernel 2.2).''
         ASSERT(s_info->protocol == TSOCK_PROTOCOL_UDP);
         s_info->peer_info = TSOCK_PEER_UNKNOWN;
      } else {
      }
   }

   return err;
}


// Avoids blocking in vkernel if there is data to be dequeued in our
// user-land buffer (presumably becaue somebody did a recv(MSG_PEEK)).
static int
TSockPeekAwarePselect(const tsock_socket_info_t *s_info, const int is_read, 
      struct timeval *timeout_p, sigset_t *mask_p)
{
   int err = 0;
   fd_set fds;
   ASSERT(s_info->fd >= 0);
   const int fd_count = s_info->fd+1;
   const size_t queue_byte_count = s_info->peek_buf ?
      RingBuffer_GetCount(s_info->peek_buf) : 0;

   FD_ZERO(&fds);
   FD_SET(s_info->fd, &fds);

   DEBUG_MSG(5, "queue_byte_count=%d timeout_p=0x%x mask_p=0x%x\n",
         queue_byte_count, timeout_p, mask_p);

   if (queue_byte_count) {
      err = 1;
   } else {
      err = SysOps_pselect(fd_count, is_read ? &fds : NULL,
            is_read ? NULL : &fds, NULL, timeout_p, mask_p);
   }

   return err;
}

// We expect higher layers to invoke this sys_select emulation routine
// on tsocket fds.
//#error "XXX: must be called from sys_select() as well"
int
TSock_Pselect(const tsock_socket_info_t *s_info, 
      const int is_read, struct timeval *timeout_p, sigset_t *mask_p)
{
   int err = 0;
#if 1
#if MAX_NR_VCPU > 1
#if PRODUCT
#error "XXX: peek queue needs to be locked"
#else
   ASSERT_UNIMPLEMENTED(0);
#endif
#endif

   DEBUG_MSG(5, "fd=%d family=%d protocol=%d is_read=%d\n", 
         s_info->fd, s_info->family, s_info->protocol, is_read);

   // XXX: We need to check the peek queue before we check the kernel
   // queue
   if (is_read || s_info->peer_info != TSOCK_PEER_TAGS) {
      err = TSockPeekAwarePselect(s_info, is_read, timeout_p, mask_p);
      ASSERT_MSG(err == -EINTR || err >= 0, "err=%d", err);
   } else if (s_info->peer_info == TSOCK_PEER_TAGS) {
      ASSERT(!is_read);
      const int is_poll = (timeout_p && timeout_p->tv_sec == 0 && 
            timeout_p->tv_usec == 0);
      // Ensure that we have queue space for the minimum tsocket send
      // -- necessary because we can't block in the tsock_send call
      // (may result in deadlock)
      while (TRUE) {
         // XXX: avail_bytes not accurate if s_info is shared among
         // concurrent tasks
         // XXX: ideally, call pselect and test of queue size should be
         // atomic; implement as a kernel-module call
         //
         // We must check the queue size with pselect rather checking
         // queue legnth directly via ioctl--in case we spin, we need
         // to be reponsive to interrupts (e.g., IPIs).
         err = TSockPeekAwarePselect(s_info, is_read, timeout_p, mask_p);
         const size_t avail_bytes = TSockGetAvailSendQueueSpace(s_info);
         const int has_space_for_tagged_send = 
            (avail_bytes > TSOCK_MAX_METADATA_LEN);
         if (is_poll) {
            ASSERT(err == 0 || err == 1);
            if (err == 1 && !has_space_for_tagged_send) {
               err = 0; 
            }
            break;
         } else {
            ASSERT(err == -EINTR || err == 0 || err == 1);
            if (err == -EINTR || (err == 1 && has_space_for_tagged_send)) {
#if DEBUG
               if (err == -EINTR) {
                  DEBUG_MSG(5, "Got EINTR\n");
               }
#endif
               break;
            } 
         }
      }
   } else {
      ASSERT(0);
   }
#endif

   DEBUG_MSG(5, "got data: err=%d\n", err);
   return err;
}

#if 0
int
TSock_Pselect(const tsock_socket_info_t *s_info, 
      const int is_read, struct timeval *timeout_p, sigset_t *mask_p)
{
   int err = 0;
#if 1
#if MAX_NR_VCPU > 1
#error "XXX: peek queue needs to be locked"
#endif

   DEBUG_MSG(5, "fd=%d family=%d protocol=%d is_read=%d\n", 
         s_info->fd, s_info->family, s_info->protocol, is_read);

   // XXX: We need to check the peek queue before we check the kernel
   // queue
   if (is_read || s_info->peer_info != TSOCK_PEER_TAGS) {
      err = TSockPeekAwarePselect(s_info, is_read, timeout_p, mask_p);
      ASSERT_MSG(err == -EINTR || err >= 0, "err=%d", err);
   } else if (s_info->peer_info == TSOCK_PEER_TAGS) {
      ASSERT(!is_read);
      const int is_poll = (timeout_p && timeout_p->tv_sec == 0 && 
            timeout_p->tv_usec == 0);
      // Ensure that we have queue space for the minimum tsocket send
      // -- necessary because we can't block in the tsock_send call
      // (may result in deadlock)
      while (TRUE) {
         // XXX: avail_bytes not accurate if s_info is shared among
         // concurrent tasks
         const size_t avail_bytes = TSockGetAvailSendQueueSpace(s_info);
         if (avail_bytes <= TSOCK_MAX_METADATA_LEN) {
            if (is_poll) {
               ASSERT(err == 0);
               break;
            } else {
               err = TSockPeekAwarePselect(s_info, is_read, timeout_p, mask_p);
               if (err < 0) {
                  // We may be interrupted by IPI
                  ASSERT(err == -EINTR);
                  break;
               }
            }
         } else {
            err = 1;
            break;
         }
      }
   } else {
      ASSERT(0);
   }
#endif

   DEBUG_MSG(5, "got data: err=%d\n", err);
   return err;
}
#endif


void
TSock_Init(int is_enabled)
{
   in_addr_t local_addr;
   /* XXX: don't hardcode the port!! */
   int reg_port = 5892;

   is_tagging_enabled = is_enabled;
   _query_port = reg_port-1;	// Save this info for later.
   local_addr = ntohl( NetOps_GetLocalAddr() );
   _serv_sock = connect_to_registration_server( local_addr, reg_port );
}
