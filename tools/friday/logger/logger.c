/**
 * Copyright (c) 2004 Regents of the University of California.  All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. Neither the name of the University nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * author:	Dennis Geels
 * $Id: logger.c,v 1.49 2006/07/03 20:25:36 geels Exp $
 *
 * logging.c
 *
 * Accept incoming log session requests and fork off threads to handle them.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <assert.h>	// assert
#include <unistd.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>	// struct timeval, timezone, gettimeofday
#include <time.h>	// time_t, time(), difftime()
#include <sys/socket.h>	// struct sockaddr
#include <netinet/in.h>	// in_addr_t, in_port_t

#include <pthread.h>
#define __USE_GNU
#include <dlfcn.h>
#include <stdarg.h>


#include "logger.h"
#include "log.h"
#include "util.h"
#include "fdops.h"

#define DEBUG 1

#define MAX_NUM_PROCS 256
#define MAXPENDING 10
#define SHARED_SEGMENT_SIZE (0x1 << 22)
#define HIGHEST_VCLOCK 0x7FFFFFFFFFFFFFFFLL
#define DEFAULT_PREALLOC_NUM_SEGMENTS 1
#define DEFAULT_PORT 7777
#define INACTIVITY_DELAY_S 60

#if DEBUG
#define DEBUG_MSG(s) logger_printf(s)
#else
#define DEBUG_MSG(s)
#endif

int __shared_segment_size = SHARED_SEGMENT_SIZE;

/* Incoming socket: we will accept incoming connections on this socket. */
int in_sock = -1;

/* Time at startup.  Second granularity is sufficient. */
time_t startup_time_s;
/* Time to give up waiting for a connection.
   This variable is guarded by client_table_lock below.
 */
time_t inactivity_timeout_s;


typedef struct shmseg {
   int shmid;
   void* shmaddr;

   int* pos;
   char* data;

   int size;

   TAILQ_ENTRY(shmseg) entries;
} shmseg_t;

TAILQ_HEAD(shmlist, shmseg);

/* This structure describes a client. For our purposes, we expect this
 * to be a single process. */
typedef struct client_info {
   pid_t pid;					/* pid of the logging process */
   pid_t pgid;					/* group id of the logging process */
   char filename[PATH_MAX];	/* name of the log file */

   int fd;					/* handle to process's log file */

   int sock;					/* connection socket to client */

   int is_allocated;			/* is the slot allocated? */

   /* Linked list of shared memory segmentsthat are currently allocated. */
   struct shmlist alloc_list_head;
} client_info_t;

struct shmlist free_list_head;

/* Table of logging info, one entry for each registered process. Why do
 * we need to maintain a global table? We don't--it's vestigial a feature
 * from back in the day where we braodcasted shared memory updates.
 * Access to this table should be locked since clients can come and go at 
 * any time. */
client_info_t client_table[MAX_NUM_PROCS];

/* How many clients are there at this moment. Access to this variable
 * should be locked since clients can come and go at any time. */
int num_clients = 0;

/* CRITICAL: You must use this lock before accessing (i.e., read or write)
 * the client table or the number of clients variable. */
pthread_mutex_t client_table_lock;

int num_shmsegs = 0;

/* Now many segments should we allocate at a time? */
int num_prealloc_segs = DEFAULT_PREALLOC_NUM_SEGMENTS;

/* Data structures for remote queries */

// Information about one local registered port:
typedef struct registered_port {
   int port;
   char * protocol;	// One of PROT_STR_* 
   pid_t pgid;
   LIST_ENTRY(registered_port) entries;
} registered_port_t;

// TODO: Is a more efficient data structure required?
typedef LIST_HEAD(registered_port_list, registered_port) registered_port_list_t;
registered_port_list_t port_list;
/* This lock must be held when accessing port_list. */
pthread_mutex_t port_list_lock;

static void deallocate_client_slot(client_info_t* pi, uint64_t vclock,
      char* reason_str);
static void destroy_shm_segments();

static void init_client_table() {
   /* Initialize the client table. */
   memset(client_table, 0x0, sizeof(client_table));
}


/* Cleanup we should always perform */
static void normal_cleanup() {
  destroy_shm_segments();
}

/* Full cleanup for messy death */
static void abnormal_cleanup() {
   int i;
   client_info_t* pi = NULL;

   /* Close and flush all logs before exiting. */
   for (i = 0; i < MAX_NUM_PROCS; i++) {
      pi = &client_table[i];
      if (pi->is_allocated) {
         deallocate_client_slot(pi, 0, "abnormal cleanup");
      }

   }

   normal_cleanup();
}

void pthread_fatal(const char* fmt, ...) {
   va_list args;

   printf("client thread fatal: ");

   va_start(args, fmt);
   vprintf(fmt, args);
   va_end(args);

	printf("\n");

   pthread_exit(NULL);
}


/* Allocate a bunch of segments and add it to the free list
 * of segments. */
static void allocate_shm_segments(int num_to_allocate) {
   int i;
   int shmid;
   void* shmaddr;
   shmseg_t* s;

   /* Build a free list of preallocated shared memory segments. */
   for (i = 0; i < num_to_allocate; i++) {
      /* Create a shared segment for this client. */
      if ((shmid = shmget(IPC_PRIVATE, __shared_segment_size,
                  0600 | IPC_CREAT)) == -1) {
         fatal("can't preallocate shared segment of size %d\n",
               __shared_segment_size);
      }

      /* Attach the segment into the address space. */
      if ((shmaddr = shmat(shmid, (void *) 0, 0)) == (void*)-1) {
         fatal("can't attach shared segment for this client\n");
      }

      assert(shmaddr != NULL);

      /* Initialize the segment. */
      memset((void*)shmaddr, 0x0, __shared_segment_size);

      s = malloc(sizeof(shmseg_t));

      s->shmid = shmid;
      s->shmaddr = shmaddr;
      s->pos = (int*)shmaddr;
      s->data = (void*)((int*)shmaddr + 1);
      s->size = __shared_segment_size;

      /* Add the segment to the end of the free list. */
      TAILQ_INSERT_TAIL(&free_list_head, s, entries);
   }
}

/* Initialize the free list of segments. */
static void init_segment_list() {
   TAILQ_INIT(&free_list_head);
}

static shmseg_t* get_shm_segment(client_info_t* c) {
   shmseg_t* s;

   pthread_mutex_lock(&client_table_lock);
   s = free_list_head.tqh_first;

   /* Remove a node from the free list. */
   if (s != NULL) {
      TAILQ_REMOVE(&free_list_head, s, entries);
   } else {
      /* We need to increase our allocation. */
		allocate_shm_segments(num_prealloc_segs);

		s = free_list_head.tqh_first;
		if (s != NULL) {
			TAILQ_REMOVE(&free_list_head, s, entries);
		} else {
			/* Out of memory? */
			pthread_mutex_unlock(&client_table_lock);

			deallocate_client_slot(c, 0, 
					"no more shared memory segments available: out of memory?\n");
			pthread_fatal("unable to allocate additional shared memory segments");
		}
	}

   assert(s != NULL);
   assert(s->pos != NULL);

   /* Add it to the end of the alloc list. */
   TAILQ_INSERT_TAIL(&c->alloc_list_head, s, entries);
   pthread_mutex_unlock(&client_table_lock);

   assert(s != NULL);
   assert(s->pos != NULL);

   /* Initialize the segment struct in case we are reusing an old one. */
   *(s->pos) = 0;

   return s;
}


/* Iterates through the free list and deallocates memory for
 * each segment. */
static void destroy_shm_segments() {
   shmseg_t* s;
   struct shmid_ds shmds;

   for (s = free_list_head.tqh_first; s != NULL; s = s->entries.tqe_next) {
      /* Detach and remove the sysV shared memory segment. */
      shmdt((void*)s->shmaddr);
      shmctl(s->shmid, IPC_RMID, &shmds);
   }

   /* Remove all the nodes in the list. */
   while (free_list_head.tqh_first != NULL) {
      /* Save a pointer to the head before we remove it, so that we
       * can free it once it has be unlinked. */
      s = free_list_head.tqh_first;

      TAILQ_REMOVE(&free_list_head, free_list_head.tqh_first, entries);

      free(s);
   }
}

/* Return all allocated segments to the free list. */
static void free_shm_segments(client_info_t* c) {
   shmseg_t* s;

   /* Remove all the nodes in the alloc list and place them in the free list. */
   while (c->alloc_list_head.tqh_first != NULL) {
      /* Save a pointer to the head before we remove it, so that we
       * can move it to the free list once it has be unlinked. */
      s = c->alloc_list_head.tqh_first;

      TAILQ_REMOVE(&c->alloc_list_head, c->alloc_list_head.tqh_first, entries);

      TAILQ_INSERT_TAIL(&free_list_head, s, entries);
   }
}

/* Create an incoming socket. We don't need an outgoing socket since
 * we will never communicate with the senders. */
static void initialize(int port) {
   struct sockaddr_in sin;
   int on = 1;

   /* Setup the listen/accept socket. */
   memset(&sin, 0x0, sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_port = htons(port);
   sin.sin_addr.s_addr = htonl(INADDR_ANY);

   if ((in_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
      perror("socket");
      exit(-1);
   }

   /* This lets us reuse this socket (address:port) if
    * we crash and have to restart. */
   setsockopt(in_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

   if (bind(in_sock, (struct sockaddr*) &sin, sizeof(sin)) < 0) {
      perror("bind");
      exit(-1);
   }

   if (listen(in_sock, SOMAXCONN) < 0) {
      perror("listen");
      exit(-1);
   }

   init_client_table();
}

static int write_log(client_info_t* pi, void* segment, unsigned size) {
   int n;

   if ((n = safe_write(pi->fd, segment, size)) < size) {
		perror("write");
	}

	logger_printf("Wrote %d bytes of %d bytes\n", n, size);

	return n;
}

static void flush_shared_memory(client_info_t* pi, int64_t current_vclock) {
	shmseg_t *s = NULL, *next_s = NULL;

	pthread_mutex_lock(&client_table_lock);

	s = pi->alloc_list_head.tqh_first;

	if (s) {
		int size;

		next_s = s->entries.tqe_next;

		/* The log size is the first word, and s->pos bytes
		 * afterward is the data. */
		size = *(s->pos)+sizeof(int);
		if (write_log(pi, s->pos, size) < size) {
			/* We're about to exit, so don't die holding the lock. */
			pthread_mutex_unlock(&client_table_lock);

			deallocate_client_slot(pi, 0, "problem writing to log file");
			pthread_fatal("write_log returned less than expected amount of data");
		}

		/* Remove the segment from alloc list. */
		TAILQ_REMOVE(&pi->alloc_list_head, s, entries);

		/* Return the segment to the free list. */
		TAILQ_INSERT_TAIL(&free_list_head, s, entries);
	}

	pthread_mutex_unlock(&client_table_lock);
}

static client_info_t* allocate_client_slot() {
	int i;
	client_info_t* pi = NULL;

	pthread_mutex_lock(&client_table_lock);
	// Forget any plans to quit due to inactivity.
	inactivity_timeout_s = 0;

	for (i = 0; i < MAX_NUM_PROCS; i++) {
		if (!client_table[i].is_allocated) {
			client_table[i].is_allocated = 1;
			num_clients++;
			assert(num_clients < MAX_NUM_PROCS);

			pi = &client_table[i];

			/* Initialize the client's segment list. */
			TAILQ_INIT(&pi->alloc_list_head);

			break;
		}
	}

	assert( i<MAX_NUM_PROCS );

	pthread_mutex_unlock(&client_table_lock);

	return pi;
}

static void deallocate_client_slot(client_info_t* pi, uint64_t vclock,
		char* reason_str) {
	char filename[256];
	int fd;
	registered_port_t* rp;

	logger_printf("Deallocating client pid %d: %s\n",
			pi->pid, reason_str);
	/* Atomically deallocate the slot and close the log file
	 * associated with it to avoid race conditions involving
	 * concurrent shared memory writes. */

	assert(pi);
	assert(pi->is_allocated);

	/* Close the client's socket. */
	close(pi->sock);

	/* Flush __all__ shared memory entries. */
	flush_shared_memory(pi, HIGHEST_VCLOCK);

	pthread_mutex_lock(&client_table_lock);

	close_log(pi->fd, vclock, reason_str /* reason for closing */);

	/* Output a dummy file to signal that the file has been
	 * flushed to disk. Our test script uses this signals to
	 * determien if liblog has finished or not. */
	snprintf(filename, sizeof(filename), "/tmp/done.with.flush.%d",
			pi->pgid);
	fd = creat(filename, 0600);
	close(fd);

	free_shm_segments(pi);

	// Unregister all ports for this pgid.
	pthread_mutex_lock(&port_list_lock);

	for( rp = port_list.lh_first; rp != NULL; rp = rp->entries.le_next ) {
		if( DEBUG ) logger_printf( "scanning: %d, '%s', %d\n", rp->port, rp->protocol, rp->pgid );
		if( pi->pgid == rp->pgid ) {
			logger_printf( "removing port %d, '%s', %d\n", rp->port, rp->protocol, rp->pgid );
			LIST_REMOVE( rp, entries );
			free(rp);
		}
	}
	pthread_mutex_unlock(&port_list_lock);    

	memset(pi, 0x0, sizeof(client_info_t));

	num_clients--;
	assert(num_clients >= 0);

	if( num_clients == 0 ) {
		// Make plans to quit due to inactivity.
		time_t now_s;
		assert( (time_t)-1 != time(&now_s) );	  
		inactivity_timeout_s = now_s + INACTIVITY_DELAY_S;
	}

	pthread_mutex_unlock(&client_table_lock);
}


/* Adds a new registered_port_t to the list */
void port_set( int pgid, int port, char *protocol )
{
	int found;
	registered_port_t* rp;

	if( DEBUG ) logger_printf( "port set: %d, %d, '%s'\n", pgid, port, protocol );
	pthread_mutex_lock(&port_list_lock);

	// Look for existing entry.
	found = FALSE;
	for( rp = port_list.lh_first; rp != NULL; rp = rp->entries.le_next ) {
		if( DEBUG ) logger_printf( "scanning: %d, '%s', %d\n", rp->port, rp->protocol, rp->pgid );
		if( (rp->port == port) && (0 == strcmp(rp->protocol,protocol)) ) {
			found = TRUE;
			if( pgid == rp->pgid ) {
				break;
			} else {
				logger_printf("port set called with mismatch pgid: %d != %d\n",
						pgid, rp->pgid);
			}
		}
	}
	if( ! found ) {	// Add a new one.
		rp = (registered_port_t*)malloc(sizeof(registered_port_t));
		rp->pgid = pgid;
		rp->port = port;
		if( 0 == strcmp( protocol, PROT_STR_UDP ) ) {
			rp->protocol = PROT_STR_UDP;
			LIST_INSERT_HEAD( &port_list, rp, entries );      
		} else if( 0 == strcmp( protocol, PROT_STR_TCP ) ) {
			rp->protocol = PROT_STR_TCP;      
			LIST_INSERT_HEAD( &port_list, rp, entries );
		} else {
			logger_printf("port set called with invalid prot: %s\n", protocol );
		}
	}

	pthread_mutex_unlock(&port_list_lock);    

	return;
}

/* Adds a new registered_port_t to the list */
void port_clear( int pgid, int port, char *protocol )
{
	registered_port_t* rp;

	if( DEBUG ) logger_printf( "port clear: %d, %d, '%s'\n", pgid, port, protocol );  

	pthread_mutex_lock(&port_list_lock);

	for( rp = port_list.lh_first; rp != NULL; rp = rp->entries.le_next ) {
		if( DEBUG ) logger_printf( "scanning: %d, '%s', %d\n", rp->port, rp->protocol, rp->pgid );
		if( (rp->port == port) && (0 == strcmp(rp->protocol,protocol)) ) {
			if( pgid == rp->pgid ) {
				LIST_REMOVE( rp, entries );
				free(rp);
			} else {
				logger_printf("port clear called with mismatch pgid: %d != %d\n",
						pgid, rp->pgid);
			}
			break;
		}
	}

	pthread_mutex_unlock(&port_list_lock);    

	return;
}

static void safe_snarf(int s, client_info_t* pi, void* buf, size_t size,
		char* error_str) {

	if (safe_read(s, buf, size) <= 0) {
		deallocate_client_slot(pi, 0, error_str);
		pthread_fatal(error_str);
	}
}

static void safe_barf(int s, client_info_t* pi, void* buf, size_t size,
		char* error_str) {

	if (safe_write(s, buf, size) < 0) {
		deallocate_client_slot(pi, 0, error_str);
		pthread_fatal(error_str);
	}
}

static void dispatch(int network, client_info_t* pi, LogMsgHdr* hdr) {
	assert(pi);
	assert(hdr);

	if (DEBUG) logger_printf( "Dispatch (%d, id:<%d,%d>, type:%d)\n", network, hdr->src_pid, hdr->src_pgid, hdr->type );

	switch (hdr->type) {
		case MSG_LOG_CREATE:
			/* Fill in the pid and group id. */
			pi->pid = hdr->src_pid;
			pi->pgid = hdr->src_pgid;

			/* Parse the log's filename from the message. */
			safe_snarf(network, pi, pi->filename, hdr->data_size,
					"can't read the log's filename");

			if (pi->fd >= 0) {
				/* Flush out shared memory entries. */
				flush_shared_memory(pi, hdr->vclock);

				/* Looks like we are rotating to the next log. Close the
				 * current log before we open the new log. */
				logger_printf("Rotating; closing old log.\n");
				close_log(pi->fd, hdr->vclock, "rotate");
			} else {
				/* Since this is the first time we are opening a log (i.e.,
				 * not rotating, we shouldn't be activated until we do open
				 * it. */
				assert(pi->fd < 0);
			}

			{
				shmseg_t* s;
				/* Move to a new segment. */
				s = get_shm_segment(pi);

				if (s) {
					/* Tell the client the id of the new shared segment and its
					 * size so that he can attach to it and continue logging. */
					safe_barf(network, pi, &s->shmid, sizeof(int),
							"can't send segment id");
					safe_barf(network, pi, &s->size, sizeof(int),
							"can't send segment size");
				} else {
					int shmid = -1, size = 0;
					safe_barf(network, pi, &shmid, sizeof(int),
							"can't send segment id");
					safe_barf(network, pi, &size, sizeof(int),
							"can't send segment size");
					deallocate_client_slot(pi, 0, "can't get a new segment");
					pthread_fatal("can't get a new segment");
				}
			}

			logger_printf("Opening %s.\n", pi->filename );

			if ((pi->fd = open_log(pi->filename, hdr->vclock)) < 0) {
				pthread_fatal("got rotation message but can't open the new log");
			}

			/* INVARIANT: a non-negative file desc means that the slot is
			 * active. That is, its log file is opened and ready to accept
			 * data. */
			assert(pi->fd >= 0);

			break;

		case MSG_LOG_FLUSH: 
			{
				shmseg_t* s;

				/* Write all log entries in shared memory to disk. */
				flush_shared_memory(pi, hdr->vclock);

				/* Move to a new segment. */
				s = get_shm_segment(pi);

				if (s) {
					/* Tell the client the id of the new shared segment and its
					 * size so that he can attach to it and continue logging. */
					safe_barf(network, pi, &s->shmid, sizeof(int),
							"can't send segment id");
					safe_barf(network, pi, &s->size, sizeof(int),
							"can't send segment size");
				} else {
					int shmid = -1, size = 0;
					safe_barf(network, pi, &shmid, sizeof(int),
							"can't send segment id");
					safe_barf(network, pi, &size, sizeof(int),
							"can't send segment size");
					deallocate_client_slot(pi, 0, "can't get a new segment");
					pthread_fatal("can't get a new segment");
				}

				break;
			}

		case MSG_LOG_CLOSE:
			{
				char close_reason_str[hdr->data_size];
				assert(pi->fd >= 0);


				safe_snarf(network, pi, close_reason_str, hdr->data_size,
						"can't read the close reason");

				logger_printf("Closing log for %d (%s).\n", 
						hdr->src_pid, close_reason_str);

				deallocate_client_slot(pi, hdr->vclock, close_reason_str);

				pthread_exit(NULL);
			}
			break;

		case MSG_PORT_REGISTER:
			{
				char port_and_prot[hdr->data_size];
				int port;
				char protocol[MAX_PROT_STR_LEN];

				safe_snarf(network, pi, port_and_prot, hdr->data_size,
						"can't read the port to register");

				logger_printf("Registering: %s\n", port_and_prot );
				if( 2 != sscanf( port_and_prot, PORT_PROT_FMT,
							&port, protocol ) ) {
					deallocate_client_slot(pi, 0, "Bad request");
					pthread_fatal("can't parse the port or prot");
				}

				port_set( hdr->src_pgid, port, protocol );
			}
			break;

		case MSG_PORT_UNREGISTER:
			{
				char port_and_prot[hdr->data_size];
				int port;
				char protocol[MAX_PROT_STR_LEN];

				safe_snarf(network, pi, port_and_prot, hdr->data_size,
						"can't read the port to unregister");

				logger_printf("Unregistering: %s\n", port_and_prot );
				if( 2 != sscanf( port_and_prot, PORT_PROT_FMT,
							&port, protocol ) ) {
					deallocate_client_slot(pi, 0, "Bad request");
					pthread_fatal("can't parse the port or prot");
				}

				port_clear( hdr->src_pgid, port, protocol );
			}
			break;

		default:
			pthread_fatal("unknown message type: %d", hdr->type);
			break;
	}
}


/* Pthread start routine. */
void* logger_main(void* arg) {

	LogMsgHdr hdr;
	int client_sock = *((int*)arg);
	client_info_t* pi;
	free(arg);

	/* This is a new log. allocate a slot for it in our client table. */
	pi = allocate_client_slot();
	assert(pi);


	pi->sock = client_sock;
	pi->fd = -1;

	while (1) {
		/* The first sizeof(LogMsgHdr) bytes should be the
		 * message header. Extract it from the network. */

		safe_snarf(client_sock, pi, &hdr, sizeof(hdr), 
				"problem receiving message header");

		/* Figure out what to do with the message. */
		dispatch(client_sock, pi, &hdr);
	}
}


static void sigint_handler(int sig) {

	abnormal_cleanup();

	exit(sig);
}

/**
 * Read a query string from an incoming TCP connection, parse the
 * query, reply if query is well-formed. 
 */
static void handle_remote_query( int query_fd )
{
	int recv_len;  
	char query_buf[MAX_QUERY_MSG_LEN+1];
	char rep_buf[MAX_QUERY_REP_LEN+1];
	int fmt_matched;
	char local_addr[MAX_QUERY_MSG_LEN];
	int local_port;
	char protocol[MAX_QUERY_MSG_LEN];
	registered_port_t* rp;        

	recv_len = recv( query_fd, query_buf, MAX_QUERY_MSG_LEN, 0 );
	if( recv_len <= 0 ) {
		if( DEBUG ) logger_printf("No data available\n" );
	} else {
		query_buf[recv_len] = '\0';
		// Debug statement assumes all bytes are printable:
		if( DEBUG ) logger_printf("Query: '%s'\n", query_buf );

		// Now figure out which query it is (if any)
		// First, try UPTIME:
		if( 0 == strcmp( query_buf, UPTIME_QUERY_MSG_FMT ) ) {
			time_t now_s;
			int uptime_s;

			assert( time(&now_s) != (time_t)-1 );
			uptime_s = (int)difftime( now_s, startup_time_s );

			if( DEBUG ) logger_printf( "system_uptime: %d\n", uptime_s );

			sprintf( rep_buf, UPTIME_QUERY_REP_FMT, uptime_s );
			// Don't worry about timeouts, close() errors, etc. (for now).
			safe_write( query_fd, rep_buf, strlen(rep_buf)+1 );
			close( query_fd );
			return;
		}
		// Else:

		fmt_matched = sscanf( query_buf, PORT_QUERY_MSG_FMT, local_addr,
				&local_port, protocol );
		if( fmt_matched == 3 ) {
			int active = FALSE;
			// Debug statement assumes all bytes are printable:
			if( DEBUG ) logger_printf("port query( %s:%d/%s )\n",
					local_addr, local_port, protocol );
			// For now, ignore local_addr.

			pthread_mutex_lock(&port_list_lock);

			for( rp = port_list.lh_first; rp != NULL; rp = rp->entries.le_next ) {
				if( DEBUG ) logger_printf( "scanning: %d, '%s', %d\n", rp->port, rp->protocol, rp->pgid );    
				if( (rp->port == local_port) && (0 == strcmp(rp->protocol,protocol)) ) {
					active = TRUE;
					break;
				}
			}

			pthread_mutex_unlock(&port_list_lock);

			if( DEBUG ) logger_printf("port query -> %d\n", active );
			sprintf( rep_buf, PORT_QUERY_REP_FMT, (active?"TRUE":"FALSE") );
			// Don't worry about timeouts, close() errors, etc. (for now).
			safe_write( query_fd, rep_buf, strlen(rep_buf)+1 );
			close( query_fd );
			return;
		}

		if( DEBUG ) logger_printf("Unexpected query: '%s'\n", query_buf );
	}
	return;
}


/**
 * Listen for remote queries. 
 */
static void * remote_query_main( void * arg ) {
	struct sockaddr_in sin;
	int listen_port, listen_fd, recv_fd;
	socklen_t addr_len;
	fd_set listen_fds;
	int fd_count, reuse;

	listen_port = *((int*)arg) - 1;	// For now, use port below main one.
	listen_fd = socket( PF_INET, SOCK_STREAM, 0 );
	assert( listen_fd > 0 );

	memset( &sin, 0, sizeof(sin) );
	sin.sin_family = AF_INET;
	sin.sin_port = htons( listen_port );
	sin.sin_addr.s_addr = htonl( INADDR_ANY );

	// Don't tie up the listen port if we crash.
	reuse = 1;
	assert( 0 == setsockopt( listen_fd, SOL_SOCKET,
				SO_REUSEADDR, &reuse, sizeof(reuse) ) );
	if (bind( listen_fd,
				(struct sockaddr const*)&sin, sizeof(sin) ) != 0) {
		perror("bind");
		fatal("remote_query_main: can't bind the remote query port\n");
	}
	if (listen( listen_fd, SOMAXCONN ) != 0) {
		perror("listen");
		fatal("remote_query_main: can't listen on the remote query port\n");
	}

	logger_printf("Logger listening for queries on port %d.\n", listen_port);

	// Initialize the table for tracking active ports.
	LIST_INIT( &port_list );
	pthread_mutex_init(&port_list_lock, NULL );      

	while( TRUE ) {
		addr_len = sizeof(sin);
		FD_ZERO(&listen_fds);
		FD_SET(listen_fd, &listen_fds);
		fd_count = listen_fd+1;
		fd_count = select( fd_count, &listen_fds, NULL, NULL, NULL );
		if( fd_count < 0 ) {
			assert( errno == EINTR );
			continue;
		} else {
			assert( (fd_count == 1) &&
					(FD_ISSET(listen_fd, &listen_fds)) );

			if ((recv_fd = accept( listen_fd, (struct sockaddr *)&sin, 
							&addr_len )) < 0) {
				perror("accept:");
				fatal("remote_query_main: can't accept connection from client\n");
			}

			assert( recv_fd >= 0 );

			if( DEBUG ) logger_printf("Logger accepted query from %s:%d.\n",
					inet_ntoa(sin.sin_addr), ntohs(sin.sin_port) );

			handle_remote_query( recv_fd );
		}
	}
	return NULL;
}


void print_usage(int argc, char** argv) {
	printf("usage: %s [port] [num_prealloc_segments]\n", argv[0]);
}

int main(int argc, char** argv) {

	pthread_attr_t tattr;
	pthread_t tid;
	int port = DEFAULT_PORT;
	fd_set listen_fds;
	int fd_count;
	struct timeval timeout;

	if (argc >= 2) port = atoi(argv[1]);
	if (argc >= 3) num_prealloc_segs = atoi(argv[2]);

	logger_printf("Starting logger on port %d.\n", port);
	initialize(port);

	signal(SIGINT, (void*) sigint_handler);

	// Make plans to quit if no clients connect.
	assert( time(&startup_time_s) != (time_t)-1);
	inactivity_timeout_s = startup_time_s + INACTIVITY_DELAY_S;

	/* We want each worker thread to die on exit. That's why we must
	 * create it in detached state. */
	pthread_attr_init(&tattr);
	pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	pthread_mutex_init(&client_table_lock, NULL);

	/* Start a thread to serve remote queries. */
	if( pthread_create(&tid, NULL, remote_query_main, &port) != 0) {
		perror("pthread_create");
		fatal("main: can't create remote query thread\n");
	}

	init_segment_list();

	/* Main server loop. Accept an incoming connection, create a worker
	 * thread to handle it, and then hand it off. Rinse and repeat. */
	while (1) {
		int client_sock, *client_sock_arg = NULL;
		struct sockaddr_in client_addr;
		socklen_t client_addr_len;

		client_addr_len = sizeof(client_addr);
		FD_ZERO(&listen_fds);
		FD_SET(in_sock, &listen_fds);
		fd_count = in_sock+1;
		timeout.tv_sec = INACTIVITY_DELAY_S/4;
		assert( timeout.tv_sec >= 1 );	// sanity check
		timeout.tv_usec = 0;
		
		fd_count = select( fd_count, &listen_fds, NULL, NULL, &timeout );
		//logger_printf("main select returned %d.\n", fd_count);		
		if( fd_count < 0 ) {
		  assert( errno == EINTR );
		  continue;
		} else if( fd_count == 0 ) {	// select timed out.

		  // inactivity_timeout_s, protected by
		  // client_table_lock, is non-zero only if we have no
		  // active clients.  If we pass that non-zero time, exit.
		  pthread_mutex_lock(&client_table_lock);
		  //logger_printf("inactivity_timeout: %d.\n", inactivity_timeout_s );		
		  if( inactivity_timeout_s != 0 ) {
		    time_t now_s;
		    assert( (time_t)-1 != time(&now_s) );
		    logger_printf("inactivity_timeout: %d, now: %d.\n",
				  inactivity_timeout_s, now_s );
		    if( now_s > inactivity_timeout_s ) {
		      normal_cleanup();		      // Cleans up shm, etc.
		      exit(0);
		    }
		  }
		  pthread_mutex_unlock(&client_table_lock);
		  
		} else {	// listen socket ready
		  
		  assert( (fd_count == 1) && (FD_ISSET(in_sock, &listen_fds)) );

		  client_sock = accept(in_sock, (struct sockaddr *)&client_addr,
				       &client_addr_len);
		  if( client_sock <= 0 ) {
		    perror("accept");
		    fatal("main: can't accept a connection\n");
		  }
		client_sock_arg = malloc(sizeof(int));
		assert(client_sock_arg != NULL);
		*client_sock_arg = client_sock;

		if (pthread_create(&tid, &tattr, logger_main, client_sock_arg) != 0) {
			perror("pthread_create");
			fatal("main: can't create a thread\n");
		}
		}
	}

	return 0;
}
