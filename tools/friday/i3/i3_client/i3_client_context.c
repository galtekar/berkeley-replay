/***************************************************************************
                          i3_client_context.c  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>   /* basic system data types */
#include <sys/socket.h>  /* basic socket definitions */
#include <sys/time.h>    /* timeval{} for select() */
#include <sys/errno.h>    
#include <sys/utsname.h>
#include <time.h>        /* timespec{} for pselect() */
#include <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "../utils/utils.h"
#include "trig_binheap.h"
#include "i3.h"
#include "i3_fun.h"
#include "i3_client.h"
#include "i3_client_fun.h"
#include "trig_event_list.h"
#include "i3_config.h"
#include "debug.h"

#define MIN_PORT_NUM 10000
#define MAX_PORT_NUM 11000
#define DEFAULT_SRV_LIST_FILE "srv_list.cfg"

#define CL_CONTEXT_REFRESH_USEC 1000000ULL
#define UMILLION 1000000ULL


int tval_zero(struct timeval *t);
void tval_min(struct timeval *tmin, struct timeval *t1, struct timeval *t2);
void tval_sub(struct timeval *tres, struct timeval *t1, struct timeval *t2);
void tval_normalize(struct timeval *t);
struct in_addr get_local_addr_cl();
int check_addr_change(struct in_addr *ia);
  
/***************************************************************************
 *  cl_init_context - allocate and initialize i3 client context. the context 
 *                    maintains the address of a default i3 server and the 
 *                    list of the triggers inserted by the client
 *
 *  input:
 *    local_ip_addr, local_port - local IP address and port where 
 *       i3 packets are to be received (in host format)
 *
 *  return:
 *    allocated context
 ***************************************************************************/

cl_context *cl_create_context(struct in_addr *local_ip_addr,
			      uint16_t local_port)
{
  cl_context	*ctx;
  uint8_t	opt_mask;
  uint16_t is_tcp16=0;
  char is_tcp;
  int idx;
  struct sockaddr_in server_addr;

  aeshash_init();

  read_ushort_par("/parameters/i3_server/use_tcp",&is_tcp16,0);
  is_tcp = (char) is_tcp16;

  if (local_port == 0) {
    srandom(getpid() ^ time(0));
    local_port = MIN_PORT_NUM + random()%(MAX_PORT_NUM - MIN_PORT_NUM);
    printf("my port number: %d\n", local_port);
  }

  if (!(ctx = (cl_context *)calloc(1, sizeof(cl_context))))
    panic("cl_init_context: memory allocation error (1)\n");

  gettimeofday(&ctx->now, NULL);

  if (!(ctx->s_array = (srv_address *)calloc(MAX_NUM_SRV,sizeof(srv_address))))
    panic("cl_init_context: memory allocation error (2)\n");

  /* read the list of i3 server addreses from the configuration file */
  read_srv_list(ctx);

  /* create field descriptor and address data structure to 
   * receive i3 traffic */
  if ((ctx->fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror ("socket");
    printf("Failed to create socket\n");
    exit(-1);
  }

  memset(&ctx->local, 0, sizeof(struct sockaddr_in));
  ctx->local.sin_family = AF_INET;
  ctx->local.sin_addr.s_addr = htonl(INADDR_ANY);
  ctx->local.sin_port = htons(local_port);
    
  /* bind to the port */
  if (bind(ctx->fd, (struct sockaddr *) &ctx->local, 
	   sizeof(struct sockaddr_in)) < 0) 
    panic("cl_init_context: bind\n");

  ctx->is_tcp = is_tcp;
  if (is_tcp) {
    fprintf(stderr, "Warning: Mobility using TCP unsupported\n");
    if ((ctx->tcp_fd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket");
      printf("Failed to create TCP socket\n");
      exit(-1);
    }
    if (bind(ctx->tcp_fd, (struct sockaddr *) &ctx->local, 
	     sizeof(struct sockaddr_in)) < 0) 
      panic("cl_init_context: TCP bind\n");

    /* Get server from the list and connect to it
     * For now, it is assumed that there is only one server on the
     * list and (obviously) that is the first hop i3 server */
    idx = get_i3_server(ctx->num_servers, ctx->s_array);
    if (-1 == idx)
	panic("cl_init_context: no i3 servers to connect to\n");
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(ctx->s_array[idx].addr.s_addr);
    server_addr.sin_port = htons(ctx->s_array[idx].port);
    if (connect(ctx->tcp_fd, (struct sockaddr *)&server_addr, 
		sizeof(struct sockaddr_in)) < 0)
      panic("cl_init_context: TCP connect\n");
  }


  if (local_ip_addr)
    ctx->local_ip_addr = *local_ip_addr;
  else
    ctx->local_ip_addr = get_local_addr_cl(); // keep it in host format 

  ctx->local_port = local_port;

  /* PRIORITY QUEUE Initialization */
#define MAX_TRIGGERS 100000
  ctx->trig_refresh_queue = TrigInitialize(MAX_TRIGGERS);

  /* precompute option part of headers */
  for (opt_mask = 0; opt_mask < MAX_OPTS_MASK_SIZE; opt_mask++)
    make_data_opt(ctx, opt_mask, &ctx->precomputed_opt[opt_mask]);

  /* Ping list initialization */
  ctx->list = NULL;

  return ctx;
}

/* close sockets and re-open them */
void cl_reinit_context(cl_context *ctx)
{
  static int so_reuseaddr = 1;
  
  close(ctx->fd);
  close(ctx->tcp_fd);

  if ((ctx->fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror ("socket recreation");
    exit(-1);
  }

  memset(&ctx->local, 0, sizeof(struct sockaddr_in));
  ctx->local.sin_family = AF_INET;
  ctx->local.sin_addr.s_addr = htonl(INADDR_ANY);
  ctx->local.sin_port = htons(ctx->local_port);

  if ((setsockopt(ctx->fd, SOL_SOCKET, SO_REUSEADDR,
	  &so_reuseaddr, sizeof(so_reuseaddr))) < 0) {
    perror("setsockopt");
  }
  
  if (bind(ctx->fd, (struct sockaddr *) &ctx->local, 
	   sizeof(struct sockaddr_in)) < 0) 
    panic("cl_reinit_context: bind\n");

  if (ctx->is_tcp) {
    fprintf(stderr, "Warning: Mobility using TCP unsupported\n");  
  }
}


void cl_destroy_context(cl_context *ctx)
{
  int i;
  uint8_t opt_mask;

  for (i = 0; i < CL_HTABLE_SIZE; i++) {
    if (ctx->trigger_htable[i])
      cl_free_trigger_list(ctx->trigger_htable[i]);
    if (ctx->id_htable[i])
      cl_free_id_list(ctx->id_htable[i]);
  }

  TrigDestroy(ctx->trig_refresh_queue);

  for (opt_mask = 0; opt_mask < MAX_OPTS_MASK_SIZE; opt_mask++)
      if (ctx->precomputed_opt[opt_mask].p)
	  free(ctx->precomputed_opt[opt_mask].p);

  cl_destroy_path_list(ctx);

  free(ctx->s_array);
}

/* periodically refresh the client context */
void cl_refresh_context(cl_context *ctx)
{
    gettimeofday(&(ctx->now), NULL);
    while (TrigFindMin(ctx->trig_refresh_queue)->time < wall_time())
    {
	process_trig_event(ctx, TrigDeleteMin(ctx->trig_refresh_queue));
    }
}


#define MAX_PACKET_SIZE 4096
int cl_context_select(cl_context *ctx, int n, 
		      fd_set *readfds, fd_set *writefds, fd_set *exceptfds, 
		      struct timeval *cl_to)
{  
  int			max_fd, rc;
  static struct timeval to;
  static uint64_t 	curr_time, last_addr_check_time, last_srv_update_time;
  static uint64_t	last_refresh_time, next_refresh_time;
  struct timeval 	refresh_to;
  static cl_buf		*clb = NULL;
  cl_trigger 		*ctr, *ctr_next;
  i3_header  		*hdr; 
  char			packet_received = 0;

  assert(readfds);

  /* initialize vars when this method is called for the first time */
  if (NULL == clb) {
    last_refresh_time = last_addr_check_time = last_srv_update_time = wall_time();
    clb = cl_alloc_buf(MAX_PACKET_SIZE);
  }
 
  max_fd = max(ctx->fd + 1, n);
  if (ctx->is_tcp)
    max_fd = max(ctx->tcp_fd + 1, max_fd);

  for (;;) {
    FD_SET(ctx->fd, readfds); 
    if (ctx->is_tcp)
      FD_SET(ctx->tcp_fd, readfds);

    /* record when triggers must be refreshed next */
    if (!TrigIsEmpty(ctx->trig_refresh_queue)) {   
	next_refresh_time = TrigFindMin(ctx->trig_refresh_queue)->time;
	sub_wall_time(&refresh_to, next_refresh_time, wall_time());
    } else {
#define LARGE_TIME 100
	refresh_to.tv_sec = refresh_to.tv_usec = LARGE_TIME;
    }

    /* determine timeout of select */
    if (cl_to) {
      /* if user specifies finite time, 
       * min(NextTriggerRefresh,UserSpecifiedTime) */
      tval_min(&to, &refresh_to, cl_to);
      tval_sub(cl_to, cl_to, &to);
    } else {
      /* else, choose NextTriggerRefresh */
      to = refresh_to;
    }

    /* select() */
    if ((rc = select(max_fd, readfds, writefds, exceptfds, &to)) < 0) {
      if (errno == EINTR)
	continue;
      else
	err_sys("select_error\n");
    }

    if (rc >= 1)
      packet_received = 1;

    /* packet has been received */
    if (FD_ISSET(ctx->fd, readfds) || 
	(ctx->is_tcp && FD_ISSET(ctx->tcp_fd, readfds)))
    {
      rc -= 1;
  
      /* hdr is allocated in cl_receive_packet; remember to free it ... */
      cl_receive_packet(ctx, &hdr, clb);

      if (hdr == NULL)
	continue;

      if (hdr->option_list) 
	/* process option list received in the packet header */
	cl_process_option_list(ctx, hdr->option_list);
 
      if (hdr->stack && hdr->stack->len) {
	/* get trigger's data structure */
	ctr = cl_get_trigger_by_id(
		ctx->trigger_htable[CL_HASH_TRIG(hdr->stack->ids)],
		hdr->stack->ids);

	for (; ctr;) {
	  /* the packet may match multiple triggers; get the next matching 
           * trigger, if any */
	  ctr_next = ctr->next;  

	  if (ctr->cbk_path_receive.fun != NULL)
	    cl_trigger_callback(ctx, ctr, CL_CBK_PATH_RECEIVE, hdr, clb);
	  else if (ctr->cbk_receive_packet.fun != NULL) 
	    cl_trigger_callback(ctx, ctr, CL_CBK_RECEIVE_PACKET, hdr, clb);
	  else if (hdr->flags & I3_DATA) 
	    cl_trigger_callback(ctx, ctr, CL_CBK_RECEIVE_PAYLOAD, NULL, clb);
	  /* ctr pointer shouldn'be used after this call because the ctr
           * might have been deleted in the callback */

          ctr = ctr_next;
	  while(TRUE) {
	     ctr = cl_get_trigger_by_id(ctr, hdr->stack->ids);
	     if (NULL == ctr || ctr->t->to->type == I3_ADDR_TYPE_IPv4)
		 break;
	     ctr = ctr->next;
	  }
	}
      }
      /* ... here we free the header */
      free_i3_header(hdr);
    }

    /* check if refreshing of any triggers needs to be done */
    curr_time = wall_time();
    if (curr_time >= next_refresh_time && 
	!TrigIsEmpty(ctx->trig_refresh_queue))
    {
      cl_refresh_context(ctx);
      last_refresh_time = curr_time;
    }    

    /* check if address has changed */
#define ADDR_CHECK_PERIOD 2*1000000ULL
    if (curr_time - last_addr_check_time > ADDR_CHECK_PERIOD) {
      if (check_addr_change(&(ctx->local_ip_addr))) {
	struct in_addr temp;
	temp.s_addr = htonl(ctx->local_ip_addr.s_addr);
	fprintf(stderr, "Detected address change to %s: updating triggers\n",
	        inet_ntoa(temp));
	// cl_reinit_context(ctx);
	TrigRemoveAddr(&(ctx->trig_refresh_queue));
	cl_update_triggers(ctx);

	// inform ping process
	set_status(ctx->ping_start_time, curr_time);
      }
      last_addr_check_time = curr_time;
    }

#define SERVER_UPDATE_PERIOD 60*1000000ULL
    if (curr_time - last_srv_update_time > SERVER_UPDATE_PERIOD) {
      update_srv_list(ctx);
      last_srv_update_time = curr_time;
    }

    /* either cl_to expired or a packet on another socket 
     * has been received*/
    /* --- WARNING: This can lead to EXTREMELY subtle bugs --- TODO! */
    if (packet_received || (cl_to && tval_zero(cl_to))) {
      return rc;
    }
  }
}


int get_i3_server(int num_servers, srv_address *s_array)
{
  int num = 0;
  int i;

  if (num_servers == 0)
      return -1;

  for (i = 0; i < 2 * num_servers; i++) {
    num = random() % num_servers;
    if (s_array[num].status == ID_UP)
      return num;
  }

  num = 0;
  for (i = 0; i < num_servers; i++) {
    if (s_array[i].status == ID_UP)
      return i;
    if (s_array[i].status == ID_DOWN)
      num++;
  }
  /* there are known servers in the list, but all of them are down;
   * select a random one */
  if (num) {
    num = random() % num;
    for (i = 0; i < num_servers; i++) {
      if (s_array[i].status == ID_DOWN) {
	if (num == 0)
	  return i;
	else
	  num--;
      }
    }
  }

  panic("Likely bug in get_i3_server\n");
  return -1;
}


// void insert_i3_server(srv_address *s_array, uint32_t ip_addr, uint16_t port)
// {
//   int i;
// 
//   for (i = 0; i < MAX_NUM_SRV; i++) {
//     if (!s_array[i].status) {
//      break;
//     }
//   }
//   if (i < MAX_NUM_SRV) {
//     s_array[i].port = port;
//     s_array[i].addr.s_addr = ip_addr; 
//     s_array[i].status = ID_UP;
//   }
// }


srv_address *set_i3_server_status(srv_address *s_array, 
				  uint32_t ip_addr, uint16_t port,
				  int status)
{
  int i;

  for (i = 0; i < MAX_NUM_SRV; i++) {
    if ((s_array[i].port == port) &&
	(s_array[i].addr.s_addr == ip_addr)) {
      s_array[i].status = status;
      return &s_array[i];
    }
  }

  return NULL;
}



/* read the list of server addresses and their port numbers
 * from the configuration files */
void read_srv_list(cl_context *ctx)
{
  int  i = 0, port, ret;
  char addrstr[MAX_BUF_SIZE];
  char idstr[MAX_BUF_SIZE];
  char** addrs = read_strings_par("/parameters/i3_server/addr", &ctx->num_servers);

  for (i = 0; i < ctx->num_servers; i++)
  {
    ret = sscanf(addrs[i], "%s %d %s\n", addrstr, &port, idstr);
    free(addrs[i]);

    DEBUG(15,"Using i3 server at %s %d\n",addrstr,port);

    if (i >= MAX_NUM_SRV)
      continue;

    if (ret >= 3)
	ctx->s_array[i].id = atoi3id(idstr);
    else
	fprintf(stderr, "Warning: proxy configuration file has incomplete <addr> field\n");
    ctx->s_array[i].port = port;
#ifdef __CYGWIN__
    if (inet_aton(addrstr, &ctx->s_array[i].addr) < 0)
#else
    if (inet_pton(AF_INET, addrstr, &ctx->s_array[i].addr) < 0)
#endif
	err_sys("client_init: inet_pton error\n");

    /* inet_pton returns the address in network format;
     * convert it in host format */
    ctx->s_array[i].addr.s_addr = ntohl(ctx->s_array[i].addr.s_addr);
    ctx->s_array[i].status = ID_DOWN;

  }

  free(addrs);

  printf("Number of i3 servers = %d\n", ctx->num_servers);
}

void update_srv_list(cl_context *ctx)
{
  int i, k = MAX_NUM_SRV;
  uint16_t port[MAX_NUM_SRV];
  uint32_t addr[MAX_NUM_SRV];
  uint64_t rtt[MAX_NUM_SRV];
  
  if (cl_get_top_k_servers(&k, addr, port, rtt) == CL_RET_OK) {
    for (i = 0; i < k; i++) {
      ctx->s_array[i].addr.s_addr = addr[i];
      ctx->s_array[i].port = port[i];
    }
    if (k > 0)
      ctx->num_servers = k;
  }
}
  

/* function used to process timeval data structures */
int tval_zero(struct timeval *t)
{
  if (t->tv_sec || t->tv_usec)
    return FALSE;
  else
    return TRUE;
}

void tval_min(struct timeval *tmin, struct timeval *t1, struct timeval *t2)
{
  if (!t1)
    *tmin = *t2;
  else if (!t2)
    *tmin = *t1;
  else {
    tval_normalize(t1);
    tval_normalize(t2);

    if (t1->tv_sec < t2->tv_sec)
      *tmin = *t1;
    else if (t1->tv_sec > t2->tv_sec)
      *tmin = *t2;
    else if (t1->tv_usec < t2->tv_usec)
      *tmin = *t1;
    else
      *tmin = *t2;
  }
}


void tval_sub(struct timeval *tres, struct timeval *t1, struct timeval *t2)
{
  assert(t1);
  assert(t2);

  /* assume t1 is greater than t2 */
  if (t1->tv_usec < t2->tv_usec) {
    tres->tv_usec = 1000000 + t1->tv_usec - t2->tv_usec;
    tres->tv_sec = t1->tv_sec - t2->tv_sec - 1;
  } else {
    tres->tv_usec = t1->tv_usec - t2->tv_usec;
    tres->tv_sec = t1->tv_sec - t2->tv_sec;
  }
}

void tval_normalize(struct timeval *t)
{
  if (t->tv_usec >= UMILLION) {
    t->tv_sec += t->tv_usec/UMILLION;
    t->tv_usec = t->tv_usec % UMILLION;
  }
}

/* get local address -- use fn in utils/ */  
struct in_addr get_local_addr_cl()
{
  struct in_addr ia;
  ia.s_addr = ntohl(get_local_addr());
  return ia;
}

int check_addr_change(struct in_addr *ia)
{
  struct in_addr new;
  new.s_addr = ntohl(get_local_addr());
  if (ia->s_addr != new.s_addr) {
    ia->s_addr = new.s_addr;
    return 1;
  } else {
    return 0;
  }
}
