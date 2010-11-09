/***************************************************************************
                          i3_client_api.c  -  description
                             -------------------
    begin                : Aug 20 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include <errno.h>    
#include <pthread.h>

#include "i3.h"
#include "i3_fun.h"
#include "trig_binheap.h"

#include "i3_client.h"
#include "i3_client_fun.h"
#include "ping_thread.h"
#include "i3server_list.h"

static cl_context *g_ctx = NULL; /* context associated with the process */

/************************************************************************
 * cl_init1, cl_init - create and initialize a context data structure (g_ctx) 
 *                     cl_init1() is equivalent to cl_init(NULL, 0, NULL)
 *  input (for cl_init):
 *    local_ip_addr, local_port - an IP address and a port number on the 
 *                                local machine 
 *    file_i3_srv_list - a file containing a list of i3 servers. each
 *                       line of the file contains a pair consisting
 *                       of (ip address, port number), e.g.,
 *                       "128.35.68.192 10000"
 *************************************************************************/

int cl_init1()
{
  if (g_ctx != NULL)
    return CL_RET_DUP_CONTEXT;
 
  g_ctx = cl_create_context(NULL, 0);

  return CL_RET_OK;
}

int cl_init_ping(char *url)
{
    pthread_t ping_thread;
    PingThreadData *data;
    char *temp_str;
    int i;
    
    if (g_ctx == NULL)
	return CL_RET_DUP_CONTEXT;
    
    g_ctx->list = (I3ServerList *) malloc(sizeof(I3ServerList));
    g_ctx->ping_start_time = (uint64_t *) malloc(sizeof(uint64_t));
    init_i3server_list(g_ctx->list);

    for (i = 0; i < g_ctx->num_servers; i++)
      create_i3server(g_ctx->list, g_ctx->s_array[i].addr.s_addr,
	  	g_ctx->s_array[i].port, g_ctx->s_array[i].id);
    
    data = (PingThreadData *) malloc(sizeof(PingThreadData));
    temp_str = (char *) malloc(strlen(url)+1);
    strcpy(temp_str, url);
    data->url = temp_str;
    data->list = g_ctx->list;
    data->ping_start_time = g_ctx->ping_start_time;

    pthread_create(&ping_thread, NULL, ping_thread_entry, (void *)data);
    return CL_RET_OK;
}

int cl_init(struct in_addr *local_ip_addr, uint16_t local_port)
{
  unsigned short use_ping;
  
  if (g_ctx != NULL)
    return CL_RET_DUP_CONTEXT;

  g_ctx = cl_create_context(local_ip_addr, local_port);

  read_ushort_par("/parameters/i3_server/closest_server", &use_ping,0);

  if (use_ping)
  {
    char status_url[500] = "www.cs.berkeley.edu/~karthik/i3_status.txt";
    read_string_par("/parameters/i3_server/status_url",status_url,0);
    printf("Starting ping thread\n");
    return cl_init_ping(status_url);
  }

  return CL_RET_OK;
}


/************************************************************************
 * Returns RTT of given addr (in host format)
 ***********************************************************************/
int cl_get_rtt_server(uint32_t addr, uint64_t *rtt)
{
    if (g_ctx == NULL || g_ctx->list == NULL)
	return CL_RET_NO_AUTO_SERVER_SELECT;

    *rtt = get_rtt(g_ctx->list, addr);
    
    return CL_RET_OK;
}

int cl_get_rtt_id(ID *id, uint64_t *rtt)
{
    if (g_ctx == NULL || g_ctx->list == NULL)
	return CL_RET_NO_AUTO_SERVER_SELECT;

    *rtt = get_rtt_id(g_ctx->list, id);
    
    return CL_RET_OK;
}

/************************************************************************
 * Returns top k servers sorted by RTT.
 *
 * At return, "k" would contain the actual number of servers that are
 * returned (may be smaller than requested)
 ***********************************************************************/
int cl_get_top_k_servers(int *k, uint32_t best_addr[],
    		uint16_t best_port[], uint64_t	best_rtt[])
{ 
    if (g_ctx == NULL || g_ctx->list == NULL) 
	return CL_RET_NO_AUTO_SERVER_SELECT;
    
    *k = get_top_k(g_ctx->list, *k, best_addr, best_port, best_rtt);
    
    return CL_RET_OK;
}

int cl_get_top_k_ids(int *k, ID best_id[], uint64_t best_rtt[])
{
    if (g_ctx == NULL || g_ctx->list == NULL)
	return CL_RET_NO_AUTO_SERVER_SELECT;

    *k = get_top_k_id(g_ctx->list, *k, best_id, best_rtt);
    
    return CL_RET_OK;
}


/************************************************************************
 * cl_exit - free all resources allocated by the local context (g_ctx)
 ***********************************************************************/

int cl_exit()
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;

  cl_destroy_context(g_ctx);
  return CL_RET_OK;
}


/************************************************************************
 * cl_check_status - returns the number of available i3 servers
 * 		     returns -1 when g_ctx == NULL
 *************************************************************************/

int cl_check_status()
{
    int idx;
    if (g_ctx == NULL)
      return -1;
    idx = get_i3_server(g_ctx->num_servers, g_ctx->s_array);
    if (-1 == idx) return 0;
    return (ID_UP == g_ctx->s_array[idx].status);
}

/************************************************************************
 * cl_register_callback - register a callback associated with the 
 *                        local context
 *
 * Input:
 *   cbk_type - callback type (see below)
 *   fun      - callback function
 *   data     - pointer to a client data structure, to be passed
 *              back when the callback is invoked
 *
 * The list of supported callback types (cbk_type) is the following:
 *   CL_CBK_TRIGGER_INSERTED - this callback is invoked when  
 *                             the client receives the first ack
 *                             as a result of a trigger insertion. 
 *                             The callback has the following arguments:
 *                             fun(i3_trigger *t, void *data), where
 *                             "t" represents the inserted trigger, and 
 *                             "data" represents the client's data
 * 
 *   CL_CBK_TRIGGER_REFRESH_FAILED- this callback is invoked when the
 *                                  refreshing of a trigger fails. A
 *                                  refreshing failure occurs when none 
 *                                  of the client's refreshing messages
 *                                  is acked during a refresh period which 
 *                                  has a duration of TRIGGER_REFRESH_PERIOD 
 *                                  sec. The client refreshes a trigger by 
 *                                  sending a refreshing message 
 *                                  MAX_NUM_TRIG_RETRIES*ACK_TIMEOUT before
 *                                  the refreshing period expires. If the
 *                                  first refresh message is not acked, the 
 *                                  client resends the refresh message 
 *                                  approximately every ACK_TIMEOUT sec.
 *                                  
 *                                  The callback function has the following 
 *                                  arguments: fun(i3_trigger *t, void *data).
 *
 *                                  A typical response of the client to
 *                                  this callback is to reinsert the trigger
 *                                  using the cl_reinsert_trigger function.
 *         
 *   CL_CBK_TRIGGER_NOT_FOUND - this callback is invoked when the client
 *                              sends packets to an ID id, and there is 
 *                              no trigger in the network matching this "id"
 *                            
 *                              The callback function has the following 
 *                              arguments: fun(ID *id, void *data).
 *
 *   CL_CBK_TRIGGER_CONSTRAINT_FAILED - callback invoked when an unconstrained
 *   				trigger insertion is attempted.
 *
 *   				callback fn: fun(ID *id, void *data).
 * 
 *   CL_CBK_RECEIVE_PACKET  - this callback is invoked upon
 *                            receiving an i3 packet.
 *
 *                            The callback function has the following 
 *                            arguments: 
 *                                 fun(i3_trigger *t, i3_header *hdr,
 *                                     cl_buf *b, void *data), where "t" 
 *                               represents the trigger matching the
 *                               the packet's ID, "hdr" represents the 
 *                               packet's header, "b" contains the 
 *                               packet's payload, and "data" represents
 *                               the client's data.
 *
 *   CL_CBK_RECEIVE_PAYLOAD - this callback is invoked upon
 *                            receiving a data packet. This callback is
 *                            suppressed by the CL_CBK_RECEIVE_PACKET callback.
 *
 *                            The callback function has the following 
 *                            arguments: 
 *                                 fun(i3_trigger *t, cl_buf *b, void *data)
 *
 *   CL_CBK_SERVER_DOWN - this callback is invoked when  the client
 *                        concludes than an i3 server is down. This happens
 *                        when the client either receives no acks (in the form
 *                        of I3_OPT_CACHE_ADDR replies) to sending packets
 *                        to that server during a refresh period of 
 *                        ID_REFRESH_PERIOD sec, or when the client 
 *                        receives no acks to three consecutive 
 *                        I3_OPT_REQUEST_FOR_CACHE queries.
 *
 *                         The callback function has the following arguments: 
 *                           fun(struct in_addr ip_addr, uint16_t port, 
 *                               void *data), where "ip_addr" and "port"
 *                         identifies the reported server.
 *
 *   CL_CBK_ROUTE_BROKEN - invoked when when server indicates that the
 *   			   i3_server corresponding to the next hop is
 *   			   dead, and some action is needed to recover
 *
 *************************************************************************/

int cl_register_callback(uint16_t cbk_type, void (*fun)(), void *data) 
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;

  return cl_register_context_callback(g_ctx, cbk_type, fun, data);
}


/************************************************************************
 * cl_insert_trigger - insert a trigger pointing to the local node
 *
 *  input:
 *    id - trigger's ID
 *    prefix_len - length of the minimum prefix of "id" on which 
 *                 the ID of the incoming packets should match
 *   
 *
 *  return:
 *    pointer to the trigger or NULL if trigger couldn't be created
 *
 *************************************************************************/

i3_trigger *cl_insert_trigger_key(ID *id, uint16_t prefix_len, Key *key)
{
  cl_trigger *ctr;

  if (g_ctx == NULL)
    return NULL;
  
  ctr = cl_create_trigger_gen(g_ctx, I3_ADDR_TYPE_IPv4, id, prefix_len, 
	  		g_ctx->local_ip_addr, g_ctx->local_port, NULL, key);
  if (ctr) {
    cl_insert_trigger_into_i3(g_ctx, ctr);
    return ctr->t;
  } else
    return NULL;
}


/************************************************************************
 * cl_create_trigger_addr - insert a trigger pointing to a given
 *                          IP address/port number
 *
 *  input:
 *    id - trigger's ID 
 *    prefix_len - length of the minimum prefix of "id" on which 
 *                 the ID of the incoming packets should match
 *    ip_addr, port - IP address and port number to which the 
 *                    trigger points to (should be on the local machine
 *                    since the trigger insertion will challenge the
 *                    insertion)
 *  return:
 *    pointer to the trigger or NULL if the trigger couldn't be created
 *
 *************************************************************************/

i3_trigger *cl_insert_trigger_addr_key(ID *id, uint16_t prefix_len,
			struct in_addr ip_addr, uint16_t port, Key *key)
{
  cl_trigger *ctr;

  if (g_ctx == NULL)
    return NULL;
  
  ctr = cl_create_trigger_gen(g_ctx, I3_ADDR_TYPE_IPv4, 
			      id, prefix_len, ip_addr, port, NULL, key);
  if (ctr) {
    cl_insert_trigger_into_i3(g_ctx, ctr);
    return ctr->t;
  } else
    return NULL;
}


/************************************************************************
 * cl_insert_trigger_stack - insert a trigger pointing to a given stack
 *
 *  input:
 *    id - trigger's ID 
 *    prefix_len - length of the minimum prefix of "id" on which 
 *                 the ID of the incoming packets should match
 *    stack - stack of IDs to which the trigger points to
 * 
 *  return:
 *    pointer to the trigger or NULL if the trigger couldn't be created
 *
 *************************************************************************/

i3_trigger *cl_create_trigger_stack(ID *id, uint16_t prefix_len, 
				    i3_stack *stack)
{
  cl_trigger *ctr;
  struct in_addr nothing;

  if (g_ctx == NULL)
    return NULL;
  
  ctr = cl_create_trigger_gen(g_ctx, I3_ADDR_TYPE_STACK, 
			      id, prefix_len, nothing, 0, stack, 0);

  if (ctr)  return ctr->t;
  else	    return NULL;
}

i3_trigger *cl_insert_trigger_stack(ID *id, uint16_t prefix_len, 
				     i3_stack *stack)
{
  cl_trigger *ctr;
  struct in_addr nothing;

  if (g_ctx == NULL)
    return NULL;
  
  ctr = cl_create_trigger_gen(g_ctx, I3_ADDR_TYPE_STACK, 
			      id, prefix_len, nothing, 0, stack, 0);

  if (ctr) {
    cl_insert_trigger_into_i3(g_ctx, ctr);
    return ctr->t;
  } else
    return NULL;
}


/************************************************************************
 * cl_reinsert_trigger - reinsert trigger "t". Usually this function 
 *                       is called when the client receives a
 *                       CL_CBK_TRIGGER_REFRESH_FAILURE callback for "t". 
 *
 *************************************************************************/

int cl_reinsert_trigger(i3_trigger *t)
{
  cl_trigger *ctr;
  
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;

  ctr = cl_get_trigger_from_list(g_ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);

  if (!ctr) 
    return CL_RET_NO_TRIGGER;

  cl_insert_trigger_into_i3(g_ctx, ctr);
  
  return CL_RET_OK;
}

int cl_reinsert_trigger_later(i3_trigger *t)
{
  cl_trigger *ctr;
  TrigInsertNode *t_node;

  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;

  ctr = cl_get_trigger_from_list(g_ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);

  if (!ctr) 
    return CL_RET_NO_TRIGGER;

  if (ctr->status != CL_TRIGGER_STATUS_IDLE) {
    assert(ctr->is_queued);
    return CL_RET_TRIGGER_ALREADY_EXISTS;
  }

  assert(!ctr->is_queued);
  t_node = (TrigInsertNode *) emalloc(sizeof(TrigInsertNode));
  t_node->t = duplicate_i3_trigger(ctr->t);
  t_node->state = REFRESH_TO_SEND;
#define REINSERT_WAIT_TIME 10
  t_node->time = wall_time() + REINSERT_WAIT_TIME * 1000000ULL;
  TrigInsert(t_node, g_ctx->trig_refresh_queue);
  
  ctr->status = CL_TRIGGER_STATUS_INSERTED;
  ctr->is_queued = TRUE;
  
  return CL_RET_OK;
}

/************************************************************************
 * cl_remove_trigger - remove trigger "t". This involves sending
 *                     an explicit message (I3_OPT_TRIGGER_REMOVE)
 *                     to remove the trigger from the infrastructure
 *
 *************************************************************************/

int cl_remove_trigger_i3(i3_trigger *t)
{
  cl_trigger *ctr;

  assert(t);

  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;

  ctr = cl_get_trigger_from_list(g_ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);

  if (!ctr) 
    return CL_RET_NO_TRIGGER;
  
  return cl_remove_trigger_from_i3(g_ctx, ctr);
}

int cl_remove_trigger(i3_trigger *t)
{
  cl_trigger *ctr;
  int         rc;

  assert(t);

  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;

  ctr = cl_get_trigger_from_list(g_ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);

  if (!ctr) 
    return CL_RET_NO_TRIGGER;
  
  /* remove & destroy trigger */
  rc = cl_remove_trigger_from_i3(g_ctx, ctr);
  cl_destroy_trigger(g_ctx, ctr);

  return rc;
}


/************************************************************************
 * cl_register_trigger_callback - register a callback associated with a
 *                                trigger. These callbacks are similar
 *                                to the callbacks asssociated to the 
 *                                context (see cl_register_callback).
 *                                A callback associated to a trigger 
 *                                has strict priority over the same 
 *                                callback associated to the context.
 *
 * Input:
 *   t - trigger to which the callback is associated to
 *   cbk_type - callback type (see below)
 *   fun      - callback function
 *   data     - pointer to a client data structure, to be passed
 *              back when the callback is invoked
 *
 * The list of supported callback types (cbk_type) is the following:
 *   CL_CBK_TRIGGER_INSERTED - this callback is invoked when  
 *                             the client receives the first ack
 *                             as a result of a trigger insertion. 
 *                             The callback has the following arguments:
 *                             fun(i3_trigger *t, void *data), where
 *                             "t" represents the inserted trigger, and 
 *                             "data" represents the client's data
 * 
 *   CL_CBK_TRIGGER_REFRESH_FAILED- this callback is invoked when the
 *                                  refreshing of a trigger fails. A
 *                                  refreshing failure occurs when none 
 *                                  of the client's refreshing messages
 *                                  is acked during a refresh period which 
 *                                  has a duration of TRIGGER_REFRESH_PERIOD 
 *                                  sec. The client refreshes a trigger by 
 *                                  sending a refreshing message 
 *                                  MAX_NUM_TRIG_RETRIES*ACK_TIMEOUT sec
 *                                  before the refreshing period expires.
 *                                  If the first refresh message is not
 *                                  acked, the client resends the refresh
 *                                  message approximately every 
 *                                  ACK_TIMEOUT sec.
 *                                  
 *                                  The callback function has the following 
 *                                  arguments: fun(i3_trigger *t, void *data).
 *
 *                                  A typical response of the client to
 *                                  this callback is to reinsert the trigger
 *                                  using the cl_reinsert_trigger function.
 *         
 *   CL_CBK_RECEIVE_PACKET  - this callback is invoked upon
 *                            receiving an i3 packet.
 *
 *                            The callback function has the following 
 *                            arguments: 
 *                                 fun(i3_trigger *t, i3_header *hdr,
 *                                     cl_buf *b, void *data), where "t" 
 *                               represents the trigger matching the
 *                               the packet's ID, "hdr" represents the 
 *                               packet's header, "b" contains the 
 *                               packet's payload, and "data" represents
 *                               the client's data.
 *
 *   CL_CBK_RECEIVE_PAYLOAD - this callback is invoked upon
 *                            receiving a data packet. This callback is
 *                            suppressed by the CL_CBK_RECEIVE_PACKET callback.
 *
 *                            The callback function has the following 
 *                            arguments: 
 *                                 fun(i3_trigger *t, cl_buf *b, void *data)
 *
 *************************************************************************/

int cl_register_trigger_callback(i3_trigger *t, uint16_t cbk_type, 
				 void (*fun)(), void *data)
{
  cl_trigger *ctr;

  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;
  
  ctr = cl_get_trigger_from_list(g_ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);
  if (!ctr) 
    return CL_RET_NO_TRIGGER;
 
  return cl_register_trigger_callback1(ctr, cbk_type, fun, data);
}


/************************************************************************
 * cl_send_to_id - send a packet to an ID
 ***********************************************************************/

int cl_send_to_id(ID *id, cl_buf *clb)
{
  return cl_send_to_id_opts(id, clb, 0, 0);
}
int cl_send_to_id_bwmeasure(ID *id, cl_buf *clb)
{
  /* This would send the packet with a total size = the value present
   * in clb->data_len. This is useful for app-level bw-measurements */
  return cl_send_to_id_opts(id, clb, 0, 1);
}
int cl_send_to_id_opts(ID *id, cl_buf *clb, uint8_t opts_mask, char is_total_len)
{
  i3_stack *s;

  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;
  
  s = alloc_i3_stack();
  init_i3_stack(s, id, 1 /* only one ID in the stack */);
  cl_send_data_packet(g_ctx, s, clb, opts_mask, is_total_len);
  free_i3_stack(s);

  return CL_RET_OK;
}

/************************************************************************
 * cl_send_to_stack - send a packet along a set of IDs 
 ***********************************************************************/

int cl_send_to_stack(i3_stack *stack, cl_buf *clb)
{
  return cl_send_to_stack_opts(stack, clb, 0);
}
int cl_send_to_stack_opts(i3_stack *stack, cl_buf *clb, uint8_t opts_mask)
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;
  
  // for now, setting is_total_len to "0"
  cl_send_data_packet(g_ctx, stack, clb, opts_mask, 0);
  return CL_RET_OK;
}


/************************************************************************
 * cl_send_to_header - send a packet specifying the full packet header.
 *                     The destination is contained in hdr->stack.
 ***********************************************************************/

int cl_send_to_header(i3_header *hdr, cl_buf *clb)
{
  return cl_send_to_header_opts(hdr, clb, 0);
}
int cl_send_to_header_opts(i3_header *hdr, cl_buf *clb, uint8_t opts_mask)
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;
  
  cl_send_packet(g_ctx, hdr, clb, opts_mask);
  return CL_RET_OK;
}


/************************************************************************
 * cl_select - function to replace the select() function (sys/select.h)
 *             Either this function or cl_loop() should be invoked at
 *             the end of every client program since cl_select()/cl_loop()
 *             are responsibe with the trigger refreshing and processing
 *             the options of the received packets.
 ***********************************************************************/

int cl_select(int n, fd_set *readfds, fd_set *writefds, 
	       fd_set *exceptfds, struct timeval *cl_to)
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT; 
  return cl_context_select(g_ctx, n, readfds, writefds, exceptfds, cl_to);
}


/************************************************************************
 *    PATH API
 ***********************************************************************/

cl_path *cl_setup_path(ID *path, uint16_t path_len, uint32_t tmask, int *rc)
{
  cl_path *clp;

  if (g_ctx == NULL) {
    *rc = CL_RET_NO_CONTEXT; 
    return NULL;
  }

  if ((clp = cl_create_path(g_ctx, path, path_len, tmask, rc)) == NULL)
    return NULL;

  cl_insert_path_into_i3(g_ctx, clp);

  return clp;
}

int cl_reinsert_path(cl_path *clp)
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT;
  
  assert(clp);

  cl_insert_path_into_i3(g_ctx, clp);
  
  return CL_RET_OK;
}


int cl_remove_path(cl_path *clp)
{
  if (g_ctx == NULL)
    return CL_RET_NO_CONTEXT; 
  
  cl_remove_path_from_i3(g_ctx, clp);
  cl_destroy_path(g_ctx, clp);

  return CL_RET_OK;
}


i3_trigger *cl_register_key(ID *id, uint16_t prefix_len,
			void (*fun)(), void *data, Key *key)
{
  i3_trigger *t;
  
  if ((t = cl_insert_trigger_key(id, prefix_len, key)) == NULL)
    return t;

  cl_register_trigger_callback(t, CL_CBK_PATH_RECEIVE, fun, data);

  return t;
}

void cl_get_srv_addr(unsigned int *addr,ushort *port)
{
  *addr = g_ctx->s_array[0].addr.s_addr;
  *port = g_ctx->s_array[0].port;
}

#define cl_path_send(id, clb) cl_send_to_id(id, clb)

/* constraints related functions */
void cl_generate_constraint_id(ID *id, Key *key, int type)
{
    generate_constraint_id(id, key, type);
}
void cl_generate_l_constraint_key(Key *rkey, Key *lkey)
{
    generate_l_constraint(rkey, lkey);
}
void cl_set_key_id(ID *id, Key *key)
{
    set_key_id(id, key);
}
void cl_l_constrain_path(ID *id, int path_len)
{
    l_constrain_path(id, path_len);
}
void cl_r_constrain_path(ID *id, int path_len)
{
    r_constrain_path(id, path_len);
}

/* setting IDs as public_IDs */
void cl_set_public_id(ID *id)
{
    set_id_type(id, I3_ID_TYPE_PUBLIC);
}
void cl_set_private_id(ID *id)
{
    set_id_type(id, I3_ID_TYPE_PRIVATE);
}
