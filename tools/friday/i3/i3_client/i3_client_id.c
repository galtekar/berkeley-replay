/***************************************************************************
                          i3_client_id.c  -  description
                             -------------------
    begin                : Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include "i3.h"
#include "i3_fun.h"
#include "trig_binheap.h"
#include "i3_client.h"
#include "i3_client_fun.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


cl_id *cl_alloc_id()
{
  cl_id *cid;

  if ((cid = (cl_id *)calloc(1, sizeof(cl_id))) != NULL)
    return cid;

  panic("cl_alloc_id: memory allocation error.\n");
  return NULL;
}

void cl_free_id(cl_id *cid)
{
  free(cid);
}


void cl_free_id_list(cl_id *cid_head)
{
  cl_id *cid;

  assert(cid_head);

  while (cid_head) {
    cid = cid_head->next;
    cl_free_id(cid_head);
    cid_head = cid;
  }
}


/* return a node whose id is on the same i3 server */
cl_id *cl_get_id_from_list(cl_id *head, ID *id)
{
  cl_id *cid;

  for (cid = head; cid; cid = cid->next)  
    if (!memcmp((char *)&cid->id, (char *)id, (MIN_PREFIX_LEN >> 3))) 
      return cid;
  return NULL;
}


/* remove a given identifier node from list; don't destroy it */ 
void cl_remove_id_from_list(cl_id **phead, cl_id *cid)
{

  assert(cid);

  if (*phead == cid) {
    *phead = (*phead)->next;
    if (*phead)
      (*phead)->prev = NULL;
  } else {
    cid->prev->next = cid->next;
    if (cid->next)
      cid->next->prev = cid->prev;
  }
}

/* add identifier at the head of the list */
void cl_add_id_to_list(cl_id **phead, cl_id *cid)
{
  assert(cid);

  cid->next = *phead;
  if (*phead)
    (*phead)->prev = cid;
  cid->prev = NULL;
  *phead = cid;
}

cl_id *cl_get_valid_id(cl_context *ctx, ID *id, int *refresh)
{
  cl_id *cid;
  int idx = CL_HASH_ID(id);
  srv_address *srv;
  struct in_addr ia;
  
  *refresh = TRUE;
  if ((cid = cl_get_id_from_list(ctx->id_htable[idx], id)) == NULL) 
    return NULL;
  if (cid->retries_cnt >= MAX_NUM_ID_RETRIES) {
    cl_remove_id_from_list(&ctx->id_htable[idx], cid);
    srv = set_i3_server_status(ctx->s_array, 
			       htonl(cid->i3_srv.sin_addr.s_addr),
			       htons(cid->i3_srv.sin_port), ID_DOWN);
    ia.s_addr = htonl(cid->i3_srv.sin_addr.s_addr);
    if (NULL == srv)
      return NULL;
    cl_id_callback(ctx, CL_CBK_SERVER_DOWN, id, &srv->addr, &srv->port); 
    cl_free_id(cid);
    return NULL;
  } else {
    if (ctx->now.tv_sec - cid->last_ack.tv_sec > 
       ID_REFRESH_PERIOD-ACK_TIMEOUT*(MAX_NUM_ID_RETRIES-cid->retries_cnt)) {
      cid->retries_cnt++;
      return cid;
    }
  }
  *refresh = FALSE;
  return cid;
}

/* ip_addr and port number are in host format */
cl_id *cl_update_id(cl_context *ctx, ID *id, 
		    struct in_addr *ip_addr, uint16_t port)
{
  cl_id *cid;

  if ((cid = cl_get_id_from_list(ctx->id_htable[CL_HASH_ID(id)], id)) != NULL) {
    cid->i3_srv.sin_addr.s_addr = ntohl(ip_addr->s_addr);
    cid->i3_srv.sin_port = ntohs(port);
    cid->retries_cnt = 0;
    cid->last_ack = ctx->now;
    set_i3_server_status(ctx->s_array, ip_addr->s_addr, port, ID_UP);
    return cid;
  } else 
    return NULL;
}


/* ip_addr and port number are in host format */
cl_id *cl_create_id(cl_context *ctx, ID *id, 
		    struct in_addr *ip_addr, uint16_t port)
{
  cl_id *cid;

  if ((cid = cl_get_id_from_list(ctx->id_htable[CL_HASH_ID(id)], id)) != NULL)
    return cid;

  cid = cl_alloc_id();
  memcpy((char *)&cid->id, id, ID_LEN);
  bzero(&cid->i3_srv, sizeof(struct sockaddr_in));
  cid->i3_srv.sin_family = AF_INET;
  cl_add_id_to_list(&ctx->id_htable[CL_HASH_ID(&cid->id)], cid);
  cid->i3_srv.sin_addr.s_addr = htonl(ip_addr->s_addr);
  cid->i3_srv.sin_port = htons(port);
  cid->retries_cnt = 0;
  cid->last_ack = ctx->now;
  set_i3_server_status(ctx->s_array, ip_addr->s_addr, port, ID_UP);


  return cid;
}
