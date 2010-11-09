/***************************************************************************
                          i3_client_callback.c  -  description
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


/***********************************************************************
 *  cl_trigger_callback - invoke a callback associated with a trigger
 *
 *  input:
 *    ctx - context
 *    ctr - pointer to the trigger data structure on which this callback
 *          is invoked
 *    hdr - packet header; used only when CL_CBK_RECEIVE_PACKET is invoked
 *    payload, payload_len - pointer to the payload and its lengths; used
 *                           either when  CL_CBK_RECEIVE_PACKET and
 *                           CL_CBK_RECEIVE_PAYLOAD are invoked
 *
 ************************************************************************/

void cl_trigger_callback(cl_context *ctx, cl_trigger *ctr, int cbk_type, 
			 i3_header *hdr, cl_buf *cbl) 
{
  switch (cbk_type) {
  case CL_CBK_TRIGGER_INSERTED:
    // printf("In Callback: trigger with following ID inserted\n");
    // printf_i3_id(&(ctr->t->id), 2); 
    if (ctr->path)
      return cl_path_callback(ctx, ctr->path, CL_CBK_PATH_INSERTED);
    if (ctr->cbk_trigger_inserted.fun) {
      ctr->cbk_trigger_inserted.fun(ctr->t, ctr->cbk_trigger_inserted.data);
    } else if (ctx->cbk_trigger_inserted.fun) {
      ctx->cbk_trigger_inserted.fun(ctr->t, ctx->cbk_trigger_inserted.data);
    } else {
      printf("Default callback: trigger with following ID inserted\n");
      printf_i3_id(&(ctr->t->id), 2); 
    }
    break;
  case CL_CBK_TRIGGER_REFRESH_FAILED:
    if (ctr->path)
      return cl_path_callback(ctx, ctr->path, CL_CBK_PATH_REFRESH_FAILED);
    if (ctr->cbk_trigger_refresh_failed.fun) 
      ctr->cbk_trigger_refresh_failed.fun(ctr->t, 
					  ctr->cbk_trigger_refresh_failed.data);
    else if (ctx->cbk_trigger_refresh_failed.fun)
      ctx->cbk_trigger_refresh_failed.fun(ctr->t, 
					  ctx->cbk_trigger_refresh_failed.data);
    else {
      printf("Default callback: trigger with following ID couldn't \
be inserted/refreshed\n");
      printf_i3_id(&(ctr->t->id), 2); 
    }
    break;

  case CL_CBK_TRIGGER_CONSTRAINT_FAILED:
    if (ctr->path)
	return cl_path_callback(ctx, 
		ctr->path, CL_CBK_TRIGGER_CONSTRAINT_FAILED);
    if (ctr->cbk_trigger_constraint_failed.fun)
	ctr->cbk_trigger_constraint_failed.fun(ctr->t,
		ctr->cbk_trigger_constraint_failed.data);
    else if (ctx->cbk_trigger_constraint_failed.fun)
	ctx->cbk_trigger_constraint_failed.fun(ctr->t,
		ctx->cbk_trigger_constraint_failed.data);
    else {
	printf("Default callback: trigger with following ID didn't satisfy constraints\n");
	printf_i3_id(&(ctr->t->id), 2);
    }
    break;

  case CL_CBK_RECEIVE_PACKET:
    if (ctr->cbk_receive_packet.fun)
      ctr->cbk_receive_packet.fun(ctr->t, hdr, cbl, 
				  ctr->cbk_receive_packet.data);
    else if (ctx->cbk_receive_packet.fun)
      ctx->cbk_receive_packet.fun(ctr->t, hdr, cbl,
				  ctx->cbk_receive_packet.data);
    else {
      printf("Default callback: received packet matching following ID\\n");
      printf_i3_id(&(ctr->t->id), 2); 
    }
    break;
  case CL_CBK_RECEIVE_PAYLOAD:
    if (ctr->cbk_receive_packet.fun)
      break;
    else if (ctr->cbk_receive_payload.fun)
      ctr->cbk_receive_payload.fun(ctr->t, cbl,
				   ctr->cbk_receive_payload.data);
    else if (ctx->cbk_receive_packet.fun)
      break;
    else if (ctx->cbk_receive_payload.fun)
      ctx->cbk_receive_payload.fun(ctr->t, cbl,ctx->cbk_receive_payload.data);
    else {
      printf("Default callback: received data matching following ID\\n");
      printf_i3_id(&(ctr->t->id), 2); 
    }
    break;
  case CL_CBK_PATH_RECEIVE:
    {
      ID       *id_next = NULL;
      
      if (hdr->stack && hdr->stack->len && (hdr->stack->len > 1))
	id_next = &hdr->stack->ids[1];
 
      if (ctr->cbk_path_receive.fun)
	ctr->cbk_path_receive.fun(&ctr->t->id, id_next, cbl,  
				  ctr->cbk_receive_packet.data);
      else {
	printf("Default callback: received packet matching following ID\n");
	printf_i3_id(&(ctr->t->id), 2); 
      }
    }
    break;
  case CL_CBK_ROUTE_BROKEN:
    if (ctr->path)
      return cl_path_callback(ctx, ctr->path, CL_CBK_ROUTE_BROKEN);
    if (ctr->cbk_route_broken.fun) 
      ctr->cbk_route_broken.fun(ctr->t, ctr->cbk_route_broken.data);
    else if (ctx->cbk_route_broken.fun)
      ctx->cbk_route_broken.fun(ctr->t, ctx->cbk_route_broken.data);
    else {
      printf("Default callback: route broken while at the following trigger\n");
      printf_i3_trigger(ctr->t, 2); 
     }
    break;

  default:
    panic("cl_trigger_callback: invalid callback type!\n");
  }
}

/***********************************************************************
 *  cl_id_callback - invoke a callback associated with an ID
 *
 *  input:
 *    ctx - context
 *    id - ID with which the callback is associated
 *
 ************************************************************************/

void cl_id_callback(cl_context *ctx, int cbk_type, ID *id,
		    struct in_addr *ip_addr, uint16_t *port)
{
  switch (cbk_type) {
  case CL_CBK_TRIGGER_NOT_FOUND:
    if (ctx->cbk_trigger_not_found.fun)
      ctx->cbk_trigger_not_found.fun(id, ctx->cbk_trigger_not_found.data);
    else {
      printf("Default callback: there is no trigger matching following ID\n");
      printf_i3_id(id, 2); 
    }
    break;
  case CL_CBK_SERVER_DOWN:
    if (ctx->cbk_server_down.fun)
      ctx->cbk_server_down.fun(ip_addr, port, ctx->cbk_server_down.data);
    else
    {
      ip_addr->s_addr = htonl(ip_addr->s_addr);
      printf("Default callback: server couldn't be contacted (%s, %d)\n", 
	     inet_ntoa(*ip_addr), *port);
      ip_addr->s_addr = ntohl(ip_addr->s_addr);
    }
    break;
  default:
    panic("cl_callback: invalid callback type!\n");
  }
}


/***********************************************************************
 *  cl_path_callback - invoke a callback associated with a path
 *
 *  input:
 *    ctx - context
 *    ctp - pointer to the path data structure on which this callback
 *          is invoked
 *
 ************************************************************************/

void cl_path_callback(cl_context *ctx, cl_path *clp, int cbk_type) 
{
  int i;

  switch(cbk_type) {
  case CL_CBK_PATH_INSERTED:
    for (i = 0; i < clp->trigger_num; i++) {
      if (clp->triggers[i]->status != CL_TRIGGER_STATUS_INSERTED)
	return;
    }
    clp->status = CL_PATH_STATUS_INSERTED;
    if (clp->cbk_path_inserted.fun) 
      clp->cbk_path_inserted.fun(clp, clp->cbk_path_inserted.data);
    else if (ctx->cbk_path_inserted.fun)
      ctx->cbk_path_inserted.fun(clp, ctx->cbk_path_inserted.data);
    else {
      printf("Default callback: following path inserted\n");
      cl_printf_path(clp); 
    }
    break;
  case CL_CBK_PATH_REFRESH_FAILED:
    clp->status = CL_PATH_STATUS_IDLE;   
    if (clp->cbk_path_refresh_failed.fun) 
      clp->cbk_path_refresh_failed.fun(clp, clp->cbk_path_refresh_failed.data);
    else if (ctx->cbk_path_refresh_failed.fun)
      ctx->cbk_path_refresh_failed.fun(clp, ctx->cbk_path_refresh_failed.data);
    else {
      printf("Default callback: folllowing couldn't be inserted/refreshed\n");
      cl_printf_path(clp); 
    }
    break;
  case CL_CBK_TRIGGER_CONSTRAINT_FAILED:
    panic("cl_path_callback: CL_CBK_TRIGGER_CONSTRAINT_FAILED not implemented\n");
    break;
  case CL_CBK_ROUTE_BROKEN:
    panic("cl_path_callback: CL_CBK_ROUTE_BROKEN not implemented\n");
    break;
  default:
    panic("cl_path_callback: invalid callback type\n");
  }
}


/************************************************************************
 *  cl_register_trigger_callback1 - associate a callback with a trigger 
 *
 *  input:
 *    ctr - trigger
 *    cbk_type - callback type
 *    fun - callback function
 *    data - pointer to a user data associated with the callback
 *************************************************************************/

int cl_register_trigger_callback1(cl_trigger *ctr, uint16_t cbk_type,
#ifndef CCURED                                  
				  void (*fun)(),
#else                                  
				  void (*fun)(void*),
#endif                                  
                                  void *data)
{
  switch (cbk_type) {
  case CL_CBK_TRIGGER_INSERTED:
    ctr->cbk_trigger_inserted.fun = fun;
    ctr->cbk_trigger_inserted.data = data;
    break;
  case CL_CBK_TRIGGER_REFRESH_FAILED:
    ctr->cbk_trigger_refresh_failed.fun = fun;
    ctr->cbk_trigger_refresh_failed.data = data;
    break;
  case CL_CBK_TRIGGER_CONSTRAINT_FAILED:
    ctr->cbk_trigger_constraint_failed.fun = fun;
    ctr->cbk_trigger_constraint_failed.data = data;
    break;
  case CL_CBK_RECEIVE_PACKET:
    ctr->cbk_receive_packet.fun = fun;
    ctr->cbk_receive_packet.data = data;
    /* this callback takes precedence over 
     * CL_CBK_RECEIVE_PAYLOAD callback */
    if (ctr->cbk_receive_payload.fun)
      return CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD;
   break;
  case CL_CBK_RECEIVE_PAYLOAD:
    ctr->cbk_receive_payload.fun = fun;
    ctr->cbk_receive_payload.data = data;
    /* this callback is ignored if CL_CBK_RECEIVE_PACKET is already defined */
    if (ctr->cbk_receive_packet.fun)
      return CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD;
    break;
  case CL_CBK_PATH_RECEIVE:
    ctr->cbk_path_receive.fun = fun;
    ctr->cbk_path_receive.data = data;
    break;
  case CL_CBK_ROUTE_BROKEN:
    ctr->cbk_route_broken.fun = fun;
    ctr->cbk_route_broken.data = data;
    break;
  default:
    panic("cl_cbk_register_trigger_callback: invalid callback type!\n");
  }
  return CL_RET_OK;
}


/************************************************************************
 *  cl_register_path_callback - associate a callback with a path 
 *
 *  input:
 *    clp - trigger
 *    cbk_type - callback type
 *    fun - callback function
 *    data - pointer to a user data associated with the callback
 *************************************************************************/

int cl_register_path_callback(cl_path *clp, uint16_t cbk_type,
#ifndef CCURED                              
			      void (*fun)(),
#else                              
			      void (*fun)(void*),
#endif                              
                              void *data)
{
  switch (cbk_type) {
  case CL_CBK_PATH_INSERTED:
    clp->cbk_path_inserted.fun = fun;
    clp->cbk_path_inserted.data = data;
    break;
  case CL_CBK_PATH_REFRESH_FAILED:
    clp->cbk_path_refresh_failed.fun = fun;
    clp->cbk_path_refresh_failed.data = data;
    break;
  default:
    panic("cl_register_path_callback: invalid callback type!\n");
  }
  return CL_RET_OK;
}


/************************************************************************
 *  cl_register_context_callback - associate a callback with a context 
 *
 *  input:
 *    ctr - trigger
 *    cbk_type - callback type
 *    fun - callback function
 *    data - pointer to a user data associated with the callback
 *************************************************************************/

int cl_register_context_callback(cl_context *ctx, uint16_t cbk_type,
#ifndef CCURED                                 
				 void (*fun)(),
#else
                                 void (*fun)(void *),
#endif                                 
                                 void * data)
{
  switch (cbk_type) {
  case CL_CBK_TRIGGER_NOT_FOUND:
    ctx->cbk_trigger_not_found.fun = fun;
    ctx->cbk_trigger_not_found.data = data;
    break;
  case CL_CBK_TRIGGER_INSERTED:
    ctx->cbk_trigger_inserted.fun = fun;
    ctx->cbk_trigger_inserted.data = data;
    break;
  case CL_CBK_TRIGGER_REFRESH_FAILED:
    ctx->cbk_trigger_refresh_failed.fun = fun;
    ctx->cbk_trigger_refresh_failed.data = data;
    break;
  case CL_CBK_TRIGGER_CONSTRAINT_FAILED:
    ctx->cbk_trigger_constraint_failed.fun = fun;
    ctx->cbk_trigger_constraint_failed.data = data;
    break;
  case CL_CBK_RECEIVE_PACKET:
    ctx->cbk_receive_packet.fun = fun;
    ctx->cbk_receive_packet.data = data;
    /* this callback takes precedence over 
     * CL_CBK_RECEIVE_PAYLOAD callback 
     */
    if (ctx->cbk_receive_payload.fun)
      return CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD;
   break;
  case CL_CBK_RECEIVE_PAYLOAD:
    ctx->cbk_receive_payload.fun = fun;
    ctx->cbk_receive_payload.data = data;
    /* this callback is ignored if CL_CBK_RECEIVE_PACKET is already defined */
    if (ctx->cbk_receive_packet.fun)
      return CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD;
    break;
   case CL_CBK_PATH_INSERTED:
    ctx->cbk_path_inserted.fun = fun;
    ctx->cbk_path_inserted.data = data;
    break;
  case CL_CBK_PATH_REFRESH_FAILED:
    ctx->cbk_path_refresh_failed.fun = fun;
    ctx->cbk_path_refresh_failed.data = data;
    break;
  case CL_CBK_ROUTE_BROKEN:
    ctx->cbk_route_broken.fun = fun;
    ctx->cbk_route_broken.data = data;
    break;
  default:
    panic("cl_context_path_callback: invalid callback type!\n");
  }
  return CL_RET_OK;
}



/************************************************************************
 *  cl_duplicate_data - allocate memory and copy given data 
 *
 *  input:
 *    pdata, len - pointer to and the length of the data to be copied
 *
 *  return:
 *    pointer to duplicate data
 *************************************************************************/

void *cl_duplicate_data(void *pdata, unsigned int len)
{
  void *p;

  if ((p = (void *)calloc(1, len)) == NULL)
    panic("cl_alloc_data: memory allocation error\n");

  memcpy(p, pdata, len);

  return p;
}

