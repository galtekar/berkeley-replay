/***************************************************************************
                          i3_client_context.h  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_CONTEXT_H
#define I3_CLIENT_CONTEXT_H

#include "i3_client.h"

cl_context *cl_create_context(struct in_addr *ip_addr,
			      uint16_t local_port
			      );
void cl_destroy_context(cl_context *ctx);
int cl_register_context_callback(cl_context *ctx, uint16_t cbk_type, 
				 void (*fun)(), void *data);
int cl_context_select(cl_context *ctx, int n, 
		      fd_set *readfds, fd_set *writefds, fd_set *exceptfds, 
		      struct timeval *cl_to);

void read_srv_list(cl_context *ctx);
void update_srv_list(cl_context *ctx);
srv_address *set_i3_server_status(srv_address *s_array, 
				  uint32_t ip_addr, uint16_t port,
				  int status);
int get_i3_server(int num_servers, srv_address *s_array);
#endif
