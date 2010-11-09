/***************************************************************************
                          i3_client_callback.h  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_CALLBACK_H
#define I3_CLIENT_CALLBACK_H

int cl_register_context_callback(cl_context *ctx, uint16_t cbk_type, 
				 void (*fun)(void*), void *data); 
int cl_register_trigger_callback1(cl_trigger *clt, uint16_t cbk_type, 
				  void (*fun)(void*), void *data);
void cl_trigger_callback(cl_context *ctx, cl_trigger *ctr, 
			 int cbk_type, i3_header *hdr, cl_buf *clb);
void cl_id_callback(cl_context *ctx, int cbk_type, ID *id,
		    struct in_addr *addr, uint16_t *port);
void cl_path_callback(cl_context *ctx, cl_path *ctp, int cbk_type);

#endif
