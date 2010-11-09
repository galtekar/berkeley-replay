/***************************************************************************
                          i3_client_id.h  -  description
                             -------------------
    begin                : Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_ID_H
#define I3_CLIENT_ID_H 

 
/* functions implemented in i3_client_id.c */
cl_id *cl_alloc_id();
void cl_free_id(cl_id *cid);
cl_id *cl_get_id_from_list(cl_id *head, ID *id);
cl_id *cl_get_valid_id(cl_context *ctx, ID *id, int *refresh);
void cl_free_id_list(cl_id *cid_head);
void cl_remove_id_from_list(cl_id **phead, cl_id *cid);
void cl_add_id_to_list(cl_id **phead, cl_id *cid);
/* ip_addr and port number are in host format */
cl_id *cl_create_id(cl_context *ctx, ID *id, 
		    struct in_addr *ip_addr, uint16_t port);
/* ip_addr and port number are in host format */
cl_id *cl_update_id(cl_context *ctx, ID *id, 
		    struct in_addr *ip_addr, uint16_t port);

#endif
