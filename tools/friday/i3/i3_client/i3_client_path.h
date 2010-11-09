/***************************************************************************
                          i3_client_path.h  -  description
                             -------------------
    begin                : Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_PATH_H
#define I3_CLIENT_PATH_H 

 
/* functions implemented in i3_client_path.c */

cl_path *cl_create_path(cl_context *ctx, ID *path, 
			uint16_t path_len, uint32_t tmask, int *rc);
void cl_destroy_path(cl_context *ctx, cl_path *clp);
void cl_destroy_path_list(cl_context *ctx);
void cl_insert_path_into_i3(cl_context *ctx, cl_path *clp);
void cl_remove_path_from_i3(cl_context *ctx, cl_path *clp);
int cl_compute_path_key(ID *path, uint16_t len);
int cl_path_check_mask(uint32_t tmask, uint16_t path_len, 
		       uint16_t *trigger_num);
void cl_create_shadow_id(ID *id, ID *new_id);
void cl_printf_path(cl_path *clp);

#endif
