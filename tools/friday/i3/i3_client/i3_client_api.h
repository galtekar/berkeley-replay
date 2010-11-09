/***************************************************************************
                          i3_client_api.h  -  description
                             -------------------
    begin                : Aug 20 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_API_H
#define I3_CLIENT_API_H

#include "trig_binheap.h"
#include "i3_client.h"
#include "../i3/i3_config.h"

/* context related functions; the client needs to create
 * a context before any other i3_* function invokation
 */
int cl_init1();
/* cl_init1() is equivalent to cl_init(NULL, 0, NULL) */
int cl_init(struct in_addr *ip_addr,
	     uint16_t local_port);
int cl_exit();

int cl_check_status();

/* ping servers */
int cl_get_rtt_server(uint32_t addr, uint64_t *rtt);
int cl_get_top_k_servers(int *k, uint32_t best_addr[],
	uint16_t best_port[], uint64_t best_rtt[]);
int cl_get_rtt_id(ID *id, uint64_t *rtt);
int cl_get_top_k_ids(int *k, ID best_id[], uint64_t best_rtt[]);

/* register a callback */		
int cl_register_callback(uint16_t cbk_type, void (*fun)(), void *data);
/* duplicate data: (1) create a buffer p of size len, (2) copy pdata
 * to p, and (3) return p
 */ 
void *cl_duplicate_data(void *pdata, unsigned int len);

/* constraints related functions */
void cl_generate_constraint_id(ID *id, Key *key, int type);
void cl_generate_l_constraint_key(Key *rkey, Key *lkey);
void cl_set_key_id(ID *id, Key *key);
void cl_l_constrain_path(ID *id, int path_len);
void cl_r_constrain_path(ID *id, int path_len);

/* setting IDs as public_IDs */
void cl_set_public_id(ID *id);
void cl_set_private_id(ID *id);

/* trigger related functions */
/* create different types pf triggres and insert the into infrastructure */
/* create a trigger pointing to default local address and port number 
 * on which cl_select listens 
 */
#define cl_insert_trigger(id, prefix_len) cl_insert_trigger_key(id, prefix_len, 0)
i3_trigger *cl_insert_trigger_key(ID *id, uint16_t prefix_len, Key *key);

/* create a trigger pointing to a given IP address and port number;
 * the IP address *should* be local */ 
#define cl_insert_trigger_addr(id, prefix_len, ip_addr, port) cl_insert_trigger_addr_key(id, prefix_len, ip_addr, port, 0)
i3_trigger *cl_insert_trigger_addr_key(ID *id, uint16_t prefix_len, 
			struct in_addr ip_addr, uint16_t port, Key *key);

/* create a trigger pointing to a stack */
i3_trigger *cl_create_trigger_stack(ID *id, uint16_t prefix_len, 
				    i3_stack *stack);
i3_trigger *cl_insert_trigger_stack(ID *id, uint16_t prefix_len, 
				    i3_stack *stack);

/* reinsert trigger in the infrastructure */
#define cl_insert_trigger_in_i3(t) cl_reinsert_trigger(t)
int cl_reinsert_trigger(i3_trigger *t);
int cl_reinsert_trigger_later(i3_trigger *t);
int cl_remove_trigger(i3_trigger *t);
int cl_remove_trigger_i3(i3_trigger *t);

/* register a a callback associate with a trigger */
int cl_register_trigger_callback(i3_trigger *t, uint16_t cbk_type, 
				 void (*fun)(), void *data);


/* create & free a cl_buf data structure used to send/receive packets */
cl_buf *cl_alloc_buf(unsigned int len);
void cl_free_buf(cl_buf *clb);

/* send packet functions */
int cl_send_to_id(ID *id, cl_buf *clb);
int cl_send_to_id_bwmeasure(ID *id, cl_buf *clb);
int cl_send_to_id_opts(ID *id, cl_buf *clb, uint8_t opts_mask, char is_total_len);
int cl_send_to_stack(i3_stack *s, cl_buf *clb);
int cl_send_to_stack_opts(i3_stack *s, cl_buf *clb, uint8_t opts_mask);
int cl_send_to_header(i3_header *hdr, cl_buf *clb);
int cl_send_to_header_opts(i3_header *hdr, cl_buf *clb, uint8_t opts_mask);

/* cl_select invokes cl_refresh_context periodically;
 * Note - you should invoke this even if you don't want to receive
 * any message! This is NOT intuitive. 
 */
int cl_select(int n, fd_set *readfds, fd_set *writefds, 
	      fd_set *exceptfds, struct timeval *cl_to);

/* helper function for edge i3 -- returns the address and port number of the i3 server being used
   by the client */

void cl_get_serv_addr(unsigned int *addr,ushort *port);

/* path operations -- not implemented in the new version yet */
cl_path *cl_setup_path(ID *path, uint16_t path_len, uint32_t tmask, int *rc);
int cl_reinsert_path(cl_path *clp);
int cl_remove_path(cl_path *clp);
int cl_register_path_callback(cl_path *clp, uint16_t cbk_type, 
			      void (*fun)(), void *data);

#define cl_register(id, prefix_len, fun, data) cl_register_key(id, prefix_len, fun, data, 0)
i3_trigger *cl_register_key(ID *id, uint16_t prefix_len,
			void (*fun)(), void *data, Key *key);
#define cl_reregister(t) cl_reinsert_trigger(t)
#define cl_unregister(t) cl_remove_trigger(t)

#define cl_path_send(id, clb) cl_send_to_id(id, clb)

#endif // I3_CLIENT_API_H
