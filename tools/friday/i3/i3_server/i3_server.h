#ifndef I3_SERVER_H
#define I3_SERVER_H

#include "i3_matching.h"
#include "i3_id_cache.h"
#include "i3_pushback.h"
#include "i3_monitor_state.h"

#define ACCEPT_TCP 0
#if ACCEPT_TCP
#include "tcp_state.h"
#endif

typedef struct srv_context {
  int fd; /* file descript used to send i3-to-i3 packets */
#if (ACCEPT_TCP)
  int tcp_fd; /* file descript used to send i3-to-i3 packets */
  TCPState *tcp_state;
#endif
  struct sockaddr_in local; /* local address at which the server
			     * receives i3 traffic 
			     */
  struct in_addr     local_ip_addr; /* local IP address; this field is
				     * needed because the IP address in 
				     * "local" data structure is set to
                                     * INADDR_ANY (host format)
				     */
  struct timeval  now; /* updated every time srv_refresh_context  
			* is invoked
			*/
  ptree_node **trigger_hash_table;
  srv_id_array *id_cache;
  srv_pback_entry pback_table[SRV_PBACK_TABLE_SIZE];
  MonitorInfoList mon_list;
} srv_context;  

int srv_is_pback_entry(srv_context *ctx, ID *id);
void srv_update_pback_table(srv_context *ctx, ID *id);

#endif // I3_SERVER_H
