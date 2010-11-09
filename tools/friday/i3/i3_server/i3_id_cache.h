#ifndef I3_ID_CACHE_H
#define I3_ID_CACHE_H

#include "i3.h"

typedef struct srv_id_entry {
  ID      id;
  i3_addr addr; /* address of i3 server where packets with 
		 * identifier "id" are sent
		 */
  int     valid;
#define SRV_ID_TIMEOUT      20 /* in secodns */    
#define SRV_ID_PING_TIMEOUT 1  /* in seconds */
#define SRV_ID_NUM_RETRIES  3
  struct timeval last_ping; /* time when this id was pinged for the
			     * last time.
			     * Pings are piggybacked in data packets sent
			     * to ids with the same prefix; there are no 
			     * special ping messages.
			     */
  struct timeval last_ack; /* time when the latest ack from a ping 
			    * to this id prefix was received. 
			    * The entry is removed if nothing was 
			    * heard from this prefix for SRV_ID_NODE_TIMEOUT 
			    * seconds or SRV_ID_NODE_NUM_RETRIES consecutive
			    * pings were not answered
			    */
  int            retries_cnt; /* number of consecutive pings un-acked so far */
  int            avg_rtt; /* average RTT to the i3 server responsible for 
			   * this prefix; computed by using exponential 
			   * averaging: avg_rtt = avg_rtt*\alpha + 
			   * measured_rtt*(1 - \alpha) 
			   */
#define SRV_ID_NODE_IAPLHA  2 /* this corresponds to 
			       * \alpha = 1/2^SRV_ID_NODE_IALPHA
			       */
} srv_id_entry;


#define SRV_ID_CACHE_SIZE 32768

typedef struct srv_id_array {
  int size;
  srv_id_entry *a;
} srv_id_array;


/* xxx: use only the first 32 bits from id to hash ... for now 
 * assume the size of the cache is no larger than 2^16
 */
#define SRV_ID_HASH(id, size)  ((*(unsigned short *)&id->x[0] + \
     *(unsigned short *)&id->x[sizeof(short)]) % size)

srv_id_array *srv_alloc_id_array();
void srv_insert_id_entry(srv_id_array *sia, ID *id, 
			 i3_addr *addr, struct timeval *now);
srv_id_entry *srv_get_valid_id_entry(srv_id_array *sia, ID *id, 
				     struct timeval *now);
int srv_time_to_refresh_id_entry(srv_id_entry *sie, struct timeval *now);
void printf_id_entry(srv_id_entry *sie);

#endif // I3_ID_CACHE_H
