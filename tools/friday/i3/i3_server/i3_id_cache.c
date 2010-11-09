/***************************************************************************
                         i3_id_cache.c  -  description
                             -------------------
    begin                : July 26 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include <stdlib.h>

#include "i3_id_cache.h"
#include "i3_fun.h"

/* basic operations to mainpulate srv_id_node entries */

srv_id_array *srv_alloc_id_array()
{
  srv_id_array *sia;

  if ((sia = (srv_id_array *)calloc(1, sizeof(srv_id_array))) == NULL)
    panic("srv_alloc_id_array(1): memory allocation error.\n");

  sia->size = SRV_ID_CACHE_SIZE;
  if ((sia->a = 
       (srv_id_entry *)calloc(sia->size, sizeof(srv_id_entry))) == NULL)
    panic("srv_alloc_id_array(2): memory allocation error.\n");
  return sia;
}

void srv_free_id_array(srv_id_array *sia)
{
  if (sia->size)
    free(sia->a);
  free(sia);
}


/* hash the id and return the corresponing entry; we assume
 * that all ids that hash to the same entry resides on the 
 * same i3 server with a high probability
 */
srv_id_entry *srv_get_id_entry(srv_id_array *sia, ID *id)
{
  int idx = SRV_ID_HASH(id, sia->size);

  return &sia->a[idx];
}
 

void srv_insert_id_entry(srv_id_array *sia, ID *id, 
			 i3_addr *addr, struct timeval *now)
{
  srv_id_entry *sie = srv_get_id_entry(sia, id);

  sie->addr = *addr;
  sie->last_ack = *now;
  sie->retries_cnt = 0;
  sie->id = *id;
  sie->valid = TRUE;
}
 
srv_id_entry *srv_get_valid_id_entry(srv_id_array *sia, ID *id, 
				     struct timeval *now)
{
  srv_id_entry *sie = srv_get_id_entry(sia, id);

  if (!sie->valid)
    return NULL;
  if (sie->retries_cnt >= SRV_ID_NUM_RETRIES ||
      (now->tv_sec - sie->last_ack.tv_sec > SRV_ID_TIMEOUT)) {
    sie->valid = FALSE;
    return NULL;
  }
  return sie;
}


int srv_time_to_refresh_id_entry(srv_id_entry *sie, struct timeval *now)
{
  if ((now->tv_sec - sie->last_ack.tv_sec >= 
       SRV_ID_TIMEOUT - SRV_ID_PING_TIMEOUT*SRV_ID_NUM_RETRIES) &&
      (now->tv_sec - sie->last_ping.tv_sec >= SRV_ID_PING_TIMEOUT)) 
    return TRUE;
  else
    return FALSE;
}


void printf_id_entry(srv_id_entry *sie) 
{
  printf("retries_cnt = %d\n", sie->retries_cnt);
  printf_i3_id(&sie->id, 2);
  printf("last_ack = %ld\n", sie->last_ack.tv_sec);
  printf_i3_addr(&sie->addr, 2);
  printf("valid = %d\n", sie->valid); 
}
