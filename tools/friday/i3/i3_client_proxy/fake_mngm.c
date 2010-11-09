/***************************************************************************
                          fake_mngm.c  -  description
                             -------------------
    begin                : Son Jun 22 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "i3.h"
#include "i3_id.h"
#include "i3_misc.h"
#include "i3_addr.h"
#include "i3_trigger.h"
#include "i3_proxy.h"
#include "fake_mngm.h"
#include "fake_log.h"
#include "i3_client_api.h"
#include "i3_client.h"
#include "../i3/i3_config.h"

#include "dns_thread.h"

extern i3_addr     local_i3_addr;

#ifdef __CYGWIN__
extern char tun_dev_address[MAX_DNS_NAME_LEN];
#endif

 // Fake-IP-List is currently a linked list. will be changed to 
 // a hash table or something faster.

struct fake_addr  *fake_addr_list_start = NULL;
struct fake_addr  *fake_addr_list_end = NULL;

unsigned long     fakes;
extern char              fake_addr_range_start[MAX_CONFIG_PARM_LEN];

/***********************************/
/** Initializes fake lists        **/
/***********************************/


void init_fake_lists()
{
   fakes = inet_addr(fake_addr_range_start); 
}

uint32_t alloc_fake_IP()
{
  // TODO: replace this by an intelligent management of used fake-ips
  uint32_t ret = fakes;
  fakes = htonl(ntohl(fakes) +1);
  return ret;
}

void add_fake_addr(struct fake_addr  *fake)
{
  fake->next = fake_addr_list_start;
  fake->prev = NULL;

  if (fake->next)
    fake->next->prev = fake;
  else
    fake_addr_list_end = fake;

  fake_addr_list_start = fake;
}


struct fake_addr* alloc_fake_addr(char addr_type, ID *id)
// just alloc & initialize fake data structure
// IP address assignment will be done by alloc_fake_IP(),
// when the partner's private trigger is confirmed
{
  struct fake_addr   *fake;
  
  fake = (struct fake_addr *) malloc( sizeof(struct fake_addr) );
  if ( !fake )
  {
    panic("FATAL ERROR: memory allocation error in alloc_fake_addr\n");
    return NULL;
  }
  memset(fake, 0, sizeof(struct fake_addr));

  if (addr_type == I3_ADDR_TYPE_IPv4)
  {
#ifdef __CYGWIN__
    struct i3_addr i3_addr_tun;
    memcpy(&i3_addr_tun, &local_i3_addr, sizeof(i3_addr));
    i3_addr_tun.t.v4.addr.s_addr = ntohl(inet_addr(tun_dev_address));
    memcpy(&fake->real_addr, &i3_addr_tun, sizeof(i3_addr));
#else
    memcpy(&fake->real_addr, &local_i3_addr, sizeof(i3_addr));
#endif
    fake->fake_addr.type = I3_ADDR_TYPE_IPv4;
  }
  else
  {
    DEBUG(1, "\n Support for other than IPv4 is not implemented yet.\n");
    exit(-1);
  }
  fake->state = FAKE_STATE_NEW;
  time(&fake->last_use);
  
  if (id)
  {
    memcpy(&fake->prv_id, id, ID_LEN);
  }
  else
  {
    gen_private_ID(&fake->prv_id);
  }
      
  // TODO: Insert structure in a hash-table based on addr
  add_fake_addr(fake);

  generate_r_constraint(&fake->prv_id, &fake->prv_trig_key);
  if ((fake->prv_trig =
       cl_insert_trigger_key(&fake->prv_id, ID_LEN_BITS,
			     &fake->prv_trig_key)) == NULL)
  {
    DEBUG(1, "\n Error from cl_insert_trigger in inserting private trigger for fake-addr: ");
    if (1 <= I3_DEBUG_LEVEL) printf_id(&fake->prv_id, 0);
    return NULL;
  }

  return fake;
}

struct fake_addr *lookup_fake_addr(i3_addr *addr)
{
  struct fake_addr *list = fake_addr_list_start;
  time_t curtime;
  time(&curtime);
   

  while(list)
  {
#if !defined(CCURED) || defined(__CYGWIN__)
    if (((addr->type == I3_ADDR_TYPE_IPv4) && (list->fake_addr.t.v4.addr.s_addr == addr->t.v4.addr.s_addr)))
#else
     {
       int sameAddress = 0;
       if (addr->type == I3_ADDR_TYPE_IPv4)
         sameAddress =
           (list->fake_addr.t.v4.addr.s_addr == addr->t.v4.addr.s_addr);
       else if (addr->type == I3_ADDR_TYPE_IPv6) {
         struct in6_addr fake = list->fake_addr.t.v6.addr;
         struct in6_addr addr6 = addr->t.v6.addr;
         sameAddress = (memcmp(&fake, &addr6, sizeof(struct in6_addr)) == 0);
       }
       if (sameAddress)
#endif         
     {
         list->num_req++;
         return list;
      }
      else
      {
	list = list->next;
      }
   }
   return NULL;
}

void remove_fake_addr(fake_addr* fake)
{
  struct pkt_queue_entry *pkt, *pktnext;

  if (fake == fake_addr_list_start)
    fake_addr_list_start = fake->next;
  else
    fake->prev->next = fake->next;

  if (fake == fake_addr_list_end)
    fake_addr_list_end = fake->prev;
  else
    fake->next->prev = fake->prev;

  pkt = fake->output_queue;
  while (pkt != NULL)
    {
      pktnext = pkt->next;
      free(pkt->buf);
      free(pkt);
      pkt = pktnext;
    }

  free(fake);
}

void free_fake_addr(i3_addr *addr)
{
   struct fake_addr   *fake;

   fake = lookup_fake_addr(addr);
   {
      DEBUG(5, "\n No fake found in list for this IP address");
      return;
   }
   
   remove_fake_addr(fake);
}

void handle_proxy_trigger_request(ID *sender_private_id, ID* my_id)
{
  static cl_buf	    *clb = NULL;
  ID                prv_id;   
  struct id_list    *idl, *prv_idl;
  struct fake_addr  *fake;

  if (NULL == clb)
    clb = cl_alloc_buf(I3_PROXY_HDR_LEN);
  
  idl = lookup_id(my_id);
  if (idl == NULL)
  {
    DEBUG(5, "\n Can not find id_list-struct for id: ");
    if (5 <= I3_DEBUG_LEVEL) printf_id(my_id, 0);
    return;
  }   

  if (idl->type == ID_LIST_DNS)
  {
    prv_idl = lookup_dest_id(sender_private_id);
    if (prv_idl == NULL) { // sender unknown. new connection request
      DEBUG(15,"handling a new connection request\n");
      gen_private_ID(&prv_id);
      
      // alloc fake_addr structure, cl_insert_trigger
      fake = alloc_fake_addr(I3_ADDR_TYPE_IPv4, &prv_id);
      if (fake == NULL) {
	DEBUG(1, "\n Failed to allocate memory for fake_addr\n");
	return;
      }

      // alloc fake IP address
      fake->fake_addr.t.v4.addr.s_addr = alloc_fake_IP();
      memcpy(&fake->dest_id, sender_private_id, ID_LEN);
      fake->dest_stack.len = 1;
      fake->dest_stack.ids = &fake->dest_id;
      fake->state = FAKE_STATE_CNF;
      
      insert_id_in_id_list(&prv_id, ID_LIST_ADDR, fake);
    } else {
      // request from known sender
      DEBUG(11,"confirming a existing connection\n");
      if (prv_idl->s.addr->prv_trig == NULL)
	{ // my private trigger was temporarily removed.
	  // insert the trigger again
	  DEBUG(11,"re-insert private trigger\n");
	  fake = prv_idl->s.addr;
	  fake->state = FAKE_STATE_RECNF;
	  
	  if ((fake->prv_trig =
	       cl_insert_trigger_key(&fake->prv_id, ID_LEN_BITS,
				     &fake->prv_trig_key)) == NULL)
	    {
	      DEBUG(1, "\n Error from cl_insert_trigger in inserting private trigger for fake-addr: ");
	      if (1 <= I3_DEBUG_LEVEL) printf_id(&fake->prv_id, 0);
	      return;
	    }
	}
      else
	{ // trigger available. just send back confirmation.
	  DEBUG(15,"Sending private trigger confirmation at ");
	  if ( 15 <= I3_DEBUG_LEVEL)
	    printf_i3_id(sender_private_id,2);
	  
	  pack_trigger_cnf(clb,&(prv_idl->s.addr->prv_id));
	  cl_send_to_stack(&(prv_idl->s.addr->dest_stack), clb);
	}
    }
  }
  return;
}

void handle_proxy_trigger_confirmation(ID *sender_private_id, ID* arrival_id)
{
   struct id_list       *id_list;
   struct fake_addr     *fake;
   struct fake_dns_req  *fake_dns;

   id_list = lookup_id(arrival_id);
   if (id_list == NULL || id_list->type != ID_LIST_ADDR)
   {
      DEBUG(5, "\n Can not find id_list-struct for id or ID is not of type ID_LIST_ADDR: ");
      if (5 <= I3_DEBUG_LEVEL) printf_id(arrival_id, 0);
      return;
   }

   if (id_list->s.addr->state == FAKE_STATE_NEW) {
     // store private id of partner
     // set state to OK
     fake = id_list->s.addr;
     memcpy(&fake->dest_id, sender_private_id, ID_LEN);
     fake->dest_stack.len = 1;
     fake->dest_stack.ids = &fake->dest_id;

     id_list->s.addr->state = FAKE_STATE_OK;
     
     flush_pkt_queue(fake);

     fake->num_req++;
     
     if (id_list->s.addr->fake_dns_req &&
	 id_list->s.addr->fake_dns_req->answered == 0) {
       // allocate fake IP address
       fake->fake_addr.t.v4.addr.s_addr = alloc_fake_IP();
       
       fake_dns = id_list->s.addr->fake_dns_req;
       if (fake_dns && fake_dns->fake_addr) {
	 answer_dns_query(fake_dns->dns_packet, &fake_dns->fake_addr->fake_addr, fake_dns->dns_packet_len);
	 fake_dns->answered = 1;
       }
     }
     // log fake insertion to fake_log_file
     log_fake_insertion_mutex(fake);
   } else if (id_list->s.addr->state == FAKE_STATE_OK ||
	      id_list->s.addr->state == FAKE_STATE_RENEW) {
     id_list->s.addr->state = FAKE_STATE_OK;
     fake = id_list->s.addr;
     if (compare_ids(&fake->dest_id, sender_private_id) != 0) {
       // partner's private ID was changed
       remove_id_from_id_list(&fake->dest_id);
       memcpy(&fake->dest_id, sender_private_id, ID_LEN);
       fake->dest_stack.len = 1;
       fake->dest_stack.ids = &fake->dest_id;
       log_fake_changeID_mutex(fake);
     }
     fake->retry = 0;
     
     fake->num_req++;
     
     // answer DNS query
     if (fake->fake_dns_req != NULL) {
       fake_dns = fake->fake_dns_req;
       if (fake_dns->answered == 0) {
	 answer_dns_query(fake_dns->dns_packet, &fake_dns->fake_addr->fake_addr,
			  fake_dns->dns_packet_len);
	 fake_dns->answered = 1;
       }
     }

     flush_pkt_queue(fake);
	   
     return;
   } else {
     // unknown fake state 
     return;
   }
}
