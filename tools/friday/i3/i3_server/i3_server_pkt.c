#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>   /* basic system data types */
#include <sys/socket.h>  /* basic socket definitions */
#include <arpa/inet.h>
#include <sys/time.h>    /* timeval{} for select() */
#include <errno.h>    
#include <sys/utsname.h>
#include <time.h>                /* timespec{} for pselect() */
#include <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "i3.h"
#include "i3_fun.h"
#include "i3_api.h"
#include "i3_server.h"

#if NEWS_INSTRUMENT
#include "i3_server_info.h"
#include "i3_news.h"
#include "i3_news_instrument.h"
#endif

#include "chord_api.h"
#include "../utils/utils.h"

#include "nat_table.h"
#include "i3_server_utils.h"

extern unsigned short srv_port;

#if ACCEPT_TCP
#include "i3_tcp_fns.h"
#endif

void send_packet_ipv4_wrapper(srv_context *ctx, char *pkt, int len, 
	    struct in_addr *dst_addr, uint16_t dst_port, int dst_fd)
{
#if (ACCEPT_TCP)
    int tcp_socket;
    lookup_tcp_state(ctx->tcp_state, dst_addr->s_addr, dst_port, &tcp_socket);
    if (tcp_socket != -1) {
      printf("Using TCP socket\n");
      send_tcp(pkt, len, tcp_socket);
    }
    else
#endif
      send_packet_ipv4(pkt, len, dst_addr, dst_port, dst_fd);
}	

void send_trigger_not_present(srv_context *ctx, ID *id, i3_addr *to, int sfd)
{
 #define MAX_PKT_SIZE 1024
  char pkt[MAX_PKT_SIZE];
  unsigned short len;
  i3_header *h;
  i3_option *o;
  i3_option_list *ol;
  ID *id1;

  ol = alloc_i3_option_list();
  o = alloc_i3_option();
  if ((id1 = (ID *)malloc(ID_LEN)) == NULL)
    panic("send_data_reply: memory allocation erro.\n");
  memcpy((char *)id1, (char *)id, ID_LEN);
  init_i3_option(o, I3_OPT_TRIGGER_NOT_PRESENT, (void *)id1);
  append_i3_option(ol, o);

  h = alloc_i3_header();
  init_i3_header(h, FALSE, NULL, ol);

  pack_i3_header(pkt, h, &len);

  /* send packet */
#ifndef CCURED  
  send_packet_ipv4_wrapper(ctx, pkt, len, &to->t.v4.addr, to->t.v4.port, sfd);
#else
  { // CCured does not want you to take the address of a union field
    struct in_addr dest = to->t.v4.addr;
    send_packet_ipv4_wrapper(ctx, pkt, len, &dest, to->t.v4.port, sfd);
    to->t.v4.addr = dest;
  }
#endif
  free_i3_header(h);
}

#ifndef __RTTI
#define __RTTI
#endif

void send_trigger_reply(srv_context *ctx, 
			void * __RTTI *tarray, char *opt_type_array, 
			int tnum, i3_addr *to, int sfd)
{
#define MAX_PKT_SIZE 1024
  char pkt[MAX_PKT_SIZE];
  unsigned short len;
  int        i;
  i3_header *h;
  i3_option *o;
  i3_option_list *ol;
  i3_trigger *t, *t1;
  i3_addr *a;
  static Key null_key;

  for (i = 0; i < tnum; i++) {
    switch(opt_type_array[i]) {
    case I3_OPT_TRIGGER_ACK:
    case I3_OPT_TRIGGER_CHALLENGE:
    case I3_OPT_CONSTRAINT_FAILED:
    case I3_OPT_ROUTE_BROKEN:
      t1 = (i3_trigger *)tarray[i];

      ol = alloc_i3_option_list();

      // update_nonce(t1); /* nonce computed before*/
      
      /* TODO : add stack if the packet has to be sent to an id */
      
      /* create option for I3_OPT_TRIGGER_CHALLENGE or I3_OPT_TRIGGER_ACK */
      o = alloc_i3_option();
      init_i3_option(o, opt_type_array[i], 
		     (void *)duplicate_i3_trigger(t1));
      append_i3_option(ol, o);

      /* add option for I3_OPT_CACHE_ADDR -- sent with every trigger
       * ack and trigger challenge. Use a trigger data structure to
       * send I3_OPT_CACHE_ADDR */
      o = alloc_i3_option();
      t = alloc_i3_trigger();
      a = alloc_i3_addr();
      init_i3_addr_ipv4(a, ctx->local_ip_addr, srv_port);
      init_i3_trigger(t, &(t1->id), 
		      MIN_PREFIX_LEN /* this doesn't matter here */, 
		      a, &t1->key);
      init_i3_option(o, I3_OPT_CACHE_ADDR, t);
      append_i3_option(ol, o);

      /* finish to create the header */
      h = alloc_i3_header();
      init_i3_header(h, FALSE, NULL, ol);
      pack_i3_header(pkt, h, &len);

      /* send packet */
      if (opt_type_array[i] == I3_OPT_TRIGGER_ACK)
	printf("Send back ack\n");
      else if (opt_type_array[i] == I3_OPT_TRIGGER_CHALLENGE)
	printf("Send back challenge\n");
      else if (opt_type_array[i] == I3_OPT_CONSTRAINT_FAILED)
	printf("Send back constraint failed\n");
      else
	printf("Send back route broken\n");
	
      // printf_i3_header(h, 2);
#ifndef CCURED      
      send_packet_ipv4_wrapper(ctx, pkt, len, &to->t.v4.addr, to->t.v4.port, sfd);
#else
      {
        struct in_addr dest = to->t.v4.addr;
        send_packet_ipv4_wrapper(ctx, pkt, len, &dest, to->t.v4.port, sfd);
        to->t.v4.addr = dest;
      }
#endif
      free_i3_header(h);
      break;
    case I3_OPT_CACHE_ADDR:
      ol = alloc_i3_option_list();
      o = alloc_i3_option();
      t = alloc_i3_trigger();
      a = alloc_i3_addr();
      init_i3_addr_ipv4(a, ctx->local_ip_addr, srv_port);
      init_i3_trigger(t, (ID *)tarray[i], MIN_PREFIX_LEN, a, &null_key);
      init_i3_option(o, I3_OPT_CACHE_ADDR, t);
      append_i3_option(ol, o);

      /* finish create the header */
      h = alloc_i3_header();
      init_i3_header(h, FALSE, NULL, ol);
      pack_i3_header(pkt, h, &len);

      /* send packet */
      printf("send back cache address\n");
      //printf_i3_header(h, 2);

#ifndef CCURED
      send_packet_ipv4_wrapper(ctx, pkt, len, &to->t.v4.addr, to->t.v4.port, sfd);
#else
      {
        struct in_addr tmp = to->t.v4.addr;
        send_packet_ipv4_wrapper(ctx, pkt, len, &tmp, to->t.v4.port, sfd);
        to->t.v4.addr = tmp;
      }
#endif      
      free_i3_header(h);
      break;

    default:
      panic("send_trigger_reply: unexpected option_type\n");
    }
  }
  
}

/***************************************************************************
 *
 * Purpose: Forward a packet to an IP address of an end-host
 *
 **************************************************************************/
void forward_packet_ip(srv_context *ctx, char *payload, int payload_len,
	i3_header *hdr, int header_room, i3_addr *to, int to_end_host)
{
    unsigned short	hdr_len, packet_len;
    char		*pkt_start;
    i3_header		*new_hdr;
    struct in_addr	ia;
    
    ia.s_addr = htonl(to->t.v4.addr.s_addr);
    //printf("Forwarding via IP to %s:%d\n", inet_ntoa(ia), to->t.v4.port);
    assert(to->type == I3_ADDR_TYPE_IPv4 || to->type == I3_ADDR_TYPE_IPv6);

    /* remove options and form a new header */
    new_hdr = alloc_i3_header();
    if (to_end_host)
	init_i3_header(new_hdr, 1, hdr->stack, 0);
    else
	init_i3_header(new_hdr, 1, hdr->stack, hdr->option_list);
    
    /* fill header of packet */
    hdr_len = get_i3_header_len(new_hdr);
    pkt_start = payload - hdr_len;
    packet_len = payload_len + hdr_len;
    pack_i3_header(pkt_start, new_hdr, &hdr_len);
    
    /* send */
    if (to->type == I3_ADDR_TYPE_IPv4) {
#ifndef CCURED      
      send_packet_ipv4_wrapper(ctx, pkt_start, packet_len, 
	      		&to->t.v4.addr, to->t.v4.port, ctx->fd);
#else
      {
        struct in_addr tmp = to->t.v4.addr;
        send_packet_ipv4_wrapper(ctx, pkt_start, packet_len, 
                                 &tmp, to->t.v4.port, ctx->fd);
        to->t.v4.addr = tmp;
      }
#endif      
    } else {
#ifndef CCURED      
      send_packet_ipv6(pkt_start, packet_len,
	      		&to->t.v6.addr, to->t.v6.port, ctx->fd);
#else
      {
        struct in6_addr tmp = to->t.v6.addr;
        send_packet_ipv6(pkt_start, packet_len,
                         &tmp, to->t.v6.port, ctx->fd);
        to->t.v6.addr = tmp;
      }
#endif
    }

    /* just free the header object, and not what is inside
     * those are freed when hdr is freed at the end of process_initial */
    free(new_hdr);
}



/**************************************************************************
 * Purpose: Forward an i3 packet along chord if no cache entries exist
 * 		to directly sent to the node responsible
 *************************************************************************/
void forward_packet_chord(i3_header *hdr, char *payload, int payload_len)
{
  uint16_t	hdr_len, packet_len;
  char 		*packet_start;
  chordID	key;

  hdr_len = get_i3_header_len(hdr);
  packet_start = payload - hdr_len;
  packet_len = payload_len + hdr_len;

  pack_i3_header(packet_start, hdr, &hdr_len);
  memmove(key.x, get_first_id(packet_start), CHORD_ID_BITS/8 * sizeof(char));
  
  chord_route(&key, packet_start, packet_len);
}


/***************************************************************************
 *
 * Purpose: Forward a packet to an I3 node
 *
 * Note: hdr->option_list might already contain some options now
 *
 **************************************************************************/
void forward_packet_i3(srv_context *ctx, char *payload, int payload_len,
    		i3_header *hdr, int header_room, trigger_node *t_node)
{
    ID			*id = hdr->stack->ids;
    srv_id_entry	*cache_entry;
    i3_option		*opt_sender;
    i3_addr		*to;
    struct in_addr	ia;

    /* check whether the id that the packet is
     * forwarded to has a valid cache entry */
    cache_entry = srv_get_valid_id_entry(ctx->id_cache, id, &ctx->now);

    /* add I3_OPT_SENDER anyway */
    opt_sender = create_i3_option_sender(ctx);
    append_i3_option(hdr->option_list, opt_sender);

    /* check if the node has died, and if so fwd by chord and send a
     * reply back to the person who inserted the trigger (oops!) */
    if (NULL != cache_entry) {
      i3_addr *temp = &(cache_entry->addr);
      if ((temp->type != I3_ADDR_TYPE_IPv4)) {
	printf("%x\n", temp->type);
	printf("process_packet_2: invalid address type.\n");
      } 
#if 0
      else if (monitor_is_dead(&(ctx->mon_list), 
	    temp->t.v4.addr.s_addr, temp->t.v4.port)) {
	char opt_type[1];
	void *t[1];
	// Commented out as not sure if this is needed
	opt_type[0] = I3_OPT_ROUTE_BROKEN;
	t[0] = t_node->trigger;
	/* Note: Trigger removed as well */
	send_trigger_reply(ctx, t, opt_type, 1, t_node->ret_a, ctx->fd);
	remove_trigger(ctx->trigger_hash_table, t_node->trigger);
	cache_entry = NULL;
      } 
#endif
      else {
	// printf("Link fine, forwarding\n");
      }
    }

    if (NULL == cache_entry) {
      i3_option *o_req_cache;
      ia.s_addr = htonl(ctx->local_ip_addr.s_addr);
	
      /* no entry in the cache for this "id" -- request to cache it */
      fprintf(stderr, "FI3: At %s:%d, no cache entry for id\n",
	      inet_ntoa(ia), ctx->local.sin_port);
      fprintf_i3_id(stderr, id, 0);

      o_req_cache = create_i3_option_req_cache();
      append_i3_option(hdr->option_list, o_req_cache);

      /* forward packet via underlying DHT */
      // printf("Forwarding via chord\n");
      forward_packet_chord(hdr, payload, payload_len);
    } else {
      if (srv_time_to_refresh_id_entry(cache_entry, &ctx->now)) {
        /* time to refresh cache entry */
        i3_option *o_req_cache = create_i3_option_req_cache();
        append_i3_option(hdr->option_list, o_req_cache);
        cache_entry->retries_cnt++;
        cache_entry->last_ping = ctx->now;
      } else {
        /* just add I3_SENDER_OPTION to receive eventual error messages
         * such as I3_TRIGGER_NOT_PRESENT (for now, do nothing here) */
      }

      /* send packet to i3 node addr via IP */
      to = &cache_entry->addr;
      if ((to->type != I3_ADDR_TYPE_IPv4) && (to->type != I3_ADDR_TYPE_IPv6)) {
        printf("%x\n", to->type);
        panic("process_packet_2: invalid address type.\n");
      }
      // printf("Cache entry available: forwarding via IP\n");
      forward_packet_ip(ctx, payload, payload_len,
			hdr, header_room, &cache_entry->addr, 0);
    }
}


/* NAT ADDITION */

char nat_translate(srv_context *ctx, char *pkt,
		   int plen, int header_room,
		   struct sockaddr_in* real_add)
{
  unsigned short lenp, leno;
  char *p;
  i3_option* option;
  i3_addr* real_addr;
  i3_addr* cur_addr;
  char natted = 0, insert = 0, remove = 0, data = 0, local = 0;
  ID* id;
 
  if ( !get_first_hop(pkt) )
    return 0;

  real_addr = alloc_i3_addr();
  init_i3_addr_ipv4(real_addr, real_add->sin_addr, real_add->sin_port);

  // it has some control packet - trigger insertion/removal
  // note: i3_opt_sender has to be of ipv4 for us to detect nat
  
  /* Identify whether the client is natted (by looking at the 
   * i3_opt_sender field and the address in udp header) 
   */

  id = (ID*)(get_hdr_stack(pkt));
  local = is_id_local(id, ctx);
  checkoptions(pkt, &natted, &insert, &remove, &data, real_addr);

  // no insert and removal allowed in one packet
  if (insert == 1 && remove == 1)
  {
    free_i3_addr(real_addr);
    return 0;
  }

  /* If client has not sent a trigger insertion packet, return */
  // trigger removal: we do not allow non-local triggers to be removed through us
  
  if ( !natted || (!insert && !data && !remove )  )
  {
    free_i3_addr(real_addr);
    return 0;
  }
  
  cur_addr = alloc_i3_addr();
  init_i3_addr_ipv4(cur_addr, ctx->local_ip_addr, ntohs(ctx->local.sin_port));

  p = get_hdr_options(pkt);
  lenp = ntohs(*(unsigned short *)p); /* get option list's length */
  lenp -= sizeof(unsigned short);     /* skip option list's length field */
  p += sizeof(unsigned short);

  while (lenp)
  {
    printf("case 1\n");
    
    option = unpack_i3_option(p, &leno);

    /* Rewrite i3_opt_sender to R's real addr (if the trigger is local) 
     * or G's addr (for non-local trigger). 
     */
    if  ( option->type == I3_OPT_SENDER )
    {
      if ( local || data) // if local / data to non-local-id so that "not id present" can be sent
	nat_translate_sender_ip_option(p,real_addr);
      else
	nat_translate_sender_ip_option(p,cur_addr);
    }

    /* For non_local trigger insertions */
    /* need to translate to real_addr */
    if ( option->type == I3_OPT_TRIGGER_INSERT && !local)
    {
      char* startnonce = p + 2 + sizeof(ID) + sizeof(unsigned short); // 2 = option type + flags
      int i;
      /* Nonce is set to zero (so that A sends a challenge through G) */
      for(i=0;i<NONCE_LEN;i++)
	*(startnonce++) = (char)0;
      printf("Inserted into nattable\n");
      /* Add state (trigger,R's real addr) to record the fact 
       * we are expecting A's challenge packet 
       */

      if ( option->entry.trigger->to->type == I3_ADDR_TYPE_IPv4)
      {
	nat_translate_sender_ip_option(p+2+sizeof(ID)+sizeof(uint16_t)+NONCE_LEN-1,real_addr);
	nat_table_insert(id,real_addr,option->entry.trigger->prefix_len,option->entry.trigger->to,ctx->now.tv_sec);
      }
      else
      {
	nat_table_insert(id,option->entry.trigger->to,option->entry.trigger->prefix_len,real_addr,ctx->now.tv_sec);
      }
      
    }

    p += leno;
    lenp -= leno;
    free_i3_option(option);
  }

  free_i3_addr(real_addr);
  free_i3_addr(cur_addr);
  return 1;
}

// 1 - if v handled it
// 0 - ow

/* NAT ADDITION */
/* relaying challenges for non-local ids */
int handle_challenge(srv_context* ctx, char* pkt, int len)
{
  unsigned short lenp, leno;
  char *p;
  i3_option* option;
  i3_addr* real_addr=NULL;

  p = get_hdr_options(pkt);
  lenp = ntohs(*(unsigned short *)p); /* get option list's length */
  lenp -= sizeof(unsigned short); /* skip option list's length field */
  p += sizeof(unsigned short);

  while (lenp)
  {
    printf("case 2\n");
    
    option = unpack_i3_option(p, &leno);

    if ( option->type == I3_OPT_TRIGGER_CHALLENGE && real_addr == NULL)
    {
      nat_table_retrieve(&(option->entry.trigger->id),
	      option->entry.trigger->to,
	      option->entry.trigger->prefix_len,
	      &real_addr,ctx->now.tv_sec);
      
      if (option->entry.trigger->to->type == I3_ADDR_TYPE_IPv4 && real_addr != NULL)
      {
	nat_translate_sender_ip_option(
		p + 2 + sizeof(ID) + sizeof(uint16_t) + NONCE_LEN - 1,real_addr);
	real_addr = duplicate_i3_addr(option->entry.trigger->to);
      }
       
      /* remove state */
      nat_table_remove(&(option->entry.trigger->id),
	      option->entry.trigger->to,
	      option->entry.trigger->prefix_len);

      if ( real_addr == NULL)
	return 0;
    }

    if ( option->type == I3_OPT_CACHE_ADDR && real_addr != NULL)
    {
      /*  change option i3_opt_cache_addr to i3_opt_force_cache_addr 
       *  making it compulsory for the client to cache A's ip address. */
      p[0] = ((char) I3_OPT_FORCE_CACHE_ADDR);
    }
 
    p += leno;
    lenp -= leno;
    free_i3_option(option);
  }

  if ( real_addr != NULL)
  {
    /*     printf("Sending len %d to \n",len); */
    /*     printf_i3_addr(real_addr,2); */
    free_i3_addr(real_addr);
    /* forward to R using its real addr */
#ifndef CCURED    
    send_packet_ipv4_wrapper(ctx, pkt, len, &(real_addr->t.v4.addr), real_addr->t.v4.port,ctx->fd);
#else
    {
      struct in_addr tmp = real_addr->t.v4.addr;
      send_packet_ipv4_wrapper(ctx, pkt, len, &tmp, real_addr->t.v4.port,ctx->fd);
      real_addr->t.v4.addr = tmp;
    }
#endif    
    return 1;
  }

  
  return 0;
}





