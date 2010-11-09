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
#include <netdb.h>

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

#include "dns_thread.h"

#include "auth.h"

extern i3_addr     local_i3_addr;

 // Fake-IP-List is currently a linked list. will be changed to 
 // a hash table or something faster.

struct fake_addr  *fake_addr_list_start = NULL;
struct fake_addr  *fake_addr_list_end = NULL;

unsigned long     fakes;
extern char              fake_addr_range_start[MAX_CONFIG_PARM_LEN];
extern ID server_proxy_trigger;

extern int dnsfd;
extern struct sockaddr_in dns_server_addr;
struct dns_query *dns_query_list = NULL;
 
/***********************************/
/** Initializes fake lists        **/
/***********************************/


void init_fake_lists()
{
   fakes = inet_addr(fake_addr_range_start); 
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

struct fake_addr* alloc_fake_addr(char addr_type, ID *id,uint32_t srvaddr)
{
  struct fake_addr   *fake;

  /* XXX: just simply call alloc for now; preallocate a pool of buffers
     in the future */
  fake = (struct fake_addr *) malloc( sizeof(struct fake_addr) );
  if (fake)
  {
    memset(fake, 0, sizeof(struct fake_addr));

    // TODO: replace this by an intelligent management of used fake-ips
    if (addr_type == I3_ADDR_TYPE_IPv4)
    {
      // real_addr in host, fake_addr in network format
      memcpy(&fake->real_addr, &local_i3_addr, sizeof(i3_addr));
      fake->real_addr.t.v4.addr.s_addr = srvaddr;
      memcpy(&fake->fake_addr, &local_i3_addr, sizeof(i3_addr));
      fake->fake_addr.t.v4.addr.s_addr = fakes;
      fakes =  htonl(ntohl(fakes) +1);
    }
    else
    {
      DEBUG(1, "\n Support for other than IPv4 is not implemented yet.\n");
      exit(-1);
    }

    fake->state = FAKE_STATE_NEW;

    time(&fake->last_use);
      
    // TODO: Insert structure in a hash-table based on addr
    add_fake_addr(fake);
    
    if (id)
    {
      memcpy(&fake->prv_id, id, ID_LEN);
    }
    else
    {
      gen_private_ID(&fake->prv_id);
      DEBUG(1, "\n TODO: Choose random trigger.\n");

    }
    //init_i3_trigger(&fake->prv_trig, &fake->prv_id, ID_LEN_BITS, &local_i3_addr);

    DEBUG(20, "\n Inserting private trigger for fake-addr: ");
    if (20 <= I3_DEBUG_LEVEL) printf_i3_addr(&fake->fake_addr, 0);
    DEBUG(20, "\n   ID: "); if (20 <= I3_DEBUG_LEVEL) printf_id(&fake->prv_id, 0);

    generate_r_constraint(&fake->prv_id, &fake->prv_trig_key);
    fake->prv_trig = cl_insert_trigger_key(&fake->prv_id, ID_LEN_BITS,&fake->prv_trig_key);
    if (!fake->prv_trig)
    {
      DEBUG(1, "\n Error inserting private trigger for fake-addr: ");
      if (1 <= I3_DEBUG_LEVEL) printf_id(&fake->prv_id, 0);
      /*if (1 <= I3_DEBUG_LEVEL) printf_i3_addr(&fake->fake_addr, 0);*/ DEBUG(1, "\n");
      return NULL;
    }
  }
  else
  {
    DEBUG(1, "\nFATAL ERROR: memory allocation error in alloc_fake_ip()\n");
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
     
     if (((addr->type == I3_ADDR_TYPE_IPv4) && (list->fake_addr.t.v4.addr.s_addr == addr->t.v4.addr.s_addr))
         || ((addr->type == I3_ADDR_TYPE_IPv6) && (memcmp(list->fake_addr.t.v6.addr.s6_addr, addr->t.v6.addr.s6_addr, 128/8 )==0)))
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
  if (fake == fake_addr_list_start)
    fake_addr_list_start = fake->next;
  else
    fake->prev->next = fake->next;

  if (fake == fake_addr_list_end)
    fake_addr_list_end = fake->prev;
  else
    fake->next->prev = fake->prev;

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

void handle_public_trigger_request(char* buf, ID* dns_id)
{
  ID senderid;
  char *legacyurl=NULL;
  char *username=NULL,*nonce1=NULL;
  char nonce2[AUTH_KEY_LEN/8],nonce3[AUTH_KEY_LEN/8];
  char dns_query[MAX_DNS_NAME_LEN];
  static uint16_t transaction_id = 0;
  struct dns_query *query;

  memcpy(senderid.x,buf,ID_LEN);
  buf += ID_LEN;
  buf += unpack_variable_length(buf,&username,-1);
  buf += unpack_variable_length(buf,&nonce1,AUTH_KEY_LEN/8);
  int authres = user_login(&senderid,username,nonce1);
  DEBUG(11,"User: %s Authres: %d\n",username,authres);
  free(nonce1);
  free(username);
  
  if ( !authres )
    return;
  
  buf += unpack_variable_length(buf,&legacyurl,-1);
  strlwr(legacyurl);

  DEBUG(15,"Request for public trigger for %s at ",legacyurl);
  if (15 <= I3_DEBUG_LEVEL) print_time();

  //form DNS query
  transaction_id++;
  int msg_len = 0;
  msg_len = form_dns_query(dns_query, legacyurl, transaction_id);
  
  if (sendto(dnsfd, dns_query, msg_len, 0,
	     (struct sockaddr *) &dns_server_addr,
	     sizeof(struct sockaddr_in)) >= 0) { // sendto OK
    query = malloc(sizeof(struct dns_query));
    if (query == NULL) {
      DEBUG(1, "\nFATAL ERROR: memory allocation error in handle_public_trigger_request()\n");
      return;
    }
    time(&query->time);
    query->transaction_id = transaction_id;
    strcpy(query->name, legacyurl);
    query->client_id = duplicate_i3_id(&senderid);
    insert_dns_query(query);
  }
  free(legacyurl);
  return;
}

int form_dns_query(char *dns_query, char *dns_name, uint16_t transaction_id)
{
  int i, char_cnt;
  
  ((uint16_t *)dns_query)[0] = htons(transaction_id); //set transaction ID
  dns_query[2] = 0x01; dns_query[3] = 0x00; //Flags: 0x0100 (Standard query)
  dns_query[4] = 0x00; dns_query[5] = 0x01; //Questions: 1
  memset(dns_query + 6, 0, 6); //Answer RRs, Authority RRs, Additional RRs: 0
  //format Name
  char_cnt = 0;
  for (i = 0; i < strlen(dns_name); i++) {
    if (dns_name[i] == '.') {
      dns_query[12 + i - char_cnt] = char_cnt;
      memcpy(dns_query + 13 + i - char_cnt, dns_name + i - char_cnt, char_cnt);
      char_cnt = 0;
    } else if (i == strlen(dns_name) - 1) {
      dns_query[12 + i - char_cnt] = char_cnt + 1;
      memcpy(dns_query + 13 + i - char_cnt, dns_name + i - char_cnt, char_cnt + 1);
    } else {
      char_cnt++;
    }
  }
  dns_query[i + 13] = 0x00;
  dns_query[i + 14] = 0x00; dns_query[i + 15] = 0x01; // Type: Host address
  dns_query[i + 16] = 0x00; dns_query[i + 17] = 0x01; // Class: inet
  return i+18;
}

void handle_proxy_trigger_request(ID *sender_private_id, ID* dns_id)
{
  static cl_buf	    *clb = NULL;
  ID                dns_prv_id;   
  struct dns_query  *request;
  struct id_list    *idl;
  struct fake_addr  *fake;

  //printf("new private trigger request\n");

  if (NULL == clb)
    clb = cl_alloc_buf(I3_PROXY_HDR_LEN);

  idl = lookup_dest_id(sender_private_id);
  if (idl != NULL) {
    // request from known sender
    DEBUG(10, "confirming a existing connection\n");
    fake = idl->s.addr;
    if (idl->s.addr->prv_trig == NULL) {
      // my private trigger was temporarily removed.
      // insert the trigger again
      DEBUG(10, "re-insert private trigger\n");
      fake->state = FAKE_STATE_RECNF;

      if ((fake->prv_trig =
	   cl_insert_trigger_key(&fake->prv_id, ID_LEN_BITS,
				 &fake->prv_trig_key)) == NULL) {
	DEBUG(1, "\n Error from cl_insert_trigger in inserting private trigger for fake-addr: ");
	if (1 <= I3_DEBUG_LEVEL) printf_id(&fake->prv_id, 0);
      }
    } else {
      DEBUG(15,"Sending private trigger confirmation at ");
      if (15 <= I3_DEBUG_LEVEL) print_time();
      pack_trigger_cnf(clb,&(fake->prv_id));
      cl_send_to_stack(&(fake->dest_stack), clb);
    }
    return;
  }

  request = lookup_dns_query_by_client_id(sender_private_id);
  if (request == NULL)
  {
    DEBUG(5, "\n Can not find pending request for client-id: ");
    if (5 <= I3_DEBUG_LEVEL) printf_id(sender_private_id, 0);
    DEBUG(5, "\n TODO: Currently no action for this case !!!\n");
    return;
  }   

  gen_private_ID(&dns_prv_id);

  fake = alloc_fake_addr(I3_ADDR_TYPE_IPv4, &dns_prv_id, request->targetIP);
  remove_dns_query(request);
   
  insert_id_in_id_list(&dns_prv_id, ID_LIST_ADDR, fake);

  // dns_prv_id = points to server
  // sender_private_id = points to client

  memcpy(&fake->dest_id, sender_private_id, ID_LEN);

  fake->dest_stack.len = 1;
  fake->dest_stack.ids = &fake->dest_id;
  fake->state = FAKE_STATE_CNF;
}



void handle_proxy_trigger_confirmation(ID *sender_private_id, ID* arrival_id)
{

   struct id_list       *id_list, *snd_id;
   struct fake_addr     *fake;
   struct fake_dns_req  *fake_dns;

   
   snd_id = lookup_id(sender_private_id);
   if (snd_id)
   {
     //printf("\n We already have an i3-connection to this ID:"); printf_id(sender_private_id, 0);
     //printf("\n TODO: Currently no action for this case ! !\n");
   }

   id_list = lookup_id(arrival_id);
   if (id_list == NULL)
   {
      DEBUG(5, "\n Can not find id_list-struct for id: ");
      if (5 <= I3_DEBUG_LEVEL) printf_id(arrival_id, 0);
      DEBUG(5, "\n TODO: Currently no action for this case !!!\n");
      return;
   }

   if (id_list->type != ID_LIST_ADDR)
   {
      DEBUG(5, "\n ID is not of ID_LIST_ADDR: ");
      if (5 <= I3_DEBUG_LEVEL) printf_id(arrival_id, 0);
      DEBUG(5, "\n TODO: Currently no action for this case !!!\n");
      return;
   }


   // store private id of partner
   // set state to OK

   fake = id_list->s.addr;
   memcpy(&fake->dest_id, sender_private_id, ID_LEN);
   fake->dest_stack.len = 1;
   fake->dest_stack.ids = &fake->dest_id;

   
   id_list->s.addr->state = FAKE_STATE_OK;

   fake->num_req++;

   if (id_list->s.addr->fake_dns_req)
   {
      fake_dns = id_list->s.addr->fake_dns_req;
   
      if (fake_dns && fake_dns->fake_addr)
         answer_dns_query(fake_dns->dns_packet, &fake_dns->fake_addr->fake_addr, fake_dns->dns_packet_len);
   }
   else
   {
      DEBUG(1, "PROBLEM: No fake_dns-entry matched in handle_proxy_trigger_confirmation()");
   }
}

void insert_dns_query(struct dns_query *query) {
  query->next = dns_query_list;
  query->prev = NULL;
  if (dns_query_list != NULL) {
    dns_query_list->prev = query;
  }
  dns_query_list = query;
  return;
}
void remove_dns_query(struct dns_query *query) {
  if (query == dns_query_list) {
    dns_query_list = query->next;
    if (dns_query_list != NULL)
      dns_query_list->prev = NULL;
  } else {
    query->prev->next = query->next;
    if (query->next != NULL)
      query->next->prev = query->prev;
  }
  free(query->client_id);
  free(query);
  return;
}

struct dns_query *lookup_dns_query(uint16_t transaction_id) {
  struct dns_query *query, *tmp;
  query = dns_query_list;
  time_t curtime;
  time(&curtime);
  
  while (query) {
    if (query->transaction_id == transaction_id){
      return query;
    }
    if (curtime - query->time >= DNS_QUERY_TIMEOUT) {
      tmp = query->next;
      remove_dns_query(query);
      query = tmp;
    } else {
      query = query->next;
    }
  }

  return NULL;
}
  
struct dns_query *lookup_dns_query_by_client_id(ID *id) {
  struct dns_query *query, *tmp;
  query = dns_query_list;
  time_t curtime;
  time(&curtime);
  
  while (query) {
    if (memcmp(query->client_id, id, ID_LEN) == 0)
      return query;
    if (curtime - query->time >= DNS_QUERY_TIMEOUT) {
      tmp = query->next;
      remove_dns_query(query);
      query = tmp;
    } else {
      query = query->next;
    }
  }

  return NULL;
}
