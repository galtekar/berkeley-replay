/***************************************************************************
                          dns_thread.c  -  description
                             -------------------
    begin                : Die Jan 14 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#ifdef __CYGWIN__
#include <w32api/windows.h>
#include <w32api/iphlpapi.h>
#elif !defined(__APPLE__)
#include <error.h>
#endif
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include "debug.h"
#include "i3.h"
#include "i3_id.h"
#include "i3_addr.h"
#include "i3_trigger.h"
#include "i3_header.h"
#include "i3_proxy.h"
#include "dns_thread.h"
#include "fake_mngm.h"
#include "fake_log.h"
#include "i3_client_api.h"
#include "i3_client.h"
#include "addrbook.h"
#include "auth.h"

#ifdef __CYGWIN__
extern int     dnsfd, addrlen;
extern HANDLE  tunfd;
extern int     readsp[2];
#else
extern int     tunfd, dnsfd, addrlen;
#endif
extern struct  sockaddr_in	saddr, daddr;

struct real_dns_req *dns_req_list_start = NULL, *dns_req_list_end = NULL;

extern i3_addr     local_i3_addr;

extern char  pub_dns_fname[MAX_DNS_NAME_LEN];
extern char  fake_dns_fname[MAX_DNS_NAME_LEN];
extern char  id_list_fname[MAX_DNS_NAME_LEN];
extern unsigned short enable_hashed_urls;

extern unsigned short   max_dns_retry;
extern unsigned short   stale_timeout;

// Fake-DNS-List is currently a linked list. will be changed to hash or something faster...

struct fake_dns_req   *fake_dns_list_start = NULL;
struct fake_dns_req   *fake_dns_list_end = NULL;

struct pub_i3_dns     *pub_i3_dns_list_start = NULL;
struct pub_i3_dns     *pub_i3_dns_list_end = NULL;

extern char fake_log_fname[MAX_DNS_NAME_LEN];
extern pthread_mutex_t mutexlog;
extern char* myusername;

void print_time()
{
  struct timeval t;
  gettimeofday(&t, NULL);
  DEBUG(11,"Sec: %ld Microsec: %ld\n",t.tv_sec,t.tv_usec);
}

void eprint_time()
{
  struct timeval t;
  gettimeofday(&t, NULL);
  fprintf(stderr,"Sec: %ld Microsec: %ld\n",t.tv_sec,t.tv_usec);
}

void print_packet(char* pkt,int size)
{
  int i;

  return;

  printf("Pkt Size: %d\n",size);

  if ( size <= 40)
    return;

  printf("******************\n");
  for(i=40;i<size;i++)
    printf("%c",pkt[i]);
  printf("\n******************\n");
}

// Sets server_proxy_trigger = public trigger to contact _some_ server proxy
// Using anycast
// First DEFAULT_SERVER_PROXY_TRIGGER_LEN set to the anycast address
// remaining bits chosen randomly

void random_server_proxy_trigger(ID* server_proxy_trigger)
{
  ID myid;
  int i;

  get_random_ID(&myid);

  for(i=DEFAULT_SERVER_PROXY_TRIGGER_LEN;i<ID_LEN;i++)
    server_proxy_trigger->x[i] = myid.x[i];

  set_public_id(server_proxy_trigger);
}
  
// Extracts domain name in dns query
// And stores in dns_quest

void parse_dns_query_name(char *dns_quest, char *dns_quest_str)
{
  char 	cnt = dns_quest[0];
  uint  len = 0;

  while(cnt)
  {
    strncpy(dns_quest_str + len, &dns_quest[len +1], cnt);
    len += cnt;
    dns_quest_str[len] = '.'; len++;
    cnt = dns_quest[len];
  }
  dns_quest_str[len -1] = 0x00;
}


// Used for calculating the checksum of ip-headers

unsigned short in_cksum(unsigned short *addr, int len)
{
  register int nleft = len;
  register unsigned short *w = addr;
  register int sum = 0;
  unsigned short answer = 0;

  while (nleft > 1)
  {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1)
  {
    *(u_char *)(&answer) = *(u_char *)w;
    sum += answer;
  }
   
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return(answer);
}


// Answers a previously grabbed DNS-request and sends
// the answer back via the tun-device

void answer_dns_query(char *dns_request, i3_addr *addr, unsigned int len)
{
  char 		buf[BUF_LEN];
  uint16_t	chksum;

  if (addr != NULL && addr->type != I3_ADDR_TYPE_IPv4)
  {
    DEBUG(1, "\n Currently, only IPv4 is supported");
    exit(-1);
  }
   
  memcpy(buf, dns_request, len);

  // change ip addresses
  memcpy(buf + 12, dns_request + 16, 4);
  memcpy(buf + 16, dns_request + 12, 4);

  // Exchange UDP port numbers
  memcpy(buf + 20, dns_request + 22, 2);
  memcpy(buf + 22, dns_request + 20, 2);
  memset(buf + 26, 0, 2);

  // Set the fields of the DNS answer
  buf[30] = buf[30] | 0x84;
  buf[34] = 0x00;
  memset(buf + 36, 0, 4);

  if (addr != NULL) { // answer IP address
    // IP total length += 16
    buf[3] += 16;
    // update IP header checksum
    chksum = ntohs(((uint16_t *) buf)[5]);
    chksum -= 0x10;
    ((uint16_t *) buf)[5] = htons(chksum);

    buf[25] += 16; // UDP length += 16

    buf[31] = 0x80; // NO_ERROR
    buf[35] = 0x01; // Answer RRs: 1

    buf[len + 0] = 0xc0;
    buf[len + 1] = 0x0c;
    buf[len + 2] = 0x00;
    buf[len + 3] = 0x01;
    buf[len + 4] = 0x00;
    buf[len + 5] = 0x01;
    buf[len + 6] = 0x00; // TTL
    buf[len + 7] = 0x00; // TTL
    buf[len + 8] = 0x00; // TTL
    buf[len + 9] = 0x00; // TTL
    buf[len + 10] = 0x00; // data length
    buf[len + 11] = 0x04; // data length
    // At last, put in the fake address, that represents the DNS answer
#ifndef CCURED    
    memcpy(buf + len + 12, &addr->t.v4.addr.s_addr, sizeof(unsigned long));
#else
    * (in_addr_t *)(buf + len + 12) = addr->t.v4.addr.s_addr;
#endif    
  } else {
    // return "DNS_NAME_ERROR(No such name)"
    buf[31] = 0x83; // NAME_ERROR
    buf[35] = 0x00; // Answer RRs: 0
  }

  // Send fake answer via tun-dev to legacy application
#ifdef __CYGWIN__
  write_to_tun(tunfd, buf, len + 16);
#else
  write(tunfd, buf, len + 16);
#endif
}


// Put a struct for each submitted dns request in a queue and wait for the answer

void push_dns_request_in_queue(char *buf)
{
  struct real_dns_req    *dns_req;
   
  /* XXX: just simply call alloc for now; preallocate a pool of buffers
     in the future */
  dns_req = (struct real_dns_req *)malloc(sizeof(struct real_dns_req));
  if (dns_req)
  {
    memset(dns_req, 0, sizeof(struct real_dns_req));

    // TODO: Make sure that this packet has no options, etc.
    // size must be 28 bytes
    memcpy(dns_req->packet_data, buf, 20 + 8);
    dns_req->id = (buf[28] << 8) + buf[29];
      
    dns_req->next = dns_req_list_start;
    dns_req->prev = NULL;

    if (dns_req->next)
      dns_req->next->prev = dns_req;
    else
      dns_req_list_end = dns_req;
    dns_req_list_start = dns_req;
  }
  else
  {
    DEBUG(1, "\nCould not allocate dns_req-struct\n");
    exit(-1);
  }
}


// removes a previously submitted dns-request from the queue

void remove_dns_request_from_queue(struct real_dns_req *dns_req)
{
  if (dns_req == dns_req_list_start)
    dns_req_list_start = dns_req->next;
  else
    dns_req->prev->next = dns_req->next;
   
  if (dns_req == dns_req_list_end)
    dns_req_list_end = dns_req->prev;
  else
    dns_req->next->prev = dns_req->prev;

  free(dns_req);
}

// search a certain dns-request in the list of pending dns-requests
int get_dns_request_from_queue(char *buf, unsigned short  udplen)
{
  unsigned short       key;
  struct real_dns_req  *dns_req;


  key = (buf[28] << 8) + buf[29];

  dns_req = dns_req_list_end;   

  while(dns_req)
  {
    if (dns_req->id == key)
    {
      memcpy(buf, dns_req->packet_data, 20 + 6);

      // change ip addresses
      memcpy(buf + 12, dns_req->packet_data + 16, 4);
      memcpy(buf + 16, dns_req->packet_data + 12, 4);

      ((uint16_t *) buf)[1] = htons(udplen + 28);
      ((uint16_t *) buf)[5] = 0;
      ((uint16_t *) buf)[5] = in_cksum((uint16_t *) buf, 20);
       
      memcpy(buf + 20, dns_req->packet_data + 22, 2);
      memcpy(buf + 22, dns_req->packet_data + 20, 2);
      ((uint16_t *) buf)[12] = htons(udplen + 8);
      memset(buf + 26, 0, 2);
      remove_dns_request_from_queue(dns_req);
      return 1;
    }
    else
    {
      dns_req = dns_req->prev;      
    }
  }

  DEBUG(1, "\n Key not found in list of pending DNS requests.\n");

  return 0;
}


// prints the status of all active fake dns-names into stream 'handle'

void  printf_fake_dns_status(FILE *handle)
{
  struct fake_dns_req  *fake_dns;
  int                  i = 0;
  time_t             now;

  time(&now);

  fprintf(handle, "\n Status of the currently fake DNS-names managed by i3-proxy:");
  fprintf(handle, "\n=============================================================\n");
  fprintf(handle, "\n logged at: %s", ctime(&now));
  fprintf(handle, "\n");

  fake_dns = fake_dns_list_start;
  while(fake_dns)
  {
    fprintf(handle, "\n Entry %02u: ", i);
    if (fake_dns->fake_addr)
    {
#ifndef __CYGWIN__
      uint j;
#endif
      if (fake_dns->fake_addr->state == FAKE_STATE_OK)
      {
	fprintf(handle, ", Status: FAKE_STATE_OK");
      }
      if (fake_dns->fake_addr->state == FAKE_STATE_CNF)
      {
	fprintf(handle, ", Status: FAKE_STATE_CNF");
      }
      if (fake_dns->fake_addr->state == FAKE_STATE_RECNF)
      {
	fprintf(handle, ", Status: FAKE_STATE_RECNF");
      }
      else if (fake_dns->fake_addr->state == FAKE_STATE_NEW)
      {
	fprintf(handle, ", Status: FAKE_STATE_NEW");
      }
      else if (fake_dns->fake_addr->state == FAKE_STATE_RENEW)
      {
	fprintf(handle, ", Status: FAKE_STATE_RENEW");
      }
      else if (fake_dns->fake_addr->state == FAKE_STATE_PARTNER_DORMANT)
      {
	fprintf(handle, ", Status: FAKE_STATE_PARTNER_DORMANT");
      }

      fprintf(handle, ", Address: ");
         
      if (fake_dns->fake_addr->fake_addr.type == I3_ADDR_TYPE_IPv4)
      {
	fprintf(handle, "%s", inet_ntoa( fake_dns->fake_addr->fake_addr.t.v4.addr ));
      }
#ifndef __CYGWIN__
      else if (fake_dns->fake_addr->fake_addr.type == I3_ADDR_TYPE_IPv6)
      {
	for (j = 0; j < sizeof(struct in6_addr); j++)
	  fprintf(handle, "%02x:", fake_dns->fake_addr->fake_addr.t.v6.addr.s6_addr[j]);
      }
#endif
      else
	fprintf(handle, "(unknown address type: %d)", fake_dns->fake_addr->fake_addr.type);
    }
    else
      fprintf(handle, "(not yet assigned)");

    fprintf(handle, ", last use: %s", ctime(&fake_dns->fake_addr->last_use));
         
    fprintf(handle, "\n           DNS: %s, Requests: %lu\n", fake_dns->dns_name, fake_dns->num_req);


    fake_dns = fake_dns->next;
  }

  fprintf(handle, "\n");
}

// search fake_dns_req-struct with URL=dns_name in hash-table

struct fake_dns_req   *lookup_fake_dns(char *dns_name)
{
  struct fake_dns_req  *list = fake_dns_list_start;

  strlwr(dns_name);
   
  while(list)
  {
    DEBUG(15,"DNS List: %s, Asked: %s\n",list->dns_name,dns_name);
    
    if (strcmp(list->dns_name, dns_name) == 0)
    {
      i3_addr* copyaddr = duplicate_i3_addr(&(list->fake_addr->fake_addr));
      
      // we have timed out
      if ( lookup_fake_addr(copyaddr) == NULL )
      {
	DEBUG(15,"Timed out\n");
	free_i3_addr(copyaddr);
	return NULL;
      }
      free_i3_addr(copyaddr);
      
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

struct fake_dns_req   *lookup_fake_dns_by_ID(ID *id)
{
  struct fake_dns_req  *list = fake_dns_list_start;

  while(list) {
    if (compare_ids(&list->dns_id, id) == 0)
      return list;

    list = list->next;
  }
  return NULL;
}

void remove_fake_dns(struct fake_dns_req* fake)
{
  if (fake == fake_dns_list_start)
    fake_dns_list_start = fake->next;
  else
    fake->prev->next = fake->next;

  if (fake == fake_dns_list_end)
    fake_dns_list_end = fake->prev;
  else
    fake->next->prev = fake->prev;

  free(fake);
}

void add_dns(struct pub_i3_dns  *dns)
{
  dns->next = pub_i3_dns_list_start;
  dns->prev = NULL;

  if (dns->next)
    dns->next->prev = dns;
  else
    pub_i3_dns_list_end = dns;

  pub_i3_dns_list_start = dns;
}

void add_fake_dns(struct fake_dns_req  *fake_dns)
{
  // insert fake_dns-request in i3_dns-hash-table
  fake_dns->next = fake_dns_list_start;
  fake_dns->prev = NULL;

  if (fake_dns->next)
    fake_dns->next->prev = fake_dns;
  else
    fake_dns_list_end = fake_dns;

  fake_dns_list_start = fake_dns;
}

void new_pub_dns(char *dns_str_full)
{
  struct pub_i3_dns    *dns;
  char *dns_str,*dns_key;
  char* find;
  Key key;

  dns_str = strtok_r(dns_str_full," ",&find);
  dns_key = strtok_r(NULL," ",&find);

  if ( dns_key == NULL )
  {
    DEBUG(1,"DNS key not present for %s\n",dns_str);
    return;
  }

//   printf("DNS String: %s\n DNS Key: ",dns_str); 
   convert_str_to_hex_key(dns_key,&key); 
//   printf_i3_key(key.x,2); 

  /* XXX: just simply call alloc for now; preallocate a pool of buffers
     in the future */
  dns = (struct pub_i3_dns *) malloc( sizeof(struct pub_i3_dns) );
  
  if (dns)
  {
    memset(dns, 0, sizeof(struct pub_i3_dns));
    strncpy(dns->dns_name, dns_str, MAX_DNS_NAME_LEN);
    strlwr(dns->dns_name);
    {
      ID* lid = lookup_addrbook(dns->dns_name);
      if ( lid != NULL)
      {
	init_i3_id(&dns->dns_id, lid);
	free_i3_id(lid);
      }
      else if ( enable_hashed_urls )
      {
	hash_URL_on_ID(dns->dns_name, &dns->dns_id);
      }
      else
      {
	DEBUG(1,"Public trigger for inserting %s not specified in address book\n",dns->dns_name);
	free(dns);
	return;
      }
	
    }

    if ( 15 <= I3_DEBUG_LEVEL)
      printf_i3_id(&dns->dns_id,2);

    /* ensure that the ID is public_id */
    if (get_id_type(&(dns->dns_id)) != I3_ID_TYPE_PUBLIC) {
	weprintf("Attempting to insert public trigger that does not have public_id bit set\n");
    }
    
    cl_insert_trigger_addr_key(&dns->dns_id, ID_LEN_BITS,
	    local_i3_addr.t.v4.addr, local_i3_addr.t.v4.port, &key);

    add_dns(dns);
    insert_id_in_id_list(&dns->dns_id, ID_LIST_DNS, dns);      
  }
  else
  {
    DEBUG(1, "\n FATAL ERROR: memory allocation error in new_pub_dns()\n");
    return;
  }
}



struct pub_i3_dns *lookup_pub_i3_dns(char *dns_str)
{
  struct pub_i3_dns *list = pub_i3_dns_list_start;

  while(list)
  {
    if (strcmp(list->dns_name, dns_str) == 0)
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



void remove_pub_dns(char *dns_str)
{
  struct pub_i3_dns   *list;


  list = lookup_pub_i3_dns(dns_str);
  {
    DEBUG(5, "\n DNS-String '%s' not found in pub_i3_dns-list.\n", dns_str);
    return;
  }

  if (list == pub_i3_dns_list_start)
    pub_i3_dns_list_start = list->next;
  else
    list->prev->next = list->next;

  if (list == pub_i3_dns_list_end)
    pub_i3_dns_list_end = list->prev;
  else
    list->next->prev = list->prev;

  free(list);
}


void  printf_pub_dns_status(FILE *handle)
{
  struct pub_i3_dns  *pub_dns;
  int                i = 0;
  uint               j;
  time_t             now;

  time(&now);
   
  fprintf(handle, "\n Status of the public DNS-names managed by i3-proxy:");
  fprintf(handle, "\n=====================================================\n");
  fprintf(handle, "\n logged at: %s", ctime(&now));
  fprintf(handle, "\n");
         
  pub_dns = pub_i3_dns_list_start;

  while(pub_dns)
  {
    fprintf(handle, "\n Entry %02u: URL: %s, Requests: %lu, ID: ", i, pub_dns->dns_name, pub_dns->num_req);

    for (j = 0; j < ID_LEN; j++)
      fprintf(handle, "%02X", pub_dns->dns_id.x[j]);

    fprintf(handle, ", Requests: %lu \n", pub_dns->num_req);
    i++;

    pub_dns = pub_dns->next;
  }

  fprintf(handle, "\n");
}

// Packing Functions
// clb is already allocated for

// Packing strings: should terminate in zero, if len=-1

int pack_variable_length(char *buf,char* str,int len)
{
  uint16_t slen;

  if ( len == -1)
  {
    slen = htons(strlen(str));
    memcpy(buf,(char*)(&slen),sizeof(uint16_t));
    buf += sizeof(uint16_t);
    slen = ntohs(slen); 
  }
  else
    slen = len;

  memcpy(buf,str,slen);
  return ((len==-1)?sizeof(uint16_t):0) + slen;
}

// Caller has to deallocate if variable length
int unpack_variable_length(char* buf,char** varstr,int len)
{
  uint16_t slen;
  
  if ( len == -1)
  {
    memcpy(&slen,buf,sizeof(slen));
    slen = ntohs(slen);
    buf += sizeof(uint16_t);
  }
  else
    slen = len;

  if ( *varstr == NULL && len == -1)
    *varstr = malloc(slen+1);

  if ( *varstr == NULL && len != -1)
    *varstr = malloc(slen);

  memcpy(*varstr,buf,slen);

  if ( len == -1)
    (*varstr)[slen]=0;
  
  return ((len==-1)?sizeof(uint16_t):0) + slen;
}

void pack_trigger_removal(cl_buf* clb,ID* id)
{
  clb->data[0] = I3_PROXY_VERSION;
  clb->data[1] = I3_PROXY_PRIVATE_TRIG_REMOVE;
  memcpy(clb->data + 2,id, ID_LEN);
  clb->data_len = clb->max_len = I3_PROXY_HDR_LEN;
}

void pack_fake_removal(cl_buf* clb,ID* id)
{
  clb->data[0] = I3_PROXY_VERSION;
  clb->data[1] = I3_PROXY_FAKE_REMOVE;
  memcpy(clb->data + 2,id, ID_LEN);
  clb->data_len = clb->max_len = I3_PROXY_HDR_LEN;
}

void pack_trigger_req(cl_buf *clb, ID* id)
{
  clb->data[0] = I3_PROXY_VERSION;
  clb->data[1] = I3_PROXY_PRIVATE_TRIG_REQ;
  memcpy(clb->data + 2,id, ID_LEN);
  clb->data_len = clb->max_len = I3_PROXY_HDR_LEN;
}

int pack_public_trigger_req(cl_buf* clb,struct fake_addr  *fake)
{
  char* buf = clb->data;
  buf[0] = I3_PROXY_VERSION;
  buf[1] = I3_PROXY_PUBLIC_TRIG_REQ;
  buf += 2;

  memcpy(buf,(fake->prv_id).x,ID_LEN);
  buf += ID_LEN;
  buf += pack_variable_length(buf,myusername,-1);

  char* server_name = match_rules_spname(fake->fake_dns_req->dns_name);
  if ( !server_login(server_name,&(fake->prv_id),buf) )
  {
    free(server_name);
    return 0;
  }
    
  free(server_name);
  buf += AUTH_KEY_LEN / 8;
  
  buf += pack_variable_length(buf,fake->fake_dns_req->dns_name,-1);
  clb->data_len = clb->max_len = (buf - clb->data) / sizeof(char);
  return 1;
}

void pack_auth_trigger_req(cl_buf *clb, ID* id,char* nonce)
{
  char *buf = clb->data;
  buf[0] = I3_PROXY_VERSION;
  buf[1] = I3_PROXY_AUTH_PRIVATE_TRIG_REQ;
  buf += 2;
  memcpy(buf,id->x,ID_LEN);
  buf += ID_LEN;
  buf += pack_variable_length(buf,(char*)nonce,AUTH_KEY_LEN/8);
  clb->data_len = clb->max_len = 2 + ID_LEN + AUTH_KEY_LEN/8;
}

void pack_trigger_cnf(cl_buf* clb,ID  *id)
{
  clb->data[0] = I3_PROXY_VERSION;
  memcpy(clb->data + 2,id,ID_LEN);
  clb->data_len = clb->max_len = I3_PROXY_HDR_LEN;
  clb->data[1] = I3_PROXY_PRIVATE_TRIG_CNF;
}

// f has gone stale

void private_trigger_timeout(fake_addr* f)
{
  /*
  // Send trigger removal message to the other end
  cl_buf* clb = cl_alloc_buf(I3_PROXY_HDR_LEN);
  pack_trigger_removal(clb,&(f->prv_id));
  cl_send_to_stack(&f->dest_stack, clb);
  */

  // Clear up local state
  if ( f->fake_dns_req != NULL && f->fake_dns_req->dns_packet != NULL )
  {
    DEBUG(11,"Timing out %s\n",f->fake_dns_req->dns_name);
    remove_fake_dns(f->fake_dns_req);
  }
  // Remove our private trigger id from our table
  remove_id_from_id_list(&(f->prv_id));

  //cl_free_buf(clb);
}

// Public Trigger for legacy server obtained
// Now, request private trigger

void handle_public_trigger_confirmation(char* buf, ID* myprivateid)
{
  struct id_list       *id_list;
  struct fake_addr     *fake;
  cl_buf* clb;
  ID publicid;
  char *nonce1=NULL,*nonce2=NULL;
  char nonce3[AUTH_KEY_LEN/8];

  DEBUG(15,"got public trigger at ");
  if (15 <= I3_DEBUG_LEVEL) print_time();

  // lookup state
  // if no state, return
  id_list = lookup_id(myprivateid);
  if (id_list == NULL || id_list->type != ID_LIST_ADDR)
    return;

  // if our state for this flow is absent / not waiting for public trigger
  fake = id_list->s.addr;
  if ( fake == NULL || !waiting_for_public_trigger(fake->fake_dns_req))
  {
    return;
  }

  memcpy(publicid.x,buf,ID_LEN);
  buf += ID_LEN;
  buf += unpack_variable_length(buf,&nonce1,AUTH_KEY_LEN/8);
  buf += unpack_variable_length(buf,&nonce2,AUTH_KEY_LEN/8);
  int authres = server_auth(myprivateid,nonce1,nonce2,nonce3);
  free(nonce1);
  free(nonce2);
  
  if ( !authres)
  {
    DEBUG(11,"Failed auth in public trigger confirmation!\n");
    return;
  }

  DEBUG(11,"Passed auth in public trigger confirmation!\n");

  // store info about newly obtained public trigger
  init_i3_id(&(fake->fake_dns_req->dns_id),&publicid);
  fake->fake_dns_req->dns_stack.ids = &(fake->fake_dns_req->dns_id);
  fake->fake_dns_req->dns_stack.len = 1;
  fake->state = FAKE_STATE_NEW;

  // send request for private trigger
  clb = cl_alloc_buf(2 + ID_LEN + AUTH_KEY_LEN/8);
  pack_auth_trigger_req(clb,(&(fake->prv_id)),nonce3); 
  cl_send_to_stack(&(fake->fake_dns_req->dns_stack), clb);
  
  DEBUG(11,"Sending auth private trigger request at ");
  if (11 <= I3_DEBUG_LEVEL) print_time();

  // allocate fake IP address
  fake->fake_addr.t.v4.addr.s_addr = alloc_fake_IP();

  answer_dns_query(fake->fake_dns_req->dns_packet, &fake->fake_addr,
		   fake->fake_dns_req->dns_packet_len);
  fake->fake_dns_req->answered = 1;
}

// Partner notified that he temporarily dropped his private trigger
void handle_trigger_remove(ID* id)
{
  struct id_list    *id_list;

  id_list = lookup_id(id);
  if ((id_list == NULL) || (id_list && (id_list->type != ID_LIST_ADDR)))
    return;

  DEBUG(10, "  partner's private tigger for %s was temporarily removed\n",
	inet_ntoa(id_list->s.addr->fake_addr.t.v4.addr));

  if (id_list->s.addr != NULL)
    id_list->s.addr->state = FAKE_STATE_PARTNER_DORMANT;
}

// Other side tearing down flow corresponding to id
// Remove our state as well

void handle_fake_remove(ID* id)
{
  struct id_list    *id_list;

  DEBUG(20, "handle_fake_remove()");

  id_list = lookup_id(id);
  // If you don't have state under id
  if ((id_list == NULL) || (id_list && (id_list->type != ID_LIST_ADDR)))
    return;

  // Fake_DNS packet captured
  if ( id_list->s.addr->fake_dns_req != NULL && id_list->s.addr->fake_dns_req->dns_packet != NULL )
  {
    DEBUG(11,"Timing out %s\n",id_list->s.addr->fake_dns_req->dns_name);
    remove_fake_dns(id_list->s.addr->fake_dns_req);
  }
  remove_fake_addr(id_list->s.addr);
  remove_id_from_id_list(id);
}

// Are we still waiting for the public trigger?
// We can distinguish by checking whether the DNS_ID is pointing to
// to the server proxy or not

int waiting_for_public_trigger(struct fake_dns_req  *fake_dns)
{
  ID* check = match_rules(fake_dns->dns_name);

  if ( check == NULL )
	  return 0;
  
  if ( !memcmp(&(fake_dns->dns_id.x),&(check->x),DEFAULT_SERVER_PROXY_TRIGGER_LEN) )
  {
    free_i3_id(check);
    return 1;
  }
  free_i3_id(check);
  return 0;
}

// Handle dns request for a legacy dns name

struct fake_dns_req  *handle_fake_legacy_dns_request(char *dns_str, char *buf, uint32_t len)
{
  struct fake_dns_req  *fake_dns;
  ID                   prv_id;
	    
  static cl_buf *clb = NULL;
  if (NULL == clb)
    clb = cl_alloc_buf(I3_PROXY_HDR_LEN);

  DEBUG(15,"Handling fake legacy dns for %s at ",dns_str);
  if (15 <= I3_DEBUG_LEVEL) print_time();

  memset(&prv_id, 0, ID_LEN);

  strlwr(dns_str);
   
  fake_dns = lookup_fake_dns(dns_str);
  
  if (fake_dns) {
    if (!waiting_for_public_trigger(fake_dns)) {
      DEBUG(15, "\n We already have an entry for this dns-name: %s", fake_dns->dns_name);

      if (fake_dns->fake_addr &&
	  (fake_dns->fake_addr->state == FAKE_STATE_OK ||
	   fake_dns->fake_addr->state == FAKE_STATE_PARTNER_DORMANT))
	{
	  DEBUG(15, "\n Status: FAKE_STATE_OK, fake-addr: ");
	  if (15 <= I3_DEBUG_LEVEL)
	    printf_i3_addr(&fake_dns->fake_addr->fake_addr, 0);
	  DEBUG(15, "Responding with old address. \n");
	  answer_dns_query(buf, &fake_dns->fake_addr->fake_addr, len);
	}
      else if(fake_dns->fake_addr && fake_dns->fake_addr->state == FAKE_STATE_NEW)
	{
	  DEBUG(15, "\n Status: FAKE_STATE_NEW ");
	  DEBUG(15, "Conn-Req. no. %u. Trying again!\n", fake_dns->fake_addr->retry);
	  DEBUG(15,"Send private trigger-request to partner\n");

	  pack_trigger_req(clb,&(fake_dns->fake_addr->prv_id));
	  cl_send_to_stack(&fake_dns->dns_stack, clb);

	  fake_dns->fake_addr->retry++;
	  return fake_dns;
	}
    
      fake_dns->fake_addr->num_req++;
      return fake_dns;
    } else {
      if (fake_dns->fake_addr->prv_trig == NULL) {
	// reinsert trigger
	if ((fake_dns->fake_addr->prv_trig =
	     cl_insert_trigger_key(&fake_dns->fake_addr->prv_id, ID_LEN_BITS,
				   &fake_dns->fake_addr->prv_trig_key)) == NULL) {
	    DEBUG(1, "\n trigger insertion failed ");
	    if (1 <= I3_DEBUG_LEVEL) printf_id(&fake_dns->fake_addr->prv_id, 0);
	    DEBUG(1, "\n");
	}
	return fake_dns;
      } else {
	// Retry request for public trigger
	struct cl_buf *auth_clb;
	auth_clb = cl_alloc_buf(2 + sizeof(ID) + sizeof(uint16_t) +
				strlen(myusername) + AUTH_KEY_LEN/8 +
				strlen(fake_dns->dns_name) + sizeof(uint16_t) );
	if ( !pack_public_trigger_req(auth_clb,fake_dns->fake_addr) )
	  return;
    
	DEBUG(15,"Sending public trigger request to at ");
	if ( 15 <= I3_DEBUG_LEVEL ) {
	  printf_i3_id(&(fake_dns->dns_id),2);
	  print_time();
	}
	cl_send_to_stack(&(fake_dns->dns_stack),clb);
	return fake_dns;
      }
    }
  } else { // fake_dns == NULL

    /* XXX: just simply call alloc for now; preallocate a pool of buffers
       in the future */
    fake_dns = (struct fake_dns_req *) malloc(sizeof(struct fake_dns_req));
    memset(fake_dns, 0, sizeof(struct fake_dns_req));
    strcpy(fake_dns->dns_name, dns_str);
    DEBUG(15, "\n Creating fake_dns-entry for dns-name: %s\n", fake_dns->dns_name);
  
    add_fake_dns(fake_dns);
  
    gen_private_ID(&prv_id);
    ID* server_proxy_trigger = match_rules(dns_str);
    random_server_proxy_trigger(server_proxy_trigger);
  
    init_i3_id(&fake_dns->dns_id,server_proxy_trigger);
    fake_dns->dns_stack.ids = &fake_dns->dns_id;
    fake_dns->dns_stack.len = 1;
  
    fake_dns->dns_packet_len = len;
    memcpy(fake_dns->dns_packet, buf, len);
  
    fake_dns->fake_addr = alloc_fake_addr(I3_ADDR_TYPE_IPv4, &prv_id);
    free_i3_id(server_proxy_trigger);
  
    if (fake_dns->fake_addr) {
      fake_dns->fake_addr->state = FAKE_STATE_NEW;
      fake_dns->num_req ++;
      fake_dns->fake_addr->num_req++;
      fake_dns->fake_addr->fake_dns_req = fake_dns;
      
      init_i3_id(&fake_dns->fake_addr->dest_id,&prv_id);
      init_i3_stack(&fake_dns->fake_addr->dest_stack, &fake_dns->fake_addr->dest_id, 1);
      insert_id_in_id_list(&fake_dns->fake_addr->prv_id, ID_LIST_ADDR, fake_dns->fake_addr);
      
      DEBUG(11,"Waiting for our private trigger to get inserted at ");
      if (11 <= I3_DEBUG_LEVEL) print_time();
      
      return fake_dns;
    } else {
      remove_fake_dns(fake_dns);
      return NULL;
    }
  }
}



struct fake_dns_req  *handle_fake_dns_request(char *dns_str, char *buf, uint32_t len)
{
  struct fake_dns_req  *fake_dns;
  ID                   prv_id;
  struct id_list       *idl;
	    
  static cl_buf *clb = NULL;
  if (NULL == clb)
    clb = cl_alloc_buf(I3_PROXY_HDR_LEN);

  DEBUG(15,"Handling fake dns at ");
  if (15 <= I3_DEBUG_LEVEL)  print_time();

  memset(&prv_id, 0, ID_LEN);

  strlwr(dns_str);
   
  fake_dns = lookup_fake_dns(dns_str);
  
  if (fake_dns) 
  {
    // replace the old DNS query packet with the new one
    fake_dns->dns_packet_len = len;
    memcpy(fake_dns->dns_packet, buf, len);
    fake_dns->answered = 0;
    
    if (fake_dns->fake_addr && fake_dns->fake_addr->state == FAKE_STATE_OK) {
      DEBUG(15, "\n We already have an entry for this dns-name: %s", fake_dns->dns_name);
      
      // check if my private ID is still available
      idl = lookup_id(&fake_dns->fake_addr->prv_id);
      if (fake_dns->fake_addr->prv_trig != NULL) {
	// my private ID is still in i3 infrastcucture
	DEBUG(15, "\n Status: FAKE_STATE_OK, fake-addr: ");
	if (15 <= I3_DEBUG_LEVEL) printf_i3_addr(&fake_dns->fake_addr->fake_addr, 0);
	
	//send I3_PROXY_PRIVATE_TRIG_REQ to the partner to confirm the connection is still OK
	DEBUG(15, " sending I3_PROXY_PRIVATE_TRIG_REQ to confirm the connection\n");
	pack_trigger_req(clb, &(fake_dns->fake_addr->prv_id));
	cl_send_to_stack(&fake_dns->dns_stack, clb);
	
	// wait for I3_PROXY_PRIVATE_TRIG_CNF
	return fake_dns;
      } else {
	// my private trigger was temporarily removed from i3 infrastcucture
	// insert private trigger again
	fake_dns->fake_addr->state = FAKE_STATE_RENEW;
	if ((fake_dns->fake_addr->prv_trig =
	     cl_insert_trigger_key(&fake_dns->fake_addr->prv_id,
				   ID_LEN_BITS,
				   &fake_dns->fake_addr->prv_trig_key)) == NULL) {
	  DEBUG(1, "\n failed to re-insert my private trigger: ");
	  if (1 <= I3_DEBUG_LEVEL) printf_id(&fake_dns->fake_addr->prv_id, 0);
	  return NULL;
	}

	// wait for CL_CBK_TRIGGER_INSERTED
	return fake_dns;
      }
    } else if(fake_dns->fake_addr && fake_dns->fake_addr->state ==
	      FAKE_STATE_PARTNER_DORMANT) {
      // the partner notified that its private trigger was temporarily removed
      // send private trigger request
      
      fake_dns->fake_addr->state = FAKE_STATE_RENEW;
      pack_trigger_req(clb,&(fake_dns->fake_addr->prv_id));
      cl_send_to_stack(&fake_dns->dns_stack, clb);
      
      // wait for I3_PROXY_PRIVATE_TRIG_CNF
      return fake_dns;
    } else if(fake_dns->fake_addr &&
	      (fake_dns->fake_addr->state == FAKE_STATE_NEW ||
	       fake_dns->fake_addr->state == FAKE_STATE_RENEW)) {
      DEBUG(15, "\n Status: FAKE_STATE_NEW/FAKE_STATE_RENEW ");
      if (fake_dns->fake_addr->retry > max_dns_retry) {
	// already tried 'max_dns_retry' times
	// giving up
	struct fake_addr *fake = fake_dns->fake_addr;
	DEBUG(10, "\n Tried to reach ID ");
	DEBUG(10, " %u times. Giving up now.", max_dns_retry);
	log_fake_removal_mutex(&fake->prv_id);
	private_trigger_timeout(fake);
	remove_fake_addr(fake);
      } else {
	DEBUG(15, "Conn-Req. no. %u. Trying again!\n", fake_dns->fake_addr->retry);
	DEBUG(15,"send private trigger-request to partner\n");	    
	
	pack_trigger_req(clb,&(fake_dns->fake_addr->prv_id));
	cl_send_to_stack(&fake_dns->dns_stack, clb);
	
	fake_dns->fake_addr->retry++;
	return fake_dns;
      }
    } else {
      DEBUG(15, "\n Status: unknown\n");
    }
  } else {
    /* XXX: just simply call alloc for now; preallocate a pool of buffers
       in the future */
    fake_dns = (struct fake_dns_req *) malloc(sizeof(struct fake_dns_req));
    if (fake_dns) {
      memset(fake_dns, 0, sizeof(struct fake_dns_req));
      strcpy(fake_dns->dns_name, dns_str);

      DEBUG(15, "\n Creating fake_dns-entry for dns-name: %s\n", fake_dns->dns_name);

      {
	ID* lid = lookup_addrbook(dns_str);
	if ( lid != NULL )
	{
	  init_i3_id(&fake_dns->dns_id,lid);
	  free_i3_id(lid);
	}
	else if ( enable_hashed_urls )
	{
	  hash_URL_on_ID(dns_str, &fake_dns->dns_id);
	}
	else
	{
	  DEBUG(1,"Public trigger for %s not specified in address book\n",dns_str);
	  if (fake_dns->dns_packet != NULL && fake_dns->answered == 0)
	    answer_dns_query(buf, NULL, len);
	  free(fake_dns);
	  return NULL;
	}
	
	add_fake_dns(fake_dns);}
	 
      fake_dns->dns_stack.ids = &fake_dns->dns_id;
      fake_dns->dns_stack.len = 1;
      
      gen_private_ID(&prv_id);            
      
      fake_dns->dns_packet_len = len;
      memcpy(fake_dns->dns_packet, buf, len);
      
      fake_dns->fake_addr = alloc_fake_addr(I3_ADDR_TYPE_IPv4, &prv_id);
      
      if (fake_dns->fake_addr) {
	fake_dns->fake_addr->state = FAKE_STATE_NEW;
	fake_dns->num_req ++;
	fake_dns->fake_addr->num_req++;
	fake_dns->fake_addr->fake_dns_req = fake_dns;
	
	{
	  ID* lid = lookup_addrbook(dns_str);
	  if ( lid != NULL)
	  {
	    init_i3_id(&fake_dns->fake_addr->dest_id,lid);
	    free_i3_id(lid);
	  }
	  else if ( enable_hashed_urls )
	  {
	    hash_URL_on_ID(dns_str,&fake_dns->fake_addr->dest_id);
	  }
	  else
	  {
	    DEBUG(1,"Public trigger for %s not specified in address book\n",dns_str);
	    free(fake_dns);
	    return NULL;
	  }
	}

	init_i3_stack(&fake_dns->fake_addr->dest_stack, &fake_dns->fake_addr->dest_id, 1);
	insert_id_in_id_list(&fake_dns->fake_addr->prv_id, ID_LIST_ADDR, fake_dns->fake_addr);

	return fake_dns;
      } else {
	DEBUG(1, "\n Error: Can not allocate fake_addr-struct in fake_dns_request()\n");
      }
      return NULL;
    }
  }
  return NULL;
}




// This thread prints periodically the status of the data structures
// in various files

void *status_thread (void *arg)
{
  FILE  *pub_dns_fd, *fake_dns_fd, *id_list_fd;
  char  count = 0;
  time_t last_refresh, last_timeoutcheck, curtime;

  time(&last_refresh);
   
  while(1)
  {
#ifdef __CYGWIN__
    usleep(1000000);
#else
    sleep(1);
#endif
    count ++;
      
    time(&curtime);

    // refresh fake log file at intervals of FAKE_LOG_INTERVAL
    if (curtime - last_refresh > FAKE_LOG_INTERVAL) {
      last_refresh = curtime;
      refresh_fake_log_mutex();
    }

    // check timeout
    if (curtime - last_timeoutcheck > CHECK_TIMEOUT_INTERVAL) {
      last_timeoutcheck = curtime;
      check_timeout();
    }

    if (count == 5)
    {
      count = 0;
      if (pub_dns_fname[0])
      {
	pub_dns_fd = fopen(pub_dns_fname, "w+");
	if(pub_dns_fd == NULL) { DEBUG(1, "\n Error opening: %s\n", pub_dns_fname); exit(0);}
	printf_pub_dns_status(pub_dns_fd);
	fclose(pub_dns_fd);
      }

      if (fake_dns_fname[0])
      {
	fake_dns_fd = fopen(fake_dns_fname, "w+");
	if(pub_dns_fd == NULL) {DEBUG(1, "\n Error opening: %s\n", fake_dns_fname); exit(0);}
	printf_fake_dns_status(fake_dns_fd);
	fclose(fake_dns_fd);
      }

      if (id_list_fname[0])
      {
	id_list_fd = fopen(id_list_fname, "w+");
	if(id_list_fd == NULL) {DEBUG(1, "\n Error opening: %s\n", id_list_fname); exit(0);}
	printf_id_list(id_list_fd);
	fclose(id_list_fd);
      }
    }
  }
   
  pthread_exit((void *) 0);
}




void *dns_answer_thread (void *arg)
{
  int   len;
  char  buf[BUF_LEN];
   
  DEBUG(10, " DNS answering thread started...\n");

  while(1)
  {	
    len = recv(dnsfd, buf + 28, BUF_LEN, 0);

    if (len <= 0)
    {
      DEBUG(1, "\n Error at receiving packet in dns answer thread\n");
    }
    else
    {
      DEBUG(15, "Sending back the received DNS response.\n");

      if (get_dns_request_from_queue(buf, len))
      {
#ifdef __CYGWIN__
	write_to_tun(tunfd, buf, len + 28);
#else
	write(tunfd, buf, len + 28);
#endif
      }         
    }
  }
  pthread_exit((void *) 0);
}

int is_dns_packet(char* buf)
{
  struct udphdr *udp_hdr;
  
  if (buf[0] == 0x45 && buf[9] == 0x11) // Check if UDP?
  {
    udp_hdr = (struct udphdr *) &buf[20];
	     
#if (defined(__CYGWIN__) || defined(__APPLE__))
    if (ntohs(udp_hdr->uh_dport) == 0x0035)  // DNS-Request
#else
      if (ntohs(udp_hdr->dest) == 0x0035)  // DNS-Request
#endif
	return 1;
  }
  
  return 0; 
}

void *tun_input_thread (void *arg)
{
  char			*buf;
  static cl_buf	*clb = NULL;
  int			read_ret;
  struct udphdr	*udp_hdr;

  if (NULL == clb)
    clb = cl_alloc_buf(BUF_LEN);
  buf = clb->data + 2;
   
  DEBUG(10, " Tunnel Input Thread started...\n");
   
  while(1)
  {
#ifdef __CYGWIN__
    if ((read_ret = read(readsp[1], buf, BUF_LEN)) < 0)
#else
      if ((read_ret = read(tunfd, buf, BUF_LEN)) < 0)
#endif
      {
	DEBUG(1, "\nERROR: read_from_tun(): read(sockfd_tun) failed\n");
	exit(0);
      }

    

    if ( is_dns_packet(buf))
    {
      uint16_t  	dns_flags, dns_numquest, lenstr;
      char			*dns_hdr, *dns_quest;
      char        dns_quest_str[BUF_LEN];
		 
      DEBUG(15, " DNS Request: ");

      udp_hdr = (struct udphdr *) &buf[20];
      dns_hdr = (char *) udp_hdr + 8;
      dns_flags = ntohs(*((uint16_t *) dns_hdr + 1));
      dns_numquest = ntohs(*((uint16_t *) dns_hdr + 2));
      dns_quest = dns_hdr + 12;
      parse_dns_query_name(dns_quest, dns_quest_str);
      lenstr = strlen(dns_quest_str);

      DEBUG(15,"DNS String: %s\n",dns_quest_str);
      
      if (strcmp(".i3", dns_quest_str + lenstr -3) == 0) 
      {
	struct fake_dns_req  *fake_dns;
	DEBUG(15, "i3 DNS Request: Flags: %x, Num questions: %x, Query: %s\n", dns_flags, dns_numquest, dns_quest_str);
	fake_dns = handle_fake_dns_request(dns_quest_str, buf, read_ret);
      }
      else if ( match_rules(dns_quest_str) != NULL )
      {
	struct fake_dns_req  *fake_dns;
	DEBUG(15, "i3 DNS Request: Flags: %x, Num questions: %x, Query: %s\n", dns_flags, dns_numquest, dns_quest_str);
	fake_dns = handle_fake_legacy_dns_request(dns_quest_str, buf, read_ret);
      }
      else
      {
	DEBUG(15, "Non-i3 DNS Request: Flags: %x, Num questions: %x, Query: %s\n", dns_flags, dns_numquest, dns_quest_str);
	push_dns_request_in_queue(buf);

#ifdef __CYGWIN__
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_PER_ADAPTER_INFO pPerAdapterInfo;
	ULONG OutBufLen = 0;
	    
	GetAdaptersInfo(NULL, &OutBufLen);
	pAdapterInfo = (PIP_ADAPTER_INFO)malloc(OutBufLen);
	GetAdaptersInfo(pAdapterInfo, &OutBufLen);
	    
	PIP_ADAPTER_INFO pai = pAdapterInfo;
	while (pai) {
	  if (pai->GatewayList.IpAddress.String[0] != 0) {
	    OutBufLen=0;
	    GetPerAdapterInfo(pai->Index, NULL, &OutBufLen);
	    pPerAdapterInfo = (PIP_PER_ADAPTER_INFO)malloc(OutBufLen);
	    GetPerAdapterInfo(pai->Index, pPerAdapterInfo, &OutBufLen);
	    if (pPerAdapterInfo->DnsServerList.IpAddress.String[0] != 0) {
	      daddr.sin_addr.s_addr = inet_addr(pPerAdapterInfo->DnsServerList.IpAddress.String);
	      sendto(dnsfd, buf + 28, read_ret - 28, 0, (struct sockaddr *) &daddr, addrlen);
	      break;
	    }
	  }
	  pai = pai->Next;
	}
	free(pAdapterInfo);
	free(pPerAdapterInfo);
#else
	// Take the destination to the original dns-server into the proxy-dns-request.
	memcpy(&(daddr.sin_addr.s_addr), buf + 16, sizeof(struct in_addr));
	sendto(dnsfd, buf + 28, read_ret - 28, 0, (struct sockaddr *) &daddr, addrlen);
#endif
      }

      continue;
    }

    // not a DNS query packet
    struct fake_addr  *fake;
    i3_addr           addr;
	     
    addr.type = I3_ADDR_TYPE_IPv4;
    addr.t.v4.addr.s_addr = ((unsigned long *) buf)[4];
    
    DEBUG(20," Got a packet: %u.%u.%u.%u of size %d\n",
	  buf[16], buf[17], buf[18], buf[19],(int)read_ret);
	     
    fake = lookup_fake_addr(&addr);
    if (fake == NULL) {
      DEBUG(10, "No fake-entry for this packet: ");
      if (10 <= I3_DEBUG_LEVEL)
	printf_i3_addr(&addr, 0); 
      continue;
    }
    
    if (fake->prv_trig != NULL) { // my private trigger is available
      if (fake->state == FAKE_STATE_OK) {// OK to send
	DEBUG(20, " Sending packet with len %u to i3-server: ", read_ret +2);
	if (20 <= I3_DEBUG_LEVEL) { printf_id(&fake->dest_stack.ids[0],0); }
	time(&fake->last_use);
	
	clb->data[0] = I3_PROXY_VERSION;
	clb->data[1] = I3_PROXY_DATA;
	clb->data_len = read_ret + 2;
	cl_send_to_stack(&fake->dest_stack, clb);
	continue;
      } else if (fake->state == FAKE_STATE_NEW ||   // confirmation is on-going
		 fake->state == FAKE_STATE_RENEW || // put packet to queue
		 fake->state == FAKE_STATE_RECNF) { // 
	insert_pkt_to_queue(fake, buf, read_ret);
	continue;
      } else if (fake->state == FAKE_STATE_PARTNER_DORMANT) {
	// the partner notified that his private trigger was temporarily removed
	// send private trigger request to the partner
	if (fake->fake_dns_req != NULL) {
	  fake->state = FAKE_STATE_RENEW;
	  insert_pkt_to_queue(fake, buf, read_ret);
	  pack_trigger_req(clb,&(fake->prv_id));
	  cl_send_to_stack(&fake->fake_dns_req->dns_stack, clb);
	  // wait for I3_PROXY_PRIVATE_TRIG_CNF
	  continue;
	} else {
	  // I don't know the partner's public ID
	  // just discard the packet
	  DEBUG(15, " the fake connection is currently unavailable\n");
	  continue;
	}
      } else {
	// unexpected state
	// just discard it
	continue;
      }
    } else { // my private trigger was temporarily removed from i3
      if (fake->state == FAKE_STATE_PARTNER_DORMANT) {
	// I know that the partner's private ID was also removed
	if (fake->fake_dns_req == NULL) {
	  // I don't know the partner's public ID
	  // there is no way to recover the connection
	  // just discard the packet
	  DEBUG(10, " the fake connection is currently unavailable\n");
	  continue;
	} else {
	  // re-insert private trigger and send priv_trig_req
	  fake->state = FAKE_STATE_RENEW;
	}
      } else if (fake->state == FAKE_STATE_RENEW ||
		 fake->state == FAKE_STATE_RECNF) {
	// reconfirmation is on-going and can not send the packet right now
	// as my private trigger is unavailable
	// put the packet into the queue and wait RENEW/RECNF finish
	insert_pkt_to_queue(fake, buf, read_ret);
	continue;
      } else if (fake->state != FAKE_STATE_OK) {
	// unexpected state (FAKE_STATE_NEW)
	// just discard the packet
	DEBUG(10, " the fake connection is currently unavailable\n");
	continue;
      }
      
      // FAKE_STATE_OK:
      //   just re-insert the private trigger and send queued packets
      // FAKE_STATE_DORMANT(canged to FAKE_STATE_RENEW):
      //   re-insert the private trigger, send priv_trig_req, receive priv_trig_cnf
      //   then send queued packets

      if (fake->prv_trig == NULL) {
	if ((fake->prv_trig =
	     cl_insert_trigger_key(&fake->prv_id, ID_LEN_BITS,
				   &fake->prv_trig_key)) == NULL) {
	  DEBUG(1, "\n failed to re-insert my private trigger: ");
	  if (1 <= I3_DEBUG_LEVEL) printf_id(&fake->prv_id, 0);
	  return NULL;
	}
      }

      insert_pkt_to_queue(fake, buf, read_ret);

      // wait my private trigger is inserted
      continue;
    }  }
  pthread_exit((void *) 0);
}

void change_addr_fix_checksum(char *ip_hdr, struct fake_addr  *fake)
{
  uint16_t old_ip_chk, new_ip_chk;
  unsigned long  tmp_addr, old_snd_addr, old_rcv_addr, new_snd_addr, new_rcv_addr;
      
  memcpy(&old_rcv_addr, ip_hdr + 16, 4);
  tmp_addr = htonl(fake->real_addr.t.v4.addr.s_addr);
  memcpy(ip_hdr + 16, &tmp_addr, 4);
  new_rcv_addr = fake->real_addr.t.v4.addr.s_addr;
   
  memcpy(&old_snd_addr, ip_hdr + 12, 4);
  tmp_addr = fake->fake_addr.t.v4.addr.s_addr;
  memcpy(ip_hdr + 12, &tmp_addr, 4);
  new_snd_addr = ntohl(fake->fake_addr.t.v4.addr.s_addr);

  old_rcv_addr = ntohl(old_rcv_addr);
  old_snd_addr = ntohl(old_snd_addr);

  old_ip_chk = ((uint16_t *) ip_hdr)[5];
  ((uint16_t *) ip_hdr)[5] = 0;
  new_ip_chk = in_cksum((uint16_t *) ip_hdr, 20);
  ((uint16_t *) ip_hdr)[5] = new_ip_chk;

  if (ip_hdr[0] == 0x45)
  {
    uint32_t  checksum;
         
    switch (ip_hdr[9])
    {
    case 1: // ICMP
      // Do nothing!
      break;

    case 2: // IGMP
      // Do nothing!
      break;

    case 6: // TCP
      // incrementally update TCP checksum (see RFC 1141) 
      checksum = ntohs(((uint16_t *) ip_hdr)[18]);
                  
      checksum += (~new_rcv_addr & 0xffff) + (old_rcv_addr & 0xffff);
      checksum += (~new_snd_addr & 0xffff) + (old_snd_addr & 0xffff);
      checksum += ((~new_rcv_addr) >> 16) + (old_rcv_addr >> 16);
      checksum += ((~new_snd_addr) >> 16) + (old_snd_addr >> 16);
      checksum = (checksum & 0xffff) + (checksum>>16);
		
      ((uint16_t *) ip_hdr)[18] = htons((checksum & 0xffff) + (checksum>>16));
      break;

    case 17: // UDP
      // incrementally update UDP checksum (see RFC 1141)
      checksum = ntohs(((uint16_t *) ip_hdr)[16]);
                  
      checksum += (~new_rcv_addr & 0xffff) + (old_rcv_addr & 0xffff);
      checksum += (~new_snd_addr & 0xffff) + (old_snd_addr & 0xffff);
      checksum += ((~new_rcv_addr) >> 16) + (old_rcv_addr >> 16);
      checksum += ((~new_snd_addr) >> 16) + (old_snd_addr >> 16);
      checksum = (checksum & 0xffff) + (checksum>>16);
		
      ((uint16_t *) ip_hdr)[16] = htons((checksum & 0xffff) + (checksum>>16));
      break;
               
    default:      
      DEBUG(5,"\n Unsupported layer4-protocol in handle_data_packet(), packet-type: %u\n", ip_hdr[9]);
      break;
    }            
  }
}

// handle a DNS answer relayed from server proxy
// a DNS answer is relayed when it contains error
// if a query was successfully resolved, the server proxy
// just returns I3_PROXY_PUBLIC_TRIG_CNF
void handle_legacy_dns_answer(char *udpmsg, int len, ID *my_id)
{
  struct id_list *idl;
  struct fake_addr *fake;
  static char dns_packet[BUF_LEN];

  idl = lookup_id(my_id);
  if (idl == NULL) {
    // unknown ID (might be removed before)
    return;
  }

  if (idl->type != ID_LIST_ADDR ||
      idl->s.addr->fake_dns_req == NULL ||
      idl->s.addr->fake_dns_req->dns_packet == NULL) {
    // unexpected condition
    return;
  }

  fake = idl->s.addr;

  // copy original IP, UDP header & DNS transaction ID to buf
  memcpy(dns_packet, fake->fake_dns_req->dns_packet, 30);
  // swap src/dst IP addresses & UDP port numbers
  memcpy(dns_packet + 12, fake->fake_dns_req->dns_packet + 16, 4);
  memcpy(dns_packet + 16, fake->fake_dns_req->dns_packet + 12, 4);
  memcpy(dns_packet + 20, fake->fake_dns_req->dns_packet + 22, 2);
  memcpy(dns_packet + 22, fake->fake_dns_req->dns_packet + 20, 2);

  // copy dns answer to buf except transaction ID
  memcpy(dns_packet + 30, udpmsg + 2, len -2 );

  ((uint16_t *) dns_packet)[1] = htons(len + 28); // Total Length in IP header
  // compute IP checksum
  ((uint16_t *) dns_packet)[5] = 0;
  ((uint16_t *) dns_packet)[5] = in_cksum((uint16_t *) dns_packet, 20);
  ((uint16_t *) dns_packet)[12] = htons(len + 8); // UDP Length
  memset(dns_packet + 26, 0, 2); // set UDP checksum = 0

  private_trigger_timeout(fake);
  remove_fake_addr(fake);

#ifdef __CYGWIN__
  write_to_tun(tunfd, dns_packet, len + 28);
#else
  write(tunfd, dns_packet, len + 28);
#endif
}
void handle_data_packet(char *ip_hdr, int len, ID *id)
{
  struct fake_addr  *fake;
  struct id_list    *id_list;

  DEBUG(20, " handle_data_packet(): Packet before:");
  if (20 <= I3_DEBUG_LEVEL) print_buf(ip_hdr, len);

  id_list = lookup_id(id);
  if ((id_list == NULL) || (id_list && (id_list->type != ID_LIST_ADDR)))
  {
    DEBUG(5, " handle_data_packet(): Houston, we have a problem....;-)");
    return;
  }

  DEBUG(20,"Received data packet of length %d\n",len);
  if (10 <= I3_DEBUG_LEVEL)  print_time();

  fake = id_list->s.addr;

  if (fake->state == FAKE_STATE_CNF ||
      fake->state == FAKE_STATE_RECNF ||
      fake->state == FAKE_STATE_PARTNER_DORMANT)
    fake->state = FAKE_STATE_OK;

  time(&fake->last_use);
    
  if (fake->real_addr.type == I3_ADDR_TYPE_IPv4)
  {
    change_addr_fix_checksum(ip_hdr, fake);
  }
#ifndef __CYGWIN__
  else if (fake->real_addr.type == I3_ADDR_TYPE_IPv6)
  {
    DEBUG(1, "\n IPv6 is not implemented yet in handle_data_packet(...)");
  }
#endif
  else 
  {
    DEBUG(1, "\n ERROR: Unknown address type in handle_data_packet(...)");
    exit(-1);
  }

#ifdef __CYGWIN__
  write_to_tun(tunfd, ip_hdr, len);
#else
  write(tunfd, ip_hdr, len);
#endif
}


void proxy_receive_packet(i3_trigger *t, cl_buf *clb, void *data)
{
  char* buf = clb->data;
  ID          id_ret;
  int         payload_len = clb->data_len;

  init_i3_id(&id_ret,&(t->id));

  DEBUG(15, " i3-packet arrived at ID: ");

  if (15 <= I3_DEBUG_LEVEL) printf_id(&id_ret, 0);
  DEBUG(15, "\n");

  // printf("i3 proxy packet arrived at ID len=%d\n",payload_len);

  if (payload_len)
  {
    DEBUG(15, " i3-packet (");

    switch (buf[1])
    {
    case I3_PROXY_PUBLIC_TRIG_CNF:
      DEBUG(11, "I3_PROXY_PUBLIC_TRIG_CNF)\n");
      handle_public_trigger_confirmation(buf+2, &id_ret);
      break;
    case I3_PROXY_PRIVATE_TRIG_REMOVE:
      DEBUG(11, "I3_PROXY_PRIVATE_TRIG_REMOVE)\n");
      handle_trigger_remove(&id_ret);
      break;
    case I3_PROXY_FAKE_REMOVE:
      DEBUG(11, "I3_PROXY_FAKE_REMOVE)\n");
      handle_fake_remove(&id_ret);
      break;
    case I3_PROXY_PRIVATE_TRIG_REQ:
      DEBUG(11, "I3_PROXY_PRIVATE_TRIG_REQ)\n");

      handle_proxy_trigger_request((ID *) (buf+2), &id_ret);
      break;

    case I3_PROXY_PRIVATE_TRIG_CNF:
      DEBUG(11, "I3_PROXY_PRIVATE_TRIG_CNF)\n");
      handle_proxy_trigger_confirmation((ID *) (buf+2), &id_ret);
      break;

    case I3_PROXY_LEGACY_DNS_ERROR:
      DEBUG(11, "I3_PROXY_LEGACY_DNS_ERROR)\n");
      handle_legacy_dns_answer(buf + 2, payload_len - 2, &id_ret);
      break;

    case I3_PROXY_DATA:
      DEBUG(11, "I3_PROXY_DATA");
      DEBUG(15, ") received (Payload: %d), ", payload_len -2);

      handle_data_packet(buf+2, payload_len -2, &id_ret);
      break;

    default:
      printf("%d\n",(int)buf[1]);
      printf("%d\n",(int)buf[0]);
      printf("%d\n",(int)buf[-1]);

      
      DEBUG(15, "unknown)\n");
    }
  }
}

void proxy_trigger_inserted(i3_trigger* t,void *data)
{
  ID* inserted_id = &(t->id);
  struct fake_addr  *fake;
  struct id_list    *id_list;
  cl_buf *clb;
   
  id_list = lookup_id(inserted_id);
  if ((id_list == NULL) || (id_list && (id_list->type != ID_LIST_ADDR)))
  {
    // public trigger
    return;
  }

  fake = id_list->s.addr;

  if (fake->state == FAKE_STATE_RENEW ||
      fake->state == FAKE_STATE_RECNF ||
      fake->state == FAKE_STATE_OK)
    DEBUG(15,"my private trigger fo %s was re-inserted\n",
	  inet_ntoa(fake->fake_addr.t.v4.addr));

  if ( fake->fake_dns_req != NULL && waiting_for_public_trigger(fake->fake_dns_req))
  {
    clb = cl_alloc_buf(2 + sizeof(ID) + sizeof(uint16_t) + strlen(myusername) + AUTH_KEY_LEN/8 + strlen(fake->fake_dns_req->dns_name) + sizeof(uint16_t) );
    
    if ( !pack_public_trigger_req(clb,fake) )
      return;
    
    DEBUG(15,"Sending public trigger request to at ");
    if ( 15 <= I3_DEBUG_LEVEL ) {
      printf_i3_id(&(fake->fake_dns_req->dns_id),2);
      print_time();
    }
    cl_send_to_stack(&(fake->fake_dns_req->dns_stack),clb);
    return;
  }

  clb = cl_alloc_buf(I3_PROXY_HDR_LEN);

  if (fake->state == FAKE_STATE_CNF ||
      fake->state == FAKE_STATE_RECNF)
  {
    DEBUG(15,"Sending private trigger confirmation at ");
    if ( 15 <= I3_DEBUG_LEVEL) {
      printf_i3_id(&(fake->prv_id),2);
      print_time();
    }
    pack_trigger_cnf(clb,&(fake->prv_id));
    cl_send_to_stack(&(fake->dest_stack), clb);

    // log fake insertion to fake_log_file
    if (fake->state == FAKE_STATE_CNF)
      log_fake_insertion_mutex(fake);
  }
  else if (fake->state == FAKE_STATE_NEW ||
	   fake->state == FAKE_STATE_RENEW)
  {
    DEBUG(15,"Sending private trigger request at ");
    if ( 15 <= I3_DEBUG_LEVEL) {
      printf_i3_id(&(fake->prv_id),2);
      print_time();
    }
    pack_trigger_req(clb,&(fake->prv_id));
    cl_send_to_stack(&(fake->fake_dns_req->dns_stack), clb);
  }
  else if (fake->state == FAKE_STATE_OK)
  {
    flush_pkt_queue(fake);
  }

  //cl_free_buf(clb);
}

// Callback triggered when packet is sent to non-existent trigger

void proxy_trigger_not_present(i3_trigger *t, i3_header *hdr, cl_buf *clb, void *data)
{
  ID id_ret;
  struct id_list    *idl; 
  struct fake_addr* idfakeaddr;
  struct fake_dns_req *fake_dns;
  
  init_i3_id(&id_ret,&(t->id));

  // public trigger or private trigger ?
  fake_dns = lookup_fake_dns_by_ID(&id_ret);

  if (fake_dns != NULL) { // public trigger
    DEBUG(10, "\n partner's public trigger was not found");
    if ( fake_dns->dns_packet != NULL && fake_dns->answered == 0) {
      DEBUG(15, "\n answer DNS query\n");
      answer_dns_query(fake_dns->dns_packet, NULL,
                       fake_dns->dns_packet_len);
    }
    idfakeaddr = fake_dns->fake_addr;
    if (idfakeaddr->state != FAKE_STATE_NEW)
      log_fake_removal_mutex(&idfakeaddr->prv_id);
    // use private_trigger_timeout() for removing trigger, fake_dns, and id
    private_trigger_timeout(idfakeaddr);
    remove_fake_addr(idfakeaddr);
    return;
  }

  DEBUG(10, "private trigger was missing\n");
  idl = lookup_dest_id(&id_ret);

  if ( idl == NULL )
  {
    DEBUG(15, " \n IDL == NULL !!!!");
    return;
  }

  if (idl->type != ID_LIST_ADDR)
  {
    DEBUG(15, "\n NOT ID_LIST_ADDR");
    return;
  }
    
  // private trigger was missing
  idfakeaddr = idl->s.addr;
               
  if (idfakeaddr->state == FAKE_STATE_OK
      && idfakeaddr->fake_dns_req != NULL) {
    // i3 connection has once established, but
    // partner's private trigger no longer exists.
    // send private trigger request again to re-establish i3 connection.
    if (idfakeaddr->retry > max_dns_retry) {
      // already tried 'max_dns_retry' times
      // giving up
      DEBUG(10, "\n Tried to reach ID ");
      DEBUG(10, " %u times. Giving up now.", max_dns_retry);
      log_fake_removal_mutex(&idfakeaddr->prv_id);
      private_trigger_timeout(idfakeaddr);
      remove_fake_addr(idfakeaddr);
    } else {
      DEBUG(10, "\n Tried to reach ID ");
      DEBUG(10, " %u times. Trying again.", idl->s.addr->retry);
      idfakeaddr->retry++;
      clb = cl_alloc_buf(I3_PROXY_HDR_LEN);
      pack_trigger_req(clb,&(idl->s.addr->prv_id));
      cl_send_to_stack(&(idfakeaddr->fake_dns_req->dns_stack), clb);
    }
  }
}

// continue to call cl_select after setting callback

void *proxy_input_thread(void* arg)
{
  fd_set dummy;
  
  DEBUG(10, " Proxy Input Thread started...\n");

  cl_register_callback(CL_CBK_RECEIVE_PAYLOAD,proxy_receive_packet, NULL);
  cl_register_callback(CL_CBK_TRIGGER_NOT_FOUND,proxy_trigger_not_present,NULL);
  cl_register_callback(CL_CBK_TRIGGER_INSERTED,proxy_trigger_inserted,NULL);

  while(1)
  {
    FD_ZERO(&dummy);
    cl_select(0,&dummy,NULL,NULL,0);
  }

  pthread_exit((void *) 0);
}


