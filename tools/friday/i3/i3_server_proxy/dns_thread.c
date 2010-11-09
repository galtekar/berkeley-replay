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
#ifndef __APPLE__
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
#include "auth.h"


extern int     tunfd, dnsfd, addrlen;
extern struct  sockaddr_in	saddr, daddr;

extern ID anycast_public_trigger, unicast_public_trigger;
extern Key anycast_trigger_key, unicast_trigger_key;

struct real_dns_req *dns_req_list_start = NULL, *dns_req_list_end = NULL;

extern i3_addr     local_i3_addr;

extern char  pub_dns_fname[MAX_DNS_NAME_LEN];
extern char  fake_dns_fname[MAX_DNS_NAME_LEN];
extern char  id_list_fname[MAX_DNS_NAME_LEN];

extern unsigned short   max_dns_retry;
extern unsigned short   stale_timeout;

// Fake-DNS-List is currently a linked list. will be changed to hash or something faster...

struct fake_dns_req   *fake_dns_list_start = NULL;
struct fake_dns_req   *fake_dns_list_end = NULL;

struct pub_i3_dns     *pub_i3_dns_list_start = NULL;
struct pub_i3_dns     *pub_i3_dns_list_end = NULL;

void print_time()
{
  struct timeval t;
  gettimeofday(&t, NULL);
  DEBUG(5,"Sec: %ld Microsec: %ld\n",t.tv_sec,t.tv_usec);
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

  if (addr->type != I3_ADDR_TYPE_IPv4)
  {
    DEBUG(1, "\n Currently, only IPv4 is supported");
    exit(-1);
  }
   
  memcpy(buf, dns_request, len);

  // change ip addresses
  memcpy(buf + 12, dns_request + 16, 4);
  memcpy(buf + 16, dns_request + 12, 4);

  buf[3] += 16;
  chksum = ntohs(((uint16_t *) buf)[5]);
  chksum -= 0x10;
  ((uint16_t *) buf)[5] = htons(chksum);

  // Exchange UDP port numbers
  memcpy(buf + 20, dns_request + 22, 2);
  memcpy(buf + 22, dns_request + 20, 2);
  memset(buf + 26, 0, 2);

  // Change DNS packet type
  buf[25] += 16;

  // Set the fiels of the DNS answer
  buf[30] = 0x81; buf[31] = 0x80;
  buf[34] = 0x00; buf[35] = 0x01;
  memset(buf + 36, 0, 4);

  buf[len + 0] = 0xc0;
  buf[len + 1] = 0x0c;
  buf[len + 2] = 0x00;
  buf[len + 3] = 0x01;
  buf[len + 4] = 0x00;
  buf[len + 5] = 0x01;
  buf[len + 6] = 0x00;
  buf[len + 7] = 0x01;
  buf[len + 8] = 0x1c;
  buf[len + 9] = 0x5d;
  buf[len + 10] = 0x00;
  buf[len + 11] = 0x04;
  // At last, put in the fake address, that represents the DNS answer
  memcpy(buf + len + 12, &addr->t.v4.addr.s_addr, sizeof(unsigned long));

  // Send fake answer via tun-dev to legacy application
  write(tunfd, buf, len + 16);
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

// Caller has to deallocate
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
    (*varstr)[slen] = 0;
  
  return ((len==-1)?sizeof(uint16_t):0) + slen;
}


void pack_public_trigger_cnf(cl_buf* clb,ID  *id,char* n1,char* n2)
{
  char *buf = clb->data;
  buf[0] = I3_PROXY_VERSION;
  buf[1] = I3_PROXY_PUBLIC_TRIG_CNF;
  buf+=2;
  memcpy(buf,id->x,ID_LEN);
  buf += ID_LEN;
  buf += pack_variable_length(buf,n1,AUTH_KEY_LEN/8);
  buf += pack_variable_length(buf,n2,AUTH_KEY_LEN/8);
  clb->data_len = clb->max_len = 2 + ID_LEN + AUTH_KEY_LEN/8 + AUTH_KEY_LEN/8;
}

void send_public_trigger(ID* senderid,ID* publicid,char* nonce1,char* nonce2)
{
  cl_buf *clb;
  i3_stack s;

  DEBUG(11,"Sending public trigger at ");
  print_time();
  
  clb = cl_alloc_buf(2 + ID_LEN + AUTH_KEY_LEN/8 + AUTH_KEY_LEN/8);
  pack_public_trigger_cnf(clb,publicid,nonce1,nonce2);
  init_i3_stack(&s,senderid, 1);
  cl_send_to_stack(&s,clb);
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
      memcpy(buf, dns_req->packet_data, 20 + 8);

      // change ip addresses
      memcpy(buf + 12, dns_req->packet_data + 16, 4);
      memcpy(buf + 16, dns_req->packet_data + 12, 4);

      ((uint16_t *) buf)[1] = htons(udplen + 28);
      ((uint16_t *) buf)[5] = 0;
      ((uint16_t *) buf)[5] = in_cksum((uint16_t *) buf, 20);
       
      memcpy(buf + 20, dns_req->packet_data + 22, 2);
      memcpy(buf + 22, dns_req->packet_data + 20, 2);
      ((uint16_t *) buf)[12] = htons(udplen);       
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
      uint j;

      if (fake_dns->fake_addr->state == FAKE_STATE_OK)
      {
	fprintf(handle, ", Status: FAKE_STATE_OK");
      }
      if (fake_dns->fake_addr->state == FAKE_STATE_CNF)
      {
	fprintf(handle, ", Status: FAKE_STATE_CNF");
      }
      else if (fake_dns->fake_addr->state == FAKE_STATE_NEW)
      {
	fprintf(handle, ", Status: FAKE_STATE_NEW");
      }

      fprintf(handle, ", Address: ");
         
      if (fake_dns->fake_addr->fake_addr.type == I3_ADDR_TYPE_IPv4)
      {
	fprintf(handle, "%s", inet_ntoa( fake_dns->fake_addr->fake_addr.t.v4.addr ));
      }
      else if (fake_dns->fake_addr->fake_addr.type == I3_ADDR_TYPE_IPv6)
      {
	for (j = 0; j < sizeof(struct in6_addr); j++)
	  fprintf(handle, "%02x:", fake_dns->fake_addr->fake_addr.t.v6.addr.s6_addr[j]);
      }
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

// Packing Functions
// clb is already allocated for

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

void pack_public_trigger_req(cl_buf* clb,struct fake_addr  *fake)
{
  uint16_t slen;
  clb->data[0] = I3_PROXY_VERSION;
  clb->data[1] = I3_PROXY_PUBLIC_TRIG_REQ;
  memcpy(clb->data + 2, &(fake->prv_id),ID_LEN);
  slen = strlen(fake->fake_dns_req->dns_name);
  slen = htons(slen);
  memcpy(clb->data+2+sizeof(ID),(char*)(&slen),sizeof(uint16_t));
  slen = ntohs(slen);
  memcpy(clb->data+2+sizeof(ID)+sizeof(uint16_t),fake->fake_dns_req->dns_name,slen);
  clb->data_len = clb->max_len = 2 + sizeof(ID) + strlen(fake->fake_dns_req->dns_name) + sizeof(uint16_t);
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
  cl_buf* clb = cl_alloc_buf(I3_PROXY_HDR_LEN);
  pack_fake_removal(clb,&(f->prv_id));
  cl_send_to_stack(&f->dest_stack, clb);
  
  if ( f->fake_dns_req != NULL && f->fake_dns_req->dns_packet != NULL )
  {
    DEBUG(15,"Timing out %s\n",f->fake_dns_req->dns_name);
    remove_fake_dns(f->fake_dns_req);
  }
  remove_id_from_id_list(&(f->prv_id));
}

void handle_fake_remove(ID* id)
{
  struct id_list    *id_list;

  DEBUG(20, " handle_trigger_remove()");
  //printf("Timing out\n");

  id_list = lookup_id(id);
  if ((id_list == NULL) || (id_list && (id_list->type != ID_LIST_ADDR)))
  {
    return;
  }

  if ( id_list->s.addr->fake_dns_req != NULL && id_list->s.addr->fake_dns_req->dns_packet != NULL )
  {
    //printf("Timing out %s\n",id_list->s.addr->fake_dns_req->dns_name);
    remove_fake_dns(id_list->s.addr->fake_dns_req);
  }
  log_fake_removal_mutex(id);
  remove_fake_addr(id_list->s.addr);
  remove_id_from_id_list(id);
}

void add_fake_dns(struct fake_dns_req  *fake_dns);


// search fake_dns_req-struct with URL=dns_name in hash-table

struct fake_dns_req   *lookup_fake_dns(char *dns_name)
{
  struct fake_dns_req  *list = fake_dns_list_start;

  strlwr(dns_name);
   
  while(list)
  {
    if (strcmp(list->dns_name, dns_name) == 0)
    {
      i3_addr* copyaddr = duplicate_i3_addr(&(list->fake_addr->real_addr));
      
      // we have timed out
      if ( lookup_fake_addr(copyaddr) == NULL )
      {
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

void insert_server_proxy_trigger()
{
  ID myid;
  int i;

  get_random_ID(&myid);

  for(i=DEFAULT_SERVER_PROXY_TRIGGER_LEN;i<ID_LEN;i++) 
    anycast_public_trigger.x[i] = myid.x[i];

  set_public_id(&anycast_public_trigger);

  DEBUG(1,"Using anycast server proxy trigger\n");
  printf_i3_id(&anycast_public_trigger,2);

  if (!cl_insert_trigger_addr_key(&anycast_public_trigger,
				  DEFAULT_SERVER_PROXY_TRIGGER_LEN*8,
				  local_i3_addr.t.v4.addr,local_i3_addr.t.v4.port,
				  &anycast_trigger_key)) {
    DEBUG(1, "\n Error inserting anycast server proxy trigger\n");
    return;
  }
  
  set_public_id(&unicast_public_trigger);

  DEBUG(1,"Using unicast server proxy trigger\n");
  printf_i3_id(&unicast_public_trigger,2);

  if (!cl_insert_trigger_addr_key(&unicast_public_trigger,
				  DEFAULT_SERVER_PROXY_TRIGGER_LEN*8,
				  local_i3_addr.t.v4.addr,local_i3_addr.t.v4.port,
				  &unicast_trigger_key)) {
    DEBUG(1, "\n Error inserting unicast server proxy trigger\n");
    return;
  }
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

void get_random_key(Key *id)
{
  int   i;

  for(i=0; i < KEY_LEN; i++)
  {
#ifdef __CYGWIN__
    id->x[i] = (char) (random() % 255);
#else
    id->x[i] = (char) (rand() % 255);
#endif
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
    sleep(1);
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
	fake_dns_fd = fopen("/tmp/fake_dns", "w+");
	if(pub_dns_fd == NULL) {DEBUG(1, "\n Error opening: %s\n", fake_dns_fname); exit(0);}
	printf_fake_dns_status(fake_dns_fd);
	fclose(fake_dns_fd);
      }

      if (id_list_fname[0])
      {
	id_list_fd = fopen("/tmp/id_list", "w+");
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
  int   len, i;
  char  buf[BUF_LEN];
  char  legacyurl[MAX_DNS_NAME_LEN];
  uint32_t hostaddr;
  struct dns_query *query;
  struct id_list    *dns_id_list;
  char nonce2[AUTH_KEY_LEN/8],nonce3[AUTH_KEY_LEN/8];

  struct i3_stack dest_stack;
  static cl_buf* clb;
  if (clb == NULL) {
    clb = cl_alloc_buf(BUF_LEN + 2);
    clb->data[0] = I3_PROXY_VERSION;
    clb->data[1] = I3_PROXY_LEGACY_DNS_ERROR;
  }
      
      

  DEBUG(10, " DNS answering thread started...\n");

  while(1)
  {	
    len = recv(dnsfd, buf, BUF_LEN, 0);

    if (len <= 0)
    {
      DEBUG(1, "\n Error at receiving packet in dns answer thread\n");
    }
    else
    {
      query = lookup_dns_query(ntohs(((uint16_t *)buf)[0]));
      if (query == NULL) // no matching transaction_id found
	continue;

      if (!((buf[2] & 0xf8) == 0x80 &&
	    (buf[3] & 0x0f) == 0x00 &&
	    ntohs(((uint16_t *)buf)[3]) != 0)) {
	DEBUG(1, "DNS answer != (Standard query response, No error), or num of Answers != 0\n");
	// copy DNS answer to i3 packet
	memcpy(clb->data + 2, buf, len);
	dest_stack.len = 1;
	dest_stack.ids = query->client_id;
	clb->data_len = len + 2;
	cl_send_to_stack(&dest_stack, clb);
	remove_dns_query(query);
	continue;
      } else {
	parse_dns_query_name(buf + 12, legacyurl);
	i = 18 + strlen(legacyurl);
	while (i < len) {
	  if ((buf[i] & 0xc0) == 0xc0)
	    i = i + 2;
	  else {
	    while (buf[i] != 0)
	      i++;
	    i++;
	  }
	  if (buf[i] == 0x00 && buf[i+1] == 0x01) { //Type: Host address
	    // retrieve IP address
	    memcpy(&hostaddr, buf+ i + 10, 4);
	    query->targetIP = ntohl(hostaddr);

	    // send back the unicast public trigger to the client
	    if ( user_login_retrieve(query->client_id,nonce2,nonce3) )
	      send_public_trigger(query->client_id,
				  &unicast_public_trigger,nonce2,nonce3);
	    break;
	  } else {
	    i = i + 10 + buf[i+8] * 256 + buf[i+9];
	  }
	}
      }         
    }
  }
  pthread_exit((void *) 0);
}



void *tun_input_thread (void *arg)
{
  char			*buf;
  static cl_buf	*clb = NULL;
  int			read_ret;

  if (NULL == clb)
    clb = cl_alloc_buf(BUF_LEN+2);
  buf = clb->data + 2;
   
  DEBUG(10, " Tunnel Input Thread started...\n");
   
  while(1)
  {
    struct fake_addr  *fake;
    i3_addr           addr;
	
    if ((read_ret = read(tunfd, buf, BUF_LEN)) < 0)
    {
      DEBUG(1, "\nERROR: read_from_tun(): read(sockfd_tun) failed\n");
      exit(0);
    }

    DEBUG(5,"Packet on tun of length %d at ",read_ret);
    print_time();

    // only packets from server come here
	     
    addr.type = I3_ADDR_TYPE_IPv4;
    addr.t.v4.addr.s_addr = ((unsigned long *) buf)[4];
	     
    DEBUG(20, " Got a packet: %u.%u.%u.%u ", buf[16], buf[17], buf[18], buf[19]);
	     
    fake = lookup_fake_addr(&addr);
    if (fake == NULL)
    {
      DEBUG(10, "No fake-entry for this packet: ");
      if (10 <= I3_DEBUG_LEVEL)
      {
	printf_i3_addr(&addr, 0); print_buf(buf, read_ret);
      }
      continue;
    }
	     
    if (fake->state == FAKE_STATE_OK ||
	fake->state == FAKE_STATE_RECNF) {// OK to send
      if (fake->prv_trig != NULL) { // my private trigger is available
	DEBUG(20, " Sending packet with len %u to i3-server: ", read_ret +2);
	if (20 <= I3_DEBUG_LEVEL) { printf_id(&fake->dest_stack.ids[0],0); }
	
	time(&fake->last_use);
	
	clb->data[0] = I3_PROXY_VERSION;
	clb->data[1] = I3_PROXY_DATA;
	clb->data_len = read_ret + 2;
	cl_send_to_stack(&fake->dest_stack, clb);
      } else { // my private trigger was temporarily removed from i3 infrastructure
        if ((fake->prv_trig =
             cl_insert_trigger_key(&fake->prv_id, ID_LEN_BITS,
                                   &fake->prv_trig_key)) == NULL) {
          DEBUG(1, "\n failed to re-insert my private trigger: ");
          if (1 <= I3_DEBUG_LEVEL) printf_id(&fake->prv_id, 0);
	  continue;
	}
	insert_pkt_to_queue(fake, buf, read_ret);
	continue;
      }
    }
    else
    {
      DEBUG(5, "\n Can not send packet to server: state = %02x, stack.len = %u, Entry is NOT in appropriate state\n ", fake->state, fake->dest_stack.len);
		 
    }
  }
   
  pthread_exit((void *) 0);
}


void handle_data_packet(char *ip_hdr, int len, ID *id)
{
  struct fake_addr  *fake;
  struct id_list    *id_list;
  uint16_t          old_ip_chk, new_ip_chk;

   
  DEBUG(20, " handle_data_packet(): Packet before:");
  if (20 <= I3_DEBUG_LEVEL) print_buf(ip_hdr, len);

  id_list = lookup_id(id);
  if ((id_list == NULL) || (id_list && (id_list->type != ID_LIST_ADDR)))
  {
    DEBUG(5, " handle_data_packet(): Houston, we have a problem....;-)");
    return;
  }

  DEBUG(20,"Received data packet of length %d at ",len);
  if (20 <= I3_DEBUG_LEVEL) {
    print_time();
    print_buf(ip_hdr, len);
  }

  fake = id_list->s.addr;

  if (fake->state == FAKE_STATE_CNF ||
      fake->state == FAKE_STATE_RECNF)
    fake->state = FAKE_STATE_OK;

  time(&fake->last_use);
    
  if (fake->real_addr.type == I3_ADDR_TYPE_IPv4)
  {
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
	// changed 16 to 13
	checksum = ntohs(((uint16_t *) ip_hdr)[13]);
                  
	checksum += (~new_rcv_addr & 0xffff) + (old_rcv_addr & 0xffff);
	checksum += (~new_snd_addr & 0xffff) + (old_snd_addr & 0xffff);
	checksum += ((~new_rcv_addr) >> 16) + (old_rcv_addr >> 16);
	checksum += ((~new_snd_addr) >> 16) + (old_snd_addr >> 16);
	checksum = (checksum & 0xffff) + (checksum>>16);
		
	((uint16_t *) ip_hdr)[13] = htons((checksum & 0xffff) + (checksum>>16));
	break;
               
      default:      
	DEBUG(5,"\n Unsupported layer4-protocol in handle_data_packet(), packet-type: %u\n", ip_hdr[9]);
	break;
      }            
    }
  }
  else if (fake->real_addr.type == I3_ADDR_TYPE_IPv6)
  {
    DEBUG(1, "\n IPv6 is not implemented yet in handle_data_packet(...)");
  }
  else 
  {
    DEBUG(1, "\n ERROR: Unknown address type in handle_data_packet(...)");
    exit(-1);
  }

  // TODO: In case of TCP or UDP, calculate checksum

  DEBUG(20, " handle_data_packet(): Packet after:");
  if (20 <= I3_DEBUG_LEVEL) print_buf(ip_hdr, len);

  write(tunfd, ip_hdr, len);
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
    case I3_PROXY_FAKE_REMOVE:
      DEBUG(15, "I3_PROXY_FAKE_REMOVE)\n");
      handle_fake_remove(&id_ret);
      break;
    case I3_PROXY_PUBLIC_TRIG_REQ:
      DEBUG(11, "I3_PROXY_PUBLIC_TRIG_REQ)\n");
      handle_public_trigger_request((buf+2), &id_ret);
      break;
    case I3_PROXY_PRIVATE_TRIG_REQ:
      DEBUG(11, "I3_PROXY_PRIVATE_TRIG_REQ)\n");
      if (lookup_dest_id((ID *) (buf+2)))
	handle_proxy_trigger_request((ID *) (buf+2), &id_ret);
      break;
    case I3_PROXY_AUTH_PRIVATE_TRIG_REQ:
      DEBUG(11, "I3_PROXY_AUTH_PRIVATE_TRIG_REQ)\n");
      char *nonce1=NULL;
      unpack_variable_length(buf+2+ID_LEN,&nonce1,AUTH_KEY_LEN/8);
      int authres = user_verify((ID*)(buf+2),nonce1);
      free(nonce1);
      if ( !authres )
	break;
      DEBUG(11,"succesfully verified!\n");
      handle_proxy_trigger_request((ID *) (buf+2), &id_ret);
      break;
    case I3_PROXY_PRIVATE_TRIG_CNF:
      DEBUG(11, "I3_PROXY_PRIVATE_TRIG_CNF)\n");
      handle_proxy_trigger_confirmation((ID *) (buf+2), &id_ret);
      break;

    case I3_PROXY_DATA:
      DEBUG(11, "I3_PROXY_DATA");
      DEBUG(15, ") received (Payload: %d), ", payload_len -2);
      handle_data_packet(buf+2, payload_len -2, &id_ret);
      break;

    default:
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

  if ( !compare_ids(&(t->id),&(anycast_public_trigger)))
  {
    DEBUG(10, "Anycast server proxy trigger inserted at ");
    if (10 <= I3_DEBUG_LEVEL) print_time();
    return;
  }
   
  if ( !compare_ids(&(t->id),&(unicast_public_trigger)))
  {
    DEBUG(10, "Unicast server proxy trigger inserted at ");
    if (10 <= I3_DEBUG_LEVEL) print_time();
    return;
  }
   
  id_list = lookup_id(inserted_id);

  if ( id_list == NULL )
    return;
  
  fake = id_list->s.addr;

  if ( fake->state != FAKE_STATE_CNF &&
       fake->state != FAKE_STATE_RECNF &&
       fake->state != FAKE_STATE_NEW )
    return;

  clb = cl_alloc_buf(I3_PROXY_HDR_LEN);

  if (fake->state == FAKE_STATE_CNF || fake->state == FAKE_STATE_RECNF)
  {
    DEBUG(15,"Sending private trigger confirmation at ");
    print_time();
    pack_trigger_cnf(clb,&(fake->prv_id));
    cl_send_to_stack(&(fake->dest_stack), clb);
    if (fake->state == FAKE_STATE_CNF)
      log_fake_insertion_mutex(fake);
  }
  else if ( fake->state == FAKE_STATE_NEW)
  {
    DEBUG(15,"Sending private trigger request at ");
    print_time();
    pack_trigger_req(clb,&(fake->prv_id));
    cl_send_to_stack(&(fake->fake_dns_req->dns_stack), clb);
  }

  //cl_free_buf(clb);
}

void proxy_trigger_not_present(i3_trigger *t, i3_header *hdr, cl_buf *clb, void *data)
{
  ID id_ret;
  struct id_list    *idl;
  struct fake_addr* idfakeaddr;
  
  init_i3_id(&id_ret,&(t->id));

  DEBUG(1, " ID not present \n");
  printf_i3_id(&id_ret,2);
         
  idl = lookup_dest_id(&id_ret);

  if ( idl == NULL )
  {
    DEBUG(1, " \n IDL == NULL !!!!");
    return;
  }
  
  DEBUG(15, "\n IDL != NULL");
            
  if (idl->type != ID_LIST_ADDR)
  {
    DEBUG(15, "\n NOT ID_LIST_ADDR");
    return;
  }
    
  DEBUG(15, "\n ID_LIST_ADDR");
  idfakeaddr = idl->s.addr;
               
  if (idfakeaddr->state != FAKE_STATE_CNF)
  {
    DEBUG(15, "\n NOT FAKE_STATE_CNF");
    DEBUG(10, "\n Missing Trigger is not a pending dns-request on the server side. ");
    if (10 <= I3_DEBUG_LEVEL) printf_id(&id_ret, 0);
    
    if ( idfakeaddr->fake_dns_req != NULL && idfakeaddr->fake_dns_req->dns_packet != NULL && idfakeaddr->retry < max_dns_retry)
    {
      // DNS Request => client side
      cl_buf* clb1 = cl_alloc_buf(I3_PROXY_HDR_LEN);
      idl->s.addr->state = FAKE_STATE_NEW;

      DEBUG(15,"Requesting new private trigger\n");
      pack_trigger_req(clb,&(idfakeaddr->fake_dns_req->fake_addr->prv_id));
      cl_send_to_stack(&(idfakeaddr->fake_dns_req->dns_stack), clb1);
      idfakeaddr->retry++;
      //      cl_free_buf(clb1);
    }

    return;
  }
    

  DEBUG(15, "\n FAKE_STATE_CNF");

  // if not sent MAX_TRIGGER_RETRY, try again

  if (idl->s.addr->retry > max_dns_retry)
  {
    DEBUG(10, "\n Tried to reach ID ");
    DEBUG(10, " %u times. Giving up now.", max_dns_retry);
    // aufgeben
    // false dns zurückgeben
  }
  else
  {
    DEBUG(10, "\n Tried to reach ID ");
    DEBUG(10, " %u times. Trying again.", idl->s.addr->retry);
    DEBUG(15, "\n Sending I3_PROXY_PRIVATE_TRIG_CNF to ID: ");
    if (5 <= I3_DEBUG_LEVEL) printf_i3_stack(&idl->s.addr->dest_stack,0);
    idl->s.addr->retry++;

    pack_trigger_cnf(clb,&(idl->s.addr->prv_id));
    cl_send_to_stack(&idl->s.addr->dest_stack, clb);
    idl->s.addr->state = FAKE_STATE_CNF;
    
    // usleep(200000);
    // hier unterscheiden zwischen server und client
    // bei server, nochmal versuchen
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

  insert_server_proxy_trigger();

  while(1)
  {
    FD_ZERO(&dummy);
    cl_select(0,&dummy,NULL,NULL,0);
  }
  

  pthread_exit((void *) 0);
}


