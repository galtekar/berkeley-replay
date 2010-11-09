/***************************************************************************
                          fake_mngm.h  -  description
                             -------------------
    begin                : Son Jun 22 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef FAKE_MNGM_H
#define FAKE_MNGM_H

#include "i3.h"
#include "i3_stack.h"
#include "i3_proxy.h"
#include "fake_mngm_common.h"

#define DNS_QUERY_TIMEOUT 2

typedef struct dns_query
{
  time_t time;
  uint16_t transaction_id;
  char name[MAX_DNS_NAME_LEN];
  ID *client_id;
  struct dns_query *next;
  struct dns_query *prev;
  uint32_t targetIP;
} dns_query;
    
struct fake_addr* alloc_fake_addr(char addr_type, ID *id,uint32_t);

struct fake_addr *lookup_fake_addr(i3_addr *addr);
struct fake_addr *lookup_fake_id(ID *id);

void remove_fake_addr(fake_addr* fake);
void free_fake_addr(i3_addr *addr);

void init_fake_lists();

void handle_proxy_trigger_request(ID * sender_prv_id, ID *dns_pub_id);
void handle_public_trigger_request(char * buf, ID *dns_pub_id);
void handle_proxy_trigger_confirmation(ID *sender_private_id, ID* arrival_id);

int form_dns_query(char *dns_query, char *dns_name, uint16_t transaction_id);
void insert_dns_query(struct dns_query *query);
void remove_dns_query(struct dns_query *query);
struct dns_query *lookup_dns_query(uint16_t transaction_id);
struct dns_query *lookup_dns_query_by_client_id(ID *id);

#endif

