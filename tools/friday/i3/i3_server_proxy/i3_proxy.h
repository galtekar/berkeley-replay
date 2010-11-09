/***************************************************************************
                          i3_proxy.h  -  description
                             -------------------
    begin                : Die Jan 14 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef I3_PROXY_H_
#define I3_PROXY_H_

#include <time.h>

#include "i3.h"
#include "debug.h"
#include "../i3/i3_config.h"

#define BUF_LEN 2000
#define DEFAULT_SERVER_PROXY_TRIGGER_LEN 24

#define I3_PROXY_VERSION   0x01

#define I3_PROXY_HDR_LEN   (ID_LEN + 2)

#define I3_PROXY_PRIVATE_TRIG_REQ   0x01
#define I3_PROXY_PRIVATE_TRIG_CNF   0x02
#define I3_PROXY_PRIVATE_TRIG_REMOVE   0x03
#define I3_PROXY_DATA               0x04
#define I3_PROXY_PUBLIC_TRIG_REQ   0x05
#define I3_PROXY_PUBLIC_TRIG_CNF   0x05
#define I3_PROXY_AUTH_PRIVATE_TRIG_REQ   0x06
#define I3_PROXY_FAKE_REMOVE           0x07
#define I3_PROXY_LEGACY_DNS_ERROR  0x08

#define FAKE_TYPE_CLIENT   0x01
#define FAKE_TYPE_SERVER   0x02

#define FAKE_STATE_NEW     0x00
#define FAKE_STATE_CNF     0x01
#define FAKE_STATE_OK      0x02
#define FAKE_STATE_PARTNER_DORMANT 0x03
#define FAKE_STATE_RENEW 0x04
#define FAKE_STATE_RECNF 0x05


#define ID_LIST_DNS        0x01
#define ID_LIST_ADDR       0x02

#define MAX_DNS_NAME_LEN   512

#define MAX_PACKET_SIZE    4096

#define CLOSEST_SERVER_THRESHOLD 0.9

#define CALLER_PRIVATE_TRIGGER_TIMEOUT 7200
#define CALLEE_PRIVATE_TRIGGER_TIMEOUT 120
#define FAKE_TIMEOUT 7200
#define CHECK_TIMEOUT_INTERVAL 30
#define FAKE_LOG_INTERVAL FAKE_TIMEOUT

typedef struct fake_addr
{
  struct fake_addr  *next;
  struct fake_addr  *prev;

  i3_addr           real_addr;
  i3_addr           fake_addr;

  struct fake_dns_req      *fake_dns_req;
  ID                prv_id;
  i3_trigger        *prv_trig;
  Key               prv_trig_key;

  ID                dest_id;
  i3_stack          dest_stack;

  uint16_t orig_port;

  unsigned long     num_req;
  char              state;
  char              retry;
  time_t            last_use;

   struct pkt_queue_entry *output_queue;
} fake_addr;

typedef struct pkt_queue_entry
{
  struct pkt_queue_entry *next;
  int packet_len;
  char *buf;
} pkt_queue_entry;

typedef struct real_dns_req
{
   char                    packet_data[28];
   unsigned short          id;

   // insertion time for garbage collection
   struct real_dns_req     *next;
   struct real_dns_req     *prev;
} real_dns_req;



typedef struct fake_dns_req
{
  struct fake_dns_req     *next;
  struct fake_dns_req     *prev;

  struct fake_addr        *fake_addr;
  unsigned long           num_req;

  ID                      dns_id;
  i3_stack                dns_stack;
  unsigned int            dns_packet_len;

  char                    dns_packet[BUF_LEN];
  char                    dns_name[MAX_DNS_NAME_LEN];
  //  struct fake_dns_req     *next_struct;
} fake_dns_req;


typedef struct pub_i3_dns
{
  struct pub_i3_dns    *next;
  struct pub_i3_dns    *prev;

  uint32_t ipaddr; // ip address of host which inserted the public trigger
  
  ID                   dns_id;
  i3_stack             dns_stack;
  i3_trigger           dns_trig;

  unsigned long        num_req;
  char                 dns_name[MAX_DNS_NAME_LEN];
  ID*                  confirm;
} pub_i3_dns;


typedef struct id_list
{
   ID                id;
   char              type;
   unsigned long     num_req;

   union
   {
      struct   pub_i3_dns  *dns;
      struct   fake_addr   *addr;
   }s;
   
   struct id_list    *next;
   struct id_list    *prev;
} id_list;

void insert_id_in_id_list(ID *id, char type, void *ptr);
void remove_id_from_id_list(ID *id);
struct id_list *lookup_id(ID *id);
struct id_list *lookup_dest_id(ID *id);

void  printf_id_list(FILE *handle);

void hash_ip_on_ID(struct in_addr ip_addr, ID *id);

void strlwr(char *str);
//void get_random_ID(ID *id);
void gen_private_ID(ID *id);

void print_buf(char *buf, int ret);

void proxy_fprintf_i3_id(FILE *handle, ID *id);
void fprintf_i3_addr(FILE *handle, i3_addr *addr);

void get_random_ID(ID *id);


#endif	// I3_PROXY_H_

