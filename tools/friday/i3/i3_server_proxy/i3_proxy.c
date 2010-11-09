/***************************************************************************
                          i3_proxy.c  -  description
                             -------------------
    begin                : Die Jan 14 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#ifndef __APPLE__
#include <error.h>
#endif
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#ifndef __APPLE__
#include <linux/if_tun.h>
#endif
#include <netinet/if_ether.h> 
#include <signal.h>
#include <netdb.h>
#include <sys/utsname.h>

#include "i3.h"
#include "i3_addr.h"
#include "i3_trigger.h"

#include "i3_client_api.h"
#include "i3_client.h"
 
#include "dns_thread.h"
#include "fake_mngm.h"
#include "fake_log.h"
#include "i3_proxy.h"
#include "../utils/utils.h"
#include "auth.h"


#define COMMAND_LEN  256

#define PROXY_CONFIG_FILE_NAME   "i3-server-proxy.xml"

#define DEFAULT_I3_PROXY_PORT    5610
#define DEFAULT_DNS_REQUEST_PORT 55677

unsigned short  i3_proxy_port = DEFAULT_I3_PROXY_PORT;
unsigned short  dns_request_port = DEFAULT_DNS_REQUEST_PORT;   
unsigned short  max_dns_retry = 3;
unsigned short  stale_timeout = 120;


char           alternative_dns_server[MAX_CONFIG_PARM_LEN];
char    fake_addr_range_start[MAX_CONFIG_PARM_LEN]="10.0.0.2";
char fake_addr_range_mask[MAX_DNS_NAME_LEN]="255.0.0.0";

char     tun_dev_path[MAX_DNS_NAME_LEN] = "/dev/net/tun";
char     tun_dev_name[MAX_DNS_NAME_LEN] = "tun0";
char     tun_mtu[20] = "1500";
char     tun_tab_name[MAX_DNS_NAME_LEN] = "tuntab";
char     tun_dev_address[MAX_DNS_NAME_LEN] = "10.0.0.1";

struct sockaddr_in dns_server_addr;

char     iptables_cmd[MAX_DNS_NAME_LEN] = "/usr/sbin/iptables";
char     ip_cmd[MAX_DNS_NAME_LEN] = "/sbin/ip";
char     route_cmd[MAX_DNS_NAME_LEN] = "/sbin/route";

#define CHORD_ID_LEN 20
#define DEFAULT_PREFIX_LEN 5
ID default_prefix;
int actual_prefix_len=0;
unsigned short use_ping=0;

ID     anycast_public_trigger, unicast_public_trigger;
Key     anycast_trigger_key, unicast_trigger_key;

struct sockaddr_in	saddr, daddr;
int 	               tunfd, dnsfd, addrlen = sizeof(struct sockaddr);

char  pub_dns_fname[MAX_DNS_NAME_LEN] = "";
char  fake_dns_fname[MAX_DNS_NAME_LEN] = "";
char  id_list_fname[MAX_DNS_NAME_LEN] = "";

char  fake_log_fname[MAX_DNS_NAME_LEN] = "fake.log";
pthread_mutex_t mutexlog;

char public_key_file[MAX_DNS_NAME_LEN];
char private_key_file[MAX_DNS_NAME_LEN];
char *myusername;

i3_addr           local_i3_addr;
struct in_addr    my_addr, my_addr_nf;

struct id_list *id_list_start = NULL;
struct id_list *id_list_end = NULL;



/************************************************/
/**** Inits IPTables to grab packets for i3 *****/
/************************************************/

void init_iptables() 
{
  char command[COMMAND_LEN];
  char* myip;
  
  sprintf(command, "%s -F -t mangle", iptables_cmd);
  system(command);

  sprintf(command, "%s -F -t nat", iptables_cmd);
  system(command);

  sprintf(command,"echo 1 > /proc/sys/net/ipv4/ip_forward");
  system(command);
 
  local_i3_addr.t.v4.addr.s_addr = ntohl(local_i3_addr.t.v4.addr.s_addr);
  myip = inet_ntoa(local_i3_addr.t.v4.addr);
  local_i3_addr.t.v4.addr.s_addr = htonl(local_i3_addr.t.v4.addr.s_addr);

/*   sprintf(command,"%s -t mangle -A PREROUTING -i ! %s --dest ! %s -j DROP",iptables_cmd,tun_dev_name,myip); */
/*   printf("Command: %s\n",command); */
/*   system(command); */

  sprintf(command,"%s -t nat -A POSTROUTING --source 127.0.0.1 -j ACCEPT",iptables_cmd); 
  printf("Command: %s\n",command);
  system(command);

  sprintf(command,"%s -t nat -A POSTROUTING --source ! %s -j SNAT --to-source %s",iptables_cmd,myip,myip);
  printf("Command: %s\n",command);
  system(command);

  {
    struct in_addr route;
    route.s_addr = inet_addr(tun_dev_address) & inet_addr(fake_addr_range_mask);
    char *fake_addr_route = inet_ntoa(route);
    
    sprintf(command, "%s add -net %s netmask %s dev %s", route_cmd, fake_addr_route,
	    fake_addr_range_mask, tun_dev_name);
    printf("Command: %s\n",command);
    system(command);
  }
   
  // ip route add default table i3_mobility dev tun0 
  sprintf(command, "%s route add default table %s dev %s", ip_cmd, tun_tab_name, tun_dev_name);
  printf("Command: %s\n",command);
  system(command); 
}


/************************************************/
/* TODO: use a better hash function H to        */
/* compute the public trigger identifier        */
/************************************************/


void hash_ip_on_ID(struct in_addr ip_addr, ID *id)
{
  uint i;

  for (i = 0; i < ID_LEN / (sizeof(ip_addr)); i++)
  {
    memcpy(id->x + i*sizeof(ip_addr), &ip_addr, sizeof(ip_addr));
  }
}



/************************************************/
/* Used for changing all characters to lowercae */
/* within an URL                                */
/************************************************/

void strlwr(char *str)
{
   uint i, len;

   len = strlen(str);
   for(i=0; i<len; i++)
   {
      str[i] = tolower(str[i]);
   }
}

void get_random_ID(ID *id)
{
   int   i;
   
   for(i=0; i < ID_LEN; i++)
   {
      id->x[i] = (char) (rand() % 255);
   }
}

void update_prefix()
{
  ID new_closest;
  uint64_t new_closest_rtt,cur_closest_rtt;
  int n=1;

  assert(cl_get_top_k_ids(&n,&new_closest, &new_closest_rtt) == CL_RET_OK);

  // no prefix set yet
  if ( !actual_prefix_len )
  {
    actual_prefix_len = CHORD_ID_LEN;
    init_i3_id(&default_prefix,&new_closest);
    return;
  }
  
  assert(cl_get_rtt_id(&default_prefix,&cur_closest_rtt) == CL_RET_OK);

  if ( new_closest_rtt < ((float) CLOSEST_SERVER_THRESHOLD * (float) cur_closest_rtt) )
    init_i3_id(&default_prefix,&new_closest);
  
}


void gen_private_ID(ID *id)
{
  int i;

  get_random_ID(id);
  set_private_id(id);

  if ( use_ping )
    update_prefix();

  if ( actual_prefix_len )
  {
    
    for (i = 0; i < DEFAULT_PREFIX_LEN; i++)
      id->x[i] = default_prefix.x[i];

    for(i = (DEFAULT_PREFIX_LEN-1); i>=0;i--)
    {
      if ( id->x[i] != 0)
      {
	id->x[i]--;
	break;
      }
      else
	id->x[i] = 0xff;
    }
  }

}

    
/************************************************/
/**** Opening tun-device                   ******/
/************************************************/  
    
int init_tun() 
{
#ifndef __APPLE__    
  struct ifreq   ifr;
#endif
  int            tunfd;   char           command[BUF_LEN];
   
  if ((tunfd = open(tun_dev_path, O_RDWR)) < 0)
  {
    DEBUG(1, "Opening %s failed ! \n", tun_dev_path);
    close(tunfd);
    return 0;
  }

#ifndef __APPLE__
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, tun_dev_name, 4);
  if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0)
  {
    close(tunfd);
    return 0;
  }
#endif

  sprintf(command, "/sbin/ifconfig %s %s pointopoint %s mtu %s up", tun_dev_name, tun_dev_address, tun_dev_address, tun_mtu);
  system(command);

  return tunfd;
}


/************************************************/
/**** Print hexdump of a received IP packet *****/
/****    answer_dns_query                                   *****/
/**** (Assumes no IP options are present    *****/
/************************************************/

void print_buf(char *buffer, int n) 
{
   char  *iphead;

   /* Check to see if the packet contains at least
    * complete Ethernet (14), IP (20) and TCP/UDP
    * (8) headers.
    */

   iphead = buffer;
   if (*iphead==0x45)
   {  /* Double check for IPv4
       * and no options present */
      DEBUG(5, "IP SA: %u.%u.%u.%u ",
          (unsigned char) iphead[12], (unsigned char) iphead[13],
          (unsigned char) iphead[14], (unsigned char) iphead[15]);
      DEBUG(5, "DA: %u.%u.%u.%u ",
          (unsigned char) iphead[16], (unsigned char) iphead[17],
          (unsigned char) iphead[18], (unsigned char) iphead[19]);
      DEBUG(5, "SP: %u DP: %u ",
          (unsigned short) ((iphead[20]<<8)+iphead[21]),
          (unsigned short) ((iphead[22]<<8)+iphead[23]));
      if (iphead[9] == 1)
      {
         DEBUG(5, "L4: ICMP\n");
      }
      else if (iphead[9] == 6)
      {
         DEBUG(5, "L4: TCP\n");
      }
      else if (iphead[9] == 17)
      {
         DEBUG(5, "L4: UDP\n");
      }
      else if (iphead[9] == 2)
      {
         DEBUG(5, "L4: IGMP\n");
      }
      else
      {
         DEBUG(5, "L4 protocol: %u\n", (unsigned char) iphead[9]);
      }
   }
}


/************************************************/
/**** Init DNS answering socket              ****/
/************************************************/

int init_dns_socket() 
{
   int   sockfd;

   if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
   {
      DEBUG(1, " Error opening socket !\n");
      return 0;
   }

   memset(&saddr, 0, sizeof(struct sockaddr_in));
   saddr.sin_family =  AF_INET;
   saddr.sin_addr = my_addr_nf;
   saddr.sin_port = htons(dns_request_port);

   memset(&daddr, 0, sizeof(struct sockaddr_in));
   daddr.sin_family =  AF_INET;
   daddr.sin_addr.s_addr = INADDR_ANY;
   daddr.sin_port = htons(53);

   if (bind(sockfd, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in)) < 0)
   {
      DEBUG(1, " Error bind dns source address !\n");
      return 0;
   }
   return sockfd;
}


/******************************************
 ** printf_i3_addr for printing in a file **
 ******************************************/

void fprintf_i3_addr(FILE *handle, i3_addr *addr)
{
  uint i;

  switch (addr->type)
  {
  case I3_ADDR_TYPE_IPv4:
    /* */
    fprintf(handle, "%s", inet_ntoa(addr->t.v4.addr));
    break;
  case I3_ADDR_TYPE_IPv6:
    /* */
    for (i = 0; i < sizeof(struct in6_addr); i++)
      fprintf(handle, "%02x:", addr->t.v6.addr.s6_addr[i]);
    break;
  }
}


/******************************************
 ** printf_i3_id for printing in a file **
 ******************************************/

void proxy_fprintf_i3_id(FILE *handle, ID *id)
{
  uint i;


  for (i = 0; i < sizeof(ID); i++)
    fprintf(handle, "%02X", (int)(id->x[i]));
}



/************************************************/
/*** Returns the ip-address of this host     ****/
/************************************************/

struct in_addr get_my_addr()
{
  struct in_addr ia;
  ia.s_addr = ntohl(get_local_addr());
  return ia;

}



/************************************************/
/*** Inserts id_list-struct with 'id' into   ****/
/*** the ID-hash-table                       ****/
/***                                         ****/
/*** ptr points to an pub_i3_dns-struct or   ****/
/*** a fake_addr-struct. Which type is       ****/
/*** specified by the type-parameter         ****/
/*** (ID_LIST_DNS or ID_LIST_ADDR)           ****/
/************************************************/


void insert_id_in_id_list(ID *id, char type, void *ptr)
{
   struct id_list    *id_list;


   if (lookup_id(id))
   {
         DEBUG(15, " ID is already in the list\n");
         return;
   }
   
   /* XXX: just simply call alloc for now; preallocate a pool of buffers
      in the future */
   id_list = (struct id_list *) malloc( sizeof(struct id_list) );
   if (id_list)
   {
      memset(id_list, 0, sizeof(struct id_list));

      memcpy(&id_list->id, id, sizeof(ID));

      if (type == ID_LIST_DNS)
      {
         id_list->type = ID_LIST_DNS;
         id_list->s.dns =  ptr;
      }
      else if (type == ID_LIST_ADDR)
      {
         id_list->type = ID_LIST_ADDR;
         id_list->s.addr =  ptr;
      }
      else
      {
         DEBUG(1, " Error: no or wrong type specified in insert_id_in_id_list()\n");
         return;
      }

         // TODO: Insert structure in a hash-table based on id_list
      id_list->next = id_list_start;
      id_list->prev = NULL;

      if (id_list->next)
         id_list->next->prev = id_list;
      else
         id_list_end = id_list;

      id_list_start = id_list;
   }
   else
   {
      DEBUG(1, " FATAL ERROR: memory allocation error in insert_id_in_id_list()\n");
      return;
   }
}


/************************************************/
/*** Removes id_list-struct with 'id' from   ****/
/*** the ID-hash-table                       ****/
/***                                         ****/
/************************************************/


void remove_id_from_id_list(ID *id)
{
   struct id_list   *id_list;


   id_list = lookup_id(id);
   if (id_list == NULL)
   {
      DEBUG(5, " ID not found in id-list.\n");
      return;
   }

   if (id_list == id_list_start)
      id_list_start = id_list->next;
   else
      id_list->prev->next = id_list->next;

   if (id_list == id_list_end)
      id_list_end = id_list->prev;
   else
      id_list->next->prev = id_list->prev;

   free(id_list);
}



/************************************************/
/*** Searches an id in the ID-hash-table     ****/
/*** An ID is either a pub_i3_dns-struct or  ****/
/*** a fake_addr-struct                      ****/
/***                                         ****/
/*** returns NULL if id is not found         ****/
/*** returns pointer to id_list-struct if found */
/************************************************/

struct id_list *lookup_id(ID *id)
{
   struct id_list *list = id_list_start;

   while(list)
   {
      if (memcmp(&list->id, id, ID_LEN) == 0)
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



struct id_list *lookup_dest_id(ID *id)
{
   struct id_list    *idl = id_list_start;

   while(idl)
   {
      if ((idl->type == ID_LIST_ADDR) && (memcmp(&idl->s.addr->dest_id, id, ID_LEN) == 0))
      {
         idl->num_req++;
         return idl;
      }
      else
      {
         idl = idl->next;
      }
   }
   return NULL;
}



/************************************************/
/*** Outputs all entries in the id_list-hash ****/
/***                                         ****/
/************************************************/


void  printf_id_list(FILE *handle)
{
   struct id_list  *entry;
   int             i = 0;
   time_t          now;


   time(&now);

   fprintf(handle, "\n List and type of all currently IDs used by i3-proxy:");
   fprintf(handle, "\n======================================================\n");
   fprintf(handle, "\n logged at: %s", ctime(&now));
   fprintf(handle, "\n");   


   entry = id_list_start;

   while(entry)
   {
      fprintf(handle, "\n Entry %02u: ID: ", i);

      proxy_fprintf_i3_id(handle, &entry->id);

      fprintf(handle, ", Requests: %lu", entry->num_req);

      fprintf(handle, "\n           Type: ");

      if (entry->type == ID_LIST_DNS)
      {
         fprintf(handle, " ID_LIST_DNS, URL = %s, Requests: %lu",
                         entry->s.dns->dns_name, entry->s.dns->num_req);
      }
      else if (entry->type == ID_LIST_ADDR)
      {
         fprintf(handle, " ID_LIST_ADDR  state = ");
         if (entry->s.addr->state == FAKE_STATE_OK)
            fprintf(handle, "FAKE_STATE_OK");
         else if (entry->s.addr->state == FAKE_STATE_CNF)
            fprintf(handle, "FAKE_STATE_CNF");
         else if (entry->s.addr->state == FAKE_STATE_NEW)
            fprintf(handle, "FAKE_STATE_NEW");
         else
            fprintf(handle, "%u", entry->s.addr->state);

         fprintf(handle, "\n           Real address: "); fprintf_i3_addr(handle, &entry->s.addr->real_addr);
         fprintf(handle, "\n           Fake address: "); fprintf_i3_addr(handle, &entry->s.addr->fake_addr);

         fprintf(handle, "\n           Private ID: "); proxy_fprintf_i3_id(handle, &entry->s.addr->prv_id);
         fprintf(handle, "\n           Destin. ID: "); proxy_fprintf_i3_id(handle, &entry->s.addr->dest_id);
         fprintf(handle, "\n           Requests: %lu", entry->s.addr->num_req);
         fprintf(handle, ", last use: %s", ctime(&entry->s.addr->last_use));
      }
      
      fprintf(handle, "\n");

      entry = entry->next;
      i++;
   }

   fprintf(handle, "\n");
}




/************************************************/
/*** initializes the i3-context of the proxy ****/
/***                                         ****/
/************************************************/

void init_i3_proxy_context()
{
   cl_init(&my_addr, i3_proxy_port);
   init_i3_addr_ipv4(&local_i3_addr, my_addr, i3_proxy_port);
}

void convert_str_to_hex(char* source,ID* id)
{
  int i;
  char num[3];
  
  if ( strlen(source) % 2 )
    strcat(source,"0");

  for(i=0;i<ID_LEN;i++)
    id->x[i]=0;
  
  for(i=0;i<strlen(source);i+=2)
  {
    num[0] = source[i];
    num[1] = source[i+1];
    num[2] = 0;
    id->x[i/2] =  (unsigned char)strtol(num, NULL, 16);
  }
}

void convert_str_to_hex_key(char* source,Key* id)
{
  int i;
  char num[3];
  
  if ( strlen(source) % 2 )
    strcat(source,"0");

  for(i=0;i<KEY_LEN;i++)
    id->x[i]=0;
  
  for(i=0;i<strlen(source);i+=2)
  {
    if ( (i/2) >= KEY_LEN )
      break;
    
    num[0] = source[i];
    num[1] = source[i+1];
    num[2] = 0;
    id->x[i/2] =  (unsigned char)strtol(num, NULL, 16);
  }
}

/************************************************/
/*** reads parameters from config file      *****/
/***                                        *****/
/************************************************/

void init_config_values(char* fname)
{
  char beforeconv[2*ID_LEN+1];

  read_parameters(fname);

  // use_ping 
  read_ushort_par("/parameters/i3_server/closest_server", &use_ping,0);

  // Start address of the range from which the fake-ip-addresses are taken
  read_string_par("/parameters/proxy/fake_addr_range/start", fake_addr_range_start,0);

  // Address mask of the range from which the fake-ip-addresses are taken
  read_string_par("/parameters/proxy/fake_addr_range/mask", fake_addr_range_mask,0);

  // UDP port of the i3-proxy
  read_ushort_par("/parameters/proxy/port", &i3_proxy_port,0);

  //      // Number of retries before giving up to reach a trigger
  //   read_ushort_par(fdconf, &max_dns_retry, "MAX_DNS_RETRY");
  //
  //      // Number of seconds, after that an unused i3-"connection" will be closed
  //   read_ushort_par(fdconf, &stale_timeout, "STALE_TIMEOUT");

  // Path and filename of the tun-device
  read_string_par("/parameters/proxy/tun/path", tun_dev_path,0);

  // tun-dev-name, e.g. 'tun0'
  read_string_par("/parameters/proxy/tun/name", tun_dev_name,0);

  // tun-dev-address, e.g. '10.0.0.1'
  read_string_par("/parameters/proxy/tun/addr", tun_dev_address,0);

  // name of the routing table needed for redirecting the packet, e.g. tun_tab
  read_string_par("/parameters/proxy/tun/rt_table_name", tun_tab_name,0);

  // mtu of the tun-device, should be (1500 - i3_headers)
  read_string_par("/parameters/proxy/tun/mtu", tun_mtu,0);

  // Path and name of iptables-command-tool
  read_string_par("/parameters/proxy/iptables_cmd", iptables_cmd,0);

  // Path and name of ip-command-tool
  read_string_par("/parameters/proxy/ip_cmd", ip_cmd,0);

  // filename and path for the pub_dns-status-file, e.g. '/tmp/pub_dns'
  read_string_par("/parameters/proxy/status_files/pub_dns", pub_dns_fname,0);

  // filename and path for the pub_dns-status-file, e.g. '/tmp/fake_dn'
  read_string_par("/parameters/proxy/status_files/fake_dns", fake_dns_fname,0);

  // filename and path for the pub_dns-status-file, e.g. '/tmp/pub_dns'
  read_string_par("/parameters/proxy/status_files/id_list",id_list_fname,0);

  // filename and path for the fake status log file, e.g. '/tmp/fake.log'
  read_string_par("/parameters/proxy/fake_log", fake_log_fname,0);

  read_string_par("/parameters/proxy/authentication/public_key_file",public_key_file,0);
  read_string_par("/parameters/proxy/authentication/private_key_file",private_key_file,0);

  {
    char *id_str,*key_str;
    char* find;
    Key key;

    read_string_par("/parameters/proxy/anycast_trigger",beforeconv,1);
    id_str = strtok_r(beforeconv," ",&find);
    key_str = strtok_r(NULL," ",&find);

    if ( key_str == NULL )
    {
      DEBUG(1,"No key for server proxy anycast trigger\n");
      exit(-1);
    }

    if ( (strlen(id_str) / 2) > DEFAULT_SERVER_PROXY_TRIGGER_LEN ) {
      printf("Too many bytes for SERVER_PROXY_TRIGGER");
      exit(-1);
    }

    convert_str_to_hex(id_str,&anycast_public_trigger);
    convert_str_to_hex_key(key_str,&anycast_trigger_key);

    read_string_par("/parameters/proxy/unicast_trigger",beforeconv,1);
    id_str = strtok_r(beforeconv," ",&find);
    key_str = strtok_r(NULL," ",&find);

    if ( key_str == NULL )
    {
      DEBUG(1,"No key for server proxy unicast trigger\n");
      exit(-1);
    }

    convert_str_to_hex(id_str,&unicast_public_trigger);
    convert_str_to_hex_key(key_str,&unicast_trigger_key);

  }
  

  
  

  DEBUG(10, "\n");
}



/************************************************/
/*** main routine of i3_proxy               *****/
/***                                        *****/
/*** initializes structures and starts threads **/
/************************************************/

int main(int argc, char *argv[]) 
{
  pthread_t      dns_answer_thrd, tun_input_thrd, proxy_input_thrd, status_thrd;
  char           *fname = PROXY_CONFIG_FILE_NAME;
  int            i;
  FILE           *resolvconf;
  FILE           *fdlog;
  int            flush_log = 0;

  srand(getpid() ^ time(0));

  my_addr = get_my_addr();
  my_addr_nf.s_addr = htonl(my_addr.s_addr);

   
  if (argc > 1)
  {
    for (i = 1; i<argc; i++)
    {
      if (strcmp(argv[i], "-h") == 0)
      {
	printf("Usage: %s [-h] [-f CONFIG_FILE]\n", argv[0]);
	printf("'-h': Printd this help information\n");
	printf("'-a': Use specified ip-address as host-address, e.g. 141.3.70.138\n");
	printf("'-f': Use alternative proxy-config-file - default is 'i3-proxy.conf'\n");
	printf("'-p': Prefix to be used for private trigger identifiers (in hexa)\n");
	printf("'-c': Cold start (flush the fake log file before it starts)\n");
	exit(0);
      }
      else if (strcmp(argv[i], "-f") == 0)
      {
	fname = argv[i+1];
	i++;
      }
      else if (strcmp(argv[i], "-a") == 0)
      {
	my_addr_nf.s_addr = inet_addr(argv[i+1]);
	my_addr.s_addr = htonl(my_addr_nf.s_addr);
	i++;
      } 
      else if (strcmp(argv[i], "-c") == 0)
      {
	flush_log = 1;
      }
      else if (strcmp(argv[i], "-p") == 0)
      {
	int idx, k;
	char num[2*sizeof(char) + 1];
	     
	idx = 0;
	for (k = 0; k < ID_LEN; k++) {
	  /* copy and convert one byte at a time */
	  if (idx == strlen(argv[i+1]))
	    break;
	  num[0] = argv[i+1][idx];
	  idx++;
	  if (idx < strlen(argv[i+1]))
	    num[1] = argv[i+1][idx];
	  else
	    num[1] = '0';
	  num[2] = 0;
	  // printf("idx=%d %s", idx, num); 
	  default_prefix.x[k] = (unsigned char)strtol(num, NULL, 16);
	  // printf(", num = %02x\n", default_prefix[k]);
	  if (idx == strlen(argv[i+1]))
	    break;
	  idx++;
	}

	for(;k<ID_LEN;k++)
	  default_prefix.x[k] = 0;
	
	actual_prefix_len = ((strlen(argv[i+1])) >> 1) + (strlen(argv[i+1]) & 0x1);
	
	if ( strlen(argv[i+1]) != 2 * CHORD_ID_LEN )
	{
	  DEBUG(1,"Prefix for private triggers should be entire ChordID: %d bytes long\n",(int) CHORD_ID_LEN);
	  exit(-1);
	}
	
	i++;
	
      }
    }
  }

  DEBUG(10, "\n Proxy host address: %s\n", inet_ntoa(my_addr_nf));
      
  init_config_values(fname);
  init_fake_lists();
  init_i3_proxy_context();
  
  crypto_init();
  myusername = read_in_private_key(private_key_file);
  read_in_public_keys(public_key_file);

  resolvconf = fopen("/etc/resolv.conf", "r");
  if (!resolvconf) {
    printf(" Could not open /etc/resolv.conf.\n");
    exit(-1);
  } else {
    char addr_string[MAX_DNS_NAME_LEN];
    char buf[BUF_LEN], *ptr;
    dns_server_addr.sin_family = AF_UNSPEC;
    while (fgets(buf, BUF_LEN, resolvconf) != NULL) {
      ptr = strtok(buf, " \t");
      if (strcmp(ptr, "nameserver") == 0) {
	ptr = strtok(NULL, " ");
	strcpy(addr_string, ptr);
	dns_server_addr.sin_family = AF_INET;
	dns_server_addr.sin_addr.s_addr = inet_addr(addr_string);
	dns_server_addr.sin_port = htons(53);
	break;
      }
    }
    fclose(resolvconf);
    if (dns_server_addr.sin_family == AF_UNSPEC) {
      printf("Could not find any nameserver in /etc/resolv.conf\n");
      exit(-1);
    }
  }

  if (flush_log != 1) {
    fdlog = fopen(fake_log_fname, "r");
    if (fdlog == NULL) {
      DEBUG(1, "Could not open fake_log_file %s. Skip loading fake info\n", fake_log_fname);
    } else {
      load_fake_log(fdlog);
      fclose(fdlog);
    }
  }

  {
    FILE *fd = fopen("id_list_new", "w");
    printf_id_list(fd);
    fclose(fd);
  }

  fdlog = fopen(fake_log_fname, "w");
  if (!fdlog) {
    DEBUG(1, " Error opening fake_log_file !\n");
    exit(-1);
  }
  refresh_fake_log(fdlog);
  fclose(fdlog);


  dnsfd = init_dns_socket();

  if (dnsfd)
  {
    DEBUG(15, " Created Socket for DNS Requests...\n");
  }
  else
  {
    perror("DNS");
    DEBUG(1, " Error createing Socket for DNS Requests !\n");
    exit(-1);
  }

  tunfd = init_tun();
  if (tunfd)
  {
    DEBUG(15, " Initialized Tunnel Device for i3-Proxy\n");
  }
  else
  {
    DEBUG(1, " Error initializing Tunnel Device for i3-Proxy !\n");
    exit(-1);
  }

  init_iptables();

  DEBUG(15, " Initialized iptables for grabbing packets...\n");

  if (pthread_create(&dns_answer_thrd, NULL, dns_answer_thread, (void *) NULL))
  {
    DEBUG(1, " Error creating dns_thread !\n");
  }

  if (pthread_create(&tun_input_thrd, NULL, tun_input_thread, (void *) NULL))
  {
    DEBUG(1, "Error creating tun_input_thread !\n");
  }

  if (pthread_create(&proxy_input_thrd, NULL, proxy_input_thread, (void *) NULL))
  {
    DEBUG(1, "Error creating proxy_input_thread !\n");
  }

  if (pthread_create(&status_thrd, NULL, status_thread, (void *) NULL))
  {
    DEBUG(1, "Error creating status_thread !\n");
  }

  pthread_join(status_thrd, NULL);
  pthread_join(proxy_input_thrd, NULL);
  pthread_join(dns_answer_thrd, NULL);
  pthread_join(tun_input_thrd, NULL);

  crypto_exit();
   
  exit(0);
}
