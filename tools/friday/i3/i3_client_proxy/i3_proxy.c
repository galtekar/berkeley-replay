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
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <netdb.h>
#include <sys/utsname.h>

#if (!defined( __CYGWIN__ ) && !defined(__APPLE__))
#include <error.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <linux/if_tun.h>
#include <netinet/if_ether.h> 
#endif

#ifdef __CYGWIN__
#include <cygwin/socket.h>
#include <w32api/windows.h>
#include <w32api/winioctl.h>
#include <w32api/iphlpapi.h>
#include <w32api/iprtrmib.h>

#define TAP_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_PHYSICAL_NETCARD | 8000, \
            request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_LASTMAC           TAP_CONTROL_CODE (0, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_SET_STATISTICS        TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (8, METHOD_BUFFERED)

#define REG_CONTROL_NET "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define REG_INTERFACES_KEY "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"

#define USERMODEDEVICEDIR "\\\\.\\"
#define TAPSUFFIX ".tap"
#endif

#include "i3.h"
#include "i3_addr.h"
#include "i3_trigger.h"

#include "i3_client_api.h"
#include "i3_client.h"
 
#include "dns_thread.h"
#include "addrbook.h"
#include "fake_mngm.h"
#include "fake_log.h"
#include "i3_proxy.h"
#include "../utils/utils.h"
#include "auth.h"
#include "../i3/i3_config.h"

#define COMMAND_LEN  256

#define PROXY_CONFIG_FILE_NAME   "i3-client-proxy.xml"

#define DEFAULT_I3_PROXY_PORT    5610
#define DEFAULT_DNS_REQUEST_PORT 55677

unsigned short  i3_proxy_port = DEFAULT_I3_PROXY_PORT;
unsigned short  dns_request_port = DEFAULT_DNS_REQUEST_PORT;   
unsigned short  max_dns_retry = 2;
unsigned short  stale_timeout = 120;
unsigned short  enable_hashed_urls = 0;

char           alternative_dns_server[MAX_CONFIG_PARM_LEN];
char    fake_addr_range_start[MAX_CONFIG_PARM_LEN]="10.0.0.1";
char           fake_addr_range_mask[MAX_CONFIG_PARM_LEN] = "255.0.0.0";

char     tun_dev_path[MAX_DNS_NAME_LEN] = "/dev/net/tun";
char     tun_dev_name[MAX_DNS_NAME_LEN] = "tun0";
char     tun_mtu[20] = "1500";
char     tun_tab_name[MAX_DNS_NAME_LEN] = "tuntab";
char     tun_dev_address[MAX_DNS_NAME_LEN] = "10.0.0.1";

char     iptables_cmd[MAX_DNS_NAME_LEN] = "/usr/sbin/iptables";
char     ip_cmd[MAX_DNS_NAME_LEN] = "/sbin/ip";

char     addrbook_fname[MAX_DNS_NAME_LEN] = "i3_addr_book.txt";

char public_key_file[MAX_DNS_NAME_LEN]="public.key";
char private_key_file[MAX_DNS_NAME_LEN]="private.key";
char *myusername;

#define CHORD_ID_LEN 20
#define DEFAULT_PREFIX_LEN 5
ID default_prefix;
int actual_prefix_len=0;

unsigned short use_ping=0;
  

struct sockaddr_in	saddr, daddr;
#ifdef __CYGWIN__
int 	               dnsfd, addrlen = sizeof(struct sockaddr);
HANDLE                 tunfd;
int                    readsp[2];
#else
int 	               tunfd, dnsfd, addrlen = sizeof(struct sockaddr);
#endif

char  pub_dns_fname[MAX_DNS_NAME_LEN] = "";
char  fake_dns_fname[MAX_DNS_NAME_LEN] = "";
char  id_list_fname[MAX_DNS_NAME_LEN] = "";
char  fake_log_fname[MAX_DNS_NAME_LEN] = "fake.log";

pthread_mutex_t mutexlog;

i3_addr           local_i3_addr;
struct in_addr    my_addr, my_addr_nf;

struct id_list *id_list_start = NULL;
struct id_list *id_list_end = NULL;

#ifdef __CYGWIN__

//
// add route information for fake addresses
//

void add_fake_route()
{
  in_addr_t fake_start_addr = inet_addr(fake_addr_range_start);
  in_addr_t mask = inet_addr(fake_addr_range_mask);
  in_addr_t tun_addr = inet_addr(tun_dev_address);
  in_addr_t tun_mask = inet_addr("255.255.255.252");
  if ((tun_addr & tun_mask) == (fake_start_addr & tun_mask)) {
    DEBUG(1, "FAKE_ADDR_RANGE_START should not be within the subnet of the tun interface\n");
    exit(-1);
  } else if ((tun_addr & mask) == (fake_start_addr & mask) && tun_addr > fake_start_addr) {
    DEBUG(1, "FAKE_ADDR_RANGE_START should be greater than TUN_DEV_ADDRESS\n");
    exit(-1);
  }

  // wait for tun_dev to be up before calling CreateIpForwardEntry
  MIB_IPFORWARDROW bestroute;
  for (;;) {
    if (GetBestRoute(tun_addr ^ (~tun_mask), 0, &bestroute) != NO_ERROR){
      DEBUG(1, "add_fake_route(): GetBestRoute failed\n");
      exit(-1);
    }
    if (bestroute.dwForwardNextHop == tun_addr)
      break;
    usleep(100000);
  }

  MIB_IPFORWARDROW route;
  memset(&route, 0, sizeof(MIB_IPFORWARDROW));
  route.dwForwardDest = fake_start_addr & mask;
  route.dwForwardMask = mask;
  route.dwForwardNextHop = tun_addr ^ (~tun_mask);
  if (GetBestInterface(route.dwForwardNextHop,
		       &route.dwForwardIfIndex) != NO_ERROR) {
    DEBUG(1, "add_fake_route(): GetBestInterface failed\n");
    exit(-1);
  }
  route.dwForwardType = 4;
  route.dwForwardProto = 3;

  if (CreateIpForwardEntry(&route) != NO_ERROR) {
    DEBUG(1, "add_fake_route(): CreateIpForwardEntry failed.\n");
    exit (-1);
  }
  return;
}

#else

/************************************************/
/**** Inits IPTables to grab packets for i3 *****/
/************************************************/

void init_iptables() 
{
  char command[COMMAND_LEN];

  sprintf(command, "%s -F -t mangle", iptables_cmd);
  system(command);
 
  sprintf(command, "%s -A OUTPUT -t mangle  -p udp --sport %u --dport 53 -j ACCEPT", iptables_cmd, dns_request_port);
  system(command);

  sprintf(command, "%s -A OUTPUT -t mangle  -p udp --dport 53 -j MARK --set-mark 1", iptables_cmd);
  system(command);

  sprintf(command, "%s -A OUTPUT -t mangle  -d %s/%s -j MARK --set-mark 1", iptables_cmd,fake_addr_range_start,fake_addr_range_mask);
  system(command);
 
  sprintf(command, "%s -A OUTPUT -t mangle -j ACCEPT", iptables_cmd);
  system(command);
 
  // ip rule add fwmark 1 table i3
  sprintf(command, "%s rule add fwmark 1 table %s", ip_cmd, tun_tab_name);
  system(command);
   
  // ip route add default table i3_mobility dev tun0
  sprintf(command, "%s route add default table %s dev %s", ip_cmd, tun_tab_name, tun_dev_name);
  system(command);   
}
#endif

/************************************************/
/* Used for changing all characters to lowercae */
/* within an URL                                */
/************************************************/

#ifndef __CYGWIN__
void strlwr(char *str)
{
  uint i, len;

  len = strlen(str);
  for(i=0; i<len; i++)
  {
    str[i] = tolower(str[i]);
  }
}
#endif

void hash_URL_on_ID(char* curl, ID *id)
{
  strlwr(curl);
  memset(id, 0, ID_LEN);
  strncpy(id->x, curl, ID_LEN);
}

void get_random_ID(ID *id)
{
  int   i;
   
  for(i=0; i < ID_LEN; i++)
  {
#ifdef __CYGWIN__
    id->x[i] = (char) (random() % 255);
#else
    id->x[i] = (char) (rand() % 255);
#endif
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
    
#ifdef __CYGWIN__
void *tunreader(void *arg)
{
  DWORD len;
  char buf[BUF_LEN];
  OVERLAPPED overlapped;

  overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

  for (;;) {
    overlapped.Offset = 0;
    overlapped.OffsetHigh = 0;
    ResetEvent(overlapped.hEvent);

    int status = ReadFile(tunfd, buf, BUF_LEN, &len, &overlapped);

    if (!status) {
      if (GetLastError() == ERROR_IO_PENDING) {
	WaitForSingleObject(overlapped.hEvent, INFINITE);
	if (!GetOverlappedResult(tunfd, &overlapped, &len, FALSE))
	  continue;
      } else {
	DEBUG(1,"tunreader: error while reading from tun device\n");
	return 0;
      }
    }
    write(readsp[0], buf, len);
  }
  return 0;
}

void write_to_tun(HANDLE tunfd, char *buf, int len)
{
  DWORD lenin;
  OVERLAPPED overlapped = {0};
  if (!WriteFile(tunfd, buf, len, &lenin, &overlapped)) 
    DEBUG(1, "Failed to write packet to tun device\n");
}

HANDLE init_tun()
{
  HANDLE hTAP32 = INVALID_HANDLE_VALUE;

  HKEY key;
  int enum_index;
  char devid[1024], devname[1024], path[1024];
  long len;

  if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_CONTROL_NET, 0, KEY_READ, &key)) {
    DEBUG(1, "Unable to read registry:\n");
    return NULL;
  }

  // search an adapter with TAPSUFFIX
  enum_index = 0;
  while (1) {
    len = sizeof(devid);
    if(RegEnumKeyEx(key, enum_index, devid, &len, 0, 0, 0, NULL) != ERROR_SUCCESS) {
      RegCloseKey(key);
      return NULL;
    }
  
    snprintf(devname, sizeof(devname), USERMODEDEVICEDIR "%s" TAPSUFFIX, devid);
    hTAP32 = CreateFile(devname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    
    if(hTAP32 != INVALID_HANDLE_VALUE) {
      RegCloseKey(key);
      CloseHandle(hTAP32);
      break;
    }
    enum_index++;
  }

  // Open TAP-Win32 device
  hTAP32 = CreateFile(devname, GENERIC_WRITE|GENERIC_READ,  0,  0,
		      OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
  if (hTAP32 == INVALID_HANDLE_VALUE) {
    DEBUG(1, "Could not open Windows tap device\n");
    return NULL;
  }

  // set TAP-Win32 device in TUN mode
  {
    in_addr_t ep[2];
    ep[0] = inet_addr(tun_dev_address);
    ep[1] = ep[0] ^ inet_addr("0.0.0.3");
    if (!DeviceIoControl (hTAP32, TAP_IOCTL_CONFIG_POINT_TO_POINT,
			  ep, sizeof (ep),
			  ep, sizeof (ep), &len, NULL)) {
      DEBUG(1, "ERROR: The TAP-Win32 driver rejected a DeviceIoControl call to set Point-to-Point mode\n");
      return 0;
    }
  }

  // address configuration
  {
    in_addr_t ep[4];
    ep[0] = inet_addr(tun_dev_address); // IP address
    ep[1] = inet_addr("255.255.255.252"); // netmask
    ep[2] = ep[0] ^ inet_addr("0.0.0.3"); // remote IP address
    ep[3] = 31536000; // DHCP lease time (1year)
    
    if (!DeviceIoControl (hTAP32, TAP_IOCTL_CONFIG_DHCP_MASQ,
			  ep, sizeof (ep),
			  ep, sizeof (ep), &len, NULL)) {
      DEBUG(1, "failed to configure addresses.\n");
      return NULL;
    }
  }
  
  ULONG status = TRUE;
  if (!DeviceIoControl (hTAP32, TAP_IOCTL_SET_MEDIA_STATUS,
			&status, sizeof (status),
			&status, sizeof (status), &len, NULL)) {
    DEBUG(1,"failed to set TAP-Win32 status as 'connected'.\n");
    return NULL;
  }
  
  Sleep(100);

  // set NameServer address on TAP-Win32 adapter
  HKEY interface_key;
  snprintf (path, sizeof(path), "%s\\%s",
	    REG_INTERFACES_KEY, devid);
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0,
		   KEY_WRITE, &interface_key) != ERROR_SUCCESS) {
    printf("Error opening registry key: %s", path);
    return NULL;
  }

  // use tunnel endpoint address for NameServer's address
  struct in_addr dns;
  char *addr_string;
  dns.s_addr = inet_addr(tun_dev_address) ^ inet_addr("0.0.0.3");
  addr_string = inet_ntoa(dns);
  if (RegSetValueEx(interface_key, "NameServer", 0, REG_SZ,
		    addr_string, strlen(addr_string)) != ERROR_SUCCESS) {
    printf("Changing TAP-Win32 adapter's NameServer failed\n");
    return NULL;
  }
  RegCloseKey(interface_key);
  
  if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, readsp)) {
    DEBUG(1, "sockpair failed\n");
    return NULL;
  }
  return hTAP32;
}
#else
int init_tun() 
{
#ifndef __APPLE__  
  struct ifreq   ifr;
#endif  
  int            tunfd;   char           command[BUF_LEN];

  system("/sbin/modprobe tun");

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
#endif

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
#ifdef __CYGWIN__
  saddr.sin_addr.s_addr = INADDR_ANY;
#else
  saddr.sin_addr = my_addr_nf;
#endif
  saddr.sin_port = htons(dns_request_port);

  memset(&daddr, 0, sizeof(struct sockaddr_in));
  daddr.sin_family =  AF_INET;
  daddr.sin_addr.s_addr = INADDR_ANY;
  daddr.sin_port = htons(53);

  if (bind(sockfd, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in)) < 0)
  {
    DEBUG(1, " Error bind source address !\n");
    return 0;
  }
  return sockfd;
}


/******************************************
 ** printf_i3_addr for printing in a file **
 ******************************************/

void fprintf_i3_addr(FILE *handle, i3_addr *addr)
{
#ifndef __CYGWIN__
  uint i;
#endif

  switch (addr->type)
  {
  case I3_ADDR_TYPE_IPv4:
    /* */
    fprintf(handle, "%s", inet_ntoa(addr->t.v4.addr));
    break;
#ifndef __CYGWIN__
  case I3_ADDR_TYPE_IPv6:
    /* */
    for (i = 0; i < sizeof(struct in6_addr); i++)
      fprintf(handle, "%02x:", addr->t.v6.addr.s6_addr[i]);
    break;
#endif
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

#ifdef __CYGWIN__
  PIP_ADAPTER_INFO pAdapterInfo;
  ULONG OutBufLen = 0;

  GetAdaptersInfo(NULL, &OutBufLen);
  pAdapterInfo = (PIP_ADAPTER_INFO)malloc(OutBufLen);
  GetAdaptersInfo(pAdapterInfo, &OutBufLen);

  PIP_ADAPTER_INFO pai = pAdapterInfo;
  while (pai) {
    if (pai->GatewayList.IpAddress.String[0] != 0) {
      ia.s_addr = ntohl(inet_addr(pai->IpAddressList.IpAddress.String));
      break;
    }
    pai = pai->Next;
  }
  free(pAdapterInfo);
#else
  ia.s_addr = ntohl(get_local_addr());
#endif
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
      else if (entry->s.addr->state == FAKE_STATE_RECNF)
	fprintf(handle, "FAKE_STATE_RECNF");
      else if (entry->s.addr->state == FAKE_STATE_NEW)
	fprintf(handle, "FAKE_STATE_NEW");
      else if (entry->s.addr->state == FAKE_STATE_RENEW)
	fprintf(handle, "FAKE_STATE_RENEW");
      else if (entry->s.addr->state == FAKE_STATE_PARTNER_DORMANT)
	fprintf(handle, "FAKE_STATE_PARTNER_DORMANT");
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

void init_config_values(char* file)
{
  read_parameters(file);

  // use_ping
  read_ushort_par("/parameters/i3_server/closest_server", &use_ping,0);

  // Start address of the range from which the fake-ip-addresses are taken
  read_string_par("/parameters/proxy/fake_addr_range/start", fake_addr_range_start,0);

  // Address mask of the range from which the fake-ip-addresses are taken
  read_string_par("/parameters/proxy/fake_addr_range/mask", fake_addr_range_mask,0);

  // UDP port of the i3-proxy
  read_ushort_par("/parameters/proxy/port", &i3_proxy_port,0);

  // Allow hashed urls?
  read_ushort_par("/parameters/proxy/enable_hashed_urls", &enable_hashed_urls,0);

  //      // Number of retries before giving up to reach a trigger
  //   read_ushort_par(fdconf, &max_dns_retry, "MAX_DNS_RETRY");
  //
  //      // Number of seconds, after that an unused i3-"connection" will be closed
  //   read_ushort_par(fdconf, &stale_timeout, "STALE_TIMEOUT");


#ifndef __CYGWIN__
  // Path and filename of the tun-device
  read_string_par("/parameters/proxy/tun/path", tun_dev_path,0);

  // tun-dev-name, e.g. 'tun0'
  read_string_par("/parameters/proxy/tun/name", tun_dev_name,0);

  // name of the routing table needed for redirecting the packet, e.g. tun_tab
  read_string_par("/parameters/proxy/tun/rt_table_name", tun_tab_name,0);

  // Path and name of iptables-command-tool
  read_string_par("/parameters/proxy/iptables_cmd", iptables_cmd,0);

  // Path and name of ip-command-tool
  read_string_par("/parameters/proxy/ip_cmd", ip_cmd,0);
#endif

  // mtu of the tun-device, should be (1500 - i3_headers)
  read_string_par("/parameters/proxy/tun/mtu", tun_mtu,0);

  // tun-dev-address, e.g. '10.0.0.1'
  read_string_par("/parameters/proxy/tun/addr", tun_dev_address,0);

  /*   if ( atoi(tun_mtu) < 1500 ) */
  /*   { */
  /*     printf("MTU not allowed to be lesser than 1500. Setting MTU to 1500.\n"); */
  /*     strcpy(tun_mtu,"1500"); */
  /*   } */

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
  
  DEBUG(10, "\n");
}

/************************************************/
/*** Registers all fake DNS names           *****/
/***                                        *****/
/************************************************/

void init_fake_dns_names()
{
  int num,i;
  char** urls = read_strings_par("/parameters/proxy/public_triggers/trigger",&num);

  for(i=0;i<num;i++)
  {
    new_pub_dns(urls[i]);
    DEBUG(1, "Added %s to the set of i3-supported DNS-names\n", urls[i]);
    free(urls[i]);
  }

  free(urls);
}

void usage(char *command)
{
  printf("Usage: %s [-h] [-f CONFIG_FILE]\n", command);
  printf("'-h': Print this help information\n");
  printf("'-a': Use specified ip-address as host-address, e.g. 141.3.70.138\n");
  printf("'-f': Use alternative proxy-config-file - default is 'i3-client-proxy.xml'\n");
  printf("'-p': Prefix to be used for private trigger identifiers (in hexa)\n");
  printf("'-c': Cold start (flush the fake log file before it starts)\n");
#ifdef __CYGWIN__
  printf("'-I [args]': Install i3_proxy as a service with optional [args]\n");
  printf("'-R': Remove i3_proxy service\n");
  printf("'-S': Start i3_proxy service\n");
  printf("'-C': Cold start i3_proxy service\n");
  printf("'-E': Stop i3_proxy service\n");
#endif
}


/************************************************/
/*** main routine of i3_proxy               *****/
/***                                        *****/
/*** initializes structures and starts threads **/
/************************************************/

#ifdef __CYGWIN__
int init_i3_proxy(int argc, char *argv[])
#else
int main(int argc, char *argv[]) 
#endif
{
  pthread_t      dns_answer_thrd, tun_input_thrd, proxy_input_thrd, status_thrd;
  char           *fname = PROXY_CONFIG_FILE_NAME;
  int            i;
  FILE           *fdlog;
  int            flush_log = 0;

#ifdef __CYGWIN__
  srandom(getpid() ^ time(0));
  umask(0000);
#else
  srand(getpid() ^ time(0));
#endif

  my_addr = get_my_addr();
  my_addr_nf.s_addr = htonl(my_addr.s_addr);
   
  if (argc > 1)
  {
    for (i = 1; i<argc; i++)
    {
      if (strcmp(argv[i], "-h") == 0)
      {
	usage(argv[0]);
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
      else if (strcmp(argv[i], "-c") == 0)
      {
	flush_log = 1;
      }
    }
  }

  DEBUG(10, "\n Proxy host address: %s\n", inet_ntoa(my_addr_nf));
      
  init_config_values(fname);
  init_addrbook(addrbook_fname);
  init_rulebook();
  init_fake_lists();
  init_i3_proxy_context();
  init_fake_dns_names();

  crypto_init();
  myusername = read_in_private_key(private_key_file);
  read_in_public_keys(public_key_file);

  if (flush_log != 1) {
    fdlog = fopen(fake_log_fname, "r");
    if (fdlog == NULL) {
      DEBUG(1, "Could not open fake_log_file %s. Skip loading fake info\n", fake_log_fname);
    } else {
      load_fake_log(fdlog);
      fclose(fdlog);
    }
  }

  fdlog = fopen(fake_log_fname, "w");
  if (!fdlog) {
    DEBUG(1, " Error opening fake_log_file !\n");
    exit(-1);
  }
  refresh_fake_log(fdlog);
  fclose(fdlog);

  pthread_mutex_init(&mutexlog, NULL);

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

#ifdef __CYGWIN__
  add_fake_route();
  DEBUG(15, " Initialized IP route for grabbing packets...\n");
#else
  init_iptables();
  DEBUG(15, " Initialized iptables for grabbing packets...\n");
#endif

#ifdef __CYGWIN__
  pthread_t tunreader_thrd;
  if (pthread_create(&tunreader_thrd, NULL, tunreader, NULL)) {
    DEBUG(1,"error creating tunreader thread\n");
    exit(0);
  }
  DEBUG(1, " Initialized tunreader thread\n");
#endif
   
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

#ifdef __CYGWIN__
  pthread_join(tunreader_thrd, NULL);
#endif
  pthread_join(status_thrd, NULL);
  pthread_join(proxy_input_thrd, NULL);
  pthread_join(dns_answer_thrd, NULL);
  pthread_join(tun_input_thrd, NULL);

  crypto_exit();

#ifdef __CYGWIN__
  return 0;
#else
  exit(0);
#endif
}
