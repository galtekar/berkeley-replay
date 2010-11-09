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
#include <sys/ioctl.h>
#include <net/if.h>

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

extern unsigned short srv_port;


int is_id_local(ID *id,srv_context* ctx)
{
    chordID key;
  
    memmove(key.x, id, CHORD_ID_BITS/8 * sizeof(char));
    return chord_is_local(&key);

}

struct in_addr get_my_addr()
{
#if 0	// geels: remove gethostbyname for now
  struct hostent *hptr;
  struct utsname myname;
  char str[INET6_ADDRSTRLEN];
  struct sockaddr_in servaddr;

  uint32_t addr;
  addr = get_local_addr();
  servaddr.sin_addr.s_addr = ntohl(addr);
  return servaddr.sin_addr;
  
  if (uname(&myname) < 0) {
    err_sys("uname error.\n");
    exit(-1);
  }

  if ((hptr = gethostbyname(myname.nodename)) == NULL) {
    err_sys("gethostbyname error\n");
    exit(-1);
  }

  /* get host address -- it has to be an easier way to do it! */
  inet_ntop(hptr->h_addrtype, *(hptr->h_addr_list), str, sizeof(str));
  if (inet_pton(AF_INET, str, &servaddr.sin_addr) < 0)
    err_sys("inet_pton error\n");

  /* convert addres in host format, as inet_pto returns network format */
  servaddr.sin_addr.s_addr = ntohl(servaddr.sin_addr.s_addr);
  return servaddr.sin_addr;
#else	// copied from chord/hosts.c:get_local_addr_eth()
  int i, tempfd;
  struct sockaddr_in addr;
#define IFNAME_LEN		256
#define MAX_NUM_INTERFACES	3  
  char ifname[IFNAME_LEN];
  struct ifreq ifr;		
  
  for (i = 0; i < MAX_NUM_INTERFACES; i++) {
    sprintf(ifname, "eth%d", i);
    strcpy(ifr.ifr_name, ifname);
    printf("calling hosts.c:socket\n");
    tempfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (-1 != ioctl(tempfd, SIOCGIFFLAGS, (char *)&ifr)) {
      if (0 != (ifr.ifr_flags & IFF_UP)) {
	if (-1 != ioctl(tempfd, SIOCGIFADDR, (char *)&ifr)) {
	  addr = *((struct sockaddr_in *) &ifr.ifr_addr);
	  return addr.sin_addr;
	}
      }
    }
  }
  // Nothing worked.  Just return trivial answer.
#define TRIVIAL_LOCAL_ADDR	"127.0.0.1"  
  if( 0 == inet_aton( TRIVIAL_LOCAL_ADDR, &(addr.sin_addr) ) ) {
    err_sys("inet_aton error" );
  }
  addr.sin_addr.s_addr = ntohl(addr.sin_addr.s_addr);
  return addr.sin_addr;
#endif
}

i3_option *create_i3_option_req_cache()
{
    i3_option	*opt;

    opt = alloc_i3_option();
    init_i3_option(opt, I3_OPT_REQUEST_FOR_CACHE, NULL);
    return opt;
}

i3_option *create_i3_option_sender(srv_context *ctx)
{
    i3_option	*opt;
    i3_addr	*addr;

    addr = alloc_i3_addr();
    init_i3_addr_ipv4(addr, ctx->local_ip_addr, ntohs(ctx->local.sin_port));
    
    opt = alloc_i3_option();
    init_i3_option(opt, I3_OPT_SENDER, (void *)addr);
    return opt;
}


/***************************************************************************
 *
 * Purpose: Pop and replace hdr->stack
 *
 * Return: true if number of ids does not grow beyond I3_MAX_STACK_LEN
 *
 **************************************************************************/
i3_header *replace_stack(i3_header *hdr, i3_addr *to)
{
    unsigned short	to_stack_len, hdr_stack_len;
    
    i3_header 		*new_hdr = alloc_i3_header();
    i3_stack		*new_stack = alloc_i3_stack();
    i3_option_list	*new_option_list;

    new_option_list = duplicate_i3_option_list(hdr->option_list);
    
    /* check if new stack is permissible */
    new_stack->len = hdr->stack->len + to->t.stack->len - 1;
    if (new_stack->len > I3_MAX_STACK_LEN) {
	printf("cannot have more than %d triggers in a stack!\n",
		I3_MAX_STACK_LEN);
	return NULL;
    }

    /* pack new_stack */
    new_stack->ids = (ID *)malloc(sizeof(ID) * new_stack->len);

    to_stack_len = (to->t.stack->len) * sizeof(ID);
    memcpy((char *)new_stack->ids, (char *)to->t.stack->ids, to_stack_len);
    
    hdr_stack_len = (hdr->stack->len - 1) * sizeof(ID);
    memcpy((char *)new_stack->ids + to_stack_len,
	    (char *)&hdr->stack->ids[1], hdr_stack_len);
    
    /* setup new header */
    init_i3_header(new_hdr, hdr->flags, new_stack, new_option_list);

    return new_hdr;
}


/* NAT ADDITION */
/* rewrite ip address */
void nat_translate_sender_ip_option(char* option,i3_addr* to_addr)
{
  unsigned short len;
  // translate all ips to to_addr
  assert (*(option+1) == I3_ADDR_TYPE_IPv4);
  pack_i3_addr(option+1,to_addr,&len);
  //assert(len == sizeof(unsigned short) + sizeof(unsigned int) + 1);
}

/* NAT ADDITION */
/* check options in packet, and decide whether is natted, 
 * whether trigger is inserted, removed 
 */
void checkoptions(char *pkt, char* natted, char* insert,
		  char* remove, char* data, i3_addr* real_addr)
{
  unsigned short lenp, leno;
  char *p;
  i3_option* option;

  p = get_hdr_options(pkt);
  lenp = ntohs(*(unsigned short *)p); /* get option list's length */
  lenp -= sizeof(unsigned short); /* skip option list's length field */
  p += sizeof(unsigned short);

  if ( (get_flags(pkt) & I3_DATA) != 0 )
    *data = 1;

  while (lenp)
  {

    option = unpack_i3_option(p, &leno);
    
    if  (option->type == I3_OPT_SENDER && 
	 option->entry.ret_addr->type == I3_ADDR_TYPE_IPv4 && 
	 !addr_equal(option->entry.ret_addr, real_addr))
      *natted = 1;
    
    if ( option->type == I3_OPT_TRIGGER_REMOVE )
      *remove = 1;
    
    if ( option->type == I3_OPT_TRIGGER_INSERT )
      *insert = 1;
    
    p += leno;
    lenp -= leno;
    free_i3_option(option);
  }
  
}




