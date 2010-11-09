#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>   /* basic system data types */
#include <sys/socket.h>  /* basic socket definitions */
#include <sys/time.h>    /* timeval{} for select() */
#include <errno.h>    
#include <sys/utsname.h>
#include <time.h>                /* timespec{} for pselect() */
#include <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>
#include <netdb.h>

#include "i3.h"
#include "i3_fun.h"

void init_i3_id_fromstr(ID *id, char *name)
{
  uint i;

  for (i = 0; i < ID_LEN; i++)
    id->x[i] = name[i % strlen(name)];
}

void init_key_fromstr(Key *key, char *name)
{
  uint i;

  for (i = 0; i < KEY_LEN; i++)
    key->x[i] = name[i % strlen(name)];
}

int id_local(char *id)
{
  // to be changed when more than one server
  return TRUE; 
}

void send_packet_ipv4(char *pkt, int len, struct in_addr *dst_addr, 
		      uint16_t dst_port, int dst_fd)
{
  struct sockaddr_in dstaddr;

  bzero(&dstaddr, sizeof(dstaddr));
  dstaddr.sin_family = AF_INET;
  dstaddr.sin_addr.s_addr = htonl(dst_addr->s_addr);
  dstaddr.sin_port = htons(dst_port);

  if (sendto(dst_fd, pkt, len, 0, 
	     (struct sockaddr *)&dstaddr, sizeof(dstaddr)) < 0)
    err_sys("send_ipv4: sendto error\n");
}

#ifndef __CYGWIN__
void send_packet_ipv6(char *p, int len, 
		      struct in6_addr *ip6_addr, uint16_t port, int rfd)
{
  printf("send_packet_ipv6: not implemented yet!\n");
}
#endif

void send_packet_i3(char *p, int len)
{
  printf("send_i3: not implemented yet!\n");
}



