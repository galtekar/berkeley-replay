#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include "debug.h"
#include "arch.h"


#if 0
/* Sends a message to @fd. Work like send(), but ensures
 * that all LEN bytes are sent. */
ssize_t 
NetOps_Write(int fd, const void* buf, size_t len)  
{
	size_t bytes_written = 0;
	ssize_t bytes_out;
	const char *bufp;

	/* TODO: avoid copying by using sendmsg()!! */

	bufp = (const char *)buf;
	while (bytes_written < len) {
		if ((bytes_out = write(fd, bufp, 
						len - bytes_written)) < 0) {
			perror("write");

         // Not safe to use errno, since dietlibc is unaware of our
         // tasks
			if (errno != EINTR) {
				return -1;
			}
		}

		bufp += bytes_out;
		bytes_written += bytes_out;
	}

	return len;
}
#endif

ssize_t 
NetOps_SendAll(int fd, const void* buf, size_t len, int flags)
{
	size_t bytes_written = 0;
	ssize_t err;
	const char *bufp;

   // Not safe to use errno, since dietlibc is unaware of our
   // tasks

   bufp = (const char *)buf;

   while (bytes_written < len) {
      if ((err = SysOps_send(fd, bufp, len - bytes_written, flags)) < 0) {
         if (err != -EINTR) {
            return -1;
         }
      }

      ASSERT( err >= 0 );

		bufp += err;
		bytes_written += err;
	}

	return len;
}

/* Reads LEN bytes from FD info BUF. It works just like
 * recv() except that it ensures that you get all LEN bytes
 * despite interruptions. */
ssize_t 
NetOps_ReadAll(int fd, void* buf, size_t len, int flags) 
{
	ssize_t err;
	char *bufp = buf;
	size_t received_so_far = 0;

	while (received_so_far < len) {
      if ((err = SysOps_recv(fd, bufp, len - received_so_far, 
                  flags)) > 0) {
         bufp += err;
         received_so_far += err;
      } else {
         /* recv() may have been interrupted by a signal. In such a
          * case, try again rather than returning. */
         if (err != -EINTR) {
            return err;
         }
      }
   }
   ASSERT(received_so_far == len);

   return received_so_far;
}

/* pack: pack binary items into buf, return length */

static u64
htonll(const u64 q)
{
#ifdef __x86__
   u64 res;
   u32 *i = (u32*) &q;
   u32 *o = (u32*) &res;

   o[0] = htonl(i[1]);
   o[1] = htonl(i[0]);
#else
#error "XXX"
#endif

   return res;
}

static u64
ntohll(const u64 q)
{
#ifdef __x86__
   u64 res;
   u32 *i = (u32*) &q;
   u32 *o = (u32*) &res;

   o[0] = ntohl(i[1]);
   o[1] = ntohl(i[0]);
#else
#error "XXX"
#endif

   return res;
}

ssize_t
NetOps_Pack(void *buf, size_t buf_len, const char *fmt, ...)
{
   va_list args;
   const char *p;
   uchar *bp;
   ushort h;
   ulong l;
   ullong q;
   const char *s;

   bp = (uchar*) buf;
   va_start(args, fmt);
   for (p = fmt; *p != '\0'; p++) {
      switch (*p) {
      case 'c':   /* char */
      case 'b':
      case 'B':
         /* use int and not char, since according to gcc, "char in
          * promoted to int when passed through ..." */
         *bp++ = va_arg(args, int);
         break;
      case 'h':
      case 'H':   /* short */
         /* use int and not short, because shorts are promoted to
          * ints when passed through ... */
         h = va_arg(args, int);
         h = htons(h);
         memmove(bp, (char *)&h, sizeof(short));
         bp += sizeof(short);
         break;
#ifdef __x86__
      case 'i':
#else
#error "XXX: unimplemented"
#endif
      case 'l':   /* long */
      case 'L':
         l = va_arg(args, ulong);
         l = htonl(l);
         memmove(bp, (char *)&l, sizeof(l));
         bp += sizeof(l);
         break;
      case 'Q':   /* quad (i.e., long long)*/
         q = va_arg(args, uint64_t);
         q = htonll(q);
         memmove(bp, (char *)&q, sizeof(q));
         bp += sizeof(q);
         break;
      case 's':
         s = va_arg(args, const char*);
         strcpy((char*)bp, s);
         bp += strlen(s) + 1;
         break;
      default:   /* illegal type character */
         va_end(args);
         return -1;
      }
   }
   va_end(args);
   return bp - (uchar*)buf;
}

/**********************************************************************/

/* unpack: unpack binary items from buf, return length */
ssize_t
NetOps_Unpack(const void *buf, size_t buf_len, const char *fmt, ...)
{
   va_list args;
   const char *p;
   const uchar *bp;
   uchar *pc;
   ushort *ps;
   ulong *pl;
   uint64_t *ql;

   bp = (const uchar*) buf;  
   va_start(args, fmt);
   for (p = fmt; *p != '\0'; p++) {
      switch (*p) {
      case 'c':   /* char */
      case 'b':
      case 'B':
         pc = va_arg(args, uchar*);
         *pc = *bp++;
         break;
      case 'h':   /* short */
      case 'H':
         ps = va_arg(args, ushort*);
         *ps = ntohs(*(ushort*)bp);
         bp += sizeof(ushort);
         break;
#ifdef __x86__
      case 'i':
#else
#error "XXX: unimplemented"
#endif
      case 'l':   /* long */
      case 'L':
         pl = va_arg(args, ulong*);
         *pl  = ntohl(*(ulong*)bp);
         bp += sizeof(ulong);
         break;
      case 'Q':   /* quad */
         ql = va_arg(args, uint64_t*);
         *ql  = ntohll(*(uint64_t*)bp);
         bp += sizeof(*ql);
         break;
      default:   /* illegal type character */
         va_end(args);
         return -1;
      }
   }
   va_end(args);
   return bp - (const uchar*) buf;
}


#define TRIVIAL_LOCAL_ADDR	"127.0.0.1"
#define MAX_NUM_INTERFACES	3
#define IFNAME_LEN		256

/***************************************************************************
 * 
 * Purpose: Get IP address of local machine by ioctl on eth0-ethk
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
static uint32_t 
get_local_addr_eth(void)
{
	int i, tempfd;
	struct sockaddr_in addr;
	char ifname[IFNAME_LEN];
	struct ifreq ifr;		

	for (i = 0; i < MAX_NUM_INTERFACES; i++) {
		sprintf(ifname, "eth%d", i);
		strcpy(ifr.ifr_name, ifname);
		tempfd = socket(AF_INET, SOCK_DGRAM, 0);

		if (-1 != ioctl(tempfd, SIOCGIFFLAGS, (char *)&ifr)) {
			if (0 != (ifr.ifr_flags & IFF_UP)) {
				if (-1 != ioctl(tempfd, SIOCGIFADDR, (char *)&ifr)) {
					addr = *((struct sockaddr_in *) &ifr.ifr_addr);
					return addr.sin_addr.s_addr;
				}
			}
		}
	}

	return inet_addr(TRIVIAL_LOCAL_ADDR);
}

/***************************************************************************
 * 
 * Purpose: Get IP address of local machine
 * 
 * Return: As an unsigned long in network byte order
 *
 **************************************************************************/
uint32_t 
NetOps_GetLocalAddr()
{
	uint32_t addr;

#ifdef TRY_UNAME_HOSTNAME_LOOKUP
#if TRY_UNAME_HOSTNAME_LOOKUP
	/* If this host is mobile, then this lookup may return an IP address
	 * that no longer belongs to this host. The hostname assigned by
    * DHCP may not get updated when the host moves to a new network,
	 * perhaps because that network does not assign hostnames or is behind
	 * a NAT. In such a case, the host will retain the original hostname,
	 * whic is no longer valid in the new location. Nevertheless, that
	 * invalid hostname will be resolved and its IP address returned. */

	/* First try uname/gethostbyname */
	if ((addr = get_local_addr_uname()) != inet_addr(TRIVIAL_LOCAL_ADDR))
		return addr;
#endif
#endif

	/* If that is unsuccessful, try ioctl on eth interfaces */
	if ((addr = get_local_addr_eth()) != inet_addr(TRIVIAL_LOCAL_ADDR))
		return addr;

	/* This is hopeless, return TRIVIAL_IP */
	return(inet_addr(TRIVIAL_LOCAL_ADDR));
}
