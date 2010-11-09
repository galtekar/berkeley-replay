/* host registration (mainly for testing) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <netdb.h>
#include <net/if.h>

#include "logreplay.h"
#include "libc_pointers.h"
#include "errops.h"
#include "gcc.h"

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
static uint32_t get_local_addr_eth(void)
{
	int i, tempfd;
	struct sockaddr_in addr;
	char ifname[IFNAME_LEN];
	struct ifreq ifr;		

	for (i = 0; i < MAX_NUM_INTERFACES; i++) {
		sprintf(ifname, "eth%d", i);
		strcpy(ifr.ifr_name, ifname);
		tempfd = (*__LIBC_PTR(socket))(AF_INET, SOCK_DGRAM, 0);

		if (-1 != (*__LIBC_PTR(ioctl))(tempfd, SIOCGIFFLAGS, (char *)&ifr)) {
			if (0 != (ifr.ifr_flags & IFF_UP)) {
				if (-1 != (*__LIBC_PTR(ioctl))(tempfd, SIOCGIFADDR, (char *)&ifr)) {
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
static uint32_t get_local_addr(void)
{
	uint32_t addr;

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

	/* If that is unsuccessful, try ioctl on eth interfaces */
	if ((addr = get_local_addr_eth()) != inet_addr(TRIVIAL_LOCAL_ADDR))
		return addr;

	/* This is hopeless, return TRIVIAL_IP */
	return(inet_addr(TRIVIAL_LOCAL_ADDR));
}

/***********************************************************************/
/* get_addr: get IP address of server */
in_addr_t HIDDEN __liblog_get_addr(void)
{
	return (in_addr_t) get_local_addr();
}
