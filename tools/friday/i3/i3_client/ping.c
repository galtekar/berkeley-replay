#include "../utils/gen_utils.h"
#include "debug.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include "ping.h"

#define UMILLION 1000000ULL

/* initialize icmp socket and make it non-blocking */
int init_icmp_socket(int *sock)
{
    struct sockaddr_in saddr;
    int flags, ret;
    
    *sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (*sock < 0) {
	perror("icmp socket");
	return -1;
    }
    
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(0);
    ret = bind(*sock, (const struct sockaddr *)&saddr, sizeof(saddr));
    if (ret != 0) {
	perror("bind()");
	return -1;
    }
    
    flags = fcntl(*sock, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(*sock, F_SETFL, flags);

    return 0;
}

/* Fill in echo request packet and send to destination */
int send_echo_request(int socket, uint32_t addr, int seq) 
{
    EchoRequest	echoReq;
    static int	nId = 1;
    int		i, nRet;
    struct sockaddr_in to_addr;
	
    /* fill in echo request packet */
    /* header */
    echoReq.icmphdr.type	= ICMP_ECHOREQ;
    echoReq.icmphdr.code 	= 0;
    echoReq.icmphdr.checksum	= 0;
    echoReq.icmphdr.id		= nId;
    echoReq.icmphdr.seq		= seq;
    /* target of ICMP ping */
    echoReq.addr 		= addr;
    echoReq.time 		= wall_time();
    /* fill random data */
    for (i = 0; i < REQ_DATASIZE; i++)
	echoReq.data[i] = (char)(random()&0x000000ff);
    /* compute checksum */
    echoReq.icmphdr.checksum = in_ping_cksum((uint16_t *)&echoReq, 
	    					sizeof(EchoRequest));
    
    /* fill address structure */
    memset((void *) &to_addr, 0, sizeof(struct sockaddr_in));
    to_addr.sin_family = AF_INET;
    to_addr.sin_addr.s_addr = htonl(addr);
    to_addr.sin_port = htons(0);
    
    /* Send the echo request */
    nRet = sendto(socket, (void *) &echoReq, sizeof(EchoRequest), 0,
	    (struct sockaddr *) &to_addr, sizeof(struct sockaddr_in));
    
    if (nRet < 0) 
	perror("icmp sendto()");
    return nRet;
}

/* Process received ICMP packet: code is self-documenting */
int recv_echo_reply(int s, uint32_t *ret_addr, uint16_t *ret_seq, uint64_t *ret_rtt)
{	
    IPHdr *iphdr;
    EchoRequest *echoReply;
    struct sockaddr_in addr;
    char data[MAX_PKT_LEN];
    int nAddrLen = sizeof(struct sockaddr_in);
    int nRet;
    
    nRet = recvfrom(s, (char *)data, MAX_PKT_LEN,
	    	    0, (struct sockaddr *)& addr, &nAddrLen);
    iphdr = (IPHdr *) data;
    echoReply = (EchoRequest *) (data + sizeof(IPHdr));
    
    if (nRet < 0) {
	perror("echo_reply");
    }
    else if (nRet < sizeof(IPHdr) + sizeof(ICMPHdr)) {
	DEBUG(11, 
		"Not enough bytes received: ignoring ICMP packet: %d, %d, %d\n",
		nRet,sizeof(IPHdr), sizeof(ICMPHdr));
    }
    else if ((iphdr->protocol != IPPROTO_ICMP)) {
	DEBUG(11, "Incorrect protocol type received\n");
    }
    else if (ntohl(addr.sin_addr.s_addr) != echoReply->addr) {
	struct in_addr ia;
	ia.s_addr = htonl(echoReply->addr);
	DEBUG(11, 
		"Sent address (%s) does not match recv address ", inet_ntoa(ia));
	DEBUG(11, "%s\n", inet_ntoa(addr.sin_addr));
    }
    else if (echoReply->icmphdr.type != ICMP_ECHOREPLY) {
	DEBUG(11, "Not ECHO_REPLY message: ignoring ICMP packet\n");
    }
    else if (nRet >= sizeof(EchoRequest) + sizeof(IPHdr)) {
	*ret_rtt  = wall_time() - echoReply->time;
	*ret_addr = echoReply->addr;
	*ret_seq  = echoReply->icmphdr.seq;
	//printf("IP = %s, RTT = %Ld, Seq = %d\n",
	//	inet_ntoa(addr.sin_addr), *ret_rtt, *ret_seq);
	return 1;
    } else {
	DEBUG(11, "Not enough bytes received: %d, %d, %d\n",
		nRet, sizeof(EchoRequest), sizeof(IPHdr));
    }

    return 0;
}

/* IN_CKSUM: Internet checksum routine */
uint16_t in_ping_cksum(uint16_t *addr, int len)
{
    register int nleft = len;
    register uint16_t *w = addr;
    register uint16_t answer;
    register int sum = 0;
    
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we
     * add sequential 16 bit words to it, and at the end, fold back
     * all the carry bits from the top 16 bits into the lower 16 bits.
     */
    while( nleft > 1 )  {
	sum += *w++;
	nleft -= 2;
    }
    
    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
	uint16_t u = 0;
	
	*(uint8_t *)(&u) = *(uint8_t *)w ;
	sum += u;
    }
    
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = ~sum;			/* truncate to 16 bits */
    return (answer);
}
