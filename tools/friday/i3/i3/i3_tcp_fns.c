#include "i3_tcp_fns.h"
#include "../utils/byteorder.h"

#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>

/* Purpose: Send i3 data on TCP socket 
 * Note: To avoid copying of packets, the two sends are performed */
int send_tcp(char *p, int len, int fd)
{
    char header[TCP_I3_HEADER_SIZE];

    /* Send header */
    header[0] = TCP_I3_HEADER_MAGIC;
    hnputs(header + 1, (uint16_t) len);
    
    if (send(fd, header, TCP_I3_HEADER_SIZE, 0) != TCP_I3_HEADER_SIZE) {
	perror("TCP header send");
	return -1;
    }

    /* Send rest of the packet */
    if (send(fd, p, len, 0) < len) {
	perror("TCP Send");
	return -1;
    }

    return len;
}

/* Purpose: Recv i3 data on TCP socket */
#define MAX_ATTEMPTS 10
int recv_tcp(char *p, int len, int fd)
{
    int recv_len, pkt_size, total_recv_len = 0, num_attempts = 0;

    /* recv header */
    recv_len = recv(fd, p, TCP_I3_HEADER_SIZE, 0);
    if (recv_len < 0) {
	perror("TCP header recv");
	return recv_len;
    }
    
    /* recv rest of the packet */
    if (recv_len > 0) {
	assert(TCP_I3_HEADER_MAGIC == p[0]);
	pkt_size = nhgets(p + 1);
	assert(len >= pkt_size);

	while (pkt_size > 0 && num_attempts++ < MAX_ATTEMPTS) {
	    recv_len = recv(fd, p, pkt_size, 0);
	    total_recv_len += recv_len;
	    pkt_size -= recv_len;
	    p += recv_len;
	}
    }
    
    /* Hack! */
    if (pkt_size > 0) {
	printf("Still some more bytes to be received, quitting!\n");
	return -1;
    } else {
	return total_recv_len;
    }
}
