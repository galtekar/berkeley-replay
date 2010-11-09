#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>

#include "i3_monitor.h"
#include "../utils/gen_utils.h"

#define I3_PING_PKT 0x01
#define ECHO_PACKET_SIZE 40
#define MAX_PACKET_SIZE 1200
#define INTER_PROBE_TIME_PER_NODE_MS 1000
#define MAX_NUM_NODES 200

/* True if the packet is a request to the i3 server to echo the pkt */
char is_echo_request(char *p)
{
    return (((*p) & I3_PING_PKT) == 1);
}

/* Echo request (by monitor to i3_server at its addr:port) */
void echo_request(int fd, MonitorInfo *info)
{
    struct sockaddr_in to_addr;
    int rc;
    char p[ECHO_PACKET_SIZE];

    p[0] = I3_PING_PKT;
    
    memset((void *) &to_addr, 0, sizeof(struct sockaddr_in));
    to_addr.sin_family = AF_INET;
    to_addr.sin_addr.s_addr = htonl(info->addr);
    to_addr.sin_port = htons(info->port);

    if (info->num_unacked < MAX_UNACKED) info->num_unacked++;
    /* if (info->num_unacked >= NUM_UNACKED_ERROR)
	printf("Number of unacked packets to %s:%d = %d\n", 
	  inet_ntoa(to_addr.sin_addr), info->port, info->num_unacked); */

    rc = sendto(fd, p, ECHO_PACKET_SIZE, 0,
	    (struct sockaddr *)&to_addr, sizeof(to_addr));
    if (rc < 0)
	perror("Echo reply");

}

/* Echo reply (by i3_server back to monitor) */
void echo_reply(int fd, char *p, int len, struct sockaddr_in *addr)
{
    struct sockaddr_in to_addr;
    int rc;
    
    memset((void *) &to_addr, 0, sizeof(struct sockaddr_in));
    to_addr.sin_family = AF_INET;
    to_addr.sin_addr.s_addr = htonl(addr->sin_addr.s_addr);
    to_addr.sin_port = htons(addr->sin_port);

    rc = sendto(fd, p, len, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
    if (rc < 0)
	perror("Echo reply");
}

/* Echo response (monitor's response to echo reply) */
void echo_response(char *p, int len, struct sockaddr_in *addr, MonitorInfoList *list)
{
    MonitorInfo *info = lookup_mon_info_list(list,
	   	 addr->sin_addr.s_addr, addr->sin_port);

    info->num_unacked = 0;
}

/* send a bunch of echo requests back to back */
int send_echo_request_burst(int fd, MonitorInfo *mon_arr[], 
			int head, int num_send, int num_nodes)
{
    int i;
    for (i = 0; i < num_send; i++) {
	int index = (head + i) % num_nodes;
	if (i >= num_nodes)
	    break;
	echo_request(fd, mon_arr[index]);
    }
    return i;
}

/* Ping - echo request/response */
void *monitor_server_state(void *arg)
{
    ThrArg *targ = (ThrArg *) arg;
    MonitorInfoList *list = targ->list;
    MonitorInfo *mon_arr[MAX_NUM_NODES];
    int num_nodes = read_list_array(list, mon_arr);
    int inter_probe_time = INTER_PROBE_TIME_PER_NODE_MS/num_nodes;

    /* schedule computation */
    uint64_t last_sent, curr_time;
    int num_send; int head;
    
    /* sockets init */
    int fd, rc, n, len;
    fd_set rset;
    struct timeval to;
    char buf[MAX_PACKET_SIZE];
    struct sockaddr_in addr;
    
    assert(num_nodes < MAX_NUM_NODES);

    if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror ("socket");
	exit(-1);
    }

    len = sizeof(struct sockaddr_in);
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(0);
    
    if (bind(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
	perror("bind");
	exit(-1);
    }
    
    /* init send schedule params */
    last_sent = wall_time();
    head = 0;
    
    while (1) {
	FD_ZERO(&rset);
	FD_SET(fd, &rset);
	to.tv_sec = 0; to.tv_usec = 1000;
	
	/* select with appropriate timeout */
	if ((rc = select(fd+1, &rset, NULL, NULL, &to)) < 0) {
	    if (errno == EINTR)
		continue;
	    else
		perror("select");
	} else if (rc > 0) {
	    /* if pkt received, take action */
	    assert(FD_ISSET(fd, &rset));
	    n = recvfrom(fd, buf, MAX_PACKET_SIZE, 0, (struct sockaddr *)&addr, &len);
	    if (n < 0)
		perror("recvfrom");
	    else {
		addr.sin_addr.s_addr = ntohl(addr.sin_addr.s_addr);
		addr.sin_port = ntohs(addr.sin_port);
		echo_response(buf, n, &addr, list);
	    }
	}

	/* compute time elapsed since last "send burst" */
	curr_time = wall_time();
	num_send = (curr_time - last_sent)/inter_probe_time/1000;

	/* send burst */
	num_send = send_echo_request_burst(fd, mon_arr, head, num_send, num_nodes);
	head = (head + num_send) % num_nodes;
	if (num_send > 0)
	    last_sent = curr_time;
    }

    pthread_exit(0);
    return 0;
}
