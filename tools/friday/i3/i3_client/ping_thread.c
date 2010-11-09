#include "ping_thread.h"
#include "ping.h"
#include "http.h"
#include "i3server_list.h"
#include "../utils/gen_utils.h"

#include "i3.h"
#include "i3_id.h"
#include "debug.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>

#define START_TIME 5 * 60 * 1000000ULL

#define PERIOD_PING_START 10 * 1000000ULL
#define PERIOD_PING_STEADY 5 * 10 * 1000000ULL
#define PERIOD_PICK_NEW_SERVER_START 60 * 1000000ULL
#define PERIOD_PICK_NEW_SERVER_STEADY 5 * 60 * 1000000ULL
#define PERIOD_SERVERLIST_WGET 5 * 60 * 1000000ULL
#define PING_STEADY_TIME 5 * 60 * 1000000ULL

uint64_t period_ping[2] = {PERIOD_PING_START, PERIOD_PING_STEADY};
uint64_t period_pick_new_server[2] = {PERIOD_PICK_NEW_SERVER_START, PERIOD_PICK_NEW_SERVER_STEADY};

pthread_mutex_t status_mutex = PTHREAD_MUTEX_INITIALIZER;
int status_lock()
{
#ifndef __CYGWIN__
    if (pthread_mutex_lock(&status_mutex)) {
	fprintf(stderr, "status_mutex: problem with locking mutex\n");
	return 1;
    }
#endif
    return 0;
}
int status_unlock()
{
#ifndef __CYGWIN__
    if (pthread_mutex_unlock(&status_mutex)) {
	fprintf(stderr, "status_mutex: problem with unlocking mutex\n");
	return 1;
    }
#endif
    return 0;
}

char is_valid(char type)
{
    if (PING_STATUS_STEADY == type || PING_STATUS_START == type)
	return 1;
    else
	return 0;
}

void set_status(uint64_t *ping_start_time, uint64_t curr_time)
{
    status_lock();
    if (ping_start_time != NULL)
	*ping_start_time = curr_time;
    status_unlock();
}

char get_status(uint64_t *ping_start_time, uint64_t curr_time)
{
    char ret = PING_STATUS_STEADY;
    status_lock();
    if (curr_time - *ping_start_time > PING_STEADY_TIME) {
	ret = PING_STATUS_STEADY;
    } else {
	ret = PING_STATUS_START;
    }
    status_unlock();
    return ret;
}

    
void send_npings(int sock, I3ServerList *list, I3ServerListNode **node, int n)
{
    int i;
    static int seq = 0;
    
    n = n % list->num_i3servers;
    for (i = 0; i < n; i++) {
	send_echo_request(sock, (*node)->addr, seq);
	
	*node = (*node)->next_list;
	if (NULL == *node) {
	    *node = list->list;
	    seq++;
	}
    }
}

void *ping_thread_entry(void *data)
{
    PingThreadData *pdata = (PingThreadData *)data;
    
    int sock, maxfd, ret;
    fd_set all_rset, rset;
    struct timeval to;
    int i;

    I3ServerList *list = pdata->list;
    char *url = pdata->url;
    uint64_t *ping_start_time = pdata->ping_start_time;
       
    int num_pings;
    I3ServerListNode *next_to_ping;
    uint64_t last_ping_time, curr_time;
    uint64_t last_add_new_i3servers, last_update_serverlist;

    /* initial update of list */
    update_i3_server_list(url, list, &next_to_ping);
    add_new_i3servers_to_ping(list, &next_to_ping);
    
    if (init_icmp_socket(&sock) == -1)
      abort();
    FD_SET(sock, &all_rset);
    maxfd = sock + 1;
    
    /* eternal loop */
    last_ping_time = last_add_new_i3servers = last_update_serverlist = wall_time();
    set_status(ping_start_time, last_ping_time);
    for (;;) {
	rset = all_rset;
        to.tv_sec = 0; to.tv_usec = 10000;
        if ((ret = select(maxfd, &rset, NULL, NULL, &to)) < 0) {
            if (errno == EINTR)
                continue;
            else {
                perror("select");
                abort();
            }
        }

	/* message received on icmp socket */
	if (FD_ISSET(sock, &rset)) {
	    uint32_t addr; uint16_t seq; uint64_t rtt;
	    if (recv_echo_reply(sock, &addr, &seq, &rtt)) {
		update_list(list, addr, seq, rtt);
	    }
	}

	/* need to send icmp messages */
	curr_time = wall_time();
	if (list->num_i3servers > 0) {
	    char status = get_status(ping_start_time, curr_time);
	    num_pings = (curr_time - last_ping_time)/
			(period_ping[status]/list->num_i3servers);
	    if (num_pings > 0) {
		if (NULL == next_to_ping) {
		    DEBUG(10, "No servers to ping. Aborting\n");
		}
		send_npings(sock, list, &next_to_ping, num_pings);
		last_ping_time = curr_time;
	    }
	}
	
	/* change the list of i3 servers */
	if (curr_time - last_add_new_i3servers >
		period_pick_new_server[get_status(ping_start_time, curr_time)]) {
	    DEBUG(10, "Adding new servers to list\n");
	    add_new_i3servers_to_ping(list, &next_to_ping);
	    last_add_new_i3servers = curr_time;
	}
	
	/* update (wget) i3 server list */
	if (curr_time - last_update_serverlist > PERIOD_SERVERLIST_WGET) {
	    DEBUG(10, "Updating server list from server\n");
	    update_i3_server_list(url, list, &next_to_ping);
	    last_update_serverlist = curr_time;
	}
    }

    pthread_exit(0);
    return 0;
}
