#include "i3_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "../utils/inetfns.h"

#define AH_MULTIPLIER 31
static uint32_t host_hash(uint32_t addr, uint16_t port, uint32_t n)
{
    uint32_t    h = 0;
    int32_t     i;
    unsigned char *b;

    // go through addr
    b = (unsigned char *) &addr;
    for (i = 0; i < 4; i++)
        h = AH_MULTIPLIER * h + b[i];

    // go through port
    b = (unsigned char *) &port;
    for (i = 0; i < 2; i++)
        h = AH_MULTIPLIER * h + b[i];


    return h % n;
}

MonitorInfo *lookup_mon_info_list(MonitorInfoList *list, uint32_t addr, uint16_t port)
{
    MonitorInfo	*info;
    uint32_t	h;

    h = host_hash(addr, port, HOSTHASH);
    for (info = list->info[h]; info != NULL; info = info->next)
	if (info->addr == addr)
	    break;

    return info;
}

int monitor_is_dead(MonitorInfoList *list, uint32_t addr, uint16_t port)
{
    struct in_addr ia;
    MonitorInfo *info = lookup_mon_info_list(list, addr, port);
    if (NULL == info) {
	ia.s_addr = htonl(addr);
	printf("Warning: Not monitoring server %s:%d\n", inet_ntoa(ia), port);
	return 0;
    }

    if (info->num_unacked >= NUM_UNACKED_ERROR) return 1;
    else return 0;
}

/* lifted from hash-based tables from i3_server/i3_news */
#define MAXIMUM_RTT_MS 1000
void insert_mon_info_list(MonitorInfoList *list, uint32_t addr, uint16_t port)
{
    uint32_t	h;
    MonitorInfo	*info = (MonitorInfo *) malloc(sizeof(MonitorInfo));
    
    assert(lookup_mon_info_list(list, addr, port) == 0);

    /* create new obj */
    info->addr = addr;
    info->port = port;
    info->num_unacked = 0;
    info->rtt = MAXIMUM_RTT_MS;

    /* insert */
    h = host_hash(addr, port, HOSTHASH);
    info->next = list->info[h];
    list->info[h] = info;
    list->num_nodes++;
}

void print_mon_info_list(MonitorInfoList *list)
{
    int h;
    MonitorInfo	*info;
    struct in_addr ia;
    for (h = 0; h < HOSTHASH; h++) {
	for (info = list->info[h]; info != NULL; info = info->next) {
	    ia.s_addr = htonl(info->addr);
	    printf("Monitoring server: %s\n", inet_ntoa(ia));
	}
    }
}

void read_server_info(char *conf_file, int local_port, MonitorInfoList *list)
{
    FILE *fp;
    char addr[100], port[100], vport[100], id[100];
    
    uint32_t local_addr = get_local_addr();
    struct hostent *hp;
    int h;

    /* init list to null */
    list->num_nodes = 0;
    for (h = 0; h < HOSTHASH; h++)
	list->info[h] = NULL;

    /* read from file */
    fp = fopen(conf_file, "r");
    if (fp == NULL) {
        printf("fopen(%s,\"r\") failed:", conf_file);
	exit(-1);
    }

    while (fscanf(fp, "%s %s %s %s\n", addr, port, vport, id) == 4) {
        hp = gethostbyname(addr);
        if (hp == NULL)
            printf("gethostbyname(%s) failed:", addr);
	
	if ((local_addr == *((in_addr_t *) hp->h_addr))
		&& (local_port) == atoi(port))
	    continue;

        insert_mon_info_list(list, 
		ntohl(*((in_addr_t *) hp->h_addr)), atoi(port));
    }
}

int read_list_array(MonitorInfoList *list, MonitorInfo *arr[])
{
    uint32_t	h;
    int		count = 0;
    MonitorInfo	*info;

    for (h = 0; h < HOSTHASH; h++)
	for (info = list->info[h]; info != NULL; info = info->next)
	    arr[count++] = info;

    assert(count == list->num_nodes);
    return count;
}
