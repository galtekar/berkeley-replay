#ifndef _I3_MONITOR_STATE_H
#define _I3_MONITOR_STATE_H
#include <netdb.h>
#ifdef __APPLE__
#include <inttypes.h>  // Need uint32_t
#endif

#define MAX_UNACKED 1000
#define NUM_UNACKED_ERROR 3

#define HOSTHASH 200

typedef struct MonitorInfo {
    uint32_t	addr;		// as always, host byte order
    uint16_t	port;
    int		num_unacked;	// num of contiguous unanswered ICMP echo req
    int		rtt;		// in milliseconds

    struct MonitorInfo *next;
} MonitorInfo;

typedef struct MonitorInfoList {
    int		num_nodes;
    MonitorInfo *info[HOSTHASH];
} MonitorInfoList;

void read_server_info(char *conf_file, int port, MonitorInfoList *list);
MonitorInfo *lookup_mon_info_list(MonitorInfoList *list,
				uint32_t addr, uint16_t port);
int monitor_is_dead(MonitorInfoList *list,
				uint32_t addr, uint16_t port);
int read_list_array(MonitorInfoList *list, MonitorInfo *info[]);

#endif
