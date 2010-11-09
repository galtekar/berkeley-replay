#ifndef _I3_MONITOR_H
#define _I3_MONITOR_H

#include "i3_monitor_state.h"

#define PING_PERIOD_MS 100

typedef struct ThrArg {
    MonitorInfoList *list;
} ThrArg;

void *monitor_server_state(void *arg);
void echo_reply(int fd, char *p, int len, struct sockaddr_in *addr);
char is_echo_request(char *p);

#endif
