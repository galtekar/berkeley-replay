#ifndef _PING_THREAD_H
#define _PING_THREAD_H

#include "i3server_list.h"

#define PING_STATUS_START 0
#define PING_STATUS_STEADY 1

typedef struct PingThreadData {
    I3ServerList *list;
    char *url;
    uint64_t *ping_start_time;
} PingThreadData;

void set_status(uint64_t *ping_start_time, uint64_t time);
void *ping_thread_entry(void *data);

#endif
