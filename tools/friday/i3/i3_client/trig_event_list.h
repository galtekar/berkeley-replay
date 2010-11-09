#ifndef _TRIG_EVENT_LIST_H
#define _TRIG_EVENT_LIST_H

#include "trig_binheap.h"
#include "i3_client.h"

#include <netdb.h>

uint64_t get_trigger_next_refresh_time();

void process_trig_event(cl_context *ctx, TrigInsertNode *node);

#endif
