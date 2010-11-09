#ifndef _EVENTQ_H
#define _EVENTQ_H

#include "iopause.h"
#include "codonsutils.h"

#define UPDATE_BROADCAST 1

typedef struct EVENT{
	long time;
	int type;
}Event;

typedef struct EVENT_Q{
	Event event;
	struct EVENT_Q* next;
}EventQ;

typedef enum {
	FALSE = 0,
	TRUE = 1
} BOOL;

Event* add_event(EventQ **q, long time, int event);
Event* get_event(EventQ** q);
BOOL is_present_event(EventQ* q,int event);
void handle_event_q(iopause_fd* fd, EventQ** q, DNSMessageList* list);
void print_event(EventQ* q);


#endif
