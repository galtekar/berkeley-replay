#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "eventq.h"
#include "logger.h"
#include "codonsutils.h"

Event* add_event(EventQ **q, long offset, int event){
	//fprintf(stderr,"add_event\n");
	log_default ( VVVERBOSE, "Entering add_event\n");
	EventQ* tmp1=(EventQ *)malloc(sizeof(EventQ));
	assert(tmp1!=NULL);
	EventQ* tmp2=*q;
	EventQ* prev=NULL;
	log_default(VVERBOSE,"Adding event of type:%d\n", event);
	log_default(VVERBOSE,"Checking\n");
	time_t t;
	time(&t);
	tmp1->event.time=offset+t;
	tmp1->event.type=event;
	tmp1->next=NULL;
	while(tmp2!=NULL && tmp2->event.time<=tmp1->event.time){
		prev=tmp2;
		tmp2=tmp2->next;
	}
	if(prev==NULL){
		*q=tmp1;
		tmp1->next=tmp2;
	}else{
		prev->next=tmp1;
		tmp1->next=tmp2;
	}
	if((*q)->event.type==4){
		print_event(*q);
	}
	log_default ( VVVERBOSE, "Leaving  add_event\n");
	return &(tmp1->event);
}

Event* get_event(EventQ** q){
	log_default ( VVVERBOSE, "Entering get_event\n");
	time_t t;
	time(&t);
	Event* event=NULL;
	EventQ* prev;
	if(*q!=NULL && t>=(*q)->event.time){
		event=(Event *)malloc(sizeof(Event));
		assert(event!=NULL);
		Event* src=&(*q)->event;
		memcpy(event,src,sizeof(Event));
		prev=*q;
		*q=(*q)->next;
		free(prev);
	}
	if(event!=NULL)
		log_default( VVVERBOSE,"Timed out\n");
	log_default ( VVVERBOSE, "Leaving get_event\n");
	return event;
}


BOOL is_present_event(EventQ *q, int type){
	log_default ( VVVERBOSE, "Entering is_present_event\n");
	EventQ* p=q;
	while(p!=NULL){
		if(p->event.type==type)
			return TRUE;
		p=p->next;
	}
	log_default ( VVVERBOSE, "Leaving  is_present_event\n");
	return FALSE;
}

void print_event(EventQ* q){
	EventQ* p=q;
	log_default(VVERBOSE,"The event Q:\n");
	int i=0;
	time_t t;
	time(&t);
	log_default(VVERBOSE,"Time:%ld\n",t);
	while(p!=NULL){
		log_default_notime(VVERBOSE,"\t%d:Event type:%d(%ld)\n",i,p->event.type, p->event.time);
		p=p->next;
	}		
}

void handle_event_q(iopause_fd* fd, EventQ**q, DNSMessageList* list){
	log_default ( VVVERBOSE, "Entering handle_event_q\n");
	Event* event;
	int time;
	while((event=get_event(q))!=NULL){
		log_default(VERBOSE,"Got event of type:%d\n",event->type);
		switch(event->type){
			case UPDATE_BROADCAST:
			{
				DNSMessageList* tmp = list;
				log_default (VERBOSE, "Cache size=%d\n", cache_size (tmp));
				while (tmp!=NULL){
					if ( tmp->status == AUTH) {
						log_default ( VERBOSE, "Pushing a DNS message\n");
						log_default ( VERBOSE, "Query data:\n");
						log_query_data (VERBOSE, *(tmp->message->qdata));
						char* packet = 0;
						packDNSMessage ( tmp->message, &packet);
						Message* message = (Message *)malloc (sizeof (Message));
						assert (message!=NULL);

						message->type = DNS_BROADCAST;
						message->payloadSize = tmp->message->length;
						message->payload= packet;
						send_message ( fd->fd, message);
						free (packet);
					}
					tmp = tmp->next;
				}
				add_event ( q, 250000, UPDATE_BROADCAST);
			}			
			break;
			default:
				log_default(NORMAL,"Error: unknown event type\n");
			break;
		}
		free(event);
	}
	log_default ( VVVERBOSE, "Leaving  handle_event_q\n");
}
