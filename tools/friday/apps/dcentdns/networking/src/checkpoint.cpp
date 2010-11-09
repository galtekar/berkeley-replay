#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <global.h>
#include "logger.h"
#include "checkpoint.h"


TimeStamp timestamp[MAX_NUM_EVENTS];
int event_count = 0;


void add_checkpoint(int type, int seq)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    assert(event_count < MAX_NUM_EVENTS);
    
    timestamp[event_count].ts = now.tv_sec * UMILLION + now.tv_usec;
    timestamp[event_count].seq = seq;
    timestamp[event_count].type = type;
//	Log::print ("Adding checkpoint %d,%d\n",timestamp[event_count].ts,timestamp[event_count].type, SILENT);
    event_count++;
}

char* get_event_name (int eventType) {

    switch (eventType) {
		case GENERATE_KEY_START:
			return  "GENERATE_KEY_START";
		case GENERATE_KEY_END:
			return  "GENERATE_KEY_END";
		case SEND_INIT_PV_START:
			return  "SEND_INIT_PV_START";
		case SEND_INIT_PV_END:
			return "SEND_INIT_PV_END";
		case SEND_INCREMENT_PV_START:
			return "SEND_INCREMENT_PV_START";
		case SEND_INCREMENT_PV_END:
			return "SEND_INCREMENT_PV_END";
		case RECEIVE_INIT_PV_START:
			return "RECEIVE_INIT_PV_START";
		case RECEIVE_INIT_PV_END:
			return "RECEIVE_INIT_PV_END";
		case RECEIVE_INCREMENT_PV_START:
			return "RECEIVE_INCREMENT_PV_START";
		case RECEIVE_INCREMENT_PV_END:
			return "RECEIVE_INCREMENT_PV_END";
	    case VERIFY_PV_START:
			return "VERIFY_PV_START";
		case VERIFY_PV_END:
			return "VERIFY_PV_END";
		case SEND_FAKE_INIT_PV_START:
			return  "SEND_FAKE_INIT_PV_START";
		case SEND_FAKE_INIT_PV_END:
			return "SEND_FAKE_INIT_PV_END";
		case SEND_FAKE_INCREMENT_PV_START:
			return  "SEND_FAKE_INCREMENT_PV_START";
		case SEND_FAKE_INCREMENT_PV_END:
			return "SEND_FAKE_INCREMENT_PV_END";
        default:
            return "UNKNOWN EVENT";
        break;
    }

}

void dump_event_info(int signal)
{
    int i;
	Log::print ("Entering dump_event_info\n", Log::VVVERBOSE);
	if( Log::get_level() != Log::SILENT){
		Log::print ("Warning: Program run in non-silent mode!!!!\n", Log::SILENT);
	}
    for (i = 0; i < event_count; i++) {
	    Log::print ( 
			to_string(timestamp[i].ts)+
			"\tSequence:" + 
			to_string(timestamp[i].seq) + 
			"\tType:" + 
			to_string(get_event_name (timestamp[i].type)) + "\n"
			, Log::SILENT);
    }
	Log::print ("Exiting dump_event_info\n", Log::VVVERBOSE);
}
