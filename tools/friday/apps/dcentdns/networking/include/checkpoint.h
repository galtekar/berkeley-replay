#ifndef _CHECKPOINT_H

#define _CHECKPOINT_H

#define GENERATE_KEY_START 0
#define GENERATE_KEY_END 1
#define SEND_INIT_PV_START 2
#define SEND_INIT_PV_END 3
#define SEND_INCREMENT_PV_START 4
#define SEND_INCREMENT_PV_END 5
#define RECEIVE_INIT_PV_START 6
#define RECEIVE_INIT_PV_END 7
#define RECEIVE_INCREMENT_PV_START 8
#define RECEIVE_INCREMENT_PV_END 9
#define VERIFY_PV_START 10
#define VERIFY_PV_END 11
#define SEND_FAKE_INIT_PV_START 12
#define SEND_FAKE_INIT_PV_END 13
#define SEND_FAKE_INCREMENT_PV_START 14
#define SEND_FAKE_INCREMENT_PV_END 15
#define RECEIVE_INIT_START 16
#define RECEIVE_INIT_END 17

#define MAX_NUM_EVENTS 100000
#define UMILLION 1000000ULL
	void add_checkpoint(int type, int seq);
	char* get_event_name (int eventType);
	void dump_event_info(int signal);


typedef struct TIMESTAMP{
	int seq;
	int type;
	long ts;
}TimeStamp;
#endif
