#ifndef _EVENTQ_H

#define _EVENTQ_H

class Server;
class Event {
	public:
		typedef enum {
			SEND_INIT_PV 	= 1,
			SEND_BEACON 	= 2,
			RECEIVE_BEACON 	= 3,
			END_WARMUP 		= 4,
			START_ROUTER 	= 5,
			ROUTER_INTERVAL = 6,
			COMPUTE_FLOWS   = 7
			} Type;
		long time;
		int type;
		int neighborId;
		
		Event ();
		Event ( long _time, Type _type );
		Event ( long _time, Type _type, int _neighborId );
		~Event (){}

		void print ();

		friend bool operator < (const Event& e1, const Event& e2){
			if (e1.time > e2.time)
				return true;
			else
				return false;
		}


};

class EventQ {
		priority_queue<Event> pq;
		map <int, int> count;
		EventQ ();
	public:
		static EventQ* instance ();
		void add_event ( long offset, Event::Type eventType);
		bool is_present_event( Event::Type eventType);
		void dispatch_events( Server* server);
		void print ();	
};
#endif
