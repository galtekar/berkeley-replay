#include "global.h"

/////CPP
Event::Event (){}

Event::Event ( long _time, Type _type ){
	time = _time;
	type = _type;
	neighborId = -1;
}

Event::Event ( long _time, Type _type, int _neighborId ) {
	time = _time;
	type = _type;
	neighborId = _neighborId;
}

void Event::print(){}

EventQ::EventQ(){
//	pq = new priority_queue<Event>();
//	count = new map <int, int>();
}

EventQ* EventQ::instance (){
	static EventQ eventq;
	return &eventq;
}

void EventQ::add_event ( long offset, Event::Type eventType){
	time_t t;
	time(&t);	
	t+= offset;
	Log::print ( "At time:"+ to_string (t-offset)+ " Adding event of type " + to_string(eventType) + " to fire at " + to_string(t) +" ("+ to_string(offset)+") \n", Log::VERBOSE);
	Event* e = new Event (t, eventType);
	pq.push (*e);	
	count [eventType]++;
}

void EventQ::dispatch_events( Server* server){
	Log::print ("Entering EventQ::dispatch_events\n", Log::VVVERBOSE);
	time_t t;
	time(&t);
	typedef deque<Neighbor>::iterator diter;
	deque<Neighbor>* neighbors = server->neighbors;
	while ( pq.size()>0 && pq.top().time <= t ){
		const Event* event = &pq.top();
		cout << "Dispatching event of type:" + to_string(event->type)+ "\n";
		switch (event->type){
			case Event::SEND_INIT_PV:
				for ( diter i = neighbors->begin(); i != neighbors->end(); i++ ) {
					if( i->status == Neighbor::AUTHENTICATED ) {
						MessageHandler::send_init_pv_message ( server, &(*i) );
					}
				}
			break;
			case Event::END_WARMUP:
				Log::print ("Ending warmup\n", Log::NORMAL);
			break;
			case Event::COMPUTE_FLOWS:
				{
					Log::print ("Computing flows\n", Log::VERBOSE);
					DataContainer* dc = server->dc;
					dc->compute_flows (server);
					add_event ( server->config->flowComputeInterval, Event::COMPUTE_FLOWS);
					Log::print ("Computed flows\n", Log::VERBOSE);
				}
			break;
			default:
				Log::print ("Error: unknown event type of " + to_string(event->type), Log::NORMAL);
			break;
		}

		pq.pop();

		/* BUG FIX: the count was incremented in add_event but was
		 * never decremented. */
		count[event->type]--;
	}
}

void EventQ::print() {}



bool EventQ::is_present_event( Event::Type eventType) {

	if (count.find (eventType) != count.end()) {
		return (count[eventType] > 0);
	}

	return false;
}
