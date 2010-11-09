#ifndef _SCHEDULER_H

#define _SCHEDULER_H


class Message;
class KeyedId;
class Id;
class Server;

class SchedulerElement{
	public:
		static unsigned int counter;
		unsigned int fifoPriority;
		Message* message;
		unsigned char* digest;
		int incomingSockfd;

		SchedulerElement ();
		SchedulerElement (Message* _message, int _incomingSockfd, unsigned char* _digest);
//		SchedulerElement (const SchedulerElement& se);
//		const SchedulerElement& operator = (const SchedulerElement& se);
		~SchedulerElement();
		
		friend bool operator < ( const SchedulerElement& e1, const SchedulerElement& e2){
			int diff = e1.fifoPriority - e2.fifoPriority;
			if (abs(diff)>INT_MAX/2) diff+=INT_MAX;
			if (diff > 0)
				return true;
			else
				return false;
		}

		friend ostream& operator << (ostream& os, const SchedulerElement& se){
			return os	<< "[[priority="<<se.fifoPriority<<","
						<< se.message
						<< "]]";
		}

		string to_string (){
			ostringstream os;
			os << *this;
			return os.str();
		}
};

class PrioritySchedulerElement:public SchedulerElement{
	public:
		int idPriority;
		int keyedIdPriority;
		bool compare (const SchedulerElement& e);  

		PrioritySchedulerElement::PrioritySchedulerElement();
		PrioritySchedulerElement (Message* _message, int _incomingSockfd, unsigned char* _digest, int _ip, int _kip);
//		PrioritySchedulerElement ( const PrioritySchedulerElement& pse);
//		const PrioritySchedulerElement& operator = (const PrioritySchedulerElement& pse);
		~PrioritySchedulerElement();
		
		friend bool operator < ( const PrioritySchedulerElement& e1, const PrioritySchedulerElement& e2){
			if (e1.idPriority > e2.idPriority)
				return true;
			else if (e1.idPriority < e2.idPriority)
				return false;
			else{
				if (e1.keyedIdPriority > e2.keyedIdPriority)
					return true;
				else if (e1.keyedIdPriority < e2.keyedIdPriority)
					return false;
				else{
					int diff = e1.fifoPriority - e2.fifoPriority;
					if (abs(diff)>INT_MAX/2) diff+=INT_MAX;
					if (diff > 0)
						return true;
					else
						return false;

				}
			}
		}


		friend ostream& operator << (ostream& os, const PrioritySchedulerElement& pse){
			return os	<< "[[priority="<<pse.fifoPriority<<","
						<< pse.message
						<< "]]";
		}

		string to_string (){
			ostringstream os;
			os << *this;
			return os.str();
		}
};

class Scheduler{
	public:	
		typedef enum {FIFO=0, PRIORITY=1} Type;
	private:
		priority_queue<PrioritySchedulerElement> pq;
		queue<SchedulerElement> q;
		queue<SchedulerElement> dataq;

		Type type;
		map<KeyedId, int> keyedIdMap;
		map<Id, int> idMap;
		Scheduler(Type _type);
	public:
		static Scheduler* instance(Type _type);
		
		void add_message(Message* _message, int _incomingSockfd, unsigned char* _digest);
		void add_dns_message (Message* message, int incomingSockfd);
		
		void dispatch_messages (Server* server);
		bool relay_message ( Server* server );
		bool relay_dns_message ( Server* server );
		Message* receive_message (Server* server, int incomingSockfd );
		Type  get_type ();
		void print();



};
#endif
