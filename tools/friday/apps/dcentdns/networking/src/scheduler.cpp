#include "global.h"

#include <errno.h>

///CPP
unsigned int SchedulerElement::counter = 0;

SchedulerElement::SchedulerElement(){}

SchedulerElement::SchedulerElement (Message* _message, int _incomingSockfd, unsigned char* _digest){
	fifoPriority = counter;
	counter ++;
	message = _message;
	digest = _digest;
/*	digest = new_char(SHA_DIGEST_LENGTH);
	memset (digest, 0, SHA_DIGEST_LENGTH);
	memcpy (digest, _digest, SHA_DIGEST_LENGTH);*/
	incomingSockfd = _incomingSockfd;
}
/*
SchedulerElement::SchedulerElement (const SchedulerElement& se){
	fifoPriority = se.fifoPriority;
	message = 
	digest = new_char(SHA_DIGEST_LENGTH);
	memset(digest, 0, SHA_DIGEST_LENGTH);
	memcpy(digest, se.digest, SHA_DIGEST_LENGTH);
	incomingSockfd = se.incomingSockfd;
}

const SchedulerElement& operator = (const SchedulerElement& se){
	if (this! = &se){
		
	}
}*/

SchedulerElement::~SchedulerElement(){
/*	if ( message != NULL )
		delete message;
	if ( digest != NULL )
		delete digest;*/
}


PrioritySchedulerElement::PrioritySchedulerElement(){}

PrioritySchedulerElement::PrioritySchedulerElement(Message* _message, int _incomingSockfd, unsigned char* _digest, int _ip, int _kip):SchedulerElement( _message, _incomingSockfd, _digest){
	idPriority = _ip;
	keyedIdPriority = _kip;
}

PrioritySchedulerElement::~PrioritySchedulerElement(){}

Scheduler* Scheduler::instance(Type _type){
	static Scheduler s(_type);
	return &s;
}

Scheduler::Scheduler(Type _type){
	type = _type;
//	pq = new priority_queue<PrioritySchedulerElement>();
//	q = new queue<SchedulerElement>();
}
	
void Scheduler::add_dns_message (Message* message, int incomingSockfd) {
	Log::print ( "Entering Scheduler::add_dns_message\n", Log::VVVERBOSE);
	SchedulerElement* e = new SchedulerElement(message, incomingSockfd, NULL);
	dataq.push (*e);
	Log::print ( "Leaving Scheduler::add_dns_message\n", Log::VVVERBOSE);
}


void Scheduler::add_message(Message* message, int incomingSockfd, unsigned char* digest){
	Log::print ( "Entering Scheduler::add_message\n", Log::VVVERBOSE);
	switch (type){
		case FIFO:
			{
				SchedulerElement* e = new SchedulerElement(message, incomingSockfd, digest);
				q.push(*e);
				Log::print ( "Added message\n", Log:: Log::VERBOSE);
				break;
			}
		case PRIORITY: 
			{
				int ip=0;
				int kip=0;
				int count=0;
			
				typedef vector<PVElement>::iterator viter;
				vector<PVElement>* pkList=message->get_pk_list();
				assert (pkList !=NULL);
				for (viter i = pkList->begin(); i!=pkList->end() ; i++){
					Log::print ("count=" + to_string(count)+"\n", Log::VVVERBOSE);
					count++;
					Id* id = i->get_id();
					KeyedId* keyedId = i->get_keyed_id();
					int tmp1 = idMap[*id];
					int tmp2 = keyedIdMap[*keyedId];
					idMap[*id]++;
					keyedIdMap[*keyedId]++;
					if (tmp1>ip)
						ip = tmp1;
					if (tmp2>kip)
						kip = tmp2;
	
					delete id;
					delete keyedId;
				}
				PrioritySchedulerElement* e = new PrioritySchedulerElement(message, incomingSockfd, digest, ip, kip);
				pq.push (*e);
				Log::print ( "Added message\n", Log:: Log::VERBOSE);
				break;
			}
		default:
			Log::print ( "Wrong scheduler type\n", Log::SILENT);
			exit(1);
	}
	Log::print ( "Leaving Scheduler::add_message\n", Log::VVVERBOSE);
}


void Scheduler::print(){
}

Scheduler::Type Scheduler::get_type (){
	return type;
}


bool Scheduler::relay_message ( Server* server ){
	Log::print ( "Entering Scheduler::relay_message\n", Log::VVVERBOSE);
	bool flag = false;
	typedef deque<Neighbor>::iterator iter;
	deque<Neighbor>* neighbors = server->neighbors;
	Config*  config = server->config;
	/*	Get a handle on the message to be relayed. This message is not dequeued from the scheduler queue.*/
	const SchedulerElement* e = NULL;
	switch (type){
		case FIFO:
			if (q.size () >0)
				e = &q.front();
		break;
		case PRIORITY:
			if (pq.size() > 0)
				e = &pq.top();
		break;
		default:
			Log::print ( "Wrong scheduler type\n", Log::SILENT);
			exit(1);
	}

	/*	Handle the message according to its type. */
	if ( e!= NULL ){
		Message* message = e->message;
		unsigned char* digest = e->digest;
		switch ( message->type ){
			case Message::PV_MESSAGE:
				{
				Path* path = message->get_path ();
				
				
				/* Iterate through each neighbor */	
				for ( iter i = neighbors->begin(); i!=neighbors->end(); i++){
					if(	config->testTwoNode || 
							i->receiveSockfd != e->incomingSockfd){

						/*	Don't send the message back the way it came, 
							unless we want to do a two-node test.
							*/
							
						if(	i->status == Neighbor::AUTHENTICATED){

							/*	The node to which the message is forwarded
								is authenticated.*/

							KeyedId* ki = new KeyedId ( i->id, i->ip, i->publicKey);
							bool isPresent= (find (path->v.begin(), path->v.end(), *ki)!=path->v.end());
							if( config->testTwoNode ||
									!isPresent){
								/* 	Test to ensure no loops
									unless we want to do a two-node test.*/
								
								Log::print ("Trying to relay message to (IP=" + to_string(i->ip) + ",ID=" + to_string(i->id) + ")\n", Log::VERBOSE);
								
								/*	Send the incremented path vector.*/
								MessageHandler::send_increment_pv_message ( server, &(*i), message, digest);
							}else{
								Log::print ("Not relaying message to (IP=" + to_string(i->ip) + ",ID=" + to_string(i->id) + ") due to loop\n", Log::VERBOSE);
							}
							delete ki;
						}else{
							Log::print ("Not relaying message to unauthenticated (IP=" + to_string(i->ip) + ",ID=" + to_string(i->id) + ")\n", Log::NORMAL);
						}
					}else{
						Log::print ("Not relaying message back to (IP=" + to_string(i->ip) + ",ID=" + to_string(i->id) + ")\n", Log::NORMAL);
					}
				}
				Log::print ( "Here\n", Log::VVERBOSE);
				delete path;
				Log::print ( "Here\n", Log::VVERBOSE);
				}
			break;
			default:
				Log::print ( "Not handling message of unknown type\n", Log::NORMAL);
			break;
		}
		Log::print ( "Handled the message\n", Log::VVERBOSE);
		delete message;
		delete digest;
		Log::print ( "Deallocated memory\n", Log::VVERBOSE);
		/* This is where we deallocate the SchedulerElement (and the message that it points to) that was  examined */
		switch (type){
			case FIFO:
				q.pop();
			break;
			case PRIORITY:
				pq.pop();
			break;
			default:
				Log::print ( "Wrong scheduler type\n", Log::SILENT);
			exit(1);
		}	
		Log::print ( "Popped the scheduler\n", Log::VVERBOSE);
		flag = true;
	}
	Log::print ( "Leaving Scheduler::relay_message\n", Log::VVVERBOSE);
	return flag;
}


bool Scheduler::relay_dns_message ( Server* server ){
	bool flag = false;
	Log::print ( "Entering Scheduler::relay_dns_message\n", Log::VVVERBOSE);
	typedef deque<Neighbor>::iterator iter;
	deque<Neighbor>* neighbors = server->neighbors;

	SchedulerElement* e = NULL;
	if (dataq.size () >0)
		e = &dataq.front();
	if ( e!= NULL ){
		Message* message = e->message;
		for ( iter i = neighbors->begin(); i!=neighbors->end(); i++){
			if(	i->receiveSockfd != e->incomingSockfd){

				if(	i->status == Neighbor::AUTHENTICATED){
	
					/*	The node to which the message is forwarded
						is authenticated.*/

					MessageHandler::send_dns_message ( server, &(*i), message);
				}
			}
		}

		Log::print ( "Handled the message\n", Log::VVERBOSE);
		delete message;
		Log::print ( "Deallocated memory\n", Log::VVERBOSE);
		/* This is where we deallocate the SchedulerElement (and the message that it points to) that was  examined */
		dataq.pop();
		flag = true;
	}
	Log::print ( "Leaving Scheduler::relay_dns_message\n", Log::VVVERBOSE);
	return flag;
}

void Scheduler::dispatch_messages (Server* server){
	Log::print ( "Entering Scheduler::dispatch_message\n", Log::VVVERBOSE);
	for (int count = 0; count < server->config->msgsPerPoll ; count++ ){
		if ( !relay_message (server)  && !relay_dns_message (server))
			return;
	}
	Log::print ( "Leaving Scheduler::dispatch_message\n", Log::VVVERBOSE);
}

/* Reads LEN bytes from socket FD info BUF. It works just like
	 * recv() except that it ensures that you get all LEN bytes. */
static ssize_t safe_read(int fd, void* buf, size_t len) {
	int packet_len;
	char *bufp = (char*)buf;
	size_t received_so_far = 0;

	while (received_so_far < len) {
		errno = 0;
		packet_len = read(fd, bufp, len - received_so_far);

		if (packet_len > 0) {
			/* Place the incoming data in the appropriate place in the buffer. */
			bufp += packet_len;

			/* Update how much we have received so far. */
			received_so_far += packet_len;
		} else {
			/* recv() may have been interrupted by a system call. In such a
			 * case, try again rather than returning. */
			if (errno != EINTR) {
				/* BUG: shouldn't this be <= ? */
				if (packet_len <= 0) perror("read");
				return packet_len;
			}
		}
	}


	return received_so_far;
}


Message* Scheduler::receive_message (Server* server, int incomingSockfd ){

	/*	 First receive the message object.
		 Determine its type.
		 Then receive the subsequent path vectors.
	 */

	Message* message= new Message();
	int numBytes;

#if 0
	while(total < sizeof(Message)){
		numBytes=recv(incomingSockfd,((char *)message+total),sizeof(Message)-total,0);
		if (numBytes <=0)
			break;
		total+=numBytes;
	}
	Log::print ("Received a total of " + to_string(total) + " on socket " + to_string(incomingSockfd) + "\n", Log::VERBOSE);
#endif

	numBytes = safe_read(incomingSockfd, (char*)message, sizeof(Message));

	message->payload = NULL;
	message->pkList = NULL;
	message->sigList = NULL;


	if(numBytes<=0){
		/* 	Error in receiving the Message object.
				Close the connection and destroy the corresponding objects.
		 */
		Log::print ("Received " + to_string(numBytes) + " on socket " + to_string(incomingSockfd) + "\n", Log::VERBOSE);
		if(numBytes==0)
			Log::print ("Socket " + to_string(incomingSockfd)+ " closed\n", Log::NORMAL);
		else
			Log::print ("Error on socket " + to_string(incomingSockfd) + " closed\n", Log::NORMAL);
		Neighbor* neighbor;

		if( (neighbor=server->get_neighbor(incomingSockfd))!=NULL ){
			server->disconnect( neighbor);
		}
		close (incomingSockfd);
		FD_CLR (incomingSockfd, &(server->readfds));
	} else {
		/*	Receive the rest of the message based on its type.
		 */
		Log::print ("Here with message of size "+ to_string(message->payloadSize) +"\n", Log::VERBOSE);

		switch ( message->type){
			case Message::INIT_MESSAGE:
				MessageHandler::receive_init_message ( message, incomingSockfd);
				break;

			case Message::PV_MESSAGE:
				MessageHandler::receive_pv_message ( message, incomingSockfd);
				break;

			case Message::DNS_BROADCAST:
				MessageHandler::receive_dns_message (message, incomingSockfd);	
				break;

			default:
				break;
		} // End of switch ( message->type)

		Log::print ( "Leaving Scheduler::receive_message\n", Log::VERBOSE);		
		return message;
	}

	return NULL;
}
