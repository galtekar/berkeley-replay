#include <errno.h>

#include "global.h"
#include "dnsmessage.h"

Server* server = NULL;

static void generate_fake_dns_message() {
	unsigned char zero_buf[256];
	static int rnum = 0;

	//rnum = 1+(int)(20.0 * rand()/(RAND_MAX+1.0));
	rnum++;


	sprintf((char*)zero_buf, "Hello %d from DNS server %d.", rnum, server->id);

	DNSMessage* dnsmessage = new DNSMessage (DNSMessage::DNS_BROADCAST,
			sizeof(zero_buf), zero_buf);

	typedef deque<Neighbor>::iterator diter;

	assert(server != NULL);

	/* Broadcast the DNS message to all neighbors. */

	for ( diter i = server->neighbors->begin(); i != 
			server->neighbors->end(); i++){

		if(i->status == Neighbor::AUTHENTICATED){
			Message* message = 
				MessageHandler::convert_dns_message (server, dnsmessage);

			MessageHandler::send_dns_message ( server, &(*i), message); 
		}
	}

	printf("Broadcasted fake message: ``%s''.\n", zero_buf);
}

static void sig_handler(int sigNum) {

	switch(sigNum) {
		case SIGALRM:
			generate_fake_dns_message();
			break;
	}
}

void Server::disconnect (Neighbor* neighbor){
	KeyedId ki(neighbor->id,inet_ntoa(neighbor->address.sin_addr),neighbor->publicKey);
	Id id(neighbor->id,inet_ntoa(neighbor->address.sin_addr));
	neighbor->disconnect();

	set<Edge>* edgeSet = dc->get_edge_set();	
	/*	We remove only the edges.
		The rest of the state remains till we get more up-to-date information.
	 */
	typedef set<Edge>::iterator iter;
	for (iter i = edgeSet->begin(); i!=edgeSet->end(); i++){
		Edge e = *i;
		// For now, we retain these edges.
		/*		if (e.v1 == ki || e.v2 == ki)
				dc->delete_edge(e);*/
	}
}	

Server::Server ( char* filename ){
	state=Server::BOOT;
	FD_ZERO(&(readfds));
	FD_ZERO(&(writefds));
	FD_ZERO(&(exceptfds));
	FD_ZERO(&(tempreadfds));
	FD_ZERO(&(tempwritefds));
	FD_ZERO(&(tempexceptfds));

	config = Config::instance(filename);
	config->init_server (this);
	log = Log::instance ( config->level, id, ip, port);
	//	fptr=init_log(id,inet_ntoa(address.sin_addr),ntohs(address.sin_port), config->level);

	Log::print ( "Init log completed\n", Log::NORMAL);

	reuse=1;
	if((listener=socket(AF_INET,SOCK_STREAM,0))==-1){
		Log::print ( "Error in socket call.", Log::SILENT);
		perror("socket");
		exit(2);
	}
	if(setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(int))==-1){
		Log::print ( "Error in setsocketopt call.", Log::SILENT);
		perror("setsockopt");
		exit(1);
	}

	if(bind(listener,(struct sockaddr *)&(address),sizeof(struct sockaddr))==-1){
		Log::print ( "Error in bind call.", Log::SILENT);
		perror("bind");
		exit(1);
	}

	if(listen(listener,10)==-1){
		Log::print ( "Error in listen call.", Log::SILENT);
		perror("listen");
		exit(1);
	}
	FD_SET(listener,&(readfds));
	fdmax=listener;

	add_checkpoint(GENERATE_KEY_START,0);
	privateKey=RSA_generate_key(KEY_SIZE,RSA_F4,NULL,NULL);
	add_checkpoint(GENERATE_KEY_END,0);
	publicKey=private_to_public(privateKey);
	for(int i=0;i<KEY_SIZE;i++)
		pkBuf[i]=0;
	keySize=public_key_to_char(publicKey,pkBuf,KEY_SIZE);

	Log::print ("Starting up\n", Log::NORMAL);
	Log::print ("In mode:" + to_string(config->level) + "\n", Log::SILENT);
	Log::print ("Router type:"  + to_string(config->routerType) + "\n", Log::SILENT);
	Log::print ("Malicious:" + to_string(isMalicious) + "\n", Log::SILENT);
	Log::print ("k=" + to_string(k) + "\n", Log::SILENT);
	Log::print ("My address:(IP=" + to_string(ip) + ", Port=" + to_string(port) + ", ID=" + to_string(id) + ")\n", Log::NORMAL);
	Log::print ("My public key:\n", Log::NORMAL);
	Log::dump (pkBuf, keySize, Log::NORMAL);
	Log::print ("\n", Log::NORMAL, false);
	neighbors = init_neighbors ( config->neighborFile );
	Log::print ("Initialized my neighbor entries\n", Log::NORMAL);

	dc				= DataContainer::instance ();
	knownNodeMap 	= new map <KeyedId, PathList>();
	unknownNodeMap 	= new map <KeyedId, PathList>();
	neighborMap	= new map <Id, RSA*>();

	provisionalMap	= new map <KeyedId, int>();
	optimizedNodeMap= new map <KeyedId, int>();
	Log::print ( "Initialized maps\n", Log::NORMAL);

	KeyedId ki (id,inet_ntoa(address.sin_addr),publicKey);
	PathList pl ;
	Id tmpid (id,inet_ntoa(address.sin_addr));
	knownNodeMap->insert ( make_pair(ki, pl) );
	map<Id, RSA*>* keyMap = dc->get_key_map();
	keyMap->insert (make_pair(tmpid,publicKey));
	optimizedNodeMap->insert ( make_pair(ki, 0) );
	dc->add_node (ki, true);

	eventq = EventQ::instance();
	eventq->add_event(config->warmupTime,Event::END_WARMUP);
	scheduler = Scheduler::instance( config->schedulerType );
	isNeighborDown= true;

	pvSent=0;
	pvReceived=0;
	srand((unsigned)time(NULL));
	eventq->add_event ( config->flowComputeInterval, Event::COMPUTE_FLOWS );

	struct itimerval timer, otimer;

#define DEFAULT_STABILIZE_PERIOD 120000000.0
	int STABILIZE_PERIOD = 1+(int)(DEFAULT_STABILIZE_PERIOD * rand()/(RAND_MAX+1.0));

	timer.it_interval.tv_sec  = STABILIZE_PERIOD / 1000000;
	timer.it_interval.tv_usec = STABILIZE_PERIOD % 1000000;

	timer.it_value.tv_sec  = STABILIZE_PERIOD / 1000000;
	timer.it_value.tv_usec = STABILIZE_PERIOD % 1000000;

	setitimer(ITIMER_REAL, &timer, &otimer);

	signal(SIGALRM, sig_handler);
	signal(SIGPIPE,SIG_IGN);
}


Server::~Server (){
	delete config;
	delete eventq;
	delete scheduler;

	RSA_free(privateKey);
	delete_rsa(&publicKey);
}

Server* Server::instance (char* filename){
	static Server s (filename);
	return &s;
}

void Server::run() {
	/* Wait for all events to happen*/
	for(;;) {
		int newfd;
		int addrlen;
		struct timeval timeout;

		poll();

		tempreadfds = readfds;
		tempwritefds = writefds;
		exceptfds = exceptfds;
		timeout.tv_sec = config->pollInterval.tv_sec;
		timeout.tv_usec = config->pollInterval.tv_usec;

		if (select ( fdmax+1, &tempreadfds, &tempwritefds, 
					&tempexceptfds, &timeout) < 0) {

			if (errno == EINTR) {
				continue;
			} else {
				assert(0);
			}
		} 

		for(int i=0; i <= fdmax; i++) {
			if(FD_ISSET (i, &tempreadfds)) {

				if(i == listener) {
					/*	Possible new connection */
					struct sockaddr_in remoteAddr;
					addrlen = sizeof(remoteAddr);

					if( (newfd = accept (listener, (struct sockaddr *)&remoteAddr, (socklen_t *)&addrlen)) ==-1) {
						Log::print ( "Error in Server::run(). Exiting\n", Log::SILENT);
						exit (1);
					} else{
						/* Got a new connection */
						FD_SET(newfd,&(readfds));
						if(newfd > fdmax)
							fdmax=newfd;
					}
				} else {
					/* New data on an an established connection*/
					Message* message = scheduler->receive_message ( this, i);
					if (!message) continue;

					assert(!(message->type < 0 || message->type >=
								Message::MESSAGE_TYPES));

					Neighbor* neighbor = NULL;

					switch ( message->type ) {
						case Message::INIT_MESSAGE: 
							{
								neighbor = is_neighbor(message->id,message->ip);
								assert(neighbor != NULL);

								assert(neighbor->status == Neighbor::CONNECTED);

								PVElement* tmp = message->get_first_node();

								assert(tmp != NULL);

								neighbor->status = Neighbor::AUTHENTICATED;
								neighbor->set_public_key (tmp->payload, tmp->payloadSize);
								neighbor->receiveSockfd=i;
								cout << "Authenticated neighbor (" + to_string(message->ip) + "," + to_string(message->id) +") on socket " + to_string (neighbor->receiveSockfd)+ "\n";

								KeyedId ki (neighbor->id, neighbor->ip, 
										neighbor->publicKey);

								Id id (neighbor->id, neighbor->ip);
								/*	Create a path representing the edge to this neighbor*/
								Path path ;
								path.add_element (ki);
								KeyedId myki (this->id, ip, publicKey);
								path.add_element (myki);

								PathList tmpPathList = PathList (path);

								/*	Update all the maps */
								knownNodeMap->insert ( make_pair(ki, tmpPathList) );
								map<Id, RSA*>* keyMap = dc->get_key_map();
								keyMap->insert (make_pair(id, neighbor->publicKey));
								optimizedNodeMap->insert ( make_pair(ki, 0) );
								dc->add_node (ki, true);
								/*	Add the reverse edge when 
									we get an INIT_PV message from our neighbor.
								 */
								Edge e(myki, ki);
								dc->add_edge (e);
								neighborMap->insert (make_pair(id, neighbor->publicKey));

								MessageHandler::process_init_message(this, neighbor, message, i);
								set <KeyedId>* knownNodeSet = dc->get_known_node_set();
								set<KeyedId>* unknownNodeSet = dc->get_unknown_node_set();

								Log::print ("Number of verified nodes:" + to_string(knownNodeSet->size()) + "\n", Log::NORMAL);
								Log::print ( "List of verified nodes\n" + to_string (*knownNodeSet), Log::VERBOSE);
								Log::print ("Number of unverified nodes:" + to_string(unknownNodeSet->size()) + "\n", Log::NORMAL);
								Log::print ( "List of unverified nodes\n" + to_string (*unknownNodeSet), Log::VERBOSE);
								Log::print ("Number of optimized verified nodes:" + to_string(optimizedNodeMap->size()) + "\n", Log::NORMAL);
								Log::print ("Number of edges:" + to_string((dc->get_edge_set())->size()) + "\n", Log::NORMAL);
								for ( map<KeyedId, PathList>::iterator i = unknownNodeMap->begin(); i != unknownNodeMap->end() ; i++){
									const PathList& p = i->second;
									Log::print ("Path:"+to_string(p)+"\n", Log::VERBOSE);
								}

								/* 	Schedule a SEND_INIT_PV event
										since we have a new node authenticated
								 */
								long time  = config->wakeupTime;
								if (!eventq->is_present_event (Event::SEND_INIT_PV) ){
									eventq->add_event ( time, Event::SEND_INIT_PV );
								}
							}
							break;

						case Message::PV_MESSAGE:
							{
								PVElement* lastNode=message->get_last_node();
								Log::print ( "Last node = (" + to_string(message->lastId) + "," + to_string (message->lastIp) + ")\n", Log::VERBOSE);
								int result = -1;

								neighbor=is_neighbor(lastNode->id,lastNode->ip);

								assert(neighbor != NULL);

								result = MessageHandler::process_pv_message (this, 
										neighbor, message, i);

								if(result==-1){
									delete message;
								} else {
									// The message is freed when it is queued out of the scheduler
								}
							}
							break;

						case Message::DNS_BROADCAST:
							MessageHandler::process_dns_message (this, message, i);	
							break;

						default:
							Log::print ("Unexpected packet type\n", Log::NORMAL);
							break;
					}
				}
			}
		}
	}
}


void Server::poll (){

	if( isNeighborDown ) {

		isNeighborDown = false;
		typedef deque<Neighbor>::iterator iter;
		long time  = config->wakeupTime;

		for ( iter i = neighbors->begin(); i != neighbors->end(); i++ ){

			Neighbor::Status status = i->try_connect (this);

			int is_valid_status = (status == Neighbor::CONNECTED);
			int is_in_queue = eventq->is_present_event (Event::SEND_INIT_PV);

			//printf("1=%d 2=%d\n", is_valid_status, is_in_queue);

			if (is_valid_status && !is_in_queue) {
				//cout << "Adding SEND_INIT_PV to queue.\n";
				eventq->add_event ( time, Event::SEND_INIT_PV );
			}

			if (status != Neighbor::AUTHENTICATED )
				isNeighborDown = true;
		}
	}

	eventq->dispatch_events (this);
	scheduler-> dispatch_messages (this);
}

Neighbor* Server::is_neighbor ( int id, char* ip){	
	typedef deque<Neighbor>::iterator diter;
	for (diter i = neighbors->begin(); i != neighbors->end(); i++) {
		if ( i->is_identity (id, ip)){
			return &(*i);
		}
	}

	return NULL;
}

Neighbor* Server::get_neighbor ( int incomingSockfd){	
	typedef deque<Neighbor>::iterator diter;
	for (diter i = neighbors->begin(); i != neighbors->end(); i++) {
		if ( i->receiveSockfd == incomingSockfd){
			return &(*i);
		}
	}
	return NULL;
}


deque <Neighbor>* Server::init_neighbors( char* filename ){
	Log::print ( "Entering Server::init_neighbors\n", Log::VVVERBOSE);
	string idString;
	string hostnameString;
	string portString;
	neighbors = new deque<Neighbor>();
	ifstream inp (filename);
	while ( ! std::getline (inp, idString, '_').eof()){
		std::getline (inp, hostnameString, '_');
		std::getline (inp, portString);
		int id = atoi(idString.c_str());
		int port = atoi (portString.c_str());
		char* hostname = strdup (hostnameString.c_str());
		Neighbor* neighbor = new Neighbor (hostname, port, id);
		neighbors->push_back (*neighbor);
	}
	inp.close();
	Log::print ( "Exiting Server::init_neighbors\n", Log::VVVERBOSE);
	return neighbors;
}

map<Id, RSA*>* Server::get_key_map(){
	return dc->get_key_map();
}

int main ( int argc, char* argv[] ){

	if (argc == 2){
		server = Server::instance (argv[1]);
		server->run();
	} else {
		printf("Usage:%s config file\n", argv[0]);
		exit(1);
	}

	delete server;
}
