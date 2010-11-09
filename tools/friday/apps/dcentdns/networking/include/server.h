#ifndef _SERVER_H
#define _SERVER_H 

class Config;
class Scheduler;
class EventQ;
class Neighbor;
class PathList;
class Edge;
class Log;
class DataContainer;
class Id;

class Server{
		Server ( char* filename );
	public:
		typedef enum {
			BOOT = 1,
			INIT = 2,
			STABLE = 3} State;

		fd_set readfds;
		fd_set writefds;
		fd_set exceptfds;

		fd_set tempreadfds;
		fd_set tempwritefds;
		fd_set tempexceptfds;
		int listener;
		int fdmax;
		
		Config* config;
		Log* log;
		
		struct sockaddr_in address;
		char ip [IP_ADDRESS];
		int id;
		int port;


		deque<Neighbor>* neighbors;
		bool  isNeighborDown;
		int state;
		int reuse;
		int k;

		RSA* privateKey;
		RSA* publicKey;
		unsigned char pkBuf[KEY_SIZE];
		int keySize;

		map <Id, RSA*> *neighborMap;
		map <KeyedId, PathList> *knownNodeMap;
		map <KeyedId, PathList> *unknownNodeMap;
		map <KeyedId, int> *provisionalMap, *optimizedNodeMap;

		DataContainer* dc;


		int isMalicious;
		int chain;
		FILE* fptr;
	
		struct timeval timer;
		Scheduler* scheduler;
		EventQ* eventq;

		int pvSent;
		int pvReceived;
	
		int dnssockfd;
		struct sockaddr_in dnsAddr;
		bool dnsConnected;

		static Server* instance (char* filename);
		void poll();
		void run ();
		Neighbor* is_neighbor ( int id, char* ip);
		Neighbor* get_neighbor ( int incomingSockfd);
		~Server ();
		//void sig_handler ( int sigNum );
		void disconnect (Neighbor* neighbor);
		deque <Neighbor>* init_neighbors( char* filename );
		void dns_init();
		int dns_connect();
		map<Id, RSA*>* get_key_map();
};

#endif
