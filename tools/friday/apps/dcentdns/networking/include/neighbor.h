#ifndef _NEIGHBOR_H
#define _NEIGHBOR_H 

class KeyedId;
class Id;
class Server;

class Neighbor{
	public:
		typedef enum {
			DISCONNECTED	= 0,
			CONNECTED 		= 1,
			AUTHENTICATED 	= 2} Status;
		
		static char* statusString[];
		struct sockaddr_in address; 
		int id;
		char ip [IP_ADDRESS];

		Status status;
		int sockfd;
		int receiveSockfd;
		RSA* publicKey;
		unsigned char pkBuf[KEY_SIZE];
		int keySize;
		int cost;

		Neighbor ();
		Neighbor ( char* host, int port, int id );
		Neighbor ( char* host, int port, int id, int cost );
		Neighbor ( const Neighbor& _n );
		const Neighbor& operator = (const Neighbor& _n );
		~Neighbor ();
		
		KeyedId* get_keyed_id (Neighbor* neighbor);
		Id* get_id(Neighbor* neighbor);
		bool is_identity ( int id, char* ip);
		void print ();
		void change_status (Status _status);
		Status try_connect( Server* server);
		void disconnect();
		void set_public_key (RSA* publicKey);
		void set_public_key (unsigned char* _publicKey, int _keySize);
		
		friend ostream& operator<< (ostream& os, const Neighbor& _n){
			//return os<< "("<<_n.id<<","<<_n.ip<<")";
			return os<< "("<<_n.id<<")";
		}
};
#endif
