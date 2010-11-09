#ifndef _MESSAGE_H
#define _MESSAGE_H 
#include <iterator>
#include "logger.h"

class PVElement;
class Server;
class Neighbor;
class Path;
class DNSMessage;

class Message{
	public:
		static char* messageType[];
		typedef vector<PVElement> PVVector;


		static const int MESSAGE_TYPES=8;
		typedef enum {
			INIT_MESSAGE	= 0,
			PV_MESSAGE 		= 1,
			BEACON 			= 2,
			PVROUTER_MESSAGE = 3,
			LSROUTER_MESSAGE = 4,
			DVROUTER_MESSAGE = 5,
			DISCOVERY_MESSAGE= 6,
			DNS_BROADCAST	 = 7
			} Type ;
		Type type;
		
		
		int hopCount;
		/*  Right now there's no use for a payload.
			Just in case*/
		int payloadSize;
		unsigned char* payload;

		
		int id;
		char ip[IP_ADDRESS];

		/** So that we don't have to access the pathvector to get this info*/
		int lastId;
		char lastIp[IP_ADDRESS];
		PVVector* pkList;
		PVVector* sigList;


		Message ();
		Message ( Type _type, int _id, char* _ip);
		Message ( Type _type, int _id, char* _ip, PVVector* _pkList);
		Message ( Type _type, int _id, char* _ip, PVVector* _pkList, PVVector* _sigList);
		~Message ();
		Message (const Message & _m);
		const Message& operator = (const Message& _m);
		bool operator < (const Message& _m) const;

		bool operator == (const Message & _m) const;
		
		void send (int sockfd);
		Message* receive (int sockfd);


		void digest ( unsigned char *newDigest);
		static void incremental_digest (unsigned char* oldDigest, int digestSize, PVElement& pve, unsigned char* newDigest);
		static int sign (unsigned char* digest, int digestSize, RSA* privateKey, unsigned char** signature);
		bool verify ( unsigned char* digest);
		
		bool verify_dns ( RSA* publicKey);

		void increment (PVElement& pke, PVElement& se);

		PVElement* get_last_node ();
		PVElement* get_first_node();
		bool match_public_key (map<Id, RSA*>& neighborMap);

		void set_payload( const char* _payload, int _payloadSize);
		unsigned char* get_payload(int  &size); 

		Path* get_path ();
		vector<PVElement>* get_pk_list();
		vector<PVElement>* get_sig_list();
		void set_pk_list ( vector<PVElement>* _pkList);
		void set_sig_list ( vector<PVElement>* _sigList);

		friend ostream& operator << (ostream& os, const Message& message){
			vector<PVElement>* pkList = message.pkList;
			vector<PVElement>* sigList = message.sigList;
				os	<< "[hopcount="<<message.hopCount<<","
						<< "(id="<<message.id<<","
						<< "ip="<<message.ip<<"),"
						<< "(lastId="<<message.lastId<<","
						<< "lastIp="<<message.lastIp<<"),";
						
					if ( pkList!=NULL && pkList->size()> 0){
						os	<< "(PKList=";
						copy (pkList->begin(), pkList->end(), 
							ostream_iterator<PVElement> (os, ","));
						os << ")";
					}
					if ( sigList!=NULL && sigList->size()> 0){
						os	<< ",(sigList=";
						copy (sigList->begin(), sigList->end(), 
							ostream_iterator<PVElement> (os, ","));
						os << ")";
					}
					os	<< "]";
			return os;
		}

};

class MessageHandler{
	public:
		static int flush_object ( int sockfd, void* _buf, int length);
		static int receive_object ( int sockfd, void* _buf, int length);

		static void send_init_message ( Server* server, Neighbor* neighbor);

		static void send_init_pv_message ( Server* server, Neighbor* neighbor);

		static Message* convert_dns_message ( Server* server, DNSMessage* dnsMessage);
		
		static void send_dns_message ( Server* server, Neighbor* neighbor, Message* message);

		static void send_increment_pv_message( Server* server, Neighbor* neighbor, Message* message, unsigned char* oldDigest);

		static int relay_increment_pv_message ( Server* server, Neighbor* neighbor, Message* message, unsigned char* oldDigest, int incomingSockfd);
		
		static int relay_init_pv_message ( Server* server, Neighbor* neighbor, Message* message, unsigned char* oldDigest, int incomingSockfd);

		static int receive_init_message ( Message* message, int incomingSockfd );

		static int receive_pv_message ( Message* message, int incomingSockfd );

		static int receive_dns_message ( Message* message, int incomingSockfd );

		static int process_init_message (Server* server, Neighbor* neighbor, Message* message, int incomingSockfd);

		static int process_pv_message ( Server* server, Neighbor* neighbor, Message* message,int incomingSockfd);

		static int process_dns_message ( Server* server, Message* message, int incomingSockfd);
		
		static void path_vector_test( Server* server, Path* path);
		
};
#endif
