#ifndef _PV_H
#define _PV_H

#include "rsa.h"

class KeyedId;
class Id;
class PVElement{
	public:
		static char* pveType[];

		typedef enum { PK = 0, SIG = 1 } Type;
		int id;
		Type  type;
		char ip[IP_ADDRESS];
		unsigned char* payload;
		int payloadSize;
		int cost;

		PVElement ();
		PVElement ( const PVElement& _pve);
		PVElement ( Type _type, int _id, char* _address);
		PVElement ( Type _type, int _id, char* _address, unsigned char* _payload, int _payloadSize);
		PVElement ( Type _type, int _id, char* _address, unsigned char* _payload, int _payloadSize, int _cost);
		
		~PVElement();

		const PVElement& operator = (const PVElement& _pve);
		Type get_type ();
		unsigned char* get_payload();
		RSA* get_pk();		
		KeyedId* get_keyed_id ();
		Id* get_id();

		int send (int sockfd);
		int receive (int sockfd);

		friend ostream& operator << (ostream& os, const PVElement& pve){
			return os	<<"("
							<<pve.id<<","
							<<pve.ip<<","
							<<pveType[pve.type]<<","
							<<"payloadSize="<<pve.payloadSize
						<<")";
/*			return os	<<"("
							<<pve.id<<","
							<<pveType[pve.type]<<","
						<<")";*/
		}
		
};
#endif
