#ifndef _DNSMESSAGE_H
#define _DNSMESSAGE_H

#include "global.h"

class Message;


class DNSMessage{
	public:
		static char* messageType [];
typedef enum {
	DNS_BROADCAST = 0
}  Type;

		Type type;
		int payloadSize;
		unsigned char* payload;

		DNSMessage ();
		DNSMessage ( Type _type, int payloadSize, unsigned char* payload);
		DNSMessage (const DNSMessage& _msg);
		const DNSMessage& operator = (const DNSMessage& _msg);
		void send (int sockfd);
		void receive (int sockfd);
		Message* get_message( Server* server);

		bool operator < (const DNSMessage& msg) const;
		bool operator == (const DNSMessage& msg) const;
};
#endif
