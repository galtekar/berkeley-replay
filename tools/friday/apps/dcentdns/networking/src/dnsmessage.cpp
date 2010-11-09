#include "dnsmessage.h"

DNSMessage::DNSMessage(){}

DNSMessage::DNSMessage ( Type _type, int _payloadSize, unsigned char* _payload ){
	type = _type;
	payloadSize = _payloadSize;
	payload = _payload;
/*	payload = new_char (payloadSize);
	assert (payload != NULL);
	memcpy (payload, _payload, payloadSize);*/
}
/*
DNSMessage::DNSMessage (const DNSMessage& _m){
	type = _m.type;
	payloadSize = _m.payloadSize;
	memcpy (payload, _m.payload, payloadSize);
}

const DNSMessage& DNSMessage::operator = (const DNSMessage& _m){
	if (this != &_m){
		type = _m.type;
		payloadSize = _m.payloadSize;
		memcpy (payload, _m.payload, payloadSize);
	}
	return *this;
}
*/

bool DNSMessage::operator < (const DNSMessage& _m) const {
	int size = payloadSize<_m.payloadSize?payloadSize:_m.payloadSize;
	int flag = memcmp ( payload, _m.payload, size);	
	bool result;
	if (flag < 0)
		result = true;
	else
		result = false;
	return result;
}

bool DNSMessage::operator == (const DNSMessage& _m) const{
	if ( payloadSize!= _m.payloadSize)
		return false;
	else {
		int flag = memcmp (payload, _m.payload, payloadSize);
		return (flag==0)?true:false;
	}
}

void DNSMessage::receive(int sockfd){
	Log::print ("Entering DNSMessage::receive\n", Log::VERBOSE);
	MessageHandler::receive_object ( sockfd, this, sizeof(DNSMessage));
	payload = new_char (payloadSize);
	MessageHandler::receive_object ( sockfd, payload, payloadSize);
	Log::print ("Leaving DNSMessage::receive\n", Log::VERBOSE);
}

void DNSMessage::send (int sockfd){
	MessageHandler::flush_object (sockfd, this, sizeof (DNSMessage));
	MessageHandler::flush_object (sockfd, payload, payloadSize);
}

Message* DNSMessage::get_message(Server* server){
	Message* message = new Message ( Message::DNS_BROADCAST, server->id, server->ip);
	message->payloadSize = payloadSize;
	memcpy ( message->payload, payload, payloadSize);
	return message;
}


