#include "global.h"
#include "rsa.h"
#include "logger.h"
#include "pv.h"

///CPP
char* PVElement::pveType[]={"PublicKey","Signature"};

PVElement::PVElement(){
	memset(ip,0,IP_ADDRESS);
	payloadSize = 0;
	payload =  NULL;
}

PVElement::PVElement ( const PVElement& _pve){
	id = _pve.id;
	type = _pve.type;
	memcpy (ip, _pve.ip, IP_ADDRESS);
	payloadSize = _pve.payloadSize;
	payload =  new_char (payloadSize);
	memcpy (payload, _pve.payload, payloadSize);
	cost = _pve.cost;
}

PVElement::~PVElement(){
	if (payloadSize>0 && payload!=NULL)
		free (payload);
}

PVElement::PVElement ( Type _type, int _id, char* _address){
	id = _id;
	type = _type;
	memset (ip, 0, IP_ADDRESS);
	memcpy (ip, _address, IP_ADDRESS);
	payloadSize = 0;
	payload = NULL;
	cost = 0;
}


PVElement::PVElement ( Type _type, int _id, char* _address, unsigned char* _payload, int _payloadSize) {
	id = _id;
	type = _type;
	memset (ip, 0, IP_ADDRESS);
	memcpy (ip, _address, IP_ADDRESS);
	payloadSize = _payloadSize;
	payload = new_char (payloadSize);
	memcpy ( payload, _payload, _payloadSize );
	cost = 0;
}

PVElement::PVElement ( Type _type, int _id, char* _address, unsigned char* _payload, int _payloadSize, int _cost) {
	id = _id;
	type = _type;
	memset (ip, 0, IP_ADDRESS);
	memcpy (ip, _address, IP_ADDRESS);
	payloadSize = _payloadSize;
	payload = new_char (payloadSize);
	memcpy ( payload, _payload, _payloadSize );
	cost = _cost;
}

const PVElement& PVElement::operator = (const PVElement& _pve){
	if (this != &_pve){
		id = _pve.id;
		type = _pve.type;
		memset (ip, 0, IP_ADDRESS);
		memcpy (ip, _pve.ip, IP_ADDRESS);
		payloadSize = _pve.payloadSize;
		payload = new_char (payloadSize);
		memcpy ( payload, _pve.payload, payloadSize);
		cost = _pve.cost;
	}
	return *this;
}

PVElement::Type PVElement::get_type(){
	return type;
}

unsigned char* PVElement::get_payload(){
	return payload;
}

RSA* PVElement::get_pk(){
	assert ( type == PK );
	RSA* publicKey = char_to_public_key ( payload, payloadSize);
	return publicKey;
}

int PVElement::send (int sockfd){
	int result1 = MessageHandler::flush_object (sockfd, this, sizeof(PVElement));
	if (result1 <= 0) return -1;
	int result2 = MessageHandler::flush_object (sockfd, payload, payloadSize );
	if (result2 <= 0) return -1;
	return result1+result2;
}

int PVElement::receive (int sockfd){
	Log::print ( "Entering PVElement::receive\n", Log::VVVERBOSE);		
	int result1  = MessageHandler::receive_object (sockfd, this, sizeof(PVElement));
	if (result1 <= 0) return -1;
	payload = new_char (payloadSize);
	Log::print ("Here\n", Log::VERBOSE);
	result1 = MessageHandler::receive_object (sockfd, payload, payloadSize);
	if (result1 <= 0) return -1;
	Log::print ( "Leaving PVElement::receive\n", Log::VVVERBOSE);		
	return 0;
}


Id* PVElement::get_id(){
	Id* tmpId = new Id (id, ip);
	assert (tmpId!=NULL);
	return tmpId;
}

KeyedId* PVElement::get_keyed_id (){
	RSA* publicKey = char_to_public_key (payload, payloadSize);
	KeyedId* keyedId = new KeyedId (id, ip, publicKey);
	delete_rsa (&publicKey);
	assert (keyedId != NULL);
	return keyedId;
}
