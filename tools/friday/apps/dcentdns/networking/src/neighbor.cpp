#include "global.h"
#include "logger.h"
#include "rsa.h"
#include "keyedlist.h"
#include "neighbor.h"
#include "message.h"
#include "server.h"
#include "server.h"


////CPP
char* Neighbor::statusString[]={"Disconnected","Connected","Authenticated"};

Neighbor::Neighbor (){
}


Neighbor::Neighbor ( char* _host, int _port, int _id ){
	Log::print ("Entering Neighbor::Neighbor\n", Log::VVVERBOSE);
	struct hostent *he;
	he = gethostbyname(_host);

	address.sin_family = AF_INET;
	address.sin_port = htons(_port);


	address.sin_addr = *((struct in_addr *)he->h_addr);
	memcpy ( ip, inet_ntoa (address.sin_addr), IP_ADDRESS);
	memset(&(address.sin_zero),'\0',8);
	status = DISCONNECTED;
	sockfd = socket(AF_INET,SOCK_STREAM,0);
	id = _id;
	receiveSockfd = -1;
	publicKey = NULL;
	memset (pkBuf, 0, KEY_SIZE);
	keySize = 0;
	cost = 0;

	printf("Created neighbor object: id=%d hostname=%s ip=%s port=%d\n",
			_id, he->h_name, ip, _port);

	Log::print ("Leaving Neighbor::Neighbor\n", Log::VVVERBOSE);
}

Neighbor::Neighbor ( char* _host, int _port, int _id, int _cost ) {
	struct hostent *he;
	he = gethostbyname(_host);
	address.sin_family = AF_INET;
	address.sin_port = htons(_port);
	address.sin_addr = *((struct in_addr *)he->h_addr);
	memcpy ( ip, inet_ntoa (address.sin_addr), IP_ADDRESS);
	memset(&(address.sin_zero),'\0',8);
	status = DISCONNECTED;
	sockfd = socket(AF_INET,SOCK_STREAM,0);
	id = _id;
	receiveSockfd = -1;
	publicKey = NULL;
	memset (pkBuf, 0, KEY_SIZE);
	keySize = 0;
	cost = _cost;
}

Neighbor::Neighbor ( const Neighbor& _n ){
	address.sin_family = _n.address.sin_family;
	address.sin_port = _n.address.sin_port;
	address.sin_addr = _n.address.sin_addr;
	memcpy ( ip, _n.ip, IP_ADDRESS);
	memset( &(address.sin_zero), '\0', 8);
	status = _n.status;
	sockfd = _n.sockfd;
	receiveSockfd = _n.receiveSockfd;
	id = _n.id;
	publicKey = RSAPublicKey_dup (_n.publicKey);
	memset (pkBuf, 0, KEY_SIZE);
	keySize = public_key_to_char ( publicKey, pkBuf, KEY_SIZE);
	cost = _n.cost;
}

const Neighbor& Neighbor::operator = (const Neighbor& _n ){
	if (this != &_n){
		address.sin_family = _n.address.sin_family;
		address.sin_port = _n.address.sin_port;
		address.sin_addr = _n.address.sin_addr;
		memcpy ( ip, _n.ip, IP_ADDRESS);
		memset( &(address.sin_zero), '\0', 8);
		status = _n.status;
		sockfd = _n.sockfd;
		receiveSockfd = _n.receiveSockfd;
		id = _n.id;
		publicKey = RSAPublicKey_dup (_n.publicKey);
		memset (pkBuf, 0, KEY_SIZE);
		keySize = public_key_to_char ( publicKey, pkBuf, KEY_SIZE);
		cost = _n.cost;
	}
	return *this;
}

Neighbor::~Neighbor () { 
	if (keySize > 0 && publicKey!=NULL) {
		delete_rsa (&publicKey);		
		memset (pkBuf, 0, KEY_SIZE);
		keySize = 0;
	}
}

KeyedId* Neighbor::get_keyed_id(Neighbor* neighbor){
	if(neighbor->status!=AUTHENTICATED)
		return NULL;
	return new KeyedId(neighbor->id, neighbor->ip,neighbor->publicKey);
}

Id* Neighbor::get_id(Neighbor* neighbor){
	return new Id(neighbor->id, neighbor->ip);
}

Neighbor::Status Neighbor::try_connect( Server* server){
	if (status == DISCONNECTED ){
		if(connect (sockfd, (struct sockaddr *)&address, sizeof(address))!=-1){
			cout << "Connected successfully to (" + to_string(inet_ntoa(address.sin_addr)) + "," + to_string(ntohs(address.sin_port)) + "," + to_string(id) + ") on socket " + to_string(sockfd) + "\n";

			Log::print ("Connected successfully to (" + to_string(inet_ntoa(address.sin_addr)) + "," + to_string(ntohs(address.sin_port)) + "," + to_string(id) + ") on socket " + to_string(sockfd) + "\n", Log::NORMAL);
			MessageHandler::send_init_message(server, this);
			status=CONNECTED;
		}
	}
	return status;
}

void Neighbor::disconnect(){
	status = DISCONNECTED;
	close(sockfd);
	sockfd = socket(AF_INET,SOCK_STREAM,0);
}

void Neighbor::print (){
	Log::print ("(ID=" + to_string(id) + ",IP=" + ip + ",Port=" + to_string(ntohs (address.sin_port)) + ",Status=" + statusString[status] + ",Send socket=" + to_string (sockfd) + ",Receive socket=" + to_string(receiveSockfd) + "\n", Log::NORMAL);
}

void Neighbor::change_status (Status _status){
	status = _status;
}


bool Neighbor::is_identity( int _id, char * _ip){
	if ( (strcmp (ip , _ip)==0) && (id == _id))
		return true;
	else
		return false;
}

void Neighbor::set_public_key (RSA* publicKey){
	publicKey = RSAPublicKey_dup (publicKey);
	keySize = public_key_to_char( publicKey, pkBuf, KEY_SIZE);
}

void Neighbor::set_public_key (unsigned char* _publicKey, int _keySize){
	publicKey = char_to_public_key (_publicKey, _keySize);
	keySize = _keySize;
	memcpy (pkBuf, _publicKey, _keySize);
}
