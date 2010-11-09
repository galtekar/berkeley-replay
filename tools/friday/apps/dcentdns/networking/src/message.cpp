#include "global.h"
#include "logger.h"
#include "keyedlist.h"
#include "server.h"
#include "message.h"
#include "neighbor.h"
#include "rsa.h"
#include "pv.h"
#include "scheduler.h"
#include "checkpoint.h"

#include <errno.h>

char* Message::messageType[]={"Init","PV", "Beacon","PVRouterMessage", "LSRouterMessage", "DVRouterMessage", "DiscoveryMessage", "BroadcastMessage"};

extern Server* server;


///CPP

Message::Message(){
	Log::print ( "Entering Message::Message\n", Log::VVVERBOSE);
	payloadSize = 0;
	payload = NULL;
	id = -1;
	lastId = -1;
	memset ( ip, 0, IP_ADDRESS);
	memset (lastIp, 0, IP_ADDRESS);
	pkList = NULL;
	sigList = NULL;
	Log::print ( "Leaving Message::Message\n", Log::VVVERBOSE);
}

Message::Message ( Type _type, int _id, char* _ip){
	Log::print ( "Entering Message::Message(,,)\n", Log::VVVERBOSE);
	type = _type;
	payloadSize = 0;
	payload = NULL;
	id = _id;
	lastId = id;
	memset ( ip, 0, IP_ADDRESS);
	memcpy ( ip, _ip, IP_ADDRESS);
	memset ( lastIp, 0, IP_ADDRESS);
	memcpy ( lastIp, ip, IP_ADDRESS);

	pkList = NULL;
	sigList = NULL;
	switch (type){
		case INIT_MESSAGE:
			hopCount = 0;
			break;
		case PV_MESSAGE:
			hopCount = 1;
			break;	
		case DNS_BROADCAST:
			hopCount = 0;
			break;
		default:
			hopCount = 0;
			break;
	}
	Log::print ( "Leaving Message::Message\n", Log::VVVERBOSE);
}

Message::Message ( Type _type, int _id, char* _ip, vector<PVElement>* _pkList){
	Log::print ( "Entering Message::Message(:,:,:,:)\n", Log::VVVERBOSE);
	type = _type;
	payloadSize = 0;
	payload = NULL;
	id = _id;
	lastId = id;
	memset ( ip, 0, IP_ADDRESS);
	memcpy ( ip, _ip, IP_ADDRESS);
	memset (lastIp, 0, IP_ADDRESS);
	memcpy ( lastIp, ip, IP_ADDRESS);
	
	pkList = new vector<PVElement>();
	*pkList = *_pkList;
	sigList = NULL;
	switch (type){
		case INIT_MESSAGE:
			hopCount = pkList->size();
			break;
		case PV_MESSAGE:
			hopCount = 1;
			break;	
		case DNS_BROADCAST:
			hopCount = 0;
			break;
		default:
			hopCount = 0;
			break;
	}
	Log::print ( "Leaving Message::Message (:,:,:,:)\n", Log::VVVERBOSE);
}


Message::Message ( Type _type, int _id, char* _ip, vector<PVElement>* _pkList, vector<PVElement>* _sigList){
	Log::print ( "Entering Message::Message (:,:,:,:,:)\n", Log::VVVERBOSE);
	type = _type;
	payloadSize = 0;
	payload = NULL;
	id = _id;
	lastId = id;
	memset ( ip, 0, IP_ADDRESS);
	memcpy ( ip, _ip, IP_ADDRESS);
	memset (lastIp, 0, IP_ADDRESS);
	memcpy ( lastIp, ip, IP_ADDRESS);
	
	if ( _pkList != NULL) {
		pkList = new vector<PVElement>();
		*pkList = *_pkList;
	} else
		pkList = NULL;
	if ( _sigList != NULL) {
		sigList = new vector<PVElement>();
		*sigList = *_sigList;
	} else
		sigList = NULL;
	switch (type){
		case INIT_MESSAGE:
			hopCount = 0;
			break;
		case PV_MESSAGE:
			hopCount = 1;
			break;	
		case DNS_BROADCAST:
			hopCount = 0;
			break;
		default:
			hopCount = 0;
			break;
	}
	Log::print ( "Leaving Message::Message(:,:,:,:,:)\n", Log::VVVERBOSE);
}

Message::Message (const Message& _m){
	Log::print ( "Entering Message::copy_constructor\n", Log::VVVERBOSE);
	type = _m.type;
	hopCount = _m.hopCount;
	payloadSize = _m.payloadSize;
	payload = new_char (payloadSize);
	memcpy (payload, _m.payload, payloadSize) ;
	id = _m.id;
	lastId = _m.id;
	memset ( ip, 0, IP_ADDRESS);
	memset (lastIp, 0, IP_ADDRESS);
	memcpy (ip, _m.ip, IP_ADDRESS);
	memcpy (lastIp, _m.ip, IP_ADDRESS);
	
	pkList = NULL;
	sigList= NULL;
	if ( _m.pkList !=NULL){
		pkList = new vector<PVElement>();
		*pkList = *(_m.pkList);
	}
	if ( _m.sigList!=NULL) {
		sigList = new vector<PVElement>();
		*sigList = *(_m.sigList);
	}
	Log::print ( "Leaving Message::copy_constructor\n", Log::VVVERBOSE);
}

const Message& Message::operator = (const Message& _m){
	Log::print ( "Entering Message::=\n", Log::VVVERBOSE);
	if (this != &_m){
		type = _m.type;
		hopCount = _m.hopCount;
		payloadSize = _m.payloadSize;
		if (payload !=NULL)
			delete payload;
		payload = new_char (payloadSize);
		memcpy (payload, _m.payload, payloadSize) ;
		id = _m.id;
		lastId = _m.id;
		memset ( ip, 0, IP_ADDRESS);
		memset (lastIp, 0, IP_ADDRESS);
		memcpy (ip, _m.ip, IP_ADDRESS);
		memcpy (lastIp, _m.ip, IP_ADDRESS);

		if ( pkList !=NULL){
			delete pkList;
			pkList = NULL;
		}
		if ( sigList!=NULL) {
			delete sigList;
			sigList = NULL;
		}

		if ( _m.pkList != NULL){
			pkList = new vector<PVElement>();
			*pkList = *(_m.pkList);
		}

		if ( _m.sigList != NULL ){
			sigList = new vector<PVElement>();
			*sigList = *(_m.sigList);
		}
	}
	Log::print ( "Leaving Message::=\n", Log::VVVERBOSE);
	return *this;
}

Message::~Message (){
	Log::print ( "Entering Message::~Message\n", Log::VVVERBOSE);
	if ( pkList!= NULL)
		delete pkList;
	if ( sigList!= NULL ) 
		delete sigList;
	if ( payloadSize>0 &&  payload != NULL )
		delete payload;
	Log::print ( "Leaving Message::~Message\n", Log::VVVERBOSE);
}

bool Message::operator < (const Message& _m) const{
	if ( id<_m.id){
		return true;
	} else if (id>_m.id){
		return false;
	} else {
		int tmp1 = memcmp (ip, _m.ip, IP_ADDRESS);
		if (tmp1 < 0 )
			return true;
		else if (tmp1>0)
			return false;
		else{
			if ( payloadSize < _m.payloadSize){
				return true;
			} else if (payloadSize > _m.payloadSize){
				return false;
			} else {
				int tmp2 = memcmp (payload, _m.payload, payloadSize);
				Log::print ("Result of memcmp=" + to_string (tmp2) + "\n", Log::VERBOSE);
				return (tmp2 < 0)? true:false;
			}
		}
	}
	
}

bool Message::operator == (const Message & _m) const{
	bool tmp1 = (id==_m.id);
	bool tmp3 = (memcmp (ip, _m.ip, IP_ADDRESS) ==0)? true:false;
	bool tmp2 ;
	if ( payloadSize < _m.payloadSize){
		tmp2 = false;
	} else if (payloadSize > _m.payloadSize){
		tmp2 = false;
	} else {
		tmp2 = (memcmp (payload, _m.payload, payloadSize) == 0)? true:false;
	}
	bool result = (tmp1 && tmp2 && tmp3);
	Log::print ("In Message:==, result = " + to_string(result) + "\n");
	return result;
}

void Message::increment (PVElement& pke, PVElement& se){
	type = PV_MESSAGE;
	hopCount++;
	if ( pkList == NULL ){
		pkList = new vector<PVElement>();
		lastId = pke.id;
		memcpy (lastIp, pke.ip, IP_ADDRESS);
	} else {
		PVElement& lastNode = pkList->back();
		lastId = lastNode.id;
		memcpy (lastIp, lastNode.ip, IP_ADDRESS);
	}
	if ( sigList == NULL )
		sigList = new vector<PVElement>();

	pkList->push_back (pke);
	sigList->push_back(se);
}

void Message::digest ( unsigned char *newDigest){
	int bufSize = SHA_DIGEST_LENGTH + sizeof(char)*IP_ADDRESS + sizeof(int);
	unsigned char buf[bufSize];
	unsigned char tmpDigest[SHA_DIGEST_LENGTH];
	for (int i=0; i<bufSize; i++)
		buf[i]=0;
		
	SHA1 ((const unsigned char *) payload, payloadSize, tmpDigest);
	memcpy (buf, tmpDigest, SHA_DIGEST_LENGTH);
	memcpy (buf+SHA_DIGEST_LENGTH, ip, sizeof(char)*IP_ADDRESS);
	memcpy (buf+SHA_DIGEST_LENGTH+sizeof(char)*IP_ADDRESS, &id, sizeof(int));
	SHA1 (buf, bufSize, newDigest);
}

void Message::incremental_digest (unsigned char* oldDigest, int digestSize, PVElement& pve, unsigned char* newDigest){
	int bufSize = 2*SHA_DIGEST_LENGTH + sizeof(char)*IP_ADDRESS + sizeof(int);
	unsigned char buf[bufSize];
	unsigned char tmpDigest[SHA_DIGEST_LENGTH];
	for (int i=0; i<bufSize; i++)
		buf[i]=0;

		
	SHA1 ((const unsigned char *) pve.payload, pve.payloadSize, tmpDigest);
	if ( oldDigest != NULL)
		memcpy (buf, oldDigest, digestSize);
	memcpy (buf+SHA_DIGEST_LENGTH, tmpDigest, SHA_DIGEST_LENGTH);
	memcpy (buf+2*SHA_DIGEST_LENGTH, pve.ip, sizeof(char)*IP_ADDRESS);
	memcpy (buf+2*SHA_DIGEST_LENGTH+sizeof(char)*IP_ADDRESS, &pve.id, sizeof(int));
	SHA1 (buf, bufSize, newDigest);
//	return SHA_DIGEST_LENGTH;
}

bool Message::verify ( unsigned char* finalDigest){
	Log::print ( "Entering Message::verify\n", Log::VVVERBOSE);
	int flag = true;
	unsigned char digest[SHA_DIGEST_LENGTH];
	typedef vector<PVElement>::iterator viter;
	for ( viter i = pkList->begin(), 
		j = sigList->begin() ; 
			i != pkList->end() 
				&& j != sigList->end(); 
					i++){	
		int result = 1;
		if ( i == pkList->begin() )
			incremental_digest ((unsigned char*)payload, payloadSize, *i, digest);
		else {
			RSA* publicKey = (i-1)->get_pk();
			incremental_digest ( digest, SHA_DIGEST_LENGTH, *i, digest);
			result = RSA_verify (NID_sha1, digest, SHA_DIGEST_LENGTH, j->payload,j->payloadSize,publicKey);
			Log::print ( "Digest\n", Log::VVERBOSE);
			Log::dump ( digest, SHA_DIGEST_LENGTH, Log::VVERBOSE);
			Log::print ( "\n", Log::VVERBOSE, false); 
			Log::print ( "Signature\n", Log::VVERBOSE);
			Log::dump ( j->payload, j->payloadSize, Log::VVERBOSE);
			Log::print ( "\n", Log::VVERBOSE, false); 
			unsigned char buf[KEY_SIZE];
			int keySize = public_key_to_char (publicKey, buf, KEY_SIZE);
			Log::print ( "Public key\n", Log::VVERBOSE);
			Log::dump ( buf, keySize, Log::VVERBOSE); 
			Log::print ( "\n", Log::VVERBOSE, false); 
/*			FILE* fp = fopen ("sig.txt", "w");
			char* tmp = (char *)j->payload;
			for (int k=0; k < (j->payloadSize); k++)
				fprintf (fp, "%d:",tmp[k]);
			fclose(fp);
			fp = fopen ("digest.txt", "w");
			for (int k=0; k < SHA_DIGEST_LENGTH; k++)
				fprintf (fp, "%d:", digest[k]);
			fclose(fp);
*/
			Log::print ("HERE\n", Log::VVERBOSE);
			j++;
			Log::print ("HERE\n", Log::VVERBOSE);
			RSA_free (publicKey);
			Log::print ("HERE\n", Log::VVERBOSE);
		}	

		if (!result){
			flag = false;
			break;
		}
	}
	memcpy ( finalDigest, digest, SHA_DIGEST_LENGTH);
	Log::print ( "Leaving Message::verify\n", Log::VVVERBOSE);
	return flag;
}

bool Message::verify_dns ( RSA* publicKey){
	Log::print ("Entering Message::verify_dns\n", Log::VVVERBOSE);
	unsigned char digest[SHA_DIGEST_LENGTH];
	Log::print ("Taking digest\n", Log::VVERBOSE);
	this->digest (digest);
	assert (digest != NULL);
	assert (sigList != NULL);
	Log::print ("Getting sigList\n", Log::VVERBOSE);
	PVElement& se = (*sigList )[0];
	Log::print ("Verifying\n", Log::VVERBOSE);
	if (publicKey==NULL){
		Log::print ("Null key\n", Log::VVERBOSE);
	}
	if (se.payloadSize==0 || se.payload==NULL){
		Log::print (" Signature payload null\n", Log::VVERBOSE);
	} else{
		Log::print ("Printing signature payload\n", Log::VVERBOSE);
		Log::dump (se.payload, se.payloadSize, Log::VVERBOSE);
		Log::print ("Public key\n", Log::VVERBOSE);
		unsigned char pkBuf[KEY_SIZE];
		int keySize=public_key_to_char(publicKey,pkBuf,KEY_SIZE);
		Log::dump (pkBuf, keySize, Log::VVERBOSE);

	}
	bool result = RSA_verify (NID_sha1, digest, SHA_DIGEST_LENGTH, se.payload,se.payloadSize,publicKey);
	Log::print ("Leaving Message::verify_dns\n", Log::VVVERBOSE);
	return result;
}


int Message::sign (unsigned char* digest, int digestLength, RSA* privateKey, unsigned char** signature){
	unsigned int size;
	*signature=new_char(RSA_size(privateKey));

	RSA_sign (NID_sha1, (unsigned char *)digest,digestLength , (unsigned char *)*signature, &size, privateKey);
	return size;
}

void Message::send( int sockfd ){
	typedef  vector <PVElement>::iterator viter;
	int sent=0;
	switch ( type ){
		case INIT_MESSAGE:
			sent+=MessageHandler::flush_object ( sockfd, this, sizeof(Message));
			if (payloadSize > 0) {
				sent+=MessageHandler::flush_object ( sockfd, payload, payloadSize);
			}
			for ( viter i = pkList->begin(); i != pkList->end(); i++)
				sent+=i->send( sockfd );
		break;

		case PV_MESSAGE:
			sent+=MessageHandler::flush_object ( sockfd, this, sizeof(Message));
			if (payloadSize > 0) {
				sent+=MessageHandler::flush_object ( sockfd, payload, payloadSize);
			}
			for ( viter i = pkList->begin(); i != pkList->end(); i++)
				sent+=i->send( sockfd );
			for ( viter i = sigList->begin(); i != sigList->end(); i++)
				sent+=i->send( sockfd );
		break;

		case DNS_BROADCAST:
			{
			Log::print ( "Sending dns message\n");
			sent+=MessageHandler::flush_object (sockfd, this, sizeof (Message));
			Log::print ( "Sending dns message payload\n", Log::VERBOSE);
			if (payloadSize > 0) {
				sent+=MessageHandler::flush_object ( sockfd, payload, payloadSize);
			}
			Log::print ( "Sending dns message signature\n", Log::VERBOSE);
			PVElement se = sigList->front();
			sent+=se.send (sockfd);
			break;
			}

		default:
			Log::print ( " Unknown message type\n", Log::SILENT);
	}
	Log::print ("Bytes sent in "+ to_string(messageType[type]) +" message:"+to_string(sent)+"\n", Log::VERBOSE);
}

PVElement* Message::get_first_node(){
	if ( pkList->size() > 0)
		return &pkList->front();
	else 
		return NULL;
}

PVElement* Message::get_last_node (){
	if ( pkList!=NULL && pkList->size()>1)
		return &(*pkList)[pkList->size()-2];
	else
		return NULL;
}

/* Sends a message to the log server. Work like send(), but ensures
	 * that all LEN bytes are sent. */
static ssize_t safe_write(int fd, char* buf, size_t len)  {
	size_t bytes_written = 0;
	ssize_t bytes_out;
	char *bufp;

	/* TODO: avoid copying by using sendmsg()!! */

	bufp = buf;
	while (bytes_written < len) {
		errno = 0;
		if ((bytes_out = write(fd, bufp,
						len - bytes_written)) < 0) {
			perror("write");

			if (errno != EINTR) {
				return bytes_out;
			} else {
				continue;
			}
		}

		bufp += bytes_out;
		bytes_written += bytes_out;
	}

	return len;
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
				if (packet_len < 0) perror("read");
				return packet_len;
			}
		}
	}

	assert(received_so_far == len);

	return received_so_far;
}

int MessageHandler::flush_object(int sockfd,void* _buf,int length){
	int totalSent=0;

	assert(length > 0);

	totalSent = safe_write(sockfd, (char*)_buf, length);

	return totalSent;
}

int MessageHandler::receive_object ( int sockfd, void *buf, int length){
	int total = 0;

	assert(length > 0);

	total = safe_read(sockfd, (char*)buf, length);

	return total;
}

void MessageHandler::send_init_message ( Server* server, Neighbor* neighbor){
	//	PVElement pve = PVElement ( PVElement::PK, server->id,  server->ip, server->pkBuf, server->keySize);
	DataContainer* dc = server->dc;
	vector<PVElement> pkList = vector<PVElement>();
	//	pkList.push_back (pve);
	for (int i=1 ; i<= dc->node_size(); i++){
		KeyedId* ki = dc->get_node(i);
		assert (ki!=NULL);
		PVElement* pve = ki->get_pve();	
		pkList.push_back(*pve);	
	}
	string edges = dc->get_edge_string();
	const char* payloadString = edges.c_str();
	Message* message = new Message ( Message::INIT_MESSAGE, server->id, server->ip, &pkList );
	cout << "Sending payload " + edges +" of size " + to_string(edges.length()) + "\n";
	message->set_payload (payloadString, strlen(payloadString));
	message->send ( neighbor->sockfd );
	delete message;
}

void MessageHandler::send_init_pv_message ( Server* server, Neighbor* neighbor){
	Log::print ( "Entering Message::send_init_pv_message\n", Log::VVVERBOSE);
	Log::print ( "Sending init_pv message\n", Log::VERBOSE);
	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned char* signature;
	int signatureLength;
	int id = server->id;
	PVElement pve1 = PVElement ( PVElement::PK, id,  server->ip, server->pkBuf, server->keySize);
	PVElement pve2=PVElement ( PVElement::PK, neighbor->id, neighbor->ip, neighbor->pkBuf, neighbor->keySize);
	vector<PVElement> pkList = vector<PVElement>();
	vector<PVElement> sigList = vector<PVElement>();
	pkList.push_back (pve1);
	pkList.push_back (pve2);
	Message::incremental_digest ( NULL, 0, pve1, digest);
	Message::incremental_digest ( digest, SHA_DIGEST_LENGTH, pve2, digest);
	signatureLength = Message::sign ( digest, SHA_DIGEST_LENGTH, server->privateKey, &signature );
	PVElement se1 = PVElement ( PVElement::SIG, server->id, server->ip, signature, signatureLength );

	Log::print ( "Digest\n", Log::VVERBOSE);
	Log::dump ( digest, SHA_DIGEST_LENGTH, Log::VVERBOSE);
	Log::print ( "\n", Log::VVERBOSE, false); 
	Log::print ( "Signature\n", Log::VVERBOSE);
	Log::dump ( signature, signatureLength, Log::VVERBOSE);
	Log::print ( "\n", Log::VVERBOSE, false); 

	FILE* fp = fopen ("sent-sig.txt", "w");
	char* tmp = (char *)signature;
	for (int k=0; k < signatureLength; k++)
		fprintf (fp, "%d:",tmp[k]);
	fclose(fp);
	fp = fopen ("sent-digest.txt", "w");
	for (int k=0; k < SHA_DIGEST_LENGTH; k++)
		fprintf (fp, "%d:", digest[k]);
	fclose(fp);


	sigList.push_back (se1);

	Message* message=new Message( Message::PV_MESSAGE, server->id, server->ip, &pkList, &sigList);
	message->send ( neighbor->sockfd );

	Log::print ( "Sending Init PV: " + to_string(*message) + "\n", Log::VERBOSE);
	delete message;	
	Log::print ( "Leaving Message::send_init_pv_message\n", Log::VVVERBOSE);
}

void MessageHandler::send_increment_pv_message( Server* server, Neighbor* neighbor, Message* message, unsigned char* oldDigest){
	Log::print ( "Entering Message::send_increment_pv_message\n", Log::VVVERBOSE);
	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned char* signature;
	int signatureLength;

	PVElement pke= PVElement ( PVElement::PK, neighbor->id, neighbor->ip, neighbor->pkBuf, neighbor->keySize);
	Message::incremental_digest ( oldDigest, SHA_DIGEST_LENGTH, pke, digest);
	Log::print ("Here\n", Log::VVERBOSE);
	signatureLength = Message::sign ( digest, SHA_DIGEST_LENGTH, server->privateKey, &signature);
	Log::print ("Here\n", Log::VVERBOSE);
	PVElement se = PVElement ( PVElement::SIG, server->id, server->ip, signature, signatureLength);
	Log::print ("Here\n", Log::VVERBOSE);

	Message* newMessage = new Message (*message);
	Log::print ("Here\n", Log::VVERBOSE);
	newMessage->increment ( pke, se );
	Log::print ("Here\n", Log::VVERBOSE);
	newMessage->send( neighbor->sockfd );
	Log::print ("Here\n", Log::VVERBOSE);

	Log::print ("Relayed message" + to_string(*newMessage)+ " to (IP="+ to_string(neighbor->ip) + ",ID=" + to_string(neighbor->id) + ")\n", Log::VERBOSE);
	delete newMessage;

	Log::print ( "Leaving Message::send_increment_pv_message\n", Log::VVVERBOSE);
}

void MessageHandler::send_dns_message ( Server* server, Neighbor* neighbor, Message* message){
	Log::print ( "Entering Message::send_dns_message\n", Log::VERBOSE);
	message->send ( neighbor->sockfd );
	Log::print ( "Sending DNS_BROADCAST: " + to_string(*message) + " to " + to_string(*neighbor)+ "\n", Log::VERBOSE);
	Log::print ( "Leaving Message::send_dns_message\n", Log::VERBOSE);
}

Message* MessageHandler::convert_dns_message ( Server* server, DNSMessage* dnsMessage){
	Log::print ( "Entering Message::convert_dns_message\n", Log::VERBOSE);
	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned char* signature;
	int signatureLength;
	Log::print ("Here 1\n", Log::VVERBOSE);
	vector<PVElement> sigList = vector<PVElement>();
	Message* message=new Message( Message::DNS_BROADCAST, server->id, server->ip);
	message->payloadSize = dnsMessage->payloadSize;
	message->payload = new_char (message->payloadSize);
	assert (message->payload != NULL);
	memcpy (message->payload, dnsMessage->payload, message->payloadSize);
	Log::print ("Here 2\n", Log::VVERBOSE);

	Log::print ("Here 3\n", Log::VVERBOSE);
	message->digest (digest);
	Log::print ("Here 4\n", Log::VVERBOSE);
	signatureLength = Message::sign ( digest, SHA_DIGEST_LENGTH, server->privateKey, &signature );
	PVElement se1 = PVElement ( PVElement::SIG, server->id, server->ip, signature, signatureLength );
	Log::print ("Here 5\n", Log::VVERBOSE);
	sigList.push_back (se1);
	Log::print ("Here 6\n", Log::VVERBOSE);
	message->set_sig_list( &sigList);
	Log::print ( "Leaving Message::convert_dns_message\n", Log::VERBOSE);
	return message;
}

int MessageHandler::receive_init_message ( Message* message, int incomingSockfd ){
	Log::print ( "Entering MessageHandler::receive_init_message\n", Log::VERBOSE);		
	assert  (message!=NULL);
	cout << "Message payload="+ to_string (message->payloadSize) + "\t hopcount="+ to_string (message->hopCount) + "\n";

#if 1
	/* galtekar: INIT messages may have 0 payload size. We musn't let 
	 * receive_object know, because it will trip an assert. */
	if (message->payloadSize) {
		unsigned char* buf = new_char (message->payloadSize);

		int numBytes = MessageHandler::receive_object ( incomingSockfd, buf, message->payloadSize);

		if(numBytes <= 0) {
			Neighbor* neighbor;

			if( (neighbor=server->get_neighbor(incomingSockfd))!=NULL ){
				server->disconnect( neighbor);
			}

			close (incomingSockfd);
			FD_CLR (incomingSockfd, &(server->readfds));

			return -1;
		}

		message->payload = buf;
	}
#endif

	message->pkList = new vector<PVElement>();
	for (int i=0; i< message->hopCount; i++){
		PVElement pke = PVElement ();
		int result = pke.receive ( incomingSockfd );
		if (result < 0) return -1;
		(message->pkList)->push_back (pke);
	}

	return 0;
}


int MessageHandler::receive_pv_message ( Message* message, int incomingSockfd ){
	Log::print ( "Entering MessageHandler::receive_pv_message\n", Log::VVVERBOSE);		
	assert  (message!=NULL);

	if (message->payloadSize > 0) {
		message->payload = new_char (message->payloadSize);
		int numBytes = MessageHandler::receive_object ( incomingSockfd, message->payload, message->payloadSize);

		if(numBytes <= 0) {
			Neighbor* neighbor;

			if( (neighbor=server->get_neighbor(incomingSockfd))!=NULL ){
				server->disconnect( neighbor);
			}

			close (incomingSockfd);
			FD_CLR (incomingSockfd, &(server->readfds));

			return -1;
		}
	} else {
		printf("Got PV message with 0 size.\n");
	}

	message->pkList = new vector<PVElement>();
	for (int i=0; i<= message->hopCount; i++){
		PVElement pke = PVElement ();
		int result = pke.receive ( incomingSockfd );
		if (result < 0) return -1;
		(message->pkList)->push_back (pke);
	}
	message->sigList = new vector<PVElement>();
	for (int i=0; i< message->hopCount; i++){
		PVElement se = PVElement ();
		int result = se.receive ( incomingSockfd );
		if (result < 0) return -1;
		(message->sigList)->push_back (se);
	}
	Log::print ( "Leaving MessageHandler::receive_pv_message\n", Log::VVVERBOSE);		
	return 0;
}

int MessageHandler::receive_dns_message ( Message* message, int incomingSockfd ){
	Log::print ( "Entering MessageHandler::receive_dns_message\n", Log::VERBOSE);		
	assert  (message!=NULL);

	assert(message->payloadSize > 0);
	Log::print ("Message payload="+ to_string (message->payloadSize) + "\t hopcount="+ to_string (message->hopCount) + "\n", Log::VERBOSE);
	unsigned char* buf = new_char (message->payloadSize);
	int numBytes = MessageHandler::receive_object ( incomingSockfd, buf, message->payloadSize);

	if(numBytes <= 0) {
		Neighbor* neighbor;

		if( (neighbor=server->get_neighbor(incomingSockfd))!=NULL ){
			server->disconnect( neighbor);
		}

		close (incomingSockfd);
		FD_CLR (incomingSockfd, &(server->readfds));

		return -1;
	}

	message->payload = buf;
	message->sigList = new vector<PVElement>();
	PVElement se = PVElement ();
	int result = se.receive ( incomingSockfd );
	if (result < 0) return -1;
	(message->sigList)->push_back (se);
	Log::print ( "Leaving MessageHandler::receive_dns_message\n", Log::VERBOSE);		
	return 0;
}

int MessageHandler::process_init_message (Server* server, Neighbor* neighbor, Message* message, int incomingSockfd){
	Log::print ( "Entering MessageHandler::process_init_message\n", Log::VVVERBOSE);		
	DataContainer* dc = server->dc;
	typedef vector<PVElement>::iterator iter;
	map<int, KeyedId> deserializeMap;
	int j = 0;
	for (iter i = message->pkList->begin(); i!=message->pkList->end() ; i++, j++){
		KeyedId* ki = i->get_keyed_id();
		deserializeMap.insert (make_pair(j, *ki));
		dc->add_tmp_node (*ki, *neighbor, server->k);
	}	

	if (message->payloadSize > 0) {
		assert(message->payload);
		string edges ( (const char *)message->payload);
		stringstream s (edges);
		string arc;
		while ( !std::getline (s, arc).eof() ){
			Log::print (arc+"\n", Log::VERBOSE);		
		}
	}
	Log::print ( "Leaving MessageHandler::process_init_message\n", Log::VVVERBOSE);		

	return 0;
}

int MessageHandler::process_pv_message ( Server* server, Neighbor* neighbor, Message* message,int incomingSockfd){
	Log::print ( "Entering MessageHandler::process_pv_message\n", Log::VVVERBOSE);		
	int result = 0;
	unsigned char* digest = new_char(SHA_DIGEST_LENGTH);
	DataContainer* dc = server->dc;

	Config* config = server->config;
	set<Edge>* edgeSet = dc->get_edge_set();
	if ( message->match_public_key (*server->neighborMap) ){
		/* If  no neighbor has used a different public key 
			from what it has used in the INIT_MESSAGE*/
		bool status = message->verify (digest);
		Log::print ( "Message:reliable ? " + to_string (status) + "\n", Log::VERBOSE );
		Path* path = message->get_path ();
		cout << "Path:" + to_string (*path)+ "\n";

		if (status) {
			/* The message has been authenticated */

			/*	The count_new_edges and count_new_nodes
				have the side effect of adding
				new node/edges if any to the corresponding 
				data structures.
			 */
			bool relayMessage = false;
			set <KeyedId>* knownNodeSet = dc->get_known_node_set();
			set <KeyedId>* unknownNodeSet = dc->get_unknown_node_set();
			Log::print ( "Number of verified nodes = " +to_string(*knownNodeSet) + "\t Number of unverified nodes = "+ to_string(*unknownNodeSet) + "\n", Log::VERBOSE);
			Log::print ( "Number of edges = " + to_string (edgeSet->size()) + "\n", Log::VERBOSE);



			typedef vector<KeyedId>::iterator iter;
			for (iter i = path->v.begin(); i != path->v.end(); i++) {
				/*	Since the last node is anyway 
					my id
				 */
				if ( (i+1) != path->v.end()) {
					Edge e = Edge(*i, *(i+1));
					Log::print ("Examining node "+ to_string(*i) +" \n", Log::VERBOSE);
					Log::print ("Examining edge "+ to_string(e) +" \n", Log::VERBOSE);
					bool newNode = dc->is_new_node (*i);
					bool newEdge = dc->is_new_edge (e);

					if (newNode){
						dc->add_node (*i);
						Log::print ("Seeing node " + to_string(*i) + " for the first time\n", Log::VERBOSE);
						Log::print ( "List of verified nodes\n" + to_string (*knownNodeSet) + "\n", Log::VERBOSE);
						Log::print ( "List of unverified nodes\n" + to_string (*unknownNodeSet) + "\n", Log::VERBOSE);
					}
					if (newEdge){
						Log::print ("Added new edge" + to_string(e) + ".\n", Log::VERBOSE);
						dc->add_edge(e);
					}
					if ( newNode || newEdge)
						relayMessage = true;
					else 
						Log::print ("Neither new node nor edge\n", Log::VERBOSE);
				}

				if (config->pathVectorTest){
					/*	Get the suffix of the path 
						beginning at the current node i.
					 */
					vector<KeyedId> tmpVector ( path->v.end()-i);
					copy ( i, path->v.end(), tmpVector.begin());
					Path tmpPath = Path (tmpVector);

					/*	Try to find id-disjoint paths to node i. */
					MessageHandler::path_vector_test (server, &tmpPath);
				} else {
					/*	Search for disjoint paths 
						using the Max-flow algorithm.
					 */
				}

			}

			if (message->hopCount ==1)
				relayMessage = true;

			/*	Schedule this message to be relayed
				only if it carries some new information.
				Unless we want to run a two-node test.
			 */
			if ( config->testTwoNode || relayMessage )
				server->scheduler->add_message ( message, incomingSockfd, digest );


		} else {
			Log::print ( "Signatures in message do not match\n", Log::NORMAL);
			result = -1;
		}
	} else {
		Log::print ( 
				string ("Message with neighbor (IP=")
				+ message->ip + 
				", ID=" + to_string(message->id) 
				+ " in path rejected because public keys did not match\n", Log::NORMAL);
		result = -1;
	}
	Log::print ( "Leaving MessageHandler::process_pv_message\n", Log::VVVERBOSE);		
	return result;
}

int MessageHandler::process_dns_message ( Server* server, 
		Message* message, int incomingSockfd){

	map< Id, RSA*>* keyMap = server->get_key_map();
	Id id (message->id, message->ip);
	if (keyMap->find (id) == keyMap->end()){
		printf("Got DNS message ``%s'' from unreliable node (%d, %s).\n",
				message->payload, message->id, message->ip);
		return -1;
	}
	RSA* publicKey =(*keyMap)[id];
	DataContainer* dc = server->dc;

	bool status = message->verify_dns (publicKey);
	bool notSeen = dc->add_dns_message (*message);
	Log::print ( "Message:notSeen ? " + to_string (notSeen) + "\n", Log::VERBOSE);
	Log::print ( "Message:reliable ? " + to_string (status) + "\n", Log::VERBOSE );

	if ( notSeen && status ) {
		server->scheduler->add_dns_message ( message, incomingSockfd);
		printf("Got unseen and reliable DNS message ``%s''.\n", message->payload);
	} else {
		printf("Got seen/unreliable DNS message ``%s''.\n", message->payload);
	}

	return 0;
}



bool Message::match_public_key ( map<Id, RSA*>& neighborMap){
	Log::print ( "Entering Message::match_public_key\n", Log::VVVERBOSE);
	bool flag = true;
	typedef vector<PVElement>::iterator viter;
	unsigned char buf[KEY_SIZE];
	for ( viter i = pkList->begin(); i != pkList->end(); i++){
		Id* id = i->get_id ();
		if (neighborMap.find (*id) != neighborMap.end()){
			RSA* rsa = neighborMap[*id];
			int keySize = public_key_to_char(rsa,buf,KEY_SIZE);
			if( keySize != i->payloadSize || memcmp(buf,i->payload,keySize)!=0) {
				flag = false;
				break;
			}
			Log::print ( 
					"Message with neighbor (IP=" + 
					to_string(i->ip) + 
					", ID=" + to_string(i->id) + ")"+
					+ " in path has public keys matched\n", Log::VVERBOSE);
		}
		delete id;
	}
	Log::print ( "Leaving Message::match_public_key\n", Log::VVVERBOSE);
	return flag;
}

Path* Message::get_path(){
	Path* path = new Path();
	typedef vector<PVElement>::iterator viter;
	for ( viter i = pkList->begin(); i != pkList->end(); i++){
		KeyedId* ki = i->get_keyed_id();
		path->add_element (*ki);
		delete ki;
	}
	return path;
}


vector<PVElement>* Message::get_pk_list(){
	return pkList;
}

void Message::set_pk_list ( vector<PVElement>* _pkList){
	pkList = new vector <PVElement>();
	*pkList = *_pkList;
}

void Message::set_sig_list ( vector<PVElement>* _sigList){
	sigList = new vector<PVElement>();
	*sigList = *_sigList;
}

vector<PVElement>* Message::get_sig_list(){
	return sigList;
}


void Message::set_payload (const char* _payload, int _payloadSize){
	payloadSize = _payloadSize;
	payload = new_char (payloadSize);
	memcpy (payload, _payload, payloadSize);
}

unsigned char* Message::get_payload (int &size){
	size = payloadSize;
	return payload;
}

void MessageHandler::path_vector_test( Server* server, Path* path){
	KeyedId* ki = path->get_first_node();

	DataContainer* dc = server->dc;
	map <KeyedId, PathList>* knownNodeMap = server->knownNodeMap;
	map <KeyedId, PathList>* unknownNodeMap = server->unknownNodeMap;
	map <Id, RSA*>* keyMap = server->get_key_map();
	map <KeyedId, int>* optimizedNodeMap = server->optimizedNodeMap;
	set <Edge>* edgeSet = dc->get_edge_set ();

	if ( knownNodeMap->find (*ki) == knownNodeMap->end () ){
		if (unknownNodeMap->find (*ki) == unknownNodeMap->end ()){
			/* Never seen this keyed id (node) before */
			/* Create a new entry */

			Log::print ("Seeing node " + to_string(*ki) + " for the first time\n", Log::VERBOSE);
			PathList tmpPathList = PathList ( *path );
			unknownNodeMap->insert (make_pair (*ki, tmpPathList));
			Log::print ( "List of verified nodes\n" + to_string (*knownNodeMap), Log::VERBOSE);
			Log::print ( "List of unverified nodes\n" + to_string (*unknownNodeMap), Log::VERBOSE);
		} else {
			/* 	Seen this node before but 
					don't know it it's a reliable node. */
			Log::print ("Seen node " + to_string(*ki) + " before.\n", Log::VERBOSE);

			PathList& pathList = (*unknownNodeMap)[*ki];
			pathList.add_path (*path);
			Log::print ("Added path to node " + to_string(*ki) + ".\n", Log::VERBOSE);
			PathList* disjointPaths = NULL;
			if ( (disjointPaths = pathList.found_disjoint ( server->k))!=NULL){
				/* If it has the k disjoint paths, 
					it's reliable.*/
				knownNodeMap->insert (make_pair (*ki, *disjointPaths));
				RSA* tmpKey = RSAPublicKey_dup (ki->publicKey);
				keyMap->insert (make_pair (*ki, tmpKey ));
				optimizedNodeMap->insert (make_pair(*ki, 0));
				dc->make_known (*ki);
				delete (disjointPaths);
				Log::print ("Node " + to_string(*ki) + " is reliable.\n", Log::VERBOSE);
				Log::print ("Number of verified nodes:" + to_string(knownNodeMap->size()) + "\n", Log::NORMAL);
				cout << "List of verified nodes\n" + to_string (*knownNodeMap);
				cout << "List of unverified nodes\n" + to_string (*unknownNodeMap);

				Log::print ("Number of optimized verified nodes:" + to_string(optimizedNodeMap->size()) + "\n", Log::NORMAL);
				Log::print ("Number of unverified nodes:" + to_string(unknownNodeMap->size()) + "\n", Log::NORMAL);
				Log::print ("Number of edges:" + to_string(edgeSet->size()) + "\n", Log::NORMAL);
			} else {
				/*	Don't have k disjoint paths */
				Log::print ("Can't find k disjoint paths to " + to_string(*ki) + "\n", Log::VERBOSE);

			}
		}
	} else {
		/*	This is a reliable node. 
			Do nothing.*/
		Log::print (to_string(*ki) + " is a verified nodes\n", Log::VVERBOSE);
	}
}
