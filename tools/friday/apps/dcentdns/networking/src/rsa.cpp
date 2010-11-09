#include <openssl/rsa.h>
#include <string.h>
#include <assert.h>
#include "global.h"
#include "logger.h"

RSA* rsa_dup(RSA* key){
	RSA* newKey=RSA_new();
	Log::print ("Key size=" + to_string(sizeof(RSA)) + "," +  to_string(RSA_size(newKey)) + "\n", Log::VVVERBOSE);
	if(key!=NULL)
		memcpy(newKey,key,sizeof(RSA));
	return newKey;
}

RSA* private_to_public(RSA* privateKey){
	RSA* newKey=RSAPublicKey_dup(privateKey);
	return newKey;
}

void delete_rsa(RSA** publicKey){
	RSA_free(*publicKey);
	*publicKey=NULL;
}

int public_key_to_char(RSA* key,unsigned char * buf, int size){
	unsigned char* tmp;
	Log::print ( "Enter public_key_to_char\n", Log::VVVERBOSE);
	tmp=buf;
	int length=i2d_RSAPublicKey(key,NULL);
	assert(size>=length);
	length=i2d_RSAPublicKey(key,&tmp);
	Log::print ( "Key size=" + to_string(size) + ", Buffer size=" + to_string(length) + "\n", Log::VVVERBOSE);
	Log::print ( "Exit public_key_to_char\n", Log::VVVERBOSE);
	return length;
}

RSA* char_to_public_key(unsigned char* buf,int size){
	const unsigned char* tmp=buf;
	RSA* rsa=d2i_RSAPublicKey(NULL, &tmp,(long)size);
	return rsa;
}
