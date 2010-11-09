#ifndef RSA_H
#define RSA_H

RSA* private_to_public(RSA *);
RSA* rsa_dup(RSA *);
void delete_rsa(RSA**);
RSA* char_to_public_key(unsigned char* buf,int size);
int public_key_to_char(RSA* key,unsigned char * buf, int size);
#endif
