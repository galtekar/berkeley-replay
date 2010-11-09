#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnssecutils.h"
#include "codonsutils.h"
#include "error.h"
#include "byte.h"
#include "alloc.h"

static RSA *codonsKey = 0;
static RSA *codonsPublicKey = 0;

char *codonsKeydata = 0;
int codonsKeylength = 0;
int codonsKeysize = 0;
char codonsKeytag[2] = {0,0};

uint16 computeKeytag(const char *keydata, int length) {
  int i;
  long int ac = 0;
  for (i = 0; i < length; i++) {
    ac += (i&1) ? (unsigned char)keydata[i] : ((unsigned char)keydata[i])<<8; 
  }
  ac += (ac>>16) & 0xFFFF;

  return (uint16) ac & 0xFFFF;
} 

int initCoDoNSKey(const char *filename) {
  char *temp = alloc_channel(strlen(filename)+5, 3);
  if (temp == 0) {
    errno = error_nomem;
    return 0;
  }
  sprintf(temp, "%s.pub", filename);

  FILE *fp = fopen(filename, "r");
  if (fp == 0) {
    printf("DNSSEC: Unable to open file %s\n", filename);
    alloc_free_channel(temp, 3);
    return 0;
  }

  if ((codonsKey = PEM_read_RSAPrivateKey(fp, 0, 0, 0)) == 0) {
    printf("DNSSEC: Unable to load private key from file %s\n", filename);
    fclose(fp);
    alloc_free_channel(temp, 3);
    return 0;
  }
  fclose(fp);

  fp = fopen(temp, "r");
  if (fp == 0) {
    printf("DNSSEC: Unable to open file %s\n", temp);
    alloc_free_channel(temp, 3);
    return 0;
  }

  if ((PEM_read_RSAPublicKey(fp, &codonsKey, 0, 0)) == 0) {
    printf("DNSSEC: Unable to load public key from file %s\n", temp);
    fclose(fp);
    alloc_free_channel(temp, 3);
    return 0;
  }
  fclose(fp);
  alloc_free_channel(temp, 3);
 
  char *keydata;
  int length;

  if (!writeKeydata(codonsKey, &keydata, &length)) {
    return 0;
  }
  uint16_pack_big(codonsKeytag, computeKeytag(keydata, length));
  printf("Got keytag %d\n", getshort(codonsKeytag));
  alloc_free_channel(keydata, 3); 

  codonsKeysize = RSA_size(codonsKey);
  return 1;
}

int initCoDoNSPublicKey(const char *filename) {
  char *temp = alloc_channel(strlen(filename)+5, 3);
  if (temp == 0) {
    errno = error_nomem;
    return 0;
  }
  sprintf(temp, "%s.pub", filename);

  FILE *fp = fopen(temp, "r");
  if (fp == 0) {
    printf("DNSSEC: Unable to open file %s\n", temp);
    alloc_free_channel(temp, 3);
    return 0;
  }

  if ((codonsPublicKey = PEM_read_RSAPublicKey(fp, 0, 0, 0)) == 0) {
    printf("DNSSEC: Unable to load public key from file %s\n", temp);
    fclose(fp);
    alloc_free_channel(temp, 3);
    return 0;
  }
  fclose(fp);
  alloc_free_channel(temp, 3);
  return 1;
}

int testCoDoNSKeys() {
  char teststr[20] = "hello";
  char sig[256];
  int siglen = 256;
  char digest[20];

  SHA1(teststr, strlen(teststr)+1, digest);

  if (!RSA_sign(NID_sha1, digest, 20, sig, &siglen, codonsKey)) {
    printf("Signing failed\n");
  }

  return RSA_verify(NID_sha1, digest, 20, sig, siglen, codonsPublicKey);
}

int getCoDoNSSize() {
  return codonsKeysize;
}

char *getCoDoNSKeytag() {
  return codonsKeytag;
}

void getSHA1digest(char *sigdata, int length, ResourceRecord **rrset, int rrcount, char *digest) {
  SHA_CTX shactx;
  SHA_Init(&shactx);
  SHA_Update(&shactx, sigdata, length);

  int i;
  for (i=0; i<rrcount; i++) {
    if (rrset[i] == 0) {
      continue;
    }

    SHA_Update(&shactx, rrset[i]->oname, rrset[i]->length-rrset[i]->rdatalen-10);

    char temp[10];
    byte_copy(temp, 2, rrset[i]->type); 
    byte_copy(temp+2, 2, rrset[i]->class);
    byte_copy(temp+4, 4, sigdata+4);
    uint16_pack_big(temp+8, (uint16)rrset[i]->rdatalen);
    
    SHA_Update(&shactx, temp, 10);
    SHA_Update(&shactx, rrset[i]->rdata, rrset[i]->rdatalen); 
  }

  SHA1_Final(digest, &shactx);
}

int sign(char *sigdata, int siglength, ResourceRecord **rrset, int rrcount) {
  if (sigdata == 0 || rrset == 0 || rrcount == 0) {
    printf("Invalid Arguments\n");
    return 0;
  }

  int prelength = 18 + dns_domain_length(sigdata+18);
  char digest[20];
  getSHA1digest(sigdata, prelength, rrset, rrcount, digest);

  int length;
  return RSA_sign(NID_sha1, digest, 20, sigdata+prelength, &length, codonsKey);
}

int verify(char *sigdata, int siglength, ResourceRecord **rrset, int rrcount, RSA *key) {
  if (sigdata == 0 || rrset == 0 || rrcount == 0) {
    printf("Invalid Arguments\n");
    return 0;
  }

  if (key == 0) {
    key = codonsPublicKey;
  }
  else {
    char *keydata;
    int length;
    writeKeydata(key, &keydata, &length);
    printf("keytag %d from sig %d\n", computeKeytag(keydata, length), getshort(sigdata+16));
    alloc_free_channel(keydata, 3);
  }
 
  int prelength = 18 + dns_domain_length(sigdata+18);
  char digest[20];
  getSHA1digest(sigdata, prelength, rrset, rrcount, digest);

  return RSA_verify(NID_sha1, digest, 20, sigdata+prelength, siglength-prelength, key);
}

int writeKeydata(RSA *key, char **keydata, int *length) {
  *keydata = 0;
  *length = 0;

  int explen = BN_num_bytes(key->e);
  int modlen = BN_num_bytes(key->n);

  int len = 4 + 1 + explen + modlen;
  if (explen > 255) {
    len += 2;
  }

  char *data = alloc_channel(len, 3);
  if (data == 0) {
    errno = error_nomem;
    return 0;
  }

  byte_zero(data, 2);
  data[2] = DNSSEC_PROTO;
  data[3] = DNSSEC_ALG;

  int pos = 4;
  if (explen < 255) {
    data[pos] = (uint8) explen;
    pos += 1;
  }
  else {
    data[pos] = 0;
    uint16_pack_big(data+pos+1, (uint16)explen);
    pos += 3;
  }

  pos += BN_bn2bin(key->e, data+pos);
  pos += BN_bn2bin(key->n, data+pos);

  if (pos != len) {
    printf("DNSSEC: error writing keydata\n");
    alloc_free_channel(data, 3);	
    return 0;
  }

  *keydata = data;
  *length = len;
  return 1;
} 

RSA *readKeydata(const char *keydata, int length) {
  if (length < 7) {
    errno = error_proto;
    return 0; //bad format
  }

  if (keydata[3] != 5) {
    errno = error_proto;
    return 0; //algo not implemented
  }

  int pubkeylength = length - 4; 

  RSA *key = RSA_new();

  int explength = keydata[4];
  int pos = 1;
  if (explength == 0) {
    explength = getshort(keydata+5);
    pos += 2;
  }

  if (pos+explength > pubkeylength) {
    errno = error_proto;
    return 0; //bad format
  }
  
  char exponent = keydata[4+pos];
  printf("Key details: explen %d exp %d\n", explength, exponent);
  key->e = BN_bin2bn(keydata+4+pos, explength, 0);
  if (key->e == 0) {
    errno = error_nomem;
    return 0;
  }
  pos += explength;


  key->n = BN_bin2bn(keydata+4+pos, pubkeylength-pos, 0);
  if (key->n == 0) {
    errno = error_nomem;
    return 0;
  } 
  pos = pubkeylength;

  return key;
}

void freeKey(RSA *key) {
  RSA_free(key);
}

