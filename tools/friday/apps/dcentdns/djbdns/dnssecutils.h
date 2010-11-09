#include <openssl/rsa.h>
#include "dns.h"
#include "codonsutils.h"

#ifndef DNSSEC_H
#define DNSSEC_H

#define SIG_TTL 86400
#define SIG_EXP 30 * 86400
#define DNSSEC_ALG 5
#define DNSSEC_PROTO 3
#define CODONS_NAME "\6codons"
#define CODONS_NAMELEN 8

int initCoDoNSKey(const char *filename);
int initCoDoNSPublicKey(const char *filename);
int testCoDoNSKeys();
int getCoDoNSSize();
char *getCoDoNSKeytag();
int sign(char *sig, int siglength, ResourceRecord **rrset, int rrcount);
int verify(char *sig, int siglength, ResourceRecord **rrset, int rrcount, RSA *key);

int writeKeydata(RSA *key, char **keydata, int *length);
RSA *readKeydata(const char *keydata, int length);
void freeKey(RSA *key);

#endif
