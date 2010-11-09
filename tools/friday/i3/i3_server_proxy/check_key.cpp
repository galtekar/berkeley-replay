#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <string>
#include <set>
#include <algorithm>
#include <map>
#include <stdlib.h>
#include <openssl/err.h>
#include "auth.h"
#include "../i3/debug.h"

using namespace std;

#define MAX_LEN 512

// All nonces of length AUTH_KEY_LEN/8

static const char rnd_seed[] = "string to make the random number generator think it has entropy";
void crypto_init()
{
  CRYPTO_malloc_debug_init();
  CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
  RAND_seed(rnd_seed, sizeof rnd_seed);
  ERR_load_crypto_strings();
}

void crypto_exit()
{
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_state(0);
  // CRYPTO_mem_leaks_fp(stderr);
}

map<string,RSA*> *publickeys;
RSA* myprivatekey;

// Unencrypted nonces

int equal_nonce(unsigned char* nonce1, unsigned char* nonce2)
{
  for(int i=0;i<AUTH_NONCE_LEN/8;i++)
    if ( nonce1[i] != nonce2[i])
      return 0;
  return 1;
}

// Read in public keys from file
void read_in_public_keys(char* file)
{
  if ( publickeys != NULL)
    delete publickeys;
  publickeys = new map<string,RSA*>;

  FILE* fp = fopen(file,"r");
  if ( fp == NULL )
  {
    DEBUG(1,"Could not open public key file\n");
    return;
  }

  char username[MAX_LEN],publicn[MAX_LEN],publice[MAX_LEN];
  
  do
  {
    fscanf(fp,"%s %s %s",username,publicn,publice);
    if (feof(fp))
      break;

    RSA *key;
    key = RSA_new();
    BN_dec2bn(&(key->n),publicn);
    BN_dec2bn(&(key->e),publice);

    publickeys->insert(make_pair(string(username),key));

    DEBUG(11,"User %s has RSA:",username);
    //    print_rsa_key(key);
  }
  while(1);
  
}

// has to be of length AUTH_KEY_LEN / 8
void generate_nonce(unsigned char* nonce)
{
  BIGNUM *mbn = BN_new();
  BN_rand(mbn,AUTH_NONCE_LEN,-1,0);
  int numbytes = BN_bn2bin(mbn,nonce);
  for(;numbytes < AUTH_NONCE_LEN/8;numbytes++)
    nonce[numbytes] = 0;
  
  BN_clear_free(mbn);
}

char username[200];

char *read_in_private_key(char* file)
{
  if ( myprivatekey != NULL)
    delete myprivatekey;
  myprivatekey = RSA_new();
  
  FILE* fp = fopen(file,"r");
  if ( fp == NULL )
  {
    DEBUG(1,"Could not open private key file\n");
    return NULL;
  }

  char publicn[MAX_LEN],publice[MAX_LEN],privated[MAX_LEN],privatep[MAX_LEN],privateq[MAX_LEN];
  
  fscanf(fp,"%s %s %s %s %s %s",username,publicn,publice,privated,privatep,privateq);
  if (feof(fp))
  {
    DEBUG(1,"Could not read required info from private key file\n");
    return NULL;
  }

  BN_dec2bn(&(myprivatekey->n),publicn);
  BN_dec2bn(&(myprivatekey->e),publice);
  BN_dec2bn(&(myprivatekey->d),privated);
  BN_dec2bn(&(myprivatekey->p),privatep);
  BN_dec2bn(&(myprivatekey->q),privateq);

  DEBUG(11,"User %s has RSA:",username);
  // print_rsa_key(myprivatekey); 
  
  return(username);
}


RSA *get_public_key(char* user)
{
  map<string,RSA*>::iterator piter = publickeys->find(string(user));
  if (piter == publickeys->end())
    return NULL;
  return piter->second;
}

// for testing 
int main(int argc,char** argv)
{
  crypto_init();

  if ( argc <= 2) {
    printf("Usage: ./check_key <public_key_file> <private_key_file>\n");
    return 0;
  }
  
  read_in_public_keys(argv[1]);
  
  if (!read_in_private_key(argv[2]))
  {
    printf("incorrect_format\n");
    return 0;
  }

  RSA* publickey = get_public_key(username);

  if ( publickey == NULL)
  {
    printf("user_unknown\n");
    return 0;
  }

  unsigned char checknonce1[AUTH_NONCE_LEN/8],checknonce2[AUTH_NONCE_LEN/8];
  unsigned char encnonce[AUTH_KEY_LEN/8];
  generate_nonce(checknonce1);

  if ( RSA_public_encrypt(AUTH_NONCE_LEN/8,checknonce1,encnonce,publickey,RSA_PKCS1_PADDING) != AUTH_KEY_LEN / 8)
  {
    printf("does_not_match\n");
    return 0;
  }

  if ( RSA_private_decrypt(AUTH_KEY_LEN/8,encnonce,checknonce2,myprivatekey,RSA_PKCS1_PADDING) != AUTH_NONCE_LEN / 8)
  {
    printf("does_not_match\n");
    return 0;
  }

  if ( !equal_nonce(checknonce1,checknonce2)) 
  {
    printf("does_not_match\n");
    return 0;
  }
  
  crypto_exit();
  printf("ok\n");
  
  return 1;
}
