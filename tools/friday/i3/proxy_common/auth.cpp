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
#include <pthread.h>

using namespace std;

#define MAX_LEN 512

map<string,RSA*> *publickeys;
RSA* myprivatekey;

typedef struct
{
  RSA* public_key;
  unsigned char mynonce[AUTH_NONCE_LEN/8];
  time_t starttime;
} login_attempt;

map<string,login_attempt*> *login_attempts;
map<string,login_attempt*> *client_attempts;

// All nonces of length AUTH_KEY_LEN/8

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

pthread_t      public_key_refresh_thrd;
pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;
int sleeptime = 300; // 5 mins
char public_key_file_store[200];

void *public_key_refresh(void *arg)
{
  do
  {
    int timeleft = sleeptime;

    do
    {
      timeleft = sleep(timeleft);
    } while (timeleft != 0);

    read_in_public_keys(public_key_file_store);
    
  } while(1);
  
}


void crypto_init()
{
  CRYPTO_malloc_debug_init();
  CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
  RAND_seed(rnd_seed, sizeof rnd_seed);
  ERR_load_crypto_strings();
  login_attempts = new map<string,login_attempt*>;
  client_attempts = new map<string,login_attempt*>;

  
}

void crypto_exit()
{
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_state(0);
  pthread_mutex_destroy(&mutex);
  // CRYPTO_mem_leaks_fp(stderr);
}

// Unencrypted nonces

int equal_nonce(unsigned char* nonce1, unsigned char* nonce2)
{
  for(int i=0;i<AUTH_NONCE_LEN/8;i++)
    if ( nonce1[i] != nonce2[i])
      return 0;
  return 1;
}

int timed_out(time_t oldtime)
{
  time_t curtime;
  time(&curtime);
  if ( curtime - oldtime > LOGIN_TIMEOUT )
    return 1;
  return 0;
}

void print_rsa_key(RSA* pkey)
{
  if ( pkey->n )
    DEBUG(11,"N=%s ",BN_bn2dec((pkey->n)));
  if (pkey->e )
    DEBUG(11,"E=%s ",BN_bn2dec((pkey->e)));
  if ( pkey->d )
    DEBUG(11,"D=%s ",BN_bn2dec((pkey->d)));
  if ( pkey->p)
    DEBUG(11,"P=%s ",BN_bn2dec((pkey->p)));
  if ( pkey->q)
    DEBUG(11,"Q=%s\n",BN_bn2dec((pkey->q)));
}

int lock_mutex()
{
#ifndef __CYGWIN__
  if ( pthread_mutex_lock(&mutex) )
  {
    DEBUG(1,"get_public_key/read_in_public_keys: problem with locking mutex\n");
    return 1;
  }
#endif
  return 0;
}

int unlock_mutex()
{
#ifndef __CYGWIN__
  if ( pthread_mutex_unlock(&mutex) )
  {
    DEBUG(1,"get_public_key/read_in_public_keys: problem with unlocking mutex\n");
    return 1;
  }
#endif
  return 0;
}



// Read in public keys from file
void read_in_public_keys(char* file)
{

  if (lock_mutex())
  {
    DEBUG(1,"read_in_public_keys: problem with locking mutex\n");
    return;
  }

  // printf("Reading public keys\n");
  
  if ( publickeys != NULL)
  {
    map<string,RSA*>::iterator piter;
    
    for(piter = publickeys->begin(); piter != publickeys->end(); piter++)
      if ( piter->second != NULL)
	RSA_free(piter->second);
    
    delete publickeys;
  }
  
  publickeys = new map<string,RSA*>;

  FILE* fp = fopen(file,"r");
  if ( fp == NULL )
  {
    DEBUG(1,"Could not open public key file\n");
    if ( unlock_mutex() )
    {
      DEBUG(1,"read_in_public_keys: problem with unlocking mutex\n");
      return;
    }
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

    DEBUG(11,"User %s has RSA\n",username);
    print_rsa_key(key);
  }
  while(1);
  fclose(fp);

  if ( unlock_mutex() )
  {
    DEBUG(1,"read_in_public_keys: problem with unlocking mutex\n");
    return;
  }

  if ( file != public_key_file_store )
  {
    strcpy(public_key_file_store,file);

    if (pthread_create(&public_key_refresh_thrd, NULL,public_key_refresh, (void *) NULL))
    {
      DEBUG(1, "Error creating public key refresh thread !\n");
      return;
    }
  }
  
}

// only for public keys
RSA *rsa_copy(RSA* orig)
{
  if ( orig == NULL )
    return orig;

  RSA* copy = RSA_new();

  if ( orig->n)
    copy->n = BN_dup(orig->n);
  if ( orig->e )
    copy->e = BN_dup(orig->e);

  return copy;
}
  

RSA *get_public_key(char* user)
{
  
  if ( lock_mutex() )
  {
    DEBUG(1,"get_public_key: problem with locking mutex\n");
    return NULL;
  }
  
  map<string,RSA*>::iterator piter = publickeys->find(string(user));
  
  if (piter == publickeys->end())
  {
    if ( unlock_mutex() )
    {
      DEBUG(1,"get_public_key: problem with unlocking mutex\n");
      return NULL;
    }
    return NULL;
  }

  
  RSA* copy = rsa_copy(piter->second);

  if ( unlock_mutex() )
  {
    DEBUG(1,"get_public_key: problem with unlocking mutex\n");
    RSA_free(copy);
    return NULL;
  }
  
  return copy;
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
  print_rsa_key(myprivatekey); 
  fclose(fp);
  return(username);
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

// Client proxy node

// Client proxy: Generate nonce and encrypt it
// Note: possible to have multiple attempts
// 1 on success, 0 on failure
int server_login(char* server,ID* id,char* nonce)
{
  char tstr[MAX_LEN];
  sprintf_i3_id(tstr,id);
  map<string,login_attempt*>::iterator liter = login_attempts->find(string(tstr));
  login_attempt* cur_attempt;

  // Retx: Can use same nonce until timed out
  
  if ( liter != login_attempts->end() && timed_out(liter->second->starttime)) 
  {
    delete liter->second;
    login_attempts->erase(liter);
    liter = login_attempts->end();
  }
  
  if ( liter == login_attempts->end() || timed_out(liter->second->starttime) )
  {
    cur_attempt = new login_attempt;
    if ( (cur_attempt->public_key = get_public_key(server)) == NULL)
      return 0;
    time(&(cur_attempt->starttime));
    generate_nonce(cur_attempt->mynonce);
    login_attempts->insert(make_pair(string(tstr),cur_attempt));
  }
  else
    cur_attempt = liter->second;

  if ( RSA_public_encrypt(AUTH_NONCE_LEN/8,cur_attempt->mynonce,(unsigned char*) nonce,cur_attempt->public_key,RSA_PKCS1_PADDING) != AUTH_KEY_LEN / 8)
  {
    DEBUG(1,"server_login RSA module error: %s\n",ERR_error_string(ERR_get_error(),NULL));
    return 0;
  }
  
  return 1;
}

// Client proxy: Check server has returned our nonce correctly
//               Decrypt nonce sent by server using our private key
//               Encrypt server's nonce using his public key

int server_auth(ID* id,char* rnonce,char* snonce,char* rrnonce)
{
  char tstr[MAX_LEN];
  sprintf_i3_id(tstr,id);
  map<string,login_attempt*>::iterator liter = login_attempts->find(string(tstr));
  login_attempt* cur_attempt;

  if ( liter == login_attempts->end())
  {
    DEBUG(11,"server_auth: Could not find attemptt\n");
    return 0;
  }
  
  cur_attempt = liter->second;

  if (timed_out(cur_attempt->starttime))
  {
    if ( cur_attempt->public_key)
      RSA_free(cur_attempt->public_key);
    delete cur_attempt;
    login_attempts->erase(liter);
    DEBUG(11,"server_auth: Timed out\n");
    return 0;
  }
  
  unsigned char checknonce[AUTH_NONCE_LEN/8];
  
  if ( RSA_private_decrypt(AUTH_KEY_LEN/8,(unsigned char*) rnonce,checknonce,myprivatekey,RSA_PKCS1_PADDING) != AUTH_NONCE_LEN / 8)
  {
    DEBUG(11,"server_auth: Decrypting server's nonce failed\n");
    return 0;
  }
  
  if ( !equal_nonce(checknonce,cur_attempt->mynonce))
  {
    DEBUG(11,"server_auth: Nonce match failed\n");
    return 0;
  }
  
  if ( RSA_private_decrypt(AUTH_KEY_LEN/8,(unsigned char*) snonce,checknonce,myprivatekey,RSA_PKCS1_PADDING) != AUTH_NONCE_LEN / 8)
  {
    DEBUG(11,"server_auth: Decrypting server's nonce2 failed\n");
    return 0;
  }
  
  if ( RSA_public_encrypt(AUTH_NONCE_LEN/8,checknonce,(unsigned char*) rrnonce,cur_attempt->public_key,RSA_PKCS1_PADDING) != AUTH_KEY_LEN / 8)
  {
    DEBUG(11,"server_auth: Encoding our nonce failed\n");
    return 0;
  }

  if ( cur_attempt->public_key)
    RSA_free(cur_attempt->public_key);
  delete cur_attempt;
  
  login_attempts->erase(liter);
  return 1;
}

map<string,login_attempt*> *client_logins;

// Server proxy: User attempts to login with nonce
// rnonce: nonce to return

int user_login(ID* id,char* user,char* nonce)
{
  char tstr[MAX_LEN];
  sprintf_i3_id(tstr,id);
  map<string,login_attempt*>::iterator liter = client_attempts->find(string(tstr));
  login_attempt* cur_attempt;

  // Retx: Load up different nonce until timed out
  
  if (liter != client_attempts->end()) 
  {
    delete liter->second;
    client_attempts->erase(liter);
    liter = client_attempts->end();
  }
  
  cur_attempt = new login_attempt;
  
  if ( (cur_attempt->public_key = get_public_key(user)) == NULL)
  {
    DEBUG(1,"user_login: user had no public key\n");
    delete cur_attempt;
    return 0;
  }
    
  time(&(cur_attempt->starttime));
  client_attempts->insert(make_pair(string(tstr),cur_attempt));

  if( RSA_private_decrypt(AUTH_KEY_LEN/8,(unsigned char*) nonce,cur_attempt->mynonce,myprivatekey,RSA_PKCS1_PADDING) != AUTH_NONCE_LEN/8)
  {
    DEBUG(1,"user_login: decruption of user's nonce failed\n");
    return 0;
  }
  
  return 1;
}

int user_login_retrieve(ID* id,char* rnonce1,char* rnonce2)
{
  char tstr[MAX_LEN];
  sprintf_i3_id(tstr,id);
  map<string,login_attempt*>::iterator liter = client_attempts->find(string(tstr));
  login_attempt* cur_attempt;

  // Retx: Can use same nonce until timed out
  
  if ( liter != client_attempts->end() && timed_out(liter->second->starttime)) 
  {
    delete liter->second;
    client_attempts->erase(liter);
    liter = client_attempts->end();
  }
  
  if ( liter == client_attempts->end())
    return 0;

  cur_attempt = liter->second;
  unsigned char return_nonce[AUTH_NONCE_LEN/8];
  memcpy(return_nonce,&(cur_attempt->mynonce),AUTH_NONCE_LEN/8);
  generate_nonce(cur_attempt->mynonce);
  
  if ( RSA_public_encrypt(AUTH_NONCE_LEN/8,return_nonce,(unsigned char*) rnonce1,cur_attempt->public_key,RSA_PKCS1_PADDING) != AUTH_KEY_LEN / 8)
  {
    DEBUG(1,"user_login_retrieve: encryption of user's nonce failed\n");
    return 0;
  }

  if ( RSA_public_encrypt(AUTH_NONCE_LEN/8,cur_attempt->mynonce,(unsigned char*) rnonce2,cur_attempt->public_key,RSA_PKCS1_PADDING) != AUTH_KEY_LEN / 8)
  {
    DEBUG(1,"user_login_retrieve: encryption of server's nonce failed\n");
    return 0;
  }
  
  return 1;
}


int user_verify(ID* id,char* rnonce)
{
  char tstr[MAX_LEN];
  sprintf_i3_id(tstr,id);
  map<string,login_attempt*>::iterator liter = client_attempts->find(string(tstr));
  login_attempt* cur_attempt;

  if ( liter == client_attempts->end())
  {
    DEBUG(11,"not found\n");
    return 0;
  }
  
  cur_attempt = liter->second;

  if (timed_out(cur_attempt->starttime))
  {
    delete cur_attempt;
    client_attempts->erase(liter);
    DEBUG(11,"timeout failed\n");
    return 0;
  }
  
  unsigned char checknonce[AUTH_NONCE_LEN/8];
  
  if ( RSA_private_decrypt(AUTH_KEY_LEN/8,(unsigned char*) rnonce,checknonce,myprivatekey,RSA_PKCS1_PADDING) != AUTH_NONCE_LEN / 8)
  {
    DEBUG(1,"user_verify: encryption of server's nonce failed\n");
    return 0;
  }
  
  if ( !equal_nonce(checknonce,cur_attempt->mynonce))
  {
    DEBUG(1,"user_verify: Nonce failed\n");
    return 0;
  }

  delete cur_attempt;
  client_attempts->erase(liter);
  return 1;
}

// for testing 
int test_main()
{
  crypto_init();
  
  read_in_public_keys("public.key");
  read_in_private_key("private.key");

  ID id;
  for(int i=0;i<ID_LEN/8;i++)
    id.x[i] = i;

  char nonce1[AUTH_KEY_LEN/8],nonce2[AUTH_KEY_LEN/8],nonce3[AUTH_KEY_LEN/8],nonce4[AUTH_KEY_LEN/8];
  
  printf("Server Login: %d\n",server_login("kjk",&id,nonce1));
  printf("User Login: %d\n",user_login(&id,"kjk",nonce1));
  printf("User Login: %d\n",user_login_retrieve(&id,nonce2,nonce3));
  printf("Server Auth: %d\n",server_auth(&id,nonce2,nonce3,nonce4));
  printf("User Verify: %d\n",user_verify(&id,nonce4));

  crypto_exit();
  
  return 0;
}











		  














