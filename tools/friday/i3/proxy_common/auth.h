#ifdef __cplusplus
extern "C"
{
#endif
  
#include "../i3/i3.h"
#include "../i3/i3_id.h"

  #define AUTH_KEY_LEN 1024
  // 1024 - 96 (padding for rsa) = 928
  #define AUTH_NONCE_LEN 928
  #define LOGIN_TIMEOUT 1000
  
  void crypto_init();
  void crypto_exit();

  // Used at client proxy: To read in client's private key
  // Used at server proxy: To read in server's private key
  // Returns username of client/server (pointer to static data is returned)
  char *read_in_private_key(char* file);
  
  // Used at client proxy: Initialize server name, public key database
  // Used at server proxy: Initialize username, public key database
  void read_in_public_keys(char* file);

  // Server proxy: User attempts to login with nonce
  int user_login(ID* id,char* user,char* nonce);
  int user_login_retrieve(ID* id,char* nonce,char* rnonce);
  int user_verify(ID* id,char* snonce);

  // Client proxy: Generate nonce and encrypt it
  int server_login(char *server,ID* id,char* nonce);
  int server_auth(ID* id,char* rnonce,char* snonce,char* rrnonce);
  

#ifdef __cplusplus
}
#endif

