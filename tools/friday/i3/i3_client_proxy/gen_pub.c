#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#ifdef __CYGWIN__
#include <w32api/windows.h>
#include <w32api/iphlpapi.h>
#elif !defined(__APPLE__)
#include <error.h>
#endif
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <time.h>

#include "debug.h"
#include "i3.h"
#include "i3_id.h"
#include "i3_trigger.h"

void get_random_ID(ID *id)
{
  int   i;
     
  for(i=0; i < ID_LEN; i++)
  {
    id->x[i] = (char) (rand() % 255);
  }
}

void get_random_key(Key *id)
{
  int   i;

  for(i=0; i < KEY_LEN; i++)
  {
    id->x[i] = (char) (rand() % 255);
  }
}

int main()
{
  Key lkey,rkey;
  ID myid;
  
  srand(getpid() ^ time(0));
  aeshash_init();

  /* generate random ID and make sure public_id bit is set */
  get_random_ID(&myid);
  set_public_id(&myid);

  /* set l-constraint */
  get_random_key(&rkey);
  generate_l_constraint_addr(&rkey,&lkey);
  set_key_id(&myid,&lkey);

  printf("Add this key to i3-client-proxy.xml under the i3 dns name\n");
  printf_i3_key((uint8_t*)(rkey.x),0);
  printf("Add this entry to your address book under the i3 dns name\n");
  printf_i3_id(&myid,0);
  return 0;
}



