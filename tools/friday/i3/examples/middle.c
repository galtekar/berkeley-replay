#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>   /* basic system data types */
#include <sys/socket.h>  /* basic socket definitions */
#include <sys/time.h>    /* timeval{} for select() */
#include <errno.h>    
#include <sys/utsname.h>
#include <time.h>        /* timespec{} for pselect() */
#include <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>
#include <netdb.h>

#include "i3.h"
#include "i3_fun.h"
#include "i3_api.h"
#include "../i3_server/i3_matching.h"
#include "../i3_client/i3_client_api.h"

#define PRINT_GRANULARITY 100 /* print every other PRINT GRANULARITY packet */

/* callbacks */
void process_payload(ID *id, ID *id_next, cl_buf *clb, void *data)
{
  long seq;

  if (clb->data_len) {
    /* read sequence number and add 10000 to it */ 
    seq = ntohl(*((long *)(clb->data)));
    if (seq % PRINT_GRANULARITY == 0)
      printf("recv. seq. #: %ld\n", seq);
    seq += 10000;
    seq = htonl(seq);
    memcpy(clb->data, &seq, sizeof(long));
    clb->data_len = sizeof(long);
    
   /* send packet */
    cl_path_send(id_next, clb);

  }
}


int i3_main_loop(char *srv_file, int bridge_idx)
{
  fd_set rset;
  ID id;
  Key rkey, lkey;
  i3_trigger *t;
  int rc;

  FD_ZERO(&rset);

  read_parameters(srv_file);

  /* initialize context */
  cl_init(NULL, 0 );

  /* create and insert trigger */
  init_i3_id_fromstr(&id, "this is a test id");
  id.x[0] = bridge_idx;
  init_key_fromstr(&rkey, "this is bridge key");
  cl_generate_l_constraint_key(&rkey, &lkey);
  cl_set_key_id(&id, &lkey);

  /* register with this "id" */
  t = cl_register_key(&id, MIN_PREFIX_LEN, process_payload, NULL, &rkey);

  /* loop and call cl_select */
  for (;;) {

    FD_SET(0, &rset); /* just here, to be modified if application
		       * listens on other fds
		       */
    if ((rc = cl_select(0, &rset, NULL, NULL, NULL)) < 0) {
      if (errno == EINTR)
	continue;
      else
	err_sys("select_error\n");
    }
  }

  /* remove & destroy trigger */
  cl_unregister(t);
  
  /* destroy context */
  cl_exit();
}


int main(int argc, char **argv)
{
  struct hostent *hptr;
  struct utsname myname;
  char str[INET6_ADDRSTRLEN];
  char **pptr;
  int bridge_idx;
 
  if (argc != 3) {
    printf("%s i3_server_list.txt bridge_idx\n", argv[0]);
    exit(-1);
  }
  bridge_idx = atoi(argv[2]);
  printf("bridge_idx = %d\n", bridge_idx);
  
  if (uname(&myname) < 0) {
    err_sys("uname error.\n");
    exit(-1);
  }

  if ((hptr = gethostbyname(myname.nodename)) == NULL) {
    err_sys("gethostbyname error\n");
    exit(-1);
  }

  printf("name = %s\n", hptr->h_name);
  for (pptr = hptr->h_addr_list; *pptr != NULL; pptr++) {
    printf("address = %s\n", inet_ntop(hptr->h_addrtype, 
				       *pptr, str, sizeof(str)));
  }

  i3_main_loop(argv[1], bridge_idx);
  return -1;
}

