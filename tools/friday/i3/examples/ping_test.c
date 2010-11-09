#include <stdio.h>
#include <stdlib.h>
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

#define PRINT_GRANULARITY 1 /* print every other PRINT GRANULARITY packet */

/* callbacks */
void receive_payload(i3_trigger *t, cl_buf *clb, void *data)
{
  long seq;

  if (clb->data_len) {
    seq = ntohl(*((long *)(clb->data)));
    if (seq % PRINT_GRANULARITY == 0)
      printf("recv. seq. #: %ld \n", seq);
  }
}

void constraint_failed(i3_trigger *t, void *data)
{
  printf("Trigger constraint failed\n");
}
void trigger_inserted(i3_trigger *t, void *data)
{
  printf("Trigger inserted\n");
}

void trigger_failure(i3_trigger *t, void *data)
{
  printf("Trigger failed\n");

  /* reinsert trigger */
  cl_reinsert_trigger(t);
}

int i3_main_loop(char *srv_file)
{
  fd_set rset;
  struct timeval to;
  ID id;
  i3_trigger *t1, *t;
  int rc;
  Key key;
  uint64_t last_update_time;
  
  ID id_a;
  i3_stack *s = alloc_i3_stack();

#define N 3
  uint16_t best_port[N];
  uint32_t best_addr[N], prev_best_addr[N];
  uint64_t best_rtt[N], prev_best_rtt[N];
  ID best_ID[N], prev_best_ID[N];
  
  FD_ZERO(&rset);

  read_parameters(srv_file);

  /* initialize context */
  cl_init(NULL, 0);
  // cl_init_ping("www.cs.berkeley.edu/~karthik/i3_status.txt");
  //cl_init_tcp(NULL, 0);

  /* create and insert trigger --- all triggers are r-constrained */
  init_i3_id_fromstr(&id, "this is a test id");
  id.x[MIN_PREFIX_LEN/8] = 10;
  init_i3_id_fromstr(&id_a, "this is target");
  set_private_id(&id);
  generate_r_constraint(&id, &key);
  set_key_id(&id_a, &key);
  init_i3_stack(s, &id_a, 1);
  set_private_id(&id_a);
  generate_r_constraint(&id_a, &key);
  t1 = cl_insert_trigger_stack(&id, MIN_PREFIX_LEN, s);
  assert(t1 != NULL);
  t = cl_insert_trigger_key(&id_a, MIN_PREFIX_LEN, &key);
  assert(t != NULL);

  /* for l-constrained public triggers
   *----------------------------------
   * set_public_id(&id);
   * generate_l_constraint_id(&id_a, &key);
   * set_key_id(&id, &key);
   */
  
  /* associate callbacks with the inserted trigger */
  cl_register_trigger_callback(t, CL_CBK_TRIGGER_CONSTRAINT_FAILED, 
			       constraint_failed, NULL);
  cl_register_trigger_callback(t, CL_CBK_RECEIVE_PAYLOAD, 
			       receive_payload, NULL);
  cl_register_trigger_callback(t, CL_CBK_TRIGGER_INSERTED, 
			       trigger_inserted, NULL);
  cl_register_trigger_callback(t, CL_CBK_TRIGGER_REFRESH_FAILED, 
			       trigger_failure, NULL);

  /* loop and call cl_select */
  last_update_time = wall_time();
  for (;;) {
    FD_SET(0, &rset); /* just here, to be modified if application
		       * listens on other fds
		       */
    to.tv_sec = 1; to.tv_usec = 0;
    if ((rc = cl_select(0, &rset, NULL, NULL, &to)) < 0) {
      if (errno == EINTR)
	continue;
      else
	err_sys("select_error\n");
    }

    // for testing:
    if (wall_time() - last_update_time > 10*1000000ULL) {
	struct in_addr ia;
	int i, n = N;

	memmove(prev_best_addr, best_addr, N * sizeof(uint32_t));
	assert(cl_get_top_k_servers(&n, best_addr, 
		    best_port, best_rtt) == CL_RET_OK);
	for (i = 0; i < n; i++)
	    assert(CL_RET_OK == 
		    cl_get_rtt_server(prev_best_addr[i], &(prev_best_rtt[i])));
	
	printf("Closest addr (%d): ", n);
	for (i = 0; i < n; i++) {
	    ia.s_addr = htonl(best_addr[i]);
	    printf("(%s, %0.2f ms), ", inet_ntoa(ia), best_rtt[i]/1000.0);
	}
	printf("\n");
	
	printf("Previous (%d): ", n);
	for (i = 0; i < n; i++) {
	    ia.s_addr = htonl(prev_best_addr[i]);
	    printf("(%s, %0.2f ms), ",
		    inet_ntoa(ia), prev_best_rtt[i]/1000.0);
	}
	printf("\n");
	
	memmove(prev_best_ID, best_ID, N * sizeof(ID));
	assert(cl_get_top_k_ids(&n, best_ID, best_rtt) == CL_RET_OK);
	for (i = 0; i < n; i++)
	    assert(cl_get_rtt_id(&(prev_best_ID[i]), &(prev_best_rtt[i])) 
		    == CL_RET_OK);
	
	printf("Closest ID (%d): ", n);
	for (i = 0; i < n; i++) {
	    printf("(");
	    printf_i3_id(&(best_ID[i]), 0);
	    printf(",%0.2f ms), ", best_rtt[i]/1000.0);
	}
	printf("\n");

	printf("Previous (%d): ", n);
	for (i = 0; i < n; i++) {
	    printf("(");
	    printf_i3_id(&(prev_best_ID[i]), 0);
	    printf(",%0.2f ms), ", prev_best_rtt[i]/1000.0);
	}
	printf("\n\n");
	
	last_update_time = wall_time();
    }
  }

  /* remove & destroy trigger */
  cl_remove_trigger(t);
  
  /* destroy context */
  cl_exit();
}


int main(int argc, char **argv)
{
  struct hostent *hptr;
  struct utsname myname;
  char str[INET6_ADDRSTRLEN];
  char **pptr;
 
  if (argc != 2) {
    printf("%s i3_server_list.txt\n", argv[0]);
    exit(-1);
  }
  
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

  i3_main_loop(argv[1]);
  return -1;
}

