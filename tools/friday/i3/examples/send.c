#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>   /* basic system data types */
#include <sys/socket.h>  /* basic socket definitions */
#include <sys/time.h>    /* timeval{} for select() */
#include <errno.h>    
#include <sys/utsname.h>
#include <time.h>                /* timespec{} for pselect() */
#include <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>
#include <netdb.h>

#include "i3.h"
#include "i3_fun.h"
#include "i3_api.h"
#include "../i3_server/i3_matching.h"
#include "../i3_client/i3_client_api.h"

#define TO_SEND_USEC 10000
#define TO_SEND_SEC  1

#define PRINT_GRANULARITY 1  /* print every other PRINT GRANULARITY packet */
#define PKTS_PER_SLICE    1  /* there are 1e+6*PKTS_PER_SLICE/TO_SEND_USEC
			      * sent per second 
			      */

void send_data(ID *id)
{
#define MY_PKT_SIZE 100
  static long seq = 0;
  long        temp; 
  int         k;
  static cl_buf  *clb = NULL;
  
  if (clb == NULL) 
    clb = cl_alloc_buf(MY_PKT_SIZE);


  for (k = 0; k < PKTS_PER_SLICE; k++) {
    temp = htonl(seq++);
    memcpy(clb->data, &temp, sizeof(long));
    clb->data_len = sizeof(long);
    
    /* send packet */
    cl_path_send(id, clb);
    
    if (seq % PRINT_GRANULARITY == 0) 
      printf("sent, seq. #: %ld\n", seq-1);
  }
}  


void no_path_id(ID *id, void *data)
{
  printf("Following path ID not found, ");
  printf_i3_id(id, 0);
}

void path_inserted(cl_path *clp, void *data)
{
  printf("path inserted.\n");
}

void path_refresh_failed(cl_path *clp, void *data)
{
  printf("path failed, reinsert it again ...\n");
  cl_reinsert_path(clp);
}



int i3_main_loop(char *srv_file, int path_len, uint32_t tmask)
{
  fd_set      rset;
  int         i, rc;
#define PATH_LEN 5
  ID          path[path_len];
  cl_path    *clp;
  struct timeval select_to;
  int	      prev_bridge;
  Key	      lkey, rkey;
  uint64_t    last_send_time;

  FD_ZERO(&rset);

  read_parameters(srv_file);

  /* initialize context */
  cl_init(NULL, 0 );

  /* initialize path and setup constraints */
  prev_bridge = 0;
  for (i = 0; i < path_len - 1; i++) {
    init_i3_id_fromstr(&path[i],  "this is a test id");
    path[i].x[0] = i;
    if (is_mask_bit_set(tmask, i)) {
	/* set up bridge ID.  This has to be shared with the bridge by an
	 * out of band mechanism --- in this example, it is generated from
	 * a string that is shared between sender and bridge */
	init_key_fromstr(&rkey, "this is bridge key");
	generate_l_constraint_addr(&rkey, &lkey);
	set_key_id(&(path[i]), &lkey);
	
	/* constrain path between the bridges */
	l_constrain_path(&(path[prev_bridge]), i - prev_bridge + 1);
	prev_bridge = i + 1;
    }
  }
  /* set up last ID.  This has to be shared with the receiver by an
   * out of band mechanism --- in this example, it is generated from
   * a string that is shared between sender and receiver */
  init_i3_id_fromstr(&path[path_len-1],  "this is a test id");
  init_key_fromstr(&rkey, "this is test key");
  generate_l_constraint_addr(&rkey, &lkey);
  set_key_id(&(path[path_len-1]), &lkey);

  /* l-constrain last segment of the path */
  l_constrain_path(&(path[prev_bridge]), path_len - prev_bridge);
  
  /* setup path */
  if ((clp = cl_setup_path(path, path_len, tmask, &rc)) == NULL) {
    printf("setup path error = %d\n", rc);
    cl_exit();
    exit(-1);
  }

  /* register callbacks */
  cl_register_path_callback(clp, CL_CBK_PATH_INSERTED, path_inserted, NULL);
  cl_register_path_callback(clp, CL_CBK_PATH_REFRESH_FAILED, 
			    path_refresh_failed, NULL);

  /* exception when matching trigger not found
   * (Note: CL_CBK_PATH_ID_NOT_FOUND == CL_CBK_TRIGGER_NOT_FOUND) */
  cl_register_callback(CL_CBK_PATH_ID_NOT_FOUND, no_path_id, NULL);

  /* setup the timer to send the first packet */
  select_to.tv_usec = TO_SEND_USEC;
  select_to.tv_sec = 1; //TO_SEND_SEC;

  /* loop and call cl_select */
  last_send_time = wall_time();
  for (;;) {

    FD_SET(0, &rset); /* just here, to be modified if application
		       * listens on other fds
		       */
    if ((rc = cl_select(0, &rset, NULL, NULL, &select_to)) < 0) {
      if (errno == EINTR)
	continue;
      else
	err_sys("select_error\n");
    }

    if (wall_time() - last_send_time > TO_SEND_SEC*1000000ULL + TO_SEND_USEC) {
      send_data(&path[0]);
      last_send_time = wall_time();
    }
  
    select_to.tv_usec = TO_SEND_USEC;
    select_to.tv_sec = TO_SEND_SEC;
  }  

  cl_remove_path(clp);
  /* destroy context */
  cl_exit();
}


int main(int argc, char **argv)
{
  struct hostent *hptr;
  struct utsname myname;
  char str[INET6_ADDRSTRLEN];
  char **pptr;
  uint32_t tmask;
  int path_len, i, idx;
 
  if (argc <= 2) {
    printf("%s i3_server_list.txt path_len [bridge_idx1 bridge_idx2 ..]\n", argv[0]);
    exit(-1);
  }
  path_len = atoi(argv[2]);
  printf("path_len = %d\n", path_len);
  if (path_len < 0 || path_len >= CL_MAX_PATH_LEN) {
    printf("path_len should be between 0 and %d\n", CL_MAX_PATH_LEN); 
    exit(-1);
  }

  tmask = 0;
  for (i = 3; i < argc; i++) {
    idx = atoi(argv[i]);
    if (idx < 0 || idx >= path_len-1) {
      printf("bridge_idxi should be between 0 and %d\n", path_len -2);
      exit(-1);
    }
    set_mask_bit(tmask, idx);
  }
  printf("tmask = %x\n", tmask);

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

  i3_main_loop(argv[1], path_len, tmask);
  return -1;
}

