#include <stdio.h>
#include <stdlib.h>
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
#include <unistd.h>

#include "i3.h"
#include "i3_fun.h"
#include "i3_api.h"
#include "../i3_server/i3_matching.h"
#include "../i3_client/i3_client_api.h"

#define TO_SEND_USEC 50 * 1000
#define TO_SEND_SEC  0

#define PRINT_GRANULARITY 1  /* print every other PRINT GRANULARITY packet */
#define PKTS_PER_SLICE    1  /* there are 1e+6*PKTS_PER_SLICE/TO_SEND_USEC
			      * sent per second 
			      */

void send_data(ID *id)
{
#define MY_PKT_SIZE 2000
  static long seq = 0;
  long        temp; 
  int         k;
  static cl_buf  *clb = NULL;
  
  if (clb == NULL) 
    clb = cl_alloc_buf(MY_PKT_SIZE);


  for (k = 0; k < PKTS_PER_SLICE; k++) {
    temp = htonl(++seq);
    memcpy(clb->data, &temp, sizeof(long));
    clb->data_len = 1900; // sizeof(long); 
    
    /* send packet */
    cl_send_to_id(id, clb);
    
    if (seq % PRINT_GRANULARITY == 0) 
	printf("sent, seq. #: %ld\n", seq);
  }
}  

void no_matching_trigger(ID *id, void *data)
{
  printf("Following ID not found, ");
  printf_i3_id(id, 0);
}

int i3_main_loop(char *srv_file)
{
  fd_set      rset;
  int         rc;
  ID          id;
  struct timeval select_to;

  FD_ZERO(&rset);

  read_parameters(srv_file);
  
  /* initialize context */
  //cl_init_tcp(NULL, 0);
  cl_init(NULL, 0);
  /* exception when matching trigger not found */
  cl_register_callback(CL_CBK_TRIGGER_NOT_FOUND, no_matching_trigger, NULL);

  /* create packet stack */
  init_i3_id_fromstr(&id, "this is a test id");
  cl_set_private_id(&id);
  id.x[MIN_PREFIX_LEN/8] = 10;
  id.x[MIN_PREFIX_LEN/8+1] = 128;
  printf_i3_id(&id, 2);


  /* setup the timer to send the first packet */
  select_to.tv_usec = TO_SEND_USEC;
  select_to.tv_sec = TO_SEND_SEC;

  /* loop and call cl_select */
  for (;;) {

    FD_SET(0, &rset); /* just here, to be modified if application
		       * listens on other fds */
  
    if ((rc = cl_select(0, &rset, NULL, NULL, &select_to)) < 0) {
      if (errno == EINTR)
	continue;
      else
	err_sys("select_error\n");
    }

    if ((select_to.tv_sec == 0) && (select_to.tv_usec == 0)) {

      send_data(&id);

      /* reinitialize the timer */
      select_to.tv_usec = TO_SEND_USEC;
      select_to.tv_sec = TO_SEND_SEC;
    }

    sleep(2);
  }

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
