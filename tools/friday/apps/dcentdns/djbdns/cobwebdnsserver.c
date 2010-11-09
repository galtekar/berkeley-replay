#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#include "iopause.h"
#include "taia.h"
#include "buffer.h"
#include "byte.h"
#include "dns.h"
#include "printpacket.h"
#include "stralloc.h"
#include "strerr.h"
#include "alloc.h"
#include "codonsutils.h"
#include "dnssecutils.h"
#include "error.h"
#include "ip4.h"
#include "scan.h"
#include "sgetopt.h"
#include "exit.h"
#include "roots.h"
#include "query.h"
#include "response.h"
#include "log.h"
#include "cache.h"

#define COBWEB_PORT 53
#define COBWEB_MAX_QUERIES 200

#define COBWEB_QRYBUF_LEN 1024
#define FATAL "COBWEB: fatal: "

#define COBWEB_MAX_REDIRECTS 100

#define COSEC_PORT 11111

static stralloc out;

struct QueryState {
  struct dns_transmit dns_tx;
  iopause_fd *iofd;
  int done;
  int valid;
  int error;
  struct sockaddr_in sa;
  int sasize;
  DNSQueryMsg *qryMsg;
  struct timeval started;
  struct timeval ended;
};

static char redirects[COBWEB_MAX_REDIRECTS][4];
static int numredirects = 0;
static uint64 redirecttime = 0;
static char redirectfilename[100];
static char tempredirects[COBWEB_MAX_REDIRECTS][4];
static int tempnumredirects = 0;

int readRedirects() {
  static struct timeval temptime;
  gettimeofday(&temptime, (struct timezone *) 0);
  uint64 currenttime = temptime.tv_sec*1000 + temptime.tv_usec/1000;

  if (currenttime < redirecttime) {
    return 1;
  }

  FILE *redfp = fopen(redirectfilename, "r");
  if (redfp == (FILE *)0) {
    fprintf(stderr, "COBWEB: unable to read redirection urls from file %s\n", redirectfilename);
    return 0;
  }

  int temp[4];
  for (numredirects=0; fscanf(redfp, "%d.%d.%d.%d", &temp[0], &temp[1], &temp[2], &temp[3]) == 4 && numredirects < COBWEB_MAX_REDIRECTS; numredirects++) {
    redirects[numredirects][0] = (unsigned char)temp[0];
    redirects[numredirects][1] = (unsigned char)temp[1];
    redirects[numredirects][2] = (unsigned char)temp[2];
    redirects[numredirects][3] = (unsigned char)temp[3];
  }
  printf("COBWEB: read %d redirection urls from file %s\n", numredirects, redirectfilename);
  fflush(stdout);

  fclose(redfp);

  FILE *tempredfp = fopen("redirectips2.txt", "r");
  if (tempredfp == (FILE *)0) {
    fprintf(stderr, "COBWEB: unable to read redirection urls from file %s\n", "redirectips2.txt");
    return 0;
  }

  for (tempnumredirects=0; fscanf(tempredfp, "%d.%d.%d.%d", &temp[0], &temp[1], &temp[2], &temp[3]) == 4 && tempnumredirects < COBWEB_MAX_REDIRECTS; tempnumredirects++) {
    tempredirects[tempnumredirects][0] = (unsigned char)temp[0];
    tempredirects[tempnumredirects][1] = (unsigned char)temp[1];
    tempredirects[tempnumredirects][2] = (unsigned char)temp[2];
    tempredirects[tempnumredirects][3] = (unsigned char)temp[3];
  }

  fclose(tempredfp);

  redirecttime = currenttime + 15*60*1000;
  return 1;
}

int printPacket(char *pkt, int len) {
  if (!stralloc_copys(&out, "")) {
    return 0;
  }
  if (printpacket_cat(&out, pkt, len)) {
    buffer_putflush(buffer_1, out.s, out.len);
  }
  return 1;
}

int bindsocket(int sockfd, unsigned short port) {
  struct sockaddr_in sa;
  int opt = 1;
  int bufsize = 128 * 1024;

  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
  while(bufsize >= 1024) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof bufsize) == 0)
      break;
    bufsize -= 10 * 1024;
  }

  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  uint16_pack_big((char *) &sa.sin_port, port);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  return bind(sockfd, (struct sockaddr *) &sa, sizeof sa);
}

int main(int argc,char **argv)
{
  char seed[128];
  char servers[64];
  int redirect = 0;

  dns_random_init(seed);
  byte_zero(servers, 64);
  byte_copy(servers, 4, "\177\0\0\1");

  iopause_fd *iofd = 0;  

  struct QueryState *querystate = 0; 
  int maxqueries = COBWEB_MAX_QUERIES;
  int numactive = 0;
  
  int qrysockfd;
  iopause_fd *qryiofd;
  char qrybuf[COBWEB_QRYBUF_LEN];

  int pipefd[2];
  iopause_fd *pipeiofd;
  char pipebuf[256];

  unsigned short port = COBWEB_PORT;
  unsigned short cosecport = COSEC_PORT;

  int opt;
  while ((opt = getopt(argc, argv,"p:lr:c:h")) != opteof) {
    switch(opt) {
      case 'p':
	sscanf(optarg, "%hu", &port);
	break;
      case 'l':
	query_log();
	break;
      case 'r':
	redirect = 1;
	sscanf(optarg, "%s", redirectfilename);
	break;
      case 'c':
	sscanf(optarg, "%hu", &cosecport);
	break;
      case 'h':	
      default:
	strerr_die1x(111,"COBWEB: usage: codonssecureserver [-p <port>] [-l log details] [-r <redirection file name> [-c codons secure server port] [-h help]");
    }
  }

  if ((qrysockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    strerr_die2sys(111,FATAL,"unable to open udp socket ");
  }
  if (bindsocket(qrysockfd, port)) {
    strerr_die2sys(111,FATAL,"unable to bind udp socket ");
  }
  
  if ((iofd = (iopause_fd *)malloc((maxqueries+2)*sizeof(iopause_fd))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  if ((querystate = (struct QueryState *) malloc(maxqueries*sizeof(struct QueryState))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  byte_zero(querystate, maxqueries*sizeof(struct QueryState));

  if (pipe(pipefd) < 0) {
    strerr_die2sys(111,FATAL,"unable to open pipe");
  }

  if (redirect && !readRedirects()) {
    strerr_die2sys(111,FATAL,"unable to initialize cobweb redirection servers: ");
  }

  dns_transmit_setserverport(cosecport);

  struct taia stamp;
  struct taia deadline;
  for (;;) {
    int i;

    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);

    int numiofds = 0;
    pipeiofd = iofd + numiofds;
    numiofds++;
    pipeiofd->fd = pipefd[0];
    pipeiofd->events = IOPAUSE_READ;
    if (numactive < maxqueries) {
      qryiofd = iofd + numiofds;
      numiofds++;
      qryiofd->fd = qrysockfd;
      qryiofd->events = IOPAUSE_READ;
    }
    else {
      qryiofd = 0;
    }
    for (i=0; i<maxqueries; i++) {
      if (querystate[i].valid && !querystate[i].done) {
	querystate[i].iofd = iofd + numiofds;
	numiofds++;
	dns_transmit_io(&querystate[i].dns_tx, querystate[i].iofd, &deadline);
      }
    }

    iopause(iofd, numiofds, &deadline, &stamp);

    for (i=0; i<maxqueries; i++) {
      if (querystate[i].valid && !querystate[i].done) {
	int retVal = dns_transmit_get(&querystate[i].dns_tx, querystate[i].iofd, &stamp);
	if (retVal != 0) {
	  querystate[i].error = (retVal == -1) ? errno : 0;
	  gettimeofday(&querystate[i].ended, (struct timezone *) 0);
	  querystate[i].done = 1;
	}
      }
    }

    for (i=0; i<maxqueries; i++) {
      if (querystate[i].valid && querystate[i].done) {
	querystate[i].valid = 0;
	numactive--;

	uint8 errorcode = querystate[i].error ? DNS_RCODE_SRVFAIL : 0;
	DNSMessage *resMsg = 0;

	if (!errorcode && !readDataFromPacket(querystate[i].dns_tx.packet, querystate[i].dns_tx.packetlen, &resMsg, 1)) {
	  if (errno == error_nomem) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  errorcode = DNS_RCODE_SRVFAIL;
	}
	
	if (errorcode) {
	  freeDNSMessage(&resMsg);
	  if(!createErrorMessage(&resMsg, errorcode, querystate[i].qryMsg)) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }		
	} 

	((Flags3 *)resMsg->header.flags3)->recurseavail = 1;
	byte_copy(resMsg->header.id, 2, querystate[i].qryMsg->header.id);

	char *resbuf = 0;
	if (!packDNSMessage(resMsg, &resbuf)) {
	  strerr_die2x(111,FATAL,"out of memory");
	}
	int resbuflen = resMsg->length;

	if (sendto(qrysockfd, resbuf, resbuflen, MSG_DONTWAIT, (struct sockaddr *) &querystate[i].sa, querystate[i].sasize) < resbuflen) {
	  strerr_die2sys(111,FATAL,"unable to write to udp socket ");
	}

	uint64 timetaken = (querystate[i].ended.tv_sec - querystate[i].started.tv_sec) * 1000000 + querystate[i].ended.tv_usec - querystate[i].started.tv_usec;
	printf("COBWEB: resolved codons query ");
	printName(querystate[i].qryMsg->qdata);
	printf(" type %d rcode %d length %d time %lu\n", getshort(querystate[i].qryMsg->qdata+querystate[i].qryMsg->length-16), ((Flags3 *)resMsg->header.flags3)->rcode, resMsg->length, timetaken);  
        fflush(stdout);

	free(resbuf);
	free(querystate[i].qryMsg);
	freeDNSMessage(&resMsg);
      }
    }

    if (pipeiofd->revents) {
      read(pipefd[0], pipebuf, sizeof(pipebuf)) > 0;
    }

    while (numactive < maxqueries && qryiofd && qryiofd->revents) {
      for (i=0; querystate[i].valid; i++);

      int nread;
      querystate[i].sasize = sizeof(querystate[i].sa);
      if ((nread = recvfrom(qrysockfd, qrybuf, COBWEB_QRYBUF_LEN, MSG_DONTWAIT, (struct sockaddr *)&querystate[i].sa, &querystate[i].sasize)) < 0) {
	if (errno == EAGAIN) {
	  break;
	}
	strerr_die2sys(111,FATAL,"unable to read from udp socket ");
      }

      DNSQueryMsg *qryMsg = 0;
      uint8 errorcode = 0;
      if (!readDataFromQuery(qrybuf, nread, &qryMsg)) {
	if (errno == error_nomem) {
	  strerr_die2x(111,FATAL,"out of memory");
	}
	errorcode = DNS_RCODE_BADFORM;
      }
      else if (((Flags2 *)qryMsg->header.flags2)->opcode != 0 || byte_diff(qryMsg->qdata+qryMsg->length-14, 2, DNS_C_IN) || byte_equal(qryMsg->qdata+qryMsg->length-16, 2, DNS_T_AXFR)) {
	errorcode = DNS_RCODE_NOTIMPL;
      }

      if (errorcode) {
	DNSMessage *resMsg = 0;
	if (!createErrorMessage(&resMsg, errorcode, qryMsg)) {
	  strerr_die2x(111,FATAL,"out of memory");
	}		 
	((Flags3 *)resMsg->header.flags3)->recurseavail = 1;
	byte_copy(resMsg->header.id, 2, (nread > 1) ? qrybuf : "\0\0");

	char *resbuf = 0;
	if (!packDNSMessage(resMsg, &resbuf)) {
	  strerr_die2x(111,FATAL,"out of memory");
	}
	int resbuflen = resMsg->length;

	if (sendto(qrysockfd, resbuf, resbuflen, MSG_DONTWAIT, (struct sockaddr *) &querystate[i].sa, querystate[i].sasize) < 0) {
	  strerr_die2sys(111,FATAL,"unable to write to udp socket ");
	}

	printf("COBWEB: failed to resolve query rcode %d length %d\n", ((Flags3 *)resMsg->header.flags3)->rcode, resbuflen);  
	fflush(stdout);

	free(resbuf);
	if (qryMsg != 0) {
	  free(qryMsg);
	}
	freeDNSMessage(&resMsg);
      }
      else if ((qryMsg->length-16 >= 26 && strcasecmp(qryMsg->qdata+qryMsg->length-16-26, "\011honeycomb\002cs\007cornell\003edu") == 0) || (qryMsg->length-16 >= 13 && strcasecmp(qryMsg->qdata+qryMsg->length-16-13, "\007cob-web\003org") == 0)) {
	/***
	    MERIDIAN CODE SHOULD GO HERE
	***/

	if (redirect) {
	  readRedirects();
	  int secondary = 0;

	  if ((qryMsg->length-16 >= 13 && strcasecmp(qryMsg->qdata+qryMsg->length-16-13, "\007cob-web\003org") == 0)) {
	    secondary = 1;
	  }

	  DNSMessage *resMsg = 0;
	  unsigned int redirectindex1 = dns_random(secondary ? tempnumredirects : numredirects);
	  unsigned int redirectindex2 = dns_random(secondary ? tempnumredirects : numredirects);
	  if (!secondary && !createRedirectionMessage(&resMsg, qryMsg, redirects[redirectindex1], redirects[redirectindex2])) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }		 
	  if (secondary && !createRedirectionMessage(&resMsg, qryMsg, tempredirects[redirectindex1], tempredirects[redirectindex2])) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }		 
	  ((Flags3 *)resMsg->header.flags3)->recurseavail = 1;
	  byte_copy(resMsg->header.id, 2, (nread > 1) ? qrybuf : "\0\0");
	  
	  char *resbuf = 0;
	  if (!packDNSMessage(resMsg, &resbuf)) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  int resbuflen = resMsg->length;
	  
	  if (sendto(qrysockfd, resbuf, resbuflen, MSG_DONTWAIT, (struct sockaddr *) &querystate[i].sa, querystate[i].sasize) < 0) {
	    strerr_die2sys(111,FATAL,"unable to write to udp socket ");
	  }
	  
	  printf("COBWEB: received query ");
	  printName(qryMsg->qdata);
	  printf(" rcode %d length %d\n", ((Flags3 *)resMsg->header.flags3)->rcode, resbuflen);  
	  fflush(stdout);
	  
	  free(resbuf);
	  freeDNSMessage(&resMsg);
	}
	free(qryMsg);  
      }
      else {
	/* forward other queries to codons secure server 
	   listening on port 53 at 127.0.0.1 */

	querystate[i].valid = 1;
	querystate[i].done = 0;
	querystate[i].qryMsg = qryMsg;
	gettimeofday(&querystate[i].started,(struct timezone *) 0);
	numactive++;

	if (dns_transmit_start(&querystate[i].dns_tx, servers, 1, qryMsg->qdata, qryMsg->qdata+qryMsg->length-16, "\0\0\0\0") < 0) {
	  querystate[i].error = errno;
	  gettimeofday(&querystate[i].ended, (struct timezone *) 0);
	  querystate[i].done = 1;
	}

	if (write(pipefd[1], "s", 1) <= 0) {
	  strerr_die2sys(111,FATAL,"error in write pipe ");
	}
      }
    }
  }

  exit(0);
}
