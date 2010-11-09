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

#define SURVEY_MAX_QUERIES 100

#define FATAL "SURVEY: fatal: "

static stralloc out;

struct QueryState {
  struct query q;
  char *response;
  int responselen;	
  struct dns_transmit dns_tx;
  iopause_fd *iofd;
  int done;
  int valid;
  int error;
  char nsname[256];
};

void dottoip(char ip[4], const char *src) {
  int temp[4];
  sscanf(src, "%d.%d.%d.%d", &temp[0], &temp[1], &temp[2], &temp[3]);
  ip[0] = (unsigned char)temp[0];
  ip[1] = (unsigned char)temp[1];
  ip[2] = (unsigned char)temp[2];
  ip[3] = (unsigned char)temp[3];
}

void nametodot(char *dest, const char *src) {
  int sp = 0;
  int len = src[sp++];
  int dp = 0;
  int i;
  while(len > 0) {
    for (i=0; i<len; i++) {
      if (src[sp] != 0) {
        dest[dp++] = src[sp++];
      }
      else {
        sp++;
      }
    }
    len = src[sp++];
    dest[dp++] = '.';
  }
  dest[dp] = 0;
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

int main(int argc,char **argv)
{
  char seed[128];
  dns_random_init(seed);

  char servers[64];
  byte_zero(servers, 64);
  byte_copy(servers, 4, "\177\0\0\1");

  if (dns_resolvconfip(servers) == -1) {
    strerr_die2sys(111,FATAL,"unable to read /etc/resolv.conf: ");
  }
  if (!roots_init()) {
    strerr_die2sys(111,FATAL,"unable to read root servers: ");
  }
  if (!cache_init(1000000)) {
    strerr_die2sys(111,FATAL,"unable to initialize resolver cache: ");
  }

  iopause_fd *iofd = 0;  

  struct QueryState *query = 0; 
  int maxqueries = SURVEY_MAX_QUERIES;
  int numactive = 0;

  iopause_fd *qryiofd;
  int nread = 0;
  int done = 0;
  
  if ((iofd = (iopause_fd *)malloc((maxqueries+1)*sizeof(iopause_fd))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  if ((query = (struct QueryState *) malloc(maxqueries*sizeof(struct QueryState))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  byte_zero(query, maxqueries*sizeof(struct QueryState));

  FILE *fprpnss = stdout;

  struct taia stamp;
  struct taia deadline;
  int i,j;
  for (;!done || numactive > 0;) {
    taia_now(&stamp);
    taia_uint(&deadline, 120);
    taia_add(&deadline, &deadline, &stamp);

    qryiofd = iofd;
    qryiofd->fd = 0;
    qryiofd->events = IOPAUSE_READ;
    int numiofds = 1;
    for (i=0; i<maxqueries; i++) {
      if (query[i].valid && !query[i].done) {
	query[i].iofd = iofd + numiofds;
	numiofds++;
	//dns_transmit_io(&query[i].dns_tx, query[i].iofd, &deadline);
	query_io(&query[i].q, query[i].iofd, &deadline);
      }
    }

    iopause(iofd, numiofds, &deadline, &stamp);

    for (i=0; i<maxqueries; i++) {
      if (query[i].valid && !query[i].done) {
	//int retVal = dns_transmit_get(&query[i].dns_tx, query[i].iofd, &stamp);
	int retVal = query_get(&query[i].q, query[i].iofd, &stamp);
	if (retVal != 0) {
	  query[i].error = (retVal == -1) ? errno : 0;
	  query[i].done = 1;
	  if (retVal == 1) {
            //query[i].response = query[i].dns_tx.packet;
            //query[i].responselen = query[i].dns_tx.packetlen;
            if ((query[i].response = alloc(response_len)) == 0) {
              strerr_die2x(111,FATAL,"out of memory");
            }
            byte_copy(query[i].response, response_len, response);
            query[i].responselen = response_len;
          }
	}
      }
    }

    for (i=0; i<maxqueries; i++) {
      if (query[i].valid && query[i].done) {
	query[i].valid = 0;
	numactive--;

	uint8 errorcode = query[i].error ? DNS_RCODE_SRVFAIL : 0;

	DNSMessage *resMsg = 0;
	if (!errorcode && !readDataFromPacket(query[i].response, query[i].responselen, &resMsg, 0)) {
	  if (errno == error_nomem) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  errorcode = DNS_RCODE_SRVFAIL;
	}
	
	if (!errorcode) {
	  fprintf(fprpnss, "%s\t", query[i].nsname);
	  orderResourceRecords(resMsg->rrset, resMsg->header.ancount, 0);

	  for (j=0; j<resMsg->header.ancount; j++) {
	      if (byte_equal(resMsg->rrset[j]->type, 2, DNS_T_A) && resMsg->rrset[j]->rdatalen == 4) {
		if (j == 0) {
		  fprintf(fprpnss, "A ");
		}
		fprintf(fprpnss, "%d.%d.%d.%d ", (unsigned char)resMsg->rrset[j]->rdata[0], (unsigned char)resMsg->rrset[j]->rdata[1], (unsigned char)resMsg->rrset[j]->rdata[2], (unsigned char)resMsg->rrset[j]->rdata[3]);
	      }
	      else if (byte_equal(resMsg->rrset[j]->type, 2, DNS_T_CNAME) && resMsg->rrset[j]->rdatalen < 256) {
		if (j == 0) {
		  fprintf(fprpnss, "CName ");
		}
		char cname[256];
		nametodot(cname, resMsg->rrset[j]->rdata);
		fprintf(fprpnss, "%s ", cname);
	      }
	  }
	  if (resMsg->header.ancount == 0) {
	    fprintf(fprpnss, "NXD\n");
	  }
	  else {
	    fprintf(fprpnss, "\n");
	  }
	  if (query[i].response != 0) {
	    free(query[i].response);
            query[i].response = 0;
          }
	  freeDNSMessage(&resMsg);
	}
	else {
	  fprintf(fprpnss, "%s\tERR\n", query[i].nsname);
	}
	fflush(fprpnss);
      }
    }

    while (!done && numactive < maxqueries && qryiofd->revents) {
	for (i=0; i<maxqueries && query[i].valid; i++) {
	}
	
	if (scanf("%255[^\n]\n", query[i].nsname) <= 0) {
	  done = 1;
	  //printf("Read %d urls\n", nread);
	  fflush(stdout);
	  break;
	}

	if (!(++nread%1000)) {
	  printf("Read %d urls\n", nread);
	  fflush(stdout);
	}

	char *tempname = 0;
	if (!dns_domain_fromdot(&tempname, query[i].nsname,  strlen(query[i].nsname))) {
	  strerr_die2sys(111,FATAL,"error in dns_domain_fromdot ");
	}

	query[i].valid = 1;
        query[i].done = 0;
	numactive++;
        int retVal;	
	//if (dns_transmit_start(&query[i].dns_tx, servers, 0, tempname, DNS_T_A, "\0\0\0\0") < 0) {
	if (retVal = query_start(&query[i].q, tempname, DNS_T_A, DNS_C_IN, "\0\0\0\0") != 0) {          
	  query[i].error = (retVal == -1) ? errno : 0;          
          query[i].done = 1;
          if (retVal == 1) {
            if ((query[i].response = alloc(response_len)) == 0) {
              strerr_die2x(111,FATAL,"out of memory");
            }
            byte_copy(query[i].response, response_len, response);
            query[i].responselen = response_len;
          }
          else {
	    if (errno == error_nomem) {
	      strerr_die2x(111,FATAL,"out of memory");
	    }
	    else {
	      strerr_die2sys(111,FATAL,"error in dns_transmit_start ");
	    }
          }
	}
	alloc_free(tempname);
    }
  }

  fclose(fprpnss);

  exit(0);
}


