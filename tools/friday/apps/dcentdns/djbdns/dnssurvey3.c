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

#define SURVEY_MAX_QUERIES 100

#define FATAL "SURVEY: fatal: "

static stralloc out;

struct QueryState {
  struct dns_transmit dns_tx;
  iopause_fd *iofd;
  int done;
  int valid;
  int error;
  char qname[256];
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

  FILE *fprpnss = fopen("responses.txt", "w");
  if (fprpnss == 0) {
    strerr_die2sys(111,FATAL,"unable to open nsstatus.txt: ");    
  }

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
      if (query[i].valid) {
	query[i].iofd = iofd + numiofds;
	numiofds++;
	dns_transmit_io(&query[i].dns_tx, query[i].iofd, &deadline);
      }
    }

    iopause(iofd, numiofds, &deadline, &stamp);

    for (i=0; i<maxqueries; i++) {
      if (query[i].valid) {
	int retVal = dns_transmit_get(&query[i].dns_tx, query[i].iofd, &stamp);
	if (retVal != 0) {
	  query[i].error = (retVal == -1) ? errno : 0;
	  query[i].done = 1;
	}
      }
    }

    for (i=0; i<maxqueries; i++) {
      if (query[i].valid && query[i].done) {
	query[i].valid = 0;
	numactive--;

	uint8 errorcode = query[i].error ? DNS_RCODE_SRVFAIL : 0;

	DNSMessage *resMsg = 0;
	if (!errorcode && !readDataFromPacket(query[i].dns_tx.packet, query[i].dns_tx.packetlen, &resMsg, 0)) {
	  if (errno == error_nomem) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  errorcode = DNS_RCODE_SRVFAIL;
	}
	
	if (!errorcode) {
	  fprintf(fprpnss, "%s\t%s\t", query[i].qname, query[i].nsname);
	  orderResourceRecords(resMsg->rrset, resMsg->header.ancount, 0);

	  for (j=0; j<resMsg->header.ancount; j++) {
	    if (strcasecmp(resMsg->rrset[j]->oname, resMsg->qdata->qname) == 0) {
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
	  }
	  if (resMsg->header.ancount == 0) {
	    fprintf(fprpnss, "NXD\n");
	  }
	  else {
	    fprintf(fprpnss, "\n");
	  }
	  freeDNSMessage(&resMsg);
	}
	else {
	  fprintf(fprpnss, "%s\t%s\tERR\n", query[i].qname, query[i].nsname);
	}
	fflush(fprpnss);
      }
    }

    while (!done && numactive < maxqueries && qryiofd->revents) {
	for (i=0; i<maxqueries && query[i].valid; i++) {
	}
	
	int good;
	char addr[256];
	if (scanf("%255[^\t]\t%255[^\t]\t%d\t%s\n", query[i].qname, query[i].nsname, &good, addr) <= 0) {
	  done = 1;
	  printf("Read %d urls\n", nread);
	  fflush(stdout);
	  break;
	}

	if (!(++nread%1000)) {
	  printf("Read %d urls\n", nread);
	  fflush(stdout);
	}

	if (!good) {
	  continue;
	}

	dottoip(servers, addr);

	if (byte_equal(servers, 4, "\0\0\0\0")) {
	  fprintf(fprpnss, "%s\t%s\tERR\n", query[i].qname, query[i].nsname);
	  continue;
        }

	char *tempname = 0;
	if (!dns_domain_fromdot(&tempname, query[i].qname,  strlen(query[i].qname))) {
	  strerr_die2sys(111,FATAL,"error in dns_domain_fromdot ");
	}
	
	if (dns_transmit_start(&query[i].dns_tx, servers, 0, tempname, DNS_T_A, "\0\0\0\0") < 0) {
	  if (errno == error_nomem) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  else {
	    strerr_die2sys(111,FATAL,"error in dns_transmit_start ");
	  }
	}
	alloc_free(tempname);

	query[i].done = 0;
	query[i].valid = 1;
	numactive++;
    }
  }

  fclose(fprpnss);

  exit(0);
}


