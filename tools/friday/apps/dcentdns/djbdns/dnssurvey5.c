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

  FILE *fpversion = fopen("version.txt", "w");
  if (fpversion == 0) {
    strerr_die2sys(111,FATAL,"unable to open version.txt: ");    
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
	  errorcode = ((Flags3 *)&resMsg->header.flags3)->rcode;
	  fprintf(fpversion, "%s\t%d\t", query[i].nsname, errorcode);

	  for (j=0; j<resMsg->header.ancount; j++) {
	    if (byte_equal(resMsg->rrset[j]->type, 2, DNS_T_TXT) && byte_equal(resMsg->rrset[j]->class, 2, DNS_C_CH) && strcasecmp(resMsg->rrset[j]->oname, "\7version\4bind\0") == 0) {
	      int k;
	      int pos = 0;
	      while(pos < resMsg->rrset[j]->rdatalen) {
		if (pos != 0) {
		  fprintf(fpversion, " ");
		}
		for (k=0; k<resMsg->rrset[j]->rdata[pos]; k++) {
		  char ch = resMsg->rrset[j]->rdata[pos+1+k];
		  if (ch > 31 && ch < 127 && ch != '\\') {
		    fprintf(fpversion, "%c", ch);
		  }
		  else {
		    fprintf(fpversion, "\\%o", (unsigned char)ch);
		  }
		}
		pos += ((unsigned char)resMsg->rrset[j]->rdata[pos])+1;
	      }
	    }
	  }
	  fprintf(fpversion, "\n");
	  freeDNSMessage(&resMsg);
	}
	else {
	  fprintf(fpversion, "%s\tERR\n", query[i].nsname);
	}
	fflush(fpversion);
      }
    }

    while (!done && numactive < maxqueries && qryiofd->revents) {
	for (i=0; i<maxqueries && query[i].valid; i++) {
	}
	
	char addr[256];
	if (scanf("%255[^\t]\t%s\n", query[i].nsname, addr) <= 0) {
	  done = 1;
	  printf("Read %d urls\n", nread);
	  fflush(stdout);
	  break;
	}

	if (!(++nread%1000)) {
	  printf("Read %d urls\n", nread);
	  fflush(stdout);
	}

	dottoip(servers, addr);

	if (dns_transmit_start_chaos_txt(&query[i].dns_tx, servers, "\007version\004bind\000", "\0\0\0\0") < 0) {
	  if (errno == error_nomem) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  else {
	    strerr_die2sys(111,FATAL,"error in dns_transmit_start ");
	  }
	}

	query[i].done = 0;
	query[i].valid = 1;
	numactive++;
    }
  }

  fclose(fpversion);

  exit(0);
}


