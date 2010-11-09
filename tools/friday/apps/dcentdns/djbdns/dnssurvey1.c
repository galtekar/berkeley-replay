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
#define SURVEY_MAX_NS 15
#define SURVEY_MAX_DOMS 5

#define FATAL "SURVEY: fatal: "

static stralloc out;

struct QueryState {
  struct dns_transmit dns_tx;
  iopause_fd *iofd;
  int done;
  int valid;
  int error;
  char qname[256];
  char nslist[SURVEY_MAX_DOMS][SURVEY_MAX_NS][256];
  int numnss[SURVEY_MAX_DOMS];
  int curdom;
  int numdoms;
};

int getnumdoms(char qname[256]) {
  int numdots = 0;
  int pos;
  for (pos = strlen(qname)-1; pos >= 0; pos--) {
    if (qname[pos] == '.') {
      numdots++;
    }
  }

  return numdots;
}

int getdotpos(char qname[256], int i) {
  int numdots = 0;
  int pos;
  for (pos = strlen(qname); pos >= 0 && numdots < i; pos--) {
    if (qname[pos] == '.') {
      numdots++;
    }
  }

  return (pos == 0) ? pos : (pos+1);
}

void dns_domain_todot(char *d, const char *s)
{
  char ch;

  if (!*s) {
    *d++ = '.';
  }

  while(ch = *s++) {
    while (ch--) {
      if (*s++ != 0) {
        --s; 
        *d++ = *s++;
      }
    }
    *d++ = '.';	
  }
  *d++ = 0;
}

FILE *fpbtlnck = 0;
FILE *fpnslst = 0;

void printResults(const struct QueryState *qs) {
  int i;
  int min = 1000;
  int minlevel = -1;

  for (i=0; i<qs->numdoms; i++) {
    if (qs->numnss[i] < min) {
      min =  qs->numnss[i]; 
      minlevel = i;
    }
  }
  fprintf(fpbtlnck, "%s\t%d\t%d\t%d\n", qs->qname, min, minlevel, qs->numdoms);
  fflush(fpbtlnck);

  for (i=0; qs->curdom >= 0 && i<qs->numnss[qs->curdom]; i++) {
      fprintf(fpnslst, "%s\t%s\n", qs->qname, qs->nslist[qs->curdom][i]);
  }
  fflush(fpnslst);
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

  int forward = 0;
  int opt;
  while ((opt = getopt(argc, argv,"f")) != opteof) {
    switch(opt) {
      case 'f':
	forward = 1;
	break;
      default:
	strerr_die1x(111,"SURVEY: usage: dnssurvey<n> [-f forward]");
    }
  }

  char servers[64];
  byte_zero(servers, 64);
  if (forward) {
    if (dns_resolvconfip(servers) == -1) {
      strerr_die2sys(111,FATAL,"unable to read /etc/resolv.conf: ");
    }
  }
  else {
    byte_copy(servers, 4, "\177\0\0\1");
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

  fpbtlnck = fopen("bottlenecks.txt", "w");
  if (fpbtlnck == 0) {
    strerr_die2sys(111,FATAL,"unable to open bottlenecks.txt: ");
  }
  fpnslst = fopen("nslist.txt", "w");
  if (fpnslst == 0) {
    strerr_die2sys(111,FATAL,"unable to open nslist.txt: ");
  }

  struct taia stamp;
  struct taia deadline;
  for (;!done || numactive > 0;) {
    int i;

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
	  int j;
	  for (j=0; j<resMsg->header.ancount; j++) {
	    if (byte_equal(resMsg->rrset[j]->type, 2, DNS_T_NS) && strcasecmp(resMsg->rrset[j]->oname, resMsg->qdata->qname) == 0) {
	      dns_domain_todot(query[i].nslist[query[i].curdom][query[i].numnss[query[i].curdom]++], resMsg->rrset[j]->rdata);

	      if (query[i].numnss[query[i].curdom] > SURVEY_MAX_NS) {
		fprintf(stderr, "SURVEY: %s has more than %d nameservers at level %d\n", query[i].qname, SURVEY_MAX_NS, query[i].curdom); 
		//exit(1);
		query[i].numnss[query[i].curdom]--;
	      }
	    }
	  }
	  freeDNSMessage(&resMsg);
	} 

	int pos = 0;
	if (errorcode || (pos = getdotpos(query[i].qname, query[i].curdom+2)) == 0) {
	  printResults(&query[i]);
	  continue;
	}
	query[i].curdom++;
	
	char *tempname = 0;
	if (!dns_domain_fromdot(&tempname, query[i].qname+pos+1,  strlen(query[i].qname)-pos-1)) {
	  strerr_die2sys(111,FATAL,"error in dns_domain_fromdot ");
	}
	if (dns_transmit_start(&query[i].dns_tx, servers, 1, tempname, DNS_T_NS, "\0\0\0\0") < 0) {
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

    if (!done && numactive < maxqueries && qryiofd->revents) {
      for (i=0; i<maxqueries && query[i].valid; i++) {
      }

      if (scanf("%255[^\n]\n", query[i].qname) <= 0) {
	done = 1;
	printf("Read %d urls\n", nread);
	fflush(stdout);
	continue;
      }

      if (!(++nread%1000)) {
	printf("Read %d urls\n", nread);
	fflush(stdout);
      }

      query[i].curdom = -1;
      byte_zero(query[i].numnss, sizeof(query[i].numnss));
      query[i].numdoms = getnumdoms(query[i].qname);

      if (query[i].numdoms > SURVEY_MAX_DOMS) {
	printf("High numdoms %s\n", query[i].qname);
        printResults(&query[i]);
	continue;
      }

      int pos = 0;
      if ((pos = getdotpos(query[i].qname, query[i].curdom+2)) == 0) {
        printResults(&query[i]);
        continue;
      }
      query[i].curdom++;

      char *tempname = 0;
      if (!dns_domain_fromdot(&tempname, query[i].qname+pos+1,  strlen(query[i].qname)-pos-1)) {
	strerr_die2sys(111,FATAL,"error in dns_domain_fromdot ");
      }

      if (dns_transmit_start(&query[i].dns_tx, servers, 1, tempname, DNS_T_NS, "\0\0\0\0") < 0) {
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

  fclose(fpbtlnck);
  fclose(fpnslst);

  exit(0);
}


