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

#define SURVEY_MAX_QUERIES 5000
#define SURVEY_MAX_ACTIVE 1000
#define SURVEY_PING_PERIOD 10 * 60

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
  char ip[4];
  DNSMessage *oldres;
  char *oldpkt;
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
      dest[dp++] = src[sp++];
    }
    len = src[sp++];
    dest[dp++] = '.';
  }
  dest[dp] = 0;
}

int matchanswers(const DNSMessage *newmsg, const DNSMessage *oldmsg) {
  if (newmsg == 0 || oldmsg == 0) {
    return 0; // sanity check
  }

  Flags3 *oldflags3 = (Flags3 *)&oldmsg->header.flags3;
  Flags3 *newflags3 = (Flags3 *)&newmsg->header.flags3;

  if (newflags3->rcode != oldflags3->rcode) {
    return 0; // rcodes don't match
  }

  if (newmsg->header.ancount != oldmsg->header.ancount) {
    return 0; // numbers of records don't match
  }

  int i,j;

  for (i=0; i<newmsg->header.ancount; i++) {
    if (newmsg->rrset[i] == 0 || (byte_equal(newmsg->rrset[i]->type, 2, DNS_T_SIG) && byte_equal(newmsg->rrset[i]->rdata+18, CODONS_NAMELEN, CODONS_NAME))) {
      continue;
    }
    
    for (j=0; j<oldmsg->header.ancount; j++) {
      if (matchResourceRecord(newmsg->rrset[i], oldmsg->rrset[j])) {
	break;
      }
    }
    
    if (j == oldmsg->header.ancount) {
      return 0; //no match for record
    }      
  }
  
  return 1; // complete match
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

unsigned long getTimeSecs() {
  struct timeval tv;
  gettimeofday(&tv,0);
  if (tv.tv_usec >= 500000) {    
    tv.tv_sec++;
  }
  return tv.tv_sec;
}

int main(int argc,char **argv)
{
  char seed[128];
  dns_random_init(seed);

  char nservers[64];
  byte_zero(nservers, 64);
  
  iopause_fd *iofd = 0;  

  struct QueryState *query = 0; 
  int maxqueries = SURVEY_MAX_QUERIES;
  int maxactive = SURVEY_MAX_ACTIVE;
  int numqueries = 0;
  int numactive = 0;
  int numdone = 0;

  if ((iofd = (iopause_fd *)malloc((maxactive)*sizeof(iopause_fd))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  if ((query = (struct QueryState *) malloc(maxqueries*sizeof(struct QueryState))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  byte_zero(query, maxqueries*sizeof(struct QueryState));

  int i,j;

  for (i=0; i<maxqueries; i++) {
    int good;
    char addr[256];
    if (scanf("%s%s%d%s", query[i].qname, query[i].nsname, &good, addr) <= 0) {
      break;
    }

    if (!good) {
      continue;
    }

    dottoip(query[i].ip, addr);
    numqueries++;
  }

  unsigned long nextpingtime = getTimeSecs();
  while(1) {
    unsigned long curtime = getTimeSecs();
    
    if (nextpingtime > curtime) {
      sleep(nextpingtime - curtime);
      curtime = getTimeSecs();
    }
    
    char filename[256];
    sprintf(filename, "nsstatus/%lu.txt", nextpingtime);
    FILE *fpnsstts = fopen(filename, "w");
    if (fpnsstts == 0) {
      strerr_die2sys(111,FATAL,"unable to open nstatus.txt: ");    
    }
    
    nextpingtime += SURVEY_PING_PERIOD;    

    numactive = 0;
    for (i=0; i<numqueries; i++) {
      query[i].done = 0;

      if (i < maxactive) {
	byte_copy(nservers, 4, query[i].ip);
	byte_copy(nservers+4, 4, query[i].ip);
	char *tempname = 0;
	if (!dns_domain_fromdot(&tempname, query[i].qname,  strlen(query[i].qname))) {
	  strerr_die2sys(111,FATAL,"error in dns_domain_fromdot ");
	}
	if (dns_transmit_start(&query[i].dns_tx, nservers, 0, tempname, DNS_T_A, "\0\0\0\0") < 0) {
	  if (errno == error_nomem) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  else {
	    strerr_die2sys(111,FATAL,"error in dns_transmit_start ");
	  }
	}
	alloc_free(tempname);
	query[i].valid = 1;
	numactive++;
      }
    }
    numdone = 0;

    struct taia stamp;
    struct taia deadline;
    for (;numdone < numqueries;) {
      taia_now(&stamp);
      taia_uint(&deadline, 120);
      taia_add(&deadline, &deadline, &stamp);
      
      int numiofds = 0;
      for (i=0; i<numqueries; i++) {
	if (query[i].valid) {
	  query[i].iofd = iofd + numiofds;
	  numiofds++;
	  dns_transmit_io(&query[i].dns_tx, query[i].iofd, &deadline);
	}
      }
      
      iopause(iofd, numiofds, &deadline, &stamp);
      
      for (i=0; i<numqueries; i++) {
	if (query[i].valid) {
	  int retVal = dns_transmit_get(&query[i].dns_tx, query[i].iofd, &stamp);
	  if (retVal != 0) {
	    query[i].error = (retVal == -1) ? errno : 0;
	    query[i].done = 1;
	    numdone++;
	  }
	}
      }
      
      for (i=0; i<numqueries; i++) {
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
	    int match = matchanswers(resMsg, query[i].oldres);
	    fprintf(fpnsstts, "%s\t%s\t1\t%d\t", query[i].nsname, query[i].qname, match);
	    freeDNSMessage(&query[i].oldres);
	    alloc_free(query[i].oldpkt);

	    query[i].oldres = resMsg;
	    query[i].oldpkt = query[i].dns_tx.packet;
	    query[i].dns_tx.packet = 0;

            orderResourceRecords(resMsg->rrset, resMsg->header.ancount, 0);

            for (j=0; j<resMsg->header.ancount; j++) {
              if (strcasecmp(resMsg->rrset[j]->oname, resMsg->qdata->qname) == 0) {
                if (byte_equal(resMsg->rrset[j]->type, 2, DNS_T_A) && resMsg->rrset[j]->rdatalen == 4) {
                  if (j == 0) {
                    fprintf(fpnsstts, "A ");
                  }
                  fprintf(fpnsstts, "%d.%d.%d.%d ", (unsigned char)resMsg->rrset[j]->rdata[0], (unsigned char)resMsg->rrset[j]->rdata[1], (unsigned char)resMsg->rrset[j]->rdata[2], (unsigned char)resMsg->rrset[j]->rdata[3]);
                }
                else if (byte_equal(resMsg->rrset[j]->type, 2, DNS_T_CNAME) && resMsg->rrset[j]->rdatalen < 256) {
                  if (j == 0) {
                    fprintf(fpnsstts, "CName ");
                  }
                  char cname[256];
                  nametodot(cname, resMsg->rrset[j]->rdata);
                  fprintf(fpnsstts, "%s ", cname);
                }
              }
            }
            if (resMsg->header.ancount == 0) {
              fprintf(fpnsstts, "NXD\n");
            }
            else {
              fprintf(fpnsstts, "\n");
            }
	  }
	  else {
	    fprintf(fpnsstts, "%s\t%s\t0\t1\tERR\n", query[i].nsname, query[i].qname);
	  }
	}
      }
      
      for (i=0; i<numqueries && numactive < maxactive; i++) {
	if (!query[i].valid && !query[i].done) {
	  byte_copy(nservers, 4, query[i].ip);
	  char *tempname = 0;
	  if (!dns_domain_fromdot(&tempname, query[i].qname,  strlen(query[i].qname))) {
	    strerr_die2sys(111,FATAL,"error in dns_domain_fromdot ");
	  }
	  if (dns_transmit_start(&query[i].dns_tx, nservers, 0, tempname, DNS_T_A, "\0\0\0\0") < 0) {
	    if (errno == error_nomem) {
	      strerr_die2x(111,FATAL,"out of memory");
	    }
	    else {
	      strerr_die2sys(111,FATAL,"error in dns_transmit_start ");
	    }
	  }
	  alloc_free(tempname);
	  query[i].valid = 1;
	  numactive++;
	}
      }
    }
    fclose(fpnsstts);
  }

  exit(0);
}


