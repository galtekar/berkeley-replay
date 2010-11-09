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

#define SURVEY_MAX_QUERIES 600
#define SURVEY_MAX_ACTIVE 200

#define FATAL "MONITOR: fatal: "

static stralloc out;

static char header[] = "<html>\n<head><title>CoDoNS: Current Avaliability and Performance</title></head>\n\n<body>\n<table align=\"center\" width=\"1040\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t<tr>\n\t\t<td align=\"center\"><img width=\"300\" alt=\"beehive-logo\" src=\"beehive-logo.gif\"></td>\n\t\t<td align=\"center\"><img width=\"300\" alt=\"codons-logo\" src=\"codons-logo.gif\"></td>\n\t</tr>\n</table>\n\n<table align=\"center\" width=\"1040\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t<tr>\n\t\t<td align=\"center\" width=\"1040\"><h1><b><font face=\"Garamond\" color=\"#000000\">CoDoNS: Avaliability and Performance</font></b></h1></td>\n\t</tr>\n</table>\n\n<hr width=\"1040\">\n\n<table align=\"center\" width=\"1040\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t<tr>\n\t\t<td align=\"center\" width=\"140\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>IP Address</b></font></td>\n\t\t<td align=\"center\" width=\"300\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Location</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Queries Served in Last 1 Hr</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Median Delay (ms)</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Average Delay (ms)</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Hit Rate (%)</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Bindings Cached</b></font></td>\n\t</tr>\n</table>\n\n<hr width=\"1040\">\n\n<table align=\"center\" width=\"1040\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n";

static char headerwithport[] = "<html>\n<head><title>CoDoNS: Current Avaliability and Performance</title></head>\n\n<body>\n<table align=\"center\" width=\"1040\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t<tr>\n\t\t<td align=\"center\"><img width=\"300\" alt=\"beehive-logo\" src=\"beehive-logo.gif\"></td>\n\t\t<td align=\"center\"><img width=\"300\" alt=\"codons-logo\" src=\"codons-logo.gif\"></td>\n\t</tr>\n</table>\n\n<table align=\"center\" width=\"1040\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t<tr>\n\t\t<td align=\"center\" width=\"1040\"><h1><b><font face=\"Garamond\" color=\"#000000\">CoDoNS: Avaliability and Performance</font></b></h1></td>\n\t</tr>\n</table>\n\n<hr width=\"1040\">\n\n<table align=\"center\" width=\"1040\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t<tr>\n\t\t<td align=\"center\" width=\"140\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>IP Address:Port</b></font></td>\n\t\t<td align=\"center\" width=\"300\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Location</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Queries Served in Last 1 Hr</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Median Delay (ms)</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Average Delay (ms)</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Hit Rate (%)</b></font></td>\n\t\t<td align=\"center\" width=\"120\"><font face=\"Palatino Linotype\" color=\"#800000\"><b>Bindings Cached</b></font></td>\n\t</tr>\n</table>\n\n<hr width=\"1040\">\n\n<table align=\"center\" width=\"1040\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n";

static char footer[] = "<p><img width=\"200\" alt=\"\" src=\"email.gif\"></p>\n<p><h6><a href=\"http://www.cs.cornell.edu/people/egs/beehive\">Beehive Main Page</a><br>\n<a href=\"http://www.cs.cornell.edu/people/egs/beehive/codons.php\">CoDoNS Main Page</a><br>\n<a href=\"http://www.cs.cornell.edu/\">Computer Science Department</a><br>\n<a href=\"http://www.cornell.edu/\">Cornell University</a></h6></p>\n</body>\n";

struct QueryState {
  struct dns_transmit dns_tx;
  iopause_fd *iofd;
  int done;
  int valid;
  int error;
  char name[256];
  char addr[256];
  int status;
  char servers[64];
  double numQueries;
  double hitRate;
  double avgDelay;
  double medDelay;
  double numObjects;
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
  unsigned short port = 53;
  if (argc < 2) {
    strerr_die1x(111,"usage: monitorcodons <output file> <date> [-p port]");
  }	
  int opt;
  while ((opt = getopt(argc-2,argv+2,"p:h")) != opteof) {
    switch(opt) {
      case 'p':
        sscanf(optarg, "%hu", &port);
        break;
      case 'h':
      default:
        strerr_die1x(111,"usage: monitorcodons <output file> <date> [-p port]");
    }
  }

  dns_transmit_setserverport(port);

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
    if (scanf("%s%s", query[i].name, query[i].addr) <= 0) {
      break;
    }
    dottoip(query[i].servers, query[i].addr);
    numqueries++;
  }

  numactive = 0;
  for (i=0; i<numqueries; i++) {
    query[i].done = 0;

    if (i < maxactive) {
      if (dns_transmit_start_chaos_txt(&query[i].dns_tx, query[i].servers, "\005stats\006codons\000", "\0\0\0\0") < 0) {
	if (errno == error_nomem) {
	  strerr_die2x(111,FATAL,"out of memory");
	}
	else {
	  strerr_die2sys(111,FATAL,"error in dns_transmit_start ");
	}
      }

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
	  errorcode = ((Flags3 *)&resMsg->header.flags3)->rcode;
	  //errorcode = ((Flags3 *)&query[i].dns_tx.packet[3])->rcode;
	  query[i].status = (errorcode == 0);

	  query[i].numQueries = 0;
	  query[i].avgDelay = 0;
	  query[i].medDelay = 0;
	  query[i].hitRate = 0;
	  query[i].numObjects = -1;

	  int numHits = 0;
	  for (j=0; j<resMsg->header.ancount; j++) {
	    if (byte_equal(resMsg->rrset[j]->type, 2, DNS_T_TXT) && byte_equal(resMsg->rrset[j]->class, 2, DNS_C_CH) && strcasecmp(resMsg->rrset[j]->oname, "\005stats\006codons\000") == 0) {
	      char *statsStr = resMsg->rrset[j]->rdata;
	      int statslen = resMsg->rrset[j]->rdatalen;
	      int pos;
	 
	      for (pos=0; pos<statslen;) {
		int namelen = statsStr[pos];
		if (pos+1+namelen>=statslen) {
		  break;
		}
		int valuelen = statsStr[pos+1+namelen];
		if (pos+1+namelen+1+valuelen > statslen) {
		  break;
		}

		char *name = statsStr+pos+1;
		char *valueStr = statsStr+pos+1+namelen+1;
		double value = 0;
		char formatStr[10];
		snprintf(formatStr, 10, "%%%dlf", valuelen);
		if (sscanf(valueStr, formatStr, &value) != 1) {
		  break;
		}

		pos += 1+namelen+1+valuelen;

		if (namelen == strlen("NumQueries") && byte_equal(name, namelen, "NumQueries")) {
		  query[i].numQueries = (value > 0) ? value : 0;
		}
		else if (namelen == strlen("NumHits") && byte_equal(name, namelen, "NumHits")) {
		  numHits = (value > 0) ? value : 0;
		}
		else if (namelen == strlen("AvgDelay") && byte_equal(name, namelen, "AvgDelay")) {
		  query[i].avgDelay = (value > 0) ? value : 0;
		}
		else if (namelen == strlen("MedDelay") && byte_equal(name, namelen, "MedDelay")) {
		  query[i].medDelay = (value > 0) ? value : 0;
		}
		else if (namelen == strlen("StorageOverhead#") && byte_equal(name, namelen, "StorageOverhead#")) {
		  query[i].numObjects = (value > 0) ? value : 0;
		}
	      }
	    }
	  }

	  query[i].hitRate = (query[i].numQueries == 0) ? 0 : 100*numHits/query[i].numQueries;
	    
	  //printf("MonitorCoDoNS: Debug: name %s numQueries %f avgDelay %f medDelay %f hitRate %f numObjects %f\n", query[i].name, query[i].numQueries, query[i].avgDelay, query[i].medDelay, query[i].hitRate, query[i].numObjects);

	  freeDNSMessage(&resMsg);
	}
	else {
	  query[i].status = 0;
	}
      }
    }
    
    for (i=0; i<numqueries && numactive < maxactive; i++) {
      if (!query[i].valid && !query[i].done) {
	if (dns_transmit_start_chaos_txt(&query[i].dns_tx, query[i].servers, "\005stats\006codons\000", "\0\0\0\0") < 0) {
	  if (errno == error_nomem) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  else {
	    strerr_die2sys(111,FATAL,"error in dns_transmit_start ");
	  }
	}

	query[i].valid = 1;
	numactive++;
      }
    }
  }

  struct QueryState **sortedquery;
  if ((sortedquery = (struct QueryState **) malloc(numqueries*sizeof(struct QueryState *))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  byte_zero(sortedquery, numqueries*sizeof(struct QueryState *));

  for (i=0; i<numqueries; i++) {
    sortedquery[i] = &query[i];
  }
  for (i=0; i<numqueries; i++) {
    for (j=1; j<numqueries; j++) {
      if (sortedquery[j-1]->medDelay > sortedquery[j]->medDelay) {
	struct QueryState *temp = sortedquery[j-1];
	sortedquery[j-1] = sortedquery[j];
	sortedquery[j] = temp;
      }
    }
  }
  
  FILE *fpstts = fopen(argv[1], "w");
  if (fpstts == 0) {
    strerr_die2sys(111,FATAL,"unable to open target file");
  }

  if (port == 53) {
    fprintf(fpstts, "%s", header);
  }
  else {
    fprintf(fpstts, "%s", headerwithport);
  }
  for (i=0; i<numqueries; i++) {
    if (sortedquery[i]->status) {
      int j;

      printf("%s\t%s\n", sortedquery[i]->name, sortedquery[i]->addr);

      fprintf(fpstts, "\t<tr>\n");
      if (port == 53) {	
        fprintf(fpstts, "\t\t<td align=\"center\" width=\"140\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#000000\"><b>%s</b></font></td>\n", sortedquery[i]->addr);
      }
      else {
        fprintf(fpstts, "\t\t<td align=\"center\" width=\"140\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#000000\"><b>%s:%u</b></font></td>\n", sortedquery[i]->addr, port);
      }	
      fprintf(fpstts, "\t\t<td align=\"center\" width=\"300\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#000000\"><b>");
      int namelen = strlen(sortedquery[i]->name);
      int width = 30;
      for (j=0; j<namelen; j+=width) {
	char temp[width+1];
	snprintf(temp, width+1, "%s", sortedquery[i]->name+j);
	if (j+width < namelen) {
	  fprintf(fpstts, "%s<br>", temp);
        }
	else {
          fprintf(fpstts, "%s", temp);
        }
      }
      fprintf(fpstts, "</b></font></td>\n");

      if (sortedquery[i]->numQueries != 0) {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">%.0f</font></td>\n", sortedquery[i]->numQueries);
      }
      else {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">- -</font></td>\n");
      }
      if (sortedquery[i]->numQueries != 0) {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">%.2f ms</font></td>\n", sortedquery[i]->medDelay);
      }
      else {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">- -</font></td>\n");
      }
      if (sortedquery[i]->numQueries != 0) {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">%.2f ms</font></td>\n", sortedquery[i]->avgDelay);
      }
      else {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">- -</font></td>\n");
      }
      if (sortedquery[i]->numQueries != 0) {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">%.2f %%</font></td>\n", sortedquery[i]->hitRate);
      }
      else {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">- -</font></td>\n");
      }
      if (sortedquery[i]->numObjects != -1) {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">%.0f</font></td>\n", sortedquery[i]->numObjects);
      }
      else {
	fprintf(fpstts, "\t\t<td align=\"center\" width=\"120\" height=\"50\"><font face=\"Palatino Linotype\" color=\"#0000FF\">- -</font></td>\n");
      }
      fprintf(fpstts, "\t</tr>\n");	
    }
  }
  fprintf(fpstts, "</table>\n\n<hr \"width=1040\">\n<p><h5>Last Updated: %s</h5></p>\n", argv[2]); 	
  fprintf(fpstts, "%s", footer);
  fclose(fpstts);

  exit(0);
}


