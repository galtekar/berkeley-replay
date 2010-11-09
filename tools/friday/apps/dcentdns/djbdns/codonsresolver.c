#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include "prop.h"

#include "cornell_codons_Resolver.h"

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
#include "exit.h"

#include "roots.h"
#include "response.h"
#include "query.h"
#include "log.h"
#include "cache.h"

#define CODONS_MAX_QUERIES 250 /* should be less than 1024 */
#define CODONS_QRYBUF_LEN 1024
#define CODONS_CACHE_SIZE 1000000

#define FATAL "CoDoNS: fatal: "

static char versionStr[15];

static char statsStr[1024];
static char **statsheaders;
static int numStatsValues;

static stralloc out;
static char seed[128];

static int verbosity;
static int cosec;
static char servers[64];

static int numqueries;
static int numanswers;
static double delay;

struct CoDoNSQueryState {
  struct query q;
  char *response;
  int responselen;
  iopause_fd *iofd;
  int done;
  int valid;
  int error;
  jobject keyObject;
  jobject reqObject;
  jbyteArray oldresArray;
  jbyteArray qrymsgArray;
  jboolean direct;
  struct timeval started;
  struct timeval ended;
} *codonsquerystate;

struct ClientQueryState {
  DNSQueryMsg *qryMsg;
  int valid;
  struct sockaddr_in sa;
  int sasize;
  struct timeval started;
} *clientquerystate;

static int maxcodonsqueries = CODONS_MAX_QUERIES;
static int maxclientqueries = CODONS_MAX_QUERIES;
static int numactive = 0;

static iopause_fd *iofd = 0;

static int qrysockfd;
static iopause_fd *qryiofd;
static char qrybuf[CODONS_QRYBUF_LEN];

static int pipefd[2];
static iopause_fd *pipeiofd;
static char pipebuf[256];

static jboolean copied;
static jthrowable exp;

int printPacket(char *pkt, int len) {
  if (!stralloc_copys(&out, "")) {
    return 0;
  }
  if (printpacket_cat(&out, pkt, len)) {
    buffer_putflush(buffer_1, out.s, out.len);
  }
  return 1;
}

jlong getdelay(struct timeval started, struct timeval ended) {
  return (ended.tv_usec - started.tv_usec)/1000 + (ended.tv_sec - started.tv_sec)*1000;
}

void bindsocket(unsigned short port) {
  struct sockaddr_in sa;
  int opt = 1;
  int bufsize = 128 * 1024;

  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  uint16_pack_big((char *) &sa.sin_port, port);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);

  if ((qrysockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    strerr_die2sys(111,FATAL,"unable to open udp socket ");
  }

  if (bind(qrysockfd, (struct sockaddr *) &sa, sizeof sa) < 0) {
    if ((qrysockfd = prop_create_socket(AF_INET, SOCK_DGRAM, 0, (struct sockaddr *) &sa, sizeof sa)) < 0) {
      strerr_die2sys(111,FATAL,"unable to bind udp socket ");
    }
  }
 
  setsockopt(qrysockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
  while(bufsize >= 1024) {
    if (setsockopt(qrysockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof bufsize) == 0)
      break;
    bufsize -= 10 * 1024;
  }

  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  uint16_pack_big((char *) &sa.sin_port, port);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);

}

JNIEXPORT void JNICALL Java_cornell_codons_Resolver_getStatsHeader (JNIEnv *env, jclass cls, jobject stats) {
  jclass alcls = (*env)->GetObjectClass(env, stats);
  if (alcls == 0) {
    strerr_die2sys(111,FATAL,"error getStatsHeader get object class ");
  }
  jmethodID mid = (*env)->GetMethodID(env, alcls, "add", "(Ljava/lang/Object;)Z");
  if (mid == 0) {
    strerr_die2x(111,FATAL,"unable to get methodid of add");
  }

  (*env)->CallObjectMethod(env, stats, mid, (*env)->NewStringUTF(env, "LegacyQueries"));
  if ((exp = (*env)->ExceptionOccurred(env)) != 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2x(111,FATAL,"error getStatsHeader call add ");
  }  

  (*env)->CallObjectMethod(env, stats, mid, (*env)->NewStringUTF(env, "LegacyReplies"));
  if ((exp = (*env)->ExceptionOccurred(env)) != 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2x(111,FATAL,"error getStatsHeader call add ");
  }  
  (*env)->CallObjectMethod(env, stats, mid, (*env)->NewStringUTF(env, "LegacyDelay"));
  if ((exp = (*env)->ExceptionOccurred(env)) != 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2x(111,FATAL,"error getStatsHeader call add ");
  }  
}

JNIEXPORT jint JNICALL Java_cornell_codons_Resolver_getStats (JNIEnv *env, jobject obj, jdoubleArray statsArray, jint indexInt, jboolean reset) {
  double avgdelay = (numanswers == 0) ? 0 : delay/numanswers;

  double stats[3];
  stats[0] = numqueries;
  stats[1] = numanswers;
  stats[2] = avgdelay;

  (*env)->SetDoubleArrayRegion(env, statsArray, indexInt, 3, stats);
  if ((exp = (*env)->ExceptionOccurred(env)) != 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2x(111,FATAL,"unable to copy stats");
  }
 
  if (1 <= verbosity) {
    printf("LegacyStats:\t%d\t%d\t%f\n", numqueries, numanswers, avgdelay);
    fflush(stdout);
  }

  if (reset) {
    numqueries = 0;
    numanswers = 0;
    delay = 0;
  }

  printAllocStats(reset);

  return indexInt+3;
}

JNIEXPORT void JNICALL Java_cornell_codons_Resolver_recordStatsHeader (JNIEnv *env, jclass cls, jbyteArray headersArray, jint numHeaders) {
  
  char *headers = 0;
  if ((headers = (*env)->GetPrimitiveArrayCritical(env, headersArray, &copied)) == 0) {
    strerr_die2sys(111,FATAL,"error recordStatsHeader get byte array elements ");
  }
  //if (copied) printf("Copied keyfilename\n");

  int i;
  statsheaders = (char **)alloc(numHeaders * sizeof(char *));
  if (statsheaders == (char **)0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  byte_zero(statsheaders, numHeaders *sizeof(char *));

  int pos = 0;
  for (i=0; i<numHeaders; i++) {
    int len = strlen(headers+pos);
    statsheaders[i] = alloc(len+1);
    if (statsheaders[i] == (char *)0) {
      strerr_die2x(111,FATAL,"out of memory");
    }
    sscanf(headers+pos, "%s", statsheaders[i]);
    pos += len+1;
  }
  (*env)->ReleasePrimitiveArrayCritical(env, headersArray, headers, JNI_ABORT);
  numStatsValues = numHeaders;
}

JNIEXPORT void JNICALL Java_cornell_codons_Resolver_recordStats (JNIEnv *env, jobject obj, jdoubleArray statsArray) {

  double *stats = 0;
  if ((stats = (*env)->GetPrimitiveArrayCritical(env, statsArray, &copied)) == 0) {
    strerr_die2sys(111,FATAL,"error recordStats get byte array elements ");
  }
  //if (copied) printf("Copied keyfilename\n");

  int i;
  int pos = 0;
  for (i=0; i<numStatsValues; i++) {
    pos += snprintf(statsStr+pos, 1024-pos, "%c%s", strlen(statsheaders[i]), statsheaders[i]);
    int len = snprintf(statsStr+pos, 1024-pos, " %f", stats[i]);
    if (len > 1024-pos) {
      strerr_die2x(111,FATAL,"unable to record stats values ");
    }
    statsStr[pos] = (char)(len-1);
    pos += len;
  }
  (*env)->ReleasePrimitiveArrayCritical(env, statsArray, stats, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_cornell_codons_Resolver_init (JNIEnv *env, jobject obj, jbyteArray keyfilenameArray, jbyteArray cosecipArray, jshort dnsport, jint verbosityInt, jboolean forward) {
  dns_random_init(seed);

  if (cosecipArray != 0) {
    byte_zero(servers, 64);
    (*env)->GetByteArrayRegion(env, cosecipArray, 0, 4, (jbyte *)servers);
    if ((exp = (*env)->ExceptionOccurred(env)) != 0) {
      (*env)->ExceptionDescribe(env);
      strerr_die2x(111,FATAL,"unable to get cosec ip address ");
    }
    cosec = 1;
  }
  else if (forward) {
    query_forwardonly();
    
    byte_zero(servers, 64);
    if (dns_resolvconfip(servers) == -1) {
      strerr_die2sys(111,FATAL,"unable to read /etc/resolv.conf: ");
    }
    
    if (!roots_init2(servers)) {
      strerr_die2sys(111,FATAL,"unable to initialize forwarding servers: ");
    }
    
    cosec = 0;
  }
  else {
    if (!roots_init()) {
      strerr_die2sys(111,FATAL,"unable to read root servers: ");
    }
    
    if (!cache_init(CODONS_CACHE_SIZE)) {
      strerr_die2sys(111,FATAL,"unable to initialize resolver cache");
    }
    cosec = 0;
  }

  char *keyfilename = 0;
  if ((keyfilename = (*env)->GetPrimitiveArrayCritical(env, keyfilenameArray, &copied)) == 0) {
    strerr_die2sys(111,FATAL,"error init get byte array elements ");
  }
  //if (copied) printf("Copied keyfilename\n");

  if (!initCoDoNSPublicKey(keyfilename)) {
    strerr_die2x(111,FATAL,"unable to read public key ");
  }
  (*env)->ReleasePrimitiveArrayCritical(env, keyfilenameArray, keyfilename, JNI_ABORT);

  FILE *fp = fopen("codons.version.txt", "r");
  if (fp == (FILE *)0) {
    strerr_die2x(111,FATAL,"unable to read codons.version.txt");
  }
  char tempVersionStr[14];
  fscanf(fp, "%[^\n]13", tempVersionStr);
  sprintf(versionStr, "%c%s", strlen(tempVersionStr), tempVersionStr);
  fclose(fp);

  byte_zero(statsStr, sizeof(statsStr));

  bindsocket(dnsport);
  
  if ((iofd = (iopause_fd *)malloc((maxcodonsqueries+2)*sizeof(iopause_fd))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }

  if ((codonsquerystate = (struct CoDoNSQueryState *)malloc(maxcodonsqueries*sizeof(struct CoDoNSQueryState))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  byte_zero(codonsquerystate, maxcodonsqueries*sizeof(struct CoDoNSQueryState));

  if ((clientquerystate = (struct ClientQueryState *)malloc(maxclientqueries*sizeof(struct ClientQueryState))) == 0) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  byte_zero(clientquerystate, maxclientqueries*sizeof(struct ClientQueryState));

  if (pipe(pipefd) < 0) {
    strerr_die2sys(111,FATAL,"unable to open pipe");
  }

  verbosity = verbosityInt;

  numqueries = 0;
  numanswers = 0;
  delay = 0;
}

JNIEXPORT void JNICALL Java_cornell_codons_Resolver_run(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  if (cls == 0) {
    strerr_die2sys(111,FATAL,"error run get object class ");
  }
  jmethodID qrymid = (*env)->GetMethodID(env, cls, "handleRequest", "([B[B)V");
  if (qrymid == 0) {
    strerr_die2x(111,FATAL,"unable to get methodid of handle query");
  }
  jmethodID resmid = (*env)->GetMethodID(env, cls, "handleResponse", "(Lrice/pastry/NodeId;Lcornell/codons/RequestMessage;[BJBZZ)V");
  if (resmid == 0) {
    strerr_die2x(111,FATAL,"unable to get methodid of handle response");
  }

  printf("At CoDoNS: started legacy dns resolver version %s.\n", versionStr+1);
  fflush(stdout);
  
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
    if (numactive < maxclientqueries) {
      qryiofd = iofd + numiofds;
      numiofds++;
      qryiofd->fd = qrysockfd;
      qryiofd->events = IOPAUSE_READ;
    }
    else {
      qryiofd = 0;
    }
    for (i=0; i<maxcodonsqueries; i++) {
      if (codonsquerystate[i].valid && !codonsquerystate[i].done) {
	codonsquerystate[i].iofd = iofd + numiofds;
	numiofds++;
	if (cosec) {
	  dns_transmit_io(&codonsquerystate[i].q.dt, codonsquerystate[i].iofd, &deadline);
	}
	else {
	  query_io(&codonsquerystate[i].q, codonsquerystate[i].iofd, &deadline);
	}
      }
    }

    if ((*env)->MonitorExit(env, obj) < 0) {
      (*env)->ExceptionDescribe(env);
      strerr_die2sys(111,FATAL,"error run moniter exit ");
    }

    iopause(iofd, numiofds, &deadline, &stamp);

    if ((*env)->MonitorEnter(env, obj) < 0) {
      (*env)->ExceptionDescribe(env);
      strerr_die2sys(111,FATAL,"error run moniter enter ");
    }

    for (i=0; i<maxcodonsqueries; i++) {
      if (codonsquerystate[i].valid && codonsquerystate[i].iofd != 0 && !codonsquerystate[i].done) {
	int retVal;
	if (cosec) {
	  retVal = dns_transmit_get(&codonsquerystate[i].q.dt, codonsquerystate[i].iofd, &stamp);
	}
	else {
	  retVal = query_get(&codonsquerystate[i].q, codonsquerystate[i].iofd, &stamp);
	}

	if (retVal != 0) {
	  codonsquerystate[i].error = (retVal == -1) ? errno : 0;
	  gettimeofday(&codonsquerystate[i].ended, (struct timezone *) 0);
	  codonsquerystate[i].done = 1;
	  if (retVal == 1) {
	    if (cosec) {
	      codonsquerystate[i].response = codonsquerystate[i].q.dt.packet;
	      codonsquerystate[i].responselen = codonsquerystate[i].q.dt.packetlen;
	    }
	    else {
	      if ((codonsquerystate[i].response = alloc_channel(response_len, 6)) == 0) {
		strerr_die2x(111,FATAL,"out of memory");
	      }
	      byte_copy(codonsquerystate[i].response, response_len, response);
	      codonsquerystate[i].responselen = response_len;
	    }
	  }
	}
      }
    }

    for (i=0; i<maxcodonsqueries; i++) {
      if (codonsquerystate[i].valid && codonsquerystate[i].done) {
	DNSQueryMsg *qryMsg = 0;
	if ((qryMsg = (DNSQueryMsg *)(*env)->GetPrimitiveArrayCritical(env, codonsquerystate[i].qrymsgArray, &copied)) == 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run get byte array elements ");
	}
	//if (copied) printf("Copied qryMsg\n");

	int oldresbuflen = 0;
	char *oldresbuf = 0;
	if (codonsquerystate[i].oldresArray != 0 && (oldresbuflen = (*env)->GetArrayLength(env, codonsquerystate[i].oldresArray)) < 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run get array length ");
	}
	if (codonsquerystate[i].oldresArray != 0 && (oldresbuf = (*env)->GetPrimitiveArrayCritical(env, codonsquerystate[i].oldresArray, &copied)) == 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run get byte array elements ");
	}
	//if (copied) printf("Copied oldresbuf\n");
	
	DNSMessage *oldresMsg = 0;
	if (oldresbuf != 0 && !readDataFromPacket(oldresbuf, oldresbuflen, &oldresMsg, 0)) {
	  if (errno == error_nomem) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  strerr_die2x(111,FATAL,"error run read data from old res");
	}

	if (!codonsquerystate[i].error && cosec && codonsquerystate[i].responselen > 3) {
	  ((Flags3 *)&codonsquerystate[i].response[3])->reserved = 1; 
	}

	if (!codonsquerystate[i].error) {
	  delay += getdelay(codonsquerystate[i].started, codonsquerystate[i].ended);
	  numanswers++;
	}

	uint8 errorcode = codonsquerystate[i].error ? DNS_RCODE_SRVFAIL : 0;
	uint8 parseerror = 0;
	DNSMessage *resMsg = 0;
	if (!errorcode && !readDataFromPacket(codonsquerystate[i].response, codonsquerystate[i].responselen, &resMsg, 0)) {
	  if (errno == error_nomem) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }
	  errorcode = DNS_RCODE_SRVFAIL;
	  parseerror = 1;
	}
	
	if (errorcode) {
	  freeDNSMessage(&resMsg);
	  if(!createErrorMessage(&resMsg, errorcode, qryMsg)) {
	    strerr_die2x(111,FATAL,"out of memory");
	  }		
	} 
	
	jlong ttl = getttl(resMsg);
	jboolean match = matchresponses(resMsg, oldresMsg);
	
	if (codonsquerystate[i].oldresArray != 0) {
	  (*env)->ReleasePrimitiveArrayCritical(env, codonsquerystate[i].oldresArray, oldresbuf, JNI_ABORT);
	  (*env)->DeleteGlobalRef(env, codonsquerystate[i].oldresArray);
	}
	freeDNSMessage(&oldresMsg);
	
	((Flags3 *)&resMsg->header.flags3)->reserved = 1;

	jbyteArray resbufArray = 0;
	if ((resbufArray = (*env)->NewByteArray(env, resMsg->length)) == 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run new byte array ");
	}
	char *resbuf = 0;
	if ((resbuf = (*env)->GetPrimitiveArrayCritical(env, resbufArray, &copied)) == 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run get byte array elements ");
	}
	//if (copied) printf("Copied resbuf\n");
	if (!packDNSMessage(resMsg, &resbuf)) {
	  strerr_die2x(111,FATAL,"out of memory");
	}
	(*env)->ReleasePrimitiveArrayCritical(env, resbufArray, resbuf, 0);
	
	if (1 <= verbosity) {
	  int rcode = ((Flags3*)&resMsg->header.flags3)->rcode;
	  unsigned long timetaken = getdelay(codonsquerystate[i].started, codonsquerystate[i].ended);
	  printf("Legacy: resolved query for name ");
	  printName(qryMsg->qdata);
	  printf(" type %hd rcode %d length %d ttl %ld match %s time %lu", getshort(qryMsg->qdata+qryMsg->length-16), ((Flags3 *)&resMsg->header.flags3)->rcode, resMsg->length, (long)ttl, (match ? "yes" : "no"), timetaken);
	  if (parseerror) {
	    printf(" parse error");
          }
	  else if (rcode == 2 && ttl > 0) {
	    printf(" ttl error");
	  }
	  printf("\n");
          if (rcode == 2 && ttl > 0) {
	    printDNSMessage(resMsg);
	    printPacket(codonsquerystate[i].response, codonsquerystate[i].responselen);
          }
	  fflush(stdout);
	}
	
	(*env)->ReleasePrimitiveArrayCritical(env, codonsquerystate[i].qrymsgArray, (jbyte *)qryMsg, JNI_ABORT);
	(*env)->DeleteGlobalRef(env, codonsquerystate[i].qrymsgArray);
	
	(*env)->CallObjectMethod(env, obj, resmid, codonsquerystate[i].keyObject, codonsquerystate[i].reqObject, resbufArray, ttl, ((Flags3 *)&resMsg->header.flags3)->rcode, match, codonsquerystate[i].direct);
	if ((exp = (*env)->ExceptionOccurred(env)) != 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2x(111,FATAL,"error run call handle response ");
	}
	
	(*env)->DeleteGlobalRef(env, codonsquerystate[i].keyObject);
	if (codonsquerystate[i].reqObject != 0) {
	    (*env)->DeleteGlobalRef(env, codonsquerystate[i].reqObject);
	}
	(*env)->DeleteLocalRef(env, resbufArray);
	freeDNSMessage(&resMsg);
	
	if (!cosec && codonsquerystate[i].response != 0) {
	  alloc_free_channel(codonsquerystate[i].response, 6);
	  codonsquerystate[i].response = 0;
	}
	codonsquerystate[i].valid = 0;
      }
    }

    while (numactive < maxclientqueries && qryiofd && qryiofd->revents) {
      for (i=0; clientquerystate[i].valid; i++);
      
      int qrybuflen;
      clientquerystate[i].sasize = sizeof(clientquerystate[i].sa);
      if ((qrybuflen = recvfrom(qrysockfd, qrybuf, CODONS_QRYBUF_LEN, MSG_DONTWAIT, (struct sockaddr *) &clientquerystate[i].sa, &clientquerystate[i].sasize)) < 0) {
	if (errno == EAGAIN) {
	  break;
	}
	strerr_die2sys(111,FATAL,"unable to read from udp socket ");
      }

      DNSQueryMsg *qryMsg = 0;
      uint8 errorcode = 0;
      uint8 version = 0;
      uint8 stats = 0;
      if (!readDataFromQuery(qrybuf, qrybuflen, &qryMsg)) {
	if (errno == error_nomem) {
	  strerr_die2x(111,FATAL,"out of memory");
	}
	errorcode = DNS_RCODE_BADFORM;
      }
      else if (byte_equal(qryMsg->qdata+qryMsg->length-14, 2, DNS_C_CH) && byte_equal(qryMsg->qdata+qryMsg->length-16, 2, DNS_T_TXT) && strcasecmp(qryMsg->qdata, "\007version\006codons\000") == 0) {
	  version = 1;
      }
      else if (byte_equal(qryMsg->qdata+qryMsg->length-14, 2, DNS_C_CH) && byte_equal(qryMsg->qdata+qryMsg->length-16, 2, DNS_T_TXT) && strcasecmp(qryMsg->qdata, "\005stats\006codons\000") == 0) {
	  stats = 1;
      }
      else if (((Flags2 *)&qryMsg->header.flags2)->opcode != 0 || byte_diff(qryMsg->qdata+qryMsg->length-14, 2, DNS_C_IN) || byte_equal(qryMsg->qdata+qryMsg->length-16, 2, DNS_T_AXFR)) {
	  errorcode = DNS_RCODE_NOTIMPL;
      }
      
      if (errorcode || version || stats) {
	DNSMessage *resMsg = 0;

	if (version && !createVersionMessage(&resMsg, qryMsg, versionStr)) {
	  strerr_die2x(111,FATAL,"out of memory");
	}		 
	if (stats && !createStatsMessage(&resMsg, qryMsg, statsStr)) {
	  strerr_die2x(111,FATAL,"out of memory");
	}		 
	if (errorcode && !createErrorMessage(&resMsg, errorcode, qryMsg)) {
	  strerr_die2x(111,FATAL,"out of memory");
	}		 
	((Flags3 *)&resMsg->header.flags3)->recurseavail = 1;
	byte_copy(resMsg->header.id, 2, (qrybuflen > 1) ? qrybuf : "\0\0");

	char *resbuf = 0;
	if (!packDNSMessage(resMsg, &resbuf)) {
	  strerr_die2x(111,FATAL,"out of memory");
	}
	int resbuflen = resMsg->length;
	
	if (sendto(qrysockfd, resbuf, resbuflen, MSG_DONTWAIT, (struct sockaddr *) &clientquerystate[i].sa, clientquerystate[i].sasize) < 0) {
	  strerr_die2sys(111,FATAL,"unable to write to udp socket ");
	}

	if (1 <= verbosity) {
	  if (version) {
	    printf("Interface: received version query\n");  
	  }
	  else if (stats) {
	    printf("Interface: received stats query\n");  
	  }
	  else {
	    printf("Interface: received bad query rcode %d length %d\n", ((Flags3 *)&resMsg->header.flags3)->rcode, resbuflen);  
	  }
	  fflush(stdout);
	}
	
	alloc_free_channel((char *)qryMsg, 2);
	alloc_free_channel(resbuf, 5);
	freeDNSMessage(&resMsg);
      }
      else {
	/* check for duplicate queries */
	int j;
	for (j=0; j<maxclientqueries; j++) {
	  if (clientquerystate[j].valid && byte_equal(clientquerystate[j].qryMsg->header.id, 2, qryMsg->header.id)) {
	    break;
	  }
	}
	if (j<maxclientqueries) {
	  if (1 <= verbosity) {
	    printf("Interface: received duplicate query for name ");
	    printName(qryMsg->qdata);
	    printf(" type %d\n", getshort(qryMsg->qdata+qryMsg->length-12-4));
	    fflush(stdout);
	  }
	  
	  alloc_free_channel((char *)qryMsg, 2);
	  continue;
	}

	if (1 <= verbosity) {
	  printf("Interface: received query for name ");
	  printName(qryMsg->qdata);
	  printf(" type %d\n", getshort(qryMsg->qdata+qryMsg->length-12-4));
	  fflush(stdout);
	}

	clientquerystate[i].qryMsg = qryMsg;
	clientquerystate[i].valid = 1;
	gettimeofday(&clientquerystate[i].started,(struct timezone *) 0);
	numactive++;

	jbyteArray qrymsgArray = 0;
	if ((qrymsgArray = (*env)->NewByteArray(env, qryMsg->length+2)) == 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run new byte array ");
	}
	(*env)->SetByteArrayRegion(env, qrymsgArray, 0, qryMsg->length+2, (jbyte *)qryMsg);
	if ((exp = (*env)->ExceptionOccurred(env)) != 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2x(111,FATAL,"error run set byte array region ");
	}

	jbyteArray keyArray = 0;
	if ((keyArray = (*env)->NewByteArray(env, 20)) == 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run new byte array ");
	}
	char *key = 0;
	if ((key = (*env)->GetPrimitiveArrayCritical(env, keyArray, &copied)) == 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run get byte array elements ");
	}
	//if (copied) printf("Copied key\n");

	getsha1hash(qryMsg->qdata, key);
	(*env)->ReleasePrimitiveArrayCritical(env, keyArray, key, 0);
	

	if ((*env)->MonitorExit(env, obj) < 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run moniter exit ");
	}

	(*env)->CallObjectMethod(env, obj, qrymid, keyArray, qrymsgArray);
	if ((exp = (*env)->ExceptionOccurred(env)) != 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2x(111,FATAL,"error run call handle query ");
	}

	if ((*env)->MonitorEnter(env, obj) < 0) {
	  (*env)->ExceptionDescribe(env);
	  strerr_die2sys(111,FATAL,"error run moniter enter ");
	}

	(*env)->DeleteLocalRef(env, qrymsgArray);
	(*env)->DeleteLocalRef(env, keyArray);
      }
    }

    if (pipeiofd->revents) {
      read(pipefd[0], pipebuf, sizeof(pipebuf)) > 0;
    }
  }
}

JNIEXPORT jboolean JNICALL Java_cornell_codons_Resolver_resolve(JNIEnv *env, jobject obj, jobject keyObject, jobject reqObject, jbyteArray qrymsgArray, jbyteArray oldresArray, jboolean direct) {
  jboolean retVal = JNI_FALSE;

  if (keyObject == 0 || qrymsgArray == 0) {
    return retVal;
  }

  DNSQueryMsg *qryMsg = 0;
  if ((qryMsg = (DNSQueryMsg *)(*env)->GetPrimitiveArrayCritical(env, qrymsgArray, &copied)) == 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2sys(111,FATAL,"error resolve get byte array elements ");
  }
  //if (copied) printf("Copied qryMsg\n");

  int i;
  for (i=0; i<maxcodonsqueries && codonsquerystate[i].valid; i++);
  if (i == maxcodonsqueries) {
    goto bad_return; // queue full
  }

  codonsquerystate[i].iofd = 0;
  codonsquerystate[i].valid = 1;
  codonsquerystate[i].done = 0;

  int errorcode;
  if (cosec) {
    errorcode = dns_transmit_start(&codonsquerystate[i].q.dt, servers, 1 , qryMsg->qdata, qryMsg->qdata+qryMsg->length-16, "\0\0\0\0");
  }
  else {
    errorcode = query_start(&codonsquerystate[i].q, qryMsg->qdata, qryMsg->qdata+qryMsg->length-16, qryMsg->qdata+qryMsg->length-14, "\0\0\0\0");
  }

  if (errorcode != 0) {
    if (cosec) {
      if (errno == error_nomem) {
	strerr_die2x(111,FATAL,"out of memory");
      }
      else {
	strerr_die2sys(111,FATAL,"error resolve dns_transmit_start ");
      }
    }
    else {
      codonsquerystate[i].error = (errorcode == -1) ? errno : 0;
      gettimeofday(&codonsquerystate[i].ended, (struct timezone *) 0);
      codonsquerystate[i].done = 1;
      if (errorcode == 1) {
	if ((codonsquerystate[i].response = alloc(response_len)) == 0) {
	  strerr_die2x(111,FATAL,"out of memory");
	}
	byte_copy(codonsquerystate[i].response, response_len, response);
	codonsquerystate[i].responselen = response_len;
      }
    }
  }
  
  if ((codonsquerystate[i].keyObject = (*env)->NewGlobalRef(env, keyObject)) == 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2sys(111,FATAL,"error resolve new global ref ");
  }
  codonsquerystate[i].reqObject = 0;
  if (reqObject != 0 && (codonsquerystate[i].reqObject = (*env)->NewGlobalRef(env, reqObject)) == 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2sys(111,FATAL,"error resolve new global ref ");
  }
  if ((codonsquerystate[i].qrymsgArray = (*env)->NewGlobalRef(env, qrymsgArray)) == 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2sys(111,FATAL,"error resolve new global ref ");
  }
  codonsquerystate[i].oldresArray = 0;
  if (oldresArray != 0 && (codonsquerystate[i].oldresArray = (*env)->NewGlobalRef(env, oldresArray)) == 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2sys(111,FATAL,"error resolve new global ref ");
  }
  
  codonsquerystate[i].direct = direct;
  gettimeofday(&codonsquerystate[i].started, (struct timezone *) 0);
  numqueries++;

  if (write(pipefd[1], "s", 1) <= 0) {
    strerr_die2sys(111,FATAL,"error in write pipe ");
  }
  retVal = JNI_TRUE;

  if (1 <= verbosity) {
    printf("Legacy: resolving query for name ");
    printName(qryMsg->qdata);
    printf(" type %d\n", getshort(qryMsg->qdata+qryMsg->length-12-4));
    fflush(stdout);
  }

 bad_return:
  (*env)->ReleasePrimitiveArrayCritical(env, qrymsgArray, (jbyte *)qryMsg, JNI_ABORT);
  return retVal;
}

JNIEXPORT jlong JNICALL Java_cornell_codons_Resolver_handleResponse(JNIEnv *env, jobject obj, jbyteArray qrymsgArray, jbyteArray resbufArray, jbyte rcode, jbyte hops, jboolean cached, jboolean direct) {
  jlong retVal;

  DNSQueryMsg *qryMsg = 0;
  if ((qryMsg = (DNSQueryMsg *)(*env)->GetPrimitiveArrayCritical(env, qrymsgArray, &copied)) == 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2sys(111,FATAL,"error resolve get byte array elements ");
  }
  //if (copied) printf("Copied qryMsg\n");

  int i;
  for (i=0; i<maxclientqueries; i++) {
    if (clientquerystate[i].valid && byte_equal(clientquerystate[i].qryMsg->header.id, 2, qryMsg->header.id)) {
      break;
    }
  }

  if (i == maxclientqueries || rcode == DNS_RCODE_SRVFAIL) {
    if (1 <= verbosity) {
      if (i == maxclientqueries) {
	printf("CoDoNS: DroppingResponse: name ");
      }
      else {
	printf("CoDoNS: BadResponse: name ");
      }
      printName(qryMsg->qdata);
      printf(" type %d\t%s\t%d\n", getshort(qryMsg->qdata+qryMsg->length-16), cached ? "true" : "false", hops);
      fflush(stdout);
    }
    retVal = -1;
    goto bad_return;
  }
 
  struct timeval ended;
  gettimeofday(&ended, (struct timezone *) 0);
  retVal = getdelay(clientquerystate[i].started, ended);
      
  if (1 <= verbosity) {
    if (resbufArray == 0) {
      printf("CoDoNS: Timeout: name ");
      printName(qryMsg->qdata);
      printf(" type %d\n", getshort(qryMsg->qdata+qryMsg->length-16));
    }
    else {
      printf("CoDoNS: QryStats: name ");
      printName(qryMsg->qdata);
      printf(" type %d\t%s\t%d\t%ld\n", getshort(qryMsg->qdata+qryMsg->length-16), cached ? "cached" : (direct ? "direct" : "home"), hops, retVal);
    }
    fflush(stdout);
  }
  
  int resbuflen = 0;
  char *resbuf = 0;
  if (resbufArray != 0 && (resbuflen = (*env)->GetArrayLength(env, resbufArray)) < 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2sys(111,FATAL,"error response get array length ");
  }
  if (resbufArray != 0 && (resbuf = (*env)->GetPrimitiveArrayCritical(env, resbufArray, &copied)) == 0) {
    (*env)->ExceptionDescribe(env);
    strerr_die2sys(111,FATAL,"error response get byte array elements ");
  }
  //if (copied) printf("Copied resbuf\n");

  DNSMessage *resMsg = 0;
  if (!readDataFromPacket(resbuf, resbuflen, &resMsg, 0)) {
    if (errno == error_nomem) {
      strerr_die2x(111,FATAL,"out of memory");
    }
    freeDNSMessage(&resMsg);
    if(!createErrorMessage(&resMsg, DNS_RCODE_SRVFAIL, clientquerystate[i].qryMsg)) {
      strerr_die2x(111,FATAL,"out of memory");
    }
  }
  
  if (((Flags3 *)&clientquerystate[i].qryMsg->header.flags3)->cd) {
    ((Flags3 *)&resMsg->header.flags3)->ad = 0;
  }
  else {
    ((Flags3 *)&resMsg->header.flags3)->ad = verifySignatures(resMsg);
    removeSignatures(resMsg);
  }
  
  byte_copy(resMsg->header.id, 2, clientquerystate[i].qryMsg->header.id);
  ((Flags3 *)&resMsg->header.flags3)->reserved = 0;
  ((Flags3 *)&resMsg->header.flags3)->recurseavail = 0;

  char *newresbuf = 0;
  int newresbuflen = resMsg->length;  
  if (!packDNSMessage(resMsg, &newresbuf)) {
    strerr_die2x(111,FATAL,"out of memory");
  }
  
  if (1 <= verbosity) {
    printf("Interface: sending response for name ");
    printName(clientquerystate[i].qryMsg->qdata);
    printf(" type %d\n", getshort(clientquerystate[i].qryMsg->qdata+clientquerystate[i].qryMsg->length-16));
    fflush(stdout);
  }

  freeDNSMessage(&resMsg);
  if (resbufArray != 0) {
    (*env)->ReleasePrimitiveArrayCritical(env, resbufArray, resbuf, JNI_ABORT);
  }

  if (sendto(qrysockfd, newresbuf, newresbuflen, MSG_DONTWAIT, (struct sockaddr *) &clientquerystate[i].sa, clientquerystate[i].sasize) < 0) {
    strerr_die2sys(111,FATAL,"unable to write to udp socket ");
  }
  alloc_free_channel(newresbuf, 5);

  
  alloc_free_channel((char *)clientquerystate[i].qryMsg, 2);
  clientquerystate[i].valid = 0;
  numactive--;

 bad_return:
  (*env)->ReleasePrimitiveArrayCritical(env, qrymsgArray, (jbyte *)qryMsg, JNI_ABORT);
  return retVal;
}
