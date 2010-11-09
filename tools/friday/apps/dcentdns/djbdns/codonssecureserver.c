#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
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

#include <assert.h>
#include "logger.h"
#include "eventq.h"

#define COSEC_PORT 11111
#define COSEC_MAX_QUERIES 200

#define COSEC_QRYBUF_LEN 1024
#define FATAL "COSEC: fatal: "

#define COSEC_CACHE_SIZE 1000000

DNSMessage* responseMsg;
int isCached=0;

static stralloc out;

struct QueryState {
	struct query q;
	char *response;
	int responselen;
	iopause_fd *iofd;
	int done;
	int valid;
	int error;
	int isCached;
	struct sockaddr_in sa;
	int sasize;
	DNSQueryMsg *qryMsg;
	struct timeval started;
	struct timeval ended;
};

void sig_handler(int sigNum){
	switch(sigNum){
		case SIGSEGV:
			log_default ( SILENT, "Seg fault. Exiting \n");
			break;
		case SIGINT:
			log_default ( SILENT, "Interrupted. Exiting\n");
			break;
		case SIGTERM:
			log_default ( SILENT, "Killed. Exiting\n");
			break;
		default:
			log_default ( SILENT, "Exiting on signal %d\n", sigNum);
			break;
	}
	exit(1);
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
	int forward = 0;
	int enablesigning = 1;

	dns_random_init(seed);
	byte_zero(servers, 64);
	byte_copy(servers, 4, "\177\0\0\1");

	iopause_fd *iofd = 0;  

	struct QueryState *querystate = 0; 
	int maxqueries = COSEC_MAX_QUERIES;
	int numactive = 0;

	int qrysockfd;
	iopause_fd *qryiofd;
	char qrybuf[COSEC_QRYBUF_LEN];

	int pipefd[2];
	iopause_fd *pipeiofd;
	char pipebuf[256];

	int extsockfd;
	iopause_fd *extiofd;	
	char extbuf[256];	

	int extsockfd1;
	iopause_fd *extiofd1;
	char extbuf1[256];

	int ondemand=0;

	DNSMessageList* messageList = NULL;


	struct sockaddr_in remoteAddr;
	int connected =0 ;

	unsigned short port = COSEC_PORT;
	char keyfilename[40] = "codonskey";

	int opt;
	while ((opt = getopt(argc, argv,"p:k:fdlho")) != opteof) {
		switch(opt) {
			case 'p':
				sscanf(optarg, "%hu", &port);
				break;
			case 'k':
				sscanf(optarg, "%s", keyfilename);
				break;
			case 'f':
				forward = 1;
				query_forwardonly();
				break;
			case 'd':
				enablesigning = 0;
				break;
			case 'l':
				query_log();
				break;
			case 'o':
				ondemand = 1;
				break;
			case 'h':	
			default:
				strerr_die1x(111,"COSEC: usage: codonssecureserver [-p <port>] [-k <key file name>] [-f forward] [-d disable signing] [-l log details] [-h help]");
		}
	}

	/*  if (enablesigning && !initCoDoNSKey(keyfilename)) {
		 strerr_die2x(111,FATAL,"unable to read private key ");
		 }
		 if (enablesigning && !initCoDoNSPublicKey(keyfilename)) {
		 strerr_die2x(111,FATAL,"unable to read public key ");
		 }
		 if (enablesigning && !testCoDoNSKeys()) {
		 strerr_die2x(111,FATAL,"invalid key pair ");
		 }
	 */
	if ((qrysockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		strerr_die2sys(111,FATAL,"unable to open udp socket ");
	}
	if (bindsocket(qrysockfd, port)) {
		strerr_die2sys(111,FATAL,"unable to bind udp socket ");
	}

	if ((extsockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		strerr_die2sys(111,FATAL,"unable to open external socket ");
	}
	if (bindsocket(extsockfd, port+1)) {
		strerr_die2sys(111,FATAL,"unable to bind udp socket ");
	}

	if((listen (extsockfd, 1))==-1){
		perror("listen");
		exit(2);
	}

	/**Dirty hack to ensure that 
	  poll does not return early
	 */
	if ((extsockfd1 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		strerr_die2sys(111,FATAL,"unable to open external socket ");
	}
	if (bindsocket(extsockfd1, port+2)) {
		strerr_die2sys(111,FATAL,"unable to bind udp socket ");
	} 

	init_log ( port, "", port, NORMAL);

	signal(SIGINT,sig_handler);
	signal(SIGSEGV,sig_handler);
	signal(SIGABRT,sig_handler);
	signal(SIGTERM,sig_handler);
	signal(SIGPIPE,SIG_IGN);

	EventQ* eventq = NULL;
	add_event ( &eventq, 250000, UPDATE_BROADCAST);

	if ((iofd = (iopause_fd *)malloc((maxqueries+4)*sizeof(iopause_fd))) == 0) {
		strerr_die2x(111,FATAL,"out of memory");
	}
	if ((querystate = (struct QueryState *) malloc(maxqueries*sizeof(struct QueryState))) == 0) {
		strerr_die2x(111,FATAL,"out of memory");
	}
	byte_zero( (char *)querystate, maxqueries*sizeof(struct QueryState));

	if (pipe(pipefd) < 0) {
		strerr_die2sys(111,FATAL,"unable to open pipe");
	}

	//  if (!forward && !roots_init2("127.0.0.1")) {
	if (!forward && !roots_init()) {
		strerr_die2sys(111,FATAL,"unable to read root servers: ");
	}

	if (!forward && !cache_init(COSEC_CACHE_SIZE)) {
		strerr_die2sys(111,FATAL,"unable to initialize resolver cache");
	}

	if (forward && dns_resolvconfip(servers) == -1) {
		strerr_die2sys(111,FATAL,"unable to read /etc/resolv.conf: ");
	}

	if (forward && !roots_init2(servers)) {
		strerr_die2sys(111,FATAL,"unable to initialize forwarding servers: ");
	}




	printf("before for loop\n");

	struct taia stamp;
	struct taia deadline;
	for (;;) {
		int i;

		log_default( VERBOSE, "##################\n");
		handle_event_q( extiofd1, &eventq, messageList);

		taia_now(&stamp);
		taia_uint(&deadline, 120);
		taia_add(&deadline, &deadline, &stamp);

		int numiofds = 0;
		pipeiofd = iofd + numiofds;
		numiofds++;
		pipeiofd->fd = pipefd[0];
		pipeiofd->events = IOPAUSE_READ;

		extiofd = iofd + numiofds;
		numiofds++;
		extiofd->fd = extsockfd;
		extiofd->events = IOPAUSE_READ;

		extiofd1 = iofd + numiofds;
		numiofds++;
		extiofd1->fd = extsockfd1;
		extiofd1->events = IOPAUSE_READ ;
		/* log_default(NORMAL,"extsockfd1=%d\n", extsockfd1);
			log_default(NORMAL,"extiofd1->fd=%d\n", extiofd1->fd);
			log_default(NORMAL,"extiofd1->events=%d\n", extiofd1->events);
		 */
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
				query_io(&querystate[i].q, querystate[i].iofd, &deadline);
			}
		}
		log_default ( VERBOSE, "queryiofd=%d,pipeiofd=%d,numiofds=%d\n", qrysockfd, pipeiofd->fd, numiofds);
		iopause(iofd, numiofds, &deadline, &stamp);
		if (!connected && extsockfd && extiofd->revents){
			int addrlen = sizeof(remoteAddr);
			if( ( extsockfd1 = accept ( extsockfd, (struct sockaddr *)&remoteAddr, (socklen_t *)&addrlen)) ==-1) {
				log_default ( SILENT, "Error in accepting connection\n");
				exit (1);
			}
			else{
				/* Got a new connection */
				close (extiofd1->fd);
				extiofd1->fd = extsockfd1;
				extiofd1->events = IOPAUSE_READ;
				log_default (NORMAL,"Accepted connection from (%s,%d) on %d\n" ,inet_ntoa(remoteAddr.sin_addr),htons(remoteAddr.sin_port),extsockfd);	
				/*			char * msg = "Hello\n";
							int totalSent=0;
							char *buf=(char *)msg;
							flush_message (extsockfd1, buf, 6);*/
				connected=1;
			}
		}

		if (connected && extsockfd1 && extiofd1->revents){

			/** Read DNS message pushed by some other server.*/
			log_default ( NORMAL, "Getting a pushed DNS record\n");
			Message* message = receive_message (extsockfd1);
			DNSMessage* dnsMessage;
			readDataFromPacket ( message->payload, message->payloadSize, &dnsMessage, 1);
			int added = add_dns_message ( &messageList, NONAUTH, dnsMessage);
			log_default ( VERBOSE, "Added nonauthoritative message? %d\n", added);
			free_message(&message);


			extiofd1->revents=0;
		}

		for (i=0; i<maxqueries; i++) {
			if (querystate[i].valid && !querystate[i].done) {
				log_default(VERBOSE,"Have a valid but unfinished query\n");
				int retVal = query_get(&querystate[i].q, querystate[i].iofd, &stamp);
				log_default(NORMAL,"From query_get:retVal=%d\n", retVal);
				if (retVal != 0) {
					querystate[i].error = (retVal == -1) ? errno : 0;
					log_default(VERBOSE, "Error:%d Entering if\n", errno);
					gettimeofday(&querystate[i].ended, (struct timezone *) 0);
					querystate[i].done = 1;
					if (retVal == 1) {
						log_default(VERBOSE, "Error:Entering inner if\n", errno);
						if ((querystate[i].response = alloc(response_len)) == 0) {
							strerr_die2x(111,FATAL,"out of memory");
						}
						byte_copy(querystate[i].response, response_len, response);
						querystate[i].responselen = response_len;
					}
					log_default(VERBOSE, "Error:Exiting if\n", errno);
				}
			}
		}
		for (i=0; i<maxqueries; i++) {
			if (querystate[i].valid && querystate[i].done) {
				log_default( VERBOSE, "Have a valid and completed query.\n");
				querystate[i].valid = 0;
				numactive--;

				uint8 errorcode = querystate[i].error ? DNS_RCODE_SRVFAIL : 0;
				DNSMessage *resMsg = 0;
				int caching = 0;

				if (!errorcode && !readDataFromPacket(querystate[i].response, querystate[i].responselen, &resMsg, 1)) {
					log_default( VERBOSE, "Error and could not read data fom packet: In if \n");
					if (errno == error_nomem) {
						strerr_die2x(111,FATAL,"out of memory");
					}
					errorcode = DNS_RCODE_SRVFAIL;
					log_default( VERBOSE, "Error and could not read data fom packet: Exiting if \n");
				} else if (!errorcode){
					log_default( VERBOSE, "Going to add DNS message\n");
					caching=add_dns_message ( &messageList, AUTH, resMsg );	
					log_default ( VERBOSE, "Added authoritative message? %d\n", caching);
					log_default ( NORMAL, "Cache size=%d\n", cache_size(messageList));
					if (ondemand){
						char* packet = 0;
						packDNSMessage ( resMsg, &packet);
						Message* message = (Message *)malloc (sizeof (Message));
						assert (message!=NULL);

						message->type = DNS_BROADCAST;
						message->payloadSize = resMsg->length;
						message->payload= packet;
						send_message ( extiofd1->fd, message);
						free (packet);
					}
				}

				/*	if (!errorcode && enablesigning && !addSignatures(resMsg)) {
					if (errno == error_nomem) {
					strerr_die2x(111,FATAL,"out of memory");
					}
					errorcode = DNS_RCODE_SRVFAIL;
					}*/

				if (errorcode) {	
					log_default( VERBOSE, "Error but read data from packet: In 3rd if \n");
					log_default( VERBOSE, "Freeing DNS message\n");
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
				//	log_default(NORMAL,"Response message:%s\n", resMsg->qdata);

				if (sendto(qrysockfd, resbuf, resbuflen, MSG_DONTWAIT, (struct sockaddr *) &querystate[i].sa, querystate[i].sasize) < resbuflen) {
					strerr_die2sys(111,FATAL,"unable to write to udp socket ");
				}
				log_default(NORMAL,"Reflecting DNS response  on socket %d\n", qrysockfd);
				uint64 timetaken = (querystate[i].ended.tv_sec - querystate[i].started.tv_sec) * 1000000 + querystate[i].ended.tv_usec - querystate[i].started.tv_usec;
				log_default(NORMAL,"COSEC: resolved query ");
				log_name( NORMAL, querystate[i].qryMsg->qdata);
				log_default(NORMAL," type %d rcode %d length %d time %lu\n", getshort(querystate[i].qryMsg->qdata+querystate[i].qryMsg->length-16), ((Flags3 *)resMsg->header.flags3)->rcode, resMsg->length, timetaken);  


				fflush(stdout);

				if (querystate[i].response != 0) {
					free(querystate[i].response);
					querystate[i].response = 0;
				}
				free(resbuf);
				free(querystate[i].qryMsg);
				if (!caching)
					freeDNSMessage(&resMsg);
			}
		}

		if (pipeiofd->revents) {
			read(pipefd[0], pipebuf, sizeof(pipebuf)) > 0;
			log_default(VERBOSE,"Read data on a pipe\n");
		}

		while (numactive < maxqueries && qryiofd && qryiofd->revents) {
			log_default(NORMAL,"Got a query to read on socket=%d\n", qryiofd->fd);
			for (i=0; querystate[i].valid; i++);

			int nread;
			querystate[i].sasize = sizeof(querystate[i].sa);
			log_default(VERBOSE,"Reading query on socket=%d\n", qrysockfd);
			if ((nread = recvfrom(qrysockfd, qrybuf, COSEC_QRYBUF_LEN, MSG_DONTWAIT, (struct sockaddr *)&querystate[i].sa, (socklen_t *)&querystate[i].sasize)) < 0) {
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

				log_default(NORMAL,"COSEC: failed to resolve query rcode %d length %d\n", ((Flags3 *)resMsg->header.flags3)->rcode, resbuflen);  
				fflush(stdout);

				free(resbuf);
				if (qryMsg != 0) {
					free(qryMsg);
				}
				freeDNSMessage(&resMsg);
			}
			else {
				/*
					int duplicate = 0;
					int j;
					for (j=0; j<maxqueries; j++) {
					if (querystate[j].valid && byte_equal(querystate[j].qryMsg->header.id, 2, qryMsg->header.id)) {
					duplicate = 1;
					break;
					}
					}
					if (duplicate) {
					free(qryMsg);
					continue;
					}
				 */

				log_default(NORMAL,"Got a valid DNS query\n");
				log_default(NORMAL,"Query data:%s\n", qryMsg->qdata);
				log_query_msg ( NORMAL, qryMsg);
				log_name ( NORMAL, qryMsg->qdata);
				char* qdata = qryMsg->qdata;
				responseMsg = get_dns_message ( messageList, qryMsg);
				if (responseMsg!=NULL) {
					log_default ( VERBOSE, "Answering out of cache\n");
					log_DNSMessage ( VERBOSE, responseMsg);
					isCached = 1;
				} else {
					log_default (VERBOSE, "Not in cache\n");
				}
				querystate[i].valid = 1;
				querystate[i].done = 0;
				querystate[i].isCached = isCached;
				querystate[i].qryMsg = qryMsg;
				gettimeofday(&querystate[i].started,(struct timezone *) 0);
				numactive++;

				log_default( VERBOSE, "Reflecting query on socket=%d\n", querystate[i].iofd);
				int retVal;
				if (!isCached) {
					log_default ( VERBOSE, "Querying legacy DNS\n");
					retVal = query_start(&querystate[i].q, qryMsg->qdata, qryMsg->qdata+qryMsg->length-16, qryMsg->qdata+qryMsg->length-14, "\0\0\0\0");
				}
				else{
					log_default (VERBOSE, "Using the cache\n");
					retVal = 1;
					char* packet = response;
					int packetLength;
					packDNSMessage ( responseMsg, &packet);
					response_len = responseMsg->length;
					isCached=0;
				}
				log_default ( VERBOSE, "retVal=%d\n", retVal);

				if (retVal != 0) {
					querystate[i].error = (retVal == -1) ? errno : 0;
					gettimeofday(&querystate[i].ended, (struct timezone *) 0);
					querystate[i].done = 1;
					log_default ( VVERBOSE, "Setting querystate[%d].done to 1\n", i);
					if (retVal == 1) {
						if ((querystate[i].response = alloc(response_len)) == 0) {
							strerr_die2x(111,FATAL,"out of memory");
						}
						byte_copy(querystate[i].response, response_len, response);
						querystate[i].responselen = response_len;
					}
				}

				if (write(pipefd[1], "s", 1) <= 0) {
					strerr_die2sys(111,FATAL,"error in write pipe ");
				}

			}
		}	
	}

	exit(0);
}


