/* Chord server loop */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "chord.h"
#include "../utils/gen_utils.h"

/* globals */
extern Server *srv_ref;	/* For use in stabilize() */
Server srv;
Node well_known[MAX_WELLKNOWN];
int nknown;

static void initialize(void);
static void handle_packet(int network);

/**********************************************************************/

void
chord_main(char *conf_file, int parent_sock)
{
    fd_set interesting, readable;
    int nfound, nfds;
    struct in_addr ia;
    char id[4*ID_LEN];
    FILE *fp;

    setprogname("chord");
    srandom(getpid() ^ time(0));
    memset(&srv, 0, sizeof(Server));

    fp = fopen(conf_file, "r");
    if (fp == NULL)
	eprintf("fopen(%s,\"r\") failed:", conf_file);
    if (fscanf(fp, "%hd", (short*)&srv.node.port) != 1)
        eprintf("Didn't find port in \"%s\"", conf_file);

	printf("port=%d\n", srv.node.port);
    if (fscanf(fp, " %s\n", id) != 1)
        eprintf("Didn't find id in \"%s\"", conf_file);
	printf("id: %s\n", id);
    srv.node.id = atoid(id);

    /* Figure out one's own address somehow */
	printf("calling get_addr\n");
    srv.node.addr = ntohl(get_addr());

    ia.s_addr = htonl(srv.node.addr);
    fprintf(stderr, "Chord started.\n");
    fprintf(stderr, "id="); print_id(stderr, &srv.node.id); 
    fprintf(stderr, "\n");
    fprintf(stderr, "ip=%s\n", inet_ntoa(ia));
    fprintf(stderr, "port=%d\n", srv.node.port);

	printf("calling initialize\n");
    initialize();
    join(&srv, fp);
    fclose(fp);

    FD_ZERO(&interesting);
    FD_SET(srv.in_sock, &interesting);
    FD_SET(parent_sock, &interesting);
    nfds = max(srv.in_sock, parent_sock) + 1;

    /* Loop on input */
    for (;;) {
	readable = interesting;
	nfound = select(nfds, &readable, NULL, NULL, NULL);
	if (nfound < 0 && errno == EINTR) {
            continue;
	}
	if (nfound == 0) {
	    continue;
	}
	if (FD_ISSET(srv.in_sock, &readable)) {
	    handle_packet(srv.in_sock);
	}
	else if (FD_ISSET(parent_sock, &readable)) {
	    handle_packet(parent_sock);
	}
	else {
	    assert(0);
	}
    }
}

/**********************************************************************/

/* initialize: set up sockets and such <yawn> */
static void
initialize(void)
{
    int flags;
    struct sockaddr_in sin, sout;

    setservent(1);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(srv.node.port);
    sin.sin_addr.s_addr = htonl(INADDR_ANY);

    srv.in_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv.in_sock < 0)
	eprintf("socket failed:");
   
    if (bind(srv.in_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
	eprintf("bind failed:");
	
    /* non-blocking i/o */
    flags = fcntl(srv.in_sock, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(srv.in_sock, F_SETFL, flags);

    /* outgoing socket */
    memset(&sout, 0, sizeof(sout));
    sout.sin_family = AF_INET;
    sout.sin_port = htons(0);
    sout.sin_addr.s_addr = htonl(INADDR_ANY);

    srv.out_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv.out_sock < 0)
	eprintf("socket failed:");

    if (bind(srv.out_sock, (struct sockaddr *) &sout, sizeof(sout)) < 0)
	eprintf("bind failed:");

    srv_ref = &srv;
}

/**********************************************************************/

/* handle_packet: snarf packet from network and dispatch */
static void
handle_packet(int network)
{
    int packet_len, from_len;
    struct sockaddr_in from;
    byte buf[BUFSIZE];

    from_len = sizeof(from);

    packet_len = recvfrom(network, buf, sizeof(buf), 0,
			  (struct sockaddr *) &from, &from_len);
    if (packet_len < 0) {
       if (errno != EAGAIN) {
	   weprintf("recvfrom failed:");  /* ignore errors for now */
	   return;
       }
       weprintf("handle_packet: EAGAIN");
       return;   /* pick up this packet later */
    }
    dispatch(&srv, packet_len, buf);
}
