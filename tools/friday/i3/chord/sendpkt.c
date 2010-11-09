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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "chord.h"

void send_data(Server *srv, Node *np, chordID *id, ushort n, uchar *data)
{
    byte buf[BUFSIZE];

    CHORD_DEBUG(5, print_send(srv, "send_data", id, np->addr, np->port)); 
    send_raw(srv, np->addr, np->port, pack_data(buf, id, n, data), buf);
}

/**********************************************************************/

void send_fs(Server *srv, ulong to_addr, ushort to_port,
	     chordID *id, ulong addr, ushort port)
{
  byte buf[BUFSIZE];

  CHORD_DEBUG(5, print_send(srv, "send_fs", id, to_addr, to_port)); 
  send_raw(srv, to_addr, to_port, pack_fs(buf, id, addr, port), buf); 
}

/**********************************************************************/

void send_fs_repl(Server *srv, ulong to_addr, ushort to_port,
		  chordID *id, ulong addr, ushort port)
{
  byte buf[BUFSIZE];

  CHORD_DEBUG(5, print_send(srv, "send_fs_repl", id, to_addr, to_port)); 
  send_raw(srv, to_addr, to_port, pack_fs_repl(buf, id, addr, port), buf);
}

/**********************************************************************/

void send_stab(Server *srv, ulong to_addr, ushort to_port,
	       chordID *id, ulong addr, ushort port)
{
  byte buf[BUFSIZE];

  CHORD_DEBUG(5, print_send(srv, "send_stab", id, to_addr, to_port)); 
  send_raw(srv, to_addr, to_port, pack_stab(buf, id, addr, port), buf);
}

/**********************************************************************/

void send_stab_repl(Server *srv, ulong to_addr, ushort to_port,
		    chordID *id, ulong addr, ushort port)
{
  byte buf[BUFSIZE];

  CHORD_DEBUG(5, print_send(srv, "send_stab_repl", id, to_addr, to_port)); 
  send_raw(srv, to_addr, to_port, pack_stab_repl(buf, id, addr, port), buf);
}

/**********************************************************************/

void send_notify(Server *srv, ulong to_addr, ushort to_port,
		 chordID *id, ulong addr, ushort port)
{
  byte buf[BUFSIZE];

  CHORD_DEBUG(5, print_send(srv, "send_notify", id, to_addr, to_port)); 
  send_raw(srv, to_addr, to_port, pack_notify(buf, id, addr, port), buf);
}

/**********************************************************************/

void send_ping(Server *srv, ulong to_addr, ulong to_port,
	       ulong addr, ushort port, ulong time)
{
  byte buf[BUFSIZE];

  CHORD_DEBUG(5, print_send(srv, "send_ping", NULL, to_addr, to_port)); 
  send_raw(srv, to_addr, to_port, pack_ping(buf, addr, port, time), buf);
}

/**********************************************************************/

void send_pong(Server *srv, ulong to_addr, ulong to_port, ulong time)     
{
  byte buf[BUFSIZE];

  CHORD_DEBUG(5, print_send(srv, "send_pong", &srv->node.id, to_addr, to_port)); 
  send_raw(srv, to_addr, to_port, 
	   pack_pong(buf, & srv->node.id, 
		     srv->node.addr, srv->node.port, time), buf);
}


/**********************************************************************/

void send_get_fingers(Server *srv, ulong to_addr, ulong to_port,
		      ulong addr, ushort port, ulong time)
{
  byte buf[BUFSIZE];

  CHORD_DEBUG(5, print_send(srv, "send_get_fingers", NULL, to_addr, to_port)); 
  send_raw(srv, to_addr, to_port, 
	   pack_get_fingers(buf, addr, port, time), buf);
}

/**********************************************************************/

void send_repl_fingers(Server *srv, ulong to_addr, ulong to_port, ulong time)
{
  byte buf[BUFSIZE];

  CHORD_DEBUG(5, print_send(srv, "send_repl_fingers", 
			    &srv->node.id, to_addr, to_port)); 
  send_raw(srv, to_addr, to_port, 
	   pack_repl_fingers(buf, srv, time), buf);
}



/**********************************************************************/

#ifdef SIM_CHORD

/* send_raw: send datagram to remote addr:port */
void send_raw(Server *srv, in_addr_t addr, in_port_t port, int n, uchar *buf)
{
  sim_send_raw(srv, addr, port, n, buf);
}

#else

/* send_raw: send datagram to remote addr:port */
void send_raw(Server *srv, in_addr_t addr, in_port_t port, int n, uchar *buf)
{
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = htonl(addr);

    if (sendto(srv->out_sock, buf, n, 0, (struct sockaddr *) &dest,
	       sizeof(dest)) < 0)
        weprintf("sendto failed:"); /* ignore errors for now */
}

#endif
