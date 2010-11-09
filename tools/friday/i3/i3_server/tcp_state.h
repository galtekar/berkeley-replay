#ifndef _TCP_STATE_H
#define _TCP_STATE_H

#include <netdb.h>
#ifdef __APPLE__
#include <inttypes.h>  // Need uint32_t
#endif

/*************************************************************
 *  Maintain TCP State
 ************************************************************/

/* Purpose: maintains mapping between host real addr:real port 
 * 	and fd that the tcp conn to that host has */
typedef struct TCPState {
    uint32_t	addr;	// addr of the end-host
    uint16_t	port;	// port
    int		fd;	// tcp fd corresponding to the host

    struct TCPState *next;	// maintain linked list
} TCPState;
/*  Lookup TCP state if create is 0, else insert that state */
void lookup_tcp_state(TCPState *list, uint32_t addr, uint16_t port, int *fd);
void insert_tcp_state(TCPState **list, uint32_t addr, uint16_t port, int fd);
/*  Delete TCP state. Returns -1 if unsuccessful, 1 if success */
int delete_tcp_state(TCPState **list, uint32_t addr, uint16_t port);


/*************************************************************
 *  Manage sockets, receive data etc.
 ************************************************************/

/* Add sockets from the array to fdset. Ret value is number of sockets */
int add_open_tcp_sockets(TCPState *list, fd_set *rset, int *max_fd);
/* Accept new TCP connections */
int accept_tcp_connection(TCPState **list, int fd);
/* Check if data received on any of the sockets and if so call functions */
int check_open_tcp_sockets(TCPState **list, fd_set *rset,
		char *p, int *len, struct sockaddr_in *addr);


#endif
