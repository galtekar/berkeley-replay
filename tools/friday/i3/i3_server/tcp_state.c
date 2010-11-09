#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "tcp_state.h"
#include "i3_tcp_fns.h"
#include "../utils/gen_utils.h"
#include "../utils/byteorder.h"

/* Purpose: Lookup TCP state if create is 0, else insert that state
 *   create remains 1 if it is created, else it is turned to zero if found */
void lookup_insert_tcp_state(TCPState **list, uint32_t addr,
			uint16_t port, int *fd, int create)
{
    TCPState *tcpstate, *curr, *prev;

    assert(NULL != list);
    
    /* Run through the list */
    for (curr = *list, prev = NULL;
	    curr != NULL;
	    prev = curr, curr = curr->next) {
	/* Match found */
	if (curr->addr == addr && curr->port == port) {
	    assert(0 == create);
	    *fd = curr->fd;
	    return;
	}
    }

    /* Match not found */
    if (0 == create) {
	*fd = -1;
	return;
    }

    /* Create a new entry */
    tcpstate = (TCPState *) malloc(sizeof(TCPState));
    tcpstate->addr = addr;
    tcpstate->port = port;
    tcpstate->fd = *fd;
    tcpstate->next = *list;
    *list = tcpstate;
}
void lookup_tcp_state(TCPState *list, uint32_t addr, uint16_t port, int *fd)
{
    lookup_insert_tcp_state(&list, addr, port, fd, 0);
}
void insert_tcp_state(TCPState **list, uint32_t addr, uint16_t port, int fd)
{
    lookup_insert_tcp_state(list, addr, port, &fd, 1);
}

/* Purpose: Delete TCP state */
int delete_tcp_state(TCPState **list, uint32_t addr, uint16_t port)
{
    TCPState *curr, *prev;

    assert(NULL != list);
    
    /* Run through the list */
    for (curr = *list, prev = NULL;
	    curr != NULL;
	    prev = curr, curr = curr->next) {
	/* Match found */
	if (curr->addr == addr && curr->port == port) {
	    if (NULL == prev) {
		*list = curr->next;
	    } else {
		prev->next = curr->next;
	    }
	    
	    free(curr);
	    return 1;
	}
    }

    return -1;
}

int delete_tcp_state_fd(TCPState **list, int fd)
{
    TCPState *curr, *prev;

    assert(NULL != list);
    
    /* Run through the list */
    for (curr = *list, prev = NULL;
	    curr != NULL;
	    prev = curr, curr = curr->next) {
	/* Match found */
	if (curr->fd == fd) {
	    if (NULL == prev) {
		*list = curr->next;
	    } else {
		prev->next = curr->next;
	    }
	    
	    free(curr);
	    return 1;
	}
    }

    return -1;
}


/* Purpose: Add sockets from the array to fdset */
int add_open_tcp_sockets(TCPState *list, fd_set *rset, int *max_fd)
{
    TCPState *curr;
    int tcp_max = -1;
    int count;

    /* Run through the list */
    for (curr = list, count = 0; curr != NULL; curr = curr->next, count++) {
	FD_SET(curr->fd, rset);
	tcp_max = max(tcp_max, curr->fd);
    }

    *max_fd = max(*max_fd, tcp_max + 1);
    return count;
}

/* Purpose: Accept new TCP connections */
int accept_tcp_connection(TCPState **list, int fd)
{
    struct sockaddr_in addr;
    int len = sizeof(addr);
    int new_fd;
    
    new_fd = accept(fd, (struct sockaddr *)&addr, &len);
    if (new_fd > 0) {
	/* create new tcp state */
	printf("Accepted TCP connection from (%s:%d:%d)\n",
		inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), new_fd);
	insert_tcp_state(list, ntohl(addr.sin_addr.s_addr), 
			ntohs(addr.sin_port), new_fd);
    } else {
	perror("Accept TCP connection");
    }

    return new_fd;
}

/* Purpose:  Check if data received on any of the sockets
 * 		and if so call appropriate functions.
 * Note: The first fd in the list that has data is called */
int check_open_tcp_sockets(TCPState **list, fd_set *rset,
			char *p, int *len, struct sockaddr_in *addr)
{
    TCPState *curr;

    addr->sin_family = AF_INET;
    for (curr = *list; curr != NULL; curr = curr->next) {
	/* is the fd set? */
	addr->sin_addr.s_addr = htonl(curr->addr);
	addr->sin_port = htons(curr->port);
	// printf("Checking (%s:%d): ", inet_ntoa(addr->sin_addr), curr->port);
	if (FD_ISSET(curr->fd, rset)) {
	    // printf("Yes\n");
	    if ((*len = recv_tcp(p, *len, curr->fd)) <= 0) {
		printf("Cleaning up state corresponding to fd\n");
		close(curr->fd);
		assert(-1 != delete_tcp_state_fd(list, curr->fd));
	    }	
	    return 1;
	}    
	// printf("No\n");
    }

    *len = 0;
    return 0;
}
