/* 
 * Purpose: Maintain list of i3 servers that are active.
 * Implemented as a hash table + circular array
 */

#include "i3.h"
#include "i3_id.h"
#include "i3server_list.h"
#include "qsort.h"
#include "debug.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

pthread_mutex_t i3server_list_mutex = PTHREAD_MUTEX_INITIALIZER;
int i3server_list_lock()
{
#ifndef __CYGWIN__
    if (pthread_mutex_lock(&i3server_list_mutex)) {
	fprintf(stderr, "i3server_list_mutex: problem with locking mutex\n");
	return 1;
    }
#endif
    return 0;
}
int i3server_list_unlock()
{
#ifndef __CYGWIN__
    if (pthread_mutex_unlock(&i3server_list_mutex)) {
	fprintf(stderr, "i3server_list_mutex: problem with unlocking mutex\n");
	return 1;
    }
#endif
    return 0;
}

/***************************************************************************
 * Purpose: To hash an i3 server to a location in the hash table
 *
 * Notes: Uses only addr
 **************************************************************************/
#define AH_MULTIPLIER 31
static uint32_t i3server_hash(uint32_t addr, uint32_t n)
{
    uint32_t	h = 0;
    int32_t 	i; 
    unsigned char *b;
   
    b = (unsigned char *) &addr;
    for (i = 0; i < 4; i++)
	h = AH_MULTIPLIER * h + b[i];
    
    return h % n;
}


/***************************************************************************
 * Purpose: To initialize an i3server node structure
 **************************************************************************/
I3ServerListNode *init_i3server_node(uint32_t addr, uint16_t port, ID id)
{
    I3ServerListNode	*node;
    uint32_t		h;

    h = i3server_hash(addr, I3SERVERHASH);
    
    node = (I3ServerListNode *) malloc(sizeof(I3ServerListNode));
    node->addr = addr;
    node->port = port;
    node->id = id;
    node->status = I3SERVER_ALIVE;
    node->head = 0; node->n = 0;

    return node;
}


/***************************************************************************
 * Purpose: Init i3 server list entries
 **************************************************************************/
void init_i3server_list(I3ServerList *i3list)
{
    int i;
    
    i3server_list_lock();
    
    i3list->num_i3servers = 0;
    i3list->list = NULL;
    for (i = 0; i < I3SERVERHASH; i++)
	i3list->hash[i] = NULL;
    
    i3list->num_newservers = 0;
    i3list->full_list = NULL;

    i3server_list_unlock();
}


/***************************************************************************
 * Purpose: Delete i3 servers that are old
 * 	a) delete_i3server_hash -- from hash table
 * 	b) delete_dead_i3servers -- from list
 **************************************************************************/
static I3ServerListNode *delete_i3server_hash(I3ServerList *list, 
					uint32_t addr, uint16_t port)
{
    I3ServerListNode	*node, *prev;
    uint32_t		h;
    int			deleted_hash = 0;
    
    h = i3server_hash(addr, I3SERVERHASH);
    
    for (node = list->hash[h], prev = 0;
	    node != NULL;
	    node = node->next_hash)
    {
	if (addr == node->addr) {
	    deleted_hash = 1;
	    if (prev == 0)
		list->hash[h] = node->next_hash;
	    else 
		prev->next_hash = node->next_hash;
	    break;
	}
	prev = node;
    }
    
    assert(1 == deleted_hash);
    return node;
}

void delete_dead_i3servers(I3ServerList *i3list)
{
    I3ServerListNode *curr, *prev;
    
    i3server_list_lock();
    
    prev = NULL; curr = i3list->list; 
    while (curr != NULL) {
	if (I3SERVER_DEAD == curr->status) {
	    I3ServerListNode *to_delete = curr;
	    delete_i3server_hash(i3list, curr->addr, curr->port);
	    if (NULL == prev) {
		i3list->list = curr->next_list;
	    } else {
		prev->next_list = curr->next_list;
	    }
	    curr = curr->next_list;
	    free(to_delete);
	    i3list->num_i3servers--;
	} else {
	    prev = curr; curr = curr->next_list;
	}
    }

    prev = NULL; curr = i3list->full_list;
    while (curr != NULL) {
	if (I3SERVER_DEAD == curr->status) {
	    I3ServerListNode *to_delete = curr;
	    if (NULL == prev) {
		i3list->full_list = curr->next_list;
	    } else {
		prev->next_list = curr->next_list;
	    }
	    curr = curr->next_list;
	    free(to_delete);
	    i3list->num_newservers--;
	} else {
	    prev = curr; curr = curr->next_list;
	}
    }

    i3server_list_unlock();
}


/***************************************************************************
 * Purpose: To update components of server list with a node
 **************************************************************************/
void update_list_with_node(I3ServerList *list, I3ServerListNode *node)
{
    uint32_t h = i3server_hash(node->addr, I3SERVERHASH);

    list->num_i3servers++;
    
    node->next_hash = list->hash[h];
    list->hash[h] = node;
    
    node->next_list = list->list;
    list->list = node;
}


/***************************************************************************
 * Purpose: Create new entry for a new i3 server
 **************************************************************************/
I3ServerListNode *create_i3server(I3ServerList *list,
 			uint32_t addr, uint16_t port, ID id)
{
    I3ServerListNode *node = init_i3server_node(addr, port, id);
    update_list_with_node(list, node);
    return node;
}


/***************************************************************************
 * Purpose: To update ping information when a packet is received
 **************************************************************************/
int update_list(I3ServerList *list, uint32_t addr, uint16_t seq, uint64_t rtt)
{
    uint32_t		h;
    I3ServerListNode	*node;

    i3server_list_lock();
    
    h = i3server_hash(addr, I3SERVERHASH);
    for (node = list->hash[h]; node != NULL; node = node->next_hash) {
	if (addr == node->addr) {
	    int index = node->head;
	    node->ping_info[index].seq = seq;
	    node->ping_info[index].rtt = rtt;
	    node->head = (node->head + 1) % HISTORY_SIZE;
	    if (node->n < HISTORY_SIZE)
		node->n++;
	    i3server_list_unlock();
	    return 1;
	}
    }

    i3server_list_unlock();
    return 0;
}

/***************************************************************************
 * Purpose: Lookup an i3 server from list. If *refresh is TRUE, the
 * 	server entry is refreshed. If entry does not exist, it is created.
 *	If it is created, refresh remains TRUE, else is set to FALSE.
 **************************************************************************/
I3ServerListNode *update_i3server(I3ServerList *list,
				uint32_t addr, uint16_t port, ID id)
{
    uint32_t		h;
    I3ServerListNode	*node;
 
    i3server_list_lock();
    h = i3server_hash(addr, I3SERVERHASH);
    for (node = list->hash[h]; node != NULL; node = node->next_hash) {
	if (addr == node->addr) {
	    node->port = port;
	    node->id = id;
	    node->status = I3SERVER_ALIVE;
	    i3server_list_unlock();
	    return node;
	}
    }

    for (node = list->full_list; node != NULL; node = node->next_list) {
	if (addr == node->addr) {
	    node->port = port;
	    node->id = id;
	    node->status = I3SERVER_ALIVE;
	    i3server_list_unlock();
	    return node;
	}
    }
    
    i3server_list_unlock();

    return add_to_new_i3servers(list, addr, port, id);
}


/***************************************************************************
 * Purpose: Print the chord ring of the servers
 **************************************************************************/
void print_i3servers(I3ServerList *list)
{
    I3ServerListNode *node;
    struct in_addr ia;
    printf("Printing list of all entries\n");
    
    for (node = list->list;
	    node != 0;
	    node = node->next_list) {
	ia.s_addr = htonl(node->addr);
	printf("(%s:%d)  ", inet_ntoa(ia), node->port);
    }
    printf("\n");

    for (node = list->full_list;
	    node != 0;
	    node = node->next_list) {
	ia.s_addr = htonl(node->addr);
	printf("(%s:%d)  ", inet_ntoa(ia), node->port);
    }
    printf("\n");
}

void mark_i3servers_dead(I3ServerList *list)
{
    I3ServerListNode	*node;
    
    for (node = list->list;
	    node != NULL;
	    node = node->next_list) {
	node->status = I3SERVER_DEAD;
    }

    for (node = list->full_list;
	    node != NULL;
	    node = node->next_list) {
	node->status = I3SERVER_DEAD;
    }
}


/***************************************************************************
 * Purpose: get closest node and its rtt
 *	a) get_rtt -- gets rtt for a single node.  picks median of the 
 *	   last k tries subject to the fact that loss < THRES_LOSS
 *	b) get_closest -- 
 *		(i) of all nodes, get lowest rtt
 *		(ii) get rtt of previous best node
 **************************************************************************/
#define MAX_RTT 10*1000000ULL
#define THRES_LOSS 0.4
uint64_t get_rtt_node(I3ServerListNode *node)
{
    struct in_addr ia;
    int i, start, total;
    int n_lost = 0, prev_seq;
    uint64_t median_rtt, rtt_arr[HISTORY_SIZE];
    
    if (0 == node->n) {
	ia.s_addr = htonl(node->addr);
	return MAX_RTT;
    }
    
    /* sort */
    for (i = 0; i < node->n; i++)
	rtt_arr[i] = node->ping_info[i].rtt;
    qksort(rtt_arr, 0, node->n-1);
    median_rtt = rtt_arr[node->n/2];
    
    /* check number of lost packets */
    if (node->n < HISTORY_SIZE) {
	i = 0; start = 1; total = node->n-1;
    } else {
	i = node->head; 
	start = (node->head + 1) % HISTORY_SIZE;
	total = HISTORY_SIZE-1;
    }
    prev_seq = node->ping_info[i].seq;
    for (i = 0; i < total; i++) {
	int index = (start + i) % HISTORY_SIZE;
	n_lost += (node->ping_info[index].seq - prev_seq - 1);
	prev_seq = node->ping_info[index].seq;
    }
    if (n_lost > (int)(THRES_LOSS * HISTORY_SIZE)) {
	DEBUG(11, "Too many losses -- ignoring: %d, %d\n",
		n_lost, (int)(THRES_LOSS * HISTORY_SIZE));
	return MAX_RTT;
    }

    /* return median */
    return median_rtt;
}

int sort_list(I3ServerList *list,
	       I3ServerListNode *sorted_list[], uint64_t sorted_rtt[])
{
    I3ServerListNode *curr; 
    int num = 0, i, j;
    uint64_t temp_rtt;
 
    for (curr = list->list; curr != NULL; curr = curr->next_list) {
	sorted_list[num] = curr;
	sorted_rtt[num] = get_rtt_node(curr);
	num++;
    }

    for (i = 1; i < num; i++)
	for (j = 0; j < num - i; j++) {
	    if (sorted_rtt[j] > sorted_rtt[j+1]) {
		temp_rtt = sorted_rtt[j];
		sorted_rtt[j] = sorted_rtt[j+1];
		sorted_rtt[j+1] = temp_rtt;

		curr = sorted_list[j];
		sorted_list[j] = sorted_list[j+1];
		sorted_list[j+1] = curr;
	    }
	}

    return num;
}

int get_top_k(I3ServerList *list, int k,
		uint32_t best_addr[], uint16_t best_port[], uint64_t best_rtt[])
{
    I3ServerListNode *sorted_list[MAX_I3_SERVERS];
    uint64_t sorted_rtt[MAX_I3_SERVERS];
    int num, i;

    i3server_list_lock();
    num = sort_list(list, sorted_list, sorted_rtt);
    i3server_list_unlock();
   
    for (i = 0; i < num; i++) {
	if (i >= k)
	    return k;
	best_addr[i] = sorted_list[i]->addr;
	best_port[i] = sorted_list[i]->port;
	best_rtt[i] = sorted_rtt[i];
    }
    return num;
}

uint64_t get_rtt(I3ServerList *list, uint32_t addr)
{
    uint32_t		h;
    I3ServerListNode	*node;
 
    i3server_list_lock();
    h = i3server_hash(addr, I3SERVERHASH);
    for (node = list->hash[h]; node != NULL; node = node->next_hash) {
	if (addr == node->addr) {
	    i3server_list_unlock();
	    return get_rtt_node(node);
	}
    }
    i3server_list_unlock();
    return MAX_RTT;
}

int get_top_k_id(I3ServerList *list, int k,
		ID best_id[], uint64_t best_rtt[])
{
    I3ServerListNode *sorted_list[MAX_I3_SERVERS];
    uint64_t sorted_rtt[MAX_I3_SERVERS];
    int num, i;

    i3server_list_lock();
    num = sort_list(list, sorted_list, sorted_rtt);
    i3server_list_unlock();
   
    for (i = 0; i < num; i++) {
	if (i >= k)
	    return k;

	best_id[i] = sorted_list[i]->id;
	best_rtt[i] = sorted_rtt[i];
    }
    return num;
}

int is_between(ID *middle, ID *start, ID *end)
{
    int a = compare_ids(start, middle);
    int b = compare_ids(middle, end);
    int c = compare_ids(end, start);

    if ((a <= 0 && b < 0) || (a <= 0 && c < 0) || (b < 0 && c < 0))
	return 1;
    else
	return 0;
}

uint64_t get_rtt_id(I3ServerList *list, ID *id)
{
    int start = 1;
    I3ServerListNode    *node;
    ID closestID;
    uint64_t closestRTT = MAX_RTT;
    
    i3server_list_lock();
    for (node = list->list; node != NULL; node = node->next_list) {
	if (start || is_between(&(node->id), id, &closestID)) {
	    closestID = node->id;
	    closestRTT = get_rtt_node(node);
	    start = 0;
	}
    }
    i3server_list_unlock();
    return closestRTT;
}

/***************************************************************************
 * Purpose: Find next element in the list that is alive
 **************************************************************************/
I3ServerListNode *find_next_alive(I3ServerList *list, I3ServerListNode *curr)
{
    while (NULL != curr) {
	if (I3SERVER_ALIVE == curr->status)
	    return curr;
	curr = curr->next_list;
    }

    curr = list->list;
    while (NULL != curr) {
	if (I3SERVER_ALIVE == curr->status)
	    return curr;
	curr = curr->next_list;
    }

    return NULL;
}

/***************************************************************************
 * Purpose: Remove low-performance i3 servers from list. Limit size to top-K
 **************************************************************************/
void remove_bad_i3servers(I3ServerList *list)
{
    I3ServerListNode *sorted_list[MAX_I3_SERVERS], *prev, *curr;
    uint64_t sorted_rtt[MAX_I3_SERVERS];
    int num, i;

    num = sort_list(list, sorted_list, sorted_rtt);
 
    for (i = 0; i < num; i++) {
	struct in_addr ia;
	ia.s_addr = htonl(sorted_list[i]->addr);
	if (i >= MAX_I3_SERVERS - NUM_TO_PURGE)
	    sorted_list[i]->status = I3SERVER_DEAD;
	else
	    sorted_list[i]->status = I3SERVER_ALIVE;
    }

    prev = NULL; curr = list->list; 
    while (curr != NULL) {
	if (I3SERVER_DEAD == curr->status) {
	    I3ServerListNode *to_move = curr;
	    delete_i3server_hash(list, curr->addr, curr->port);
	    if (NULL == prev) {
		list->list = curr->next_list;
	    } else {
		prev->next_list = curr->next_list;
	    }
	    curr = curr->next_list;
	    list->num_i3servers--;

	    to_move->next_list = list->full_list;
	    list->full_list = to_move;
	    list->num_newservers++;
	} else {
	    prev = curr; curr = curr->next_list;
	}
    }
    
    DEBUG(20, "After deletion (num servers = %d, %d)\n",
	    list->num_i3servers, list->num_newservers);
}

I3ServerListNode *add_to_new_i3servers(I3ServerList *list,
			uint32_t addr, uint16_t port, ID id)
{
    I3ServerListNode *node = init_i3server_node(addr, port, id);

    /* update components of server list */
    list->num_newservers++;

    node->next_list = list->full_list;
    list->full_list = node;

    return node;
}

void add_new_i3servers_to_ping(I3ServerList *list, I3ServerListNode **next_ping)
{
    int i, r, num, num_added;
    I3ServerListNode *node, *prev;

    remove_bad_i3servers(list);

    num = MAX_I3_SERVERS - list->num_i3servers;
    if (list->num_newservers > 0) {
	r = rand() % list->num_newservers;
	node = list->full_list;
	prev = NULL;
	
	DEBUG(20, "Num full servers = %d, r = %d\n", list->num_newservers, r);
	for (i = 0; i < r; i++) {
	    prev = node;
	    node = node->next_list;
	}
    }

    i3server_list_lock();
    num_added = 0;
    while (list->num_newservers > 0) {
	I3ServerListNode *tomove;

	if (num_added >= num)
	    break;
	
	if (NULL == node) {
	    node = list->full_list;
	    prev = NULL;
	}
	tomove = node;
	node = node->next_list;
	
	/* remove node from new list */
	if (NULL == prev) {
	    list->full_list = node;
	} else {
	    prev->next_list = node;
	}
	list->num_newservers--;
	
	/* add node to list */
	tomove->head = 0; tomove->n = 0;
	update_list_with_node(list, tomove);

	num_added++;
    }
    i3server_list_unlock();

    *next_ping = list->list;
}
