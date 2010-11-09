#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>   /* basic system data types */
#include <sys/socket.h>  /* basic socket definitions */
#include <arpa/inet.h>
#include <sys/time.h>    /* timeval{} for select() */
#include <errno.h>    
#include <sys/utsname.h>
#include <time.h>                /* timespec{} for pselect() */
#include <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>

#include "i3.h"
#include "i3_fun.h"
#include "i3_api.h"
#include "i3_server.h"

#if NEWS_INSTRUMENT
#include "i3_server_info.h"
#include "i3_news.h"
#include "i3_news_instrument.h"
#endif

#include "chord_api.h"
#include "../utils/utils.h"

#include "nat_table.h"
#include "i3_server_pkt.h"
#include "i3_server_utils.h"

#include "i3_monitor.h"

#define SELECT_TIME	1
#define MAXLINE		4096

unsigned short srv_port;

srv_context *srv_init_context(struct in_addr local_addr,
		uint16_t local_port)
{
	srv_context *ctx;

	if (!(ctx = (srv_context *)calloc(1, sizeof(srv_context))))
		panic("srv_init_context: memory allocation error.\n");

	/* create field descriptor and address data structure to 
	 * receive i3 traffic */
	if ((ctx->fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror ("socket"); printf("Failed to create socket\n");
		exit(-1);
	}

	bzero(&ctx->local, sizeof(struct sockaddr_in));
	ctx->local.sin_family = AF_INET;
	ctx->local.sin_addr.s_addr = htonl(INADDR_ANY);
	ctx->local.sin_port = htons(local_port);

	/* bind to the port */
	if (bind(ctx->fd, (struct sockaddr *) &ctx->local, 
				sizeof(struct sockaddr_in)) < 0) {
		panic("srv_init_context: bind (%d)\n", local_port);
	}

#define MAX_BACKLOG 5
#if (ACCEPT_TCP)
	ctx->tcp_state = NULL;
	if ((ctx->tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror ("socket"); printf("Failed to create socket\n");
		exit(-1);
	}
	if (bind(ctx->tcp_fd, (struct sockaddr *) &ctx->local,
				sizeof(struct sockaddr_in)) < 0) {
		panic("srv_init_context: tcp bind (%d)\n", local_port);
	}
	if (listen(ctx->tcp_fd, MAX_BACKLOG) < 0) {
		panic("srv_init_context: listen (%d)\n", local_port);
	}
#endif

	ctx->local_ip_addr = local_addr; // keep it in host format 

	ctx->trigger_hash_table = alloc_trigger_hash_table();

	ctx->id_cache = srv_alloc_id_array();

	return ctx;
}

/* periodically refresh server context */
void srv_refresh_context(srv_context *ctx)
{
	gettimeofday(&(ctx->now), NULL);
}

void process_options(srv_context *ctx, i3_header *hdr, 
		int return_address, i3_addr **ret_addr,
		int process_local, int process_nonlocal,
		char *payload, int *payload_len,
		char natted, i3_addr* real_addr)
{
#define BUF_REPLY_SIZE 1500
#define MAX_TRIGGERS   25 /* maximum number of trigger in packet--arbitrary */
	i3_option  *option;
	void *t[MAX_TRIGGERS]; /* array of triggers in the option list
							* that have to be challenged or acked
							*/
	char        opt_type[MAX_TRIGGERS];
	int         t_idx = 0;
	i3_addr    *ret_a = NULL; /* should be only one returning address in the 
								 option list */
	i3_addr* fake_addr;
	i3_trigger *to_insert_trigger = NULL; // addition to store ret_a in trigger

	if (NULL == hdr->option_list)
		return;

	for (option = hdr->option_list->head; option; option = option->next) {
		if (!is_valid_option(option)) {
			printf("process_options: invalid option type: %d\n", 
					option->type);    
		}

		if (process_local) {
			switch (option->type) {
				case I3_OPT_TRIGGER_INSERT: 
					printf("Attempting inserting trigger\n");
					if (t_idx >= MAX_TRIGGERS) {
						printf("process_options: too many triggers!\n");
						break;
					}

					/* check trigger constraints */
					if (! check_constraint(option->entry.trigger))
					{
						printf("Constraint check failed\n");
						opt_type[t_idx] = I3_OPT_CONSTRAINT_FAILED;
					}
					else 
					{
						if (natted && option->entry.trigger->to->type == I3_ADDR_TYPE_IPv4)
						{
							fake_addr = option->entry.trigger->to;
							option->entry.trigger->to = real_addr;
						}

						/* check nonce on packet */
						if (check_nonce(option->entry.trigger))
						{
							printf("Inserting trigger for \n");
							printf_i3_id(&(option->entry.trigger->id),2);

							// addition to store ret_a in trigger
							to_insert_trigger = duplicate_i3_trigger(option->entry.trigger);
							opt_type[t_idx] = I3_OPT_TRIGGER_ACK;
						}
						else
						{
							opt_type[t_idx] = I3_OPT_TRIGGER_CHALLENGE;
							update_nonce(option->entry.trigger);
						}

						if ( natted && option->entry.trigger->to->type == I3_ADDR_TYPE_IPv4)
							option->entry.trigger->to = fake_addr;
					}

					t[t_idx] = option->entry.trigger;
					t_idx++;
					break;

				case I3_OPT_REQUEST_FOR_CACHE:
					opt_type[t_idx] = I3_OPT_CACHE_ADDR;
					t[t_idx] = &hdr->stack->ids[0];
					t_idx++;
					break;

				case I3_OPT_TRIGGER_REMOVE:
					/* NAT ADDITION */

					/*  If the trigger removal packet has the right nonce and the
					 *  RHS of the trigger is a IP address, then remove state
					 *  (trigger,R's real addr) */

					if ( natted && option->entry.trigger->to->type == I3_ADDR_TYPE_IPv4)
					{
						fake_addr = option->entry.trigger->to;
						option->entry.trigger->to = real_addr;
					}

					if (check_nonce(option->entry.trigger))
					{
						remove_trigger(ctx->trigger_hash_table,option->entry.trigger);
					}

					if ( natted && option->entry.trigger->to->type == I3_ADDR_TYPE_IPv4)
						option->entry.trigger->to = fake_addr;

					break;

				case I3_OPT_SENDER:
					/* this is the sender address, where replies are sent */
					ret_a = option->entry.ret_addr;
					if (return_address && ret_addr) {
						*ret_addr = duplicate_i3_addr(ret_a);
					}
					break;

				case I3_OPT_CACHE_ADDR:
					srv_insert_id_entry(ctx->id_cache,
							&option->entry.trigger->id,
							option->entry.trigger->to, &ctx->now);
					break;

				case I3_OPT_TRIGGER_NOT_PRESENT:

					/* there is no trigger with ID t, where
					 * t.id==option->entry.id, in the infrastructure; remember to
					 * remove all triggers pointing to t.id next time a packet
					 * with this ID is processed */

					srv_update_pback_table(ctx, option->entry.id);
					break;

					//case I3_OPT_GET_RANGE:
					/* get the range of ids that this i3 server is responsible for */

					//break;

				default:
					break;
			}
		}

		/* insert trigger if needed */
		if (to_insert_trigger) {
			insert_trigger(ctx->trigger_hash_table,
					to_insert_trigger, ret_a, ctx->now.tv_sec);
			free_i3_trigger(to_insert_trigger);
		}

		/* send reply if needed */
		if (ret_a && t_idx) {
			send_trigger_reply(ctx, t, opt_type, t_idx, ret_a, ctx->fd);
		}

		if (process_nonlocal) {    
			assert(NULL != payload && NULL != payload_len);
			switch (option->type) {
#if NEWS_INSTRUMENT
				case I3_OPT_LOG_PACKET:
					log_news_pkt(payload, *payload_len);
					break;

				case I3_OPT_APPEND_TS:
					append_local_ts(ctx, payload, payload_len);
					break;
#else
					/* No non-local options defined yet */
#endif
				default:
					break;
			}
		}
	}
}

void process_options_local(srv_context *ctx, i3_header *hdr, i3_addr **ret_addr, char natted, i3_addr* real_addr)
{
	process_options(ctx, hdr, 1, ret_addr, 1, 0, 0, 0, natted, real_addr);
}

void process_options_nonlocal(srv_context *ctx, i3_header *hdr,
		char *payload, int *payload_len)
{
	process_options(ctx, hdr, 0, 0, 0, 1, payload, payload_len,0,NULL);
}

/***************************************************************************
 *
 * Purpose: Further processing on a packet. eg. matching, forwarding etc.
 *
 * Caveat: Make sure at the end hdr does not get deleted twice!
 * 	e.g. add sth like if (hdr!= 0) delete.
 * 
 **************************************************************************/
void process_packet_further(srv_context *ctx, char *payload,
		int payload_len, i3_header *hdr, 
		int header_room, i3_addr *ret_addr,
		trigger_node *t_node)
{
	ID	*id = hdr->stack->ids;

	/* if local, lookup and process, else fwd along i3 */
	if (is_id_local((ID *)id,ctx)) {
		ptree_node	*pt;
		unsigned int	prefix_len;

#if NEWS_INSTRUMENT
		/* process non-local options such as LOG_PACKET, ADD_TS 
		 * Note: If (id1,id2) &(id1, id3) are triggers such that
		 * both id1 and id2 are on the same i3 server,
		 * then all non local options will be screwed up.
		 * This is not expected to be the case in NEWS,
		 * so we allow this (to not sacrifice efficiency).
		 * Fix: Copy payload/len and send it to
		 * process_packet_further */

		process_options_nonlocal(ctx, hdr, payload, &payload_len);
		assert(hdr->option_list != NULL);
#else
		/* TODO: Non-local options processing has not been
		 * incorporated in the code as there is no need for it yet */
#endif

		/* lookup trigger */
		pt = lookup_trigger(ctx->trigger_hash_table, (ID *)id, &prefix_len);
		pt = cleanup_ptree_node(pt, ctx->trigger_hash_table,
				(ID *)id, ctx->now.tv_sec);
		/* check if a _valid_ trigger exists */
		if ((NULL != pt) && 
				(prefix_len >= max(MIN_PREFIX_LEN,pt->tn->trigger->prefix_len))) {

			/* ret_addr is no longer relevant as no more control
			 * messages will be sent back to sender. here is replaced
			 * by address of the local i3_server */
			i3_addr *curr_addr = alloc_i3_addr();
			trigger_node	*tn, *tn_next;
			i3_addr		*to;
			init_i3_addr_ipv4(curr_addr,
					ctx->local_ip_addr, ntohs(ctx->local.sin_port));

			/* i3 small scale multicast operation */
			for (tn = pt->tn; tn; ) {
				i3_header *new_hdr;

				tn_next = tn->next;

				switch (tn->trigger->to->type) {
					case I3_ADDR_TYPE_IPv4:
					case I3_ADDR_TYPE_IPv6:
						// printf_i3_id((ID*)id,2);
						// printf("Forwarding to end-host\n");
						forward_packet_ip(ctx, payload, payload_len, 
								hdr, header_room,  tn->trigger->to, 1);
						break;

					case I3_ADDR_TYPE_STACK:
						to = tn->trigger->to;
						assert(to->t.stack->len);

						/* Pushback if no trigger found */
						if (srv_is_pback_entry(ctx, &to->t.stack->ids[0])) {
							/* ID to which this packet is to be forwarded is not
							 * present (the ID was inserted in ctx->pushback->table
							 * upon receiving an I3_OPT_TRIGGER_NOT_PRESENT option);
							 * remove trigger */  
							printf("Pushback - removing trigger\n");
							remove_trigger(ctx->trigger_hash_table, tn->trigger);
						} else {
							/* forward the packet */
							new_hdr = replace_stack(hdr, tn->trigger->to);
							if (NULL != new_hdr) {
								process_packet_further(ctx, payload, 
										payload_len, new_hdr, header_room, curr_addr, tn);
								free_i3_header(new_hdr);
							}
						}
						break;

					default:
						panic("Unknown type in trigger\n");
				}

				tn = tn_next;
			}

			free_i3_addr(curr_addr);
		} else {
			printf("Id not present, %p\n", pt);

			/* send control mesg only to other hosts/i3 nodes */
			if (NULL != ret_addr) {
				send_trigger_not_present(ctx, hdr->stack->ids, ret_addr, ctx->fd);
			}
		}   
	} else {
		assert(NULL != t_node);
		// printf("Forwarding via i3\n");
		forward_packet_i3(ctx, payload, payload_len, hdr, header_room, t_node);
	}
}



/***************************************************************************
 * 
 * Purpose: Called when a packet first arrives at an i3 node.
 *
 * Optimization: TODO
 * header_room - number of bytes that preceedes "packet" pointer
 * and which are allocated -- these can be used to avoid copying
 * the packet's payload

 *  ( to edit comment : from this point onwards, the payload is
 * maintained separately. memcpy of payload is avoided by using
 * header_room to pack the header _only_ before sending it out of
 * the node )
 *
 **************************************************************************/
void process_packet_initial(srv_context *ctx, char *packet,
		int packet_len, int header_room,
		struct sockaddr_in* real_addr)
{
	i3_header	*hdr = NULL;
	uint16_t	hdr_len;
	char		*id = get_hdr_stack(packet);
	char		firsthop;
	char 		natted;
	i3_addr	*ret_addr = NULL;
	i3_addr	*real_i3_addr;
	int ret_code;

	if ( packet_len < 3 )
		return;

	if ( packet[0] != I3_v01 || packet[1] > (I3_FIRST_HOP + I3_OPTION_LIST + I3_DATA) || packet[2] > I3_MAX_STACK_LEN )
		return;

	ret_code = check_i3_header(packet,packet_len);

	if ( ret_code != FALSE )
	{
		printf("Invalid packet: %d\n",ret_code);
		return;
	}

	/* i3 server ping HACK! XXX */
	if (is_echo_request(packet)) {
		echo_reply(ctx->fd, packet, packet_len, real_addr);
		return;
	}

	real_i3_addr = alloc_i3_addr();
	init_i3_addr_ipv4(real_i3_addr, real_addr->sin_addr, real_addr->sin_port);

	/* NAT ADDITION */

	/* Nat_translate is called before any processing is done on the packet */
	firsthop = get_first_hop(packet);
	natted = nat_translate(ctx, packet, packet_len, header_room, real_addr);
	clear_first_hop(packet);

	/*   hdr = unpack_i3_header(packet, &hdr_len); */
	/*   printf("After nat\n"); */
	/*   printf_i3_header(hdr,2); */
	/*   free_i3_header(hdr); */

	/* unpack i3 header */
	hdr = unpack_i3_header(packet, &hdr_len);

	/* no stack; this is a control packet addressed to this node, 
	 * e.g., I3_OPTION_TRIGGER_NOT_PRESENT
	 * XXX Potential process-DoS attack -- needs to be fixed */
	if (get_stack_len(packet) == 0) {

		/* Handle challenge from another i3 server for a id that we have.
		 * The packets contains a list of challenges all in response 
		 * to the same trigger insertion
		 * We will find the first challenge, find the real_addr,
		 * and send it to him */

		if (handle_challenge(ctx, packet, packet_len))
		{
			free_i3_header(hdr);
			free_i3_addr(real_i3_addr);
			return;
		}

		/* Do normal processing */
		process_options_local(ctx, hdr, 0, natted, real_i3_addr);
		free_i3_header(hdr);
		free_i3_addr(real_i3_addr);
		return;
	}

	/* if the id is not local to the machine, call basic_chord */
	if (!is_id_local((ID *)id, ctx)) {
		chordID key;
		fprintf(stderr, "is_local: FALSE\n");
		printf_i3_id((ID *)id, 2);

		memmove(key.x, get_first_id(packet), CHORD_ID_BITS/8 * sizeof(char));
		chord_route(&key, packet, packet_len);
		free_i3_addr(real_i3_addr);
		return;
	}

	/* Note: At this point, the packet is meant for this i3 server */

	/* process local options */
	if (hdr->option_list) {
		process_options_local(ctx, hdr, &ret_addr, natted, real_i3_addr);
		remove_local_i3_options(hdr->option_list);
		// XXX: Check where option list has to be freed
		// why should it be freed before the packet is completely
		// sent out for good?
	}

	/* Only data packets are served beyond this point.
	 * Further packet processing is done from a separate sub-routine */
	if (hdr->flags & I3_DATA) {
		if (!hdr->option_list)
			hdr->option_list = alloc_i3_option_list();
		//printf("Received data packet\n");
		process_packet_further(ctx, packet + hdr_len, packet_len - hdr_len,
				hdr, header_room + hdr_len, ret_addr, 0);
	}

	/* Finally, free the i3 header and ret_addr.
	 * Every packet received would go through this code.
	 * Note: hdr or any of its fields should not be freed anywhere else */
	if (NULL != hdr)
		free_i3_header(hdr);

	if (NULL != ret_addr)
		free_i3_addr(ret_addr);
	free_i3_addr(real_i3_addr);
}


static void main_loop(srv_context *ctx, unsigned short port,
		char *chord_conf_file)
{
	fd_set rset;
	int    max_fd, rc, len;
	int    chord_fd;
	struct timeval select_time;
	struct sockaddr_in cliaddr;
#define MAX_PACKET_SIZE 4096
#define PREFIX_HEADER   1024 /* used for prepenfing stack in the same buffer */
	char   packet[MAX_PACKET_SIZE+PREFIX_HEADER];
	char   *p = &packet[PREFIX_HEADER];
	ssize_t n;

	FD_ZERO(&rset);

#if (ACCEPT_TCP)
	max_fd = max(ctx->fd, ctx->tcp_fd);
#endif

	chord_fd = chord_init(chord_conf_file);

	max_fd = max(max_fd, chord_fd);


	max_fd++;

	select_time.tv_usec = 0;
	select_time.tv_sec = SELECT_TIME;

	for (;;) {
		FD_ZERO(&rset);

		FD_SET(ctx->fd, &rset);
#if (ACCEPT_TCP)
		FD_SET(ctx->tcp_fd, &rset);
		add_open_tcp_sockets(ctx->tcp_state, &rset, &max_fd);
#endif

		FD_SET(chord_fd, &rset);


#if 1
		if ((rc = select(max_fd, &rset, NULL, NULL, &select_time)) < 0) {
			if (errno == EINTR)
				continue;
			else
				err_sys("select_error\n");
		}
#endif



		if (rc > 0) {
			len = sizeof(cliaddr);
			if (FD_ISSET(ctx->fd, &rset))
				n = recvfrom(ctx->fd, p, MAX_PACKET_SIZE, 0,
						(struct sockaddr *)&cliaddr, &len);
			else if (FD_ISSET(chord_fd, &rset))
				n = recv(chord_fd, p, MAX_PACKET_SIZE, 0);

#if (ACCEPT_TCP)
			else if (FD_ISSET(ctx->tcp_fd, &rset)) {
				accept_tcp_connection(&(ctx->tcp_state), ctx->tcp_fd);
				n = 0; // to make sure process_packet_initial is not called
			}
			else {
				n = MAX_PACKET_SIZE;
				if (check_open_tcp_sockets(&(ctx->tcp_state),
							&rset, p, &n, &cliaddr) == 0) {
					assert(0);
				}
			}
#else
			else assert(0);
#endif

			if (n  < 0) perror("recvfrom error");
			else if (n > 0) {
				cliaddr.sin_addr.s_addr = ntohl(cliaddr.sin_addr.s_addr);
				cliaddr.sin_port = ntohs(cliaddr.sin_port);
				process_packet_initial(ctx, p, n, PREFIX_HEADER, &cliaddr);
			}

		}

		if ((!select_time.tv_sec) && (!select_time.tv_usec)) {
			// printf("*\n");
			srv_refresh_context(ctx);
			select_time.tv_usec = 0;
			select_time.tv_sec = SELECT_TIME;
		}
	}
}

int main(int argc, char **argv)
{
	struct hostent *hptr;
	struct utsname myname;
	struct in_addr local_addr;
	char str[INET6_ADDRSTRLEN];
	char **pptr;
	unsigned short port;
	srv_context *ctx;
	time_t starttime;

	/* ThrArg targ; */
	/* pthread_t pt; */

	aeshash_init();

	if (uname(&myname) < 0) {
		err_sys("uname error.\n");
		exit(-1);
	}

	printf("Hostname: %s\n",myname.nodename);
	time(&starttime);
	printf("Starting up at %s",ctime(&starttime));
#if 0	// geels: remove gethostbyname for now.
	if ((hptr = gethostbyname(myname.nodename)) == NULL) {
		err_sys("gethostbyname error\n");
	}

	printf("name = %s\n", hptr->h_name);
	for (pptr = hptr->h_addr_list; *pptr != NULL; pptr++) {
		printf("address = %s\n", inet_ntop(hptr->h_addrtype, 
					*pptr, str, sizeof(str)));
	}
#endif
	if (argc != 3) {
		printf("%s config_file port\n", argv[0]);
		//printf("%s config_file news_list(for servers to ping) port\n", argv[0]);
		exit(-1);
	}

	printf("Size = %d\n", sizeof(ptree_node) + sizeof(trigger_node) + sizeof(i3_trigger));

	local_addr = get_my_addr();
	srv_port = port = atoi(argv[2]);
	printf("port = %d\n", port);
	ctx = srv_init_context(local_addr, port);
	nat_table_initialize();

	// ping-i3 related
	// read_server_info(argv[2], srv_port, &(ctx->mon_list));
	// targ.list = &(ctx->mon_list);
	// Pinging is not done now. Maybe uncommented if needed
	// pthread_create(&pt, NULL, monitor_server_state, (void *) &targ);

	main_loop(ctx, port, argv[1]);   // XXX: argv[1] = chord conf file
	return -1;
}
