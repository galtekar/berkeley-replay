#ifndef _I3_SERVER_PKT_H
#define _I3_SERVER_PKT_H

#ifndef __RTTI
#define __RTTI
#endif

void send_trigger_not_present(srv_context *ctx, ID *id, i3_addr *to, int sfd);
void send_trigger_reply(srv_context *ctx, 
			void * __RTTI *tarray, char *opt_type_array, 
			int tnum, i3_addr *to, int sfd);


void forward_packet_ip(srv_context *ctx, char *payload, int payload_len,
	i3_header *hdr, int header_room, i3_addr *to, int to_end_host);
void forward_packet_chord(i3_header *hdr, char *payload, int payload_len);
void forward_packet_i3(srv_context *ctx, char *payload, int payload_len,
    		i3_header *hdr, int header_room, trigger_node *t_node);


char nat_translate(srv_context *ctx, char *pkt,
		   int plen, int header_room,struct sockaddr_in* real_add);
int handle_challenge(srv_context* ctx,char* pkt,int len);;

#endif
