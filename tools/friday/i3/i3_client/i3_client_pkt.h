/***************************************************************************
                          i3_client_pkt.h  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_CLIENT_PKT_H
#define I3_CLIENT_PKT_H
 
/* functions implemented in i3_client_pkt.c */
void cl_send_data_packet(cl_context *ctx, i3_stack *stack,
		cl_buf *clb, uint8_t opts, char is_total_len);
void cl_send_packet(cl_context *ctx, i3_header *header,
				cl_buf *clb, uint8_t opts); 
void cl_sendto(cl_context *ctx, char *pkt, uint16_t pkt_len, 
    		cl_id *cid, ID *id);
void cl_receive_packet(cl_context *ctx, i3_header **phdr, cl_buf *clb);
void make_data_opt(cl_context *ctx, uint8_t opts_mask, buf_struct *b);

#endif
