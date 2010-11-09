/***************************************************************************
                          i3_client_pkt.h  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>   /* basic system data types */
#include <sys/socket.h>  /* basic socket definitions */
#include <sys/time.h>    /* timeval{} for select() */
#include <sys/errno.h>    
#include <sys/utsname.h>
#include <time.h>        /* timespec{} for pselect() */
#include <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>
#include <netdb.h>

#include "i3.h"
#include "i3_fun.h"
#include "trig_binheap.h"

#include "i3_client.h"
#include "i3_client_fun.h"
#include "i3_tcp_fns.h"


void fast_pack_i3_header(char *p, char  data, 
			 i3_stack *s, char *packed_ol, 
			 unsigned short packed_ol_len); 

cl_buf *cl_alloc_buf(unsigned int len)
{
  cl_buf *clb;

  if ((clb = (cl_buf *)malloc(sizeof(cl_buf))) == NULL)
    panic("cl_alloc_buf(1): memory allocation error\n");
  
  if ((clb->internal_buf = (char *)malloc(len + 2*CL_PREFIX_LEN)) == NULL)
    panic("cl_alloc_buf(2): memory allocation error\n");
  
  clb->data = clb->internal_buf + CL_PREFIX_LEN;
  clb->max_len = len;

  return clb;
}


void cl_free_buf(cl_buf *clb)
{
  if (clb) {
    if (clb->internal_buf) 
      free(clb->internal_buf);
    free(clb);
  }
}



void cl_send_data_packet(cl_context *ctx, i3_stack *stack,
	cl_buf *clb, uint8_t opts_mask, char is_total_len)
{
  unsigned short len;
  cl_id *cid;
  int refresh;

  /* is stack->ids[0] cached ? */
  cid = cl_get_valid_id(ctx, &stack->ids[0], &refresh);
  
  /* form the complete mask using refresh also */
  opts_mask |= (refresh != 0) ? REFRESH_MASK : 0;
  assert(opts_mask < MAX_OPTS_MASK_SIZE);

  /* use appropriate precomputed option */
  len = 2 * sizeof(char) + get_i3_stack_len(stack) + 
    ctx->precomputed_opt[opts_mask].len;
  assert(len <= CL_PREFIX_LEN);
  
  fast_pack_i3_header(clb->data - len, TRUE, stack,
		      ctx->precomputed_opt[opts_mask].p,
		      ctx->precomputed_opt[opts_mask].len);
  
/*   if (refresh) { */
/*     // add both I3_OPT_SENDER and I3_OPT_REQUEST_FOR_CACHE options */
/*     len = sizeof(char) + get_i3_stack_len(stack) +  */
/*       ctx->precomputed_opt_all.len;  */
/*     assert(len <= CL_PREFIX_LEN); */
/*     fast_pack_i3_header(clb->data - len, TRUE, stack,  */
/* 			ctx->precomputed_opt_all.p,  */
/* 			ctx->precomputed_opt_all.len);  */
/*   } else { */
/*     // add both I3_OPT_SENDER and I3_OPT_REQUEST_FOR_CACHE options */
/*     len = sizeof(char) + get_i3_stack_len(stack) +  */
/*       ctx->precomputed_opt_sender.len;  */
/*     assert(len <= CL_PREFIX_LEN); */
/*     fast_pack_i3_header(clb->data - len, TRUE, stack,  */
/* 			ctx->precomputed_opt_sender.p,  */
/* 			ctx->precomputed_opt_sender.len);  */
/*   } */

  set_first_hop(clb->data - len);
  if (!is_total_len) 
      cl_sendto(ctx, clb->data - len, clb->data_len + len, cid, &stack->ids[0]);
  else
      cl_sendto(ctx, clb->data - len, clb->data_len, cid, &stack->ids[0]);
}


void cl_send_data_packet1(cl_context *ctx, i3_stack *stack, cl_buf *clb)
{
  char *pkt;
  unsigned short len;
  i3_addr *a;
  i3_option *o;
  i3_option_list *ol;
  i3_header *h;
  cl_id *cid;
  int refresh;

  ol = alloc_i3_option_list();

  /* create I3_OPT_SENDER to tell the i3 server where to reply if 
   * trigger not present
   */
  a = alloc_i3_addr();
  init_i3_addr_ipv4(a, ctx->local_ip_addr, ctx->local_port);
  o = alloc_i3_option();
  init_i3_option(o, I3_OPT_SENDER, (void *)a);
  append_i3_option(ol, o);

  /* is stack->ids[0] cached ? */
  cid = cl_get_valid_id(ctx, &stack->ids[0], &refresh);
  if (refresh) {
    /* cache entry for stack->ids[0] doesn't exist or needs to be refreshed */
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_REQUEST_FOR_CACHE, NULL); 
    append_i3_option(ol, o);
  }

  h = alloc_i3_header();
  init_i3_header(h, TRUE, duplicate_i3_stack(stack), ol);

  /* get header length */
  len = get_i3_header_len(h);

  /* check whether we have enough room to prepend header */
  assert (len <= clb->data - clb->internal_buf); 

  /* prepend header */
  pkt = clb->data - len;
  pack_i3_header(pkt, h, &len);
  set_first_hop(pkt);
  cl_sendto(ctx, pkt, len + clb->data_len, cid, &stack->ids[0]);

  free_i3_header(h);
}

void cl_send_packet(cl_context *ctx, i3_header *hdr,
			cl_buf *clb, uint8_t opts_mask)
// TODO XXX -- opts mask is unimplemented in this case
{
  char *pkt;
  unsigned short len;
  cl_id *cid;
  int refresh;
    
  /* is there a cache entry for the first identifier in the stack ? */
  cid = cl_get_valid_id(ctx, &hdr->stack->ids[0], &refresh);
  if (refresh) {
    /* cache entry doesn't exist or needs to be refreshed */
    i3_option *o;
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_REQUEST_FOR_CACHE, NULL); 
    append_i3_option(hdr->option_list, o);
  }

  /* get header length */
  len = get_i3_header_len(hdr);
  
  /* check whether we have enough room to prepend header */
  assert (len <= clb->data - clb->internal_buf); 
  pkt = clb->data - len;
  /* copy header in front of payload */
  pack_i3_header(pkt, hdr, &len);
  set_first_hop(pkt);
  cl_sendto(ctx, pkt, len + clb->data_len, cid, &hdr->stack->ids[0]);

  free_i3_header(hdr);
}


/* return the header and the payload of an i3 packet;
 * hdr is allocated and needs to be freed in the calling function
 * pkt ix expected to be allocated by the calling function
 */

void cl_receive_packet(cl_context *ctx, i3_header **phdr, cl_buf *clb)
{
  struct sockaddr_in cliaddr;
  ssize_t n;
  int len;

  *phdr = NULL;
  len = sizeof(cliaddr);
  /* leave enough room to allow caller to invoke a cl_send operation
   * using the same buffer
   */
  clb->data = clb->internal_buf + CL_PREFIX_LEN; 
  /* recall that total length of the allocated buffer in the clb structure is
   * clb->max_len + CL_PREFIX_LEN */
  if (ctx->is_tcp) {
    if ((n = recv_tcp(clb->data, clb->max_len + CL_PREFIX_LEN, 
		      ctx->tcp_fd)) < 0)
    {
      err_sys("tcp recvfrom error");      
      return;    
    }
    if (n == 0) {
      printf("Connection closed by server, exiting...\n");
      exit(0);
    }
  }
  else
    if ((n = recvfrom(ctx->fd, clb->data, clb->max_len + CL_PREFIX_LEN, 0, 
		      (struct sockaddr *)&cliaddr, &len)) < 0)
    {
      perror("recvfrom");
      return;
    }

  if (clb->data[0] == I3_v01) {
    *phdr = unpack_i3_header(clb->data, (unsigned short *)&len);
    // len--;
    clb->data += len; /* this where the payload starts... */
    clb->data_len = n - len; /* ... and this is the payload length */
  }
}

void cl_sendto(cl_context *ctx, char *pkt, 
	       uint16_t pkt_len, cl_id *cid, ID *id) 
{
  if (cid == NULL) {
    int idx = get_i3_server(ctx->num_servers, ctx->s_array);
    if (-1 == idx) {
	fprintf(stderr, "cl_sendto: cannot get i3_servers\n");
	return;
    }
    cid = cl_create_id(ctx, id, &ctx->s_array[idx].addr, 
		       ctx->s_array[idx].port);
  }
  assert(cid); 

//   printf("Using(C) %s:%d\n", inet_ntoa(cid->i3_srv.sin_addr), ntohs(cid->i3_srv.sin_port));
  if (ctx->is_tcp) {
    printf("Using TCP socket\n");
    send_tcp(pkt, pkt_len, ctx->tcp_fd);
  }
  else
    if (sendto(ctx->fd, pkt, pkt_len, 0, (struct sockaddr *)&cid->i3_srv, 
	       sizeof(cid->i3_srv)) < 0) {
      if (errno == ENETUNREACH)
	if (cid->retries_cnt > 0)
	  cid->retries_cnt--;
      perror("cl_sendto");
    }
}


void make_data_opt(cl_context *ctx, uint8_t opt_mask, buf_struct *b)
{
  unsigned short len;
  i3_addr *a;
  i3_option *o;
  i3_option_list *ol;

  ol = alloc_i3_option_list();

  /* create ID_OPT_SENDER to tell the i3 server where to reply if 
   * trigger not present
   */
  a = alloc_i3_addr();
  init_i3_addr_ipv4(a, ctx->local_ip_addr, ctx->local_port);
  o = alloc_i3_option();
  init_i3_option(o, I3_OPT_SENDER, (void *)a);
  append_i3_option(ol, o);

  // Code_Clean: make this 3 ifs into a loop
  if (opt_mask & REFRESH_MASK) {
    /* add "request for cache" option if needed */
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_REQUEST_FOR_CACHE, NULL); 
    append_i3_option(ol, o);
  }

#if NEWS_INSTRUMENT
  if (opt_mask & LOG_PKT_MASK) {
    /* add "log packet" option if needed */
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_LOG_PACKET, NULL); 
    append_i3_option(ol, o);
  }

  if (opt_mask & APP_TS_MASK) {
    /* add "append ts" option if needed */
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_APPEND_TS, NULL); 
    append_i3_option(ol, o);
  }
#endif
  
  /* get option length ... */
  len = get_i3_option_list_len(ol);

  /* ... allocate memory ... */ 
  if ((b->p = (char *)malloc(len)) == NULL)
    panic("make_data_hdr: memory allocation error\n");
  
  /* ... and pack the option list */
  pack_i3_option_list(b->p, ol, &len);
  b->len = len;

  free_i3_option_list(ol);
}

void fast_pack_i3_header(char *p, char data, i3_stack *stack, 
			 char *packed_ol, unsigned short packed_ol_len) 
{
  unsigned short len;

  *p = I3_v01;
  p += sizeof(char); 
  //len = sizeof(char); 
  *p = (data ? I3_DATA : 0);
  if (!packed_ol)
    *p = *p & (~I3_OPTION_LIST); 
  else
    *p = *p | I3_OPTION_LIST;
  p++; //len += sizeof(char); 
  *p=0;
  pack_i3_stack(p, stack, &len);
  p += len;

  memcpy(p, packed_ol, packed_ol_len);
}

