/***************************************************************************
                          i3_client_trigger.c  -  description
                             -------------------
    begin                :  Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include <stdlib.h>
#include <sys/time.h>

#include "i3.h"
#include "i3_fun.h"
#include "trig_binheap.h"

#include "i3_client.h"
#include "i3_client_fun.h"

cl_trigger *cl_create_trigger_gen(cl_context *ctx, uint16_t addr_type, 
				  ID *id, uint16_t prefix_len,
				  struct in_addr ip_addr, uint16_t port,
				  i3_stack *stack, Key *key)
{
  i3_trigger *t;
  i3_addr    *a;
  cl_trigger *ctr;
  int idx = CL_HASH_TRIG(id);

  t = alloc_i3_trigger();
  a = alloc_i3_addr();

  switch (addr_type) {
  case I3_ADDR_TYPE_IPv4:
    init_i3_addr_ipv4(a, ip_addr, port);
    break;
  case I3_ADDR_TYPE_STACK:
    init_i3_addr_stack(a, stack);
    break;
  default:
    panic("cl_create_trigger_gen: invalid address type\n");
  }

  init_i3_trigger(t, id, max(prefix_len, MIN_PREFIX_LEN), a, key);

  if (cl_get_trigger_from_list(ctx->trigger_htable[idx], t) == NULL) {
    ctr = cl_alloc_trigger();
    ctr->t = t;
    ctr->status = CL_TRIGGER_STATUS_IDLE; 
    ctr->is_queued = FALSE;	/* Not yet inserted in PRIORITY QUEUE */
    ctr->retries_cnt = 0;
    
    cl_add_trigger_to_list(&ctx->trigger_htable[idx], ctr);
    return ctr;
  } else {
    /* trigger already presented */
    free_i3_trigger(t);
    return NULL;
  }
}


/************************************************************************
 * cl_destroy_trigger - destroy a given trigger; remove it from
 *                      ctx->trigger_htable and free memory 
 *************************************************************************/

void cl_destroy_trigger(cl_context *ctx, cl_trigger *ctr)
{
  int idx = CL_HASH_TRIG(&ctr->t->id);

  cl_remove_trigger_from_list(&ctx->trigger_htable[idx], ctr);
  cl_free_trigger(ctr);
}



/************************************************************************
 *  cl_insert_trigger_into_i3 - insert a given trigger 
 *
 *  input:
 *    ctx - context
 *    ctr - cl data structure of the trigger to be inserted
 *************************************************************************/

void cl_insert_trigger_into_i3(cl_context *ctx, cl_trigger *ctr)
{
  int refresh;

  gettimeofday(&ctr->last_ack, NULL);

  if (ctr->precomputed_pkt.p == NULL) 
    cl_make_trigger_packet(ctx, ctr->t, 
			   I3_OPT_TRIGGER_INSERT, &ctr->precomputed_pkt);

  /* "refresh" doesn't matter here as trigger inserts are always
   * acked with a control message (I3_OPT_TRIGGER_CHALLENGE or
   * I3_OPT_TRIGGER_ACK) that includes the option I3_OPT_CACHE_ADDR */
  ctr->last_ack = ctx->now;
  /* force MAX_NUM_RETRIES (if needed) when trigger is inserted 
   * XXX: maybe randomize it to not send all insertions at the same time?
   * (note that the refresh messages are already randomized; see
   * process_trigger_option())
   */
  ctr->last_ack.tv_sec -= TRIGGER_REFRESH_PERIOD; 

  /* If necessary insert into PRIORITY QUEUE  */
  if (!ctr->is_queued) {
      TrigInsertNode *t_node =
	  (TrigInsertNode *) emalloc(sizeof(TrigInsertNode));
      t_node->t = duplicate_i3_trigger(ctr->t);
      t_node->state = REFRESH_TO_CHECK;
      t_node->time = wall_time() + ACK_TIMEOUT * 1000000ULL;
      TrigInsert(t_node, ctx->trig_refresh_queue);
  }

  ctr->last_sent = ctx->now;
  ctr->status = CL_TRIGGER_STATUS_PENDING;
  cl_sendto(ctx, ctr->precomputed_pkt.p, ctr->precomputed_pkt.len, 
	    cl_get_valid_id(ctx, &ctr->t->id, &refresh),
	    &ctr->t->id);
}


/************************************************************************
 *  cl_remove_trigger_from_i3 - remove given trigger 
 *
 *  input:
 *    ctx - context
 *    ctr - cl data structure of the trigger to be inserted
 *************************************************************************/

int cl_remove_trigger_from_i3(cl_context *ctx, cl_trigger *ctr)
{
  buf_struct b;
  int refresh;
  int idx = CL_HASH_TRIG(&ctr->t->id);;

  if ((ctr = cl_get_trigger_from_list(ctx->trigger_htable[idx], ctr->t))
	  == NULL)
    return CL_RET_TRIGGER_NOT_FOUND;

  cl_make_trigger_packet(ctx, ctr->t, I3_OPT_TRIGGER_REMOVE, &b);

  cl_sendto(ctx, b.p, b.len, cl_get_valid_id(ctx, &ctr->t->id, &refresh),
	    &ctr->t->id);
  ctr->status = CL_TRIGGER_STATUS_IDLE;

  free(b.p); /* ... because b.p is allocated into cl_make_trigger_packet */
  return CL_RET_OK;
}

/* basic operations for manipulating triggers on the client side */
cl_trigger *cl_alloc_trigger()
{
  cl_trigger *ctr;

  if ((ctr = (cl_trigger *)calloc(1, sizeof(cl_trigger))) != NULL)
    return ctr;

  panic("cl_alloc_trigger: memory allocation error.\n");
  return NULL;
}

void cl_free_trigger(cl_trigger *ctr)
{
  free_i3_trigger(ctr->t);
  if (ctr->precomputed_pkt.p)
    free(ctr->precomputed_pkt.p);
  free(ctr);
}


void cl_free_trigger_list(cl_trigger *ctr_head)
{
  cl_trigger *ctr;

  assert(ctr_head);

  while (ctr_head) {
    ctr = ctr_head->next;
    cl_free_trigger(ctr_head);
    ctr_head = ctr;
  }
}

#define MAX_TRIG_PER_HASH 1000

cl_trigger *cl_get_trigger_from_list(cl_trigger *head, i3_trigger *t)
{
  cl_trigger *ctr;
  int count = 0;

  for (ctr = head; ctr; ctr = ctr->next) {
    count++;
    if (trigger_equal(t, ctr->t)) {
      if (count > MAX_TRIG_PER_HASH)
	eprintf("Too large entries per table! %d\n", count);
      return ctr;
    } else {
	// printf("Does not match\n");
    }
  }
  return NULL;
}

int does_id_match(ID *id1, ID *id2, int prefix_len)
{
  int d = prefix_len / 8; /* number of bytes */
  int r = prefix_len % 8; 
  char mask = 0;

  if (memcmp((char *)id1, (char *)id2, d))
    return FALSE;

  if (r == 0)
    return TRUE;

  mask = ~(0x7f >> (r - 1));

  if ((id1->x[d] & mask) == (id2->x[d] & mask))
    return TRUE;

  return FALSE;
}

cl_trigger *cl_get_trigger_by_id(cl_trigger *ctr_head, ID *id)
{
  cl_trigger *ctr;

  for (ctr = ctr_head; ctr; ctr = ctr->next) 
    if (does_id_match(&ctr->t->id, id, ctr->t->prefix_len) == TRUE)
      return ctr;

  return NULL;
}


/* remove a given trigger from list; don't destroy it */ 
void cl_remove_trigger_from_list(cl_trigger **phead, cl_trigger *ctr)
{

  assert(ctr);
  
  if (*phead == ctr) {
    *phead = (*phead)->next;
    if (*phead)
      (*phead)->prev = NULL;
  } else {
    ctr->prev->next = ctr->next;
    if (ctr->next)
      ctr->next->prev = ctr->prev;
  }
}


/* insert at the head of the list */
void cl_add_trigger_to_list(cl_trigger **phead, cl_trigger *ctr)
{
  assert(ctr);

  ctr->next = *phead;
  if (*phead)
    (*phead)->prev = ctr;
  ctr->prev = NULL;
  *phead = ctr;
}

/* update (id,R) --> (id,R'). called when IP addr change is detected */
void cl_update_triggers(cl_context *ctx)
{
    int idx;	 
    cl_trigger *ctr;
    
    for (idx = 0; idx < CL_HTABLE_SIZE; idx++) {
	for (ctr = ctx->trigger_htable[idx]; ctr; ctr = ctr->next) {
	    if (I3_ADDR_TYPE_IPv4 == ctr->t->to->type)
	    {
		/* (i) update addr */
		ctr->t->to->t.v4.addr = ctx->local_ip_addr;

		/* (ii) invalidate */
		ctr->is_queued = FALSE;
		ctr->retries_cnt = 0;
		free(ctr->precomputed_pkt.p);
		ctr->precomputed_pkt.p = NULL;
	    
		/* (iii) re-insert in i3 */
		cl_insert_trigger_into_i3(ctx, ctr);
	    }
	}
    }
}

void process_trigger_option(cl_context *ctx, i3_trigger *t, int opt_type)
{
  cl_trigger *ctr;
  int refresh;

  assert(ctx != NULL);

  switch (opt_type) {
    case I3_OPT_TRIGGER_CHALLENGE:
    case I3_OPT_TRIGGER_ACK:
      ctr = cl_get_trigger_from_list(
	  ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);
      if (NULL == ctr) {
	printf("Ignoring reply to a removed trigger\n");
        break;
      }
      
      ctr->last_ack = ctx->now; /* refresh trigger node entry */
      ctr->retries_cnt = 0;
      
      if (opt_type == I3_OPT_TRIGGER_CHALLENGE) {
	memcpy((char *)ctr->t->nonce, (char *)t->nonce, NONCE_LEN);
	/* check whether this trigger has been already precomputed */
	if (ctr->precomputed_pkt.p) 
	  free(ctr->precomputed_pkt.p);
	cl_make_trigger_packet(ctx, t, I3_OPT_TRIGGER_INSERT, &ctr->precomputed_pkt);

	ctr->last_sent = ctx->now;
	cl_sendto(ctx, ctr->precomputed_pkt.p, 
	    ctr->precomputed_pkt.len,
	    cl_get_valid_id(ctx, &t->id, &refresh), &t->id); 
      } else {
	if (ctr->status == CL_TRIGGER_STATUS_PENDING || 
	    ctr->status == CL_TRIGGER_STATUS_IDLE) {
	  /* randomize the end of the next refresh interval; this will 
	   * uniformly distribute the time when triggers are refreshed */
	  //ctr->last_ack.tv_sec -= (random() % TRIGGER_REFRESH_PERIOD);
	  ctr->status = CL_TRIGGER_STATUS_INSERTED;
	  ctr->retries_cnt = 0;
	  cl_trigger_callback(ctx, ctr, CL_CBK_TRIGGER_INSERTED, NULL, NULL);
	}
      }
      break;

    case I3_OPT_CONSTRAINT_FAILED:
      ctr = cl_get_trigger_from_list(
	      ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);
      cl_trigger_callback(ctx, ctr, 
	      CL_CBK_TRIGGER_CONSTRAINT_FAILED, NULL, NULL);
      break;
    
    case I3_OPT_ROUTE_BROKEN:
      ctr = cl_get_trigger_from_list(
	  ctx->trigger_htable[CL_HASH_TRIG(&t->id)], t);
      cl_trigger_callback(ctx, ctr, CL_CBK_ROUTE_BROKEN, NULL, NULL);
      break;

    case I3_OPT_CACHE_ADDR:
      if (t->to->type == I3_ADDR_TYPE_IPv4) {
#ifndef CCURED        
	if (cl_update_id(ctx, &t->id, 
	      &t->to->t.v4.addr, t->to->t.v4.port) == NULL)
	  cl_create_id(ctx, &t->id, &t->to->t.v4.addr, t->to->t.v4.port);
#else
        {
          struct in_addr tmp = t->to->t.v4.addr;
          if (cl_update_id(ctx, &t->id, 
                           &tmp, t->to->t.v4.port) == NULL)
            cl_create_id(ctx, &t->id, &tmp, t->to->t.v4.port);

          t->to->t.v4.addr = tmp;
        }
#endif        
        
      }
      break;
    
    default:
      printf("process_trigger_option: unknown option %d\n", opt_type);
  }  
}


void cl_process_option_list(cl_context *ctx, i3_option_list *ol)
{
  i3_option *option;
  cl_id     *cid;

  /* NAT ADDITION */

  /* When client reeives a i3_opt_force_cache_addr, it updates its cache, before processing other options in the message. */
  for (option = ol->head; option; option = option->next)
  {
    i3_trigger *t;
    
    switch (option->type)
    {
    case I3_OPT_FORCE_CACHE_ADDR:
      t = option->entry.trigger;
#ifndef CCURED      
      if ( t->to->type == I3_ADDR_TYPE_IPv4)        
	cl_update_id(ctx, &t->id,&t->to->t.v4.addr, t->to->t.v4.port);
#else
      {
        struct in_addr tmp = t->to->t.v4.addr;
        if ( t->to->type == I3_ADDR_TYPE_IPv4)        
          cl_update_id(ctx, &t->id,&tmp, t->to->t.v4.port);

        t->to->t.v4.addr = tmp;
      }
#endif      
        
    }
  }

  for (option = ol->head; option; option = option->next) {
    switch (option->type) {
    case I3_OPT_TRIGGER_CHALLENGE:
    case I3_OPT_TRIGGER_ACK:
    case I3_OPT_CONSTRAINT_FAILED:
    case I3_OPT_CACHE_ADDR:
    case I3_OPT_ROUTE_BROKEN:
      process_trigger_option(ctx, option->entry.trigger, option->type);
      break;
    case I3_OPT_TRIGGER_NOT_PRESENT:
      /* trigger not present */
      cid = cl_get_id_from_list(ctx->id_htable[CL_HASH_ID(option->entry.id)],
				option->entry.id);
      cl_id_callback(ctx, CL_CBK_TRIGGER_NOT_FOUND, 
		     option->entry.id, NULL, NULL);
      break;
    case I3_OPT_SENDER:
    case I3_OPT_FORCE_CACHE_ADDR:
      break;
    default:
      printf("option_type = %d\n", option->type);
      panic("cl_process_option_list: invalid option.");
    }
  }
}

/* create trigger packet -- trigger is not freed here */
void cl_make_trigger_packet(cl_context *ctx, i3_trigger *t, 
			    char opt_type, buf_struct *buf)
{
  i3_addr *a;
  i3_option *o;
  i3_option_list *ol;
  i3_stack *s;
  i3_header *h;

  ol = alloc_i3_option_list();

  if (opt_type != I3_OPT_TRIGGER_REMOVE) {
    /* create ID_OPT_SENDER to tell the i3 server where to reply with 
     * an ack or challenge message 
     */
    a = alloc_i3_addr();
    init_i3_addr_ipv4(a, ctx->local_ip_addr, ctx->local_port);
    o = alloc_i3_option();
    init_i3_option(o, I3_OPT_SENDER, (void *)a);
    append_i3_option(ol, o);
  }

  /* create "insert trigger" option */ 
  o = alloc_i3_option();
  init_i3_option(o, opt_type, (void *)duplicate_i3_trigger(t));
  append_i3_option(ol, o);
  
  s = alloc_i3_stack();
  init_i3_stack(s, &t->id, 1 /* only one ID in the stack */);

  h = alloc_i3_header();
  init_i3_header(h, FALSE, s, ol);

  buf->len = get_i3_header_len(h);

  if ((buf->p = (char *)malloc(buf->len)) == NULL)
    panic("cl_make_trigger_packet: memory allocation error\n");
  pack_i3_header(buf->p, h, &buf->len);
  set_first_hop(buf->p);
  
  free_i3_header(h);
}


