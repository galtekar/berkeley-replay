#include "trig_event_list.h"
#include "i3.h"
#include "i3_trigger.h"
#include "i3_client.h"
#include "i3_client_fun.h"
#include "i3_client_trigger.h"
#include "../utils/utils.h"
#include <math.h>

#define MIN_TRIGGER_REFRESH_PERIOD \
	(TRIGGER_REFRESH_PERIOD - MAX_NUM_TRIG_RETRIES * ACK_TIMEOUT)*3/4
#define MAX_TRIGGER_REFRESH_PERIOD \
	(TRIGGER_REFRESH_PERIOD - MAX_NUM_TRIG_RETRIES * ACK_TIMEOUT)

#define UMILLION 1000000ULL

uint64_t get_time_to_next_trigger_refresh()
{
    return (uint64_t) (UMILLION * 
	 funif_rand(MIN_TRIGGER_REFRESH_PERIOD, MAX_TRIGGER_REFRESH_PERIOD));
}

void process_trig_event(cl_context *ctx, TrigInsertNode *node)
{
    int		refresh; // not used
    uint64_t	curr_time = wall_time();
    cl_trigger	*ctr;
    
    // printf("Status for trigger %p (hash = %d): ",
    // 		node->t, CL_HASH_TRIG(&node->t->id));
    // printf_i3_trigger(node->t, 0);
    ctr = cl_get_trigger_from_list(
	    ctx->trigger_htable[CL_HASH_TRIG(&node->t->id)], node->t);
    
    if (NULL == ctr || CL_TRIGGER_STATUS_IDLE == ctr->status) {
	/* trigger no longer needs to be refreshed in i3 */
	if (NULL == ctr)
	    printf("Trigger removal detected, removing from queue\n");
	else 
	    printf("Trigger idle_status detected, removing from queue\n");
	free(node->t);
	free(node);
	return;
    }
    
    if (REFRESH_TO_CHECK == node->state) {
	uint64_t diff_time = curr_time -
	    (ctr->last_ack.tv_sec * UMILLION + ctr->last_ack.tv_usec);
	if (diff_time > MIN_TRIGGER_REFRESH_PERIOD * UMILLION) {
	    /* last packet has not been acked */
	    printf("Unsuccessful insert attempt\n");
	    ctr->retries_cnt++;
	    if (ctr->retries_cnt <= MAX_NUM_TRIG_RETRIES) {
		printf("Timeout exceeded, resending\n");
		ctr->last_sent = ctx->now;
		cl_sendto(ctx, ctr->precomputed_pkt.p, 
			ctr->precomputed_pkt.len,
			cl_get_valid_id(ctx, &ctr->t->id, &refresh),
			&ctr->t->id); 
		node->time = curr_time + ACK_TIMEOUT * UMILLION;
		TrigInsert(node, ctx->trig_refresh_queue);
	    } else {
		printf("MAX_NUM_TRIG_RETRIES reached. Retrying later\n");
		ctr->retries_cnt = 0;
		node->state = REFRESH_TO_SEND;
		node->time = curr_time + get_time_to_next_trigger_refresh();
		TrigInsert(node, ctx->trig_refresh_queue);
	    }
	} else {
	    if (CL_TRIGGER_STATUS_PENDING == ctr->status) {
		printf("Still pending, inserting later timeout\n");
		node->time = curr_time + ACK_TIMEOUT * UMILLION;
		TrigInsert(node, ctx->trig_refresh_queue);
	    } else if (CL_TRIGGER_STATUS_INSERTED == ctr->status) {
	       // printf("Successful trigger insert\n");
		uint64_t time_diff;
		node->state = REFRESH_TO_SEND;
		time_diff = get_time_to_next_trigger_refresh();
		node->time = curr_time + time_diff;
		TrigInsert(node, ctx->trig_refresh_queue);
	    }
	}
    }
    else if (REFRESH_TO_SEND == node->state) {
	ctr->last_sent.tv_sec = curr_time / UMILLION;
	ctr->last_sent.tv_usec = curr_time % UMILLION;
	cl_sendto(ctx, ctr->precomputed_pkt.p, 
		ctr->precomputed_pkt.len,
		cl_get_valid_id(ctx, &ctr->t->id, &refresh),
		&ctr->t->id); 
	node->time = curr_time + ACK_TIMEOUT * UMILLION;
	node->state = REFRESH_TO_CHECK;
	TrigInsert(node, ctx->trig_refresh_queue);
    }
    else {
	fprintf(stderr, "PANIC: Invalid event type i3_client::process_event\n");
    }
}
