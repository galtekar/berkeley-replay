/***************************************************************************
                         i3_pushback.c  -  description
                             -------------------
    begin                : Aug 26 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include <sys/time.h>
#include "i3_server.h"

/* to be moved together with tval_sub , ...(all in i3_client_contex() 
 * under utils/ 
 */
unsigned long tval_diff(struct timeval *t1, struct timeval *t2); 

void srv_update_pback_table(srv_context *ctx, ID *id)
{
  int idx = SRV_PBACK_HASH(id);

  if ((ctx->pback_table[idx].time.tv_sec == 0) ||
      (tval_diff(&ctx->now, &ctx->pback_table[idx].time)> SRV_PBACK_TIMEOUT)) {
      ctx->pback_table[idx].time = ctx->now;
      ctx->pback_table[idx].id = *id;
  }
}

int srv_is_pback_entry(srv_context *ctx, ID *id)
{
  int idx = SRV_PBACK_HASH(id);

  if ((!memcmp(id->x, ctx->pback_table[idx].id.x, sizeof(ID))) &&
      (tval_diff(&ctx->now, &ctx->pback_table[idx].time)<=SRV_PBACK_TIMEOUT))
  {
    return TRUE;
  }

  return FALSE;
}

/* return (t1 - t2) in miliseconds */
unsigned long tval_diff(struct timeval *t1, struct timeval *t2)
{
  struct timeval tres;

  assert(t1);
  assert(t2);

  /* assume t1 is greater than t2 */
  if (t1->tv_usec < t2->tv_usec) {
    tres.tv_usec = 1000000 + t1->tv_usec - t2->tv_usec;
    tres.tv_sec = t1->tv_sec - t2->tv_sec - 1;
  } else {
    tres.tv_usec = t1->tv_usec - t2->tv_usec;
    tres.tv_sec = t1->tv_sec - t2->tv_sec;
  }

  // xxx printf("ttttt = %ld\n", (tres.tv_sec << 10) + (tres.tv_usec >> 10));
  /* return ~ tres.tv_sec*1000 + tres.tv_usec/1000 */
  return ((tres.tv_sec << 10) + (tres.tv_usec >> 10));
}

