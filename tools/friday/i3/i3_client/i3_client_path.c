/***************************************************************************
                          i3_client_path.c  -  description
                             -------------------
    begin                : Aug 14 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include <string.h>
#include <stdlib.h>

#include "i3.h"
#include "i3_fun.h"
#include "trig_binheap.h"
#include "i3_client.h"
#include "i3_client_fun.h"

cl_path *cl_create_path(cl_context *ctx, ID *path, 
			uint16_t path_len, uint32_t tmask, int *rc)
{
  cl_path *clp;
  int i, old_i, k;
  uint16_t trigger_num;
  i3_stack *s;
  struct in_addr dummy;

  if (path_len > CL_MAX_PATH_LEN) {
    *rc = CL_RET_PATH_TOO_LONG;
    return NULL;
  } else if (path_len < 2) {
    *rc = CL_RET_PATH_TOO_SHORT;
    return NULL;
  }

  if ((*rc = cl_path_check_mask(tmask, path_len, &trigger_num)) != CL_RET_OK)
    return NULL;

  if ((clp = (cl_path *)calloc(1, sizeof(cl_path))) == NULL)
    panic("cl_create_path(1): memory allocation error\n");

  if ((clp->path = (ID *)malloc(sizeof(ID)*path_len)) == NULL)
    panic("cl_create_path(2): memory allocation error\n");

  if ((clp->triggers = 
       (cl_trigger **)calloc(1, sizeof(cl_trigger**)*(trigger_num))) == NULL)
    panic("cl_create_path(2): memory allocation error\n");

  clp->status = CL_PATH_STATUS_IDLE;
  clp->path_len = path_len;
  memcpy(clp->path, (char *)path, sizeof(ID)*path_len);
  clp->tmask = tmask;
  clp->trigger_num = trigger_num;

  /* create triggers */
  k = 0;
  for (i = 0; i < path_len - 1;) {
    /* create & init stack */
    s = alloc_i3_stack();

    old_i = i;
    /* check whether the next ID is a bridge ID */
    if (is_mask_bit_set(tmask, i + 1)) {
      init_i3_stack(s, &path[i+1], 2);
      i += 2;
    } else {
      init_i3_stack(s, &path[i+1], 1);
      i++;
    }
    clp->triggers[k] = 
      cl_create_trigger_gen(ctx, I3_ADDR_TYPE_STACK,
			    &path[old_i], ID_LEN_BITS, dummy, 0, s, 0);
    if (clp->triggers[k] == NULL) {
      cl_destroy_path(ctx, clp);
      *rc = CL_RET_PATH_CREATE_FAILED;
      return NULL;
    }
    clp->triggers[k]->path = clp;
    k++;
  }

  /* insert trigger at the head of the list */
  clp->next = ctx->path_list;
  ctx->path_list = clp;

  return clp;
}
    

void cl_destroy_path(cl_context *ctx, cl_path *clp)
{
  int      i;
  cl_path *clp_temp;

  for (i = 0; i < clp->trigger_num ; i++)
    if (clp->triggers[i])
      cl_destroy_trigger(ctx, clp->triggers[i]);

  /* remove path from path list */
  if (ctx->path_list == clp)
    ctx->path_list = ctx->path_list->next;
  else {
    for (clp_temp = ctx->path_list; clp_temp->next; clp_temp = clp_temp->next){
      if (clp_temp->next == clp) {
	clp_temp->next = clp_temp->next->next;
	break;
      }
    }
  }

  /* free the rest of resources */
  if (clp->path) 
    free(clp->path);
  if (clp->triggers)
    free(clp->triggers);

  free(clp);
}


void cl_destroy_path_list(cl_context *ctx)
{
  while (ctx->path_list)
    cl_destroy_path(ctx, ctx->path_list);
}

void cl_insert_path_into_i3(cl_context *ctx, cl_path *clp)
{
  int i;

  clp->status = CL_PATH_STATUS_PENDING;

  for (i = 0; i < clp->trigger_num; i++)
    if (clp->triggers[i])
      cl_insert_trigger_into_i3(ctx, clp->triggers[i]);
}

void cl_remove_path_from_i3(cl_context *ctx, cl_path *clp)
{
  int i;

  for (i = 0; i < clp->trigger_num; i++)
    if (clp->triggers[i])
      cl_remove_trigger_from_i3(ctx, clp->triggers[i]);
}


/* check if path's mask is well formed. The mask cannot start
 * or end with a bridge node, and cannot contain two consecutive
 * bridge nodes. in other words, the mask cannot start or end
 * with a "1" bit, and cannot contain two consecutive bits of "1"
 */
int cl_path_check_mask(uint32_t tmask, uint16_t path_len, 
		       uint16_t *trigger_num)
{
  int i;

  assert(path_len <= CL_MAX_PATH_LEN);

  if (is_mask_bit_set(tmask, 0) || is_mask_bit_set(tmask, path_len-1))
    return CL_RET_PATH_INVALID_MASK;

  /* check for consecutive ones */
  for (i = 1; i < path_len - 1; i++)
    if (is_mask_bit_set(tmask, i) && is_mask_bit_set(tmask, i + 1))
      return CL_RET_PATH_INVALID_MASK;

  /* compute the number of triggers that need to be inserted;
   * we already know that first and last bit are "0"
   */
  *trigger_num = path_len - 1;
  for (i = 1; i < path_len - 1; i++)
    if (is_mask_bit_set(tmask, i))
      (*trigger_num)--;

  return CL_RET_OK;
}

int cl_compute_path_key(ID *path, uint16_t len)
{
  int i, k, key = 0;

  assert(len <= CL_MAX_PATH_LEN);

  for (i = 0; i < len; i++) {
    for (k = 0; k < sizeof(ID)/sizeof(int); k++)
      key = key ^ *((int *)&path[i].x[k*sizeof(int)]);
  }
  return key;
}


/* create an ID (new_id) that hopefully resides on the same server
 * as "id" and does not collide with an application ID
 */
void cl_create_shadow_id(ID *id, ID *new_id)
{
#define RANDOM_SHADOW_LEN 2
  int i;

  memcpy(new_id, id, sizeof(ID));
  /* randomize last RANDOM_SHADOW_LEN in the prefixe */
  for (i = MIN_PREFIX_LEN/8 - RANDOM_SHADOW_LEN; i < ID_LEN; i++)
    new_id->x[i] = random();
}


void cl_printf_path(cl_path *clp)
{
  int i;
  
  printf("Path:\n");
  for (i = 0; i < clp->trigger_num; i++) {
    (is_mask_bit_set(clp->tmask, i) ? printf("*") : printf(" "));
    printf_i3_id(&clp->path[i], 0);
  }
}
