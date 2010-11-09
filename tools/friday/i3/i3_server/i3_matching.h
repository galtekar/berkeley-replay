/***************************************************************************
                         i3_matching.h  -  description
                             -------------------
    begin                : Sat Dec 7 2002
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef I3_MATCHING_H
#define I3_MATCHING_H

#include "i3.h"
#include "i3_fun.h"
#include "i3_api.h"

#define TRIGGER_TIMEOUT 30 /* in seconds */

typedef struct trigger_node_ {
  i3_trigger	*trigger;
  i3_addr	*ret_a;	// address of person who inserted the trigger
  long		last_refresh;
  struct trigger_node_ *next;
} trigger_node;

typedef struct ptree_node_ {
  ID  id;
  unsigned int        prefix_len;
  trigger_node       *tn;
  struct ptree_node_ *left;
  struct ptree_node_ *right;
  struct ptree_node_ *parent;
} ptree_node;


ptree_node **alloc_trigger_hash_table();
void insert_trigger(ptree_node **hasth_table, i3_trigger *t,
			i3_addr *ret_a, unsigned long now);
ptree_node *lookup_trigger(ptree_node **hash_table, 
			   ID *id, unsigned int *prefix_len);
void remove_trigger(ptree_node **hash_table, i3_trigger *t);


/* functions implemented in i3_matching.c */
ptree_node *alloc_ptree_node(ID *id, unsigned int prefix_len,
			     trigger_node *tn);
void *free_ptree_node(ptree_node *p);
trigger_node *alloc_trigger_node(i3_trigger *t, i3_addr *ret_a, unsigned long now);
void *free_trigger_node(trigger_node *tn);
int get_lpm(uint8_t *id1, uint8_t *id2, int start, int end);
ptree_node *get_pnode(ptree_node *pn, ID *id,
		      unsigned int *prefix_len, unsigned char leaf);
ptree_node *insert_pnode(ptree_node *pn, ptree_node *pnew,
			 unsigned int prefix_len);
ptree_node *remove_leaf(ptree_node *root, ptree_node *pn);
ptree_node *cleanup_ptree_node(ptree_node *pt, ptree_node **hash_table, ID *id,
			       unsigned long now);

void printf_id_bits(ID *id, unsigned int prefix_len, int indent);
void printf_ptree(ptree_node *pn, int indent);
void printf_ptree_id(ptree_node **hash_table, ID *id, int indent);


#define get_bit(x, bit_idx) \
  (x[(bit_idx)>>3] & ((unsigned char)0x80 >> (bit_idx-(((bit_idx)>>3)<<3))))

#endif /* I3_MATCHING_H */
