/***************************************************************************
                         i3_matching.c  -  description
                             -------------------
    begin                : Dec 7 2002
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

/**********************************************************************
 *
 * Data structure used to implement trigger matching operation. 
 * It consists of:
 *   1) A hash table of pointers of size HASH_TABLE_SIZE;
 *      Entry i of the hash maintains the set of triggers whith IDs
 *      id such that h(id_{255:128})=i, i.e., the 128-bit prefix of 
 *      each trigger from the set hases to i.
 *   2) All triggers associated with an entry are maintained
 *      into a Patricia tree data structure. 
 *   3) A node in the Patricia tree maintains an ID and a prefix len (pl).
 *      pl specifies how many bits have been matched to that point.
 *      As we move down the tree the prefix length increases. All nodes
 *      in a sub-tree routed at a particular node with ID id and prefix
 *      length pl share the same pl-bit prefix with ID id.
 *   4) A leaf with ID id in the Patricia tree maintains a list of triggers
 *      that have the same ID id.
 *
 *   Example:    
 *
 *       ------------------------------------------------------------
 *          ... |      i-1    | i=h(id_{255:128}) |     i+1      | ...  
 *       ------------------------------------------------------------
 *                                     |
 *                                     V
 *                                 --------- 
 *                                | id | pl |  
 *                                 --------- 
 *                                    / \
 *                                   /   \
 *                                 ...    V
 *                                    --------------- 
 *                                   | id1 | pl1 | t |-> list of i3 triggers
 *                                    ---------------
 * 
 *                                                                         
 **********************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "i3.h"
#include "i3_fun.h"
#include "i3_matching.h"


#define HASH_TABLE_SIZE 32768

#define HASH_IDX(id) ((*(unsigned short *)&id->x[0] + \
         *(unsigned short *)&id->x[sizeof(short)]) % HASH_TABLE_SIZE)

void insert_trigger_pnode_list(ptree_node *pn, i3_trigger *t, 
			       i3_addr *ret_a, unsigned long now);
void remove_trigger_pnode_list(ptree_node *pn, i3_trigger *t);

/**********************************************************************
 *  init_trigger_hash_table - create a hash table with 
 *                            HASH_TABLE_SIZE entries. Each entry
 *                            stores a pointer to a set of triggers. 
 *                            (Entry i mainatins all triggers whose 
 *                            128 bit hash to value i). The set of
 *                            triggers associated with an entry
 *                            are maintained in a compacted patricia 
 *                            trie data structure.
 ***********************************************************************/
ptree_node **alloc_trigger_hash_table()
{
  ptree_node **trigger_hash_table;

  if ((trigger_hash_table = 
       (ptree_node **)calloc(HASH_TABLE_SIZE, sizeof(void *))) == NULL)
    panic("alloc_trigger_hasr_table: memory allocation error\n");
  return trigger_hash_table;
}

/**********************************************************************
 *  alloc_ptree_node - create and initialized a node for the Patricia
 *                     trie data structure. A node consists of an ID
 *                     associated with a prefix_len. The leaf nodes
 *                     also mainatins a pointer to a trigger.
 *  input parameters:
 *     id         - i3 ID
 *     prefix_len - specifies the length of id's prefix;
 *                  all nodes in the sub-tree routed at a node with prefix 
 *                  x have IDs with same x-bit prefix.
 *     tn         - pointer to a list of triggers with ID id 
 *
 **********************************************************************/

ptree_node *alloc_ptree_node(ID *id, unsigned int prefix_len, 
			     trigger_node *tn)
{
  ptree_node *p;

  /* XXX: just simply call malloc for now; preallocate a pool of buffers 
     in the future */
  p = (ptree_node *)malloc(sizeof(ptree_node));
  if (p) {
    memcpy(p->id.x, id->x, ID_LEN);
    p->prefix_len = prefix_len;
    p->tn = tn;
    p->parent = p->left = p->right = NULL;
    return p;
  }
  panic("FATAL ERROR: memory allocation error in alloc_ptree_node()\n");
  return NULL;
}


/**********************************************************************
 *  free_ptree_node - free the memorey allocated to a Patricia tree
 *                    node, including the trigger node associated to that 
 *                    node (if any)
 **********************************************************************/

void *free_ptree_node(ptree_node *p)
{
  if (p->tn)
    free_trigger_node(p->tn);
  free(p);
  return NULL;
}

/**********************************************************************
 *  alloc_trigger_node - allocate a trigger node; trigger nodes
 *                       are linked in a list
 *   
 *  input:
 *    t   - i3 trigger associated with the trigger node
 *    now - current time (in sec)
 **********************************************************************/


trigger_node *alloc_trigger_node(i3_trigger *t, i3_addr *ret_a, unsigned long now)
{
  trigger_node *tn;

  if (!t)
    return NULL;

  /* XXX: just simply call malloc for now; preallocate a pool of buffers 
     in the future */
  tn = (trigger_node *)malloc(sizeof(trigger_node));
  if (tn) {
    tn->trigger = t;
    tn->ret_a = ret_a;
    tn->last_refresh = now;
    tn->next = NULL;
    return tn;
  }
  panic("FATAL ERROR: memory allocation error in alloc_trigger_node(2)\n");
  return NULL;
}


void *free_trigger_node(trigger_node *tn)
{
  free_i3_trigger(tn->trigger);
  if (tn->ret_a)
    free_i3_addr(tn->ret_a);
  free(tn);
  return NULL;
}


/**********************************************************************
 *  get_pnode - return the internal node or leafin the Patricia tree 
 *              that matches a given ID according to the longest 
 *              prefix rule
 *  
 *  input:
 *    pn - root of the Patricia tree
 *    id - ID to be matched
 *    leaf - flag specifing whether we need to get a leaf; recall that
 *           triggers are associated only with leves.
 *
 *  output:
 *    prefix_len - length of the longest prefix in the tree that 
 *                 matches id
 *
 *  return:
 *    if leaf==FALSE return the node in Patricia tree that 
 *    matches id (e.g., used for trigger insertion). Otherwise,
 *    if leaf==TRUE, return a leaf; the leaf is found by ignoring
 *    the bits that do not match.
 **********************************************************************/

ptree_node *get_pnode(ptree_node *pn, ID *id, 
		      unsigned int *prefix_len, 
		      unsigned char leaf)
{
  uint bit_idx = 0;  /* current bit being matched */
  uint byte_idx = 0; /* current byte being matched */
  uint cbit_idx = 0; /* curent bit in the byte_idx-th byte being matched; 
		     * bit_idx = byte_idx<<3 + cbit_idx 
                     */
  unsigned char mask = 0x80; /* set to 1 the cbit_idx-th bit; 
                              * all other bits are zero; this is used
                              * for bit-by-bit matching
                              */
  unsigned char skip = FALSE; /* used to skip bits that do no match;
                               * used only when leaf==TRUE
                               */
  if (!pn)
    return NULL;

  do {
 
   while (bit_idx < pn->prefix_len) {
      /* first try to match byte-by-byte */
      if (!cbit_idx && ((int)bit_idx <= (int)pn->prefix_len - CHAR_BITS)) {
        /* there are at least 8 bits to match; match next byte */
	if (id->x[byte_idx] == pn->id.x[byte_idx]) {
	  byte_idx++;
	  bit_idx += CHAR_BITS;
	  continue; /* get back and try to match the next byte */
	}
      }
      /* last byte didn't match or there were less than 8 bits to match; 
         match bit-by-bit */
      if ((id->x[byte_idx] & mask) != (pn->id.x[byte_idx] & mask)) {
	/* id and pn->id don't match in the bit_idx-th bit;
         * longest prefix match is bit_idx
         */
	if (leaf && skip) {
	  /* we want to get a single leaf; 
	   * ignore the remaining bits at this level 
	   * and go to the next one
	   */
	  bit_idx = pn->prefix_len;
	  byte_idx = bit_idx >> 3;
	  cbit_idx = bit_idx & 0x7;
	}
	break;
      } else {
        /* look for the next bit in the curent byte */
	mask = mask >> 1;
	bit_idx++;
	if (!mask) {
	  /* go to the next byte */
	  byte_idx++;
	  cbit_idx = 0;
	  mask = 0x80;
	} else
	  cbit_idx++;
      }
    }
    if (pn->prefix_len > bit_idx || pn->prefix_len == ID_LEN_BITS) {
      /* found Patricia tree node sharing the longest prefix with id */
      if (!leaf) {
	/* return Patricia tree node */
	*prefix_len = bit_idx;
	return pn;
      } else {
	/* we want a leaf */
	if (pn->prefix_len == ID_LEN_BITS) {
	  /* we got a leaf; return it */
	  if (!skip)
	    *prefix_len = bit_idx;
 	  return pn;
	} else 
	  /* we at an interior level; continue matching */
	  if (!skip) {
	    skip = TRUE;
	    *prefix_len = bit_idx;
	  }
      }
    }

    if (id->x[byte_idx] & mask) 
      pn = pn->right;
    else
      pn = pn->left;
  } while (TRUE);

  return NULL; // CCured does not see that we cannot get here
}


/**********************************************************************
 *  insert_pnode - insert a node with a given ID (pnew->id) and 
 *                 prefix length (prefix_len) in the Patricia tree
 *
 *  input:
 *    pn   - node in the tree that shares the longest prefix with pnew
 *           (usually returned by get_pnode(...,..., FALSE) function)
 *    pnew - new node to be inserted
 *    prefix_len - length of the prefix shared by pn and pnew
 *    
 *  return:
 *    node that replaces pn in the tree; pn and pnew become 
 *    children of this node
 **********************************************************************/

ptree_node *insert_pnode(ptree_node *pn, ptree_node *pnew, 
			 unsigned int prefix_len)
{
  ptree_node *pparent;

  /* create a Patricia tree node that will be the parent of
   * pnew and pn, respectively
   */
  pparent = alloc_ptree_node(&pnew->id, prefix_len, NULL);

  /* make pn and pnew children of pparent */
  if (get_bit(pnew->id.x, prefix_len)) {
    pparent->right = pnew; 
    pparent->left = pn;
  } else {
    pparent->left = pnew;
    pparent->right = pn;
  }
  if (pn->parent) {
    if (pn->parent->left == pn)
      pn->parent->left = pparent;
    else
      pn->parent->right = pparent;
  } 
  pparent->parent = pn->parent;
  pnew->parent = pn->parent = pparent;

  return pparent;
}


/**********************************************************************
 *  remove_leaf - remove a given leaf from the Patricia tree
 *    
 *  input:
 *    root - the root of the tree
 *    pn   - node to be removed
 **********************************************************************/

ptree_node *remove_leaf(ptree_node *root, ptree_node *pn)
{
  ptree_node *pparent;

  assert(!pn->left && !pn->right); /* pn should be a leaf */

  if (pn == root) {
    /* there is only one node in the tree */
    free_ptree_node(pn);
    return NULL;
  }

  /* free pn, and replace pn's parent with pn's sibling */
  pparent = pn->parent;
  if (pparent->left == pn) {
    free_ptree_node(pn);
    pn = pparent->right;
  } else {
    free_ptree_node(pn);
    pn = pparent->left;
  }

  if (pparent->parent) {
    if (pparent->parent->left == pparent) 
      pparent->parent->left = pn;
    else
      pparent->parent->right = pn;
  } 

  pn->parent = pparent->parent;
  free_ptree_node(pparent);

  if (pn->parent)
    return root;
  else
    return pn;
}


/**********************************************************************
 *  insert_trigger - insert new trigger
 *
 *  input:
 *    t   - trigger to be inserted
 *    now - current time (in sec)
 *
 *  note:
 *    the trigger's nonce *should* be checked before calling 
 *    insert_trigger, by using check_nonce(t)  
 **********************************************************************/

void insert_trigger(ptree_node **hash_table, i3_trigger *t,
			i3_addr *ret_a, long unsigned now)
{
  ID *id = &t->id;
  unsigned short idx = HASH_IDX(id); /* index of the entry where 
				      * t is to be inserted
				      */
  ptree_node **proot = &hash_table[idx]; /* address of the root 
					  * of the Patricia tree
					  * where t is to be
					  * inserted
					  */
  ptree_node *pn, *pnew;
  unsigned int pfx_len;

  if (!*proot) {
    /* this is the first node in the tree */
    *proot = alloc_ptree_node(id, ID_LEN_BITS,
	alloc_trigger_node(duplicate_i3_trigger(t), duplicate_i3_addr(ret_a), now));
   return;
  }

  /* get Patricia tree node that shares the longest prefix with id */
  pn = get_pnode(*proot, id, &pfx_len, FALSE);

  if (pfx_len == ID_LEN_BITS) {
    /* the trigger is already inserted, or another trigger with
     * the same ID is presented
     */
    insert_trigger_pnode_list(pn, t, ret_a, now);
    return;
  }

  /* create new node with ID id, and ... */
  pnew = alloc_ptree_node(id, ID_LEN_BITS,
	alloc_trigger_node(duplicate_i3_trigger(t), duplicate_i3_addr(ret_a), now));

  /* ... insert it in the tree */
  pn = insert_pnode(pn, pnew, pfx_len);

  if (!pn->parent)
    *proot = pn;
}


/**********************************************************************
 *  loookup_trigger - lookup the trigger(s) with a give ID
 *
 *  input:
 *    id - lookup for this ID
 *  output:
 *    pprefix_len - length of the best prefix match
 *  return:
 *    The node whose ID matches the given ID id (according to lpm); 
 *    the length of the prefix shared by node's ID and id is returned
 *    in pprefix_len
 **********************************************************************/

ptree_node *lookup_trigger(ptree_node **hash_table, 
			   ID *id, unsigned int *pprefix_len)
{
  return get_pnode(hash_table[HASH_IDX(id)], 
		   id, pprefix_len, TRUE);
}


/**********************************************************************
 *  remove_trigger - remove given trigger
 *
 *  input:
 *    t  - trigger to be removed
 **********************************************************************/

void remove_trigger(ptree_node **hash_table, i3_trigger *t)
{
  ID *id = &t->id;
  unsigned short idx = HASH_IDX(id);
  ptree_node *pn;
  unsigned int prefix_len;

  if (!check_nonce(t)) {
    printf("remove_trigger: check_nonce has failed!\n");
    return;
  }
  pn = get_pnode(hash_table[HASH_IDX(id)], id, &prefix_len, TRUE);

  if (prefix_len != ID_LEN_BITS)
    printf("trigger not present\n");
  else {
    remove_trigger_pnode_list(pn, t);
    if (!pn->tn)
      hash_table[idx] = remove_leaf(hash_table[idx], pn);
  }
}



/**********************************************************************
 *  insert_trigger_pnode_list - insert a trigger in the list of the 
 *                              Patricia leaf with the corresponding ID;
 *                              if the trigger is already in the list,
 *                              refresh it 
 *
 *  input:
 *    id - ID of the trigger to be inserted
 *    t  - trigger to be inserted
 *    now - current time (in sec)
 **********************************************************************/

void insert_trigger_pnode_list(ptree_node *pn, i3_trigger *t,
			       i3_addr *ret_a, unsigned long now)
{
  trigger_node *tn, *prev = 0;
  
  /* Modification: insert new entries at the end rather than the
   * beginning */

  for (tn = pn->tn; tn; prev = tn, tn = tn->next) {
    if (trigger_equal(tn->trigger, t)) {
      /* trigger already in the list; refresh it */
      tn->last_refresh = now;
      return;
    }
  }
  
  /* trigger not in the list; insert it */
  /* OLD CODE -- insert at beginning
  tn = pn->tn;
  pn->tn = alloc_trigger_node(duplicate_i3_trigger(t), now);
  pn->tn->next = tn; */
  assert(prev->next == NULL);
  tn = alloc_trigger_node(duplicate_i3_trigger(t), duplicate_i3_addr(ret_a), now);
  prev->next = tn;
}

/**********************************************************************
 *  remove_trigger_pnode_list - remove trigger from the list of the 
 *                              Patricia leaf with the corresponding ID
 *
 *  input:
 *    id - ID of the trigger to be removed 
 *    t  - trigger to be removed
 **********************************************************************/

void remove_trigger_pnode_list(ptree_node *pn, i3_trigger *t)
{
  trigger_node *tn, *tn1;

  if (trigger_equal(pn->tn->trigger, t)) {
    tn1 = pn->tn;
    pn->tn = pn->tn->next;
    free_trigger_node(tn1);
    return;
  }

  for (tn = pn->tn; tn->next; tn = tn->next) { 
    if (trigger_equal(tn->next->trigger, t)) {
      tn1 = tn->next;
      tn->next = tn->next->next;
      free_trigger_node(tn1);
      return;
    }
  }
}


/**********************************************************************
 *  cleanup_trigger_list - remove all triggers from a ptree node list
 *                         who have timeout
 *
 *  input:
 *    pn  - ptree node
 *    now - current time
 **********************************************************************/

void cleanup_trigger_list(ptree_node *pn, unsigned long now)
{
  trigger_node *tn, *tn1;

  assert (pn);

  while (pn->tn && 
	 (now - pn->tn->last_refresh > TRIGGER_TIMEOUT)) {
    tn = pn->tn;
    pn->tn = pn->tn->next;
    free_trigger_node(tn);
  }

  if (pn->tn) {
    for (tn = pn->tn; tn->next;) {
      if (now - tn->next->last_refresh > TRIGGER_TIMEOUT) {
	tn1 = tn->next;
	tn->next = tn->next->next;
	free_trigger_node(tn1);
      } else
	tn = tn->next;
    }
  } 
}


/**********************************************************************
 *  cleanup_ptree_node - remove all triggers associated to a ptree node 
 *                       that have timeout; if no trigger remains
 *                       destroy ptree node
 *
 *  input:
 *    pn  - ptree node 
 *    hash_table -
 *    id  - id corresponding to pn. note that id can be used to
 *          get pn by invoking lookup_trigger. the reason we pass
 *          pn here to avoid a costly lookup_trigger operation.  
 *    now - current time
 *
 *  return:
 *    pn - NULL if all triggers are removed; original value otherwise
 **********************************************************************/

ptree_node *cleanup_ptree_node(ptree_node *pn, ptree_node **hash_table, 
			       ID *id, unsigned long now)
{
  unsigned int idx;

  if (!pn)
    return NULL;

  cleanup_trigger_list(pn, now);
  if (!pn->tn) {
    idx = HASH_IDX(id);
    hash_table[idx] = remove_leaf(hash_table[idx], pn);
    return NULL;
  }
  return pn;
}


/*******************************************************************
 *  Following functions are for debugging proposes
 *******************************************************************/    


void printf_id_bits(ID *id, unsigned int prefix_len, int indent)
{
  uint i, k;
  char buf[INDENT_BUF_LEN];

  assert(indent <= INDENT_BUF_LEN);
  memset(buf, ' ', indent);
  buf[indent] = 0;

  printf("%s id = ", buf);

  for (i = 0; i < (prefix_len >> 3); i++) {
    for (k = 0; k < CHAR_BITS; k++) 
      if (id->x[i] & ((unsigned char)0x80 >> k))
	printf("1");
      else
	printf("0");
    printf(" ");
  }

  prefix_len = prefix_len - ((prefix_len >> 3) << 3);
  
  for (k = 0; k < prefix_len; k++) {
    if (id->x[i] & ((unsigned char)0x80 >> k))
      printf("1");
    else
      printf("0");
  }
  printf("\n");
}


void printf_ptree(ptree_node *pn, int indent)
{
  char buf[INDENT_BUF_LEN];

  if (!pn)
    return;

  assert(indent <= INDENT_BUF_LEN);
  memset(buf, ' ', indent);
  buf[indent] = 0;

  printf_id_bits(&pn->id, pn->prefix_len, indent);
  printf("%s prefix_len = %d\n", buf, pn->prefix_len);

  printf_ptree(pn->left, indent + 2);
  printf_ptree(pn->right, indent + 2);
}


void printf_ptree_id(ptree_node **hash_table, ID *id, int indent)
{
  unsigned short idx = HASH_IDX(id);
  printf_ptree(hash_table[idx], indent);
}
