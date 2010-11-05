#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "compiler.h"
#include "arch.h"
#include "debug.h"

//#define NULL ((void*) 0)

struct ListHead {
	struct ListHead *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct ListHead name = LIST_HEAD_INIT(name)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

static INLINE void
List_Init(struct ListHead *list)
{
   list->next = list;
   list->prev = list;
}

/* For internal use only. */
static INLINE void
__List_Add(struct ListHead *n, struct ListHead *prev, struct ListHead *next)
{
   next->prev = n;
   n->next = next;
   n->prev = prev;
   prev->next = n;
}

static INLINE void
List_Add(struct ListHead *n, struct ListHead *head)
{
   __List_Add(n, head, head->next);
}

/*
 * @n: element to add
 * @head: head of list to add @n to
 */
static INLINE void
List_AddTail(struct ListHead *n, struct ListHead *head)
{
   __List_Add(n, head->prev, head);
}

static INLINE void
ListDel(struct ListHead *prev, struct ListHead *next)
{
   next->prev = prev;
   prev->next = next;
}

static INLINE void
List_Del(struct ListHead *entry)
{
   ListDel(entry->prev, entry->next);
}

static INLINE void
List_DelInit(struct ListHead *entry)
{
   ListDel(entry->prev, entry->next);
   List_Init(entry);
}

static INLINE int
List_IsEmpty(const struct ListHead *head)
{
   return head->next == head;
}

#define List_Push(listP, field, nodeP) \
   List_AddTail(&nodeP->field, listP)

#define List_Pop(listP, field, nodeP) \
({ \
   if (!List_IsEmpty(listP)) { \
      nodeP = list_entry((listP)->prev, typeof(*nodeP), field); \
      List_DelInit((listP)->prev); \
   } else { \
      nodeP = NULL; \
   } \
   nodeP; \
})

#define List_PeekTop(listP, field, nodeP) \
({ \
   if (!List_IsEmpty(listP)) { \
      nodeP = list_entry((listP)->prev, typeof(*nodeP), field); \
   } else { \
      nodeP = NULL; \
   } \
   nodeP; \
})

#if 0
static INLINE void
Stack_Init(struct ListHead *headP)
{
   List_Init(headP);
}

static INLINE void
Stack_InitNode(struct ListHead *entryP)
{
   List_Init(entryP);
}
#endif
   

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_from - iterate over list of given type from the current point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type, continuing from current position.
 */
#define list_for_each_entry_from(pos, head, member) 			\
	for (; pos && &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

/**
 * list_for_each_entry_safe_from
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type from current point, safe against
 * removal of list entry.
 */
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (({ if (pos) n = list_entry(pos->member.next, typeof(*pos), member); });		\
	     pos && &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

/*
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */
struct HListNode
{
   struct HListNode *next, **pprev;
};

struct HListHead
{
   struct HListNode *first;
};

static INLINE void
HList_HeadInit(struct HListHead *h)
{
   h->first = NULL;
}

static INLINE void
HList_NodeInit(struct HListNode *h)
{
   h->next = NULL;
   h->pprev = NULL;
}

static INLINE int
HList_Empty(struct HListHead *h)
{
   return !h->first;
}

static INLINE void
HList_AddHead(struct HListNode *n, struct HListHead *h)
{
   struct HListNode *first = h->first;
   
   n->next = first;
   if (first) {
      first->pprev = &n->next;
   }
   h->first = n;
   n->pprev = &h->first;
}

static INLINE void
HList_Del(struct HListNode *n)
{
   struct HListNode *next = n->next;
   struct HListNode **pprev = n->pprev;
   *pprev = next;
   if (next) {
      next->pprev = pprev;
   }
   n->next = NULL;
   n->pprev = NULL;
}

static INLINE int
HList_IsUnlinked(struct HListNode *n)
{
   return !(n->next || n->pprev);
}

#define DEFAULT_HASH_SHIFT 12
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

/**
 * hlist_for_each_entry	- iterate over list of given type
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first; pos &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

#define hlist_for_each_entry_safe(tpos, pos, n, head, member) 		 \
	for (pos = (head)->first;					 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)


/* Fast hashing routine for a long.
   (C) 2002 William Lee Irwin III, IBM */

/*
 * Knuth recommends primes in approximately golden ratio to the maximum
 * integer representable by a machine word for multiplicative hashing.
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * These primes are chosen to be bit-sparse, that is operations on
 * them can use shifts and additions instead of multiplications for
 * machines where multiplications are slow.
 */
#if BITS_PER_LONG == 32
/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME 0x9e370001UL
#elif BITS_PER_LONG == 64
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME 0x9e37fffffffc0001UL
#else
#error Define GOLDEN_RATIO_PRIME for your wordsize.
#endif

static INLINE unsigned long 
Hash_64(u64 val, unsigned int bits)
{
   ulong res;

	u64 hash = val;

	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	u64 n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;

	/* High bits are more random, so use them. */
   res = hash >> (64 - bits);

   //LOG("0x%llx 0x%x\n", val, res);

   return res;
	//return hash >> (64 - bits);
}

static INLINE unsigned long 
Hash_Long(unsigned long val, unsigned int bits)
{
	unsigned long hash = val;

#if BITS_PER_LONG == 64
	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	unsigned long n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;
#else
	/* On some cpus multiply is faster, on others gcc will do shifts */
	hash *= GOLDEN_RATIO_PRIME;
#endif

	/* High bits are more random, so use them. */
	return hash >> (BITS_PER_LONG - bits);
}

#ifdef __cplusplus
}
#endif
