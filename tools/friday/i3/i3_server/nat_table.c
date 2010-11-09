#include <i3.h>
#include <i3_addr.h>
#include <i3_trigger.h>
#include "i3_matching.h"
#include "nat_table.h"

#define NAT_HASH_TABLE_SIZE 10000

hash_node *nattable[NAT_HASH_TABLE_SIZE] ;

#define NAT_HASH_ID(id) (((*(uint32_t *)&(id)->x[0])^(*(uint32_t *)&(id)->x[4])^\
   (*(uint32_t *)&(id)->x[8]) ^ (*(uint32_t *)&(id)->x[12]))% NAT_HASH_TABLE_SIZE)

void nat_table_initialize()
{
  int i;
  for(i=0;i<NAT_HASH_TABLE_SIZE;i++)
    nattable[i]=NULL;
}

void nat_table_insert(ID* id,i3_addr* fake_addr,uint16_t plen,i3_addr* real_addr,unsigned long tv)
{
  int idx = NAT_HASH_ID(id);
  hash_node* list = nattable[idx];
  hash_node* newnode;

  while ( list != NULL )
  {
    if ( !compare_ids(&(list->id),id) && addr_equal(list->fake_addr,fake_addr) && list->plen == plen)
    {
      free_i3_addr(list->real_addr);
      list->real_addr = duplicate_i3_addr(real_addr);
      list->tv = tv;
      return;
    }
    list = list->next;
  }

  newnode = (hash_node*) malloc(sizeof(hash_node));
  init_i3_id(&(newnode->id),id);
  newnode->real_addr = duplicate_i3_addr(real_addr);
  newnode->fake_addr = duplicate_i3_addr(fake_addr);
  newnode->tv = tv;
  newnode->plen = plen;
  newnode->next = nattable[idx];
  nattable[idx] = newnode;
}

void nat_table_retrieve(ID* id, i3_addr* fake_addr, 
		uint16_t plen, i3_addr **real_addr, unsigned long tv)
{
  int idx = NAT_HASH_ID(id);
  hash_node* list = nattable[idx];

  while ( list != NULL )
  {
    if ( !compare_ids(&(list->id),id) && addr_equal(list->fake_addr,fake_addr) && (tv-list->tv) <= TRIGGER_TIMEOUT && list->plen == plen)
    {
      if ( real_addr )
	*real_addr = duplicate_i3_addr(list->real_addr);
      return;
    }

    if ( (tv - list->tv) > TRIGGER_TIMEOUT )
    {
      hash_node* curnode;
      curnode = list->next;
      nat_table_remove(&(list->id),list->fake_addr,list->plen);
      list = curnode;
    }
    else
      list = list->next;
  }

}

void nat_table_remove(ID* id,i3_addr* fake_addr,uint16_t plen)
{
  int idx = NAT_HASH_ID(id);
  hash_node* list = nattable[idx];

  if ( list == NULL )
    return;

  if ( !compare_ids(&(list->id),id) && addr_equal(list->fake_addr,fake_addr) && list->plen == plen)
  {
    free_i3_addr(list->real_addr);
    free_i3_addr(list->fake_addr);
    nattable[idx] = list->next;
    free(list);
    return;
  }
   
  while ( list->next != NULL)
  {
    if ( !compare_ids(&(list->next->id),id) && addr_equal(list->next->fake_addr,fake_addr) && list->next->plen == plen )
    {
      hash_node* torem;
      free_i3_addr(list->next->real_addr);
      free_i3_addr(list->next->fake_addr);
      torem = list->next;
      list->next = torem->next;
      free(torem);
      return;
    }
    list = list->next;
  }

}
