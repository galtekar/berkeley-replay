#ifndef _NAT_TABLE_H
#define _NAT_TABLE_H

typedef struct hash_node_struct
{
  ID id;
  i3_addr* real_addr;
  i3_addr* fake_addr;
  unsigned long tv;
  uint16_t plen;
  struct hash_node_struct* next;
} hash_node;

void nat_table_initialize();
void nat_table_insert(ID* id, i3_addr* fake_addr, 
	uint16_t plen, i3_addr* real_addr, unsigned long tv);
void nat_table_retrieve(ID* id, i3_addr* fake_addr,
	uint16_t plen, i3_addr **real_addr, unsigned long tv);
void nat_table_remove(ID* id,i3_addr* fake_addr,uint16_t);

#endif
