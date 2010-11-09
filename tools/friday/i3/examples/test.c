#include <stdlib.h>
#include <sys/time.h>

#include "i3.h"
#include "i3_fun.h"
#include "../i3_server/i3_matching.h"

static ptree_node **t_hash_table;

void init_i3_id_from_name(ID *id, char *name)
{
  uint i;

  for (i = 0; i < sizeof(ID); i++)
    id->x[i] = random() % strlen(name);
}
  
void init_id(ID *id)
{
  uint i;

  for (i = 0; i < sizeof(ID); i++)
    id->x[i] = random();

}

i3_stack *create_stack(int len)
{
  int i;
  i3_stack *s = alloc_i3_stack();

  s->len = len;
  s->ids = malloc(sizeof(ID)*s->len);
  for (i = 0; i < s->len; i++) 
    init_id(&s->ids[i]);
  return s;
}

i3_addr *create_addr(char type, int stack_len)
{
  uint i;
  i3_addr *a = alloc_i3_addr();
  
  a->type = type;

  switch(a->type) {
  case I3_ADDR_TYPE_STACK:
    a->t.stack = create_stack(stack_len);
    break;
  case I3_ADDR_TYPE_IPv4:
    a->t.v4.addr.s_addr = random();
    a->t.v4.port = random();
    break;
  case I3_ADDR_TYPE_IPv6:
    a->t.v6.port = random();
    for (i = 0; i < sizeof(struct in6_addr); i++)
      a->t.v6.addr.s6_addr[i] = random();
  }
  return a;
}

i3_trigger *create_trigger(ID *id, i3_addr *to)
{
  i3_trigger *t = alloc_i3_trigger();
  Key key;
  
  init_i3_trigger(t, id, MIN_PREFIX_LEN, to, &key);
  return t;
}

i3_option *create_option(char type, void *entry)
{
  i3_option *o = alloc_i3_option();
  
  init_i3_option(o, type, entry);

  return o;
}



i3_option_list *create_option_list()
{
  ID id;
  i3_option_list *ol = alloc_i3_option_list();

  append_i3_option(ol, create_option(I3_OPT_SENDER, 
				     create_addr(I3_ADDR_TYPE_STACK, 2)));
  init_id(&id);
  append_i3_option(ol, create_option(I3_OPT_TRIGGER_INSERT, 
    create_trigger(&id, create_addr(I3_ADDR_TYPE_IPv4, 0))));
  init_id(&id);
  append_i3_option(ol, create_option(I3_OPT_TRIGGER_INSERT, 
    create_trigger(&id, create_addr(I3_ADDR_TYPE_IPv6, 0))));
  return ol;
}
					    
i3_header *create_header(int stack)
{
  i3_header *h = alloc_i3_header();

  if (stack)
    init_i3_header(h, TRUE, create_stack(3), create_option_list());
  else
    init_i3_header(h, TRUE, NULL, create_option_list());
  return h;
}


void test_pack_unpack()
{
  i3_stack *s;
  i3_addr  *a;
  i3_trigger *t;
  i3_option *o;
  i3_option_list *ol;
  i3_header *h;
  ID id;
  int rc;
  char type;
#define BUF_LEN 2000
  char     buf1[BUF_LEN], buf2[BUF_LEN];
  unsigned short len1, len2;

  /* check stack packing/unpacking */
  buf1[0] = buf2[0] = 0;
  s = create_stack(1);
  //printf_i3_stack(s, 2);
  pack_i3_stack(buf1, s, &len1);
  rc = check_i3_stack(buf1, &len2); printf("checked stack = %d\n", rc);
  free_i3_stack(s);
  s = unpack_i3_stack(buf1, &len2);
  //printf_i3_stack(s, 2);
  pack_i3_stack(buf2, s, &len2);
  free_i3_stack(s);
  if (len1 == len2 && !memcmp(buf1, buf2, len1))
    printf("stack packing/unpacking successful!\n");
  else
    printf("stack packing/unpacking failed!\n");

  /* check address packing/unpacking */
  a = create_addr(I3_ADDR_TYPE_STACK, 3);
  //printf_i3_addr(a, 2);
  pack_i3_addr(buf1, a, &len1);
  free_i3_addr(a);
  rc = check_i3_addr(buf1, &len2, &type); printf("check addr = %d\n", rc);
  a = unpack_i3_addr(buf1, &len2);
  //printf_i3_addr(a, 2);
  pack_i3_addr(buf2, a, &len2);
  free_i3_addr(a);
  if (len1 == len2 && !memcmp(buf1, buf2, len1))
    printf("address packing/unpacking successful!\n");
  else
    printf("address packing/unpacking failed!\n");

  /* check trigger packing/unpacking */
  init_id(&id);
  t = create_trigger(&id, create_addr(I3_ADDR_TYPE_STACK, 3));
  //printf_i3_trigger(t, 2);
  pack_i3_trigger(buf1, t, &len1);
  free_i3_trigger(t);
  rc = check_i3_trigger(buf1, &len2); printf("check trigger = %d\n", rc);
  t = unpack_i3_trigger(buf1, &len2);
  //printf_i3_trigger(t, 2);
  pack_i3_trigger(buf2, t, &len2);
  free_i3_trigger(t);
  if (len1 == len2 && !memcmp(buf1, buf2, len1))
    printf("trigger packing/unpacking successful!\n");
  else
    printf("trigger packing/unpacking failed!\n");

  /* check option packing/unpacking */
  init_id(&id);
  //o = create_option(I3_OPT_SENDER, 
  //		    create_addr(I3_ADDR_TYPE_STACK, 3));
  o = create_option(I3_OPT_TRIGGER_INSERT, 
		    create_trigger(&id, create_addr(I3_ADDR_TYPE_STACK, 3)));
  //printf_i3_option(o, 2);
  pack_i3_option(buf1, o, &len1);
  free_i3_option(o);
  rc = check_i3_option(buf1, &len2); printf("check option = %d\n", rc);
  o = unpack_i3_option(buf1, &len2);
  //printf_i3_option(o, 2);
  pack_i3_option(buf2, o, &len2);
  free_i3_option(o);
  if (len1 == len2 && !memcmp(buf1, buf2, len1))
    printf("option packing/unpacking successful!\n");
  else
    printf("option packing/unpacking failed!\n");

  /* check option_list packing/unpacking */
  ol = create_option_list();
  //printf_i3_option_list(ol, 2);
  pack_i3_option_list(buf1, ol, &len1);
  free_i3_option_list(ol);
  rc = check_i3_option_list(buf1, &len2); printf("check ol = %d\n", rc);
  ol = unpack_i3_option_list(buf1, &len2);
  //printf_i3_option_list(ol, 2);
  pack_i3_option_list(buf2, ol, &len2);
  free_i3_option_list(ol);
  if (len1 == len2 && !memcmp(buf1, buf2, len1))
    printf("option_list packing/unpacking successful!\n");
  else
    printf("option_list packing/unpacking failed!\n");

  h = create_header(TRUE);
  //printf_i3_header(h, 2);
  pack_i3_header(buf1, h, &len1);
  free_i3_header(h); 
  rc = check_i3_header(buf1, len1); printf("check header(1) = %d\n", rc);
  h = unpack_i3_header(buf1, &len2);
  //printf("===\n"); printf_i3_header(h, 2);
  pack_i3_header(buf2, h, &len2);
  free_i3_header(h);
  if (len1 == len2 && !memcmp(buf1, buf2, len1))
    printf("header packing/unpacking successful!\n");
  else
    printf("header packing/unpacking failed!\n");

  h = create_header(FALSE);
  //printf_i3_header(h, 2);
  pack_i3_header(buf1, h, &len1);
  free_i3_header(h); 
  rc = check_i3_header(buf1, len1); printf("check header(2) = %d\n", rc);
  h = unpack_i3_header(buf1, &len2);
  //printf("===\n"); printf_i3_header(h, 2);
  pack_i3_header(buf2, h, &len2);
  free_i3_header(h);
  if (len1 == len2 && !memcmp(buf1, buf2, len1))
    printf("header-without-stack packing/unpacking successful!\n");
  else
    printf("header-without-stack packing/unpacking failed!\n");

}


void test_patricia_tree()
{
  unsigned int i, jj;
#define NUM_TEST_IDS 100000

  i3_trigger *pt[NUM_TEST_IDS];
  int prefix_len;
  struct timeval tp_start, tp_end;

#define BASE 16

  for (jj = 0; jj < 100000; jj++) {
  for (i = 0; i < NUM_TEST_IDS; i++) {
    uint l;
    ID id;

    //printf("****\n");
    if (i < NUM_TEST_IDS/3)
      init_id(&id);
    if (i >= NUM_TEST_IDS/3 && i < 2*NUM_TEST_IDS/3)
      for (l = 0; l < sizeof(ID); l++)
	id.x[l] = pt[i-NUM_TEST_IDS/3]->id.x[l];
    if (i >= 2*NUM_TEST_IDS/3 && i < NUM_TEST_IDS)
      for (l = 0; l < sizeof(ID); l++)
	id.x[l] = pt[i-NUM_TEST_IDS/3]->id.x[l];
    pt[i] = create_trigger(&id, create_addr(I3_ADDR_TYPE_IPv4, 0));
    update_nonce(pt[i]);
    //printf("==\n"); printf_i3_trigger(pt[i], 2);
  }

  gettimeofday(&tp_start, NULL);
  for (i = 0; i < NUM_TEST_IDS/3; i++) 
    insert_trigger(t_hash_table, pt[i], NULL, 0L);
  for (i = NUM_TEST_IDS/3; i < 2*NUM_TEST_IDS/3; i++) 
    insert_trigger(t_hash_table, pt[i], NULL, 0L);
  for (i = 2*NUM_TEST_IDS/3; i < NUM_TEST_IDS; i++) 
    insert_trigger(t_hash_table, pt[i], NULL, 0L);
  gettimeofday(&tp_end, NULL);

  //printf_ptree(root, 2);
  //printf_id_bits(&a[3], ID_LEN_BITS, 2);
  //printf_id_bits(&pn->id, ID_LEN_BITS, 2);


  for (i = NUM_TEST_IDS/3; i < NUM_TEST_IDS/2; i++) 
    remove_trigger(t_hash_table, pt[i]);

  //for (i = 0; i < NUM_TEST_IDS/3; i++) {
  //  prefix_len = 0;
  //  lookup_trigger(&pt[i]->id, &prefix_len);
  //  assert(prefix_len == ID_LEN_BITS);
  //}
  for (i = NUM_TEST_IDS/2; i < NUM_TEST_IDS; i++) {
    prefix_len = 0;
    lookup_trigger(t_hash_table, &pt[i]->id, &prefix_len);
    assert(prefix_len == ID_LEN_BITS);
  }
 
  for (i = 0; i < NUM_TEST_IDS/3; i++) 
    remove_trigger(t_hash_table, pt[i]);
  for (i = NUM_TEST_IDS/2; i < NUM_TEST_IDS; i++) 
    remove_trigger(t_hash_table, pt[i]);
  printf("jj=%d\n", jj);

  for (i = 0; i < NUM_TEST_IDS; i++) {
    //printf("i = %d\n", i);
    free_i3_trigger(pt[i]);
  }
  }

  printf("usec=%ld\n", 
	 1000000*(tp_end.tv_sec - tp_start.tv_sec) + 
	 (tp_end.tv_usec - tp_start.tv_usec));
}


int main(int argc, char **argv)
{

  test_pack_unpack();

  t_hash_table = alloc_trigger_hash_table();
  test_patricia_tree();

  exit(-1);

}
