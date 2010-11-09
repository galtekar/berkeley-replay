/***************************************************************************
                          i3_header.c  -  description
                             -------------------
    begin                : Nov 27 2002
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include "i3.h"
#include "i3_fun.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/***************************************************************************
 *  alloc_i3_header - allocate i3 header data structure
 *
 *  return:
 *    pointer to the allocated data structure 
 ***************************************************************************/

i3_header *alloc_i3_header()
{
  struct i3_header *hdr;

  /* XXX: just simply call alloc for now; preallocate a pool of buffers 
     in the future */
  hdr = (i3_header *)calloc(1, sizeof(i3_header));
  if (hdr) 
    return hdr;

  panic("FATAL ERROR: memory allocation error in alloc_i3_header\n");
  return NULL;
}


/***************************************************************************
 *  init_i3_header - initialize i3 header data structure
 *
 *  input:
 *    hdr - header data structure to be initialized
 *    data - specifies whether the packet contains data payload
 *    stack - stack of IDs used to route the packet
 *    option_list - list of options 
 ***************************************************************************/

void init_i3_header(i3_header *hdr, char data,
		    i3_stack *stack, i3_option_list *option_list)
{
  hdr->ver = I3_v01;
  hdr->flags = (data ? I3_DATA : 0);
  hdr->stack = stack;
  if (option_list) {
    hdr->flags |= I3_OPTION_LIST;
    hdr->option_list = option_list;
  }
}

/***************************************************************************
 *  free_i3_header - free header data structure
 *
 *  input:
 *    header to be freed
 *
 ***************************************************************************/

void free_i3_header(i3_header *hdr)
{
  if (hdr->stack)
    free_i3_stack(hdr->stack);
  if (hdr->option_list)
    free_i3_option_list(hdr->option_list);
  free(hdr);
}


/***************************************************************************
 *  pack_i3_header - convert a header data structure in packet format
 *
 *  input:
 *    p - address of the buffer where the header is to be stored in 
 *        packet format (pre-allocated)
 *    hdr - header to be converted in packet format
 *    
 *  output:
 *    length - length of the header in packet format (bytes)
 ***************************************************************************/

void pack_i3_header(char *p, i3_header *hdr, unsigned short *length)
{
  unsigned short len;

  *p = hdr->ver;
  // printf("%d %d\n",p[0],*length);
  
  p += sizeof(char); *length = sizeof(char);
  
  *p = hdr->flags;
  // printf("%d %d\n",p[0],*length);
    
  if (!hdr->option_list)
    *p = *p & (~I3_OPTION_LIST); 
  else
    *p = *p | I3_OPTION_LIST;
  p += sizeof(char); *length += sizeof(char);
  // printf("%d %d\n",p[0],*length);

  *p = 0;
  pack_i3_stack(p, hdr->stack, &len);
  
  *length += len; p += len;

  if (hdr->option_list) {
    pack_i3_option_list(p, hdr->option_list, &len);
    *length += len;
  }
}


unsigned short get_i3_header_len(i3_header *hdr)
{
  unsigned short length;

  length = 2 * sizeof(char); /* version + flags*/ 

  length += get_i3_stack_len(hdr->stack);

  if (hdr->option_list) {
      length += get_i3_option_list_len(hdr->option_list);
  }

  return length;
}


/***************************************************************************
 *  unpack_i3_header - allocate an i3_header data structure
 *                      and copy info from packet into it
 *
 *  input:
 *    p - address where header is stored in packet format
 *    
 *  output:
 *    length - length of the header info in packet format (bytes)
 *
 ***************************************************************************/

i3_header *unpack_i3_header(char *p, unsigned short *length)
{
  unsigned short len;
  i3_header *hdr = alloc_i3_header();

  // printf("%d %d\n",p[0],*length);
  hdr->ver = p[0];
  p += sizeof(char); *length = sizeof(char);

  //    printf("%d %d\n",p[0],*length);
  hdr->flags = p[0]; 
  p += sizeof(char); *length += sizeof(char);

  // printf("%d %d\n",p[0],*length);
  hdr->stack = unpack_i3_stack(p, &len);
  p += len; *length += len;
  // printf("%d %d\n",p[0],*length);
   
  if (hdr->flags & I3_OPTION_LIST) {
    // printf("OPTIIONS: %d %d\n",p[0],*length);
    hdr->option_list = unpack_i3_option_list(p, &len);
    *length += len;
    p += len;
  }

  return hdr;
}
 

/***************************************************************************
 *  check_i3_header - check whether this si a legal header (should be
 *                    called when an i3 packet is received)
 *
 *  input:
 *    p - address where header is stored in packet format
 *
 *  return:
 *    error if any; FALSE otherwise
 *    
 ***************************************************************************/

int check_i3_header(char *p, int pkt_len)
{
  unsigned short len;
  int            rc;
  char           flags;

  /* check version */
  if (p[0] != I3_v01)
    return I3_ERR_INVALID_VER;

  p += sizeof(char); pkt_len -= sizeof(char); /* account for version */

  /* check flags */
  flags = p[0] & 0xf0;
  if (flags & ~(I3_DATA | I3_OPTION_LIST | I3_FIRST_HOP))
    return I3_ERR_INVALID_FLAGS;

  p += sizeof(char); pkt_len -= sizeof(char); /* account for flags */

  /* check ID stack */
  if ((rc = check_i3_stack(p, &len)) != FALSE)
    return rc;

  p += len; pkt_len -= len;

  /* check option list */
  if (flags & I3_OPTION_LIST) 
    if ((rc = check_i3_option_list(p, &len)) != FALSE)
      return rc;

  pkt_len -= len;
  if (pkt_len < 0)
    return I3_ERR_PKT_LEN_TOO_SHORT;

  return FALSE;
}
 

/***************************************************************************
 *  get_first_id - return the address of the first character
 *                 in the stack
 *
 *  input:
 *    p - i3 packet 
 *    
 *  return:
 *    pointer to the first ID in the stack
 *
 ***************************************************************************/

char *get_first_id(char *p)
{
  /* stack follows after version and "flags" and "stack_length" fields */
  return p + 3*sizeof(char);
}

/*********************
 ** print i3_header **
 *********************/

void printf_i3_header(struct i3_header *hdr, int indent)
{
  char buf[INDENT_BUF_LEN];

  memset(buf, ' ', indent);
  buf[indent] = 0;

  printf("%s header (version = %x, flags = %x) :\n", 
	 buf, hdr->ver, hdr->flags);

  printf_i3_stack(hdr->stack, indent + INDENT_CONST);
  if (hdr->option_list)
    printf_i3_option_list(hdr->option_list, indent + INDENT_CONST);

  fflush(stdout);
}

