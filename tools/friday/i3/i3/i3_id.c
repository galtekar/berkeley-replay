/***************************************************************************
                          i3_id.c  -  description
                             -------------------
    begin                : Nov 20 2002
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include "i3.h"
#include "i3_fun.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

/***************************************************************************
 *  alloc_i3_id - allocate a indientifie data structure
 *
 *  return:
 *    allocated identifier 
 ***************************************************************************/

ID *alloc_i3_id()
{
  ID *id;

  if ((id = (ID *)malloc(sizeof(ID))) == NULL)
    panic("alloc_i3_id: memory allocation error.\n");
  return id;
}


/***************************************************************************
 *  init_i3_id - initialized identifier
 *
 *  input
 *    id, id1 - set id to id1
 *    
 ***************************************************************************/

void init_i3_id(ID *id, ID *id1)
{
  memcpy(id->x, id1->x, sizeof(ID));
}


/***************************************************************************
 *  free_i3_id - free identifier
 *
 *  input:
 *    id to be freed
 ***************************************************************************/

void free_i3_id(ID *id)
{
  free(id);
}


/***************************************************************************
 *  duplicate_i3_id - create a replica of identifier id
 *
 *  input:
 *    id - identifier to be duplicated
 *
 *  return:
 *    replica of id
 ***************************************************************************/

ID *duplicate_i3_id(ID *id)
{
  ID *idnew = alloc_i3_id();

  init_i3_id(idnew, id);
  return idnew;
}

/***************************************************************************
 *  pack_i3_id - convert identifier in packet format
 *
 *  input:
 *    p - address of the buffer where the id is to be stored in 
 *        packet format (the buffer is pre-allocated)
 *    id - id to be converted in packet format
 *    
 *  output:
 *    length - length of the identifier in packet format
 ***************************************************************************/

void pack_i3_id(char *p, ID *id, unsigned short *length)
{
  memcpy(p, id->x, sizeof(ID));
  *length = sizeof(ID);
}



/***************************************************************************
 *  unpack_i3_id - copy identifier info from packet to an identifier 
 *                 data structure 
 *
 *  input:
 *    p - address where identifier is stored in packet format
 *   
 *  return:
 *    id - identifier data structure
 * 
 *  output:
 *    length - length of the id info in packet format
 *
 ***************************************************************************/

ID *unpack_i3_id(char *p, unsigned short *length)
{
  ID *id = alloc_i3_id();
 
  memcpy(id->x, p, sizeof(ID));
  *length = sizeof(ID);

  return id;
}

// Assume: s has enough space
void sprintf_i3_id(char* s, ID *id)
{
   uint i; 

   *s = 0;
   for (i = 0; i < sizeof(ID); i++)
   {
     char ts[20];
     sprintf(ts, "%02x", (int)(id->x[i]));
     strcat(s,ts);
   }
}



/*************************************
 ** print i3_id; just for test   **
 *************************************/

void fprintf_i3_id(FILE *fp, ID *id, int indent)
{
   char buf[INDENT_BUF_LEN];
   uint i;

  memset(buf, ' ', INDENT_BUF_LEN);
  buf[indent] = 0;

  fprintf(fp, "%s id: ", buf);
  for (i = 0; i < sizeof(ID); i++)
    fprintf(fp, "%02x", (int)(id->x[i])); 
  fprintf(fp, "\n");
}

void printf_i3_id(ID *id, int indent)
{
   char buf[INDENT_BUF_LEN];
   uint i;

  memset(buf, ' ', INDENT_BUF_LEN);
  buf[indent] = 0;

  printf("%s id: ", buf);
  for (i = 0; i < sizeof(ID); i++)
    printf("%02x", (int)(id->x[i])); 
  printf("\n");
}

/************************************************************************
 * Compare two ids and return an integer less than, equal  to, or
 * greater than zero if id1 is found, respectively, to be less than,
 * to match, or be greater than s2.
 ***********************************************************************/
int compare_ids(ID *id1, ID *id2)
{
    assert(NULL != id1 && NULL != id2);
    return memcmp(id1->x, id2->x, ID_LEN);
}

/************************************************************************
 * Purpose: Convert a string to i3 id eg. read from file
 * XXX Check where this should be included ... may be in some other
 * file -- To check for bugs also
 ***********************************************************************/
static unsigned char todigit(char ch)
{
    if (isdigit((int) ch))
	return (ch - '0');
    else
	return (10 + ch - 'a');
}

ID atoi3id(char *str)
{
    ID id;
    int i, len;
    
    assert((len = strlen(str)) <= 2*ID_LEN);
    memset(id.x, 0, ID_LEN);
    
    if (len % 2 != 0) {
	str[len] = '0';
	len++;
    }
    
    for (i = 0; i < len/2; i++)
	id.x[ i ] = (todigit(str[2*i]) << 4) | todigit(str[2*i+1]);

    str[len--] = 0;	// to restore old str
    return id;
}

/************************************************************************
 * Purpose:  Public ID constraint
 * 	Public IDs (ie. IDs that need to be protected from
 * 	impersonation) need to have "public_id" bit set. The public_id
 * 	bit is the last bit in the prefix.
 ***********************************************************************/
void set_id_type(ID *id,  char type)
{
    uint8_t mask = 1;

    if (I3_ID_TYPE_PUBLIC == type) 
	id->x[PREFIX_LEN-1] |= mask;
    else if (I3_ID_TYPE_PRIVATE == type)
	id->x[PREFIX_LEN-1] &= ~mask;
    else
	panic("set_id_type: Unknown type: %d\n", type);
}

char get_id_type(ID *id)
{
    uint8_t mask = 1;

    if ((id->x[PREFIX_LEN-1] & mask) == 1)
	return I3_ID_TYPE_PUBLIC;
    else
	return I3_ID_TYPE_PRIVATE;
}
