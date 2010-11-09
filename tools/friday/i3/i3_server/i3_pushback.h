/***************************************************************************
                         i3_pushback.h  -  description
                             -------------------
    begin                : Aug 26 2003
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#include "i3.h"

#ifndef I3_SRV_PUSHBACK_H
#define I3_SRV_PUSHBACK_H

#define SRV_PBACK_REPLACE_THRESHOLD 0.2
#define SRV_PBACK_TIMEOUT   2000 /* in miliseconds */

#define SRV_PBACK_TABLE_SIZE 16384

#define SRV_PBACK_HASH(id)  \
   ((*(unsigned long *)&id->x[0] ^ \
     *(unsigned long *)&id->x[1] ^ \
     *(unsigned long *)&id->x[3] ^ \
     *(unsigned long *)&id->x[4] ^ \
     *(unsigned long *)&id->x[5] ^ \
     *(unsigned long *)&id->x[6] ^ \
     *(unsigned long *)&id->x[7]) % SRV_PBACK_TABLE_SIZE)


typedef struct srv_pback_entry {
  ID id;
  struct timeval time;  /* in seconds */
} srv_pback_entry;

#endif // I3_SRV_PUSHBACK_H

