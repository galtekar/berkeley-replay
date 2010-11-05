#pragma once

#ifndef __cplusplus

#include "debug.h"

/* ----- String with reference counting ----- */

typedef struct {
   char *strP;
   int count;
} String;

static INLINE String *
String_Alloc(size_t len)
{
   String *sP = malloc(sizeof(*sP));
   sP->strP = malloc(len);
   sP->count = 1;

   return sP;
}

static INLINE String *
String_Get(String *sP)
{
   sP->count++;

   return sP;
}

static INLINE void
String_Put(String *sP)
{
   sP->count--;

   if (sP->count == 0) {
      ASSERT(sP->strP);
      free(sP->strP);
      sP->strP = NULL;
      free(sP);
      sP = NULL;
   }
}

#endif
