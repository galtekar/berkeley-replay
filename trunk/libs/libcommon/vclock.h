#pragma once

#include "debug.h"

#ifndef MAX_NR_VCPU
#define MAX_NR_VCPU 2
#endif

struct VectorClock {
   uint array[MAX_NR_VCPU];
};

extern uint NR_VCPU;

/* Careful: don't copy rhs's id as well. That would
 * make this a copy operation rather than an
 * update operation. */
static INLINE void
VectorClock_Update(struct VectorClock *to, struct VectorClock *from)
{
   int k;

   for (k = 0; k < NR_VCPU; k++) {
      to->array[k] = MAX(to->array[k], from->array[k]);
   }
}

static INLINE void
VectorClock_Increment(struct VectorClock *vcp, int idx)
{
   ASSERT(idx >= 0);
   ASSERT(idx < NR_VCPU);
   vcp->array[idx]++;

   ASSERT_MSG(vcp->array[idx] != 0, 
         "Vector clock overflow at component %d.\n", idx);
}

static INLINE int
VectorClock_IsHb(const struct VectorClock *a, const struct VectorClock *b)
{
   int k;
   int strictlyLess = 0;

   for (k = 0; k < NR_VCPU; k++) {
      if (b->array[k] < a->array[k]) {
         return 0;
      }

      if (b->array[k] > a->array[k]) {
         strictlyLess = 1;
      }
   }

   return strictlyLess;
}

static INLINE int
VectorClock_IsEqual(const struct VectorClock *a, const struct VectorClock *b)
{
   int k;

   for (k = 0; k < NR_VCPU; k++) {
      if (a->array[k] != b->array[k]) {
         return 0;
      }
   }

   return 1;
}

static INLINE int
VectorClock_IsParallel(const struct VectorClock *a, const struct VectorClock *b)
{
   return !VectorClock_IsHb(a, b) && !VectorClock_IsHb(b, a);
}

static INLINE int
VectorClock_IsStrictlyParallel(const struct VectorClock *a, 
                               const struct VectorClock *b)
{
   return VectorClock_IsParallel(a, b) && !VectorClock_IsEqual(a, b);
}

static INLINE void
VectorClock_Minimize(struct VectorClock *to, 
      struct VectorClock *from)
{
   int k;

   for (k = 0; k < NR_VCPU; k++) {
      to->array[k] = MIN(to->array[k], from->array[k]);
   }
}

static INLINE void
VectorClock_InitWithMax(struct VectorClock *to)
{
   int k;

   for (k = 0; k < NR_VCPU; k++) {
      to->array[k] = UINT_MAX;
   }
}

#define DECLARE_VCSTR(s) char s[NR_VCPU*12+10]

/* XXX: not string length safe. */
static INLINE const char *
VectorClock_ToStr(char *to, const struct VectorClock *from)
{
   int k;
   char *toStr = to;

   toStr[0] = 0;

   strcat(toStr, "( ");
   for (k = 0; k < NR_VCPU; k++) {
      char tmp[32];
      int res;

      res = snprintf(tmp, sizeof(tmp), "%8.8d ", from->array[k]);
      ASSERT(res >= 0 && res < sizeof(tmp));
      strcat(toStr, tmp);
   }
   strcat(toStr, ")");

   return toStr;
}

static INLINE uint
VectorClock_GetElem(const struct VectorClock *vc, int id)
{
   ASSERT(id >= 0 && id < NR_VCPU);
   return vc->array[id];
}
