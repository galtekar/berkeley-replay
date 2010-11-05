#pragma once

#include "debug.h"
#include "misc.h"

#include <limits.h>

/* ----- A simple token-bucket rate limiter ----- */

struct TokenBucketSpec {
   long rate;
   long size;
};

struct TokenBucket {
   struct TokenBucketSpec spec;

   long bucket;
   ulong lastUpdateMs;
#if DEBUG
   ulong isInitialized;
#endif
};

static INLINE void
TokenBucket_Init(struct TokenBucket *tbP, struct TokenBucketSpec spec)
{
   ASSERT_MSG(spec.rate <= spec.size, "rate=%d size=%d\n", spec.rate, spec.size);

   tbP->spec = spec;
   tbP->bucket = spec.rate;
   tbP->lastUpdateMs = MiscOps_GetTimeInMilliSecs();
#if DEBUG
   tbP->isInitialized = DEBUG_MAGIC;
#endif

   ASSERT(tbP->bucket <= tbP->spec.size);
}

static INLINE void
TokenBucket_Fill(struct TokenBucket *tbP)
{
   ASSERT(tbP->isInitialized == DEBUG_MAGIC);

   const long currTime = MiscOps_GetTimeInMilliSecs();
   const long elapsedTime = currTime - tbP->lastUpdateMs;

   ASSERT(elapsedTime >= 0);

   ASSERT(tbP->spec.rate >= 0);
   ASSERT(tbP->bucket <= tbP->spec.size);

   /* Careful about overflow. */
   const long nrTokensToAdd = MIN((tbP->spec.size - tbP->bucket), 
         (tbP->spec.rate * elapsedTime) / 1000);
   tbP->bucket += nrTokensToAdd;
   ASSERT(tbP->bucket <= tbP->spec.size);

   DEBUG_MSG(8, "nrTokensToAdd=%d tokenBucket=%d\n", nrTokensToAdd,
         tbP->bucket);

   tbP->lastUpdateMs = currTime;
}

static INLINE void
TokenBucket_Consume(struct TokenBucket *tbP, const long val)
{
   ASSERT(tbP->isInitialized == DEBUG_MAGIC);

   ASSERT(tbP->bucket >= LONG_MIN);

   /* Careful about underflow. */
   const long nrTokensToRm = MIN(tbP->bucket - LONG_MIN, val);

   tbP->bucket -= nrTokensToRm;
}

static INLINE int
TokenBucket_IsConsumable(struct TokenBucket *tbP, const long val)
{
   ASSERT(tbP->isInitialized == DEBUG_MAGIC);
   DEBUG_MSG(8, "bucket=%d val=%d\n", tbP->bucket, val);

   return tbP->bucket >= val;
}
