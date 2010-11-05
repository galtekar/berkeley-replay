/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"

struct DebugSegment {
   int id;
   u64 startBrCnt, endBrCnt;
   int level;
};

#define MAX_DEBUG_SEGMENTS 10

static struct DebugSegment dbgSegs[MAX_DEBUG_SEGMENTS];
static int numDbgSegs = 0;

static INLINE struct DebugSegment *
TaskDebugLookupByTaskId(int id)
{
   int i;

   for (i = 0; i < numDbgSegs; i++) {
      if (dbgSegs[i].id == id) {
         return &dbgSegs[i];
      }
   }

   return NULL;
}

int
Task_IsDebugLevel(int lvl)
{
   int print = 0;
   struct DebugSegment *segp;

   /* Entry for current->id gets precedence. */
   if ((segp = TaskDebugLookupByTaskId(current->id)) ||
       (segp = TaskDebugLookupByTaskId(0))) {
      u64 brCnt = BrCnt_Get();
      ASSERT(segp->id == 0 || segp->id == current->id);
#if 0
      printf("brCnt=%llu lvl=%d, id=%d sBr=%llu eBr=%llu lvl=%d\n", 
            brCnt, lvl, segp->id, segp->startBrCnt,
            segp->endBrCnt, segp->level);
#endif
      if (segp->startBrCnt <= brCnt && 
            (brCnt <= segp->endBrCnt || !segp->endBrCnt) &&
            segp->level >= lvl) {
         print = 1;
      }
   } else {
      if (lvl <= debug_level) {
         print = 1;
      }
   }

   return print;
}

void
Task_DebugPrintf(int lvl, int fd, const char* fmt, ...) 
{
   ASSERT(current);
#define __STDERR 2
   if (Task_IsDebugLevel(lvl)) {
      va_list args;

      va_start(args, fmt);
      vlprintf(fd < 0 ? __STDERR : fd, fmt, args);
      va_end(args);
   } 
}

void
Task_DebugStart()
{
   char *filepath = SharedArea_Malloc(PATH_MAX);
   char fname[256];

   snprintf(fname, sizeof(fname), "%s.%d", 
         (!VCPU_IsReplaying() ? "dbg-log" : "dbg-rep"), current->id);

   ASSERT(strlen(session.dir));
   snprintf(filepath, PATH_MAX, "%s/%s", session.dir, fname);

   Debug_Init(filepath, &Task_DebugPrintf, DEBUG_VERBOSE);

   SharedArea_Free(filepath, PATH_MAX);
}

int
Task_DebugInit()
{
   Task_DebugStart();
   return 0;
}
