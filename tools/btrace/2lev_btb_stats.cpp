/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2005 Intel Corporation 
All rights reserved. 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include <iostream>
#include <sys/mman.h>
#include <signal.h>
#include "pin.H"
#include "../InstLib/instlib.H"

#if 0
using namespace INSTLIB;

FILTER filter;
#endif

#define MAX_SLOTS 50000
#define PERF 0
#undef STATS

#if PERF
#define STATS 0
#undef ASSERTX
#define ASSERTX(x)
#else
#define STATS 1
#endif

#define UPDATE_BUFFER 0
#define BRCNT 0
#define USE_RSB 0

#if BRCNT
#define UPDATE_BRCNT(x) x
#else
#define UPDATE_BRCNT(x)
#endif

#if STATS
#define STATS_ONLY(x) x
#else
#define STATS_ONLY(x)
#endif

#if UPDATE_BUFFER
#define LOG_TO_BUFFER(x) x
#else
#define LOG_TO_BUFFER(x)
#endif

#define BUFSIZE 500000000
#if USE_RSB
#define RSB_SIZE 128 /* gimp maxCallDepth=39 */
#endif

#define BYTES2BITS(x) ((x)*8)
#define IDX2SLOTS(x) (((x)/ BYTES2BITS(sizeof(BucketType))) + 1)

typedef uint BucketType;
typedef unsigned char uchar;


FILE* fp = NULL;

struct BranchInfoStruct {
   uint idx;
   uint target;
#if STATS
   uint numTurns;
   uint numBranches;
#endif
   uint table;
   uchar shr;
};

struct ThreadInfoStruct {
   struct BranchInfoStruct *brInfos;
   BucketType *buf;
   BucketType *bufPtr;
   uint brCnt;
   uint numBranches;
#if STATS
   uint numCondDirect, numCondIDirect;
   uint numUncondDirect, numUncondIDirect;
   uint numUncondIDirectCalls, numUncondIDirectJumps, numRets;
   uint condMispredicts, btbMispredicts, rsbMispredicts;
   uint numCondExec, numCallExec, numRetExec, numBtbExec;
   int callDepth;
   int maxCallDepth;
#endif
#if USE_RSB
   uint rsb[RSB_SIZE];
   uint rsbIdx;
#endif
};

TLS_KEY infoKey;


VOID IsTakenMisprediction(VOID* tiPtr, VOID* brInfoPtr) {
   struct ThreadInfoStruct *ti = (struct ThreadInfoStruct*)tiPtr;
   struct BranchInfoStruct *brp = (struct BranchInfoStruct*)brInfoPtr;

   STATS_ONLY(brp->numBranches++;);
   UPDATE_BRCNT(ti->brCnt++;);

   uint idx = brp->shr & 0xF;
   uchar tabIdx = idx*2;
   ASSERTX(0 <= idx && idx < 16);
   uint mask = 0x3 << tabIdx;
   uchar pred = (brp->table & mask) >> tabIdx;
   //ASSERTX(pred <= 3);
#if 1
   if (pred > 0) {
      pred--;
      brp->table = (brp->table & ~mask) | ((uint)pred << tabIdx);
   }
   brp->shr = (brp->shr << 1) | 0x1;
   if (pred & 0x2) {
      LOG_TO_BUFFER(*(ti->bufPtr) = ti->brCnt;);
      ti->bufPtr++;
      STATS_ONLY(ti->condMispredicts++;);
   }
#endif
   STATS_ONLY(ti->numCondExec++;);
}

VOID IsNotTakenMisprediction(VOID* tiPtr, VOID* brInfoPtr) {
   struct ThreadInfoStruct *ti = (struct ThreadInfoStruct*)tiPtr;
   struct BranchInfoStruct *brp = (struct BranchInfoStruct*)brInfoPtr;

   STATS_ONLY(brp->numBranches++;);
   UPDATE_BRCNT(ti->brCnt++;);

   uint idx = brp->shr & 0xF;
   uchar tabIdx = idx*2;
   ASSERTX(0 <= idx && idx < 16);
   uint mask = 0x3 << tabIdx;
   uchar pred = (brp->table & mask) >> tabIdx;
   //ASSERTX(pred <= 3);
#if 1
   if (pred < 3) {
      pred++;
      brp->table = (brp->table & ~mask) | ((uint)pred << tabIdx);
   }
   brp->shr = brp->shr << 1;
   if (!(pred & 0x2)) {
      LOG_TO_BUFFER(*(ti->bufPtr) = ti->brCnt;);
      ti->bufPtr++;
      STATS_ONLY(ti->condMispredicts++;);
   }
#endif
   STATS_ONLY(ti->numCondExec++;);
}

VOID IsUIJumpTargetMisprediction(VOID* tiPtr, VOID* brInfoPtr, ADDRINT actualTarget) {
   struct ThreadInfoStruct *ti = (struct ThreadInfoStruct*)tiPtr;

   UPDATE_BRCNT(ti->brCnt++;);

   struct BranchInfoStruct *brp = (struct BranchInfoStruct*)brInfoPtr;


   if (brp->target != actualTarget) {
#if 1
      brp->target = actualTarget;
      LOG_TO_BUFFER(*(ti->bufPtr) = ti->brCnt;);
      ti->bufPtr++;
      LOG_TO_BUFFER(*(ti->bufPtr) = actualTarget;);
      ti->bufPtr++;
      STATS_ONLY(ti->btbMispredicts++;);
#endif
   }
   STATS_ONLY(ti->numBtbExec++;);
}

#if STATS
#define PushToRSB() \
   ti->rsb[ti->rsbIdx] = retAddr; \
   ti->rsbIdx = (ti->rsbIdx + 1) % RSB_SIZE; \
   ASSERTX(ti->rsbIdx < RSB_SIZE); \
   ti->callDepth++; \
   if (ti->callDepth > ti->maxCallDepth) { \
      ti->maxCallDepth = ti->callDepth; \
   } \
   STATS_ONLY(ti->numCallExec++;);
#else
#define PushToRSB() \
   ti->rsb[ti->rsbIdx] = retAddr; \
   ti->rsbIdx = (ti->rsbIdx + 1) % RSB_SIZE; \
   ASSERTX(ti->rsbIdx < RSB_SIZE);
#endif

#if USE_RSB
VOID UDCallUpdateRSB(VOID* tiPtr, ADDRINT retAddr) {
   struct ThreadInfoStruct *ti = (struct ThreadInfoStruct*)tiPtr;

   UPDATE_BRCNT(ti->brCnt++;);
   PushToRSB();
}

VOID UICallUpdateRSB(VOID* tiPtr, VOID* brInfoPtr, ADDRINT retAddr, ADDRINT actualTarget) {
   struct ThreadInfoStruct *ti = (struct ThreadInfoStruct*)tiPtr;
   struct BranchInfoStruct *brp = (struct BranchInfoStruct*)brInfoPtr;

   UPDATE_BRCNT(ti->brCnt++;);
   PushToRSB();

   if (brp->target != actualTarget) {
      brp->target = actualTarget;
      LOG_TO_BUFFER(*(ti->bufPtr) = ti->brCnt;);
      ti->bufPtr++;
      LOG_TO_BUFFER(*(ti->bufPtr) = actualTarget;);
      ti->bufPtr++;
      STATS_ONLY(ti->btbMispredicts++;);
   }
}

VOID IsRetTargetMisprediction(VOID* tiPtr, ADDRINT actualTarget) {
   struct ThreadInfoStruct *ti = (struct ThreadInfoStruct*)tiPtr;

   UPDATE_BRCNT(ti->brCnt++;);
   ti->rsbIdx = (ti->rsbIdx - 1) % RSB_SIZE;
   ASSERTX(ti->rsbIdx < RSB_SIZE);

   STATS_ONLY(ti->callDepth--);
   if (ti->rsb[ti->rsbIdx] != actualTarget) {
      LOG_TO_BUFFER(*(ti->bufPtr) = ti->brCnt;);
      ti->bufPtr++;
      LOG_TO_BUFFER(*(ti->bufPtr) = actualTarget;);
      ti->bufPtr++;
      STATS_ONLY(ti->rsbMispredicts++;);
   }
   STATS_ONLY(ti->numRetExec++;);
}
#endif

VOID Instruction(INS ins, VOID *v) {
   struct ThreadInfoStruct *ti;
   int match = 0;

   //printf("tid=%d infoKey=%d\n", PIN_ThreadId(), infoKey);
   ti = (struct ThreadInfoStruct*)PIN_GetThreadData(infoKey, PIN_ThreadId());
   ASSERTX(ti);

   if (INS_IsBranchOrCall(ins)) {
      if (INS_HasFallThrough(ins)) {
         /* Conditional. */

#if 1
         if (INS_IsDirectBranchOrCall(ins)) {
            STATS_ONLY(ti->numCondDirect++;);

            /* Conditional direct. */
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, 
                  (AFUNPTR)IsTakenMisprediction,
                  IARG_PTR, ti,
                  IARG_PTR, &ti->brInfos[ti->numBranches],
                  IARG_END);


            INS_InsertCall(ins, IPOINT_AFTER,
                  (AFUNPTR)IsNotTakenMisprediction,
                  IARG_PTR, ti,
                  IARG_PTR, &ti->brInfos[ti->numBranches], 
                  IARG_END);
         } else {
            /* Conditional indirect. */
            STATS_ONLY(ti->numCondIDirect++;);
            ASSERTX(!INS_IsCall(ins));
            ASSERTX(0);
         }
#endif

         match = 1;
      } else { 
#if 1
         /* Unconditional. */
         if (INS_IsIndirectBranchOrCall(ins)) {
            /* Unconditional indirect. */
            STATS_ONLY(ti->numUncondIDirect++;);

#if USE_RSB
            if (INS_IsProcedureCall(ins)) {
               STATS_ONLY(ti->numUncondIDirectCalls++;);
               INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                     (AFUNPTR)UICallUpdateRSB,
                     IARG_PTR, ti,
                     IARG_PTR, &ti->brInfos[ti->numBranches],
                     IARG_RETURN_IP,
                     IARG_BRANCH_TARGET_ADDR,
                     IARG_END);
            } else if (INS_IsRet(ins)) {
               STATS_ONLY(ti->numRets++;);
               INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                     (AFUNPTR)IsRetTargetMisprediction,
                     IARG_PTR, ti,
                     IARG_BRANCH_TARGET_ADDR,
                     IARG_END);
            } else {
#endif
               STATS_ONLY(ti->numUncondIDirectJumps++;);

               INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                     (AFUNPTR)IsUIJumpTargetMisprediction,
                     IARG_PTR, ti,
                     IARG_PTR, &ti->brInfos[ti->numBranches],
                     IARG_BRANCH_TARGET_ADDR,
                     IARG_END);
#if USE_RSB
            }
#endif

            match = 1;
         } else {
            /* Unconditional direct transfer. */

            STATS_ONLY(ti->numUncondDirect++;);
#if USE_RSB
            if (INS_IsProcedureCall(ins)) {
               STATS_ONLY(ti->numUncondIDirectCalls++;);
               INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                     (AFUNPTR)UDCallUpdateRSB,
                     IARG_PTR, ti,
                     IARG_RETURN_IP,
                     IARG_END);
            }
#endif
         }
#endif
      }
   }

   if (match) {
#if STATS && 0
      {
         ADDRINT addr;
         addr = INS_Address(ins);

         fprintf(fp, "%d: 0x%x\n", ti->numBranches,
               addr);
      }
#endif
      ti->numBranches++;
      ASSERTX(ti->numBranches < MAX_SLOTS);
   }
}



#if 0
BOOL SigSegvHandler(THREADID threadIdx, INT32 sig, CONTEXT *ctxt, 
      BOOL hashHndlr, VOID *v)
{
   printf("sigsegv!\n");
   //exit(-1);

   return FALSE;
}
#endif

VOID ThreadBegin(UINT32 threadID, VOID * sp, int flags, VOID *v)
{
   struct ThreadInfoStruct *ti;
   size_t infoSize;

   ti = (struct ThreadInfoStruct*) malloc(sizeof(struct ThreadInfoStruct));
   ASSERTX(ti);
   memset(ti, 0, sizeof(struct ThreadInfoStruct));

   ti->buf = (BucketType*)malloc(BUFSIZE);
   ASSERTX(ti->buf);
   //Not necessary.
   //memset(ti->buf, 0, BUFSIZE);
   ti->bufPtr = ti->buf;

   infoSize = sizeof(struct BranchInfoStruct) * MAX_SLOTS;
   ti->brInfos = (struct BranchInfoStruct*)malloc(infoSize);
   ASSERTX(ti->brInfos);
   memset(ti->brInfos, 0, sizeof(infoSize));

   PIN_SetThreadData(infoKey, ti, threadID);
   printf("ThreadBegin: tid=%d infoKey=%d\n", PIN_ThreadId(), infoKey);
}

VOID ThreadEnd(UINT32 threadID, INT32 code, VOID *v)
{
#if STATS
   struct ThreadInfoStruct *ti;

   ti = (struct ThreadInfoStruct*)PIN_GetThreadData(infoKey, threadID);
   fprintf(fp, 
         "%d: Static stats:\n"
         "numBranches: %u -- \n"
         "\tnumCondDirect=%u numCondIDirect=%u\n"
         "\tnumUncondDirect=%u numUncondIDirect=%u\n"
         "\tnumUncondIDirectCalls=%u numUncondIDirectJumps=%u numRets=%u\n"
         "Dynamic stats:\n"
         "\tbrCnt=%u\n"
         "\tnumCondExec=%u numBtbExec=%u numCallExec=%u numRetExec=%u\n"
         "\tcondMispredicts=%u btbMispredicts=%u rsbMispredicts=%u\n"
         "\tmaxCallDepth=%u\n"
         , threadID, ti->numBranches, 
         ti->numCondDirect, ti->numCondIDirect,
         ti->numUncondDirect, ti->numUncondIDirect,
         ti->numUncondIDirectCalls, ti->numUncondIDirectJumps, ti->numRets,
         ti->brCnt,
         ti->numCondExec, ti->numBtbExec, ti->numCallExec, ti->numRetExec,
         ti->condMispredicts, ti->btbMispredicts, ti->rsbMispredicts,
         ti->maxCallDepth
         );

   fprintf(fp, "%d: totalBytes=%lu\n", 
         threadID, (ulong)((ulong)ti->bufPtr - (ulong)ti->buf));
#endif
}

VOID Fini(INT32 code, VOID *v) {
   if (PIN_ThreadId() == 0) {
      ThreadEnd(PIN_ThreadId(), 0, NULL);
   }

   fclose(fp);
}
int main(INT32 argc, CHAR **argv)
{

   fp = fopen("out.bin", "w+");
   ASSERTX(fp != NULL);

   PIN_Init(argc, argv);
#if 0
   PIN_AddSignalInterceptFunction(SIGSEGV, &SigSegvHandler, NULL);
#endif
#if 1
   infoKey = PIN_CreateThreadDataKey(NULL);
   ASSERTX(infoKey != -1);
   PIN_AddThreadBeginFunction(ThreadBegin, 0);
   PIN_AddThreadEndFunction(ThreadEnd, 0);
   PIN_AddFiniFunction(Fini, 0);
   INS_AddInstrumentFunction(Instruction, 0);
#endif

   if (PIN_ThreadId() == 0) {
      ThreadBegin(PIN_ThreadId(), 0, 0, NULL);
   }

   // Never returns
   PIN_StartProgram();

   return 0;
}
