#pragma once

#include "sharedheap.h"
#include "segment.h"
#include "pagetable.h"
#include "misc.h"

#include "event.h"

#include "syncops.h"

#include "btracer.h"

typedef struct SyscallStruct {
   INT32 num;
   ADDRINT arg0, arg1, arg2, arg3, arg4, arg5;
} Syscall;

extern TLS_KEY infoKey;
extern int numThreads; /* process-private (should not be in SHAREDAREA) */

/* Thread-local data */
class Thread : public SharedHeap {
private:
   Segment *segPtr;

   void init(ThreadId _id, ThreadId _tid);


public:
   ThreadId id; /* logical id (indexes vector clocks) */
   ThreadId tid; /* Linux tid */
   ulong vpid; /* vkernel pid */
   PageTable *ptPtr;
   uint brCnt;
   ADDRINT ctidAddr;
   ADDRINT parentTid;
   Event *savedEvent;
   ThreadId cloneId;
   ulong sysno;

   BtracerStruct bt;
   int isInInst;

   FILE *dfp;


   Thread(VectorClock &startClock, ThreadId _id, ThreadId _tid, 
         ADDRINT _parentTid, ADDRINT _ctidAddr, PageTable *_ptPtr);

   ~Thread();

   void advanceSegment(VectorClock &targetClock);

   Segment* getSeg() const;

   ThreadId getId() const;

   ThreadId getTid() const;

   PageTable* getPt() const;
};

INLINE Thread* getCurrent() {
   Thread *tptr = (Thread*)PIN_GetThreadData(infoKey, PIN_ThreadId());

   return tptr;
}

extern int isReplay;
extern int isVkernelRunning;

static INLINE 
int Thread_IsLogging()
{
   return !isReplay;
}

static INLINE int 
Thread_IsReplaying()
{
   return isReplay;
}

static INLINE int 
Thread_IsVkernelRunning()
{
   return isVkernelRunning;
}

/* From the vkernel */
#include "../../vkernel/vkernel.lds.h"
static INLINE BOOL
Thread_IsInVkernel(ADDRINT pc)
{
   return Thread_IsVkernelRunning() && (__VKERNEL_START <= pc && pc < __VKERNEL_END);
}


#define current getCurrent()

static inline ADDRINT
Virt2Phys(ADDRINT vaddr)
{
   ADDRINT paddr = current->getPt()->virt2phys(vaddr);

   return paddr;
}

#include "../../vkernel/asm-offsets.h"

#if 1
#define XTASK_STRUCT(o) "%%fs:"#o
#define TASK_STRUCT(o) XTASK_STRUCT(o)
#endif

#define XSTR(v) #v
#define STR(v) XSTR(v)

static inline long
TaskStruct_GetLong(uint off)
{
   long ret;

   __asm__ __volatile__(
         "movl %%" STR(TASK_TSS) ":(%0), %1\n\t"
         : /* output */ "=r" (ret)
         : /* input */ "r" (off)
         );

   return ret;
}

static void
TaskStruct_PutLong(uint off, long val)
{
   __asm__ __volatile__(
         "movl %0, %%" STR(TASK_TSS) ":(%1)\n\t"
         : /* output */ "=&r" (off)
         : /* input */ "r" (val)
         );
}

typedef pair<const ThreadId, Thread*> ThreadPair;
class ThreadMap : public map<ThreadId, Thread*, less<ThreadId>, SharedHeapAllocator<ThreadPair> >, public SharedHeap {
public:
};
