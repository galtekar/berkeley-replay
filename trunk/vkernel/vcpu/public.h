#pragma once

#ifndef MAX_NR_VCPU
#error "MAX_NR_VCPU is undefined"
#endif

#if MAX_NR_VCPU <= 0 
#error "NR_VCPU value is invalid"
#endif

#define VCPU_MODE_REPLAY      (1 << 0)
#define VCPU_MODE_LOG         (1 << 1)
#define VCPU_MODE_DE_ENABLED  (1 << 2)
#define VCPU_MODE_SINGLESTEP  (1 << 3)

#define VCPU_MODE_RACEDETECT  (1 << 4)
#define VCPU_MODE_FORMGEN     (1 << 5)

#ifndef __ASSEMBLER__

#include "libcommon/public.h"

#define SCHEDQUEUE_IDSTR "schedqueue"
#define VCPU_IDSTR "vcpu"

struct RepLockStruct {
   struct SynchLock sl;
   volatile uint ticket;
   struct WaitQueueHead eventq;
   char idStr[64];
};
#define SYNCH_ORDERED_LOCK_INIT(self, str) {  \
   .sl = SYNCH_LOCK_INIT,  \
   .ticket = 0, \
   .eventq = __WAIT_QUEUE_HEAD_INITIALIZER(self.eventq), \
   .idStr = str, \
}

extern void    RepSynch_LockInit(struct RepLockStruct *l, const char *idStr);
extern void    RepSynch_Lock(struct RepLockStruct *l);
extern void    RepSynch_Unlock(struct RepLockStruct *l);
extern int     repSynchEnabled;

static INLINE void
RepSynch_Enable() {
   repSynchEnabled = 1;
}

static INLINE int
RepSynch_IsEnabled() {
   return repSynchEnabled;
}


#define DECLARE_ORDERED_LOCK(name) \
   struct RepLockStruct name = SYNCH_ORDERED_LOCK_INIT(name, #name)

#define ORDERED_LOCK_INIT(l, idStr)   RepSynch_LockInit(l, idStr)

#define ORDERED_LOCK(l)       RepSynch_Lock(l)
#define ORDERED_UNLOCK(l)     RepSynch_Unlock(l)

#define UNORDERED_LOCK(l)     SYNCH_LOCK(&(l)->sl)
#define UNORDERED_UNLOCK(l)   SYNCH_UNLOCK(&(l)->sl)

#define ORDERED_IS_LOCKED(l)          SYNCH_IS_LOCKOWNER(&(l)->sl)
#define ORDERED_ASSERT_IS_LOCKED(l)   ASSERT(ORDERED_IS_LOCKED(l))


#define IS_LOCKED(l)          SYNCH_IS_LOCKED(l)
#define ASSERT_IS_LOCKED(l)   ASSERT(IS_LOCKED(l))

extern struct RepLockStruct bkLock;
extern struct RepLockStruct busLock;

static INLINE void
BKL_Lock()
{
   ORDERED_LOCK(&bkLock);
}

static INLINE void
BKL_Unlock()
{
   ORDERED_UNLOCK(&bkLock);
}

static INLINE void
Bus_Lock()
{
   ORDERED_LOCK(&busLock);
}

static INLINE void
Bus_Unlock()
{
   ORDERED_UNLOCK(&busLock);
}

struct RunQueue
{
   int                  count;
   struct ListHead      list;

};

/* XXX: should be called IO queue. */
struct BlockedQueue
{
   int                  count;
   struct ListHead      list;

   /* Io-queue is protected by the vcpu lock. */
};

struct Segment;

struct Log
{
   int fd;
   ulong logStart;
   char * volatile pos;
   volatile loff_t endOff;
   volatile ulong nrRotations;
   int isLogging;
   int isProtectedInReplay;
   char idstr[32];
   loff_t size;

   /* Pointer to NR_VCPU len array of ints containing
    * rotation generation of current address for any
    * given VCPU. */
   uint *logLocalRotationGeneration;
   struct VCPU *vcpu;
   DEBUG_ONLY(int hasBeenInitialized;)
   STATS_ONLY(u64 stats[256];)

   /* Rate limiting state. */
   struct TokenBucket tokenBucket;
};


struct cgCkpt {
   struct MapStruct *undoMapP;

   struct ListHead stack;
};

#define VA(var) curr_vcpu->var


struct VCPU
{
   /* 0 ... NR_VCPU-1 */
   int id;

   /* Runqueue for this VCPU */
   struct RunQueue      runq;
   struct BlockedQueue  blockq;

   /* Protects the run and block, ensures scheduling order determinism. 
    * Block queue must be locked since task from remote VCPUs may
    * wake a task on current VCPU -- and that involves removing from
    * the wait queue and adding to the runqueue. */
   struct RepLockStruct queueLock; 

   struct Segment *segment;

   /* Ensuresthat  only one task is scheduled at a time on VCPU. */
   struct RepLockStruct     cpuLock;

   int      isActive;

   struct Log replayLog;
   struct Log checkLog;
   int checkIsLogging;

#define NUM_LEAFS 17
   uint cpuidMatrix[NUM_LEAFS][4];
   int phys_id;

   /* Each VCPU has its own list of races that it found. We
    * could've had a unified list of races and hence just one
    * file, but then we would have to lock it and that's
    * too annoying. */
   int raceFd;

   /* ----- Constraint generation (Cgen) ----- */
   u64 bbExecCount;
   ulong bbCount; /* translation number (static) of bb */
   u64 jcCounter; /* number of branches executed */
   u64 originCounter;
   u64 joinCounter;
   u64 arrayCounter;
   u64 casCounter;
   u64 parityCounter;
   ulong localScope;
   struct MapStruct *pcMapP;
#if CG_SLOW_WRITE
   FILE *cgenFile;
#else
   struct Log cgLog;
#endif
#define MAX_STMT_LEN 4096
   char formBuf[MAX_STMT_LEN];
   size_t formBufPos;

   /* We use the MMU to detect accesses to pages with tainted data.
    * Is taint-map page protection enabled or disabled for a given 
    * address space on this VCPU? We need this to avoid making
    * unnecessary calls to sys_mprotect() when disabling enabling
    * taint-map page protection. */
   struct MapStruct *cgProtStatusMapP;

   struct ListHead undoStack;
   struct cgCkpt *bbSetP;

   struct MapStruct *jointWrSetP;
   int isJoinPending;
   u64 nrCompletedJoins;

   struct MapStruct *pgAccessMapP;
   int maxNrPagesAccessedBetweenSystemEvents;
   int resumeUserCount;

   /* Logical time. Useful for determining happens-before. */
   uint64_t vclock, target_vclock, last_clock;
   /* Physical (not logical) time. Useful for measuring data-rates
    * duing replay mode analysis. */
   uint64_t wall_clock; 
   uuid_t uuid;
   /* vcpu-unique id for a message. Allows us to avoid generating a
    * new uuid for every sent message. */
   uint64_t msg_idx; 
};

extern uint          NR_VCPU;
extern struct VCPU   vcpuArray[MAX_NR_VCPU];


static INLINE struct VCPU *
VCPU_Ptr(int id)
{
   ASSERT(0 <= id && id < NR_VCPU);
   return &vcpuArray[id];
}

static INLINE int
VCPU_IsLocked(struct VCPU *vcpu)
{
   int res;
   ASSERT(vcpu);

   res = ORDERED_IS_LOCKED(&vcpu->cpuLock);

   return res;
}

static INLINE void
VCPU_Lock(struct VCPU *vcpu)
{
   ASSERT(vcpu);

   return RepSynch_Lock(&vcpu->cpuLock);
}

static INLINE void
VCPU_Unlock(struct VCPU *vcpu)
{
   ASSERT(vcpu);

   D__;
   return RepSynch_Unlock(&vcpu->cpuLock);
}

/*
 * Activation/deactivation lets segment garbage collection
 * work effectively -- if a VCPU is inactive then
 * it's knowledge needn't be considered in determining
 * which segments to throw out.
 */
static INLINE void
VCPU_Activate(struct VCPU *vcpu)
{
   ASSERT(VCPU_IsLocked(vcpu));
   vcpu->isActive = 1;
}

static INLINE void
VCPU_Deactivate(struct VCPU *vcpu)
{
   ASSERT(VCPU_IsLocked(vcpu));
   vcpu->isActive = 0;
}

static INLINE int
VCPU_IsActive(struct VCPU *vcpu)
{
   ASSERT(VCPU_IsLocked(vcpu));
   return vcpu->isActive;
}

extern int           vcpuMode;

static INLINE int 
VCPU_GetMode()
{
   return vcpuMode;
}

static INLINE void 
VCPU_SetMode(int mode)
{
   vcpuMode = mode;
}

static INLINE void 
VCPU_SetModeFlag(int flag)
{
   vcpuMode |= flag;
}

static INLINE void 
VCPU_ClearModeFlag(int flag)
{
   vcpuMode &= ~flag;
}

static INLINE int
VCPU_TestMode(int mode)
{
   return vcpuMode & mode;
}

static INLINE int 
VCPU_IsLogging() 
{
   return (vcpuMode & VCPU_MODE_LOG) != 0; 
}

static INLINE int 
VCPU_IsReplaying() 
{
   return (vcpuMode & VCPU_MODE_REPLAY) != 0; 
}

static INLINE int 
VCPU_IsDEEnabled() 
{
   return (vcpuMode & VCPU_MODE_DE_ENABLED) != 0; 
}


extern void VCPU_Fork(struct Task *tsk);
extern void VCPU_SelfInit();
extern void VCPU_SelfExit();


/*
 * Scheduler.
 */
typedef int (*BlockFn)(void*);

extern void                Sched_Fork(struct Task *t);
extern void                Sched_WakeNewTask(struct Task *t);
extern void                Sched_ScheduleFirstTime();
extern SyscallRet          Sched_BlockingRealSyscall(BlockFn fn,
                              void *arg);
extern void                Sched_Schedule();
extern int                 Sched_ScheduleTimeout(struct timespec *tsp);
extern void                Sched_WakeupSync(struct WaitQueueHead *q, 
                              uint mode);
extern void                Sched_WakeUpProcess(struct Task *t);
extern void                Sched_WakeUpState(struct Task *t, uint state);


extern void Segment_AddWrite(struct ExecPoint *ep, ulong vaddr,
               uint accessLen);
extern void Segment_AddRead(struct ExecPoint *ep, ulong vaddr,
               uint accessLen);
extern void Segment_Fork(struct Task *tsk);

struct AccessLoc {
   /* Task id of the task that made the access. Ideally, we
    * shouldn't need this, but presently brCnt are per task
    * (not VCPU as they should be), and thus we need this to
    * keep it going. */
   int task_id;

   /* Execution point of instruction that made the access. 
    * Needed to place notifications during formula gen,
    * for instance. */
   struct ExecPoint ep;

   /* ----------- For debugging ------------ */
   /* VCPU that made the access. Used to select an origin notification
    * leader. Also useful for debugging. */
   int vcpu_id;

   /* VC of segment in which access was made.  Useful for
    * debugging (and perhaps future analysis?). */
   struct VectorClock vc;
};

static INLINE int
AccessLoc_IsMatch(const struct AccessLoc *a, const struct AccessLoc *b)
{
   return (a->task_id == b->task_id) && ExecPoint_IsMatch(&a->ep, &b->ep);
}

static INLINE const char *
AccessLoc_ToStr(char *buf, size_t bufSz, const struct AccessLoc *a)
{
   PrintOps_snprintf(buf, bufSz, "%d.%d.0x%8.8x:0x%8.8x:%8.8llu",
         a->vcpu_id, a->task_id, a->ep.eip, a->ep.ecx, a->ep.brCnt);

   return buf;
}

struct RaceAccess {
   /* Is accessing insn a read or write? 
    * Needed to determine if access is part of a RW or WW race.
    * This in turn tells us whether we need to place notifications 
    * on it. */
   int isRead;

   struct AccessLoc loc;
};

struct RacePair {
   /* Global address on which there is a racing access. */
   u64 gaddr;

   /* The racing instructions that tried to concurrently
    * access @gaddr. */
   struct RaceAccess access1, access2;
};

static INLINE const char *
Race_AccessToStr(char * buf, size_t bufSz, const struct RaceAccess *r)
{
   DECLARE_VCSTR(vcStr);
   const struct AccessLoc *loc = &r->loc;

   PrintOps_snprintf(buf, bufSz, "(%s) %d.%d.0x%8.8x:0x%8.8x:%8.8llu:%s",
         r->isRead ? "r" : "w",
         loc->vcpu_id, loc->task_id, loc->ep.eip, loc->ep.ecx, loc->ep.brCnt,
         VectorClock_ToStr(vcStr, &loc->vc)
         );

   return buf;
}


static INLINE void
Race_PrintRecord(const struct RacePair *rrp)
{
   const struct RaceAccess *r1 = &rrp->access1, *r2 = &rrp->access2;
   char buf1[256], buf2[256];

   LOG(
         "<gaddr=0x%16.16llx   %s   %s>\n",
         rrp->gaddr,
         Race_AccessToStr(buf1, sizeof(buf1), r1),
         Race_AccessToStr(buf2, sizeof(buf2), r2));
}

extern void Segment_OpenRaceLog(struct VCPU *vcpu, int isCreate);
extern void Segment_CloseRaceLog(struct VCPU *vcpu);

#endif
