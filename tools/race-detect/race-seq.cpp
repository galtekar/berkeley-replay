#include <iostream>
#include <sys/mman.h>
#include <signal.h>
#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include "../InstLib/instlib.H"
#include "syncops.h"

#include <iterator>
#include <map>
#include <set>
#include <vector>
#include <queue>


#define MAX_THREADS 16
#define current ((ThreadInfo*)PIN_GetThreadData(infoKey, PIN_ThreadId()))
#define ID current->id
#define DLOG(s, ...) fprintf(lfp, "<%d>: " s, PIN_GetTid(), ##__VA_ARGS__); fflush(lfp);

#define ASSERTX_IS_LOCKED(l) ASSERTX(*l == SPIN_LOCKED)
#define ASSERTX_IS_UNLOCKED(l) ASSERTX(*l == SPIN_UNLOCKED)

#define GARBAGE_COLLECT 0
#if GARBAGE_COLLECT
#define GC() GarbageCollect()
#else
#define GC()
#endif

#define INS_TRACE 0
#define EVENT_ON_ATOMIC 1

TLS_KEY infoKey;

/* Misc */
FILE* lfp = NULL;

typedef uint LogicalClock;
typedef int ThreadId;

class VectorClock {
protected:
   LogicalClock vc[MAX_THREADS];
   char vcStr[256];
   ThreadId id;

public:
   VectorClock(ThreadId _id) {
      memset(vc, 0, sizeof(vc));
      id = _id;
   }

   LogicalClock operator[](const int index) const {
      ASSERTX(index < MAX_THREADS);
      return vc[index];
   }

   /*
    * O(n) vector clock update.
    */
   void update(const VectorClock &rhs) {
      for (int i = 0; i < MAX_THREADS; i++) {
         vc[i] = MAX(vc[i], rhs[i]);
      }
   }

   void advance(const int index) {
      vc[index]++;
      ASSERTX(vc[index] >= 0);
   }

   bool operator<<(const VectorClock& rhs) const {
      bool strictlyLess = false;

      //DLOG("<\n");
      for (int k = 0; k < MAX_THREADS; k++) {
         if (rhs.vc[k] < vc[k]) {
            return false; /* incomparible or greater than */
         }

         if (rhs.vc[k] > vc[k]) {
            strictlyLess = true;
         }
      }

      return strictlyLess;
   }

   bool operator>>(const VectorClock& rhs) const {
      return (rhs << *this);
   }

   /* isParallelWith (could be equal) */
   bool operator|(const VectorClock &rhs) const {
      return !(*this << rhs) && !(rhs << *this);
   }

   /* isStrictlyParallelWith */
   bool operator||(const VectorClock &rhs) const {
      return !(*this << rhs) && !(rhs << *this) && (*this != rhs);
   }

   bool operator==(const VectorClock &rhs) const {

      //DLOG("%s %s\n", this->toStr().c_str(), rhs.toStr().c_str());

      for (int k = 0; k < MAX_THREADS; k++) {
   
         if (vc[k] != rhs.vc[k]) {
            //DLOG("%d ret=false\n", k);
            return false;
         }
      }
      //DLOG("ret=true\n");

      return true;
   }

   bool operator!=(const VectorClock &rhs) const {
      return !(*this == rhs);
   }

   /* Must be totally ordered for comparators to work
    * properly -- use thread id to break ties. */
   bool operator<(const VectorClock& rhs) const {
      if (*this || rhs) {
         /* XXX: A bug in PIN requires that we let the child
          * thread execute first after a clone. PIN doesn't
          * like if a thread holds a lock in the thread start
          * callback -- it won't let the other thread continue
          * (and instead busy waits, potentially on some lock). 
          *
          * Assumes that child threads have larger ids.
          *
          * */
         return (this->id < rhs.id);
      }

      return *this << rhs;
   }


   string toStr() const {
      string str;
      stringstream out;
      out << "(" << 
         vc[0] << "," <<
         vc[1] << "," << 
         vc[2] << ")";
      str = out.str();
      return str;
   }
};


typedef struct AccessStruct {
   ulong pc;
   ulong brCnt;
   THREADID id;
} Access;

typedef pair<ADDRINT, vector<Access> > AccessPair;
typedef map<ADDRINT, vector<Access> > AccessMap;

struct SyscallStruct {
   INT32 num;
   VOID* arg0;
   VOID* arg1;
   VOID* arg2;
   VOID* arg3;
   VOID* arg4;
   VOID* arg5;
};

/* Thread-local data */
class ThreadInfo {
private:
   void init(ThreadId _id, ADDRINT _ctidAddr) {
      Synch_CondInit(&schedCond);
      brCnt = 0;
      garbageWindowLeft = 0;
      id = _id;
      ctidAddr = _ctidAddr;
      memset(&syscall, 0, sizeof(syscall));
   }

public:
   uint brCnt;
   LogicalClock garbageWindowLeft;
   struct SynchCond schedCond;
   VectorClock vc;
   ThreadId id;
   int ticketVal;
   ADDRINT ctidAddr;
   struct SyscallStruct syscall;

   ThreadInfo(ThreadId _id, ADDRINT _ctidAddr) : vc(_id) {
      init(_id, _ctidAddr);
   }
};
typedef map<ThreadId, ThreadInfo*> ThreadMap;
typedef pair<ThreadId, ThreadInfo*> ThreadPair;

class Channel : public VectorClock {
public:
   Channel(ThreadId _id) : VectorClock(_id) {
   }

   void putClock(VectorClock &_vc) {
      *((VectorClock*)this) = _vc;
   }

   VectorClock& getClock() {
      return *((VectorClock*)this);
   }
};
typedef map<ADDRINT, Channel*> ChannelMap; 


/* Segments */
class Segment {
private:
   VectorClock vc;

public:
   struct SynchCond *schedCond;

   Segment(VectorClock &_vc, struct SynchCond *_schedCond) : vc(_vc) {
      schedCond = _schedCond;
   }

   bool operator<(const Segment& rhs) const {
      return vc < rhs.vc;
   }
};

#if 0
struct classcomp {
  bool operator() (const VectorClock& lhs, const VectorClock& rhs) const {
     bool ret = false;

     if (lhs < rhs) {
        ret = true;
     }

     if (lhs || rhs) {
        if (lhs.id < rhs.id) {
           ret = true;
        }
     }

     DLOG("lhs: %s rhs: %s ret=%d\n", lhs.toStr().c_str(),
           rhs.toStr().c_str(), ret);

     return ret;
  }
};
#endif
typedef priority_queue<Segment> SegmentPq;
typedef map<VectorClock, AccessMap> SegmentMap;
typedef pair<VectorClock, AccessMap> SegmentPair;

/* Shared data-structs - access must be synchronized */
ThreadMap thrMap;
ChannelMap chanMap;
SegmentPq schedPq;
ThreadId nextId = 0;
ThreadInfo *parentPtr = NULL;
SegmentMap segReadMap, segWriteMap;

/* Synchronization */
SynchLock schedLock = SPIN_UNLOCKED;

static void
OnBranch()
{
   current->brCnt++;
}

static void
OnWrite(ADDRINT addr, ADDRINT pc, THREADID id)
{
   Access a;

   a.pc = pc;
   a.brCnt = current->brCnt;
   a.id = id;

   SegmentMap::iterator it;

   it = segWriteMap.find(current->vc);

   if (it == segWriteMap.end()) {
      AccessMap m;

      //DLOG("New write segment map for %s\n", current->vc.toStr().c_str());
      segWriteMap.insert(SegmentPair(current->vc, m));

      //DLOG("Finding\n");
      it = segWriteMap.find(current->vc);
      ASSERTX(it != segWriteMap.end());
   } else {
      //DLOG("Found write segment for %s\n", current->vc.toStr().c_str());
   }

   it->second[addr].push_back(a);
}

static void
OnRead(ADDRINT addr, ADDRINT pc, THREADID id)
{
   Access a;

   a.pc = pc;
   a.brCnt = current->brCnt;
   a.id = id;

   SegmentMap::iterator it;

   it = segReadMap.find(current->vc);

   if (it == segReadMap.end()) {
      AccessMap m;

      //DLOG("New read segment map for %s\n", current->vc.toStr().c_str());
      segReadMap.insert(SegmentPair(current->vc, m));

      //DLOG("Finding\n");
      it = segReadMap.find(current->vc);
      ASSERTX(it != segReadMap.end());
   } else {
      //DLOG("Found read segment for %s\n", current->vc.toStr().c_str());
   }

   it->second[addr].push_back(a);
}

#if GARBAGE_COLLECT
static void
SegmentDiscard(LogicalClock segmentId)
{
   current->segReadMap.erase(segmentId);
   current->segWriteMap.erase(segmentId);
}
#endif

static Channel*
ChannelNew(ADDRINT mutex)
{
   Channel *chnPtr = new Channel(current->id);

   chanMap[mutex] = chnPtr;

   return chnPtr;
}

#if 0
/*
 * XXX: figure how when to call this.
 */
static void
ChannelFree(ADDRINT mutex)
{
   ChannelMap::iterator im = chanMap.find(mutex);

   ASSERTX(im != chanMap.end());

   delete im->second;

   chanMap.erase(mutex);
}
#endif

static Channel*
ChannelLookup(ADDRINT mutex)
{
   Channel *chnPtr = NULL;

   ChannelMap::iterator im = chanMap.find(mutex);

   if (im == chanMap.end()) {
      chnPtr = ChannelNew(mutex);
   } else {
      chnPtr = im->second;
   }

   return chnPtr;
}

static void
PqPush(VectorClock &vc)
{
   Segment e(vc, &current->schedCond);

   /* Protected by the schedLock */
   ASSERTX_IS_LOCKED(&schedLock);
   schedPq.push(e);
   //Synch_CondSignal(&pqCond);
}

static struct SynchCond*
PqPop()
{
   struct SynchCond *ret;

   if (schedPq.empty()) {
      /*
       * XXX: Wait until there is something to dequeue.
       * There might not be anything if:
       *    - current thread is asynch-waiting on acquire,
       *    but other thread is also asynch-waiting on acquire,
       *    as in a deadlock scenario
       *
       *    - current thread is asynch-waiting on acquire,
       *    but other thread ...
       */
      //Synch_CondWait(&pqCond, &pqLock);
      ASSERTX(0);
   }

   /* Protected by the schedLock */
   ASSERTX_IS_LOCKED(&schedLock);
   ret = schedPq.top().schedCond;
   schedPq.pop();

   return ret;
}

#if 0
static void
vectorToSet(vector<Access> &vec, set<Access> &s)
{
   vector<Access>::iterator it;

   for (it = vec.begin(); it != vec.end(); it++) {
      s.insert(*it);
   }
}
#endif

typedef set<ADDRINT> AddrSet;

static char* 
use_xed(ADDRINT pc, char* buf, size_t bufSz) {
#if defined(TARGET_IA32E)
    static const xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b};
#endif
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    //FIXME: pass in the proper length...
    const unsigned int max_inst_len = 15;
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(pc), max_inst_len);
    BOOL xed_ok = (xed_code == XED_ERROR_NONE);
    if (xed_ok) {
        xed_decoded_inst_dump_intel_format(&xedd, buf, bufSz, 0);
        return buf;
    }

    return NULL;
}

static void
printAccessVec(vector<Access> &v)
{
   vector<Access>::iterator vit;
   char buf[2048], *bufPtr;
   INT32 column, line;
   string name;

   for (vit = v.begin(); vit != v.end(); vit++) {
      bufPtr = use_xed(vit->pc, buf, sizeof(buf));
      column = line = 0;
      PIN_LockClient();
      PIN_GetSourceLocation(vit->pc, &column, &line, &name);
      PIN_UnlockClient();

      ASSERTX(bufPtr);
      DLOG("  %d: 0x%lx %lu %s (%d, %d, %s)\n", vit->id, vit->pc, vit->brCnt, bufPtr,
            line, column, name.c_str());
   }
}

static void
printRaceSet(AddrSet raceSet, AccessMap &m1, AccessMap &m2)
{
   AddrSet::iterator it;

   for (it = raceSet.begin(); it != raceSet.end(); it++) {

      DLOG("Address: 0x%x\n", *it);

      printAccessVec(m1[*it]);
      DLOG("  ---------\n");
      printAccessVec(m2[*it]);
   }
}

static AddrSet
vector_intersection(AccessMap &m1, AccessMap &m2)
{
   AddrSet s1, s2;
   AddrSet final;

   AccessMap::iterator it, it_end;

   for (it = m1.begin(); it != m1.end(); it++) {
      s1.insert(it->first);
   }

   for (it = m2.begin(); it != m2.end(); it++) {
      s2.insert(it->first);
   }

   set_intersection(s1.begin(), s1.end(), s2.begin(), s2.end(),
         insert_iterator<AddrSet>(final, final.begin())
         );

   printRaceSet(final, m1, m2);

   return final;
}

/* Must be called before moving to a new segment. */
static void
RaceDetect()
{
   SegmentMap::iterator it;

   for (it = segReadMap.begin(); it != segReadMap.end(); it++) {
      if (current->vc || it->first) {
         DLOG("comparing writes of %s with reads of %s\n", current->vc.toStr().c_str(),
               it->first.toStr().c_str());
         vector_intersection(segWriteMap[current->vc],
               it->second); /* WAR */
      }
   }

   for (it = segWriteMap.begin(); it != segWriteMap.end(); it++) {
      if (current->vc || it->first) {
         DLOG("comparing reads of %s with writes of %s\n", current->vc.toStr().c_str(),
               it->first.toStr().c_str());
         vector_intersection(segReadMap[current->vc],
               it->second); /* RAW */
         DLOG("comparing writes of %s with writes of %s\n", current->vc.toStr().c_str(),
               it->first.toStr().c_str());
         vector_intersection(segWriteMap[current->vc],
               it->second); /* WAW */
      }
   }
}

#if GARBAGE_COLLECT
static void
GarbageCollect()
{
   /*
    * Garbage collect segment meta-data.
    */
   LogicalClock garbageWindowRight = UINT_MAX;

   ThreadMap::iterator it;
   for (it = thrMap.begin(); it != thrMap.end(); it++) {
      ThreadInfo *thrPtr = it->second;
      garbageWindowRight = MIN(garbageWindowRight, thrPtr->vc[ID]);
   }

   ASSERTX(current->garbageWindowLeft <= garbageWindowRight);
   for (LogicalClock s = current->garbageWindowLeft; s < garbageWindowRight; s++) {
      SegmentDiscard(s);
   }
   current->garbageWindowLeft = garbageWindowRight;
}
#endif

static void
Schedule()
{
//   DLOG("Schedule: descheduling %s\n", current->vc.toStr());
   ASSERTX_IS_LOCKED(&schedLock);

   current->vc.advance(ID);

   PqPush(current->vc);

   GC();

   struct SynchCond *condPtr;

   condPtr = PqPop();

   /* Can't send a signal to ourselves without
    * waiting for it first...so just skip
    * the signalling if we are next. */
   if (condPtr != &current->schedCond) {
      Synch_CondSignal(condPtr);
      Synch_CondWait(&current->schedCond, &schedLock);
   }
   DLOG("Schedule: scheduling %s\n", current->vc.toStr().c_str());
}

static void
SendAction(ADDRINT mutex)
{
   Channel *chnPtr = ChannelLookup(mutex);

   /* Should be done before we advance the local clock 
    * to the next segment. */
   chnPtr->putClock(current->vc);

   Schedule();
}

static void
ReceiveAction(ADDRINT mutex)
{
   Channel *chnPtr = ChannelLookup(mutex);

   RaceDetect();

   current->vc.update(chnPtr->getClock());

   Schedule();
}

static ThreadInfo *newThrPtr = NULL;

static VOID 
ThreadBegin(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{

   DLOG("ThreadBegin: tid=%d infoKey=%d\n", PIN_ThreadId(), infoKey);

   Synch_SpinLock(&schedLock);
   DLOG("here 1\n");

   PIN_SetThreadData(infoKey, newThrPtr, threadIndex);

   thrMap.insert(ThreadPair(PIN_GetTid(), current));

   if (parentPtr) { /* first thread doesn't have a parent */
      /* Resume parent and await our turn. */
      current->vc.update(parentPtr->vc);
      current->vc.advance(ID);
      PqPush(current->vc);
      Synch_CondSignal(&parentPtr->schedCond);
      DLOG("here 2\n");
      Synch_CondWait(&current->schedCond, &schedLock);
      DLOG("here 3\n");
   } else {
      current->vc.advance(ID);
   }
   DLOG("ThreadBegin: scheduling %s\n", current->vc.toStr().c_str());
}

static VOID 
ThreadEnd(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
   /* XXX: Cleanup all segment data. */
   /* will/must some of it hang-around? */

   GC();

   thrMap.erase(ID);
   delete current;

   /*
    * XXX: the very last segment we execute may not be the
    * last segment -- some thread may be blocked on an asynch-event
    */
   if (!schedPq.empty()) {
      Synch_CondSignal(PqPop());
   }
   Synch_SpinUnlock(&schedLock);
}


static void
SetTidAddressBefore(ADDRINT ctidAddr)
{
   DLOG("SetTidAddress: ctidAddr=0x%x\n", ctidAddr);
   current->ctidAddr = ctidAddr;
}

static void
FutexBefore(ADDRINT uAddr, INT32 op)
{
   DLOG("FutexBefore: uAddr=0x%x op=0x%x\n", uAddr, op);
   if (op == FUTEX_WAIT) {
      Synch_CondSignal(PqPop());
      //current->ticketVal = Synch_CondWaitTop(&current->schedCond, &schedLock);
      Synch_SpinUnlock(&schedLock);
      DLOG("here 2\n");
   }
}


static void
CloneAfter(INT32 ret, ADDRINT childTidPtr)
{
   DLOG("CloneAfter: ret=%d ctidPtr=0x%x\n", ret, childTidPtr);

   if (ret != -1) {
      /* Initialize thread data. */
      newThrPtr = new ThreadInfo(nextId, childTidPtr);
      nextId++;
      ASSERTX(nextId <= MAX_THREADS);

      parentPtr = current;

      DLOG("phere 0\n");
      Synch_CondWait(&current->schedCond, &schedLock);
      DLOG("phere 1\n");

      /* ... and we're back from the child. He should be
       * all setup and waiting to be scheduled. */

      Schedule();
   }
}


static void
FutexAfter(INT32 ret, ADDRINT uAddr, INT32 op)
{
   DLOG("FutexAfter: ret=%d uAddr=0x%x op=0x%x\n", ret, uAddr, op);
   if (op == FUTEX_WAIT) {
      if (ret == 0) { /* success -- woken by a FUTEX_WAKE call */
         //Synch_CondWaitBottom(&current->schedCond, &schedLock, current->ticketVal);
         Synch_SpinLock(&schedLock);

         ReceiveAction(uAddr);
      }
   } else if (op == FUTEX_WAKE) {
      SendAction(uAddr);
   }
}

static void
ExitBefore()
{
   DLOG("ExitBefore: current->ctidAddr=0x%x\n", current->ctidAddr);
   Channel *chnPtr = ChannelLookup(current->ctidAddr);
   chnPtr->putClock(current->vc);
}

VOID 
SysBefore(INT32 num, VOID* arg0, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
   current->syscall.num = num;
   current->syscall.arg0 = arg0;
   current->syscall.arg1 = arg1;
   current->syscall.arg2 = arg2;
   current->syscall.arg3 = arg3;
   current->syscall.arg4 = arg4;
   current->syscall.arg5 = arg5;

   switch (num) {
   case SYS_futex:
      FutexBefore((ADDRINT)arg0, (INT32)arg1);
      break;
   case SYS_set_tid_address:
      SetTidAddressBefore((ADDRINT)current->syscall.arg0);
      break;
   case SYS_exit:
   case SYS_exit_group:
      ExitBefore();
      break;
   default:
      break;
   }
}

static VOID 
SysAfter(INT32 ret)
{
   switch (current->syscall.num) {
   case SYS_clone:
      CloneAfter(ret, (ADDRINT)current->syscall.arg4 /* child_tidptr */);
      break;
   case SYS_futex:
      FutexAfter(ret, 
            (ADDRINT)current->syscall.arg0, 
            (INT32)current->syscall.arg1);
      break;
   default:
      break;
   }
}

#if EVENT_ON_ATOMIC

#if 0
static VOID
AtomicBefore(ADDRINT writeAddr)
{
   DLOG("AtomicBefore: 0x%x\n", writeAddr);
}
#endif

/*
 * Do a receive and send action, since this instruction
 * first reads and then writes to a memory location.
 *
 * SYNCH: protected by schedLock
 */
static VOID
AtomicAfter(ADDRINT writeAddr)
{
   DLOG("AtomicAfter: 0x%x\n", writeAddr);
   Channel *chnPtr = ChannelLookup(writeAddr);
   VectorClock savedVc = current->vc;

   RaceDetect();

   current->vc.update(chnPtr->getClock());

   /* NOTE: we do savedVc instead of current->vc, since
    * the receiver comes after the current segment,
    * not the next one. */
   chnPtr->putClock(savedVc);

   Schedule();
}
#endif

#if INS_TRACE
static VOID
InsBefore(ADDRINT pc)
{
   char buf[2048], *bufPtr;

   bufPtr = use_xed(pc, buf, sizeof(buf));
   ASSERTX(bufPtr);
   DLOG("  0x%x: %s\n", pc, bufPtr);
}
#endif

static VOID 
Instruction(INS ins, VOID *v) 
{
#if INS_TRACE
   INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(InsBefore),
         IARG_INST_PTR,
         IARG_END);
#endif

   if (INS_IsMemoryRead(ins)) {

      if (INS_IsAtomicUpdate(ins)) {
#if EVENT_ON_ATOMIC
#if 0
         INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(AtomicBefore),
               IARG_MEMORYREAD_EA,
               IARG_END);
#endif
         INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(AtomicAfter),
               IARG_MEMORYREAD_EA,
               IARG_END);
#endif
      } else {
         INS_InsertCall(ins, IPOINT_BEFORE,
               (AFUNPTR)OnRead,
               IARG_MEMORYREAD_EA,
               IARG_INST_PTR,
               IARG_THREAD_ID,
               IARG_END);
      }
   } else if (INS_IsMemoryWrite(ins)) {

      if (INS_IsAtomicUpdate(ins)) {
#if EVENT_ON_ATOMIC
         INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(AtomicAfter),
               IARG_MEMORYWRITE_EA,
               IARG_END);
#endif
      } else {
         INS_InsertCall(ins, IPOINT_BEFORE,
               (AFUNPTR)OnWrite,
               IARG_MEMORYWRITE_EA,
               IARG_INST_PTR,
               IARG_THREAD_ID,
               IARG_END);
      }
   } else if (INS_IsBranchOrCall(ins) &&
         INS_HasFallThrough(ins)) {
      INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
            (AFUNPTR)OnBranch,
            IARG_END);
   } else if (INS_IsSyscall(ins)) {
      // Arguments and syscall number is only available before
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
            IARG_SYSCALL_NUMBER,
            IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
            IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
            IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
            IARG_END);

      // return value only available after
      INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
            IARG_SYSRET_VALUE,
            IARG_END);

   }
}


static VOID 
Fini(INT32 code, VOID *v) 
{
   fclose(lfp);
}

static VOID
Init()
{
   DLOG("Init()\n");

   /* For the very first thread. */
   newThrPtr = new ThreadInfo(nextId, 0);
   nextId++;
}

int main(INT32 argc, CHAR **argv)
{
   lfp = fopen("out.log", "w+");
   ASSERTX(lfp != NULL);

   PIN_InitSymbols();
   PIN_Init(argc, argv);
   infoKey = PIN_CreateThreadDataKey(NULL);
   ASSERTX(infoKey != -1);
   PIN_AddFiniFunction(Fini, 0);
#if 1
   PIN_AddThreadStartFunction(ThreadBegin, 0);
   PIN_AddThreadFiniFunction(ThreadEnd, 0);
   INS_AddInstrumentFunction(Instruction, 0);
#endif

   Init();

   // Never returns
   PIN_StartProgram();

   return 0;
}
