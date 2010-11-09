#include <iostream>
#include <bitset>

#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>

#define USE_LIBVEX 0

/* From local dir */
#include "sharedheap.h"
#include "framepool.h"
#include "shmsegmap.h"

#include "segmentqueue.h"
#include "channel.h"
#include "thread.h"

#include "memevent.h"
#include "segmentevent.h"

#include "btracer.h"
#include "replaycheck.h"


/* From libcommon */
#include "syncops.h"
#include "sharedarea.h"
#include "syscall.h"


#if USE_LIBVEX
extern "C" {
#include "libvex.h"
};
#endif

#include "debug.h"


/* XXX: kernel version dependant */
#define SEMOP		 1
#define SEMGET		 2
#define SEMCTL		 3
#define MSGSND		11
#define MSGRCV		12
#define MSGGET		13
#define MSGCTL		14
#define SHMAT		21
#define SHMDT		22
#define SHMGET		23
#define SHMCTL		24

#define INSTRUMENT_INSTRUCTIONS 1
#define INSTRUMENT_ACCESSES 1
#define INSTRUMENT_ATOMIC 1
#define INSTRUMENT_BRANCHES 1
#define INSTRUMENT_SYSCALLS 1
#define INSTRUMENT_ROUTINES 0
#define ENABLE_SNOOP_EVENTS 0
#define ENABLE_REPLAYCHECK 1


SHAREDAREA ChannelMap *chanMap = NULL;
SHAREDAREA SegmentQueue *segQueue = NULL;
SHAREDAREA FramePool *framePool = NULL;
SHAREDAREA ShmSegMap *shmMap = NULL;
SHAREDAREA int numClonedThreads = 0;

extern SHAREDAREA IdMap *idMap;
extern SHAREDAREA ThreadMap *thrMap;

static VOID
BeforeRead(ADDRINT vaddr, ADDRINT pc, ADDRINT ecx)
{
   Access a;

   a.pc = pc;
   a.brCnt = current->brCnt;
   a.tid = current->vpid;
   a.vaddr = vaddr;
   a.ecx = ecx;

   DEBUG_MSG(6, "vaddr=0x%x pc=0x%x\n", vaddr, pc);

   ADDRINT paddr = Virt2Phys(vaddr);

   /* XXX: sometimes, instructions access non-mapped locations, but don't
    * fault (e.g., ls -- rep movsd). I don't know why this is, but find out.
    */
   if (paddr >= 2*PAGE_SIZE) {
      current->getSeg()->addRead(paddr, a);
   } else {
      char buf[2048], *bufPtr;

      bufPtr = use_xed(pc, buf, sizeof(buf));
      ASSERT(bufPtr);
      DLOG("  0x%x: %s\n", pc, bufPtr);
   }
}

static VOID
BeforeWrite(ADDRINT vaddr, ADDRINT pc, ADDRINT ecx)
{
   Access a;

   a.pc = pc;
   a.brCnt = current->brCnt;
   a.tid = current->vpid;
   a.vaddr = vaddr;
   a.ecx = ecx;

   DEBUG_MSG(6, "vaddr=0x%x pc=0x%x\n", vaddr, pc);
   ADDRINT paddr = Virt2Phys(vaddr);

   if (paddr >= 2*PAGE_SIZE) {
      current->getSeg()->addWrite(paddr, a);
   } else {
      char buf[2048], *bufPtr;

      bufPtr = use_xed(pc, buf, sizeof(buf));
      ASSERT(bufPtr);
      DLOG("  0x%x: %s\n", pc, bufPtr);
   }
}


static void
EventBefore(Event *evp)
{
   ASSERT(evp);

   evp->before();

   current->savedEvent = evp;
}

static void
EventAfter(Event *evp)
{
   ASSERT(evp);

   evp->after();

   delete evp; evp = NULL;
}

#if ENABLE_SNOOP_EVENTS
static VOID
SnoopBeforeAfter()
{
   Event *evp = new SnoopEvent;

   EventBefore(evp);
   EventAfter(evp);
}
#endif

#define SNOOP_PERIOD (1 << 18) /* 256M */

static VOID
OnBranchRunningVkernel()
{
   current->brCnt++;

#if 1
   /* Write the branch count into the vkernel task struct. */
   __asm__ __volatile__("movl %0, " TASK_STRUCT(oTASK_BRCNT) "\n\t"
         : /* output */ 
         : /* input */ "r" (current->brCnt)
         );
#endif
   //TaskStruct_PutLong(oTASK_BRCNT, current->brCnt);

#if ENABLE_SNOOP_EVENTS
   if (current->brCnt % SNOOP_PERIOD == 0) {
      SnoopBeforeAfter();
   }
#endif
}

static VOID
OnBranch()
{
   current->brCnt++;

#if ENABLE_SNOOP_EVENTS
   if (current->brCnt % SNOOP_PERIOD == 0) {
      SnoopBeforeAfter();
   }
#endif
}

static VOID
DebugInit(ThreadId pid)
{
   char filename[64];

   snprintf(filename, sizeof(filename), "%s.%d", (Thread_IsLogging() ? "rdl" : "rdr"), pid);

   //DLOG("filename=%s\n", filename);
   Debug_Init(filename, DEBUG_VERBOSE);
}

static ThreadId
GetPid()
{
   ThreadId pid;

   if (Thread_IsVkernelRunning()) {
      if (numClonedThreads > 1) {
      __asm__ __volatile__("movl " TASK_STRUCT(oTASK_PID) ", %0\n\t"
            : /* output */ "=r" (pid)
            : /* input */
            );
      } else {
         /* Vkernel process 1 (i.e., init) doesn't have his tss setup
          * yet, so we can't access its pid field. But we know what it's
          * going to be. */
         pid = 1;
      }
   } else {
      pid = PIN_GetTid();
   }

   return pid;
}

static VOID
ThreadStart(Event* evp) 
{
   /* We need to establish current before we invoke the event
    * handlers. Otherwise, we could move this code into 
    * evp->before(). */
   EVENT_LOCK();

   numClonedThreads++; /* in SHAREDAREA, must be protected by a lock */
   ThreadId pid = GetPid();

   /* This has to be the first thing so that we can start logging
    * immeddiately. */
   DebugInit(pid);


   DLOG("Finding in threadmap: tid=%d\n", PIN_GetTid());
   ThreadMap::iterator it = thrMap->find(PIN_GetTid());
   /* Better be in there since the parent is supposed to have
    * put it there before he created this thread. */
   ASSERT(it != thrMap->end());

   Thread *thrPtr = it->second;
   thrPtr->vpid = pid;
   ASSERT(thrPtr);
   EVENT_UNLOCK();

   PIN_SetThreadData(infoKey, thrPtr, PIN_ThreadId());
   ASSERT(current);

   Btracer_ThreadStart(pid);
#if ENABLE_REPLAYCHECK
   ReplayCheck_ThreadStart(pid);
#endif

   evp->before();
   evp->after();
   delete evp; evp = NULL;
}

static VOID 
ThreadBegin(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
   const bool isRootThread = (numClonedThreads == 0);

   /* WARNING: current is valid here only for the root thread. */
   ASSERT(!current || current);

   ThreadStart(new ThreadStartEvent(isRootThread));
}

/* Called by forked child immediately after fork. */
static VOID 
ForkBegin(THREADID threadIndex, const CONTEXT *ctxt, VOID *v)
{
   const bool isRootThread = false;
   numThreads = 1; // In Linux threads aren't inherited by children

   ThreadStart(new ThreadStartEvent(isRootThread));
}

static VOID 
ExitAfter(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
   EventAfter(current->savedEvent);

   Btracer_ThreadFinish();
#if ENABLE_REPLAYCHECK
   ReplayCheck_ThreadFinish();
#endif
      
   delete current;

   Debug_Fini();
}

static VOID 
SysBefore(ADDRINT pc, INT32 num, ADDRINT *ebx, ADDRINT *ecx, ADDRINT *edx, 
          ADDRINT *esi, ADDRINT *edi, ADDRINT *ebp)
{
   SyscallEvent *evp = NULL;

   current->sysno = num;

   switch (num) {
   case SYS_fork:
      evp = new ForkEvent; break;
   case SYS_clone:
      evp = new CloneEvent; break;
   case SYS_wait4:
      evp = new Wait4Event; break;
   case SYS_waitpid:
      evp = new WaitidEvent; break;
   case SYS_waitid:
      evp = new WaitpidEvent; break;
   case SYS_futex:
      {
         if (Thread_IsInVkernel(pc)) { break; }

         switch (*ecx /* op */) {
         case FUTEX_WAIT:
            evp = new FutexWaitEvent; break;
         case FUTEX_WAKE:
            evp = new FutexWakeEvent; break;
         default:
            /* XXX: handle FUTEX_REQUEUE, FUTEX_FD, etc... */
            ASSERT_UNIMPLEMENTED(0);
            break;
         }
      }
      break;
   case SYS_set_tid_address:
      evp = new SetTidAddressEvent; break;
   case SYS_mremap:
      /* XXX */
      ASSERT_UNIMPLEMENTED(0);
      break;
   case SYS_execve:
      /* XXX: called when vkernel tries to instrument an app with
       * an invokcation to execve (via NoSigSystem) */
      break;
   case SYS_mmap:
      evp = new OldMmapEvent(); break;
   case SYS_mmap2:
      evp = new MmapEvent; break;
   case SYS_munmap:
      evp = new MunmapEvent; break;
   case SYS_brk:
      evp = new BrkEvent; break;
   case SYS_ipc:
      switch (*ebx /* cmd */) {
      case SHMAT:
         evp = new ShmatEvent; break;
      case SHMDT:
         evp = new ShmdtEvent; break;
      case SHMGET:
         evp = new ShmgetEvent; break;
      case SHMCTL:
         evp = new ShmctlEvent; break;
      default:
         /* XXX: implement SEMOP MSG etc.. */
         DLOG("Unhandled IPC command %d\n", *ebx); break;
      }
      break;
   case SYS_exit:
   case SYS_exit_group:
      evp = new ExitEvent; break;
   case SYS_emu_mem:
      if (*ebx) {
         BeforeWrite(*ecx, *edx, *esi);
      } else {
         BeforeRead(*ecx, *edx, *esi);
      }
      break;
   case SYS_emu_branch:
      if (Thread_IsVkernelRunning()) {
         OnBranchRunningVkernel();
      } else {
         OnBranch();
      }
      break;
   default: break;
   }

   if (evp) {
      ADDRINT* sysargs[] = {ebx, ecx, edx, esi, edi, ebp};
      evp->setArgs(num, sysargs);
      EventBefore(evp);
   } else {
      current->savedEvent = NULL;
   }
}

static VOID 
SysAfter(INT32 ret)
{
   SyscallEvent *evp = dynamic_cast<SyscallEvent*>(current->savedEvent);

   if (evp) {
      evp->setReturnValue(ret);

      EventAfter(evp);
   }
}

static VOID
AtomicBefore(ADDRINT writeVaddr)
{
   EventBefore(new AtomicEvent(writeVaddr));
}

static VOID
AtomicAfter(ADDRINT writeVaddr)
{
   Event *evp = current->savedEvent;

   ASSERT(evp);
   EventAfter(evp);
}

#if INSTRUMENT_INSTRUCTIONS
static VOID
InsBefore(ADDRINT pc)
{
   char buf[2048], *bufPtr;

   bufPtr = use_xed(pc, buf, sizeof(buf));
   ASSERT(bufPtr);
   DLOG("  0x%x: %s\n", pc, bufPtr);
}
#endif

#if USE_LIBVEX

void failure_exit ( void ) {
   DLOG("VEX failure!\n");
   ASSERT(0);
}

/* logging output function */
void log_bytes( HChar* str, Int nbytes ) 
{
   DLOGSTR(str);
}

/* Vex dumps the final code in here.  Then we can copy it off
   wherever we like. */
/* 60000: should agree with assertion in VG_(add_to_transtab) in
   m_transtab.c. */
#define N_TMPBUF 60000
static UChar tmpbuf[N_TMPBUF];

static void
dispatch() {
   /* We should never execute this function since we don't
    * execute the translated code. */
   DLOG("VEX dispatch\n");
   ASSERT(0);
}

static Bool
chase_into_ok(void *opaque, Addr64 addr64)
{
   /* Since we're doing this a BBL at a time, we don't want to
    * double the work by chasing into a BBL that we will call
    * translate() on. */
   return False;
}

static IRSB*
instrument(void *opaque, IRSB *bb, VexGuestLayout *layout,
           VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   //ppIRSB(bb);

   return bb;
}

static INLINE VOID
translate(ulong bblAddr)
{
   VexArch              vex_arch;
   VexArchInfo          vex_archinfo;
   VexAbiInfo           vex_abiinfo;
   VexGuestExtents      vge;
   VexTranslateArgs     vta;
   VexTranslateResult   tres;
   Int                  tmpbuf_used;

   vex_arch = VexArchX86;
   LibVEX_default_VexArchInfo(&vex_archinfo);
   
   LibVEX_default_VexAbiInfo(&vex_abiinfo);
   

   vta.arch_guest = vex_arch;
   vta.archinfo_guest = vex_archinfo;
   vta.arch_host = vex_arch;
   vta.archinfo_host = vex_archinfo;
   vta.abiinfo_both = vex_abiinfo;

   vta.guest_bytes = (UChar*)bblAddr;
   vta.guest_bytes_addr = (Addr64)bblAddr;
   vta.callback_opaque = NULL;
   vta.chase_into_ok = &chase_into_ok;
   vta.preamble_function = NULL;
   vta.guest_extents = &vge;
   vta.host_bytes = tmpbuf;
   vta.host_bytes_size = N_TMPBUF;
   vta.host_bytes_used = &tmpbuf_used;

   vta.instrument1 = &instrument;
   vta.instrument2 = NULL;

   vta.finaltidy = NULL;
   vta.do_self_check = False;
   vta.traceflags = 0;
   
   vta.dispatch = (void*)&dispatch;

   //DLOG("VEX before translate\n");
   tres = LibVEX_Translate(&vta);
   //DLOG("VEX after translate\n");

   ASSERT(tres == VexTransOK);
   ASSERT(tmpbuf_used <= N_TMPBUF);
   ASSERT(tmpbuf_used > 0);
}

static VOID
BblBefore(ADDRINT pc)
{
   //DLOG(" bblock: 0x%x\n", pc);
   
   translate(pc); 
   
}

#endif

static INLINE VOID
Instruction_Instruction(INS ins)
{
#if INSTRUMENT_INSTRUCTIONS
   INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(InsBefore),
         IARG_INST_PTR,
         IARG_END);
#endif
}

static INLINE VOID
Instruction_Syscall(INS ins)
{
#if INSTRUMENT_SYSCALLS
   if (INS_IsSyscall(ins)) {
      // Arguments and syscall number is only available before
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
            IARG_INST_PTR,
            IARG_SYSCALL_NUMBER,
            IARG_SYSARG_REFERENCE, 0, IARG_SYSARG_REFERENCE, 1,
            IARG_SYSARG_REFERENCE, 2, IARG_SYSARG_REFERENCE, 3,
            IARG_SYSARG_REFERENCE, 4, IARG_SYSARG_REFERENCE, 5,
            IARG_END);

      // return value only available after
      INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
            IARG_SYSRET_VALUE,
            IARG_END);
   }
#endif
}

static INLINE VOID
Instruction_Atomic(INS ins)
{
#if INSTRUMENT_ATOMIC
   if (INS_IsAtomicUpdate(ins)) {
      /* Atomic updates read and write to memory. */
      ASSERT(INS_IsMemoryWrite(ins));
      ASSERT(INS_IsMemoryRead(ins));

      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(AtomicBefore),
            IARG_MEMORYWRITE_EA,
            IARG_END);
      INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(AtomicAfter),
            IARG_MEMORYREAD_EA,
            IARG_END);
   }
#endif
}

static INLINE VOID
Instruction_Access(INS ins)
{
#if INSTRUMENT_ACCESSES
   if (!INS_IsAtomicUpdate(ins)) {
      if (INS_IsMemoryRead(ins)) {

         /* NOTE: can't instrument after call/rets, so we
          * must instrument before */
         INS_InsertCall(ins, IPOINT_BEFORE,
               (AFUNPTR)BeforeRead,
               IARG_MEMORYREAD_EA,
               IARG_INST_PTR,
               IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
               IARG_END);

      } else if (INS_IsMemoryWrite(ins)) {

         INS_InsertCall(ins, IPOINT_BEFORE,
               (AFUNPTR)BeforeWrite,
               IARG_MEMORYWRITE_EA,
               IARG_INST_PTR,
               IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
               IARG_END);
      }
   }
#endif
}

static INLINE VOID
Instruction_Branch(INS ins)
{
#if INSTRUMENT_BRANCHES
   if (INS_IsBranchOrCall(ins) &&
         INS_HasFallThrough(ins)) {
      if (Thread_IsVkernelRunning()) {
         /* Some additional work is necessary when running underneath
          * the vkernel. For example, we need to write the branch count into
          * the vkernel address space. */
         /* XXX: check that the vkernel segreg is loaded */
         INS_InsertCall(ins, IPOINT_BEFORE,
               (AFUNPTR)OnBranchRunningVkernel,
               IARG_END);
      } else {
         INS_InsertCall(ins, IPOINT_BEFORE,
               (AFUNPTR)OnBranch,
               IARG_END);
      }
   } 
#endif
}


static VOID
Trace(TRACE trace, VOID *v)
{

   for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
#if USE_LIBVEX
      BBL_InsertCall(bbl, IPOINT_BEFORE,
            AFUNPTR(BblBefore),
            IARG_INST_PTR,
            IARG_END);
#endif
      for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
         ADDRINT pc = INS_Address(ins);
         Instruction_Syscall(ins);

         if (!Thread_IsInVkernel(pc)) {
            Instruction_Instruction(ins);
            Instruction_Atomic(ins);
            Instruction_Access(ins);
            Instruction_Branch(ins);
         }
         Btracer_Instruction(ins);
#if ENABLE_REPLAYCHECK
         ReplayCheck_Instruction(ins);
#endif
      }
   }
}

static VOID
BeforeRoutine(ADDRINT pc)
{
   string name = RTN_FindNameByAddress(pc);
   DEBUG_MSG(5, "Routine: %s\n", name.c_str());
}

#if INSTRUMENT_ROUTINES
static VOID
Image(IMG img, VOID* v)
{
   for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) ) {
      for( RTN rtn= SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) )  {
         RTN_Open(rtn);
         RTN_InsertCall(rtn, IPOINT_BEFORE,
               (AFUNPTR)BeforeRoutine, 
               IARG_INST_PTR,
               IARG_END);
         RTN_Close(rtn);
      }
   }
}
#endif

static void
TLS_Init()
{
   infoKey = PIN_CreateThreadDataKey(NULL);
   ASSERT(infoKey != -1);
}


static void
Init()
{
   char *isReplayStr = getenv("REPLAY");
   char *isVkernelRunningStr = getenv("VKERNEL");
   if (isReplayStr) {
      isReplay = atoi(isReplayStr);
      if (isReplay) {
         isVkernelRunning = 1;
      }
   }
   if (isVkernelRunningStr) {
      isVkernelRunning = atoi(isVkernelRunningStr);
      if (isVkernelRunning) {
         /* The vkernel uses a periodic timer to generate snoop events, so
          * we don't have to. */
         ASSERT(!ENABLE_SNOOP_EVENTS);
      } else {
         ASSERT(ENABLE_SNOOP_EVENTS);
         ASSERT(!isReplay);
      }
   }

   /* Initialize the debugging subsystem. We want to do this early
    * so we can start printing debug messages to the log immediately. */
   DebugInit(1);

   TLS_Init();

   /* Should not be turned on -- the safe malloc consumes at least
    * 12K per allocation and thus you will run out of memory fater
    * a few 100 accesses. */
#define USE_SAFE_MALLOC 0

#define SHAREDAREA_SIZE (0x1 << 28)

   /* All shared objects will be allocated in a set of pages
    * that are mapped into all (child) process addresses spaces, 
    * called the shared area. */
   SharedArea_Init("race-detect", SHAREDAREA_SIZE, USE_SAFE_MALLOC);

   extern void Segment_Init();
   Segment_Init();

   Synch_LockInit(&eventLock);

   ASSERT(chanMap == NULL);
   DLOG("Allocating global data structures.\n");
   /* verify first thread sets up all shared structures */
   chanMap = new ChannelMap;
   segQueue = new SegmentQueue;
   framePool = new FramePool;
   shmMap = new ShmSegMap(framePool);
   idMap = new IdMap;
   thrMap = new ThreadMap;

   VectorClock vc(0);
   /* First thread/process gets a brand new page table. */
   PageTable *ptPtr = new PageTable(framePool, shmMap);
   ASSERT(ptPtr);
   ThreadId myId = idMap->get();
   ASSERT(myId == 0);
   Thread *newThrPtr = new Thread(vc, myId, PIN_GetTid(),
         PIN_GetTid(), 0, ptPtr);
   ASSERT(newThrPtr);
   thrMap->insert(ThreadPair(PIN_GetTid(), newThrPtr));
   PIN_SetThreadData(infoKey, newThrPtr, PIN_ThreadId());
   DLOG("Done allocating global data structures.\n");

#if USE_LIBVEX
   {
      VexControl vc;

      vc.iropt_verbosity = 0;
      vc.iropt_level = 0;
      vc.iropt_precise_memory_exns = 0;
      vc.iropt_unroll_thresh = 120;
      vc.guest_max_insns = 50;
      vc.guest_chase_thresh = 10;


      DLOG("vex here\n");
      LibVEX_Init (
            /* failure exit function */
            &failure_exit,
            /* logging output function */
            &log_bytes,
            /* debug paranoia level */
            5,
            /* Are we supporting valgrind checking? */
            false,
            /* Control ... */
            /*READONLY*/
            &vc
            );
      DLOG("vex after\n");
   }
#endif
   Btracer_Init();
}


static BOOL
SignalHandler(THREADID threadIndex, INT32 sig, CONTEXT* ctx, 
      BOOL hashHndlr, VOID *v) {

   DLOG("SIGSEGV!\n");
   exit(-1);

   return TRUE;
}

int main(INT32 argc, CHAR **argv)
{

   PIN_InitSymbols();
   PIN_Init(argc, argv);

   Init();

   PIN_AddThreadStartFunction(ThreadBegin, 0);
   PIN_AddThreadFiniFunction(ExitAfter, 0);
   PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkBegin, 0);
   PIN_AddSignalInterceptFunction(SIGSEGV, SignalHandler, NULL);
   TRACE_AddInstrumentFunction(Trace, 0);
#if INSTRUMENT_ROUTINES
   IMG_AddInstrumentFunction(Image, 0);
#endif


   // Never returns
   PIN_StartProgram();

   return 0;
}
