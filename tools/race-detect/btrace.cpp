#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>

#include "thread.h"

#include "pin.H"
#include "debug.h"
#include "compiler.h"

#include "btracer.h"


extern "C" {
#include "libvex.h"
};


#define UPDATE_BUFFER 1
#define BRCNT 1

#if UPDATE_BUFFER
#define LOG_TO_BUFFER(x) x
#else
#define LOG_TO_BUFFER(x)
#endif


#define LOG_FILE_SIZE (1 << 24)


VOID
HandleDivergence(ulong brCnt, ulong pc, ulong logVal, ulong repVal)
{
   DEBUG_MSG(5, "Divergence: brCnt=%d pc=0x%x log=%d(0x%x) rep=%d(0x%x)\n", 
         brCnt, pc, logVal, logVal, repVal, repVal);
   ASSERT(0);
}

#if 1
VOID IsTakenMisprediction(UINT32 brId, ADDRINT pc) {
   struct BtracerStruct *bt = &current->bt;
   struct BranchInfoStruct *brp = &bt->branchInfo[brId];

   ASSERT(!current->isInInst);
   current->isInInst = 1;

   STATS_ONLY(brp->numBranches++;);

   uint idx = brp->shr & 0xF;
   uchar tabIdx = idx*2;
   ASSERT(0 <= idx && idx < 16);
   uint mask = 0x3 << tabIdx;
   uchar pred = (brp->table & mask) >> tabIdx;
   //ASSERT(pred <= 3);
   DLOG("TAKEN: brCnt=%d pc=0x%x idx=0x%x pred=%d bufptr=0x%x\n", current->brCnt, pc, idx, pred, bt->bufPtr);
#if 1
   /* Is the 2-bit counter >= 2? Indicates a not-taken guess. */
   if (pred & 0x2) {
      if (Thread_IsLogging()) {
         LOG_TO_BUFFER(*(bt->bufPtr) = current->brCnt;);
      } else {
         if (*(bt->bufPtr) != current->brCnt) {
            /* Since the mispredict was not logged, it must be a
             * divergence -- the branch should NOT have been taken. */
            HandleDivergence(current->brCnt, brp->pc,
                  *(bt->bufPtr), 1 /* taken */);
         }
      }

      DEBUG_MSG(5, "MP\n");

      bt->bufPtr++;
      STATS_ONLY(bt->condMispredicts++;);
   }

   if (pred > 0) {
      pred--;
      brp->table = (brp->table & ~mask) | ((uint)pred << tabIdx);
   }
   brp->shr = (brp->shr << 1) | 0x1;
#endif
   STATS_ONLY(bt->numCondExec++;);
   current->isInInst = 0;
}

VOID IsNotTakenMisprediction(UINT32 brId, ADDRINT pc) {
   struct BtracerStruct *bt = &current->bt;
   struct BranchInfoStruct *brp = &bt->branchInfo[brId];

   ASSERT(!current->isInInst);
   current->isInInst = 1;

   STATS_ONLY(brp->numBranches++;);

   uint idx = brp->shr & 0xF;
   uchar tabIdx = idx*2;
   ASSERT(0 <= idx && idx < 16);
   uint mask = 0x3 << tabIdx;
   uchar pred = (brp->table & mask) >> tabIdx;
   //ASSERT(pred <= 3);
   DLOG("NOT TAKEN: brCnt=%d pc=0x%x idx=0x%x pred=%d bufptr=0x%x\n", current->brCnt, pc, idx, pred, bt->bufPtr);
#if 1
   /* Is the 2-bit counter < 2? That indicates a taken guess. */
   if (!(pred & 0x2)) {
      if (Thread_IsLogging()) {
         LOG_TO_BUFFER(*(bt->bufPtr) = current->brCnt;);
      } else {
         if (*(bt->bufPtr) != current->brCnt) {
            /* Since the mispredict was not logged, it must be a
             * divergence -- the branch should have been taken. */
            HandleDivergence(current->brCnt, brp->pc, 
                  *(bt->bufPtr), 0 /* not taken */);
         }
      }
      DEBUG_MSG(5, "MP\n");
      bt->bufPtr++;
      STATS_ONLY(bt->condMispredicts++;);
   }

   if (pred < 3) {
      pred++;
      brp->table = (brp->table & ~mask) | ((uint)pred << tabIdx);
   }
   brp->shr = brp->shr << 1;
#endif
   STATS_ONLY(bt->numCondExec++;);
   current->isInInst = 0;
}

VOID INLINE
LogIndirectMispredict(struct BtracerStruct *bt, struct BranchInfoStruct *brp, ADDRINT actualTarget)
{
   if (Thread_IsLogging()) {
      LOG_TO_BUFFER(*(bt->bufPtr) = actualTarget;);
   } else {
      if (*(bt->bufPtr) != actualTarget) {
         HandleDivergence(current->brCnt, brp->pc, *(bt->bufPtr),
               actualTarget);
      }
   }
   bt->bufPtr++;
}

VOID IsUIJumpTargetMisprediction(UINT32 brId, ADDRINT actualTarget) {
   struct BtracerStruct *bt = &current->bt;
   struct BranchInfoStruct *brp = &bt->branchInfo[brId];

   ASSERT(!current->isInInst);
   current->isInInst = 1;

   DLOG("IJump: target=0x%x actualTarget=0x%x bufptr=0x%x\n",
         brp->target, actualTarget, bt->bufPtr);
   if (brp->target != actualTarget) {
      LogIndirectMispredict(bt, brp, actualTarget);
      brp->target = actualTarget;
      STATS_ONLY(bt->btbMispredicts++;);
   }
   STATS_ONLY(bt->numBtbExec++;);
   current->isInInst = 0;
}

#if BTRACER_STATS
#define PushToRSB() \
   bt->rsb[bt->rsbIdx] = retAddr; \
bt->rsbIdx = (bt->rsbIdx + 1) % RSB_SIZE; \
ASSERT(bt->rsbIdx < RSB_SIZE); \
   bt->callDepth++; \
   if (bt->callDepth > bt->maxCallDepth) { \
      bt->maxCallDepth = bt->callDepth; \
   } \
   STATS_ONLY(bt->numCallExec++;);
#else
#define PushToRSB() \
   bt->rsb[bt->rsbIdx] = retAddr; \
   bt->rsbIdx = (bt->rsbIdx + 1) % RSB_SIZE; \
   ASSERT(bt->rsbIdx < RSB_SIZE);
#endif

#if USE_RSB
VOID UDCallUpdateRSB(ADDRINT retAddr) {
   struct BtracerStruct *bt = &current->bt;

   PushToRSB();
}

VOID UICallUpdateRSB(UINT32 brId, ADDRINT retAddr, ADDRINT actualTarget) {
   struct BtracerStruct *bt = &current->bt;
   struct BranchInfoStruct *brp = &bt->branchInfo[brId];

   ASSERT(!current->isInInst);
   current->isInInst = 1;

   PushToRSB();

   DLOG("ICall: target=0x%x actualTarget=0x%x bufptr=0x%x\n",
         brp->target, actualTarget, bt->bufPtr);
   if (brp->target != actualTarget) {
      LogIndirectMispredict(bt, brp, actualTarget);
      brp->target = actualTarget;
      STATS_ONLY(bt->btbMispredicts++;);
   }

   current->isInInst = 0;
}

VOID IsRetTargetMisprediction(UINT32 brId, ADDRINT actualTarget) {
   struct BtracerStruct *bt = &current->bt;
   struct BranchInfoStruct *brp = &bt->branchInfo[brId];
   ASSERT(!current->isInInst);
   current->isInInst = 1;

   bt->rsbIdx = (bt->rsbIdx - 1) % RSB_SIZE;
   ASSERT(bt->rsbIdx < RSB_SIZE);

   STATS_ONLY(bt->callDepth--);
   DLOG("IRet: target=0x%x actualTarget=0x%x bufptr=0x%x\n",
         bt->rsb[bt->rsbIdx], actualTarget, bt->bufPtr);
   if (bt->rsb[bt->rsbIdx] != actualTarget) {
      LogIndirectMispredict(bt, brp, actualTarget);
      STATS_ONLY(bt->rsbMispredicts++;);
   }
   STATS_ONLY(bt->numRetExec++;);
   current->isInInst = 0;
}
#endif

#endif

/* One branch pc --> id map per address space. We expect these
 * to be inherited COW across forks. */
static BranchPcMap *brPcMap = NULL;
static BranchIdMap *brIdMap = NULL;
struct SynchLock brLock;

static VOID
PutBranchRange(ADDRINT start, size_t len)
{
   LOCK(&brLock);

   BranchPcMap::iterator it;

   for (it = brPcMap->begin(); it != brPcMap->end(); it++) {
      if (start <= it->first && it->first < (start+len)) {

         brIdMap->put(it->second);
      }
   }

   /* XXX: is this actually necessary? PIN probably does this
    * anyway. */
   CODECACHE_InvalidateRange(start, start+len);

   UNLOCK(&brLock);
}

static UINT32
GetBranchId(ADDRINT insAddr)
{
   UINT32 brId;

   LOCK(&brLock);

   BranchPcMap::iterator it = brPcMap->find(insAddr);

   if (it == brPcMap->end()) {
      brId = brIdMap->get();
      brPcMap->insert(BranchPair(insAddr, brId));
   } else {
      brId = it->second;
   }

   UNLOCK(&brLock);

   return brId;
}


static VOID
BtracerSysBefore(ADDRINT *eax, ADDRINT *ebx, ADDRINT *ecx, ADDRINT *edx,
      ADDRINT *esi, ADDRINT *edi, ADDRINT *ebp)
{
   current->sysno = *eax;
   ASSERT(current->sysno == *eax);

   switch (current->sysno) {
   case SYS_emu_branch:
      {
         ADDRINT pc = *ebx;
         UINT32 brId = GetBranchId(pc);
         UINT32 taken = *ecx;

         DLOG("pc=0x%x taken=%d\n", pc, taken);
         if (taken) {
            IsTakenMisprediction(brId, pc);
         } else {
            IsNotTakenMisprediction(brId, pc);
         }
      }

      break;
   case SYS_emu_ijump:
      {
         ADDRINT pc = *ebx;
         UINT32 brId = GetBranchId(pc);
         UINT32 isIndirect = *ecx;
         UINT32 jumpKind = *edx;
         ADDRINT nextInsAddr = *esi;
         ADDRINT target = *edi;

         DLOG("pc=0x%x isIndirect=%d jumpKind=0x%x nextAddr=0x%x target=0x%x\n",
               pc, isIndirect, jumpKind, nextInsAddr, target);
         switch (jumpKind) {
         case Ijk_Call:
            if (isIndirect) {
               UICallUpdateRSB(brId, nextInsAddr, target);
            } else {
               UDCallUpdateRSB(nextInsAddr);
            }
            break;
         case Ijk_Ret:
            ASSERT(isIndirect); /* by definition */
            IsRetTargetMisprediction(brId, target);
            break;
         default:
            break;
         }
      }

      break;
   default:
      break;
   }
}

static VOID
BtracerSysAfter(ADDRINT *eax, ADDRINT *ebx, ADDRINT *ecx, ADDRINT *edx,
                ADDRINT *esi, ADDRINT *edi, ADDRINT *ebp)
{
   switch (current->sysno) {
   case SYS_munmap:
      if (!SYSERR(*eax)) {
         /* Remove branches in region from branchMap and Id map. */
         ASSERT(PAGE_ALIGNED(*ebx));
         ASSERT(PAGE_ALIGNED(*ecx));
         PutBranchRange(*ebx, *ecx);
      }
      break;
   default:
      break;
   }
}


#if 1
static VOID 
BtracerNonVkInstruction(INS ins) {
   struct BtracerStruct *bt = &current->bt;
   ASSERT(bt);

   ADDRINT insAddr = INS_Address(ins);


   if (INS_IsBranchOrCall(ins)) {
      if (INS_HasFallThrough(ins)) {
         /* Conditional. */

#if 1
         if (INS_IsDirectBranchOrCall(ins)) {
            STATS_ONLY(bt->numCondDirect++;);

            /* Conditional direct. */
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                  (AFUNPTR)IsTakenMisprediction,
                  IARG_UINT32, GetBranchId(insAddr),
                  IARG_INST_PTR,
                  IARG_END);

            INS_InsertCall(ins, IPOINT_AFTER,
                  (AFUNPTR)IsNotTakenMisprediction,
                  IARG_UINT32, GetBranchId(insAddr),
                  IARG_INST_PTR,
                  IARG_END);
         } else {
            /* Conditional indirect. No such instruction (???). */
            STATS_ONLY(bt->numCondIDirect++;);
            ASSERT(!INS_IsCall(ins));
            ASSERT(0);
         }
#endif
      } else {
#if 1
         /* Unconditional. */
         if (INS_IsIndirectBranchOrCall(ins)) {
            /* Unconditional indirect. */
            STATS_ONLY(bt->numUncondIDirect++;);

#if USE_RSB
            if (INS_IsProcedureCall(ins)) {
               STATS_ONLY(bt->numUncondIDirectCalls++;);
               INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                     (AFUNPTR)UICallUpdateRSB,
                     IARG_UINT32, GetBranchId(insAddr),
                     IARG_RETURN_IP,
                     IARG_BRANCH_TARGET_ADDR,
                     IARG_END);
            } else if (INS_IsRet(ins)) {
               STATS_ONLY(bt->numRets++;);
               INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                     (AFUNPTR)IsRetTargetMisprediction,
                     IARG_UINT32, GetBranchId(insAddr),
                     IARG_BRANCH_TARGET_ADDR,
                     IARG_END);
            } else {
#endif
               STATS_ONLY(bt->numUncondIDirectJumps++;);

               INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                     (AFUNPTR)IsUIJumpTargetMisprediction,
                     IARG_UINT32, GetBranchId(insAddr),
                     IARG_BRANCH_TARGET_ADDR,
                     IARG_END);
#if USE_RSB
            }
#endif
         } else {
            /* Unconditional direct transfer. */

            STATS_ONLY(bt->numUncondDirect++;);
#if USE_RSB
            if (INS_IsProcedureCall(ins)) {
               STATS_ONLY(bt->numUncondIDirectCalls++;);
               INS_InsertCall(ins, IPOINT_TAKEN_BRANCH,
                     (AFUNPTR)UDCallUpdateRSB,
                     IARG_RETURN_IP,
                     IARG_END);
            }
#endif
         }
#endif
      }
   }
}

static VOID 
BtracerVkInstruction(INS ins) {
   if (INS_IsSyscall(ins)) {
#define PREG(r) LEVEL_BASE::REG_##r
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(BtracerSysBefore),
            IARG_REG_REFERENCE, PREG(EAX),
            IARG_REG_REFERENCE, PREG(EBX),
            IARG_REG_REFERENCE, PREG(ECX),
            IARG_REG_REFERENCE, PREG(EDX),
            IARG_REG_REFERENCE, PREG(ESI),
            IARG_REG_REFERENCE, PREG(EDI),
            IARG_REG_REFERENCE, PREG(EBP),
            IARG_END);
      INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(BtracerSysAfter),
            IARG_REG_REFERENCE, PREG(EAX),
            IARG_REG_REFERENCE, PREG(EBX),
            IARG_REG_REFERENCE, PREG(ECX),
            IARG_REG_REFERENCE, PREG(EDX),
            IARG_REG_REFERENCE, PREG(ESI),
            IARG_REG_REFERENCE, PREG(EDI),
            IARG_REG_REFERENCE, PREG(EBP),
            IARG_END);
   }
}

VOID 
Btracer_Instruction(INS ins) {
   ADDRINT pc = INS_Address(ins);

   if (Thread_IsInVkernel(pc)) {
      BtracerVkInstruction(ins);
   } else {
      BtracerNonVkInstruction(ins);
   }
}

#endif



#if 0
BOOL SigSegvHandler(THREADID threadIdx, INT32 sig, CONTEXT *ctxt, 
      BOOL hashHndlr, VOID *v)
{
   //exit(-1);

   return FALSE;
}
#endif

static VOID
BtracerCloseLog()
{
   struct BtracerStruct *bt = &current->bt;

   ASSERT(bt->buf);
   int unmapres = munmap(bt->buf, LOG_FILE_SIZE+PAGE_SIZE);
   ASSERT(unmapres == 0);
   bt->buf = bt->bufPtr = NULL;

   if (bt->logFd != -1) {
      /* XXX: shouldn't close it if this is a new thread. */
      close(bt->logFd);
   }
   bt->logFd = -1;
}

static VOID
BtracerOpenLog(ThreadId pid)
{
   char fileStr[256];
   int res, dummy = 0, fd;

   ASSERT(current);
   struct BtracerStruct *bt = &current->bt;

   /* If we inherited a log from the parent, unmap it. */
   if (bt->buf) {
      D__;
      BtracerCloseLog();
   }

   snprintf(fileStr, sizeof(fileStr), "/tmp/bt.%d", pid);
   bt->logFd = fd = open(fileStr,
         O_RDWR | (Thread_IsLogging() ? O_CREAT : 0),
         S_IWUSR | S_IRUSR);
   if (fd == -1) {
      FATAL("Can't open branch trace file ``%s''.\n", fileStr);
   }

   if (Thread_IsLogging()) {
      res = lseek(fd, LOG_FILE_SIZE-sizeof(dummy), SEEK_SET);
      res = write(fd, &dummy, sizeof(dummy));
      ASSERT(res == sizeof(dummy));
   }


   int prot = PROT_READ | (Thread_IsLogging() ? PROT_WRITE : 0);

   D__;
   void *mmapres = (void*)mmap(NULL, LOG_FILE_SIZE+PAGE_SIZE, prot, MAP_SHARED, fd, 0);
   DEBUG_MSG(5, "Log file: fd=%d start=0x%x\n", fd, mmapres);
   ASSERT(mmapres != MAP_FAILED);

   D__;
   char *guardPage = (char*)mmapres + LOG_FILE_SIZE;
   int mprotres = mprotect(guardPage, PAGE_SIZE, PROT_NONE);
   ASSERT(mprotres == 0);

   bt->buf = bt->bufPtr = (BucketType*)mmapres;
   D__;
}

VOID 
Btracer_ThreadStart(struct BtracerStruct *bt)
{
   ASSERT(bt);
   memset(bt, 0, sizeof(*bt));

   bt->buf = bt->bufPtr = NULL;
   bt->logFd = -1;
}

VOID
Btracer_ThreadEnd(struct BtracerStruct *bt)
{
}

VOID
Btracer_Init()
{
   brPcMap = new BranchPcMap;
   brIdMap = new BranchIdMap;
   Synch_LockInit(&brLock);
}

VOID
Btracer_Fini()
{
   delete brPcMap;
   delete brIdMap;
}

VOID
Btracer_Clone(struct Thread *t)
{
   /* Child inherits the log buffer from parent. So transfer
    * the pointer so that the child can unmap it before opening
    * his own buffer. */
   t->bt.buf = current->bt.buf;
}

void sigsegv_handler(int signr, siginfo_t *si, void* uc)
{
   ucontext_t *ucp = (ucontext_t*)uc;
   mcontext_t *mcp = &ucp->uc_mcontext;

   DEBUG_MSG(5, "CRASH at 0x%x cr2=0x%x!\n", mcp->gregs[::REG_EIP],
         mcp->cr2);
   exit(-1);
}

VOID
Btracer_ThreadStart(ThreadId pid)
{
   ASSERT(current);

   BtracerOpenLog(pid);

#if 0
   struct sigaction oa;

   sigaction(SIGSEGV, NULL, &oa);

   DEBUG_MSG(5, "handler=0x%x sigaction=0x%x sa_mask=0x%x sa_flags=0x%x\n", oa.sa_handler, oa.sa_sigaction, oa.sa_mask, oa.sa_flags, oa.sa_restorer);

   oa.sa_sigaction = &sigsegv_handler;
   oa.sa_flags = SA_SIGINFO | SA_ONSTACK;

   int res = sigaction(SIGSEGV, &oa, NULL);
   ASSERT(res == 0);
#endif
}

VOID 
Btracer_ThreadFinish()
{
#if BTRACER_STATS
   struct BtracerStruct *bt = &current->bt;

   DEBUG_MSG(5,
         "Staticc stats:\n"
         "\tnumCondDirect=%u numCondIDirect=%u\n"
         "\tnumUncondDirect=%u numUncondIDirect=%u\n"
         "\tnumUncondIDirectCalls=%u numUncondIDirectJumps=%u numRets=%u\n"
         "Dynamic stats:\n"
         "\tbrCnt=%u\n"
         "\tnumCondExec=%u numBtbExec=%u numCallExec=%u numRetExec=%u\n"
         "\tcondMispredicts=%u btbMispredicts=%u rsbMispredicts=%u\n"
         "\tmaxCallDepth=%u\n",
         bt->numCondDirect, bt->numCondIDirect,
         bt->numUncondDirect, bt->numUncondIDirect,
         bt->numUncondIDirectCalls, bt->numUncondIDirectJumps, bt->numRets,
         current->brCnt,
         bt->numCondExec, bt->numBtbExec, bt->numCallExec, bt->numRetExec,
         bt->condMispredicts, bt->btbMispredicts, bt->rsbMispredicts,
         bt->maxCallDepth
         );

   DEBUG_MSG(5, "totalBytes=%lu\n", (ulong)((ulong)bt->bufPtr - (ulong)bt->buf));
#endif
   BtracerCloseLog();
}
