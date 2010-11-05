/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

/*
 * Design notes:
 *
 * o We allocate a perfctr page for each thread in the address space,
 * since perfctr driver virtualizes the branch count on a per-thread
 * basis rather than a per-vcpu basis.
 *
 * XXX: virtualize on a per-vcpu basis so that we need only NR_VCPU
 * perfctr pages
 *
 * o PMI may be late -- we compensate using PMI_MAX_LATENCY 
 *
 * o On PMI, we assume that perfctr will disable the i-mode counter
 *   (i.e, the counter responsible for counting down branches to PMI).
 *   This should prevent a PMI from being generated too early because
 *   of branches executed by vkernel code.
 */

static struct vperfctr_control initControl;

static void 
HardBrCntEnable(struct vperfctr_control *pcontrol)
{
   int err;
   
   err = vperfctr_control(current->perfctr, pcontrol);

   DEBUG_MSG(5, "err=%d\n", err);
   ASSERT_UNIMPLEMENTED(!err);
}

static INLINE uint
HardBrCntCalcPmiTarget(ullong brTillPMI)
{
   uint pmiTarget;
#if 0
   struct perfctr_cpu_control *controlp = &current->pmiControl.cpu_control;
#endif

   ASSERT(brTillPMI > PMI_MAX_LATENCY);
   ASSERT(VCPU_IsReplaying());

   Task_SetCurrentFlag(TIF_PMI_PENDING);

   /* The counters are 32-bit, so if brTillPMI exceeds the 
    * max 32-bit value then we must cut it short. 
    * This of course means that we'll PMI early, but that's 
    * okay --- we can re-enter direct execution to wait for the rest. */
   pmiTarget = MIN(brTillPMI, UINT_MAX);


   /* Of course, the preemption may be late by PMI_MAX_LATENCY.
    * Compensate to make sure we don't miss the target
    * branch count. */
   pmiTarget -= PMI_MAX_LATENCY;

   DEBUG_MSG(5, "pmiTarget=%lu\n", pmiTarget);

   /* perfctr driver doesn't like a 0 ireset val. */
   ASSERT(pmiTarget != 0);

#if 0
   /* 
    * The PMI is generated when the counter overflows. Hence
    * assign the counter the negated branch count eta.
    * 
    * NOTE: If interrupts are included in the imode branch code, the PMI might
    * arrive even earlier than this. But that's okay since we can crawl up
    * to the delivery point. We just have to make sure we don't miss it. */

   controlp->ireset[1] = -((int) pmiTarget);



   /* XXX: installing an ireset via the control interface is expensive -- 
    * we need a new ioctl cmd in the perfctr driver that does just this and
    * only this. 
    *
    * or maybe make the control visible in the perfctr page? */
   HardBrCntEnable(&current->pmiControl);
#endif
   return pmiTarget;
}


void
BrCnt_OnPMI(uint ovfMask)
{
   struct Brkpt *ev;

   ASSERT(VCPU_IsReplaying());
   ASSERT(Task_TestFlag(current, TIF_PMI_PENDING));
   Task_ClearCurrentFlag(TIF_PMI_PENDING);

   /* The PMI is installed on the second counter and so
    * it should have overflowed for us to be here. */
   ASSERT(ovfMask & 0x2);

   /* NOTE: perfctr suspends i-mode counters on PMI, so no need
    * for us to do so explicitly. */

   /* 
    * Problem: perfctr suspends a-mode counters on PMI. This is bad
    * for us, since our interrupt count is still running.
    *
    * Options:
    *
    * 1. Don't suspend a-mode counters on PMI.
    *       + no need to resume a-mode on exit (no syscall overhead)
    *       - unknown side-effects?
    *
    * 2. Suspend both a-mode and interrupt counter on PMI.
    *    + just need to suspend interrupt counter.
    *    - must resume a-mode/interrupts via syscall
    *
    *
    * We went with option 1.
    */

   /* ev is task local, so no locking required */
   ev = Brkpt_PeekFirst();
   ASSERT(ev);

   /* Is the pmi late? */
   DEBUG_MSG(5, "PMI: brCnt %llu target %llu\n",
         BrCnt_Get(), Brkpt_GetBrCnt(ev));
   ASSERT(BrCnt_Get() <= Brkpt_GetBrCnt(ev));

   /* Nothing else to do here. The magic happens when we
    * resume to user mode -- the dispatch will see that the
    * notification is not PMIable and hence will crawl
    * to the delivery point in BT mode. */
}

uint ASMLINKAGE
BrCnt_CalcPmiTarget()
{
   uint pmiTarget = 0;
   ullong brTillPMI;
   struct Brkpt *ev;
   
  
   ASSERT(VCPU_IsReplaying());

   /* If we have notifications, setup a PMI for the earliest
    * brcnt. The PMI shouldn't be late, because we checked
    * that it isn't (in the dispatch helper) before deciding 
    * to enter DE mode. */

   ev = Brkpt_PeekFirst();
   if (ev && ev->kind == Bpk_Dynamic) {
      brTillPMI = Brkpt_CalcNrBranchesTillHit(ev);
      ASSERT(brTillPMI > PMI_MAX_LATENCY);

      DEBUG_MSG(5, "Next notify at brCnt %llu, ETA %llu branches.\n",
            Brkpt_GetBrCnt(ev), brTillPMI);

      pmiTarget = HardBrCntCalcPmiTarget(brTillPMI);
   }

   D__;
   return pmiTarget;
}

int
BrCnt_IsPMISig(siginfo_t *si)
{
   return si->si_signo == SIG_RESERVED_TRAP && si->si_code == SI_PMC_OVF;
}

static int
HardBrCntInit()
{
   int err;
#if PRODUCT
   /* We need FPU emulation during recording, because VEX does not
    * emulate FPU ops precisely. We get determinism by running the
    * FPU ops under vex during both recording and replay. */
#error "XXX: fix FPU emulation kernel hang bug, and turn it back on"
#else
   struct perfctr_emu_setup_struct setup = { 
      .vkernel_start = __VKERNEL_TEXT_START,
      .vkernel_end   = __IMAGE_END,
      .flags         = 0 ? VPERFCTR_EMUOPT_FPU : 0,
   };
#endif
   ASSERT(__VDSO_TEXT_END <= __VKERNEL_TEXT_START);
   ulong pageAddr = __VPERFCTR_START + (current->vperfPageIdx*PAGE_SIZE);

   if (!Task_IsThread(current)) {
      ASSERT(current->vperfPageIdx == 0);
   }
   ASSERT(pageAddr+PAGE_SIZE <= __VPERFCTR_END);

   current->perfctr = vperfctr_open_mapaddr(pageAddr);

   if (!current->perfctr) {
      FATAL("cannot open the perfctr device\n");
   }

   /* The vperfctr page is usefull only to the owning task and hence
    * we don't want the vperfctr page inherited across forks and
    * consuming precious vkernel address space. */
   err = syscall(SYS_madvise, pageAddr, PAGE_SIZE, MADV_DONTFORK);
   ASSERT(!SYSERR(err));

   HardBrCntEnable(&initControl);

   /* To ease access from assembly. */
   ASSERT(current->perfctr->kstate);
   current->perf_cpu_state = &current->perfctr->kstate->cpu_state;
   ASSERT(current->perf_cpu_state);

   //printf("before emu\n");
   err = vperfctr_emu_setup(current->perfctr, &setup);
   //printf("after emu\n");
   ASSERT(!err);

   return 1;
}

/* Note that this var limits the number of threads. */
#define MAX_VPERFCTR_PAGES 1024
static char vperfctrAreaBmp[MAX_VPERFCTR_PAGES / 8];

SYNCH_DECL_INIT(static, areaBmpLock);


void
BrCnt_SelfInit()
{
   /* The goal here is to allocate a perfctr page for this thread. 
    * The main challenge is in finding a free page in the vkernel
    * address space, which we handle using an allocation bitmap. */

   if (!Cap_Test(CAP_HARD_BRCNT)) {
      return;
   }

   if (!Task_IsThread(current)) {
      memset(vperfctrAreaBmp, 0, sizeof(vperfctrAreaBmp));
      ASSERT(current->mm);
      ASSERT(current->mm->users == 1);
   }

   SYNCH_LOCK(&areaBmpLock);

   current->vperfPageIdx = Bit_FindFirstZeroBit(
         (ulong*)vperfctrAreaBmp,
         sizeof(vperfctrAreaBmp));
   ASSERT_UNIMPLEMENTED(current->vperfPageIdx < MAX_VPERFCTR_PAGES);
   if (!Task_IsThread(current)) {
      ASSERT(current->vperfPageIdx == 0);
   }

   Bit_TestSet(current->vperfPageIdx, (ulong *) vperfctrAreaBmp);

   SYNCH_UNLOCK(&areaBmpLock);

   DEBUG_MSG(5, "current->vperfPageIdx=%d\n", current->vperfPageIdx);

   HardBrCntInit();
}


void
BrCnt_Fork(struct Task * tsk)
{
   tsk->brCntOnEntry = 0;
   tsk->vkBrCnt = 0;
   DEBUG_ONLY(tsk->lastBrCnt = 0;)
}

void FASTCALL
BrCnt_SelfExit(struct vperfctr *perfctr, int vperfPageIdx)
{
   ASSERT(current == &startupTask);

   /* May not be using hardware branch counting ... */
   if (perfctr) {
      int err;

      SYNCH_LOCK(&areaBmpLock);
      ASSERT(vperfPageIdx >= 0);
      Bit_TestClear(vperfPageIdx, (ulong*) vperfctrAreaBmp);

      /* XXX: better hope that assertions don't within
       * the vperfctr user code after the page has been unmapped. */
      err = vperfctr_close(perfctr);

      /* NO ASSERTIONS BEYOND THIS POINT -- PERFCTR PAGE IS GONE! */

      DEBUG_MSG(5, "current->realPid=%d gettid()=%d\n", current->realPid,
            gettid());
      SYNCH_UNLOCK(&areaBmpLock);


      perfctr = NULL;
   }
}

ullong REGPARM(2)
BrCnt_Sum(ulong rdpmc, struct Task *tsk)
{
   return tsk->perf_cpu_state->pmc[0].sum +
      (rdpmc - tsk->perf_cpu_state->pmc[0].start);
}

/* 
 * Intentionally REGPARM(3) and not REGPARM(2) to accomodate the 64-bit 
 * brCnt + struct Task *
 */
void REGPARM(3)
BrCnt_Tally(ullong brCnt, struct Task *tsk)
{
   tsk->vkBrCnt += brCnt - tsk->brCntOnEntry;
}

static int
BrCnt_Init()
{
   memset(&initControl, 0, sizeof(initControl));

   if (Cap_Test(CAP_HARD_BRCNT)) {
      /* Doesn't invoke the perfctr driver, just
       * sets up the control data structure. */
      PmcOps_SetupCounter(PMC_BR, &Cap_PerfInfo, 
            &initControl.cpu_control);

      /* When we get a PMI, we start executing vkernel code
       * and hence we want to stop the i-mode count --
       * this is the PMC that countdowns for PMI. But we
       * don't want the a-mode count (a non-PMI PMC that counts branches),
       * disabled -- there is no good reason to do this, other than
       * to maintain consistency with log-mode behavior. */
      initControl.flags = VPERFCTR_CONTROL_NOSUSPEND_AMODE;
      initControl.si_signo = SIG_RESERVED_TRAP;
   }

   return 0;
}

/* CORE and not POSTCORE, since entrypoint handlers will sigsegv
 * without setting up the perfctr page, and hence will sigsegv
 * if an ASSERT fires during init. */
CORE_INITCALL(BrCnt_Init);
