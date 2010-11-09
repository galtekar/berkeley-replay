#include "vkernel/public.h"
#include "private.h"
#include <fcntl.h>

/*
 * Summary:
 *
 *    This module provides notification when an execution point
 *    is reached. This is useful for efficiently replaying 
 *    preemption events and for efficiently checking for
 *    a origin access (e.g., a racing read).
 *
 * Design:
 *
 *    o One notification-point map per address space, not per task
 *       - IRSBs may be invalidated and non-notification pending
 *       task may perform instrumentation, in which case they need
 *       to know about pending notifications in other threads to instrument
 *       delivery points, without which those other tasks will miss
 *       their delivery points
 *
 *    o One notification event map per task
 *       - Different tasks may want notifications at the same site
 *       for different reasons, and hence may want to invoke different
 *       callbacks
 *
 */

static struct MapStruct *
BrkptGetMap(BPKind bpk)
{
   ASSERT(bpk == Bpk_Static || bpk == Bpk_Dynamic);

   struct MapStruct *mapP = (bpk == Bpk_Static) ? current->stBrkptMap :
      current->dyBrkptMap;

   return mapP;
}


ullong
Brkpt_CalcNrBranchesTillHit(struct Brkpt *ev)
{
   ullong eta, brCnt = BrCnt_Get(), evBrCnt = Brkpt_GetBrCnt(ev);

   ASSERT(ev);
   ASSERT(VCPU_IsReplaying());
   ASSERT_MSG(evBrCnt >= brCnt, "nfyBrCnt=%llu brCnt=%llu\n", evBrCnt, brCnt);

   eta = evBrCnt - brCnt;

   return eta;
}

/* Returns a notification with the earliest branch count. 
 * Note that multiple notifications could have the same branch count. */
struct Brkpt *
Brkpt_PeekFirst()
{
   struct Brkpt *brkP = NULL;
   struct ListHead *headP = Map_GetList(current->dyBrkptMap);

   ASSERT_KPTR(headP);

   if (!List_IsEmpty(headP)) {
      brkP = list_entry(headP->next, struct Brkpt, taskMap.list);
   }

   /* brkP == NULL, if no notifications pending. */
   ASSERT(brkP || !brkP);

   return brkP;
}

#if DEBUG

#define DUMP_BRKPTS(mapP, field) { \
   struct Brkpt *brkP; \
   list_for_each_entry(brkP, Map_GetList(mapP), field.list) { \
      const struct ExecPoint *evEp = &brkP->ep; \
      DEBUG_MSG(5, "ep: 0x%8.8x.0x%8.8x.%16.16llu callback: 0x%x\n", \
            evEp->eip, evEp->ecx, evEp->brCnt, brkP->callback); \
   } \
}
static void
BrkptPrintPending()
{
   DEBUG_MSG(5, "Pending dynamic brkpts (curr brCnt=%llu):\n", BrCnt_Get());
   DUMP_BRKPTS(current->dyBrkptMap, taskMap);
   DEBUG_MSG(5, "Pending static brkpts (curr brCnt=%llu):\n", BrCnt_Get());
   DUMP_BRKPTS(current->stBrkptMap, taskMap);
}

static void
BrkptPrintPendingAll()
{
   DEBUG_MSG(5, "All brkps in MM:\n");
   DUMP_BRKPTS(current->mm->brkptSiteMap, mmMap);
}
#endif

static int
BrkptSortCb(struct Brkpt *newP, struct Brkpt *oldP)
{
   return Brkpt_GetBrCnt(newP) < Brkpt_GetBrCnt(oldP);
}

/* 
 * Insert brkpt into a per-address space list.
 *
 * This is so that threads uninterested in receiving brkpt notification
 * don't inadvertantely remove the notification helper on a TC
 * invalidation.
 */
static void
BrkptMMOp(struct Brkpt *brkP, int isInsert)
{
   struct MapStruct *mapP = current->mm->brkptSiteMap;

   ASSERT_KPTR(mapP);

   DEBUG_MSG(5, "isInsert=%d\n", isInsert);

   SYNCH_LOCK(&current->mm->brkptSiteLock);

   if (isInsert) {
      Map_Insert(mapP, mmMap, brkP->mmMap.keyLong, brkP);
   } else {
      Map_Remove(mapP, mmMap, brkP);
   }

   SYNCH_UNLOCK(&current->mm->brkptSiteLock);
}

/*
 * XXX: should not be called while executing translated code. 
 * Invalidation may free currently executing block. */
static void
BrkptInstallWork(BPKind bpk, const struct ExecPoint *locP, 
      BkptCbFn cbP, void *arg)
{
   struct Brkpt *brkP;

   DEBUG_MSG(5, "bpk=%d loc=0x%lx, 0x%lx, 0x%llx cbP=0x%x arg=0x%x\n",
         bpk, locP->eip, locP->ecx, locP->brCnt, cbP, arg);


   ASSERT_KPTR(locP);

   brkP = (struct Brkpt *) malloc(sizeof(*brkP));

   Map_NodeInit(&brkP->taskMap, locP->eip);
   Map_NodeInit(&brkP->mmMap, locP->eip);
   brkP->kind = bpk;
   brkP->ep = *locP;
   brkP->callback = cbP;
   brkP->arg = arg;

   BrkptMMOp(brkP, 1);
   Map_InsertSorted(BrkptGetMap(bpk), taskMap, locP->eip, brkP, &BrkptSortCb);

   D__;
   DEBUG_ONLY(BrkptPrintPendingAll();)

      D__;
   /* Instrumentation at eip (i.e., the potential brkpt site) 
    * needs to be updated to invoke the brkpt helper (which in turn
    * checks for the target brkpt context). */
   TrnsTab_Invalidate(locP->eip, 1);
   D__;
}

static void
BrkptUninstall(struct Brkpt *brkP)
{
   ASSERT_COULDBE(current->is_in_code_cache);

   /* Shouldn't invalidate here, since we are still in
    * the helper context. Invalidation will nuke the
    * currently running translation. Instead invalidate
    * on exit from code block by returning TRC_INVAL
    * to the dispatch loop. 
    *
    * i.e., don't do this:
    *
    * ulong eip = ev->ctx.regs.R(eip);
    * TransTab_Invalidate(eip, 1);
    *
    */

   BrkptMMOp(brkP, 0);
   Map_Remove(BrkptGetMap(brkP->kind), taskMap, brkP);
   free(brkP);
   brkP = NULL;
}

static void
BrkptUninstallAll(struct MapStruct *mapP)
{
   struct Brkpt *brkP = NULL;

   MAP_FOR_EACH_ENTRY_SAFE_DO(mapP, taskMap, brkP) {
      ASSERT_KPTR(brkP);
      BrkptUninstall(brkP);
   } END_MAP_FOR_EACH_ENTRY_SAFE;
}

/*
 * Returns notification at execpoint @ep with callback @cbP,
 * or NULL if no such notification.
 */
static struct Brkpt *
BrkptFind(struct MapStruct *mapP, const struct ExecPoint *locP, BkptCbFn cbP)
{
   ASSERT_KPTR(locP);
   ASSERT_KPTR_NULL(cbP);
   ASSERT_KPTR(mapP);

   struct Brkpt *brkP = NULL;

   /* The notify hash is task local, so no need for a lock. */
   MAP_FOR_EACH_KEY_ENTRY_DO(mapP, taskMap, locP->eip, brkP) {
      ASSERT_KPTR(brkP);
      ASSERT(brkP->taskMap.keyLong == locP->eip);

      if (brkP->kind == Bpk_Static) {
         return brkP;
      }

      const struct ExecPoint *cLocP = &brkP->ep;

#if DEBUG
      /* There shouldn't be any stale entries in the notify list.
       * They should've been delivered and removed. */
      if (brkP->kind == Bpk_Dynamic) {
         ASSERT(cLocP->brCnt >= BrCnt_Get());
      }
#endif


      if (ExecPoint_IsMatch(cLocP, locP)) {
         if (cbP && brkP->callback != cbP) {
            continue;
         }

         return brkP;
      }
   } END_MAP_FOR_EACH_KEY_ENTRY;

   return NULL;
}

/*
 * Should not be invoked from tanslated code, since it may
 * perform invalidation of currently running translation.
 */
static int
BrkptInstall(BPKind bpk, const struct ExecPoint *locP, 
      BkptCbFn cbP, void *argP)
{
   ASSERT_KPTR(locP);
   ASSERT_KPTR(cbP);

   struct Brkpt *brkP = NULL;

   DEBUG_MSG(5, 
         "Requested brkpt at EIP 0x%x, ECX 0x%x, brCnt %llu (curr %llu)\n",
         locP->eip, locP->ecx, locP->brCnt, BrCnt_Get());

   ASSERT(cbP);
   ASSERT_MSG(bpk != Bpk_Dynamic || BrCnt_Get() <= locP->brCnt,
         "Requested brkpt can never be hit.");


   if ((brkP = BrkptFind(BrkptGetMap(bpk), locP, cbP))) {
      D__;
      /* It is valid to request multiple notifications at the same execpoint.
       * But each such notification must have a different callback.
       * It looks like that doesn't hold here, and is likely a bug.
       *
       *
       * This shouldn't trigger for preemption notifications because:
       *
       * We avoid asking for multiple preempt callbacks at the same location 
       * by checking the TIF_PREEMPT_PENDING flag. And if there are back-to-back
       * preemptions at same execpoint (which should be rare), 
       * then only one is installed at a time since the first one is 
       * uninstalled before invoking the callback (in which the new one 
       * is presumably installed). 
       */
      extern void PreemptNotificationCallback();

      if (cbP == &PreemptNotificationCallback) {
         ASSERT_MSG(0, "Brkpt for preemption point already "
               "requested.\n");
      }

      ASSERT_MSG(0, "Already requested brkpt at target point, "
            "ignoring.\n");

      return 0;
   }

   ASSERT_NULL_PTR(brkP);
   BrkptInstallWork(bpk, locP, cbP, argP);

   return 1;
}

int
Brkpt_SetAbsolute(BPKind bpKind, const struct ExecPoint *locP, 
      BkptCbFn cbP, void *argP)
{
   ASSERT(Task_IsAddrInUser(locP->eip));

   return BrkptInstall(bpKind, locP, cbP, argP);
}

int
Brkpt_RmAbsolute(BPKind bpKind, const struct ExecPoint *locP)
{
   struct Brkpt *brkP;

   if ((brkP = BrkptFind(BrkptGetMap(bpKind), locP, NULL))) {
      BrkptUninstall(brkP);
      return 1;
   }

   return 0;
}

/*
 * Sets a breakpoint @nrInsnsTillBrkpt instructions from now. 
 *
 * Useful for single-stepping on x86 where it's hard to tell where
 * the next insn might be.
 */
int
Brkpt_SetRelative(int nrInsnsTillBrkpt, BkptCbFn cbP, void *argP)
{
   DEBUG_MSG(2, "nrInsnsTillBrkpt=%d cbP=0x%x argP=0x%x\n",
         nrInsnsTillBrkpt, cbP, argP);

   ASSERT_MSG(current->insnStepCount == 0, 
         "Multiple relative breakpoints not yet supported (or needed)\n");

   current->insnStepCount = nrInsnsTillBrkpt+1;
   current->insnStepCb = cbP;
   current->insnStepArg = argP;

   SYNCH_LOCK(&current->mm->brkptSiteLock);
   current->mm->isRelativeBrkptPending++;
   SYNCH_UNLOCK(&current->mm->brkptSiteLock);

   /* We need to count every single instruction, even those that
    * have already been translated. 
    *
    * XXX: need to invalidate only those block sthat will be executed,
    * rather than all */
   TrnsTab_InvalidateAll();
   D__;

   return 1;
}

/* No need (yet) for Brkpt_RmRelative since relative brkpts remove 
 * themselves upon firing. */

static int
BrkptDoStepDeliverWork()
{
   int isHit = 0;
   int count = current->insnStepCount;

   ASSERT(count >= 0);

   if (count == 0) {
      ASSERT(isHit == 0);
      DEBUG_MSG(5, "No pending step breakpoints on this task.\n");
      goto out;
   }

   if (--current->insnStepCount == 0) {
      DEBUG_MSG(5, "Handling step breakpoint.\n");
      (current->insnStepCb)(current->insnStepArg);
      isHit = 1;

      SYNCH_LOCK(&current->mm->brkptSiteLock);
      current->mm->isRelativeBrkptPending--;
      ASSERT(current->mm->isRelativeBrkptPending >= 0);
      SYNCH_UNLOCK(&current->mm->brkptSiteLock);
   }

out:
   return isHit;
}

static void
BrkptOnHitWork(struct Brkpt *brkP)
{
   DEBUG_MSG(5, "Hit brkpt 0x%x:0x%x:%llu dyn=%d\n", brkP->ep.eip, 
         brkP->ep.ecx, brkP->ep.brCnt, brkP->kind == Bpk_Dynamic);

   BkptCbFn callback = brkP->callback;
   void *arg = brkP->arg;

   if (brkP->kind == Bpk_Dynamic) {
      /* Uninstall before invoking the callback, in case the callback 
       * inserts additional brkps at the current location. */
      BrkptUninstall(brkP);
      D__;
   }

   ASSERT(callback);
   callback(arg);
}

/* 
 * Summary:
 *
 * The thread may have requested or may request multiple
 * notifications at the same exec point. The former could happen
 * if multiple notification consumers want notification at the
 * same place (e.g., signal delivery and race delivery). 
 * The latter could happen if, during logging, we received multiple 
 * signals at the same execution point (I've seen this happen with 
 * preemption sigs when running on top of PIN). 
 *
 * Hence the while loop. We definitely need it because this
 * IRSB may not be invalidated on BrkptInstall and hence may not
 * be executed again.
 *
 * Note that the notification list is sorted by brcnt only.
 * This means that we cannot simply check the first element of the
 * notification list for a context match -- it may not correspond
 * to the the first event in the stream. To guarantee this
 * we would have to keep the notification list sorted by
 * <eip, brCnt, ecx>, and that would work only if we assume
 * that the DF (the auto-increment/decrement) flags is always
 * set or unset, which is not the case.
 */
static int
BrkptDoDeliverWork(struct MapStruct *mapP, struct ExecPoint *locP) 
{
   int isHit = 0;
   const int isBrkptPendingOnCurrent = Map_GetSize(mapP);

   if (!isBrkptPendingOnCurrent) {
      ASSERT(isHit == 0);

      DEBUG_MSG(5, "No pending breakpoints on map for this task.\n");
      goto out;
   }

   struct Brkpt *brkP = NULL;

   MAP_FOR_EACH_KEY_ENTRY_DO(mapP, taskMap, locP->eip, brkP) {
      ASSERT_KPTR(brkP);
      ASSERT(brkP->taskMap.keyLong == locP->eip);

      const struct ExecPoint *brkLocP = &brkP->ep;

      if (brkP->kind == Bpk_Dynamic) {
         /* There shouldn't be any stale entries in the notify list.
          * They should've been delivered and removed. */
         ASSERT(brkLocP->brCnt >= BrCnt_Get());

         /* Check that we didn't miss a dynamic deliver point. */
         struct Brkpt *dyBrkP = Brkpt_PeekFirst();
         ASSERT(dyBrkP->kind == Bpk_Dynamic);
         if (dyBrkP && (Brkpt_GetBrCnt(brkP) < BrCnt_Get())) {
#if DEBUG
            BrkptPrintPending();
#endif
            ASSERT_MSG(0, "We missed the brkpt delivery point.\n");
         }

         if (ExecPoint_IsMatch(brkLocP, locP)) {
            BrkptOnHitWork(brkP);
            isHit = 1;
         }
      } else if (brkP->kind == Bpk_Static) {
         BrkptOnHitWork(brkP);
         isHit = 1;
      } else {
         ASSERT(0);
      }
   } END_MAP_FOR_EACH_KEY_ENTRY;

out:
   return isHit;
}


static int
Brkpt_DirtyHelper_Check(TaskRegs *vexP, HWord pc)
{
   int isHit = 0;
   struct ExecPoint loc = { .eip = pc, .ecx = vexP->guest_ECX,
                                .brCnt = BrCnt_Get() };

   /* guest_EIP may not have been updated yet because this helper
    * is invoked before the PUT of guest_EIP. So we manually
    * update it so that any callbacks that rely on it being
    * updated (e.g., the preemption callback) see the right value. */
   ASSERT(pc == vexP->guest_EIP || pc != vexP->guest_EIP);
   vexP->guest_EIP = pc;

   isHit = BrkptDoDeliverWork(current->dyBrkptMap, &loc);
   isHit |= BrkptDoDeliverWork(current->stBrkptMap, &loc);
   isHit |= BrkptDoStepDeliverWork();

   if (isHit) {
      /* XXX: No need to invalidate if some other thread still has
       * notification pending at this site, or if there are multiple brkpts
       * at the site.
       *
       * For now, assume that isHit == 1 ==> curr IRSB is invalid. 
       * This is conservative, since there may be another notification
       * at the same ip that is yet to be delviered. But it's safe,
       * because the site will the reinstrumented in the subsequent
       * translation of this IRSB. */
      DEBUG_MSG(5, "Brkpt(s) handled.\n");

      vexP->guest_TISTART = pc; 
      vexP->guest_TILEN = 1;
   } else {
      DEBUG_MSG(5, "No brkpts handled.\n");

      /* This should happen only if some other thread is waiting on 
       * a brkpt. */
      //ASSERT(current->mm->users > 1);
   }

   return isHit;
}

static void
BrkptInstrCheck(IRSB *bbOut, const Addr64 pc)
{
   int dirtyTmp, guardTmp;
   IRDirty *dirty;
   IRStmt *exitSt, *narrowSt;

   /* VEX does not allow dirty return values to have type Ity_I1,
    * so we must put the return value in a 32-bit var and then
    * narrow it to 1 bit for the exit guard. */
   dirtyTmp = newIRTemp(bbOut->tyenv, Ity_I32);
   dirty = MACRO_unsafeIRDirty_1_N(dirtyTmp, 0, 
         Brkpt_DirtyHelper_Check,
         mkIRExprVec_1(
            mkIRExpr_HWord(pc))
         );

   dirty->needsBBP = True;
#if 0
   dirty->nFxState = 3;
   dirty->fxState[0].fx = Ifx_Modify;
   dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_EIP);
   dirty->fxState[0].size = sizeof(ulong);
   dirty->fxState[1].fx = Ifx_Read;
   dirty->fxState[1].offset = offsetof(VexGuestX86State, guest_ECX);
   dirty->fxState[1].size = sizeof(ulong);
   dirty->fxState[2].fx = Ifx_Write;
   dirty->fxState[2].offset = offsetof(VexGuestX86State, guest_TISTART);
   dirty->fxState[2].size = offsetof(VexGuestX86State, guest_TILEN) -
      offsetof(VexGuestX86State, guest_TISTART);
#else
   /* Assume that all of VEX state may be modified --- this may be the
    * case when formgen backtracks (i.e., restores a checkpoint). */
   dirty->nFxState = 1;
   dirty->fxState[0].fx = Ifx_Modify;
   dirty->fxState[0].offset = 0;
   dirty->fxState[0].size = sizeof(VexGuestX86State);
#endif

   addStmtToIRSB(bbOut, IRStmt_Dirty(dirty));

   /* It's possible that the notification fired and the invoked
    * notification callback installed additional notifications.
    * Those additional notifications in turn may install new
    * notification checks (i.e., helper calls) at instructions 
    * in the current IRSB. This could happen, if during logging
    * we got back to back preemptions in the same IRSB. 
    * If we want those checks to be executed,
    * then we must fetch a freshly-instrumented copy of the IRSB
    * before continuting.
    *
    * To obtain a fresh copy, we need only enter the dispatch 
    * with nextBblAddr set to the current instruction. The dispath
    * will see that the corresponding IRSB is invalid (if indeed
    * these are new notifications in the IRSB) and hence
    * will get a fresh copy with checks instrumented. 
    *
    * Note that this is only necessary for preemption notifications,
    * since only they will install new notifications from within
    * their callback. Racing read notification callbacks don't
    * install additional notifications. In fact, all racing read
    * notifications are installed at the very beginning of execution.
    *
    * We exit to the CURRENT instruction (kind of like jumping to
    * the same instruction). For this to work:
    *    o We can't unconditionally exit; we should exit only
    *    if the curr IRSB in invalid (i.e., a notification
    *    was handled and there are no pending notification at ip).
    *    Otherwise, we'll enter a endless loop.
    *
    *    o Any helper calls before the invalidation check
    *    must be idempotent, or there should be no such helper calls.
    *    
    *    XXX: for now, we exit if the notification check helper
    *    installed any callbacks (since one of them may be to the
    *    current IRSB). Later, we'll improve this by exiting only if the
    *    current IRSB was invalidated.
    *
    */


   /* VEX doesn't like non Ity_I1 types for exit guards, so we
    * must narrow. */
   guardTmp = newIRTemp(bbOut->tyenv, Ity_I1);
   narrowSt = IRStmt_WrTmp(guardTmp, 
         IRExpr_Unop(Iop_32to1, IRExpr_RdTmp(dirtyTmp)));
   addStmtToIRSB(bbOut, narrowSt);

   /* Must invalidate translation after notification has been handled.
    * We may no longer need the nofitication check at the delivery ip. */
   exitSt = IRStmt_Exit(IRExpr_RdTmp(guardTmp), Ijk_TInval,
         IRConst_U32(pc));
   addStmtToIRSB(bbOut, exitSt);

#if 0
   /* Should we go somewhere if the brkpt wasn't hit? */
   if (brkP->nonHitJumpIP) {
      IRStmt *exitSt2 = IRStmt_Exit(IRExpr_Const(IRConst_U1(1)), Ijk_Boring,
            IRConst_U32(brkP->nonHitJumpIP));
      addStmtToIRSB(bbOut, exitSt2);
   }
#endif
}


/* 
 * Summary:
 * The main challenge here is that our context check needs
 * an accurate EIP in order to check if the current
 * instruction is a notification delivery site.
 * But VEX doesn't update the EIP at IMarks. Instead it does
 * so with an explcit PUT to the guest_EIP after the IMark
 * for all instruction except the very first in the IRSB.
 *
 * One option is to instrument the Notification helper
 * call after the first PUT of the guest_EIP (if there is one).
 * But this assumes that there is no IR between the
 * IMark and PUT of the eip -- a dangerous assumption
 * to make given that the IRSB may have been processed
 * by other modules before coming to us. For example, the
 * race detection access trace module inserts a helper call
 * after every IMark that will go in between the IMark guest_EIP
 * and subsequent PUT.
 *
 * The other option is to not have the Notification helper
 * rely on guest_EIP and instead pass it the updated EIP 
 * (obtained from the IMark) as an argument. This is the
 * option we choose.
 */
static IRSB*
BrkptInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   int i;
   IRSB *bbOut;
   ulong currInsAddr = 0, currInsLen = 0;

   /* XXX: If there are no active notification sites, then no need
    * to instrument. But if you do this check, make sure you
    * hold the notification site map lock. */

   ASSERT(bbIn->stmts_used > 0);

   bbOut = emptyIRSB();
   bbOut->tyenv = deepCopyIRTypeEnv(bbIn->tyenv);
   bbOut->jumpkind = bbIn->jumpkind;
   bbOut->next = deepCopyIRExpr(bbIn->next);

   for (i = 0; i < bbIn->stmts_used; i++) {
      IRStmt *st = bbIn->stmts[i];
      if (st->tag == Ist_IMark) {
         currInsAddr = st->Ist.IMark.addr;
         currInsLen = st->Ist.IMark.len;
      }

      if (!currInsAddr) {
         ASSERT(!currInsLen);
         /* Skip instrumentation of IR preamble if it exists 
          * (e.g., self-check preamble if self-checking is turned on). */
         addStmtToIRSB(bbOut, st);
         continue;
      }

      ASSERT(currInsAddr);
      ASSERT(currInsLen);

      addStmtToIRSB(bbOut, st);


      /* Instrument notification check helpers only if this IRSB contains
       * a notification site. */
      if (st->tag == Ist_IMark) {
         int shouldInstrInsn = 0;

         SYNCH_LOCK(&current->mm->brkptSiteLock);

#if DEBUG
         BrkptPrintPendingAll();
#endif

         if (current->mm->isRelativeBrkptPending) {
            /* For relative brkpts, we need to check at every instruction. */
            shouldInstrInsn = 1;
         }

         if (!shouldInstrInsn) {
            struct Brkpt *brkP = NULL;

            /* For absolute brkpts, we need only check at the brkpt IP. */
            MAP_FOR_EACH_KEY_ENTRY_DO(current->mm->brkptSiteMap, mmMap, currInsAddr, 
                  brkP) {
               ASSERT(brkP->mmMap.keyLong == currInsAddr);

               shouldInstrInsn = 1;
               /* One check for all brkpts should suffice. */
               break;
            } END_MAP_FOR_EACH_KEY_ENTRY;
         }

         if (shouldInstrInsn) {
            DEBUG_MSG(5, "Instrumenting brkpt check at EIP 0x%x\n", 
                  currInsAddr);
            BrkptInstrCheck(bbOut, currInsAddr);
         }

         SYNCH_UNLOCK(&current->mm->brkptSiteLock);
      }

   }

   return bbOut;
}



static void
BrkptSelfExit()
{
#if DEBUG
   if (Brkpt_PeekFirst()) {
      /* A brkpt shouldn't be installed unless we know for
       * certain that it will be delivered. Hence all brkpts
       * should've fired by task exit and this list should
       * be empty. */

      BrkptPrintPending();
      ASSERT(0);
   }
#endif

   struct Brkpt *brkP = NULL;

   ASSERT(Map_GetSize(current->dyBrkptMap) == 0);
   ASSERT_COULDBE(Map_GetSize(current->stBrkptMap) == 0);

   BrkptUninstallAll(current->dyBrkptMap);
   BrkptUninstallAll(current->stBrkptMap);
   Map_Destroy(current->dyBrkptMap, taskMap, brkP);
   ASSERT(Map_GetSize(current->stBrkptMap) == 0);
   Map_Destroy(current->stBrkptMap, taskMap, brkP);

   ASSERT_TASKLIST_LOCKED();
   ASSERT(current->mm);
   ASSERT(current->mm->users > 0);
   ASSERT(current->mm->brkptSiteMap);
   if (current->mm->users == 1) {
      // Okay, this is the last exiting task, free the address space
      // brkpt map
#if DEBUG
      ASSERT(Map_GetSize(current->mm->brkptSiteMap) == 0);
#endif
      ASSERT_KPTR(current->mm->brkptSiteMap);
      Map_Destroy(current->mm->brkptSiteMap, mmMap, brkP);
      current->mm->brkptSiteMap = NULL;
   } else {
      // Others are still using the brkpt site map!
   }
}

static void
BrkptInit(struct Task *tsk)
{
   /* Each task gets its own notification hash. */
   DEBUG_MSG(5, "Initializing the notification hash.\n");

   tsk->dyBrkptMap = Map_Create(0);
   tsk->stBrkptMap = Map_Create(0);

   tsk->insnStepCount = 0;
   tsk->insnStepCb = NULL;
   tsk->insnStepArg = NULL;
}

static void 
BrkptFork(struct Task *tsk)
{
   /* Doesn't make sense for tsk to inherit notifications. */

   BrkptInit(tsk);

   if (!Task_IsThread(tsk)) {
      tsk->mm->brkptSiteMap = Map_Create(0);
      Synch_LockInit(&tsk->mm->brkptSiteLock);
      tsk->mm->isRelativeBrkptPending = 0;
   }
}

static struct Module mod = {
   .name          = "Breakpoints",
   .modeFlags     = 0xFFFFFFFF,
   .onStartFn     = NULL,
   .onTermFn      = BrkptSelfExit,
   .onForkFn      = BrkptFork,
   .onExitFn      = NULL,
   .instrFn       = BrkptInstrument,
   /* Must be last to ensure that breakpoint checks are the
    * first helpers after the IRMark, in case the instruction
    * has to be restarted. */
   .order         = MODULE_ORDER_LAST
};

static int
Brkpt_Init()
{
   /* We need may need brkpts during logging if a tracer (e.g., GDB)
    * attaches. */
   Module_Register(&mod);
   BrkptFork(current);

   return 0;
}

BT_INITCALL(Brkpt_Init);
