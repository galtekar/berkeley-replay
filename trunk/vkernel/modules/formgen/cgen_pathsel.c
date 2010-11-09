#include "vkernel/public.h"
#include "private.h"

/*
 * ----- Summary -----
 *
 *  The path selector tells us what path to take when, during formula
 *  generation, there are multiple possible paths we may follow to
 *  get from the fork point to a given join point in the CFG.
 *  Specifically, for a given branch (invocation of onBranch()), the
 *  selector will tell you where you need to go in order to explore one
 *  of its paths.
 *
 *  We've implemented several types of path selectors:
 *
 *  o The "input" path selector uses the path suggested by the concrete
 *  values of the current execution. This won't take you to the join
 *  point if the concrete values don't lead you there. But it will when
 *  we know all the inputs. So this is useful for testing in log or
 *  replay mode (especially in conjunction with formgen's force-origin
 *  option).
 *
 *  o The "recorded" path selector tells us to use the path recorded during
 *  the original run, assuming it was recorded.
 *
 *  o The "feasible" path selector tells us to explore all feasible paths
 *  to the specified join point.
 */



#if 0

/*
 * Returns 1 iff done exploring all paths.
 */
static const int NR_REPEATS = 1;

static void
InputOnFork(struct PathSelector *psP, ulong joinIP)
{
}

static int
InputOnJoin(struct PathSelector *psP)
{
   psP->pathId++;
   psP->brId = 0;

   if (psP->pathId >= NR_REPEATS) {
      psP->pathId = 0;
      return 1;
   } else {
      return 0;
   }
}

static PathSelCmd
InputGetNextBranch(struct PathSelector *psP, const PsBranchKind pbk, 
      const ulong dstRes, const ulong fallRes, ulong *selResP)
{
   ASSERT_KPTR(selResP);


   *selResP = dstRes;

   ASSERT(psP->pathId < NR_REPEATS);

   return Pck_Cont;
}

static void
InputAdvanceBranch(struct PathSelector *psP, ulong res)
{
   psP->brId++;
}

void
InputOnTaskEnter(struct PathSelector *psP)
{
}

void
InputOnTaskExit(struct PathSelector *psP)
{
}

int
InputOnInit(struct PathSelector *psP)
{
   psP->onTaskEnter(psP);

   if (!VCPU_IsReplaying()) {
      FATAL("InputPathSelector is usable only in replay mode.\n");
   }

//#error "XXX: abort if replay mode and not value-deterministic run"

   return 0;
}

static struct PathSelector psInput = {
   .pathId = 0,
   .brId = 0,
   .onFork =         &InputOnFork,
   .onJoin =         &InputOnJoin, 
   .getNextBranch =  &InputGetNextBranch, 
   .advanceBranch =  &InputAdvanceBranch,
   .onTaskEnter  =   &InputOnTaskEnter,
   .onTaskExit  =    &InputOnTaskExit,
   .onInit =         &InputOnInit,
};
#endif

#if 1
static void
RecOnFork(struct PathSelector *psP, const ulong joinIP)
{
}

static int
RecOnJoin(struct PathSelector *psP)
{
   psP->pathId++;
   psP->brId = -1;

   if (psP->pathId == 1) {
      psP->pathId = 0;

      return 1;
   } else {
      return 0;
   }
}

static void
RecAdvanceBranch(struct PathSelector *psP, const PsBranchKind pbk, 
                 const ulong dstRes, const ulong retIP)
{
   psP->brId++;

   struct BPred *bP = current->bt.brPredP;
   ulong currIP = curr_regs->R(eip);

   ASSERT_KPTR(bP);

   switch (pbk) {
   case Pbk_Cond:
      ASSERT(dstRes == 1 || dstRes == 0);
      psP->selTarget = BrTrace_DoCond(current->bt.brPredP, currIP, dstRes);
      break;
   case Pbk_DirectCall:
      BrTrace_DoDirectCall(bP, currIP, retIP);
      psP->selTarget = dstRes;
      break;
   case Pbk_DirectJump:
      ASSERT_UNIMPLEMENTED(0);
      break;
   case Pbk_IndJump:
      psP->selTarget = BrTrace_DoIndirectJump(bP, currIP, dstRes);
      break;
   case Pbk_IndCall:
      psP->selTarget = BrTrace_DoIndirectCall(bP, currIP, dstRes, retIP);
      break;
   case Pbk_Ret:
      psP->selTarget = BrTrace_DoRet(bP, currIP, dstRes);
      break;
   default:
      NOTREACHED();
      break;
   };
}

static PathSelCmd
RecGetBranchTarget(struct PathSelector *psP, ulong *targetP)
{
   ASSERT_KPTR(targetP);

   *targetP = psP->selTarget;
   
   return Pck_Cont;
}


void
RecOnTaskEnter(struct PathSelector *psP)
{
   current->bt.brPredP = BPred_Create();
}

void
RecOnTaskExit(struct PathSelector *psP)
{
   BPred_Destroy(current->bt.brPredP);
   current->bt.brPredP = NULL;
}

int
RecOnInit(struct PathSelector *psP)
{
   if (!VCPU_IsReplaying()) {
      FATAL("Must be in replay mode to use this.\n");
   }

#if 0
#error "XXX: duplicates code in check mod"
   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpu = VCPU_Ptr(i); 

      Log_Setup(&vcpu->checkLog, "check", vcpu,
            checkLogLocalRotationGeneration, optWantsLogging, 0);

      vcpu->checkIsLogging = 0;
   }

   /* --- We need to know what properties were logged for replay --- */
   CHECK_DO_WITH_LOG_ENTRY(CheckHeader) {
      recordedProperties = entryp->properties;
   } END_WITH_LOG_ENTRY(0);

   if (!(recordedProperties & CHK_OPT_BRANCHES)) {
      FATAL("No branches were recorded.\n");
   }
#else
   int propFlags = 0;
   if (Check_InitLog(&propFlags, 0)) {
      /* XXX: handle error */
      ASSERT_UNIMPLEMENTED(0);
   }

   ASSERT_UNIMPLEMENTED(propFlags & CHK_OPT_BRANCHES);
   ASSERT_UNIMPLEMENTED(!(propFlags & ~CHK_OPT_BRANCHES));

#endif

   return 0;
}


static struct PathSelector psRec = {
   .pathId = 0,
   .brId = -1,
   .selTarget = 0,
   .onFork =            &RecOnFork,
   .onJoin =            &RecOnJoin, 
   .getBranchTarget =   &RecGetBranchTarget,
   .advanceBranch =     &RecAdvanceBranch,
   .onTaskEnter  =      &RecOnTaskEnter,
   .onTaskExit  =       &RecOnTaskExit,
   .onInit =            &RecOnInit,
};
#endif

static void
ValueDetAdvanceBranch(struct PathSelector *psP, const PsBranchKind pbk, 
                 const ulong dstRes, const ulong retIP)
{
   psP->brId++;

   psP->selTarget = dstRes;
}

static PathSelCmd
ValueDetGetBranchTarget(struct PathSelector *psP, ulong *targetP)
{
   ASSERT_KPTR(targetP);

   *targetP = psP->selTarget;
   
   return Pck_Cont;
}

static struct PathSelector psValueDet = {
   .pathId = 0,
   .brId = -1,
   .selTarget = 0,
   .onFork =            &RecOnFork,
   .onJoin =            &RecOnJoin, 
   .getBranchTarget =   &ValueDetGetBranchTarget,
   .advanceBranch =     &ValueDetAdvanceBranch,
   .onTaskEnter  =      NULL,
   .onTaskExit  =       NULL,
   .onInit =            NULL,
};


#if 0
static void
FeasibleOnCFGFork(struct PathSelector *psP, ulong joinIP)
{
   nodeP = CFG_FindFeasibleSubCFG(forkIP, joinIP);
   Stack_Push(psP->stackP, nodeP);
}

static void
FeasibleOnCFGJoin(struct PathSelector *psP)
{
   Stack_Pop(psP->stackP, nP);

   ASSERT(nP->addr == joinIP);
}

static PathSelCmd
FeasibleOnBranch(struct PathSelector *psP, ulong currIP, ulong *selResP)
{
   int nrSucc = 0;

   Stack_Pop(psP->stackP, nP);
   ASSERT(nP->addr == currIP);

   list_for_each_successor(succP, nP) {
      Stack_Push(psP->stackP, succP);
      nrSucc++;
   }

   ASSERT_KPTR(succP);
   *selResP = succP->addr;

   return nrSucc > 1 ? Pck_Fork : Pck_Cont;
}

static void
FeasibleOnNonBranch(struct PathSelector *psP, ulong currIP)
{
   Stack_Pop(psP->stackP, nP);
   ASSERT(nP->addr == currIP);
}

struct PathSelector psFeasible = {
   .onCFGFork = &FeasibleOnCFGFork,
   .onCondBranch = &FeasibleOnCondBranch,
   .getBranchOutcome = &FeasibleGetBranchOutcome,
};
#endif

struct PathSelector *cgPsP = NULL;

void
cgPsel_Init()
{
   if (env.is_value_det) {
      cgPsP = &psValueDet;
   } else {
      cgPsP = &psRec;
   }

   ASSERT_KPTR(cgPsP);
   if (cgPsP->onInit) {
      cgPsP->onInit(cgPsP);
   }

   // For the init task
   if (cgPsP->onTaskEnter) {
      cgPsP->onTaskEnter(cgPsP);
   }

}

void
cgPsel_OnTaskStart()
{
   ASSERT_KPTR(cgPsP);
   if (cgPsP->onTaskEnter) {
      cgPsP->onTaskEnter(cgPsP);
   }
}

void
cgPsel_OnTaskTerm()
{
   ASSERT_KPTR(cgPsP);

   if (cgPsP->onTaskExit) {
      cgPsP->onTaskExit(cgPsP);
   }
}
