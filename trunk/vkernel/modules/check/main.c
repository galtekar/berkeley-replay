#include "vkernel/public.h"
#include "private.h"

#include <getopt.h>
   
static int optWantsLogging = -1;

static int optChkProps = 0;

static int checksEnabled = 0;


void
Check_DoRegs(TaskRegs *regs)
{
#define DO_OPS() \
         OP(eax); \
         OP(ecx); \
         OP(edx); \
         OP(ebx); \
         OP(esp); \
         OP(ebp); \
         OP(esi); \
         OP(edi); \
         OP(cs); \
         OP(ds); \
         OP(es); \
         OP(fs); \
         OP(gs); \
         OP(ss); \
         EFLAGS_OP(eflags);
         

   //DEBUG_MSG(0, "EIP: 0x%x\n", regs->R(eip));

#define OP(r) entryp->r = regs->R(r)

/* EFLAGS[RF] flag gets set by processor after the single-step trap
 * (or debug exception in general), but we won't get such exceptions
 * while in BT mode. So we don't record it to avoid false-positive
 * divergence errors. */
#define EFLAGS_OP(r) { \
   entryp->r = (regs->R(r) & ~(X86_EFLAGS_RF)); \
   if (Task_TestFlag(current, TIF_BT_MODE)) { \
      entryp->dep2 = regs->R(dep2); \
      entryp->ndep = regs->R(ndep); \
   } \
}

   if (VCPU_IsLogging()) {
      CHECK_DO_WITH_LOG_ENTRY(RegChk) {
         DO_OPS();
      } END_WITH_LOG_ENTRY(0);

   } else if (VCPU_IsReplaying()) {
#undef OP
#undef EFLAGS_OP
#define OP(r) \
      res &= (regs->R(r) == entryp->r); \
      if (!res) { \
         FATAL("Divergence @ 0x%x.%llu on " #r ": log=0x%x rep=0x%x\n", \
            regs->R(eip), BrCnt_Get(), entryp->r, regs->R(r)); \
      }

#define EFLAGS_OP(r) \
      { \
      ulong compEflags = regs->R(r) & ~(X86_EFLAGS_RF); \
      /*LibVEX_GuestX86_get_eflags(regs); */ \
      res &= (compEflags == entryp->r); \
      if (Task_TestFlag(current, TIF_BT_MODE)) { \
         res &= (entryp->dep2 == regs->R(dep2)); \
         res &= (entryp->ndep == regs->R(ndep)); \
      } \
      if (!res) { \
         FATAL("Divergence @ 0x%x.%llu on eflags: log=0x%x:0x%x:0x%x rep=0x%x:0x%x:0x%x\n", \
            regs->R(eip), BrCnt_Get(), \
            entryp->eflags, entryp->dep2, entryp->ndep,  \
            compEflags, regs->R(dep2), regs->R(ndep)); \
      } \
      }


      int res = 1;

      CHECK_DO_WITH_LOG_ENTRY(RegChk) {
         DO_OPS();
      } END_WITH_LOG_ENTRY(0);

      //ASSERT(res);
   }

   /* The HW br counter we use on P4 increments by 2 for conditional jumps,
    * but by 1 for everything else. The software counter emulates
    * the hardware counter. */
#if DEBUG
   ASSERT(BrCnt_Get() - current->lastBrCnt <= 2);
   current->lastBrCnt = BrCnt_Get();
#endif
}


#if 0
static int
ProcessSsCheck(config_setting_t *checkParmGroup)
{
   config_setting_t *m;

   if ((m = config_setting_get_member(checkParmGroup, "registers"))) {
      if (config_setting_get_bool(m)) {
         ssCheck.flags |= CHECK_REGS;
      } else {
         ssCheck.flags &= ~(CHECK_REGS);
      }
   }

   return ssCheck.flags != 0;
}

static int
ProcessBtCheck(config_setting_t *btCheckGroup)
{
   config_setting_t *m;

   VCPU_ClearModeFlag(VCPU_MODE_SINGLESTEP);

   if ((m = config_setting_get_member(btCheckGroup, "registers"))) {
      if (config_setting_get_bool(m)) {
         btCheck.flags |= CHECK_REGS;
      } else {
         btCheck.flags &= ~(CHECK_REGS);
      }
   }

   if ((m = config_setting_get_member(btCheckGroup, "dereferences"))) {
      if (config_setting_get_bool(m)) {
         btCheck.flags |= CHECK_DEREF;
      } else {
         btCheck.flags &= ~(CHECK_DEREF);
      }
   }

   if ((m = config_setting_get_member(btCheckGroup, "branches"))) {
      if (config_setting_get_bool(m)) {
         btCheck.flags |= CHECK_BRANCHES;
      } else {
         btCheck.flags &= ~(CHECK_BRANCHES);
      }
   }

   /* XXX: should be in the check group -- applies to SS and BT checks */
#if 0
   {
      int numCheckSegs = 0;
      if ((m = config_setting_get_member(btCheckGroup, "segments")) &&
            (m = config_setting_get_member(m, "by_task_id"))) {

         int i = 0;

         while (config_setting_get_elem(m, i)) {
            numCheckSegs++;
            i++;
         }
      }
   }
#endif

   return btCheck.flags != 0;
}
#endif

#if 0
/*
 * Invoked right before resuming to user-mode. If we are indeed in
 * single-step mode, then we need to record the register state after
 * the syscall, since we won't get a trap (or if we're in BT a
 * callout) until we execute the next user-mode instruction. 
 */
void
Check_HandleSingleStep()
{
   if ((VCPU_GetMode() & VCPU_MODE_SINGLESTEP) &&
         /* The BT-mode single step check happens in the TC, so
          * so we needn't regchk here if we are indeed about to
          * execute in the TC. */
         (!Task_TestFlag(current, TIF_BT_MODE)) &&
         (ssCheck.flags & CHECK_REGS)) {

      /* Don't regchk on preemptions -- just after each insn or
       * syscall related insn. */
      if (Task_TestFlag(current, TIF_SINGLE_STEP | TIF_CALL_MASK)) {
         /* Theoretically, we should be able to regchk every 
          * REP instruction iteration. But in practice, the CPU may
          * not generate SS trap after every iteration -- this is
          * the case on my Penitum D: family 15, model 4, stepping 4.
          */
         if (curr_regs->R(eip) != current->ssLastEip) {
            Check_DoRegs(curr_regs);
            current->ssLastEip = curr_regs->R(eip);
         }
      }
   }
}
#endif


int 
Check_IsLogging()
{
   ASSERT(current->id > 0);

   return Task_GetVCPU(current)->checkIsLogging;
}

int 
Check_IsReplaying()
{
   return !Check_IsLogging();
}

/* Must NOT be in the SHAREDAREA -- we need this to be local
 * to the address space, since log mappings are per-address space
 * as well. */
static uint checkLogLocalRotationGeneration[MAX_NR_VCPU] = { 0 };

int
Check_InitLog(int *propFlagsP, const int isLogging)
{
   int i;
   /* XXX: loop should be in Log_Setup -- we need a Linux-like
    * per-vcpu macro. */
   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpu = VCPU_Ptr(i); 

      Log_Setup(&vcpu->checkLog, "check", vcpu,
            checkLogLocalRotationGeneration, isLogging, 0);

      vcpu->checkIsLogging = isLogging;
   }

   /* --- We need to know what properties were logged for replay --- */
   if (isLogging) {
      CHECK_DO_WITH_LOG_ENTRY(CheckHeader) {
         entryp->properties = *propFlagsP;
      } END_WITH_LOG_ENTRY(0);
   } else {
      CHECK_DO_WITH_LOG_ENTRY(CheckHeader) {
         *propFlagsP = entryp->properties;
      } END_WITH_LOG_ENTRY(0);
   }

   return 0;
}

static int
CheckInit()
{
   if (checksEnabled) {

      if (optWantsLogging == -1) {
         optWantsLogging = VCPU_IsLogging();
      } 

      ASSERT(optWantsLogging == 0 || optWantsLogging == 1);

#if 0
      /* XXX: loop should be in Log_Setup -- we need a Linux-like
       * per-vcpu macro. */
      for (i = 0; i < NR_VCPU; i++) {
         struct VCPU *vcpu = VCPU_Ptr(i); 

         Log_Setup(&vcpu->checkLog, "check", vcpu,
               checkLogLocalRotationGeneration, optWantsLogging, 0);

         vcpu->checkIsLogging = optWantsLogging;
      }

      /* --- We need to know what properties were logged for replay --- */
      if (optWantsLogging) {
         CHECK_DO_WITH_LOG_ENTRY(CheckHeader) {
            entryp->properties = optChkProps;
         } END_WITH_LOG_ENTRY(0);
      } else {
         CHECK_DO_WITH_LOG_ENTRY(CheckHeader) {
            optChkProps = entryp->properties;
         } END_WITH_LOG_ENTRY(0);
      }
#endif

      if (Check_InitLog(&optChkProps, optWantsLogging)) {
         ASSERT_UNIMPLEMENTED(0);
      }

      if (optChkProps & CHK_OPT_BRANCHES) {
         BrChk_Init();
      }
      if (optChkProps & CHK_OPT_REGS) {
         RegChk_Init();
      }
      if (optChkProps & CHK_OPT_DEREFS) {
         DerefChk_Init();
      }
   }

   return 0;
}

BT_INITCALL(CheckInit);

enum { Opt_Props };

enum { BRANCHES_OPT, REGS_OPT, DEREFS_OPT };
static const char *const subOptTokens[] = {
   [BRANCHES_OPT] = "branches",
   [REGS_OPT] = "regs",
   [DEREFS_OPT] = "derefs",
   NULL
};


static int
ParseOpt(int opt, const char *arg)
{
   int err = 0;

   switch (opt) {
   case Opt_Props:
      {
         int subOpt;
         char *saveP = NULL;
         char argBuf[256];
         strncpy(argBuf, arg, sizeof(argBuf));

         while ((subOpt = MiscOps_GetNextSubOpt(argBuf, &saveP, 
                     subOptTokens)) != -1) {
            //eprintf("subOpt=%d\n", subOpt);
            switch (subOpt) {
            case BRANCHES_OPT:
               optChkProps |= CHK_OPT_BRANCHES;
               break;
            case REGS_OPT:
               optChkProps |= CHK_OPT_REGS;
               break;
            case DEREFS_OPT:
               optChkProps |= CHK_OPT_DEREFS;
               break;
            case '?':
               eprintf("invalid check property\n");
               err = -1;
               break;
            default:
               ASSERT(0);
               break;
            }
         }
      }

      if (!optChkProps) {
         optChkProps |= CHK_OPT_BRANCHES;
      }
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   };

   return err;
}

static int
ParseRecFini()
{
   checksEnabled = 1;
   optWantsLogging = 1;

   return 0;
}

static int
ParseCheckFini()
{
   checksEnabled = 1;
   optWantsLogging = 0;

   return 0;
}

static struct ModOpt optA[] = {
   [Opt_Props] = { "DRec.Properties", ParseOpt, Opk_Str, "branches",
      "Check that runtime properties are deterministic.\n"
      "Supported properties are: branches, regs, derefs" },

   { "", NULL, Opk_Bool, "", "" },
};

extern struct ModDesc MODULE_VAR(Base);

static struct ModDesc *depA[] = { &MODULE_VAR(Base), NULL };
static struct ModDesc *confA[] = { NULL };

MODULE_BASIC(
      DRec,
      "Records runtime state", 
      depA,
      confA,
      optA,
      &ParseRecFini);

MODULE_BASIC(
      DCheck,
      "Checks runtime state for determinism", 
      depA,
      confA,
      optA,
      &ParseCheckFini);
