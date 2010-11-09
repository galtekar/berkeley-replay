#pragma once

#include "vkernel/public.h"


extern void
Task_InstallDescInGDT(struct Task *tsk, struct LinuxSegmentDesc *descP);

/* All signals except those that Linux forbids us from blocking. */
#define _BLOCKABLE (~SIG_KERNEL_ONLY_MASK)

/* All signals with the exception of crashes and those forbidden from 
 * blocking by Linux. */
#define _ALWAYS_UNBLOCKED \
      (SIG_KERNEL_CRASH_MASK | SIG_KERNEL_ONLY_MASK | \
       M(SIGTRAP) | M(SIG_RESERVED_USER) )

#define GDB_SIGNALS  (M(SIGINT) | M(SIGTRAP))

#if 0
/* All the signals that we need to block while we're draining signals
 * from Linux in a sigsuspend() -- we don't want to get any user-mode
 * preemption signals while draning in vkernel, since we don't support
 * in-vkernel preemption. */
#define  SIG_DRAIN_MASK ((M(SIG_RESERVED_USER)) & _BLOCKABLE)
#endif


struct LinuxSignal
{
   int signr;
   siginfo_t si;
   /* No need since we permit non-preempt sigs only in vkernel
    * drainage points. 
    *
    * ucontext_t uc;
    */

   struct ListHead list;
};

extern void          Signal_SelfInit();
extern void          Signal_RecalcSigPending(struct Task *t);
extern ASMLINKAGE void Signal_DoNotifyResume();
extern void          Signal_NotifyParent(struct Task *tsk, int sig);
extern void          Signal_ZapOtherThreads(struct Task *p);
extern void          Signal_FlushSigQueue(struct SigPending *queue);
extern void          Signal_FlushSignalHandlers(struct Task *t, 
                        int forceDefault);
extern void          Signal_EntryFromVK(siginfo_t *si, 
                        ucontext_t *uc);
extern int           Signal_EntryFromCodeCache(siginfo_t *siP);
extern void          Signal_SendFaultSig(siginfo_t *si);
extern void          Signal_WakeUp(struct Task *t, int resume);
extern void
Signal_Queue(const siginfo_t *si);



extern void ASMLINKAGE    Preempt_ScheduleUpcoming();

extern void BrCnt_Fork(struct Task *);

#ifndef DEBUG
/* TF flag support turned on temporarily to help with switch to VEX-3.5.
 * This needs to be turned back on. */
#define REQ_TFFLAG
#endif

/* 
 * Exec.
 */
extern int  Exec_DoExecve(const char *filename, char __user * __user *argv,
                        char __user * __user *envp);
extern struct FileStruct * Exec_Open(const char *filename);
extern int  Exec_SearchBinaryHandler(struct LinuxBinPrm *bprm, TaskRegs *regs);
extern void Exec_RemoveArgZero(struct LinuxBinPrm *bprm);
extern int  Exec_CopyStringsKernel(int argc, char ** argv, 
                 struct LinuxBinPrm *bprm);
extern int  Exec_PrepareBprm(struct LinuxBinPrm *bprm);
extern int  ELF_LoadBinary(struct LinuxBinPrm *bprm, TaskRegs *regs);
extern int  Script_Load(struct LinuxBinPrm *bprm, TaskRegs *regs);

/*
 * TSS segment. 
 */
extern const ushort vkTssSelector;
extern void FASTCALL Task_SetupTLS(struct Task *);


static INLINE void
Print_Context(const struct sigcontext *scP)
{
   LOG( 
         "   TID:   %8.8d   cr2: 0x%8.8lx\n"
         "eflags: 0x%8.8lx\n"
         "   eip: 0x%8.8lx   esp: 0x%8.8lx  ebp: 0x%8.8lx\n"
         "   eax: 0x%8.8lx   ebx: 0x%8.8lx  ecx: 0x%8.8lx\n"
         "   edx: 0x%8.8lx   edi: 0x%8.8lx  esi: 0x%8.8lx\n"
         "    ds: 0x%8.8x    es: 0x%8.8x   fs: 0x%8.8x\n"
         "    gs: 0x%8.8x    ss: 0x%8.8x   cs: 0x%8.8x\n"
         ,
         gettid(), scP->cr2, scP->eflags,
         scP->eip, scP->esp, scP->ebp,
         scP->eax, scP->ebx, scP->ecx,
         scP->edx, scP->edi, scP->esi,
         scP->ds, scP->es, scP->fs, scP->gs, scP->ss, scP->cs);
}

static INLINE void
Print_VexState(const VexGuestX86State *gSt)
{
   LOG(
         "   TID:   %8.8d\n"
         "eflags: 0x%8.8lx\n"
         "   eip: 0x%8.8lx   esp: 0x%8.8lx  ebp: 0x%8.8lx\n"
         "   eax: 0x%8.8lx   ebx: 0x%8.8lx  ecx: 0x%8.8lx\n"
         "   edx: 0x%8.8lx   edi: 0x%8.8lx  esi: 0x%8.8lx\n"
         "    ds: 0x%8.8x    es: 0x%8.8x   fs: 0x%8.8x\n"
         "    gs: 0x%8.8x    ss: 0x%8.8x   cs: 0x%8.8x\n"
         ,
         gettid(), LibVEX_GuestX86_get_eflags((VexGuestX86State *)gSt),
         gSt->guest_EIP, gSt->guest_ESP, gSt->guest_EBP,
         gSt->guest_EAX, gSt->guest_EBX, gSt->guest_ECX,
         gSt->guest_EDX, gSt->guest_EDI, gSt->guest_ESI,
         gSt->guest_DS, 
         gSt->guest_ES, gSt->guest_FS, gSt->guest_GS,
         gSt->guest_SS, gSt->guest_CS);
}




static INLINE void
Debug_PrintContext(int lvl, const struct sigcontext *scP)
{
#if DEBUG
   if (DEBUG_LEVEL(lvl)) {
      Print_Context(scP);
   }
#endif
}


static INLINE void
Debug_PrintVexState(const VexGuestX86State *gSt)
{
#if DEBUG
   Print_VexState(gSt);
#endif
}

static INLINE void
Debug_PrintTaskRegs(const TaskRegs *regs)
{
   Debug_PrintVexState(regs);
}

#define FLAG2STR(f) ((cargp->flags & f) ? #f : "-")

static INLINE void
Debug_PrintCloneArgs(struct CloneArgs *cargp)
{
   QUIET_DEBUG_MSG(5, 
         "FLAGS: 0x%8.8x  CSIG: %d -- \n"
         "%20s %20s\n"
         "%20s %20s\n"
         "%20s %20s\n"
         "%20s %20s\n"
         "%20s %20s\n"
         "%20s %20s\n"
         "%20s %20s\n"
         "%20s %20s\n"
         "%20s %20s\n"
         "STACK: 0x%8.8x   PTID: 0x%8.8x\n"
         " TLSP: 0x%8.8x   CTID: 0x%8.8x\n",
         cargp->flags, cargp->flags & CSIGNAL,
         FLAG2STR(CLONE_VM),
         FLAG2STR(CLONE_FS),
         FLAG2STR(CLONE_FILES),
         FLAG2STR(CLONE_SIGHAND),
         FLAG2STR(CLONE_PTRACE),
         FLAG2STR(CLONE_VFORK),
         FLAG2STR(CLONE_PARENT),
         FLAG2STR(CLONE_THREAD),
         FLAG2STR(CLONE_NEWNS),
         FLAG2STR(CLONE_SYSVSEM),
         FLAG2STR(CLONE_SETTLS),
         FLAG2STR(CLONE_PARENT_SETTID),
         FLAG2STR(CLONE_CHILD_CLEARTID),
         FLAG2STR(CLONE_DETACHED),
         FLAG2STR(CLONE_UNTRACED),
         FLAG2STR(CLONE_CHILD_SETTID),
         FLAG2STR(CLONE_STOPPED),
         "-",
         cargp->stack, cargp->ptid, cargp->tlsDescp, cargp->ctid);
}


static INLINE void
Debug_PrintTask(struct Task *tsk)
{
   QUIET_DEBUG_MSG(5, 
         "   ID:   %8.8d  VCPU:   %8.8d  STCK: 0x%8.8x\n"
         "START: 0x%8.8x   END: 0x%8.8x  SIZE:   %8.8d\n",
         tsk->id,
         Task_GetVCPU(tsk)->id,
         Task_GetStackBase(current),
         tsk, 
         (char*)tsk + sizeof(*tsk), 
         sizeof(*tsk));
}

static INLINE void
Debug_PrintSysArgs(struct SyscallArgs *args, long ret)
{
   QUIET_DEBUG_MSG(5,
         "SYS_%-14s   ID:   %8.8d  RET: %8.8d/0x%8.8x\n"
         "         EBX: 0x%8.8x    ECX: 0x%8.8x     EDX: 0x%8.8x\n"
         "         ESI: 0x%8.8x    EDI: 0x%8.8x     EBP: 0x%8.8x\n",
         get_syscall_name(args->eax), args->eax, ret, ret,
         args->ebx, args->ecx, args->edx, 
         args->esi, args->edi, args->ebp);
}

static INLINE void
Debug_MarkSyscallStart(struct SyscallArgs *args)
{
   QUIET_DEBUG_MSG(5, 
         "== SysEntry: SYS_%-14s == "
         "0x%8.8x 0x%8.8x 0x%8.8x 0x%8.8x 0x%8.8x 0x%8.8x\n", 
         get_syscall_name(args->eax),
         args->ebx, args->ecx, args->edx, 
         args->esi, args->edi, args->ebp);
}

static INLINE void
Debug_MarkSyscallEnd(int sysno, long ret)
{
   QUIET_DEBUG_MSG(5, 
         "==  SysExit: SYS_%-14s == "
         "0x%8.8x/%d\n",
         get_syscall_name(sysno), ret, ret);
}

static INLINE void
Debug_Mark()
{
   QUIET_DEBUG_MSG(5, "================================================================================\n");
}



static INLINE void
Task_Regs2Args(TaskRegs *regs, struct SyscallArgs *args)
{
   args->ebx = regs->guest_EBX;
   args->ecx = regs->guest_ECX;
   args->edx = regs->guest_EDX;
   args->esi = regs->guest_ESI;
   args->edi = regs->guest_EDI;
   args->ebp = regs->guest_EBP;
   args->eax = regs->guest_EAX;
}

/*
 * XXX: Name is misleading -- should be called only on exec and not
 * when a thread starts.
 */
static INLINE void
Task_StartThread(TaskRegs *regs, ulong entry_eip, ulong entry_esp)
{
   Task_WriteReg(regs, eip, entry_eip);
   Task_WriteReg(regs, esp, entry_esp);
   /* Must clear to ensure consistent starting state during
    * replay and logging. */
   Task_WriteReg(regs, eax, 0);
   Task_WriteReg(regs, ebx, 0);
   Task_WriteReg(regs, ecx, 0);
   Task_WriteReg(regs, edx, 0);
   Task_WriteReg(regs, edi, 0);
   Task_WriteReg(regs, esi, 0);
   Task_WriteReg(regs, ebp, 0);
   Task_WriteReg(regs, fs, 0);
   Task_WriteReg(regs, gs, 0);

   {
      ushort tmp_cs;

      /* CS can't be changed at CPL 3. */
      savesegment(cs, tmp_cs);
      DEBUG_MSG(5, "tmp_cs=0x%x __USER_CS=0x%x\n", tmp_cs, __USER_CS);
      ASSERT(tmp_cs == __USER_CS);
      Task_WriteReg(regs, cs, __USER_CS);
   }

   /* ES, DS, and SS default to Linux's user data segments -- they
    * all overlap prefectly on top of each other. */
   Task_WriteReg(regs, es, __USER_DS);
   Task_WriteReg(regs, ds, __USER_DS);
   Task_WriteReg(regs, ss, __USER_DS);
   Task_WriteReg(regs, CC_OP, 0); /* so that VEX copies the eflags from DEP1 */
   Task_WriteReg(regs, CC_DEP1, 0);
   Task_WriteReg(regs, DFLAG, 1); /* 1 <--> increment */
   Task_WriteReg(regs, IDFLAG, 0); 
   Task_WriteReg(regs, ACFLAG, 0);
#ifdef REQ_TFFLAG
   Task_WriteReg(regs, TFFLAG, (VCPU_GetMode() & VCPU_MODE_SINGLESTEP) ? 1 : 0);
#endif
   /* We want the initial eflags to match for DE and BT exec, so use
    * the default state provided by VEX (with x86-mandated bits set). 
    * This is important in order to avoid false-positive divergences
    * during replay check. */
   Task_WriteReg(regs, CC_DEP1, LibVEX_GuestX86_get_eflags(regs));
}





extern long do_no_restart_syscall(struct RestartBlockStruct *param);

extern void System_Shutdown();

extern void  DE_EmulateRDTSC();

extern void Server_HandleActivity(siginfo_t *);

extern void Task_DebugInit();
extern void Task_DebugStart();
