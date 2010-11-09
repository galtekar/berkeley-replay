#include "vkernel/public.h"

/* We use this file to automatically generate macros for variable
 * offsets within data structures. This is used to accestacks.those variables
 * from within astacks.mbly routines. The output is asm-offsets.h and can be
 * included in astacks.mbly files.*/

#define DEFINE(sym, val) \
	asm volatile ("\n#define " #sym " %c0 " : : "i" (val))

#define XDEFINESTR(sym, val) \
   asm volatile ("\n#define " #sym " " #val);

#define DEFINESTR(sym, val) XDEFINESTR(sym, val)

#define OFFSET(sym, str, mem) \
	DEFINE(sym, __builtin_offsetof(str, mem))

void 
foo(void) 
{

   DEFINE(RT_SIGFRAME_SIZE, sizeof(struct rt_sigframe));
   OFFSET(oRT_SIGFRAME_PRETCODE, struct rt_sigframe, pretcode);
   OFFSET(oRT_SIGFRAME_MCONTEXT, struct rt_sigframe, uc.uc_mcontext);
   OFFSET(oRT_SIGFRAME_SIGMASK, struct rt_sigframe, uc.uc_sigmask);


   OFFSET(oCLONE_FUTEX, struct Task, cloneFutex);

   DEFINE(VPERFCTR_IOCTL_CMD_START_ICTR_1, VPERFCTR_START_ICTR_1);
   DEFINE(VPERFCTR_IOCTL_CMD_EMU_ENABLE, VPERFCTR_EMU_ENABLE);
   OFFSET(oPERFCTR_FD, struct vperfctr, fd);
   OFFSET(oPERFCTR, struct Task, perfctr);
   OFFSET(oPERFCTR_PAGE_IDX, struct Task, vperfPageIdx);
   OFFSET(oPERFCTR_CPUSTATE, struct Task, perf_cpu_state);
   OFFSET(oBRCNT_ON_ENTRY, struct Task, brCntOnEntry);
   OFFSET(oVK_BRCNT, struct Task, vkBrCnt);
   OFFSET(oIS_IN_CODE_CACHE, struct Task, is_in_code_cache);

   OFFSET(oTASK_PID, struct Task, pid);
   OFFSET(oTASK_REAL_PID, struct Task, realPid);

   OFFSET(oTASK_FLAGS, struct Task, flags);
   OFFSET(oTASK_SIGFLAGS, struct Task, sigFlags);

   OFFSET(oTASK_REGS, struct Task, stack.un.arch.vex);
   OFFSET(oTASK_REGS_EIP, struct Task, stack.un.arch.vex.guest_EIP);

   OFFSET(oREGS_EAX, TaskRegs, guest_EAX);
   OFFSET(oREGS_EBX, TaskRegs, guest_EBX);
   OFFSET(oREGS_ECX, TaskRegs, guest_ECX);
   OFFSET(oREGS_EDX, TaskRegs, guest_EDX);
   OFFSET(oREGS_ESI, TaskRegs, guest_ESI);
   OFFSET(oREGS_EDI, TaskRegs, guest_EDI);
   OFFSET(oREGS_EBP, TaskRegs, guest_EBP);
   OFFSET(oREGS_ESP, TaskRegs, guest_ESP);
   OFFSET(oREGS_EIP, TaskRegs, guest_EIP);
   OFFSET(oREGS_OP, TaskRegs, guest_CC_OP);
   OFFSET(oREGS_EFLAGS, TaskRegs, guest_CC_DEP1);
   OFFSET(oREGS_SS, TaskRegs, guest_SS);
   OFFSET(oREGS_GS, TaskRegs, guest_GS);
   OFFSET(oREGS_FS, TaskRegs, guest_FS);
   OFFSET(oREGS_ES, TaskRegs, guest_ES);
   OFFSET(oREGS_DS, TaskRegs, guest_DS);
   OFFSET(oREGS_CS, TaskRegs, guest_CS);
   OFFSET(oREGS_LDT, TaskRegs, guest_LDT);

   OFFSET(oSYSARGS_EAX, struct SyscallArgs, eax);
   OFFSET(oSYSARGS_EBX, struct SyscallArgs, ebx);
   OFFSET(oSYSARGS_ECX, struct SyscallArgs, ecx);
   OFFSET(oSYSARGS_EDX, struct SyscallArgs, edx);
   OFFSET(oSYSARGS_ESI, struct SyscallArgs, esi);
   OFFSET(oSYSARGS_EDI, struct SyscallArgs, edi);
   OFFSET(oSYSARGS_EBP, struct SyscallArgs, ebp);

   OFFSET(oUCONTEXT_MCONTEXT_EIP, ucontext_t, uc_mcontext.eip);

   DEFINE(TASK_SIZE, TASK_SIZE);

   /* Our TLS segmentation register (TSS stands for Task State Segment). */
   DEFINESTR(TASK_TSS, TSS);
}
