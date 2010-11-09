#pragma once 

#ifdef __ASSEMBLER__

#include "vkernel/asm-offsets.h"
#include "vkernel/task/public.h"
#include "vkernel/vcpu/public.h"
#include "libcommon/syscallids.h"
#include "libcommon/asmmacros.h"
#include <libcommon/arch.h>

/* How to get the base of the task struct from ASM */
#define GET_CURRENT_TASK(reg) \
   movl $-TASK_SIZE, reg; \
   andl %esp, reg

.macro MacroScheduleUpcomingPreemption
   call Preempt_ScheduleUpcoming  
.endm

#else

struct ExecPoint {
   ulong    eip;
   ulong    ecx;
   u64      brCnt;
};

static INLINE int
ExecPoint_IsMatch(const struct ExecPoint *e1, const struct ExecPoint *e2)
{
   int a = 1, b;

   a &= (e1->eip == e2->eip);
   a &= (e1->brCnt == e2->brCnt);
   b = a & (e1->ecx == e2->ecx);

#if 0
   if (!b) {
      if (a) {
         DEBUG_MSG(0, "Near match: 0x%x:0x%x:0x%llu  0x%x:0x%x:0x%llu\n",
               e1->eip, e1->ecx, e1->brCnt,
               e2->eip, e2->ecx, e2->brCnt);
      } else {
#if 0
         DEBUG_MSG(0, "Match failed: 0x%x:0x%x:0x%llu  0x%x:0x%x:0x%llu\n",
               e1->eip, e1->ecx, e1->brCnt,
               e2->eip, e2->ecx, e2->brCnt);
#endif
      }
   }
#endif

   return b;
}

#endif
