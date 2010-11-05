#pragma once

/* Hardware performance monitor counter operations. */

/* The hardware delivers the PMIs late. This is an
 * upper-bound, in branches, on the lateness -- you can 
 * use this upper-bound to compensate for the lateness. 
 *
 * XXX: this is machine-implementation dependent.
 *
 */
#define PMI_MAX_LATENCY  100


#ifdef __ASSEMBLER__

#include "libcommon/asm-offsets.h"

/* Use serilization instructions to ensure accurate branch counts. 
 * This appears to be necessary, at least on my P4, to get
 * accurate branch counts.*/
#define SERIALIZE 1
/* 
 * CPUID is a serializing instruction, but invoking it requires
 * saving/restoring register state. mfence is also serializing,
 * but doesn't change register state, so should be more efficient.
 * Luckily, mfence seems sufficient for accruate branch count on my P4.
 *
 * XXX: what's the performance penalty of using CPUID? Are there
 * other instructions that serialize with lower penalty
 * (doubtful but worth looking into) ?
 *
 */
#define SERIALIZE_WITH_CPUID 0


.macro MacroSerialize
#if SERIALIZE
#if SERIALIZE_WITH_CPUID
   MacroSafeCPUID
#else
   mfence
#endif
#endif
.endm

/*
 *-----------------------------------------------------------------------
 *
 * PmcOps_MacroReadBrCnt --
 *
 *
 * Summary:
 *    
 *    Reads the P4 ``retired_branch_type'' counter (event select 4) from
 *    perfctr-driver CPU state mapped at address @cpuStateAddr
 *    and returns the results in registers for quick access from assembly 
 *    code. This counter is accurate -- it does not count IRETs or RSMs.
 *
 *
 * Design note:
 *
 *    Must be a macro rather than a function in order to avoid introducing
 *    additional branches into the counter (call and ret each add one).
 *    We could compensate for these, but doing so for compiler-generated
 *    code is likely to be trick -- is it worth the extra effort and
 *    overhead?
 *
 *
 * Challenges:
 *    
 *    Reading the counter may itself cost additional branches that
 *    must be taken into account, and compensated for. These 
 *    additional branches come from the need to check for a race 
 *    and overflow checks (see below).
 *
 *    The hardware count increases by 2 for conditional jumps, but
 *    by 1 for all other types.
 *
 *    The value of RDPMC could be less than that of the counter at the
 *    start of this task's quantum, in which case we would have overflow.
 *    We check for it and try again (see below).
 *
 *    Overflow of branch counts in general shouldn't be a problem -- we
 *    use 64-bit counters that at 2^32 branches per second would be good
 *    enough for 136 years.
 *
 * Limitations:
 *
 *    XXX: Only P4 is supported at the moment.
 *
 * Returns:
 *
 *    Number of virtual retired branches (i.e., the number of branches 
 *    that only this task and no other Linux task has retired; see 
 *    perfctr API and brCnt.c for details) into EDX:EAX (a 64-bit value).
 *    
 *    The number of branches exectuted to read the counter is
 *    placed in EDI (should be 0 most of the time, except when
 *    the race occurs--and then usually 1).
 
 *
 * Clobbers:
 *    Every register except ESP and EBP (but may push to the stack). Feel
 *    free to wrap with appropriate fill/spill instructions (e.g., a PUSHA
 *    and a POPA, before and after respectively would work).
 *
 *-----------------------------------------------------------------------
 */
.altmacro
.macro PmcOps_MacroReadBrCnt cpuStateAddr:req
   /* 
    * According to the Intel manual for RDPMC: "performing back-to-back
    * fast reads [using RDPMC] are not guaranteed to be monotonic.
    * To guarantee monotonicity on back-to-back reads, a serializing
    * instruction must be placed between the two RDPMC instructions."
    *
    * Indeed, without a serialization instruction, I've observed
    * that the branch count in not strictly monotonic (you can see that 
    * the result of BrCnt_Get() skips branches).
    *
    */

   movl $-2, %edi
   movl \cpuStateAddr, %ebx
   movl oPERFCTR_CPUSTATE_MAP_0(%ebx), %ecx

LOCAL_retry2_\@:
   inc %edi
LOCAL_retry1_\@:
   /* If this is a retry, then we must've executed a taken branch
    * to get here. Thus tally the overhead of doing so. */
   inc %edi

   /* Essential before the RDPMC, according to my experiments on P4. */
   MacroSerialize
   movl oPERFCTR_CPUSTATE_INTR_COUNT(%ebx), %esi

   rdpmc


   /* 
    * The branch counters are ullong, and thus 64-bit addition is
    * required. The computation done here is:
    *  
    * EDX:EAX = k_state->sum + (rdpmc() - kstate->start) 
    *
    */

   /* live: EAX, EBX, EBP, ESP */
   subl oPERFCTR_CPUSTATE_START_0(%ebx), %eax

   /*
    * The branch counter may overflow (it's only 32-bits after all).
    * If that happens, then (rdpmc() - kstate->start) will be negative,
    * (i.e., the sign flag (SF) of EFLAGS will be set).
    * I expect this to be rare enough to just try again. Of course,
    * this would add to the overhead of acquiring the count,
    * and thus the overhead counter (EDI) should be incremented
    * (see above).
    */
   js LOCAL_retry1_\@
   movl $0, %edx
   addl oPERFCTR_CPUSTATE_SUM_0(%ebx), %eax
   adcl oPERFCTR_CPUSTATE_SUM_0+4(%ebx), %edx


   /* This comparison checks for the following race:
    *
    * Values read from RDPMC, kstate->sum, and kstate->start may be 
    * inconsistent with each other. This is due to a context 
    * switch occuring after any of these reads (at which
    * point the perfctr driver updates both sum and start).
    *
    * To deal with this race, we simply check to see
    * if there was an interrupt during the period in
    * which we read the perfctr driver values. If there
    * was no interrupt, then there was no context switch,
    * and no other kind of interrupt and thus the values 
    * are accurate. If not, we try again.
    *
    * To check for interrupts we read the interrupt count,
    * provided by our kernel driver/patch, before and after
    * we read all of the counter state.
    * Note that we check only the lower 32-bits of the
    * interrupt count -- it's highly unlikely that we'll
    * get enough interrupts for a wrap-around to the same
    * bit configuration -- I'll be damned if this creates
    * a bug later...
    */
   cmpl oPERFCTR_CPUSTATE_INTR_COUNT(%ebx), %esi

   jne LOCAL_retry2_\@ /* interrupt occured; stale values, read again */
.endm
.noaltmacro
#else

#include <libperfctr.h>

typedef 
   enum { 
      PMC_BR,
   } 
   PmcTag;

void PmcOps_SetupCounter(PmcTag tag, const struct perfctr_info *info,
      struct perfctr_cpu_control *cpu_control);


#endif
