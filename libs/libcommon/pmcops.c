#include <string.h>

#include "public.h"

/* P4 has two branch counters:
 *
 * branch_retired (event select 6):
 *    + allows us to count only the taken branches, which precludes
 *    the need to compensate for race-condition checks in
 *    MacroReadBrCnt.
 *    - includes IRET and RSM instructions as part of count,
 *    but unfortunately, we cannot compensate for RSM (it's
 *    invisible to the OS)
 *    - counts may be incorrect, even with IRET compensation,
 *    so unsuitable for replay
 *
 * retired_branch_type (event select 4)
 *    + doesn't count IRET or RSM, so can be more accurate
 *    - counts conditional branches twice, makes handling
 *    the perfctr race-condition checks a little trickier,
 *    but not too much
 *    + accurate -- works for replay
 *
 */

/*
 *
 * cpu_control->pmc_map -- which counter to use
 * cpu_control->eventsel -- the CCCR value
 * cpu_control->p4.escr -- event mask
 */
static void
PmcOpsSetupBr(const struct perfctr_info *info,
      struct perfctr_cpu_control *cpu_control)
{
   const unsigned int tsc_on = 1;
   unsigned int pmc_map0 = 0, pmc_map1 = 1;
   unsigned int evntsel0 = 0, evntsel1 = 0;
   unsigned int evntBrTaken = 0;

   memset(cpu_control, 0, sizeof(*cpu_control));

   /* Attempt to set up control to count clocks via the TSC
      and retired instructions via PMC0. */
   switch (info->cpu_type) {
   case PERFCTR_X86_GENERIC:
      ASSERT_UNIMPLEMENTED(0);
      break;
#if !defined(__x86_64__)
   case PERFCTR_X86_INTEL_P5:
   case PERFCTR_X86_INTEL_P5MMX:
   case PERFCTR_X86_CYRIX_MII:
      ASSERT_UNIMPLEMENTED(0);
      /* event 0x12 (Branches executed), count at CPL 3 */
      evntsel0 = 0x12 | (2 << 6);
      break;
   case PERFCTR_X86_INTEL_P6:
   case PERFCTR_X86_INTEL_PII:
   case PERFCTR_X86_INTEL_PIII:
   case PERFCTR_X86_INTEL_PENTM:
   case PERFCTR_X86_INTEL_CORE:
      {
         /* event 0xC4 (Branches Retired), count at CPL > 0, Enable
          * Using this means we must compensate for race-condition
          * checks in MacroReadBrCnt. */
         //uint evntBrAll = 0xC4 | (1 << 16) | (1 << 22);
         /* event 0xC9 (Branch Instructions Retired and Taken), count at CPL > 0, Enable 
          * Avoids the need for branch compensation in MacroReadBrCnt. */
         evntBrTaken = 0xC9 | (1 << 16) | (1 << 22);

         evntsel0 = evntBrTaken;
         /* XXX: for some reason, INT (20) can't be set at the same time
          * as ENABLE (22). */
         evntsel1 = 0xC9 | (1 << 16) | (1 << 20) /* INT */;
      }
      break;
#endif
   case PERFCTR_X86_INTEL_CORE2:
   case PERFCTR_X86_INTEL_ATOM:
   case PERFCTR_X86_AMD_K8:
   case PERFCTR_X86_AMD_K8C:
   case PERFCTR_X86_AMD_FAM10H:
      ASSERT_UNIMPLEMENTED(0);
      break;
#if !defined(__x86_64__)
   case PERFCTR_X86_WINCHIP_C6:
   case PERFCTR_X86_WINCHIP_2:
   case PERFCTR_X86_VIA_C3:
      ASSERT_UNIMPLEMENTED(0);
      break;
   case PERFCTR_X86_INTEL_P4:
   case PERFCTR_X86_INTEL_P4M2: /* Xeon 3.06 Ghz */
#endif
   case PERFCTR_X86_INTEL_P4M3: /* Pentium D, ... */

      /* event 4 (retired_branch_type), 0xF - all possible br types, CPL>0 */
      evntBrTaken = (0x4 << 25) | (0xF << 9) | (1 << 2);

      /* We must use MSR_TBPU_ESCR0 or MSG_TBPU_ESCR1 -- only
       * counters 4,5 and 6,7 (respectively) select these ESCRs. */
      /* map PMC0 to the MSR_MS_COUNTER0 (counter 4) with fast RDPMC */
      pmc_map0 = 0x4 | (1 << 31);
      /* CCCR for count mapped at 0: required flags, ESCR 2, Enable */
      evntsel0 = (0x3 << 16) | (2 << 13) | (1 << 12);
      cpu_control->p4.escr[0] = evntBrTaken;

      /* map PMC1 to the MSR_MS_COUNTER2 (counter 6) with fast RDPMC */
      pmc_map1 = 0x6 | (1 << 31);
      /* CCCR: Same event select as above, but with the PMI on 
       * overflow flag */
      evntsel1 = evntsel0 | (1 << 26) /* PMI_OVF */;
      cpu_control->p4.escr[1] = evntBrTaken;

      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }
   cpu_control->tsc_on = tsc_on;
   /* a-mode counters first, then i-mode counters. */
   cpu_control->nractrs = 1;
   cpu_control->nrictrs = 0;
   cpu_control->pmc_map[0] = pmc_map0;
   cpu_control->evntsel[0] = evntsel0;
   cpu_control->pmc_map[1] = pmc_map1;
   cpu_control->evntsel[1] = evntsel1;
   cpu_control->ireset[1] = 0;
}

void
PmcOps_SetupCounter(PmcTag tag, const struct perfctr_info *info,
      struct perfctr_cpu_control *cpu_control)
{
   switch (tag) {
   case PMC_BR:
      PmcOpsSetupBr(info, cpu_control);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }
}
