#define CONFIG_KPERFCTR 1
#include <linux/perfctr.h>

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
   OFFSET(oPERFCTR_CPUSTATE_TSCSTART, struct perfctr_cpu_state,
         tsc_start);
   OFFSET(oPERFCTR_CPUSTATE_INTR_COUNT, struct perfctr_cpu_state,
         intr_count);

   OFFSET(oPERFCTR_CPUSTATE_MAP_0, struct perfctr_cpu_state, pmc[0].map);
   OFFSET(oPERFCTR_CPUSTATE_START_0, struct perfctr_cpu_state, pmc[0].start);
   OFFSET(oPERFCTR_CPUSTATE_SUM_0, struct perfctr_cpu_state, pmc[0].sum);
}
