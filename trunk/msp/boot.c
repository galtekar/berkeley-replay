#include <linux/module.h>
#include <linux/stringify.h>
#include <linux/stddef.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <asm/paravirt.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/poll.h>
#include <asm/asm-offsets.h>

#include "msp_private.h"

struct shadow msp_state;
static pgd_t pgd_pool[NR_CPUS][NR_SHADOW_PGD][PTRS_PER_PGD] __attribute__((aligned(PAGE_SIZE)));

STATIC void
init_cpu(struct shadow *sh, struct msp_cpu *cpu, int id)
{
   int i;

   cpu->id = id;
   cpu->sh = sh;
   cpu->sh->nr_cpus++;
   for (i = 0; i < ARRAY_SIZE(cpu->pgdirs); i++) {
      struct pgdir *pgd = &cpu->pgdirs[i];
      pgd->pgdir = pgd_pool[id][i];
      BUG_ON((unsigned long)pgd->pgdir & ~PAGE_MASK);
   }
}

STATIC int 
init_work(void)
{
   int err = 0, i;

   for (i = 0; i < NR_CPUS; i++) {
      init_cpu(&msp_state, &msp_state.cpus[i], i);
   }
   msp_state.is_initialized = 1;
   spin_lock_init(&msp_state.lock);
   msp_state.clock = 0;

   paravirt_init();

#if IPT_ENABLE_ALL
   if ((err = ipt_init())) {
      pr_err("failed to initialize IPT tables\n");
      return err;
   }
#endif

   return err;
}


/* This gets called at early startup, from within setup_arch(). 
 * Our job is to get into paravirt mode, and register the necessary
 * pagetable callbacks. */
int __init 
msp_boot_init(void)
{
   /* Shadow can't run under Xen, VMI or itself.  It does Tricky Stuff. */
   if (paravirt_enabled()) {
      printk("SHPT does not work as a paravirt guest\n");
      return -EPERM;
   }

   init_work();

   /* All good! */
   return 0;
}
