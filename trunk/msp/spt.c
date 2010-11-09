#include <linux/mm.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/hardirq.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/bootparam.h>

#include "msp.h"
#include "msp_private.h"

/*
 * Page fault error code bits
 *	bit 0 == 0 means no page found, 1 means protection fault
 *	bit 1 == 0 means read, 1 means write
 *	bit 2 == 0 means kernel, 1 means user-mode
 *	bit 3 == 1 means use of reserved bit detected
 *	bit 4 == 1 means fault was an instruction fetch
 */
#define PF_PROT		(1<<0)
#define PF_WRITE	   (1<<1)
#define PF_USER		(1<<2)
#define PF_RSVD		(1<<3)
#define PF_INSTR	   (1<<4)

static pte_t pte_pool[NR_CPUS][NR_SHADOW_PGD][PTRS_PER_PGD][PTRS_PER_PTE] __attribute__((aligned(PAGE_SIZE)));


/*H:320 The page table code is curly enough to need helper functions to keep it
 * clear and clean.
 *
 * There are two functions which return pointers to the shadow (aka "real")
 * page tables.
 *
 * spgd_addr() takes the virtual address and returns a pointer to the top-level
 * shadow page directory entry (PGD) for that address.  Since we keep track of 
 * several page tables, the "i" argument tells us which one we're interested in 
 * (it's usually the current one). */
STATIC pgd_t *
spgd_addr(struct msp_cpu *cpu, u32 i, unsigned long vaddr)
{
	unsigned int index = pgd_index(vaddr);

	/* Return a pointer index'th pgd entry for the i'th page table. */
	return &cpu->pgdirs[i].pgdir[index];
}

/* This routine then takes the page directory entry returned above, which
 * contains the address of the page table entry (PTE) page.  It then returns a
 * pointer to the PTE entry for the given address. */
STATIC pte_t *
spte_addr(pgd_t spgd, unsigned long vaddr)
{
	pte_t *page = __va(pgd_pfn(spgd) << PAGE_SHIFT);
	/* You should never call this if the PGD entry wasn't valid */
	ASSERT(pgd_flags(spgd) & _PAGE_PRESENT);
	return &page[pte_index(vaddr)];
}

/* These two functions are just like the above two, except they access the Guest
 * page tables.  Hence they return a Guest address. */
STATIC pgd_t *
gpgd_addr(struct msp_cpu *cpu, unsigned long vaddr)
{
   unsigned long gpgdir = cpu->pgdirs[cpu->cpu_pgd].gpgdir;
   pgd_t *gpgd = __va(gpgdir);
   ASSERT(gpgdir);
   return &gpgd[pgd_index(vaddr)];
}

STATIC pte_t *
gpte_addr(pgd_t gpgd, unsigned long vaddr)
{
	pte_t *gpt = (pte_t*)__va(pgd_pfn(gpgd) << PAGE_SHIFT);
	BUG_ON(!(pgd_flags(gpgd) & _PAGE_PRESENT));
   return &gpt[pte_index(vaddr)];
}

/*H:340 Converting a Guest page table entry to a shadow (ie. real) page table
 * entry is straigtforward: the shadow uses the same pfn as the guest. */
STATIC pte_t 
gpte_to_spte(pte_t gpte)
{
	unsigned long flags;

	/* The Guest sets the global flag, because it thinks that it is using
	 * PGE.  We only told it to use PGE so it would tell us whether it was
	 * flushing a kernel mapping or a userspace mapping.  We don't actually
	 * use the global bit, so throw it away. */
	flags = (pte_flags(gpte) & ~_PAGE_GLOBAL);

	/* Now we assemble our shadow PTE from the page number and flags. */
	return pfn_pte(pte_pfn(gpte), __pgprot(flags));
}


/*H:460 And to complete the chain, clear_pte() looks like this: */
STATIC void 
clear_pte(pte_t *pte)
{
   /* Clear the entry. */
   *pte = __pte(0);
}

STATIC void 
check_gpte(struct msp_cpu *cpu, pte_t gpte)
{
   /* XXX: We don't support PSE at the moment. It should've been disabled
    * by our CPUID emulation. */
	if ((pte_flags(gpte) & _PAGE_PSE)) {
		kill_guest(cpu, "bad page table entry: PSE bit is set");
   }
}

STATIC void 
check_gpgd(struct msp_cpu *cpu, pgd_t gpgd)
{
#if 0
   BUG_ON(pgd_flags(gpgd) & _PAGE_PCD);
   BUG_ON(pgd_flags(gpgd) & _PAGE_PWT);
   BUG_ON(pgd_flags(gpgd) & _PAGE_PSE);
   BUG_ON(pgd_flags(gpgd) & _PAGE_GLOBAL);
#endif
	if ((pgd_flags(gpgd) & ~_PAGE_TABLE)) {
		kill_guest(cpu, "bad page directory entry: 0x%lx", pgd_flags(gpgd));
   }
}

/* We keep several page tables.  This is a simple routine to find the page
 * table (if any) corresponding to this top-level address the Guest has given
 * us. */
STATIC unsigned int 
find_pgdir(struct msp_cpu *cpu, unsigned long gpgdir)
{
   unsigned int i;
   for (i = 0; i < ARRAY_SIZE(cpu->pgdirs); i++) {
      if (cpu->pgdirs[i].pgdir && cpu->pgdirs[i].gpgdir == gpgdir) {
         break;
      }
   }
	return i;
}

struct downgrade_args {
   unsigned long vaddr;  /* Fault virtual address */
   pte_t gpte;           /* Fault guest PTE. */
   int write_req;        /* Was it a read or write fault? */
   uint64_t timestamp;   /* Assigned logical clock value of downgrade event. */
};



STATIC void
on_downgrade_ipi(void *arg)
{
   struct downgrade_args *darg = (struct downgrade_args *)arg;
   unsigned long pfn;
   struct ipt_entry *ipte;
   struct hlist_head *head;
   struct hlist_node *node;

   ASSERT(in_irq() && irqs_disabled() && !preemptible());
   ASSERT(darg);
   ASSERT(darg->vaddr);
   ASSERT(darg->vaddr < PAGE_OFFSET);
   ASSERT(pte_present(darg->gpte));

   pfn = pte_pfn(darg->gpte);
   ASSERT(pfn_valid(pfn));

   shadow_lock();

   head = &ipt.pfn_map[hash_long(pfn, NR_BUCKET_BITS)];
   hlist_for_each_entry(ipte, node, head, by_pfn) {
      if (ipte->pfn == pfn) {
         /* If this CPU currently maps the physical page in question,
          * then make sure it sees the downgrade (by flushing the TLB
          * entry for the vpage mapping to it). */
         if (curr_sh->guest_cr3 == ipte->gpgdir) {
            __native_flush_tlb_single(fn_to_addr(ipte->vfn));
         } else {
            /* Nothing to do. Changes will be seen when this CPU eventually
             * switches to ent->gpgdir (at which point the TLB will be 
             * automatically flushed on the CR3 write). */
         }
      }
   }

   shadow_unlock();

   wake_up_interruptible(&curr_sh->read_waitqueue);
	msp_kill_fasync(&curr_sh->fasync, SIGIO, POLL_IN);
}

STATIC void
do_crew_invalidate(struct cpumask *down_mask, unsigned long vaddr,
      int errcode, pte_t gpte, uint64_t timestamp)
{
   /* Okay to allocate IPI args on stack since we wait for remote cpus to
    * finish (see below). */
   struct downgrade_args args;

   ASSERT(pte_present(gpte));
   ASSERT(vaddr < PAGE_OFFSET);
   ASSERT(irqs_disabled());

   args.vaddr = vaddr;
   args.gpte = gpte;
   args.write_req = (errcode & PF_WRITE);
   args.timestamp = timestamp;

   /* We shouldn't deadlock here, because:
    *    (1) we are coming from user-mode, in which case we don't hold
    *    any locks, or
    *    (2) we are coming from kernel-mode, due to a user-access, but
    *    then locks shouldn't be held in that case (XXX: ??) */
#define ENABLE_IRQ_FOR_IPI 1
#if ENABLE_IRQ_FOR_IPI
   /* Must have IRQs enabled to avoid deadlock (think about what happens
    * when two cpus concurrently send IPIs to each other). */
   local_irq_enable();
#endif

   /* XXX: this call produces lots of false warnings due to the fact that we
    * have interrupts disabled here (a necessity to avoid deadlock).
    * We've patched kernel/smp.c to eliminate them, but we may need to
    * write our own IPI routines if patching becomes undesirable. */
   smp_call_function_many(down_mask, on_downgrade_ipi, (void*)&args, 1);

#if ENABLE_IRQ_FOR_IPI
   local_irq_disable();
#endif
   ASSERT(irqs_disabled());
}

STATIC int
do_downgrade_work(struct msp_cpu *rem_cpu, unsigned long gpgdir, 
      unsigned long vaddr, int errcode, pte_t gpte)
{
   int was_downgraded = 0, idx;

   idx = find_pgdir(rem_cpu, gpgdir);
   if (idx != ARRAY_SIZE(rem_cpu->pgdirs)) {
      /* Look up the matching shadow page directory entry. */
      pgd_t *spgd = spgd_addr(rem_cpu, idx, vaddr);
      /* If the top level isn't present, there's no entry to update. */
      if (pgd_flags(*spgd) & _PAGE_PRESENT) {
         /* It's present. Per CREW rules, it must be write protected if
          * the access is a read. But if it's a write, then even read
          * permissions are disallowed. */
         pte_t *spte_ptr = spte_addr(*spgd, vaddr), spte_new;
         spte_new = gpte_to_spte(errcode & PF_WRITE ? __pte(0) : 
               pte_wrprotect(gpte));
         /* If this is a read access, and remote PTE is already
          * write-protected, then spte should remain unchanged, and hence
          * no downgrade need to be performed. */
         was_downgraded = (pte_write(spte_new) != pte_write(*spte_ptr));
         *spte_ptr = spte_new;
      }
   } else {
      /* Nothing to do. Shadow pagetable for gpgdir hasn't yet been
       * initialized on this CPU (because this CPU hasn't yet executed
       * the process using gpgdir). Since shadow ptes are initialized
       * with non-present state, gpgdir is, in essence, already
       * invalidated. */
   }

   return was_downgraded;
}

STATIC int
try_to_downgrade(struct msp_cpu *rem_cpu, pte_t gpte, int errcode)
{
   int was_downgraded = 0;
   unsigned long pfn = pte_pfn(gpte);
   struct ipt_entry *ipte;
   struct hlist_head *chain;
   struct hlist_node *node;

   ASSERT(rem_cpu != curr_sh);
   ASSERT(pte_present(gpte));
   ASSERT(pfn_valid(pfn));
   ASSERT(shadow_is_locked());
   ASSERT(ipt.pfn_map);

   chain = &ipt.pfn_map[hash_long(pfn, NR_BUCKET_BITS)];
   hlist_for_each_entry(ipte, node, chain, by_pfn) {
      if (ipte->pfn == pfn) {
         was_downgraded |= do_downgrade_work(rem_cpu, ipte->gpgdir, 
               fn_to_addr(ipte->vfn), errcode, gpte);
      }
   }

   return was_downgraded;
}

STATIC struct cpumask
do_crew_downgrade(pte_t gpte, unsigned long vaddr, int errcode)
{
   int i;
   unsigned long pfn = pte_pfn(gpte);
   struct cpumask down_mask;

   ASSERT(pte_present(gpte));
   ASSERT(pfn_valid(pfn));
   ASSERT(irqs_disabled());
   ASSERT(shadow_is_locked());
   ASSERT(vaddr < PAGE_OFFSET);

   for (i = 0; i < nr_cpu_ids; i++) {
      if (cpu_online(i) && i != smp_processor_id()) {
         int was_downgraded;
         struct msp_cpu *rem_cpu = &msp_state.cpus[i];
         was_downgraded = try_to_downgrade(rem_cpu, gpte, errcode);
         if (was_downgraded) {
            ASSERT(shadow_is_locked());
            /* Notify user-mode of the downgrade, while we have the
             * shadow lock, so that all CREW events for this transaction
             * occurs before those of the next transaction. */
            msp_event_t event;
            event.kind = MSP_EV_DOWNGRADE;
            event.pfn = pfn;
            event.vaddr = vaddr;
            event.timestamp = msp_state.clock++;
            event.cpu_id = smp_processor_id(); 
            msp_queue_event(event, rem_cpu);

            cpumask_set_cpu(i, &down_mask);
         }
      }
   }

   return down_mask;
}

STATIC_INLINE int
is_addr_in_vkernel(unsigned long vaddr)
{
   return msp_config.vkernel_len &&
      (msp_config.vkernel_start <= vaddr &&
       vaddr < msp_config.vkernel_start+msp_config.vkernel_len);
}

#if 1
/*H:330
 * (i) Looking up a page table entry when the Guest faults.
 *
 * We only set up the shadow page tables lazily as
 * they're needed, so we get page faults all the time and quietly fix them up
 * and return to the Guest without it knowing.
 *
 * If we fixed up the fault (ie. we mapped the address), this routine returns
 * true.  Otherwise, it was a real fault and we need to tell the Guest. */
STATIC int
demand_page(struct msp_cpu *cpu, unsigned long vaddr, int errcode, pte_t *gpte)
{
   pgd_t *gpgd;
   pgd_t *spgd;
   pte_t *gpte_ptr;
   pte_t *spte;

   /* We're about to screw with the shadow pagetables. We better have the
    * shadow lock. */
   ASSERT(cpu == curr_sh);
   ASSERT(shadow_is_locked());

   /* First step: get the top-level Guest page table entry. */
   gpgd = gpgd_addr(cpu, vaddr);
   ASSERT(gpgd);
   /* Toplevel not present?  We can't map it in. */
   if (!(pgd_flags(*gpgd) & _PAGE_PRESENT)) {
      return 0;
   }

   /* Now look at the matching shadow entry. */
   spgd = spgd_addr(cpu, cpu->cpu_pgd, vaddr);
   if (!(pgd_flags(*spgd) & _PAGE_PRESENT)) {
      unsigned long ptepage;
      /* No shadow entry: allocate a new shadow PTE page. */
      ASSERT(cpu->cpu_pgd >= 0 && cpu->cpu_pgd < NR_SHADOW_PGD);
      ASSERT(pgd_index(vaddr) < PTRS_PER_PGD);
      ptepage = (unsigned long)
         pte_pool[cpu->id][cpu->cpu_pgd][pgd_index(vaddr)];
      //DEBUG_MSG("ptepage=0x%x\n", ptepage);
      /* This is not really the Guest's fault, but killing it is
       * simple for this corner case. */
      BUG_ON(ptepage < PAGE_OFFSET);
      BUG_ON(ptepage & ~PAGE_MASK);
      if (!ptepage) {
         kill_guest(cpu, "out of memory allocating pte page");
         return 0;
		}
		/* We check that the Guest pgd is OK. */
		check_gpgd(cpu, *gpgd);
		/* And we copy the flags to the shadow PGD entry.  The page
		 * number in the shadow PGD is the page we just allocated. */
		*spgd = __pgd(__pa(ptepage) | pgd_flags(*gpgd));
	}
   ASSERT(pgd_flags(*spgd) & _PAGE_PRESENT);

	/* OK, now we look at the lower level in the Guest page table: keep its
	 * address, because we might update it later. */
	gpte_ptr = gpte_addr(*gpgd, vaddr);
   *gpte = *gpte_ptr;

	/* Check that the Guest PTE flags are OK. */
	check_gpte(cpu, *gpte);

	/* If this page isn't in the Guest page tables, we can't page it in. */
	if (!(pte_flags(*gpte) & _PAGE_PRESENT)) {
		return 0;
   }

	/* Check they're not trying to write to a page the Guest wants
	 * read-only (bit 2 of errcode == write). */
	if ((errcode & PF_WRITE) && !(pte_flags(*gpte) & _PAGE_RW)) {
		return 0;
   }

	/* User access to a kernel-only page? (bit 3 == user access) */
	if ((errcode & PF_USER) && !(pte_flags(*gpte) & _PAGE_USER)) {
		return 0;
   }

   /* Get the pointer to the shadow PTE entry we're going to set. */
   spte = spte_addr(*spgd, vaddr);
   /* If there was a valid shadow PTE entry here before, we release it.
    * This can happen with a write to a previously read-only entry. */
   clear_pte(spte);

   /* Add the _PAGE_ACCESSED and (for a write) _PAGE_DIRTY flag */
   *gpte = pte_mkyoung(*gpte);

   /* If this is a write, we insist that the Guest page is writable. */
   if (errcode & PF_WRITE) {
      *spte = gpte_to_spte(pte_mkdirty(*gpte));
   } else {
      /* If this is a read, don't set the "writable" bit in the page
       * table entry, even if the Guest says it's writable.  That way
       * we will come back here when a write does actually occur, so
       * we can update the Guest's _PAGE_DIRTY flag. */
      *spte = gpte_to_spte(pte_wrprotect(*gpte));
   }

   /* XXX: flush needed only if spte was already present. */
   __native_flush_tlb_single(vaddr);

   /* Finally, we write the Guest PTE entry back: we've set the
    * _PAGE_ACCESSED and maybe the _PAGE_DIRTY flags. */
   *gpte_ptr = *gpte;

   /* The fault is fixed, the page table is populated, the mapping
    * manipulated, the result returned and the code complete.  A small
    * delay and a trace of alliteration are the only indications the Guest
    * has that a page fault occurred at all. */
   return 1;
}

int
guest_page_fault(struct msp_cpu *cpu, unsigned long vaddr, int errcode)
{
   int is_shadow_fault, should_do_crew = 0;
   pte_t gpte;
   struct cpumask down_mask;
   uint64_t latest_clock;

   ASSERT(cpu == curr_sh);
   ASSERT(irqs_disabled());

   cpumask_clear(&down_mask);

   shadow_lock();

   if ((is_shadow_fault = demand_page(cpu, vaddr, errcode, &gpte))) {
      /* We don't want/need to do CREW on (v)kernel pages. */
      ASSERT(pte_present(gpte));
      ASSERT(pfn_valid(pte_pfn(gpte)));

      /* Don't do CREW if:
            - the faulting loc was a kernel or vkernel page
            - the fault was caused by the vkernel
            - XXX: what if kernel caused the fault?
               - must invalidate for correctness (otherwise, we will have 
               two WRITE mappings to phys page)
       */
      should_do_crew = (pte_user(gpte) && !is_addr_in_vkernel(vaddr) &&
            !is_addr_in_vkernel(current->thread.ip));

      if (should_do_crew) {
         msp_event_t event;

         // XXX: doesn't hold, we need a strategy for this
         // downgrades are still required, but need we provide upgrade
         // notification?
         //ASSERT_UNIMPLEMENTED(current->thread.ip < PAGE_OFFSET);

         /* At this point, the shadow pagetable for the current CPU has been
          * upgraded. But we still need to downgrade, if needed, the shadow 
          * pagetables of remote CPUs in accordance with the CREW protocol. */

         down_mask = do_crew_downgrade(gpte, vaddr, errcode);

         /* 
          * Q: We we need to notify of upgrade if others were not downgraded?
          * A: Yes. We need to record the event so that, during replay, 
          * we ensure this access happens before accesses that come after it.
          */

         /* We've queued the downgrade events. Now queue an upgrade event. */
         event.kind = MSP_EV_UPGRADE;
         event.vaddr = vaddr;
         event.pfn = pte_pfn(gpte);
         event.timestamp = msp_state.clock++;
         event.cpu_id = smp_processor_id();
         msp_queue_event(event, curr_sh);

         latest_clock = msp_state.clock;
      }
   }

   /* Don't re-enable IRQs, since this may be a vmalloc fault and
    * the faulting page hasn't been added to the gpgdir yet. */
   shadow_unlock();

   /* Must do invalidations and wait_queue notifications outside of the 
    * shadow lock to prevent deadlock. */
   if (should_do_crew) {
      int sent_to_current;
      if (!cpumask_empty(&down_mask)) {
         do_crew_invalidate(&down_mask, vaddr, errcode, gpte, latest_clock);
      }

#if 0
      siginfo_t si;
      memset(&si, 0, sizeof(si));
      si.si_signo = msp_config.signo;
      si.si_code = SI_MSP_UPGRADE;
      si.si_pid = task_pid_vnr(current);
      si.si_uid = current_uid();
#endif

      wake_up_interruptible(&curr_sh->read_waitqueue);
      sent_to_current = msp_kill_fasync(&curr_sh->fasync, SIGIO, POLL_IN);
      //ASSERT(sent_to_current);
   }

   ASSERT(irqs_disabled());
   return is_shadow_fault;
}
#endif

STATIC void
release_pgd(pgd_t *spgd)
{
   /* If the entry's not present, there's nothing to release. */
   if (pgd_flags(*spgd) & _PAGE_PRESENT) {
      unsigned int i;
      /* Converting the pfn to find the actual PTE page is easy: turn
       * the page number into a physical address, then convert to a
       * virtual address (easy for kernel pages like this one). */
      pte_t *ptepage = __va(pgd_pfn(*spgd) << PAGE_SHIFT);
      /* For each entry in the page, we might need to release it. */
      for (i = 0; i < PTRS_PER_PTE; i++) {
         clear_pte(&ptepage[i]);
      }

      /* And zero out the PGD entry so we never release it twice. */
      *spgd = __pgd(0);
   }
}

#if 0
static void
release_ipt(pdt_t gpgd)
{
   /* XXX: Map[pfn(gpte)].remove(()) */
}
#endif

/*H:445 We call this from new_pgdir() when we re-used a top-level pgdir page.
 * It simply releases every PTE page from 0 up to the Guest's kernel address. */
STATIC void
flush_user_mappings(struct msp_cpu *cpu, int idx)
{
   unsigned int i;
   pgd_t *msp_pgdir = cpu->pgdirs[idx].pgdir;
   if (msp_pgdir) {
      /* Release every pgd entry up to the kernel's address. */
      for (i = 0; i < pgd_index(PAGE_OFFSET); i++) {
         release_pgd(msp_pgdir + i);
      }
   }
}

/* Flushing (throwing away) page tables. */
void
guest_pagetable_flush_user(struct msp_cpu *cpu)
{
   unsigned long flags;

   spin_lock_irqsave(&msp_state.lock, flags);

   /* Drop the userspace part of the current page table. */
   flush_user_mappings(cpu, cpu->cpu_pgd);

   spin_unlock_irqrestore(&msp_state.lock, flags);
}

STATIC pteval_t
guest_pte_flags(struct msp_cpu *cpu, unsigned long vaddr)
{
	pgd_t *gpgd;
	pte_t *gpte;
	/* First step: get the top-level Guest page table entry. */
	gpgd = gpgd_addr(cpu, vaddr);
	/* Toplevel not present?  We can't read the pte flags. */
	if (!(pgd_flags(*gpgd) & _PAGE_PRESENT)) {
		return 0;
   }

	/* OK, now we look at the lower level in the Guest page table. */
	gpte = gpte_addr(*gpgd, vaddr);

   return pte_flags(*gpte);
}

/* So, when pin_kernel_pages() asks us to pin a page, we check if it's already
 * in the shadow page tables, and if not, we call demand_page() with the
 * appropriate error code to bring it in. The tricky part is in figuring
 * out which error code to use (0 : "read" or 2 : "write"). We don't
 * want to call guest_demand_page with more permissions than the guest
 * page allows, as that would cause it to fail (return 0). */
STATIC void
pin_page(struct msp_cpu *cpu, unsigned long vaddr)
{
   pte_t gpte;
   pteval_t gflags;
   gflags = guest_pte_flags(cpu, vaddr);
   if (gflags & _PAGE_PRESENT) {
#if 1
      if (!demand_page(cpu, vaddr, (gflags & _PAGE_RW ? PF_WRITE : 0), &gpte)) {
         kill_guest(cpu, "bad kernel page %#lx", vaddr);
      }
#endif
   }
}

STATIC void 
pin_kernel_pages(struct msp_cpu *cpu)
{
   unsigned long vaddr;
   struct pgdir *sdir = &cpu->pgdirs[cpu->cpu_pgd]; 

   ASSERT(cpu == curr_sh);
   ASSERT(curr_sh->guest_cr3);
   ASSERT(!sdir->is_kernel_mapped);

   /* XXX: pin vkernel pages too; no reason to take faults for those
    * since we aren't interesting in crew'ing them. */
   /* We expect vaddr to overflow after passing through the addrspace,
    * hence the != 0. */
   ASSERT(PAGE_OFFSET != 0);
   for (vaddr = PAGE_OFFSET; vaddr != 0; vaddr += PAGE_SIZE) {
      pin_page(cpu, vaddr);
   }
   sdir->is_kernel_mapped = true;
}

/*H:435 And this is us, creating the new page directory.  If we really do
 * allocate a new one (and so the kernel parts are not there), we set
 * blank_pgdir. */
STATIC unsigned int 
new_pgdir(struct msp_cpu *cpu, unsigned long gpgdir)
{
	unsigned int next;
   /* Find an unused pgdir, don't replace in-use ones as we originally
    * did. This makes the code more predicatable, and easier to debug. */
   next = find_pgdir(cpu, 0);
   if (next < ARRAY_SIZE(cpu->pgdirs)) {
      cpu->pgdirs[next].gpgdir = gpgdir;
      ASSERT(!cpu->pgdirs[next].is_kernel_mapped);
   } else {
      BUG_ON(1);
   }
#if 0
   /* No need to flush, since pgtable should be blank. */
   /* Release all the non-kernel mappings. */
   flush_user_mappings(cpu, next);
#endif
	return next;
}

/*H:430 (iv) Switching page tables
 *
 * Now we've seen all the page table setting and manipulation, let's see what
 * what happens when the Guest changes page tables (ie. changes the top-level
 * pgdir).  This occurs on almost every context switch. */
int
guest_new_pagetable(struct msp_cpu *cpu, unsigned long gpgdir)
{
	int idx;
   unsigned long flags;
   
   ASSERT(gpgdir);

   spin_lock_irqsave(&msp_state.lock, flags);

	/* See if we have this one already. */
	idx = find_pgdir(cpu, gpgdir);
	/* If not, we allocate or mug an existing one. */
	if (idx == ARRAY_SIZE(cpu->pgdirs)) {
		idx = new_pgdir(cpu, gpgdir);
   }
   BUG_ON(!cpu->pgdirs[cpu->cpu_pgd].pgdir);
	/* If it was completely blank, we must map in the Guest kernel pages,
    * for two reasons:
    *
    * 1. To avoid double-faults. The guest may fault, but if the kernel
    * stack and handler code pages are not mapped, then it will fault
    * again.
    *
    * 2. So we don't shadow fault on those--recall we are only interested in
    * shadowing user pages.
    */
	if (!cpu->pgdirs[idx].is_kernel_mapped) {
		pin_kernel_pages(cpu);
   }
   ASSERT(cpu->pgdirs[idx].is_kernel_mapped);

   spin_unlock_irqrestore(&msp_state.lock, flags);

   return idx;
}

STATIC void
release_pagetable(struct pgdir *pg)
{
   unsigned long cpgdir = native_read_cr3();
   pgd_t *spgdir = pg->pgdir;
   ASSERT(cpgdir);
   ASSERT(cpgdir != (unsigned long)__pa(pg->pgdir));

   if (spgdir) {
      unsigned int j;
      /* Every PGD entry. */
      for (j = 0; j < PTRS_PER_PGD; j++) {
         release_pgd(spgdir + j);
      }
   }
   pg->is_kernel_mapped = false;
}

/*H:470 Finally, a routine which throws away everything: all PGD entries in all
 * the shadow page tables, including the Guest's kernel mappings.  This is used
 * on those rare occasions where the Guest calls set_pte (which doesn't
 * tell us which pgdir changed, hence forcing us to be conservative). */
STATIC void 
release_all_pagetables(struct msp_cpu *cpu)
{
   unsigned int i;

   /* Every shadow pagetable this Guest has */
   for (i = 0; i < ARRAY_SIZE(cpu->pgdirs); i++) {
      release_pagetable(&cpu->pgdirs[i]);
   }
}

/* We also throw away everything when a Guest tells us it's changed a kernel
 * mapping.  Since kernel mappings are in every page table, it's easiest to
 * throw them all away.  This traps the Guest in amber for a while as
 * everything faults back in, but it's rare. */
void 
guest_pagetable_clear_all(struct msp_cpu *cpu, bool repin)
{
   unsigned long flags;

   spin_lock_irqsave(&msp_state.lock, flags);

   release_all_pagetables(cpu);
   if (repin) {
      /* We need the Guest kernel mapped again for the shadow page table that
       * we are currently using. */
      pin_kernel_pages(cpu);
   }

   spin_unlock_irqrestore(&msp_state.lock, flags);
}

/* When a Guest address space dies, our cleanup is fairly simple. */
void 
guest_free_pagetable(struct msp_cpu *cpu, unsigned long gpgdir)
{
	unsigned int i;
   unsigned long flags;

   spin_lock_irqsave(&msp_state.lock, flags);

   i = find_pgdir(cpu, gpgdir);
   if (i < ARRAY_SIZE(cpu->pgdirs)) {
      /* So guest_new_pagetable doesn't reuse an old one without flushing the
       * user mappings first. */

      ASSERT(native_read_cr3() != __pa(cpu->pgdirs[i].pgdir));
      cpu->pgdirs[i].gpgdir = 0;
      release_pagetable(&cpu->pgdirs[i]);
   } else {
      /* Guest never used this CPU, so we have nothing to free. */
   }

   spin_unlock_irqrestore(&msp_state.lock, flags);
}

/*H:420 This is the routine which actually sets the page table entry for the
 * "idx"'th shadow page table.
 *
 * Normally, we can just throw out the old entry and replace it with 0: if they
 * use it demand_page() will put the new entry in.  We need to do this anyway:
 * The Guest expects _PAGE_ACCESSED to be set on its PTE the first time a page
 * is read from, and _PAGE_DIRTY when it's written to.
 *
 * But Avi Kivity pointed out that most Operating Systems (Linux included) set
 * these bits on PTEs immediately anyway.  This is done to save the CPU from
 * having to update them, but it helps us the same way: if they set
 * _PAGE_ACCESSED then we can put a read-only PTE entry in immediately, and if
 * they set _PAGE_DIRTY then we can put a writable PTE entry in immediately.
 */
STATIC void
do_set_pte(struct msp_cpu *cpu, int idx, unsigned long vaddr, pte_t gpte)
{
	/* Look up the matching shadow page directory entry. */
	pgd_t *spgd = spgd_addr(cpu, idx, vaddr);

	/* If the top level isn't present, there's no entry to update. */
	if (pgd_flags(*spgd) & _PAGE_PRESENT) {
		/* Otherwise, we start by releasing the existing entry. */
		pte_t *spte = spte_addr(*spgd, vaddr);

		/* If they're setting this entry as dirty or accessed, we might
		 * as well put that entry they've given us in now.  This shaves
		 * 10% off a copy-on-write micro-benchmark. */
		if (pte_flags(gpte) & (_PAGE_DIRTY | _PAGE_ACCESSED)) {
			check_gpte(cpu, gpte);
			*spte = gpte_to_spte(gpte);
		} else {
			/* Otherwise kill it and we can demand_page() it in
			 * later. */
			*spte = __pte(0);
      }
   }
}


/*H:410 Updating a PTE entry is a little trickier.
 *
 * We keep track of several different page tables (the Guest uses one for each
 * process, so it makes sense to cache at least a few).  Each of these have
 * identical kernel parts: ie. every mapping above PAGE_OFFSET is the same for
 * all processes.  So when the page table above that address changes, we update
 * all the page tables, not just the current one.  This is rare.
 *
 * The benefit is that when we have to track a new page table, we can keep all
 * the kernel mappings.  This speeds up context switch immensely. */
void
guest_set_pte(struct msp_cpu *cpu, unsigned long gpgdir, unsigned long vaddr,
              pte_t gpte)
{
	/* Kernel mappings must be changed on all top levels.  Slow, but doesn't
	 * happen often. */
	if (vaddr >= PAGE_OFFSET) {
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(cpu->pgdirs); i++) {
         /* If pgdir i hasn't yet pinned its kernel mappings, then it
          * will see this mapping when it does. So no need to update. */
			if (cpu->pgdirs[i].pgdir && cpu->pgdirs[i].is_kernel_mapped) {
				do_set_pte(cpu, i, vaddr, gpte);
         }
      }
	} else {
		/* Is this page table one we have a shadow for? */
		int pgdir = find_pgdir(cpu, gpgdir);
		if (pgdir < ARRAY_SIZE(cpu->pgdirs)) {
			/* If so, do the update. */
			do_set_pte(cpu, pgdir, vaddr, gpte);
      } else {
         ASSERT(gpgdir);
         /* gpgdir may not be a guest that we are shadowing. This is
          * possible if the guest does a pte_update on another mm. */
      }
	}
}



/*H:400
 * (iii) Setting up a page table entry when the Guest tells us one has changed.
 *
 * Just like we did in interrupts_and_traps.c, it makes sense for us to deal
 * with the other side of page tables while we're here: what happens when the
 * Guest asks for a page table to be updated?
 *
 * We already saw that demand_page() will fill in the shadow page tables when
 * needed, so we can simply remove shadow page table entries whenever the Guest
 * tells us they've changed.  When the Guest tries to use the new entry it will
 * fault and demand_page() will fix it up.
 *
 * So with that in mind here's our code to to update a (top-level) PGD entry:
 */
void
guest_set_pmd(struct msp_cpu *cpu, unsigned long gpgdir, u32 idx)
{
	int pgdir;

	/* If they're talking about a page table we have a shadow for... */
	pgdir = find_pgdir(cpu, gpgdir);
	if (pgdir < ARRAY_SIZE(cpu->pgdirs)) {
		/* ... throw it away. */
		release_pgd(cpu->pgdirs[pgdir].pgdir + idx);
   }
}

STATIC void
msp_global_write_cr3(unsigned long pgdir)
{
   native_write_cr3(pgdir);
   /* Global TLB entries may still be hanging around. Nuke them. */
   __native_flush_tlb_global();
}

void
msp_load_msp_cr3(void)
{
   struct msp_cpu * cpu = curr_sh;
   int pgd_idx = cpu->cpu_pgd;
   bool is_in_use = cpu->pgdirs[pgd_idx].gpgdir != 0;
   unsigned long vpgdir = (unsigned long)cpu->pgdirs[pgd_idx].pgdir;

   ASSERT(is_in_use);

   BUG_ON(!cpu->pgdirs[pgd_idx].is_kernel_mapped);
   BUG_ON(!vpgdir);
   BUG_ON(vpgdir & ~PAGE_MASK);
   ASSERT(vpgdir >= PAGE_OFFSET);
   msp_global_write_cr3(__pa(vpgdir));
}

void
msp_switch_to(unsigned long gpgdir)
{
   /* Our CPUID interceptor should've disabled PSE. */
   ASSERT(!cpu_has_pse);
   ASSERT(gpgdir);

   if (MSP_find_guest(gpgdir) != -1) {
      int idx;
      curr_sh->guest_cr3 = gpgdir;
      idx = guest_new_pagetable(curr_sh, gpgdir);
      /* Change the current pgd index to the new one. */
      curr_sh->cpu_pgd = idx;
      msp_load_msp_cr3();
      //DEBUG_MSG("%d: switched to gpgdir=0x%lx\n", smp_processor_id(), gpgdir);
   } else {
      /* XXX: is this necessary?? are there any user-level PGE pages? */
      if (curr_sh->guest_cr3) {
         msp_global_write_cr3(gpgdir);
      } else {
         /* This is faster, since we don't do a PGE flush. */
         native_write_cr3(gpgdir);
      }
      /* Indicate that we aren't shadowing the gpgdir. */
      curr_sh->guest_cr3 = 0;
   }
}
