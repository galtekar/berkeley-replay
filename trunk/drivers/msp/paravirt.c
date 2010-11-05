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


/* cr3 is the current toplevel pagetable page. Keep a local copy, and tell 
 * the Host when it changes. */
STATIC void 
msp_write_cr3(unsigned long cr3)
{
   msp_switch_to(cr3);
}

STATIC unsigned long 
msp_read_cr3(void)
{
   /* Is shadowing enabled? */
   if (curr_sh->guest_cr3) {
      /* Simply return the shadow cr3. */
      return curr_sh->guest_cr3;
   } else {
      return native_read_cr3();
   }
}

/* The Guest calls this to set a second-level entry (pte), ie. to map a page
 * into a process' address space.  We set the entry then tell the Host the
 * toplevel and address this corresponds to.  The Guest uses one pagetable per
 * process, so we need to tell the Host which one we're changing (mm->pgd). */

/* This is called after guest has updated entry. */
STATIC void 
msp_pte_update(struct mm_struct *mm, unsigned long vaddr, pte_t *ptep)
{
   unsigned long flags;
   unsigned long gpgdir = __pa(mm->pgd);

   ASSERT(gpgdir);

   shadow_lock_irqsave(flags);

   if (curr_sh->guest_cr3) {
      /* We don't update the guest pte, as done below, because this callback
       * is made after the guest updates a pte ( see, e.g.,
       * ptep_set_wrprotect() ). Hence this callback is made to signal that an
       * update has been made to the guest page tables.. */
      guest_set_pte(curr_sh, gpgdir, vaddr, *ptep);

      /* Must flush entry from TLB, since kernel doesn't seem to do it. 
       * XXX: is this necessary? */
      __native_flush_tlb_single(vaddr);
   } else {
      /* No op; this mirrors what is done in paravirt.c. */
   }

#if ENABLE_IPT_CODE
   /* We do CREW only on user pages, so this check saves some
    * memory. */
   if (vaddr < PAGE_OFFSET && (IPT_ENABLE_ALL /*XXX: || registered(gpgdir)*/)) {
      ipt_set_pte(gpgdir, vaddr, *ptep);
   }
#endif

   shadow_unlock_irqrestore(flags);
}

STATIC void 
msp_set_pte_at(struct mm_struct *mm, unsigned long vaddr,
      pte_t *ptep, pte_t pteval)
{
   native_set_pte_at(mm, vaddr, ptep, pteval);
   msp_pte_update(mm, vaddr, ptep);
}

/* There are a couple of legacy places where the kernel sets a PTE, but we
 * don't know the top level any more.  This is useless for us, since we don't
 * know which pagetable is changing or what address, so we just tell the Host
 * to forget all of them.  Fortunately, this is very rare (though it does
 * happen, even after boot).
 *
 * ... except in early boot when the kernel sets up the initial pagetables,
 * which makes booting astonishingly slow: 1.83 seconds! */
STATIC void 
msp_set_pte(pte_t *ptep, pte_t pteval)
{
   native_set_pte(ptep, pteval);

   /* XXX: access to nr_guests needs to be protected. */
   /* XXX: actually, we need only do this while shadowing is active--that
    * is, when there is at least one shadowed process. Without doing this,
    * bootup becomes really slow. */
   if (msp_state.nr_guests) {
      /* Forget all the pagetables. We must do this even when executing 
       * non-shadowed processes, since they may have changed the kernel 
       * mappings (e.g., by using highmem). If we don't, then the shadow 
       * mappings will not be updated, and bad stuff (e.g., double-fault) 
       * happens. */
      bool repin = curr_sh->guest_cr3 != 0;
      guest_pagetable_clear_all(curr_sh, repin);
      __native_flush_tlb_global();
   }
}


/* The Guest calls this to set a top-level entry.  Again, we set the entry then
 * tell the Host which top-level page we changed, and the index of the entry we
 * changed. Unlike set_pte, we can identify the target guest pgdir. */
STATIC void 
msp_set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
   unsigned long gpgdir = __pa(pmdp) & PAGE_MASK, flags;
   int idx = (__pa(pmdp)&(PAGE_SIZE-1))/4;
   unsigned long start_vaddr = idx << PGDIR_SHIFT;

   native_set_pmd(pmdp, pmdval);

   shadow_lock_irqsave(flags);

   if (curr_sh->guest_cr3) {
      guest_set_pmd(curr_sh, gpgdir, idx);
   }
#if ENABLE_IPT_CODE
   if (start_vaddr < PAGE_OFFSET && 
         IPT_ENABLE_ALL/*XXX: || registered(gpgdir)*/) {
      ipt_set_pmd(gpgdir, start_vaddr, pmdval);
   }
#endif

   shadow_unlock_irqrestore(flags);
}

STATIC void
msp_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
#if ENABLE_IPT_CODE
   unsigned long flags;
   shadow_lock_irqsave(flags);

   ipt_pgd_free(__pa(pgd));

   shadow_unlock_irqrestore(flags);
#endif
}

/* Unfortunately for us, the pv_mmu_ops for page tables were based on
 * native page table operations.  On native hardware you can set a new page
 * table entry whenever you want, but if you want to remove one you have to do
 * a TLB flush (a TLB is a little cache of page table entries kept by the CPU).
 *
 * So the msp_set_pte_at() and msp_set_pmd() functions above are only
 * called when a valid entry is written, not when it's removed (ie. marked not
 * present).  Instead, this is where we come when the Guest wants to remove a
 * page table entry: we tell the Host to set that entry to 0 (ie. the present
 * bit is zero). */
STATIC void
msp_flush_tlb_single(unsigned long vaddr)
{
   if (curr_sh->guest_cr3) {
      /* Simply set it to zero: if it was not, it will fault back in. */
      guest_set_pte(curr_sh, curr_sh->guest_cr3, vaddr, __pte(0));
   } 
   /* We flush the page regardless of whether we are shadowing or not. */
   __native_flush_tlb_single(vaddr);
}

/* This is what happens after the Guest has removed a large number of entries.
 * This tells the Host that any of the page table entries for userspace might
 * have changed, ie. virtual addresses below PAGE_OFFSET. */
STATIC void
msp_flush_tlb_user(void)
{
   if (curr_sh->guest_cr3) {
      guest_pagetable_flush_user(curr_sh);
   } 
   /* We flush the entire TLB (excluding global entries if PGE is enabled)
    * regardless of whether we are shadowing or not. */
   __native_flush_tlb();
}

/* This is called when the kernel page tables have changed.  That's not very
 * common (unless the Guest is using highmem, which makes the Guest extremely
 * slow), so it's worth separating this from the user flushing above. */
STATIC void
msp_flush_tlb_kernel(void)
{
   if (curr_sh->guest_cr3) {
      guest_pagetable_clear_all(curr_sh, true);
   }

   /* Flush all entries, even those marked global (assuming PGE is
    * enabled, which it should be per our CPUID emulation). */
   __native_flush_tlb_global();
}

int
msp_on_page_fault(unsigned long vaddr, unsigned long error_code)
{
   int success = 0;

   ASSERT(irqs_disabled() && !preemptible());

#if 1
   if (curr_sh->guest_cr3) {
      ASSERT(msp_state.is_initialized);
      success = guest_page_fault(curr_sh, vaddr, error_code);
   }
#endif
   return success;
}

/*
 * XXX: We intercept CPUID so that we can disable PAE and PSE/PSE-36 support, 
 * as they are currently unimplemented (we assume a two-level pagetable and 4KB
 * pages). We shouldn't need to do this in future version, though its
 * questionable how effective CREW will be with PSE (4MB pages) due to
 * greater false-sharing. */
STATIC void 
msp_cpuid(unsigned int *ax, unsigned int *bx,
      unsigned int *cx, unsigned int *dx)
{
   int function = *ax;

   native_cpuid(ax, bx, cx, dx);
   switch (function) {
	case 1:	/* Basic feature request. */
      /* Disable PAE, PSE-36, PSE. */
		*dx &= ~((1 << 17) | (1 << 6) | (1 << 3));
      break;
   default:
      break;
   }
}


/*
 * We must specify a patch routine since paravirt's default patch routine
 * directly patches write_cr3 with it's assembly counterpart rather than
 * calling msp_write_cr3. 
 *
 * XXX: this is inefficient; insns like ctls can be patched in the native
 * way since we don't need to intercept them. Copy in the native code and
 * modify appropriately.
 * */
STATIC unsigned
msp_patch(u8 type, u16 clobber, void *ibuf, unsigned long addr, unsigned len)
{
   /* Don't do anything fancy, just patch it with a direct function call. */
   return paravirt_patch_default(type, clobber, ibuf, addr, len);
}

void
paravirt_init(void)
{
   short kernel_cs;

   /* We're under msp_guest, paravirt is enabled, and we're running at
    * privilege level 0 as normal. */
   pv_info.name = "MSP";
   pv_info.paravirt_enabled = 1;

   savesegment(cs, kernel_cs);
   pv_info.kernel_rpl = kernel_cs & SEGMENT_RPL_MASK;
   /* Essential to specify a patching routine; default routine does not
    * invoke our supplied write_cr3()!! */
   pv_init_ops.patch = msp_patch;

   //pv_init_ops.arch_setup = msp_arch_setup;
   pv_cpu_ops.cpuid = msp_cpuid;

   /* Pagetable management. */
   pv_mmu_ops.write_cr3 = msp_write_cr3;
   pv_mmu_ops.read_cr3 = msp_read_cr3;

   /* no need to intercept read_cr2, since guest receives page fault
    * and is priviledged enough to see it. This is unlike a true 
    * hypervisor (e.g., lguest), where the host receives the page 
    * fault). */
   pv_mmu_ops.flush_tlb_user = msp_flush_tlb_user;
   pv_mmu_ops.flush_tlb_single = msp_flush_tlb_single;
   pv_mmu_ops.flush_tlb_kernel = msp_flush_tlb_kernel;

   pv_mmu_ops.set_pte = msp_set_pte;
   pv_mmu_ops.set_pte_at = msp_set_pte_at;
   pv_mmu_ops.set_pmd = msp_set_pmd;
   pv_mmu_ops.pte_update = msp_pte_update;
   pv_mmu_ops.pte_update_defer = msp_pte_update;
   pv_mmu_ops.pgd_free = msp_pgd_free;
}
