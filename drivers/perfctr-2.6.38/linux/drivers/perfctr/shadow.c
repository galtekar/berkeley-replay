#if 0
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/config.h>
#endif
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/perfctr.h>

#include <asm/io.h>
#include <asm/uaccess.h>

#include "compat.h"
#include "virtual.h"
#include "marshal.h"
#endif

#include <linux/mm.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/percpu.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/bootparam.h>

struct pgdir
{
	unsigned long gpgdir;
	pgd_t *pgdir;
};

struct shadow
{
   struct pgdir pgdirs[4];
};

struct shadow_cpu
{
	int cpu_pgd; /* which pgd this cpu is currently using */
   struct shadow *sh;
};

DEFINE_PER_CPU(struct shadow_cpu, cpus);

/* Helper macros to obtain the first 12 or the last 20 bits, this is only the
 * first step in the migration to the kernel types.  pte_pfn is already defined
 * in the kernel. */
#define pgd_flags(x)	(pgd_val(x) & ~PAGE_MASK)
#define pgd_pfn(x)	(pgd_val(x) >> PAGE_SHIFT)

/*H:460 And to complete the chain, release_pte() looks like this: */
static void release_pte(pte_t pte)
{
	/* Remember that get_user_pages_fast() took a reference to the page, in
	 * get_pfn()?  We have to put it back now. */
	if (pte_flags(pte) & _PAGE_PRESENT)
		put_page(pfn_to_page(pte_pfn(pte)));
}

/*H:450 If we chase down the release_pgd() code, it looks like this: */
static void release_pgd(struct shadow *sh, pgd_t *spgd)
{
	/* If the entry's not present, there's nothing to release. */
	if (pgd_flags(*spgd) & _PAGE_PRESENT) {
		unsigned int i;
		/* Converting the pfn to find the actual PTE page is easy: turn
		 * the page number into a physical address, then convert to a
		 * virtual address (easy for kernel pages like this one). */
		pte_t *ptepage = __va(pgd_pfn(*spgd) << PAGE_SHIFT);
		/* For each entry in the page, we might need to release it. */
		for (i = 0; i < PTRS_PER_PTE; i++)
			release_pte(ptepage[i]);
		/* Now we can free the page of PTEs */
		free_page((long)ptepage);
		/* And zero out the PGD entry so we never release it twice. */
		*spgd = __pgd(0);
	}
}


/*H:445 We saw flush_user_mappings() twice: once from the flush_user_mappings()
 * hypercall and once in new_pgdir() when we re-used a top-level pgdir page.
 * It simply releases every PTE page from 0 up to the Guest's kernel address. */
static void flush_user_mappings(struct shadow *sh, int idx)
{
	unsigned int i;
	/* Release every pgd entry up to the kernel's address. */
	for (i = 0; i < pgd_index(sh->kernel_address); i++)
		release_pgd(sh, sh->pgdirs[idx].pgdir + i);
}


/* We keep several page tables.  This is a simple routine to find the page
 * table (if any) corresponding to this top-level address the Guest has given
 * us. */
static unsigned int find_pgdir(struct shadow *sh, unsigned long pgtable)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(sh->pgdirs); i++)
		if (sh->pgdirs[i].pgdir && sh->pgdirs[i].gpgdir == pgtable)
			break;
	return i;
}

/*H:435 And this is us, creating the new page directory.  If we really do
 * allocate a new one (and so the kernel parts are not there), we set
 * blank_pgdir. */
static unsigned int new_pgdir(struct shadow_cpu *cpu,
			      unsigned long gpgdir,
			      int *blank_pgdir)
{
	unsigned int next;

	/* We pick one entry at random to throw out.  Choosing the Least
	 * Recently Used might be better, but this is easy. */
	next = random32() % ARRAY_SIZE(cpu->sh->pgdirs);
	/* If it's never been allocated at all before, try now. */
	if (!cpu->sh->pgdirs[next].pgdir) {
		cpu->sh->pgdirs[next].pgdir =
					(pgd_t *)get_zeroed_page(GFP_KERNEL);
		/* If the allocation fails, just keep using the one we have */
		if (!cpu->sh->pgdirs[next].pgdir)
			next = cpu->cpu_pgd;
		else
			/* This is a blank page, so there are no kernel
			 * mappings: caller must map the stack! */
			*blank_pgdir = 1;
	}
	/* Record which Guest toplevel this shadows. */
	cpu->sh->pgdirs[next].gpgdir = gpgdir;
	/* Release all the non-kernel mappings. */
	flush_user_mappings(cpu->sh, next);

	return next;
}

/*H:430 (iv) Switching page tables
 *
 * Now we've seen all the page table setting and manipulation, let's see what
 * what happens when the Guest changes page tables (ie. changes the top-level
 * pgdir).  This occurs on almost every context switch. */
void guest_new_pagetable(struct shadow_cpu *cpu, unsigned long pgtable)
{
	int newpgdir, repin = 0;

	/* Look to see if we have this one already. */
	newpgdir = find_pgdir(cpu->sh, pgtable);
	/* If not, we allocate or mug an existing one: if it's a fresh one,
	 * repin gets set to 1. */
	if (newpgdir == ARRAY_SIZE(cpu->sh->pgdirs))
		newpgdir = new_pgdir(cpu, pgtable, &repin);
	/* Change the current pgd index to the new one. */
	cpu->cpu_pgd = newpgdir;
	/* If it was completely blank, we map in the Guest kernel stack */
	if (repin)
		pin_stack_pages(cpu);
}

#if 0
void
shadow_on_pgd_alloc(struct mm_struct *mm)
{
#if 1
   int i;

   /* Allocate the shadow page tables. */
   for (i = 0; i < NR_CPUS; i++) {
      mm->shadow_pgd[i] = (pgd_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
      BUG_ON(!mm->shadow_pgd[i]);
   }
#endif
}

void
shadow_on_pgd_free(struct mm_struct *mm)
{
#if 1
   int i;

   /* Allocate the shadow page tables. */
   for (i = 0; i < NR_CPUS; i++) {
      BUG_ON(!mm->shadow_pgd[i]);
      mm->shadow_pgd[i] = free_page(mm->shadow_pgd[i]);
   }
#endif
}
#endif
