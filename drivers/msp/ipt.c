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

struct ipt_struct ipt;

STATIC void
ipt_add_entry(unsigned long pfn, unsigned long gpgdir, unsigned long vfn)
{
   struct hlist_head *pfn_head, *gpv_head, *gp_head;
   struct ipt_entry *ipte = kzalloc(sizeof(*ipte), GFP_ATOMIC);
   ASSERT_UNIMPLEMENTED(ipte);

   ipte->gpgdir = gpgdir;
   ipte->vfn = vfn;
   ipte->pfn = pfn;

   /* Add to pfn hash (for pfn-based lookup). */
   pfn_head = &ipt.pfn_map[hash_long(pfn, NR_BUCKET_BITS)];
   hlist_add_head(&ipte->by_pfn, pfn_head);

   /* Add to (gpgdir, vfn) hash (for fast pte removal). */
   gpv_head = &ipt.gpv_map[hash_long(gpgdir ^ vfn, 
         NR_BUCKET_BITS)];
   hlist_add_head(&ipte->by_gpgdir_and_vfn, gpv_head);

   /* Add to (gpgdir) hash (for fast pgd_free). */
   gp_head = &ipt.gp_map[hash_long(gpgdir, 
         NR_BUCKET_BITS)];
   hlist_add_head(&ipte->by_gpgdir, gp_head);

   ipt.nr_iptes++;
}

STATIC void
ipt_del_entry(struct ipt_entry *ipte)
{
   hlist_del(&ipte->by_pfn);
   hlist_del(&ipte->by_gpgdir_and_vfn);
   hlist_del(&ipte->by_gpgdir);

   ipt.nr_iptes--;

   kfree(ipte);
}

/*
 * Design notes:
 * - don't forget to remove previous entry for (gpgdir, vaddr), if any
 *
 * - if we are coming from a pte_update, we may not have access to the
 *   old gpte, so we can't rely on that for finding the original pfn.
 *   hence we need a scheme that doesn't rely on the original pfn.
 */
void
ipt_set_pte(unsigned long gpgdir, unsigned long vaddr, pte_t new_gpte)
{
   struct hlist_node *node, *dummy;
   struct hlist_head *chain;
   struct ipt_entry *ipte;
   unsigned long vfn = addr_to_fn(vaddr);

   ASSERT(vaddr < PAGE_OFFSET);

   /* Remove existing (gpgdir, vfn) entry, if any. */
   /* XXX: check that we don't find more than one match. */
   chain = &ipt.gpv_map[hash_long(gpgdir ^ vfn, 
         NR_BUCKET_BITS)];
   hlist_for_each_entry_safe(ipte, node, dummy, chain, by_gpgdir_and_vfn) {
      if (ipte->gpgdir == gpgdir && ipte->vfn == vfn) {
         ipt_del_entry(ipte);
      }
   }

   if (pte_present(new_gpte)) {
      unsigned long pfn = pte_pfn(new_gpte);
      ipt_add_entry(pfn, gpgdir, vfn);
   }
}

void
ipt_set_pmd(unsigned long gpgdir, unsigned long start_vaddr, 
            pmd_t new_pmde)
{
   /* The key observation here is that the range of virtual addresses
    * mapped by this pmd is fixed and independent of the contents of the
    * pte (old or new). */

#if PAGETABLE_LEVELS == 2
   /* XXX: optimization: nothing needs to be done if there is no change 
    * in PFN. */
   int i;
   unsigned long start_vfn = addr_to_fn(start_vaddr);

   pte_t *ptepage = __va(fn_to_addr(pmd_pfn(new_pmde)));
   for (i = 0; i < PTRS_PER_PTE; i++) {
      ipt_set_pte(gpgdir, fn_to_addr(start_vfn+i), 
            pmd_present(new_pmde) ? ptepage[i] : __pte(0));
   }
#elif PAGETABLE_LEVELS > 2
#error "XXX: unimplemented"
#endif
}


void
ipt_pgd_free(unsigned long gpgdir)
{
   struct ipt_entry *ipte;
   struct hlist_node *node, *dummy;
   struct hlist_head *gpgdir_chain = 
      &ipt.gp_map[hash_long(gpgdir, NR_BUCKET_BITS)];
   unsigned long nr_freed = 0;

   ASSERT(ipt.gp_map);
   hlist_for_each_entry_safe(ipte, node, dummy, gpgdir_chain, by_gpgdir) {
      if (ipte->gpgdir == gpgdir) {
         ASSERT(fn_to_addr(ipte->vfn) < PAGE_OFFSET);
         ipt_del_entry(ipte);
         nr_freed++;
      }
   }

   /* Usually, none are freed, since all mmaped ptes are removed when the 
    * address space is torn down. */
   ASSERT(nr_freed == 0 || nr_freed != 0);

   //DEBUG_MSG_LIMIT("pgd_free(0x%lx): %ld entries freed, %ld entries left\n", 
   //     gpgdir, nr_freed, ipt.nr_iptes);
}

int
ipt_init()
{
   int i;

#if !IPT_ENABLE_ALL
   if (!(ipt.pfn_map =
            kmalloc(sizeof(struct hlist_head) * NR_BUCKETS, GFP_KERNEL))) {
      return -ENOMEM;
   }

   if (!(ipt.gpv_map = 
            kmalloc(sizeof(struct hlist_head) * NR_BUCKETS, GFP_KERNEL))) {
      return -ENOMEM;
   }

   if (!(ipt.gp_map =
            kmalloc(sizeof(struct hlist_head) * NR_BUCKETS, GFP_KERNEL))) {
      return -ENOMEM;
   }
#endif

   for (i = 0; i < NR_BUCKETS; i++) {
      INIT_HLIST_HEAD(&ipt.pfn_map[i]);
      INIT_HLIST_HEAD(&ipt.gpv_map[i]);
      INIT_HLIST_HEAD(&ipt.gp_map[i]);
   }

   return 0;
}
