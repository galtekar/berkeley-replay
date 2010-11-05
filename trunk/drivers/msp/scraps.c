

/*
 * Design notes:
 * - don't forget to remove previous entry for (gpgdir, vaddr), if any
 *
 * - if we are coming from a pte_update, we may not have access to the
 *   old gpte, so we can't rely on that for finding the original pfn.
 *   hence we need a scheme that doesn't rely on the original pfn.
 */
void
ipt_set_pte(struct shpt_cpu *cpu, unsigned long gpgdir, unsigned long vaddr,
            pte_t new_gpte)
{
#if 0
   unsigned long pfn = pte_pfn(gpte), vfn = vaddr >> PAGE_SHIFT;
   struct list_head *head = &shpt_state.ipt[pfn];
   struct ipt_entry *ent = NULL;

#error "XXX: this is wrong; old pfn may be different than new pfn"

   if (pte_present(gpte)) {
      /* PfnMap[pfn(gpte)].insert((gpgdir, vaddr))  */
      ent = kzalloc(sizeof(*ent), GFP_ATOMIC);
      ASSERT_UNIMPLEMENTED(ent);

      ent->gpgdir = gpgdir;
      ent->vfn = vfn;
      list_add_tail(&ent->list, head);
   } else {
      /* PfnMap[pfn(gpte)].remove((gpgdir, vaddr)) */
      struct ipt_entry *dummy;
      list_for_each_entry_safe(ent, dummy, head, list) {
         if (ent->gpgdir == gpgdir && ent->vfn == vfn) {
            list_del(&ent->list);
            kfree(ent);
         }
      }
   }
#elif 0
   /* First we remove the ipt entry for the old gpte (i.e., the one being
    * replaced by the new_gpte), if it was mapped to a physical page. 
    * Then we add the new entry, if it's valid. */
   if (pte_present(old_gpte)) {
      unsigned long old_pfn = pte_pfn(old_gpte);
      struct ipt_entry *dummy, *ent = NULL;

      ASSERT(pfn_valid(old_pfn));
      list_for_each_entry_safe(ent, dummy, &shpt_state.ipt[old_pfn], list) {
         if (ent->gpgdir == gpgdir && ent->vfn == vfn) {
            list_del(&ent->list);
            kfree(ent);
         }
      }
   }

   if (pte_present(new_gpte)) {
      unsigned long new_pfn = pte_pfn(new_gpte);
      struct ipt_entry *ent = NULL;

      ASSERT(pfn_valid(new_pfn));
      ent = kzalloc(sizeof(*ent), GFP_ATOMIC);
      ASSERT_UNIMPLEMENTED(ent);

      ent->gpgdir = gpgdir;
      ent->vfn = vfn;
      list_add_tail(&ent->list, &shpt_state.ipt[new_pfn]);
   }
#else
   /* Remove existing (gpgdir, vfn) entry, if any. */
   ent = ipt_lookup(gpgdir, vfn);
   ipt_del_entry(ent);

   if (pte_present(new_gpte)) {
      ipt_add_entry(pfn, gpgdir, vfn);
   }
#endif
}

void
ipt_pgd_free(unsigned long gpgdir)
{
#if 1
   int i;
   struct ipt_entry *ent, *dummy;

   /* PfnMap[pfn(gpte)].remove((gpgdir, *)) */

   /* XXX: we need a per gpgdir hash to speed this up. */
   for (i = 0; i < MAX_PHYS_PAGES; i++) {
      list_for_each_entry_safe(ent, dummy, &shpt_state.ipt[i], list) {
         if (ent->gpgdir == gpgdir) {
            ipt_del_entry(ent);
         }
      }
   }
#else
   /* GpgMap[gpgdir].remove_all() */
   list_for_each_entry_safe(ent, map[gpgdir], list) {
      ipt_del_entry(ent);
   }
#endif
}
