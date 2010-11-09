#include "vkernel/public.h"
#include "private.h"

/*
 * Summary:
 *
 * Routines that other modules can call to get info about symbolic
 * state (e.g., is a memory location tainted or not). The vkernel
 * debugger server stub, for example, uses these routines to respond 
 * with appropriate values to the debugger client.
 */

int
Cgen_GetRegByte(const struct Task *tsk_ptr, off_t reg_off, struct StateByte *sb_ptr)
{
   int err = 0;
   void *dataP;

   ASSERT(reg_off >= 0);
   ASSERT(reg_off < sizeof(TaskRegs));
   ASSERT_KPTR( tsk_ptr );

   D__;

   if (TaintMap_IsRegTainted(tsk_ptr, reg_off, 1, &dataP)) {
      const struct ByteVar *bvP = (struct ByteVar*)dataP;
      const struct CondVar *cvP = bvP->cvP;

      ASSERT_KPTR(bvP);

      sb_ptr->is_symbolic = 1;
      struct SymVar *svP = &sb_ptr->un.var;

      svP->byte = bvP->byte;
      svP->is_origin = (cvP->tag == CondVar_Origin);
      svP->name = cvP->name;
      svP->bb_exec_count = cvP->bbExecCount;
   } else {
      sb_ptr->is_symbolic = 0;
   }

   // Fill in the value no matter what, in case this is a
   // value-deterministic replay and clients want to inspect value
   // (e.g., taint-flow needs to do this)
   sb_ptr->un.val = Task_GetRegByte(curr_regs, reg_off);

   return err;
}

int
Cgen_GetMemByte(const struct Task *tsk_ptr, const void *base_ptr, 
                struct StateByte *sb_ptr)
{
   int err = 0;
   void *dataP;

   ASSERT_KPTR(tsk_ptr);
   // Controller state req for process B may be received by process A,
   // in which case process A must inquire about state in B's aspace.
   ASSERT_COULDBE(tsk_ptr == current);
   ASSERT_COULDBE(tsk_ptr != current);

   if ((ulong)base_ptr < PAGE_SIZE) {
      err = -EFAULT;
      goto out;
   }

   struct GAddrRange gaddr_ranges[MAX_NR_RANGES];
   int nr_ranges = MAX_NR_RANGES;
   const int is_read = 1;
   const size_t len = 1;
   size_t tr_len;

   tr_len = GlobalAddr_FromRange2(current->mm, gaddr_ranges, &nr_ranges,
         (ulong) base_ptr, len, is_read);
   if (tr_len != len) {
      ASSERT(tr_len < len);
      err = -EFAULT;
      goto out;
   }

   if (TaintMap_AreMemRangesTainted(gaddr_ranges, nr_ranges, &dataP)) {
      const struct ByteVar *bvP = (struct ByteVar*)dataP;
      const struct CondVar *cvP = bvP->cvP;
      struct SymVar *svP = &sb_ptr->un.var;

      ASSERT_KPTR(bvP);

      sb_ptr->is_symbolic = 1;

      svP->byte = bvP->byte;
      svP->is_origin = (cvP->tag == CondVar_Origin);
      svP->name = cvP->name;
      svP->bb_exec_count = cvP->bbExecCount;
   } else {
      sb_ptr->is_symbolic = 0;
   }

   // Fill in the value no matter what, in case this is a
   // value-deterministic replay and clients want to inspect value
   // (e.g., taint-flow needs to do this)
   if ((err = Task_GetMemByte(tsk_ptr, (ulong)base_ptr, 
               &sb_ptr->un.val))) {
      sb_ptr->is_symbolic = -EFAULT;
   }

out:
   return err;
}

int
Cgen_GetTaintMap(const struct Task *tsk_ptr, const void *base_ptr,
                 const size_t len, char *taint_map)
{
   int err = 0;
   void **dataPA = NULL;

   ASSERT_KPTR(tsk_ptr);
   ASSERT_COULDBE(tsk_ptr == current);
   ASSERT_COULDBE(tsk_ptr != current);

   if ((ulong)base_ptr < PAGE_SIZE) {
      err = -EFAULT;
      goto out;
   }

   struct GAddrRange gaddr_ranges[MAX_NR_RANGES];
   int nr_ranges = MAX_NR_RANGES;
   const int is_read = 1;
   size_t tr_len;

   tr_len = GlobalAddr_FromRange2(current->mm, gaddr_ranges, &nr_ranges,
         (ulong) base_ptr, len, is_read);
   if (tr_len != len) {
      ASSERT(tr_len < len);
      err = -EFAULT;
      goto out;
   }

   dataPA = malloc(sizeof(void*) * len);
   if (TaintMap_AreMemRangesTainted(gaddr_ranges, nr_ranges, dataPA)) {
      int i;
      for (i = 0; i < len; i++) {
         if (dataPA[i]) {
            taint_map[i] = (char)1;
         } else {
            taint_map[i] = (char)0;
         }
      }
   } else {
      memset(taint_map, 0, len);
   }
   free(dataPA);
   dataPA = NULL;

out:
   return err;
}

void
Cgen_TaintMemRegion(const void *base_ptr, const size_t len)
{
   cgMap_WriteOrigin((ulong)base_ptr, len);
}
