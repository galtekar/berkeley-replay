#include "public.h"

#include "memops.h"

#include <sys/mman.h>

void
SegOps_InitDesc(struct LinuxSegmentDesc *desc_ptr, int entry_no, 
                ulong start_addr, size_t len, int prot) {
   memset(desc_ptr, 0x0, sizeof(*desc_ptr));

   /* 0 is reserved for fail-fast null-dereference. */
   ASSERT(entry_no > 0);

   desc_ptr->entry_number = entry_no; 
   desc_ptr->base_addr = start_addr;
   desc_ptr->limit = PAGE_NUM(len);
   ASSERT(desc_ptr->limit <= 0xfffff);
   desc_ptr->seg_32bit = 1;
   desc_ptr->contents = 0 /* 0 == DATA, 1 == STACK, 2 == CODE */;
   desc_ptr->read_exec_only = (prot & PROT_WRITE) ? 0 : 1;
   desc_ptr->limit_in_pages = 1;
   desc_ptr->seg_not_present = 0;
   desc_ptr->useable = (prot == PROT_NONE) ? 0 : 1;
}

int
SegOps_InstallInLDT(struct LinuxSegmentDesc *desc_ptr)
{
   int err;

   err = SysOps_modify_ldt(1, desc_ptr, sizeof(*desc_ptr));
   
   return desc_ptr->entry_number > 0 && err == 0;
}

#define YSET_SEG_REG(regname, val) \
   asm ("movw %w0, %%" #regname :: "q" (val))
#define XSET_SEG_REG(regname, val) YSET_SEG_REG(regname, val)

/* Calculates the segmentation selector value corresponding
 * to LDT entry d. We know the index in the LDT, now load the segment
 * register. The use of the LDT is described by the value 7 in the lower
 * three bits of the segment descriptor value (if bit 3 == 1, then
 * lookups are done to the LDT rather than the GDT). The
 * 2 least-significant bits indicate RPL (3 in our case). */
#define LDT_ENTRY_NO_TO_SEGMENT_SELECTOR(d) ((d)*8 + 7)

void
SegOps_SetReg(int reg, int entry_no)
{
   int segment_selector = LDT_ENTRY_NO_TO_SEGMENT_SELECTOR(entry_no);

   DEBUG_MSG(5, "segment_selector=0x%x\n", segment_selector);

   switch (reg) {
      case 0:
         XSET_SEG_REG(ds, segment_selector);
         break;
      case 1:
         XSET_SEG_REG(es, segment_selector);
         break;
      case 2:
         XSET_SEG_REG(ss, segment_selector);
         break;
      default:
         ASSERT_UNIMPLEMENTED(0);
         break;
   }
}
