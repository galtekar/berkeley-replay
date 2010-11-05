/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <string.h>

#include <sys/mman.h>

#include "vkernel/public.h"
#include "private.h"

/* Calculates the segmentation register index corresponding
 * to GDT entry d. We know the index in the GDT, now load the segment
 * register. The use of the GDT is described by the value 3 in the lower
 * three bits of the segment descriptor value. */
#define GDT_ENTRY_TO_SEGMENT_INDEX(d) ((d)*8 + 3)


/* Get the value of the TLS segmentation register we are using. */
#define YGET_TLS_SEG_REG(regname) \
   ({ int __seg; asm ("movw %%" #regname ", %w0" : "=q" (__seg)); __seg & 0xffff; })
#define XGET_TLS_SEG_REG(regname) YGET_TLS_SEG_REG(regname)
#define GET_TLS_SEG_REG() XGET_TLS_SEG_REG(TSS)

/* Set the value of the TLS segmentation register we are using. */
#define YSET_TLS_SEG_REG(regname, val) \
   asm ("movw %w0, %%" #regname :: "q" (val))
#define XSET_TLS_SEG_REG(regname, val) YSET_TLS_SEG_REG(regname, val)
#define SET_TLS_SEG_REG(val) XSET_TLS_SEG_REG(TSS, val)

const ushort vkTssSelector = GDT_ENTRY_TO_SEGMENT_INDEX(VK_TLS_ENTRY_NR);

static struct LinuxSegmentDesc
TaskGetSegmentDesc(void *base) {
   struct LinuxSegmentDesc desc;

   ASSERT(base);
   memset(&desc, 0x0, sizeof(struct LinuxSegmentDesc));

   desc.entry_number = VK_TLS_ENTRY_NR;
   desc.base_addr = (unsigned long)base;
   desc.limit = 0xfffff;
   desc.seg_32bit = 1;
   desc.contents = 0;
   desc.read_exec_only = 0;
   desc.limit_in_pages = 1;
   desc.seg_not_present = 0;
   desc.useable = 1;

   return desc;
}

/* Make the thread struct accessible via a segmentation register.
 * This allows easy and efficient access to per-thread data. */
static void
TaskInstallTLSSegment(struct Task *ts)
{
   struct LinuxSegmentDesc desc;
   int ret;

   desc = TaskGetSegmentDesc(ts);
   DEBUG_MSG(7, "Installing task_struct at 0x%x, GDT %d (0x%x).\n",
             ts, desc.entry_number, vkTssSelector);
   ASSERT(desc.entry_number == VK_TLS_ENTRY_NR);

   ret = syscall(SYS_set_thread_area, &desc);
   if (ret != 0) {
      FATAL("set_thread_area returned %d.\n", ret);
   }

   /* Make sure the kernel gave us the entry we asked for. It
    * may not if someone else already requested it. */
   ASSERT(desc.entry_number == VK_TLS_ENTRY_NR);

   /* Load the vkernel TSS. Note that when we return to app-mode,
    * our TSS register may be loaded with a different segment selector.
    * That's okay, we'll load in our selector (tssSelector)
    * on next entrance. */
   SET_TLS_SEG_REG(vkTssSelector);
}

void FASTCALL
Task_SetupTLS(struct Task *tsk)
{
   TaskInstallTLSSegment(tsk);
}
