/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

/*
 * Summary:
 *    This module allows us to replay a DE-mode single-step execution
 *    in BT mode. It's useful for verifying that BT instruction
 *    emulation is precise (i.e., does the same thing as the
 *    emulated instruction. Without this precision, logging and
 *    replay may diverge.
 *
 */

static IRSB*
SsChkInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   return RegChk_Instrument(opaque, bbIn, layout, extents, gWorTy, hWordTy);
}

#if 0
static int
IsRegChkEnabled()
{
   config_setting_t *m;

   m = config_lookup(&cfgSession, "check.registers");

   if (m) {
      return 1;
   }

   return 0;
}
#endif

static struct Module mod = {
   .name       = "Single Step Check",
   .modeFlags  = 0xFFFFFFFF,
   .onStartFn  = NULL,
   .onTermFn   = NULL,
   .onForkFn   = NULL,
   .onExitFn   = NULL,
   .instrFn    = &SsChkInstrument,
   /* XXX: SsChk must be done after entry interception since Entry_*
    * wipes out all IR stmts of an RDTSC instruction and replaces it
    * with an exit. If we had a regchk callout there, that would get
    * wiped out too. */
   .order      = 6,
};

static int
SsChk_Init()
{
   if (VCPU_GetMode() & VCPU_MODE_SINGLESTEP) {
      if (0) {
         ASSERT(VCPU_IsReplaying() || VCPU_IsLogging());
         Module_Register(&mod);
      }
   }

   return 0;
}

BT_INITCALL(SsChk_Init);
