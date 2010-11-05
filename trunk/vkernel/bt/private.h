/*
 * Copyright (C) 2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#pragma once

/* And some more of our own.  These must not have the same values as
   those from libvex_trc_values.h.  (viz, 60 or below is safe). */
#define VK_TRC_BORING             29 /* no event; just keep going */
#define VK_TRC_INNER_FASTMISS     37 /* TRC only; means fast-cache miss. */
#define VK_TRC_INNER_COUNTERZERO  41 /* TRC only; means bb ctr == 0 */
#define VK_TRC_FAULT_SIGNAL       43 /* TRC only; got sigsegv/sigbus */
#define VK_TRC_INVARIANT_FAILED   47 /* TRC only; invariant violation */

#define TT_FAST_BITS 15
#define TT_FAST_SIZE (1 << TT_FAST_BITS)
#define TT_FAST_MASK ((TT_FAST_SIZE) - 1)

#ifndef __ASSEMBLER__

#define TT_FAST_HASH(_addr)  ((((ulong)(_addr))     ) & TT_FAST_MASK)

extern ASMLINKAGE void  BT_ResumeUserMode();
extern ASMLINKAGE void  BT_InnerLoop();
extern REGPARM(1) int   BT_HandleErrorCode(uint trc);
extern void             BT_TranslateBlock(ulong bblAddr, uchar* codeBuf, 
                           size_t codeBufSz, int *codeBufSzUsed,
                           VexGuestExtents *vge);

extern void    TrnsTab_HandleFastMiss();



extern struct ListHead moduleList;
#define for_each_module() { \
   struct Module *modp; \
   list_for_each_entry(modp, &moduleList, list) {

#define end_for_each_module }}



#endif /* __ASSEMBLER */
