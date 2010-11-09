#pragma once

/* SSchk calls this. */
extern IRSB*
RegChk_Instrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy);

extern int BrChk_Init();
extern int RegChk_Init();
extern int DerefChk_Init();

extern int     checkIsLogging;

extern int flipTaskId;
extern u64 flipBrCnt;