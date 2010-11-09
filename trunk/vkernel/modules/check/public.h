#pragma once

extern void Check_DoRegs(TaskRegs *);
extern int  Check_IsLogging();
extern int  Check_IsReplaying();


#define CHK_OPT_BRANCHES (1 << 0)
#define CHK_OPT_REGS     (1 << 1)
#define CHK_OPT_DEREFS   (1 << 2)
extern int
Check_InitLog(int *propFlagsP, int isLogging);




extern int
BrTrace_DoCond(struct BPred *bP, ulong currInsAddr, int isTaken);

extern ulong
BrTrace_DoIndirectJump(struct BPred *bP, ulong currInsAddr, ulong actualTargetAddr);

extern ulong
BrTrace_DoIndirectCall(struct BPred *bP, ulong currInsAddr, ulong actualTargetAddr, ulong retTargetAddr);

extern void
BrTrace_DoDirectCall(struct BPred *bP, ulong currInsAddr, ulong retTargetAddr);

extern ulong
BrTrace_DoRet(struct BPred *bP, ulong currInsAddr, ulong actualTargetAddr);
