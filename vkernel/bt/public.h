/*
 * Copyright (C) 2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#pragma once

#include "libvex_guest_x86.h"

struct Task;
struct VmaStruct;
struct FileStruct;
struct CopySource;

extern void          BT_Fork(struct Task *tsk);
extern void          BT_Exit(struct Task *tsk);
extern void          BT_Exec();
extern VexGuestX86SegDescr*   BT_AllocZeroedX86GDT();

extern void    TrnsTab_OnVmaUnmap(const struct VmaStruct *vma, ulong start, 
                                  size_t len);
extern void    TrnsTab_Invalidate(ulong start, size_t len);
extern void    TrnsTab_InvalidateAll();
extern void    TrnsTab_Fork(struct Task *tsk);
extern void    TrnsTab_SelfInit();
extern int     TrnsTab_Init();

extern IRSB*
PreEx_Instr(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy);

struct MemTrace {
   struct ExecPoint ep;
};

struct BinTransStruct {
   void *brPredP;


   /* XXX: should be in struct RegChk struct. */
   ulong repCount;
   struct MemTrace memTrace;
};

typedef enum {
   Bpk_Static = 0x1000,
   Bpk_Dynamic,
} BPKind;

typedef void (*BkptCbFn)(void *arg);
struct Brkpt {
   struct MapField taskMap;
   struct MapField mmMap;

   struct ExecPoint ep;

   /* Callback to invoke upon notify. */
   BkptCbFn callback;
   void *arg;
   BPKind kind;
};

static INLINE u64
Brkpt_GetBrCnt(struct Brkpt *ev)
{
   return ev->ep.brCnt;
}

extern ullong  Brkpt_CalcNrBranchesTillHit(struct Brkpt *brkP);
extern struct  Brkpt * Brkpt_PeekFirst();
extern int     Brkpt_SetAbsolute(BPKind bpKind, const struct ExecPoint *locP, 
                  BkptCbFn cbP, void *argP);
extern int     Brkpt_RmAbsolute(BPKind bpKind, const struct ExecPoint *locP);
extern int     Brkpt_SetRelative(int nrInsnsTillBrkpt, BkptCbFn cbP, 
                  void *argP);

static INLINE void
Brkpt_SetStatic(ulong ip, BkptCbFn cbP, void *argP)
{
   struct ExecPoint ep = { .eip = ip, .ecx = 0, .brCnt = 0 };
   Brkpt_SetAbsolute(Bpk_Static, &ep, cbP, argP);
}

static INLINE int
Brkpt_RmStatic(ulong ip)
{
   struct ExecPoint ep = { .eip = ip, .ecx = 0, .brCnt = 0 };
   return Brkpt_RmAbsolute(Bpk_Static, &ep);
}

extern void    RegChk_Check(TaskRegs *regs);

static INLINE int
BinTrns_IsIndirectExit(IRSB *bb)
{
   int isIndirect = 0;

   switch (bb->next->tag) {
   case Iex_RdTmp:
      isIndirect = 1;
      break;
   case Iex_Const:
      isIndirect = 0;
      ASSERT(bb->jumpkind != Ijk_Ret);
      break;
   default:
      ASSERT(0);
      break;
   }

   return isIndirect;
}

static INLINE int
BinTrns_IsSyscall(IRJumpKind jmpKind)
{
   switch (jmpKind) {
   case Ijk_Sys_int128:
      return 1;
      break;
   case Ijk_Sys_syscall:
   case Ijk_Sys_int32:
   case Ijk_Sys_sysenter:
      ASSERT_UNIMPLEMENTED(0);
      return 0;
      break;
   default:
      return 0;
      break;
   }
}

static INLINE int
BinTrns_IsTrap(IRJumpKind jmpKind)
{
   return jmpKind == Ijk_SigTRAP;
}

/*
 * Is the jump kind considered a branch by the x86 hardware?
 *
 * Observe that Ijk_MapFail is a VEX instrumented branch, so this
 * function does not consider it a x86 branch op.
 */
static INLINE int
BinTrns_IsBranch(IRJumpKind jmpKind)
{
   switch (jmpKind) {
   case Ijk_Boring:
   case Ijk_Call:
   case Ijk_Ret:
      return 1;
      break;
   case Ijk_MapFail:
   default:
      return 0;
      break;
   }
}

/*
 * Should the jump be traced?
 *
 * Ijk_MapFail is traced here, unlike the above, making this suitable for
 * formgen's path-enforced execution.
 */
static INLINE int
BinTrns_IsTracedBranch(IRJumpKind jmpKind)
{
   switch (jmpKind) {
   case Ijk_Boring:
   case Ijk_Call:
   case Ijk_Ret:
   case Ijk_MapFail:
      return 1;
      break;
   default:
      return 0;
      break;
   }
}


static INLINE int
BinTrns_IsRepPrefix(ulong pc)
{
   void *pcp = (void*) pc;
   uchar *byte = (uchar*) pcp;
   int res;

   switch (*byte) {
   case 0xF2:
   case 0xF3:
      res = 1;
      break;
   default:
      res = 0;
      break;
   };

   return res;
}

static INLINE int
BinTrns_IsRDTSC(ulong pc)
{
   ushort *s = (ushort *) pc;
   int res = 0;

   switch (*s) {
      /* RDTSC opcode */
   case 0x310F:
      res = 1;
      break;
   default:
      res = 0;
      break;
   }

   return res;
}

static INLINE IRDirty *
BinTrns_DirtyHelperThatReadsExecPoint(Int regparms, HChar* name, void* addr, 
                          IRExpr **args)
{
   IRDirty *dirty;

   dirty = unsafeIRDirty_0_N(regparms, name, addr, args);

   dirty->needsBBP = True;

   dirty->nFxState = 2;
   dirty->fxState[0].fx = Ifx_Read;
   dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_EIP);
   dirty->fxState[0].size = sizeof(ulong);
   dirty->fxState[1].fx = Ifx_Read;
   dirty->fxState[1].offset = offsetof(VexGuestX86State, guest_ECX);
   dirty->fxState[1].size = sizeof(ulong);

   return dirty;
}

static INLINE IRDirty *
BinTrns_DirtyHelperThatModifiesRegs(Int regparms, HChar* name, void* addr, 
                          IRExpr **args)
{
   IRDirty *dirty;

   dirty = unsafeIRDirty_0_N(regparms, name, addr, args);

   dirty->needsBBP = True;
   dirty->nFxState = 1;

   /* We'll need to save all GPRs + EIP; no FP regs */
   dirty->fxState[0].fx = Ifx_Modify;
   dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_EAX);
   dirty->fxState[0].size = offsetof(VexGuestX86State, guest_IP_AT_SYSCALL) -
      offsetof(VexGuestX86State, guest_EAX);

   return dirty;
}

static INLINE IRDirty *
BinTrns_DirtyHelperThatReadsRegs(Int regparms, HChar* name, void* addr, 
                          IRExpr **args)
{
   IRDirty *dirty;

   dirty = unsafeIRDirty_0_N(regparms, name, addr, args);

   dirty->needsBBP = True;
   dirty->nFxState = 1;

   /* We'll need to save all GPRs + EIP; no FP regs */
   dirty->fxState[0].fx = Ifx_Read;
   dirty->fxState[0].offset = offsetof(VexGuestX86State, guest_EAX);
   dirty->fxState[0].size = offsetof(VexGuestX86State, guest_IP_AT_SYSCALL) -
      offsetof(VexGuestX86State, guest_EAX);

   return dirty;
}

static INLINE int
BinTrns_IsValidDirtyArgType(IRType ty)
{

   return (ty == Ity_I32) ||
          (ty == Ity_I64);
}

extern IRExpr *
BT_ArgFixup(IRSB *bbP, IRExpr *expP);

extern IRDirty* 
BT_UnsafeIRDirty_0_N ( IRSB *bbP, HChar* name, void* addr, 
                             IRExpr** args );

#define MACRO_BT_UnsafeIRDirty_0_N(bbP, name, args) \
   BT_UnsafeIRDirty_0_N(bbP, #name, &name, args)

extern IRDirty* 
BT_UnsafeIRDirty_1_N ( IRSB *bbP, IRTemp dst, 
      HChar* name, void* addr, IRExpr** args );

typedef enum {
   Vek_Map = 0xc001,
   Vek_Unmap,
   Vek_PreProtect,
   Vek_PostProtect,
} VmaEventKind;


typedef IRSB*   (*VexInstrument) ( /*callback_opaque*/void*, 
                               IRSB*, 
                               VexGuestLayout*, 
                               VexGuestExtents*,
                               IRType gWordTy, IRType hWordTy );
typedef void (*StartFn)(void);
typedef void (*TermFn)(void);
typedef void (*ExecFn)(void);
typedef void (*ForkFn)(struct Task*);
typedef void (*ExitFn)(struct Task*);
typedef void (*VmaEventFn)(const VmaEventKind evk, const struct VmaStruct *vmaP,
                           const ulong istart, const size_t ilen);
typedef void (*VmaForkFn)(struct Task *tskP, const struct VmaStruct *);
typedef void (*ShutdownFn)(void);
typedef void (*UserCopyFn)(
      const int isFrom, 
      const struct CopySource *srcP, 
      const struct IoVec *iov_ptr,
      const size_t total_len);
typedef void
(*OnFileEventFn)(VkEventTag tag, struct FileStruct *filp);
typedef void (*RegCopyFn)(
      const int isRead,
      const struct CopySource *srcP, 
      const uint off,
      const size_t totalLen);
typedef int  (*ProtFaultFn)(const ulong faultAddr);
typedef void (*SysFn)();
typedef void (*OnResumeUserFn)();
typedef int (*ClientReqFn)(const int, const HWord *, HWord *);


struct Module
{
   char           name[256];

   /* In what vk mode (e.g., log or replay mode) should this
    * instrFnumentation be done? */
   int            modeFlags;

   StartFn        onStartFn;
   TermFn         onTermFn;
   ExecFn         onExecFn;
   ForkFn         onForkFn;
   ExitFn         onExitFn;
   VmaEventFn     onVmaEventFn;
   VmaForkFn      onVmaForkFn;
   ShutdownFn     onShutdownFn;
   VexInstrument  instrFn;
   UserCopyFn     onUserCopyFn;
   OnFileEventFn  onFileEventFn;
   RegCopyFn      onRegCopyFn;
   ProtFaultFn    onProtFaultFn;
   SysFn          onPreSysFn;
   SysFn          onPostSysFn;
   OnResumeUserFn onResumeUserFn;
   ClientReqFn    onClientReqFn;
   uint           order;

   struct ListHead list;
};

#define MODULE_ORDER_FIRST 0             /* instrument first */
#define MODULE_ORDER_FIXUP 1
#define MODULE_ORDER_PRECORE 2
#define MODULE_ORDER_CORE 3
#define MODULE_ORDER_LAST  UINT_MAX      /* instrument last */

extern void          Module_Fork(struct Task *tsk);
extern void          Module_Exit(struct Task *tsk);
extern void          Module_OnTaskStart();
extern void          Module_OnTaskExit();
extern void          Module_OnExec();
extern void          Module_OnShutdown();
extern void          Module_OnUserCopy(
      const int isFrom, 
      const struct CopySource *srcP, 
      const struct IoVec *iov_ptr,
      const size_t total_len);
extern void
Module_OnFileEvent(VkEventTag tag, struct FileStruct *filp);
extern int           Module_OnProtFault(const ulong faultAddr);
extern void
Module_OnVmaEvent(const VmaEventKind evk, const struct VmaStruct *vmaP,
                  const ulong istart, const size_t ilen);
extern void          Module_OnVmaFork(struct Task *tskP, const struct VmaStruct *vma);
extern void          Module_OnRegCopy(const int isRead, const struct CopySource *csP, const uint regOff, const size_t len);
extern void          Module_OnPreSyscall();
extern void          Module_OnPostSyscall();
extern void          Module_OnResumeUserMode();
extern int          Module_OnClientReq(const int reqNo, const HWord *argA, HWord *retValP);

extern void    Module_Register(struct Module *modp);



extern void
BT_Translate(ulong bblAddr, uchar* codeBuf, size_t codeBufSz,
      int *codeBufSzUsed, VexGuestExtents *vge, void *InsCallback, 
      void* cbArg);
