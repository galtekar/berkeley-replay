#include "replaycheck.h"

#if 0
static VOID
DebugBeforeRead(ADDRINT addr, ADDRINT pc, int size)
{
   int res;

   if (addr) {
#define BUFSZ 4096
      char buf[BUFSZ];

      ASSERT(size <= BUFSZ);
      ASSERT(size);

      DEBUG_MSG(5, "pc=0x%x addr=0x%x size=%d\n", pc, addr, size);
      memcpy(buf, (void*)addr, size);
      if (Thread_IsLogging()) {
         res = fwrite(buf, size, 1, current->dfp);
         ASSERT(res == 1);
      } else {
         char rbuf[BUFSZ];
         res = fread(rbuf, size, 1, current->dfp);
         ASSERT(!feof(current->dfp));
         ASSERT(!ferror(current->dfp));
         ASSERT(res == 1);
         ASSERT(memcmp(rbuf, buf, size) == 0);
      }
   }
}
#endif


VOID
ReplayCheck_ThreadStart(ThreadId pid)
{
   char accessFilename[256];
   snprintf(accessFilename, sizeof(accessFilename), "/tmp/alog.%d",
         pid);
   if (current->dfp) {
      D__;
      fclose(current->dfp);
      current->dfp = NULL;
   }

   DLOG("accessFilename=%s\n", accessFilename);
   current->dfp = fopen(accessFilename, (Thread_IsLogging() ? "w+" : "r+"));
   ASSERT(current->dfp);
}

VOID
ReplayCheck_ThreadFinish()
{
   ASSERT(current->dfp);
   fclose(current->dfp);
}

VOID
ReplayCheck_Fork(Thread *t)
{
   t->dfp = current->dfp;
}

/* XXX: verify FP and XMM registers too */
#define REGOP_ALL() \
   REGOP(EAX); \
   REGOP(EBX); \
   REGOP(ECX); \
   REGOP(EDX); \
   REGOP(EDI); \
   REGOP(ESI); \
   REGOP(EBP); \
   REGOP(ESP); \
   REGOP(EFLAGS); \
   REGOP(EIP); \
   REGOP(SEG_CS); \
   REGOP(SEG_SS); \
   REGOP(SEG_DS); \
   REGOP(SEG_ES); \
   REGOP(SEG_FS); \
   REGOP(SEG_GS);


static VOID
ReplayCheckPrintCtx(CONTEXT *ctx)
{
#undef REGOP
#define REGOP(reg) DLOG(#reg ": 0x%x\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_##reg))
   REGOP_ALL();
}


static int
ReplayCheckIsContextEqual(CONTEXT *ctx1, CONTEXT *ctx2)
{
   int isEqual = 1;

#undef REGOP
#define REGOP(reg) isEqual &= (PIN_GetContextReg(ctx1, LEVEL_BASE::REG_##reg) == \
      PIN_GetContextReg(ctx2, LEVEL_BASE::REG_##reg));
   REGOP_ALL();

   return isEqual;
}

#define MAGIC 0xbad1dea0
static VOID
ReplayCheckBeforeInst(ADDRINT pc, CONTEXT *ctx)
{
   int res;
   ulong magic = MAGIC;

   ASSERT(!current->isInInst);

   current->isInInst = 1;

   if (current->cloneId != 0) {
      //goto out;
   }

   ASSERT(current->dfp);
   DEBUG_MSG(6, "pos=%d EIP=0x%x\n", ftell(current->dfp),
         PIN_GetContextReg(ctx, LEVEL_BASE::REG_EIP));
   if (Thread_IsLogging()) {
      CONTEXT rctx;
      res = fwrite(&magic, sizeof(magic), 1, current->dfp);
      ASSERT(res == 1);
      res = fwrite(ctx, sizeof(CONTEXT), 1, current->dfp);
      ASSERT(res == 1);
      /* XXX: bug goes away with this check */
      fseek(current->dfp, -sizeof(CONTEXT), SEEK_CUR);
      res = fread(&rctx, sizeof(CONTEXT), 1, current->dfp);
      ASSERT(res == 1);
      ASSERT(ReplayCheckIsContextEqual(&rctx, ctx));
   } else {
      CONTEXT rctx;
      res = fread(&magic, sizeof(magic), 1, current->dfp);
      ASSERT(res == 1);
      ASSERT(magic == MAGIC);
      res = fread(&rctx, sizeof(CONTEXT), 1, current->dfp);
      ASSERT(!feof(current->dfp));
      ASSERT(!ferror(current->dfp));
      ASSERT(res == 1);
//      if (memcmp((void*)&rctx, (void*)ctx, sizeof(CONTEXT)) != 0) {
      if (!ReplayCheckIsContextEqual(&rctx, ctx)) {
         DLOG("Replay\n");
         ReplayCheckPrintCtx(ctx);
         DLOG("Logging\n");
         ReplayCheckPrintCtx(&rctx);
         ASSERT(0);
      }
   }

out:
   current->isInInst = 0;
}


static VOID
ReplayCheckSysBefore(ADDRINT *eax, ADDRINT *ebx, ADDRINT *ecx, ADDRINT *edx,
      ADDRINT *esi, ADDRINT *edi, ADDRINT *ebp)
{
   uint sysno = *eax;

   switch (sysno) {
   default:
      break;
   }
}

static VOID
ReplayCheckSysAfter(ADDRINT *eax)
{
}


VOID
ReplayCheck_Instruction(INS ins)
{
#if 0
   if (INS_IsMemoryRead(ins)) {
      INS_InsertCall(ins, IPOINT_BEFORE,
            (AFUNPTR)DebugBeforeRead,
            IARG_MEMORYREAD_EA,
            IARG_INST_PTR,
            IARG_MEMORYREAD_SIZE,
            IARG_END);
   }
#endif
   ADDRINT pc = INS_Address(ins);

   if (!Thread_IsInVkernel(pc)) {
      INS_InsertCall(ins, IPOINT_BEFORE,
            (AFUNPTR)ReplayCheckBeforeInst,
            IARG_INST_PTR,
            IARG_CONTEXT,
            IARG_END);
   } else {

      if (INS_IsSyscall(ins)) {
#define PREG(r) LEVEL_BASE::REG_##r
         INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ReplayCheckSysBefore),
               IARG_REG_REFERENCE, PREG(EAX),
               IARG_REG_REFERENCE, PREG(EBX),
               IARG_REG_REFERENCE, PREG(ECX),
               IARG_REG_REFERENCE, PREG(EDX),
               IARG_REG_REFERENCE, PREG(ESI),
               IARG_REG_REFERENCE, PREG(EDI),
               IARG_REG_REFERENCE, PREG(EBP),
               IARG_END);

         INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(ReplayCheckSysAfter),
               IARG_REG_REFERENCE, PREG(EAX),
               IARG_END);
      }
   }
}
