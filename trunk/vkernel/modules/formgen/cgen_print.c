#include "vkernel/public.h"
#include "private.h"

static const int  wantsComments = 1;

static INLINE void
Raw_AdvanceToNextEntry(struct Log *logP, const size_t resDataSz, void **dataP)
{
   const ulong pos = (ulong) logP->pos;
   const ulong logEnd = Log_LogEnd(logP);
   if (pos + resDataSz > logEnd) {
      /* XXX: you need to pad the rest with either null of newlines. */
      Log_Rotate(logP);
   }

   *dataP = logP->pos;
}

#define DO_WITH_RAW_ENTRY(log_ptr, dataSz) { \
   void * datap = NULL; \
   struct Log * logp = log_ptr; \
   Raw_AdvanceToNextEntry(logp, dataSz, &datap);

#define END_WITH_RAW_ENTRY(dataSz) \
   { \
      Log_Advance(logp, dataSz); \
   } \
}

/* We need a commit function to ensure that an entire assert or var
 * decl is printed out on a line and not segmented across log rotations.
 */
void
cgPrint_Commit()
{
   ASSERT(curr_vcpu->formBufPos > 0);

   if (cg_OptOutputFormula) {
#if CG_SLOW_WRITE
      vfprintf(curr_vcpu->cgenFile, "%s", curr_vcpu->formBuf);
#else
      int err;
      DO_WITH_RAW_ENTRY(&curr_vcpu->cgLog, MAX_STMT_LEN) {
         strncpy(datap, curr_vcpu->formBuf, MAX_STMT_LEN);

         err = strlen(datap);

         ASSERT(err < MAX_STMT_LEN);

         /* Don't include the null-terminator since we're dumping to a
          * text file. It'll show up as a ^@ character. */
      } END_WITH_RAW_ENTRY(err);
#endif
   }

   curr_vcpu->formBufPos = 0;
}

void
CgenOut(const char *fmt, ...)
{
   va_list args;

   va_start(args, fmt);

   char *p = curr_vcpu->formBuf + curr_vcpu->formBufPos;

   ASSERT(curr_vcpu->formBufPos < MAX_STMT_LEN);
   size_t maxLen = MAX_STMT_LEN - curr_vcpu->formBufPos;

   int err = vsnprintf(p, maxLen, fmt, args);
   ASSERT_MSG(err > 0 && err <= maxLen, "err=%d maxLen=%d\n", err, maxLen);

   curr_vcpu->formBufPos += err;

   va_end(args);
}

void
cg_PrintVar(const CondVarTag kind, const int vcpuId, const u64 bbExecCount, 
      const u64 name)
{
   char *prefixStr = NULL;

   switch (kind) {
   case CondVar_Origin:
      prefixStr = "OV";
      break;
   case CondVar_Tmp:
      prefixStr = "TV";
      break;
   case CondVar_JointWrite:
      prefixStr = "JV";
      break;
   case CondVar_ArrayWrite:
      prefixStr = "AV";
      break;
   case CondVar_CAS:
      prefixStr = "CV";
      break;
   default:
      ASSERT(0);
      break;
   };

   CgenOut("%sv%de%llun%llu", prefixStr, vcpuId, bbExecCount, name);
}

void
cg_PrintLocalVarNow(const char *nameStr, const u64 idx)
{
   CgenOut("LVv%de%llus%dn%si%llu", curr_vcpu->id, VA(bbExecCount),
         VA(localScope), nameStr, idx);
}


void
cg_PrintCondVar(const struct CondVar * cvP)
{
   ASSERT(cvP);

   cg_PrintVar(cvP->tag, cvP->vcpu, cvP->bbExecCount, cvP->name);
}

void
cg_PrintByteVar(const struct ByteVar * bvP)
{
   const struct CondVar *cvP = bvP->cvP;

#if DEBUG
   ASSERT(cvP);
   ASSERT(bvP->byte >= 0);
   ASSERT_MSG(cvP->len >= 1, "%d", cvP->len);

   switch (cvP->tag) {
   case CondVar_Tmp:
      ASSERT(bvP->byte < 16);
      break;
   default:
      break;
   }
#endif

   cg_PrintCondVar(cvP);

   CgenOut("[%d:%d]", (bvP->byte+1) * 8 - 1, bvP->byte * 8);
}

void
cg_PrintSymByte(const struct CgByte *bP)
{
   if (bP->kind == Cbk_Symbolic) {
      cg_PrintByteVar(bP->Data.bvP);
   } else {
      ASSERT(bP->kind == Cbk_Concrete);
      CG_CONST(Ity_I8, bP->Data.val);
   }
}

void
cg_DeclareCondVar(const CondVarTag kind, const int vcpuId, 
      const u64 bbExecCount, const u64 name, const size_t lenInBits)
{
   cg_PrintVar(kind, vcpuId, bbExecCount, name);

   if (kind == CondVar_JointWrite || kind == CondVar_ArrayWrite) {
      ASSERT(lenInBits == T2B(Ity_I8));
   }

   CgenOut(" : BITVECTOR(%d);\n", lenInBits);
   cgPrint_Commit();
}

void
cgPrint_InitVCPU(struct VCPU *vcpuP)
{
   vcpuP->formBufPos = 0;
}
