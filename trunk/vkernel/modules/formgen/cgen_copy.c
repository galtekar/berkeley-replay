#include "vkernel/public.h"
#include "private.h"

static const int wantsComments = 1;

/* XXX: should be named cgCopy_ForcedOriginFlags */
int cgForcedOriginFlags = 0;

#define DEBUG_UPDATE_GUEST 1

static void
cgEmitOutput(void **dataPA, const char *logDataA, const size_t len)
{
   int i;
   
   ASSERT_KPTR(dataPA);
   ASSERT_KPTR(logDataA);

   CG_COMMENT("---- Output constraints ----\n");

   for (i = 0; i < len; i++) {
      if (dataPA[i]) {
         const struct ByteVar *bvP = 
            (const struct ByteVar *)dataPA[i];
         struct CondVar *cvP = bvP->cvP;

         ASSERT_KPTR(bvP);
         ASSERT_KPTR(cvP);

         STATS_ONLY(cgProf_NrTaintedOutBytes++);

         cg_LazyDeclareIfNeeded(cvP);
         CG_ASSIGN(CG_BV(bvP), CG_CONST(Ity_I8, logDataA[i]));
      }
   }
}

static void
CgenCopyFromUser(
      const struct IoVec *iov_ptr,
      const size_t totalLen,
      const void *logDataP,
      const size_t logDataLen
      )
{
   ASSERT(totalLen > 0);
   ASSERT_UNIMPLEMENTED_MSG(logDataLen == totalLen, 
         "logDataLen=%lu totalLen=%lu", logDataLen, totalLen);
   ASSERT(logDataLen > 0);
   ASSERT(logDataP);
   ASSERT_UNIMPLEMENTED(IovOps_GetCapacity(iov_ptr) == logDataLen);

   STATS_ONLY(cgProf_NrTotalOutBytes += totalLen);
   struct IoBuffer *buf_ptr = NULL;
   const char *log_ptr = logDataP;

   list_for_each_entry(buf_ptr, &iov_ptr->iov_list, list) {
      ASSERT(buf_ptr->len > 0);

      void **dataPA = malloc(sizeof(void*) * buf_ptr->len);
      const int is_read = 1;
      struct GAddrRange gaddr_ranges[MAX_NR_RANGES];
      int nr_ranges = MAX_NR_RANGES;

      GlobalAddr_FromRange2(current->mm, gaddr_ranges, &nr_ranges,
            (ulong) buf_ptr->base, buf_ptr->len, is_read);

      if (TaintMap_AreMemRangesTainted(gaddr_ranges, nr_ranges, dataPA)) {
         cgEmitOutput(dataPA, log_ptr, buf_ptr->len);
      } 

      log_ptr += buf_ptr->len;

      free(dataPA);
      dataPA = NULL;
   }
}

static void
CgenCopyToUser(
      const struct IoVec *iov_ptr,
      const size_t totalLen,
      const void *logDataP,
      const size_t logDataLen
      )
{
   size_t originLen = totalLen - logDataLen;

   ASSERT(logDataLen >= 0);
   ASSERT(originLen >= 0);
   ASSERT(originLen <= totalLen);
   ASSERT_UNIMPLEMENTED(IovOps_GetCapacity(iov_ptr) == totalLen);
   ASSERT_UNIMPLEMENTED(logDataLen == 0 || logDataLen == totalLen);
   ASSERT_COULDBE(logDataP == NULL);

   STATS_ONLY(cgProf_NrTotalInBytes += totalLen);

   if (logDataLen) {
#if DEBUG_UPDATE_GUEST
   struct IoBuffer *buf_ptr = NULL;
   const char *log_ptr = logDataP;

   list_for_each_entry(buf_ptr, &iov_ptr->iov_list, list) {
      struct CgByte **bytePA = malloc(sizeof(*bytePA) * buf_ptr->len);

      cgByte_MakeConcrete(log_ptr, buf_ptr->len, bytePA);
      cgMap_UpdateVAddr((ulong) buf_ptr->base, bytePA, buf_ptr->len);

      cgByte_PutAll(bytePA, buf_ptr->len);
      free(bytePA);
      bytePA = NULL;
      log_ptr += buf_ptr->len;
   }
#endif
   }

   if (originLen) {
#if DEBUG_UPDATE_GUEST
      ASSERT(logDataLen < totalLen);
      struct IoBuffer *buf_ptr = NULL;
      struct IoVec *origin_iov_ptr = IovOps_Dup(iov_ptr);

      IovOps_TruncateHead(origin_iov_ptr, logDataLen);
      ASSERT(IovOps_GetCapacity(origin_iov_ptr) == originLen);

      list_for_each_entry(buf_ptr, &iov_ptr->iov_list, list) {
         cgMap_WriteOrigin((ulong) buf_ptr->base, buf_ptr->len);
      }

      IovOps_Free(origin_iov_ptr);
      origin_iov_ptr = NULL;
#endif
   }

}

static int
CgenShouldForceOrigin(const struct FileStruct *filP)
{
   int res = 0;
   struct InodeStruct *inoP = File_Inode(filP);
   const InodeMajor inoMaj = Inode_GetMajor(inoP);

   DEBUG_MSG(5, "inoMaj=%d\n", inoMaj);

   switch (inoMaj) {
   case InodeMajor_Sock:
      {
         const struct SockStruct *sockP = Sock_GetStruct(inoP);
         ASSERT(!IS_ERR(sockP));
         ASSERT_KPTR(sockP);

         if (sockP->family == AF_INET ||
               sockP->family == AF_INET6) {
            res |= CG_ORIGIN_INET;
         }

         if (sockP->family == AF_UNIX || 
               sockP->family == PF_UNIX) {
            res |= CG_ORIGIN_UNIX;
         }
      }
      break;
   case InodeMajor_File:
      res |= CG_ORIGIN_FILE;
      break;
   case InodeMajor_Pipe:
      res |= CG_ORIGIN_PIPE;
      break;
   case InodeMajor_Device:
      res |= CG_ORIGIN_DEV;
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   if (filP->channel_kind == Chk_Data) {
      res |= CG_ORIGIN_DATA;
   }

   return (res & cgForcedOriginFlags) != 0;
}

void
Cgen_UserCopyCB(
      const int isFromUsr, 
      const struct CopySource *ciP, 
      const struct IoVec *iov_ptr,
      const size_t totalLen)
{
   ASSERT_KPTR(iov_ptr);
   ASSERT_KPTR(ciP);
   ASSERT(ciP->loggedLen >= 0);
   if (ciP->loggedLen > 0) {
      ASSERT_KPTR(ciP->logDataP);
   }
   ASSERT_MSG(totalLen > 0, "totalLen=%d", totalLen);
   ASSERT(totalLen == IovOps_GetCapacity(iov_ptr));

   DEBUG_MSG(5, "tag=%d isFromUsr=%d totalLen=%d\n",
         ciP->tag, isFromUsr, totalLen);

   if (isFromUsr) {
      if (ciP->loggedLen > 0) {
         CgenCopyFromUser(iov_ptr, totalLen, ciP->logDataP, ciP->loggedLen);
      }
   } else {
      size_t newLoggedDataLen = ciP->loggedLen;
      ASSERT(newLoggedDataLen <= totalLen);
      void *logDataP = (void*) ciP->logDataP;

      if (ciP->tag == Sk_SysIO && CgenShouldForceOrigin(ciP->Un.SysIO.filP)) {
         /* Pretend as though we don't know what the incoming data is,
          * hence forcing the entire userspace buffer to be marked as 
          * origin (i.e., symbolic). */
         DEBUG_MSG(5, "forcing origin\n");
         newLoggedDataLen = 0;
      } else if (ciP->tag == Sk_Zero) {
         newLoggedDataLen = totalLen;
         ASSERT_NULL_PTR(ciP->logDataP);
         /* XXX: had to do this so that symmap would see zero bytes
          * for the 0; but this is not logged */
         logDataP = (void*) malloc(newLoggedDataLen);
         memset(logDataP, 0, newLoggedDataLen);
      }

      CgenCopyToUser(iov_ptr, totalLen, logDataP, newLoggedDataLen);

      if (ciP->tag == Sk_Zero) {
         free(logDataP);
         logDataP = NULL;
      }
   }
}

#if DEBUG && PRODUCT
static void
CgenVerifyRegs(const uint off, const size_t len)
{
   void **dataPA = malloc(sizeof(void*) * len);

   if (TaintMap_IsRegTainted(current, off, len, dataPA)) {
      int i;

      for (i = 0; i < len; i++) {
         if (dataPA[i]) {
            DEBUG_MSG(5, "%d is tainted, but not logged.\n", off+i);
         }
      }

      ASSERT(0);
   }

   free(dataPA);
   dataPA = NULL;
}
#endif

static void
CgenReadReg(
      const uint off,
      const size_t totalLen,
      const void *logDataP,
      const size_t logDataLen
      )
{
   ASSERT(totalLen > 0);
   ASSERT(logDataLen <= totalLen);
   ASSERT(logDataLen > 0);
   ASSERT(logDataP);

   void **dataPA = malloc(sizeof(void*) * logDataLen);

   if (TaintMap_IsRegTainted(current, off, logDataLen, dataPA)) {
      cgEmitOutput(dataPA, logDataP, logDataLen);
   } 

   free(dataPA);
   dataPA = NULL;

#if DEBUG && PRODUCT
#error "XXX: this needs to be done on every sys/tsc/preempt entrance"
   D__;
   /* Check that only logged regs are tainted; if not, then we need to
    * include those unlogged-but-tainted regs in the logged set. */
   CgenVerifyRegs(0, off);
   D__;
   size_t len = MAX_NR_REGS - (off+logDataLen);
   CgenVerifyRegs(off+logDataLen, len);
   D__;
#endif
}

void
Cgen_RegCopyCB(
      const int is_read,
      const struct CopySource *ciP, 
      const uint offset, 
      const size_t len)
{
   ASSERT_KPTR(ciP);
   ASSERT_KPTR(ciP->logDataP);
   ASSERT_MSG(ciP->loggedLen == len, 
         "vkernel determinism not guaranteed\n");

   DEBUG_MSG(5, "offset=%d EIPoff=%d\n", offset, offsetof(VexGuestX86State, guest_EIP));

   if (is_read) {

      CgenReadReg(offset, len, ciP->logDataP, ciP->loggedLen);
   } else {
      if (1) {

#if DEBUG
         ASSERT(len <= MAX_NR_REGS);
         char before[len], after[len];
         Task_CopyFromRegs(before, offset ,len);

         ASSERT(memcmp(before, ciP->logDataP, len) == 0);
#endif

#if DEBUG_UPDATE_GUEST
         const int nrRanges = 1;
         struct MAddrRange rangeA[1] = { 
            { .kind = Mk_Reg, .start = offset, .len = len }
         };
      struct CgByte *bytePA[len];

      cgByte_MakeConcrete(ciP->logDataP, len, bytePA);
      cgMap_UpdateMAddr(rangeA, nrRanges, bytePA);

      cgByte_PutAll(bytePA, len);
#endif

#if DEBUG
         Task_CopyFromRegs(after, offset, len);

         ASSERT(memcmp(before, ciP->logDataP, len) == 0);
         ASSERT(memcmp(ciP->logDataP, after, len) == 0);
         ASSERT(memcmp(before, after, len) == 0);
#endif
      }
   }
}
