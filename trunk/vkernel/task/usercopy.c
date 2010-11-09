#include "vkernel/public.h"
#include "private.h"

/* XXX: move to libcommon/usercopy.c:copy_to_kernel_iov */
void
Task_IovCopyToKernel(
      const struct iovec *vec, 
      ulong vlen, 
      const char *src, 
      ulong bytesToCopy)
{
   int i;
   ulong sum = 0;
   const char *p = src;

   ASSERT_KPTR(vec);

   for (i = 0; i < vlen; i++) {
      if (bytesToCopy < sum + vec[i].iov_len) {
         break;
      }

      memcpy(vec[i].iov_base, p, vec[i].iov_len);

      sum += vec[i].iov_len;
      p += vec[i].iov_len;
   }

   if (i < vlen) {
      memcpy(vec[i].iov_base, p, bytesToCopy - sum);
   }
}

int
Task_CopyToUser(void __user *toP, const void *fromP, size_t n)
{
   ASSERT_UPTR(toP);
   ASSERT_KPTR(fromP);
   ASSERT(n >= 0); // sys_getsockopt may return 0 bytes to userspace
   ASSERT_UNIMPLEMENTED(VCPU_IsLogging() || VCPU_IsReplaying());

   int err;

   size_t nrBytesCopied = 0;

   DO_WITH_LOG_ENTRY_DATA_RESERVE(CopyToUser, DEBUG ? n : 0, 0) {
      err = copy_to_user(toP, fromP, n);

      ASSERT_MSG(0 <= err && err <= n, "err=%d\n", err);

      nrBytesCopied = n - err;
      ASSERT_MSG(0 <= nrBytesCopied && nrBytesCopied <= n, "nrBytesCopied=%d",
            nrBytesCopied);

      if (!VCPU_IsReplaying()) {
         entryp->ret = err;
#if DEBUG
         entryp->toP = toP;
         entryp->n = n;
         entryp->nrBytesCopied = nrBytesCopied;
         memcpy(datap, fromP, nrBytesCopied);
#endif
      } else {
#if DEBUG
         ASSERT(entryp->ret == err);
         ASSERT_MSG(entryp->toP == toP, "entryp->toP=0x%x toP=0x%x", 
               entryp->toP, toP);
         ASSERT(entryp->n == n);
         ASSERT(entryp->nrBytesCopied == nrBytesCopied);
         /* VK should send app same data, since it's supposed to be
          * deterministic. */
         if (nrBytesCopied) {
            ASSERT(memcmp(fromP, datap, nrBytesCopied) == 0);
         }
#endif
      }

      if (nrBytesCopied) {
         /* --- Notify interested modules. --- 
          * No need to copy data into log, since vkernel should
          * communicate same data. */
         struct CopySource cs = { .tag = Sk_Generic, .logDataP = fromP,
            .loggedLen = nrBytesCopied };

         struct IoVec *iov_ptr = IovOps_Alloc();
         IovOps_AddBuffer(iov_ptr, toP, n);
         Module_OnUserCopy(0, &cs, iov_ptr, nrBytesCopied);
         IovOps_Free(iov_ptr);
      }
   } END_WITH_LOG_ENTRY(DEBUG ? nrBytesCopied : 0);

   return err;
}

int
Task_CopyFromUser(void *toP, const void __user *fromP, size_t n)
{
   ASSERT_KPTR(toP);
   ASSERT_UPTR(fromP);
   ASSERT_MSG(n >= 0, "n=%d", n);
   ASSERT_UNIMPLEMENTED(VCPU_IsLogging() || VCPU_IsReplaying());

   int err;

   size_t nrBytesCopied = 0;

   DO_WITH_LOG_ENTRY_DATA_RESERVE(CopyFromUser, n, 0) {
      if (!VCPU_IsReplaying()) {
         entryp->ret = copy_from_user(datap, fromP, n);
#if DEBUG
         entryp->fromP = fromP;
         entryp->n = n;
#endif
      } else {
#if DEBUG
         /* toP is vk pointer, so it needn't be the same. */
         ASSERT(entryp->fromP == fromP);
         ASSERT(entryp->n == n);
         /* XXX: applies only for value-det recordings. */
#if 0
         if (!entryp->ret) {
            ASSERT(memcmp(datap, fromP, n) == 0);
         }
#endif
#endif
      }

      err = entryp->ret;

      ASSERT(err <= n);
      nrBytesCopied = n - err;
      ASSERT(nrBytesCopied <= n);

      if (nrBytesCopied) {
         /* --- Notify interested modules. --- */

         memcpy(toP, datap, nrBytesCopied);

         struct CopySource cs = { .tag = Sk_Generic, .logDataP = datap,
            .loggedLen = nrBytesCopied };

         struct IoVec *iov_ptr = IovOps_Alloc();
         IovOps_AddBuffer(iov_ptr, (void*)fromP, n);
         Module_OnUserCopy(1, &cs, iov_ptr, nrBytesCopied);
         IovOps_Free(iov_ptr);
      }

   } END_WITH_LOG_ENTRY(nrBytesCopied);

   return err;
}

long
Task_UserStringNCopy(char *toP, const char __user *fromP, size_t n)
{
   long err;
   size_t loggedBytes = 0;

   DO_WITH_LOG_ENTRY_DATA_RESERVE(CopyFromUser, n, 0) {
      if (!VCPU_IsReplaying()) {
#if PRODUCT
#error "XXX: what if only some of the string was read before a fault occurs?"
#error "XXX: use Task_CopyFromUser instead?"
#endif
         entryp->ret = strncpy_from_user(datap, fromP, n);

#if DEBUG
         entryp->fromP = fromP;
         entryp->n = n;
#endif
      } else {
#if DEBUG
         /* toP is vk pointer, so it needn't be the same; but the others
          * should be. */
         ASSERT(entryp->fromP == fromP);
         ASSERT(entryp->n == n);
         /* XXX: useful determinism check, but applies only to 
          * value-det recordings. */
#if 0
         if (!entryp->ret) {
            ASSERT(memcmp(datap, fromP, n) == 0);
         }
#endif
#endif
      }

      /* XXX: dunno if this is true; hard to tell from the damn inline
       * assembly; strncpy_from_user may have returned a negative
       * value on fault */
      ASSERT(entryp->ret >= 0);

      if (entryp->ret >= 0) {
         /* strncpy_from_user should've null terminated the dest
          * string. */
         ASSERT(strlen(datap) == entryp->ret);
         const size_t str_size = entryp->ret + 1;

         /* +1 for the null terminator. */
         loggedBytes = str_size;

         /* --- Notify interested modules. --- */

         memcpy(toP, datap, loggedBytes);

         struct CopySource cs = { .tag = Sk_Generic, .logDataP = datap,
            .loggedLen = loggedBytes };

         struct IoVec *iov_ptr = IovOps_Alloc();
         IovOps_AddBuffer(iov_ptr, (void*)fromP, str_size);
         Module_OnUserCopy(1, &cs, iov_ptr, str_size);
         IovOps_Free(iov_ptr);
      }

      err = entryp->ret;
      /* not <= because we need 1 for null-terminator */
      ASSERT(err < n);

   } END_WITH_LOG_ENTRY(loggedBytes);

   return err;
}

char *
Task_GetName(const char __user *fromP)
{
   ASSERT_UPTR(fromP);
   ASSERT_UNIMPLEMENTED(VCPU_IsLogging() || VCPU_IsReplaying());

   int err;
   const size_t n = PATH_MAX;
   char *result = ERR_PTR(-ENOMEM);
   char *toP = malloc(n);
   if (!toP) {
      goto out;
   }

   err = Task_UserStringNCopy(toP, fromP, n);

   result = toP;
   if (err < 0) {
      free(toP);
      result = ERR_PTR(err);
   }
out:
   return result;
}

void
Task_PutName(char *strP)
{
   ASSERT_KPTR(strP);

   free(strP);
}

/*
 * Returns length of string, including the null terminator.
 */
size_t
Task_CountUserStringLen(char __user *strP, size_t maxLen)
{
   ASSERT_UPTR(strP);

#if 1
   size_t err = 0;

   if (!VCPU_IsReplaying()) {
      err = strnlen_user(strP,maxLen);
   }

   Log_ReplayLong((ulong*)&err);

   return err;
#else
   return strnlen_user(strP, maxLen);
#endif
}

size_t
Task_ClearUser(void __user *toP, size_t len)
{
   size_t nrUnclearedBytes, nrClearedBytes;

   nrUnclearedBytes = clear_user(toP, len);

   nrClearedBytes = len - nrUnclearedBytes;

   struct CopySource cs = { .tag = Sk_Zero, .logDataP = NULL,
      .loggedLen = 0 };

   struct IoVec *iov_ptr = IovOps_Alloc();
   IovOps_AddBuffer(iov_ptr, toP, nrClearedBytes);
   Module_OnUserCopy(0, &cs, iov_ptr, nrClearedBytes);
   IovOps_Free(iov_ptr);

   return nrUnclearedBytes;
}

void
Task_WriteRegs(const TaskRegs *regP, uint off, size_t len)
{
   ASSERT(off >= 0);
   ASSERT(len > 0);

   D__;

   if (regP == Task_GetCurrentRegs()) {
      char *startP = ((char*)curr_regs) + off;

      D__;
      DO_WITH_LOG_ENTRY_DATA(RegisterState, len) {
         if (VCPU_IsLogging()) {
            /* Save reg. state. */
            memcpy(datap, startP, len);

            /* XXX: what about FP state? */
         } else if (VCPU_IsReplaying()) {
            /* XXX: verify determinism on value-det replays. */
            ASSERT(memcmp(startP, datap, len) == 0);
         }

         struct CopySource cs = { .tag = Sk_Generic, .logDataP = datap,
            .loggedLen = len };
         Module_OnRegCopy(0, &cs, off, len);

      } END_WITH_LOG_ENTRY(0);
      D__;

   }
   D__;
}
