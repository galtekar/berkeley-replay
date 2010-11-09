#include "vkernel/public.h"
#include "private.h"

/* The order in which modules is the order in which they are applied.
 * Ordering can (and is) used to ensure intermodule dependencies and
 * assumptions are met. */

struct ListHead  moduleList = LIST_HEAD_INIT(moduleList);
static int numModules = 0;

static void
ModulePrintList()
{
   struct Module *modp;

   list_for_each_entry(modp, &moduleList, list) {
      DEBUG_MSG(8, "Module: %s\n", modp->name);
   }
}

void
Module_Fork(struct Task *tsk)
{
   for_each_module() {
      if (modp->onForkFn) {
         modp->onForkFn(tsk);
      }
   } end_for_each_module;
}

void
Module_Exit(struct Task *tsk)
{
   for_each_module() {
      if (modp->onExitFn) {
         modp->onExitFn(tsk);
      }
   } end_for_each_module;
}

void
Module_OnTaskStart()
{
   TrnsTab_SelfInit();

   for_each_module() {
      if (modp->onStartFn) {
         modp->onStartFn();
      }
   } end_for_each_module;
}

void
Module_OnTaskExit()
{
   for_each_module() {
      if (modp->onTermFn) {
         modp->onTermFn();
      }
   } end_for_each_module;
}

void
Module_OnExec()
{
   for_each_module() {
      if (modp->onExecFn) {
         modp->onExecFn();
      }
   } end_for_each_module;
}

void
Module_OnVmaEvent(const VmaEventKind evk, const struct VmaStruct *vmaP,
                  const ulong istart, const size_t ilen)
{
   for_each_module() {
      if (modp->onVmaEventFn) {
         modp->onVmaEventFn(evk, vmaP, istart, ilen);
      }
   } end_for_each_module;
}

/* XXX: roll this in with OnVmaEvent? */
void
Module_OnVmaFork(struct Task *tskP, const struct VmaStruct *vma)
{
   for_each_module() {
      if (modp->onVmaForkFn) {
         modp->onVmaForkFn(tskP, vma);
      }
   } end_for_each_module;
}

void
Module_OnShutdown()
{
   for_each_module() {
      if (modp->onShutdownFn) {
         modp->onShutdownFn();
      }
   } end_for_each_module;
}

void
Module_OnUserCopy(
      const int isFrom, 
      const struct CopySource *srcP, 
      const struct IoVec *iov_ptr,
      const size_t total_len)
{
   ASSERT_KPTR(srcP);
   ASSERT_KPTR(iov_ptr);

   for_each_module() {
      if (modp->onUserCopyFn) {
         modp->onUserCopyFn(isFrom, srcP, iov_ptr, total_len);
      }
   } end_for_each_module;
}

void
Module_OnFileEvent(VkEventTag tag, struct FileStruct *filp)
{
   ASSERT(filp);
   for_each_module() {
      if (modp->onFileEventFn) {
         modp->onFileEventFn(tag, filp);
      }
   } end_for_each_module;
}

#if 0
void
Module_OnUserCopyIov(
      const int isFrom,
      const struct CopySource *csP, 
      const struct iovec *vec, 
      ulong vlen, 
      ulong lenBytes)
{
   int i;

   /* XXX: optimization -- do nothing if there is no module has a
    * user-copy callback. */

   ASSERT_KPTR(csP);
   ASSERT_KPTR(vec);

#if 0
   ulong sum = 0;
   for (i = 0; i < vlen; i++) {
      if (lenBytes < sum + vec[i].iov_len) {
         break;
      }

      Module_OnUserCopy(isFrom, csP, vec[i].iov_base, vec[i].iov_len);
      sum += vec[i].iov_len;
      loggedLen -= vec[i].iov_len;
   }

   if (i < vlen) {
      Module_OnUserCopy(isFrom, csP, vec[i].iov_base, lenBytes - sum);
   }
#else
#endif
}
#endif

void
Module_OnRegCopy(
      const int isRead,
      const struct CopySource *srcP, 
      const uint off,
      const size_t totalLen)
{
   ASSERT(srcP->tag >= 0xc001);

   for_each_module() {
      if (modp->onRegCopyFn) {
         modp->onRegCopyFn(isRead, srcP, off, totalLen);
      }
   } end_for_each_module;
}

int
Module_OnProtFault(const ulong faultAddr)
{
   int res = 0;

   for_each_module() {
      if (modp->onProtFaultFn) {
         res |= modp->onProtFaultFn(faultAddr);
      }
   } end_for_each_module;

   return res;
}

void
Module_OnPreSyscall()
{
   for_each_module() {
      if (modp->onPreSysFn) {
         modp->onPreSysFn();
      }
   } end_for_each_module;
}

void
Module_OnPostSyscall()
{
   for_each_module() {
      if (modp->onPostSysFn) {
         modp->onPostSysFn();
      }
   } end_for_each_module;
}

void
Module_OnResumeUserMode()
{
   for_each_module() {
      if (modp->onResumeUserFn) {
         modp->onResumeUserFn();
      }
   } end_for_each_module;
}

int
Module_OnClientReq(const int reqNo, const HWord *argA, HWord *retValP)
{
   int wasHandled = 0;

   for_each_module() {
      if (modp->onClientReqFn) {
         wasHandled |= modp->onClientReqFn(reqNo, argA, retValP);
      }
   } end_for_each_module;

   return wasHandled;
}

void
Module_Register(struct Module *modp)
{
   struct Module *curr_modp;
   struct ListHead *targetHead = &moduleList;

   ASSERT(!hasAppExecutionBegun);
   ASSERT(strlen(modp->name) > 0);
   ASSERT_KPTR_NULL(modp->onStartFn);
   ASSERT_KPTR_NULL(modp->onTermFn);
   ASSERT_KPTR_NULL(modp->onForkFn);
   ASSERT_KPTR_NULL(modp->onExitFn);
   ASSERT_KPTR_NULL(modp->onVmaEventFn);
   ASSERT_KPTR_NULL(modp->instrFn);
   ASSERT_KPTR_NULL(modp->onShutdownFn);
   ASSERT_KPTR_NULL(modp->onUserCopyFn);

   List_Init(&modp->list);

   /* Find a slot in the module table that respects module
    * dependencies -- straightforward insertion sort. */
   list_for_each_entry(curr_modp, &moduleList, list) {
      uint currOrder = curr_modp->order, newOrder = modp->order;

      if (newOrder <= currOrder) {
         /* Found the slot -- can't push new_modp any further down
          * the list. */
         targetHead = &curr_modp->list;
         break;
      }
   }

   ASSERT(curr_modp);
   ASSERT(targetHead);
   List_AddTail(&modp->list, targetHead);

   DEBUG_MSG(6, "Added module: %s\n", modp->name);

   numModules++;

   ModulePrintList();
}
