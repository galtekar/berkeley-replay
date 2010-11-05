/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <errno.h>
#include <sys/mman.h>

#include "vkernel/public.h"
#include "private.h"

static SHAREDAREA uint mmId = 0;

static struct MmStruct*
MemDupMm(struct MmStruct *oldmm)
{
   struct MmStruct *mm;

   mm = (struct MmStruct*) malloc(sizeof(*mm));
   memset(mm, 0, sizeof(*mm));

   mm->users = 1;

   ASSERT_TASKLIST_LOCKED();
   /* 0 is assigned to init's mm, so must increment first. */
   mm->id = ++mmId;

   /* Another thread could change oldmm's brk while we're
    * copying it. */
   Vma_Lock();
   mm->brkStart = oldmm->brkStart;
   mm->brkEnd = oldmm->brkEnd;
   Vma_Unlock();

   DEBUG_ONLY(mm->isAllocated = 1;)
   return mm;
}

int
Mem_Fork(struct Task *tsk) 
{
   struct MmStruct *mm, *oldmm;
   int retval;
   int cloneFlags = tsk->cloneArgs.flags;
   ulong tskUserStack = (ulong)tsk->cloneArgs.stack;

   ASSERT_TASKLIST_LOCKED();

   tsk->mm = NULL;

   oldmm = current->mm;
   ASSERT(oldmm);

   if (cloneFlags & CLONE_VM) {
      mm = oldmm;
      mm->users++;
      ASSERT(mm->users > 1);

      /* XXX: To speed and reduce memory loads during race detection, 
       * we assume that accesses to the stack don't race and forego 
       * adding those accesses to the active segment. But we assume 
       * that the task's stack will always be that which is passed in
       * the clone arg. But this may not hold -- a thread could jump to 
       * a new stack and then use the old stack as a heap ... unlikely 
       * but must be handled. */
      ASSERT_UNIMPLEMENTED(tskUserStack);
      if (tskUserStack) {
         struct VmaStruct *vma;
        
         Vma_Lock();
         vma = Vma_FindIntersect(current->mm, tskUserStack, 1);
         Vma_Unlock();
         ASSERT(vma);
         tsk->stack_addr = vma->start;
         tsk->stack_size = vma->len;
      }
      goto good_mm;
   } else {
      ASSERT(tsk->stack_addr == current->stack_addr);
      ASSERT(tsk->stack_size == current->stack_size);
      ASSERT(tsk->stack_addr);
      ASSERT(tsk->stack_size);
   }

   retval = -ENOMEM;
   mm = MemDupMm(oldmm);
   if (!mm) {
      goto fail_nomem;
   }

   mm->cached_vma = NULL;

good_mm:
   tsk->mm = mm;
   Debug_PrintMm(tsk->mm);
   Vma_Fork(tsk);
   TrnsTab_Fork(tsk);

   return 0;
fail_nomem:
   return retval;
}

void
Mem_SelfExit()
{
   struct Task *tsk = current;
   ASSERT_TASKLIST_LOCKED();

   if (tsk->clearChildTID) {
      D__;
      int err;
      u32 __user * tidptr = (u32 __user *)tsk->clearChildTID;
      tsk->clearChildTID = NULL;

      /* Like Linux, we don't check the error code if put_user
       * faults. */
      ASSERT_UPTR(tidptr);
      err = __put_user(0, tidptr);
      ASSERT(err || !err);
      sys_futex(tidptr, FUTEX_WAKE, 1, NULL, NULL, 0);
   }

   /* Protected by task list lock. */
   ASSERT_TASKLIST_LOCKED();

   DEBUG_MSG(5, "mm->users=%d\n", tsk->mm->users);
   ASSERT(tsk->mm->users > 0);

   if (tsk->mm->users == 1) {
      /* Looks like this is the last mm user to exit. */

      /*
       * WARNING: Do not free child's vmas from parent -- this
       * will create a race on closing Linux fds. When the child
       * dies, Linux automatically closes the fd in its fd table.
       * If the parent concurrently tries to close the fd, two
       * things can happen. The parent may close an invalid fd
       * in which case the close will return an error. Or
       * the parent may close a valid fd -- that which another task
       * allocated shortly after the dieing task -- in which case
       * operations on the fd will fail at nondeterministic points.
       *
       * Don't do this from parent:
       *    Vma_Exit(tsk);
       */
      ASSERT(tsk == current);
      Vma_SelfExit(tsk);

#define HAVE_TSK_DO_DEALLOC 0 // 0 <--> parent deallocs mm struct
#if HAVE_TSK_DO_DEALLOC
      /* XXX: This could be done in Mem_SelfExit (when users == 0),
       * but we may need it in tsk's parent (perhaps to get info
       * after a wait call) . But there are complications with letting
       * the parent clean it up...so we need a better solution. */
      DEBUG_MSG(5, "Freeing mm @ 0x%x\n", tsk->mm);
      ASSERT(tsk->mm);
      ASSERT(tsk->mm->isAllocated);
      memset(tsk->mm, 0, sizeof(*(tsk->mm)));
      free(tsk->mm);
#endif
   }
#if HAVE_TSK_DO_DEALLOC
   tsk->mm = NULL;
#endif
}

void
Mem_Exit(struct Task *tskP)
{
#if !HAVE_TSK_DO_DEALLOC
   ASSERT_KPTR(tskP->mm);
   ASSERT_TASKLIST_LOCKED();

   const int nrUsers = tskP->mm->users--;
   DEBUG_MSG(5, "nrUsers=%d\n", nrUsers);
   if (nrUsers == 0) {
      ASSERT(tskP->mm != childReaperTask->mm);
      DEBUG_MSG(5, "Freeing mm @ 0x%x\n", tskP->mm);
      ASSERT(tskP->mm->isAllocated);
      memset(tskP->mm, 0, sizeof(*(tskP->mm)));
      free(tskP->mm);
   } 
   tskP->mm = NULL;
#endif
}

/* XXX: Mem_Startup might be a better name. */
static int
Mem_Init()
{
   //Vma_Init();
   TrnsTab_Init();

   /* XXX: removing the stack results in trap instrumentation
    * not working...wierd...and the vkernel becomes [vkernel]
    * in ps output...also wierd.
    *
    * If we can do this, then we can push the vkernel image
    * even further toward the end (0xb0000000-0xc0000000),
    * which in turn provides more address space for user-level
    * maps.
    *
    * It appears that after removing the stack, any signals we
    * receive sigreturn to a stack location (that which we unmap here). 
    */
#if 0
   /* Clear address-space (everything but the vkernel of course), 
    * including the Linux-provided stack. I don't expect that this 
    * will get rid of the damn VDSO though. */
   munmap((void*)0, __IMAGE_START - 0);
   munmap((void*)__IMAGE_END, __LINUX_KERNEL_START - __IMAGE_END);
#endif

   return 0;
}

CORE_INITCALL(Mem_Init);
