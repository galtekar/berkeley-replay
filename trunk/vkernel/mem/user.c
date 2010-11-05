/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "vkernel/public.h"
#include "private.h"

/* Essentially Vma_Map but only for anonymous regions.
 * Used by the ELF loading code to map BSS pages as
 * well as by the vkernel sys_brk. */
static ulong
UserMemBrk(ulong oldaddr, ulong len) 
{
	long res;

   ASSERT(Vma_IsLocked(current->mm));

	if (!len) { return oldaddr; }

	res = Vma_Map(NULL, oldaddr, len, PROT_READ | PROT_WRITE,
			        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0);

	ASSERT(!SYSERR(res));
	ASSERT(res == oldaddr);

	return oldaddr;
}

ulong
UserMem_Brk(ulong oldaddr, size_t len)
{
   ulong oldbrk;

   Vma_Lock();

   oldbrk = UserMemBrk(oldaddr, len);

   Vma_Unlock();

   return oldbrk;
}

/*
 * Gets called by ELF loader to initialize the brk.
 */
int
UserMem_SetBrk(ulong brkStart, ulong brkEnd)
{
   brkStart = PAGE_ALIGN(brkStart);
   brkEnd = PAGE_ALIGN(brkEnd);

   DEBUG_MSG(5, "brkStart=0x%x brkEnd=0x%x\n", brkStart, brkEnd);
   if (brkEnd > brkStart) {
      ulong addr;
      /* XXX: no other users of address space exist, so lock
       * is not necessary -- verify and remove it. */
      ASSERT(current->mm->users == 1);

      Vma_Lock();
      addr = UserMemBrk(brkStart, brkEnd - brkStart);
      Vma_Unlock();

      if (BAD_ADDR(addr)) {
         ASSERT_UNIMPLEMENTED(0);
      }

   }

   /* XXX: no other users of address space exist, so lock
    * is not necessary -- verify. */
   current->mm->brkStart = current->mm->brkEnd = brkEnd;
   return 0;
}

long
sys_brk(ulong __brk)
{
	ulong newbrk, oldbrk, currbrk;

   Vma_Lock();

   D__;

   ASSERT(current);
   ASSERT(current->mm);
   ASSERT(current->mm->brkStart);

   D__;

	if (__brk < current->mm->brkStart) { D__; goto out; }

	DEBUG_MSG(5, "start=0x%x\n", current->mm->brkStart);
	newbrk = PAGE_ALIGN(__brk);
	oldbrk = PAGE_ALIGN(current->mm->brkEnd);
	ASSERT(PAGE_ALIGNED(oldbrk));
   if (oldbrk == newbrk) {
      goto set_brk;
   }

	/* Always allow shrinking the brk. */
	if (__brk <= oldbrk) {
		if (!Vma_UnMap(newbrk, oldbrk-newbrk)) {
			goto set_brk;
		} else {
			goto out;
		}
	}

	/* XXX: Check against rlimit. */
   WARN_XXX(0);

   /* Linux maintains a guard page between the brk area and other
    * mappings, so we do the same. */
   if (Vma_FindIntersect(current->mm, oldbrk, (newbrk+PAGE_SIZE)-oldbrk)) {
      goto out;
   }

	if (UserMemBrk(oldbrk, newbrk-oldbrk) != oldbrk) {
		goto out;
	}

set_brk:
	current->mm->brkEnd = __brk;
out:
   currbrk = current->mm->brkEnd;
   D__;
   Vma_Unlock();
   D__;

	DEBUG_MSG(5, "brk=0x%x ret=0x%x\n",
			__brk, currbrk);

	return currbrk;
}


ulong
UserMem_Map(struct FileStruct *filp, ulong addr, size_t len, int prot, 
            int flags, ulong pgoff)
{
   ulong err;

   Vma_Lock();

   err = Vma_Map(filp, addr, len, prot, flags, pgoff);

   Vma_Unlock();

   return err;
}

long
sys_mmap2(ulong addr, size_t len, int prot, int flags, int vfd, 
           ulong pgoff)
{
   long err;
   struct FileStruct *filp = NULL;

   DEBUG_MSG(5, "vfd=%d\n", vfd);

   if (!(flags & MAP_ANONYMOUS)) {
      filp = File_Get(vfd);

      if (!filp) {
         err = -EBADF;
         goto out;
      }

      /* vma_munmap will put the inode. */
   }

   err = UserMem_Map(filp, addr, len, prot, flags, pgoff);

   if (filp) {
      File_Put(filp);
   }

out:
   return err;
}



long
sys_mmap(struct MmapArg* arg)
{
   int err = -EINVAL;

   /* Offset must be page-aligned. */
   if (arg->offset & ~PAGE_MASK) {
      goto out;
   }

   /* Check for overflow. */
   if ((arg->offset + PAGE_ALIGN(arg->len)) < arg->offset) {
      goto out;
   }

   ASSERT(PAGE_ALIGNED(arg->offset));
   err = sys_mmap2(arg->addr, arg->len, arg->prot, arg->flags,
         arg->fd, arg->offset / PAGE_SIZE);

out:
   return err;
}


ulong 
sys_mremap(ulong addr, ulong old_len, ulong new_len,
	        ulong flags, ulong new_addr)
{
   ulong err;

   Vma_Lock();

   err = Vma_ReMap(addr, old_len, new_len, flags, new_addr);

   Vma_Unlock();

   return err;
}

long
sys_munmap(ulong addr, size_t len)
{
   int err;

   Vma_Lock();

   err = Vma_UnMap(addr, len);

   Vma_Unlock();

   return err;
}

long
sys_mprotect(ulong start, size_t len, ulong prot)
{
   int err;

   Vma_Lock();

   err = Vma_Protect(start, len, prot);

   Vma_Unlock();

   return err;
}

/* Physical memory mappings are beyond our control. Just log and replay
 * the return values. */
static long
UserMemGenericMlock(int sysno, ulong first, ulong second, ulong third)
{
   long err;

   if (!VCPU_IsReplaying()) {

      err = syscall(sysno, first, second, third);

      if (VCPU_IsLogging()) {

         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return err;
}

long
sys_mlock(ulong start, size_t len)
{
   return UserMemGenericMlock(SYS_mlock, start, len, 0);
}

long
sys_munlock(ulong start, size_t len)
{
   return UserMemGenericMlock(SYS_munlock, start, len, 0);
}

long
sys_mlockall(int flags)
{
   return UserMemGenericMlock(SYS_mlockall, flags, 0, 0);
}

long
sys_munlockall()
{
   return UserMemGenericMlock(SYS_mlockall, 0, 0, 0);
}

static long
UserMemAdvise(ulong start, size_t len, int behavior)
{
   long err;

   if (!VCPU_IsReplaying()) {

      err = syscall(SYS_madvise, start, len, behavior);

      if (VCPU_IsLogging()) {

         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return err;
}

long
sys_madvise(ulong start, size_t len, int behavior)
{
   int err;

   DEBUG_MSG(5, "behavior=0x%x\n", behavior);

   switch (behavior) {
   case MADV_NORMAL:
   case MADV_SEQUENTIAL:
   case MADV_RANDOM:
   case MADV_DONTNEED:
      err = UserMemAdvise(start, len, behavior);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      err = -EINVAL;
      break;
   }

   return err;
}

long
sys_msync(ulong start, size_t len, int flags)
{
   long err;

   if (!VCPU_IsReplaying()) {

      err = syscall(SYS_msync, start, len, flags);

      if (VCPU_IsLogging()) {

         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return err;
}

void
UserMem_Exec()
{
   Vma_Lock();

   Vma_UnMap(0, __LINUX_KERNEL_START);

   DEBUG_MSG(5, "Done clearing address space.\n");
   Vma_PrintAll();

   Vma_Unlock();
}


int
UserMem_CheckProt(ulong addr, size_t len, int prot)
{
   int res;

   Vma_Lock();

   res = Vma_CheckProt(addr, len, prot);

   Vma_Unlock();

   return res;
}

int
UserMem_ShmAt(struct FileStruct *filp, void *shmaddr, int shmflg, ulong *raddr)
{
   int err;

   ASSERT(raddr);

   Vma_Lock();

   err = Vma_ShmAt(filp, (ulong) shmaddr, shmflg, raddr);

   Vma_Unlock();

   return err;
}

int
UserMem_ShmDt(ulong addr)
{
   int err;

   Vma_Lock();

   err = Vma_ShmDt(addr);

   Vma_Unlock();

   return err;
}
