#pragma once

#include "vkernel/public.h"

/* 
 * Copied from linux-2.6.16/arch/i386/kernel. 
 */
struct MmapArg {
	ulong addr;
	ulong len;
	ulong prot;
	ulong flags;
	ulong fd;
	ulong offset;
};


extern int     Vma_Intersects(const struct VmaStruct *vma, ulong start, 
                  size_t len, struct VmaStruct *ivma);
extern ulong   Vma_Map(struct FileStruct *filp, ulong start, size_t len, 
                  int prot, int flags, ulong pgoff);
extern ulong   Vma_ReMap(ulong addr, ulong old_len, ulong new_len, ulong flags,
                  ulong new_addr);
extern int     Vma_UnMap(ulong addr, size_t len);
extern int     Vma_Protect(ulong start, size_t len, int prot);
extern int     Vma_CheckProt(ulong start, size_t len, int prot);
extern int     Vma_ShmAt(struct FileStruct *filp, ulong start, int shmflg, 
                  ulong *raddr);
extern int     Vma_ShmDt(ulong addr);
extern void    Vma_Fork(struct Task *tsk);
//extern void    Vma_Init();
extern void    Vma_SelfExit(struct Task *tsk);


static INLINE int
Vma_IsLocked(const struct MmStruct *mm)
{
   return ORDERED_IS_LOCKED(&mm->vmaLock);
}

static INLINE void
Vma_Lock()
{
   ORDERED_LOCK(&current->mm->vmaLock);
}

static INLINE void
Vma_Unlock()
{
   ASSERT(current);
   ASSERT(current->mm);
   ASSERT(Vma_IsLocked(current->mm));
   ORDERED_UNLOCK(&current->mm->vmaLock);
}

static INLINE struct VmaStruct *
Vma_Next(struct VmaStruct *vma)
{
   struct VmaStruct *vmaNext;

   vmaNext = list_entry(vma->list.next, typeof(*vma), list);

   return vmaNext;
}

static INLINE struct VmaStruct *
Vma_NextNoWrap(struct VmaStruct *vmaP)
{
   struct VmaStruct *vmaNext = NULL;
   struct ListHead *nextP = vmaP->list.next;

   if (nextP != &vmaP->mm->vmaList) {
      vmaNext = list_entry(nextP, typeof(*vmaP), list);
   } else {
      /* If we keep going, we'll wrap around, and clearly the user
       * doesn't want that here. */
   }

   return vmaNext;
}


static INLINE void
Debug_PrintMm(struct MmStruct *mm)
{
   QUIET_DEBUG_MSG(5, 
         "MM  ID: %8.8d  USR: %8.8d  ADDR: 0x%8.8x\n",
         mm->id, mm->users, mm);
}
