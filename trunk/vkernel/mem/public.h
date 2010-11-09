#pragma once

#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "vkernel/public.h"
#include "vkernel/fs/public.h"

#define IPC_SHMAT    21
#define IPC_SHMDT    22
#define IPC_SHMCTL   24

#define VERIFY_READ     PROT_READ
#define VERIFY_WRITE    PROT_WRITE
#define VERIFY_EXEC     PROT_EXEC

/* We assume that all valid user-space addresses are below
 * that of the vkernel image. */
#define BAD_ADDR(x) ((ulong)x >= __IMAGE_START)


struct Task;
struct VmaStruct;

struct VirtRange {
   ulong start;
   size_t len;
};


typedef u64 GAddr; 

struct GAddrRange {
   GAddr start;
   size_t len;
};

struct VmaOps {
   void (*open)(struct VmaStruct *);
   void (*close)(struct VmaStruct *);
};

#define MAP_EXTRA_PERMANENT 0x1
struct VmaStruct {
   ulong start;
   size_t len;
   size_t pgoff;
   int flags;
   int extraFlags;
   int prot;
   struct FileStruct *file;
   struct VmaOps *ops;

   struct MmStruct *mm; /* mm this vma is attached to, or NULL */

   struct ListHead list;
};

typedef void (*VmaIterCB)(const struct VmaStruct *, void *);

extern void    Vma_Iterate(VmaIterCB cb, void *dataP);
extern void    Vma_Print(const struct VmaStruct *);
extern void    Vma_PrintAll();
extern struct VmaStruct *  Vma_Find(const struct MmStruct *mm_ptr, ulong vaddr);
extern struct VmaStruct *  Vma_FindIntersect(struct MmStruct *mm_ptr, ulong start, size_t len);

extern struct DentryStruct * Vma_GetExecDentry();

extern int     Mem_Fork(struct Task *);
extern void    Mem_Exit(struct Task *);
extern void    Mem_SelfExit();

extern ulong   UserMem_Map(struct FileStruct *filp, ulong start, 
                  size_t bytes, int prot, int flags,  ulong pgoff);
extern int     UserMem_Unmap(ulong addr, size_t bytes);
extern int     UserMem_SetBrk(ulong brkStart, ulong brkEnd);
extern ulong   UserMem_Brk(ulong start, size_t len);
extern int     UserMem_Protect(ulong addr, size_t len, int prot);
extern int     UserMem_CheckProt(ulong addr, size_t len, int prot);

static INLINE int
GlobalAddr_IsMemAddr(GAddr gaddr)
{
   return (gaddr & (1ULL << 63)) != 0;
}

static INLINE int
GlobalAddr_IsFileAddr(GAddr gaddr)
{
   return !GlobalAddr_IsMemAddr(gaddr);
}

static INLINE u32
GlobalAddrMakeMemId(const struct MmStruct *mm)
{
   return (mm->id | (1 << 31));
}

static INLINE u32
GlobalAddrMakeInodeId(struct InodeStruct *inodp)
{
   u32 id = Inode_Ino(inodp);

   /* We reserve the lower half of the id-space for inode ids.
    * But that assumes that inode ids don't exceed that boundary. */
   ASSERT_UNIMPLEMENTED(!((id >> 31) & 0x1));

   return id;
}

static INLINE u32
GlobalAddrGetId(GAddr gaddr)
{
   return (gaddr >> 32);
}

static INLINE u32
GlobalAddr_GetVAddr(GAddr gaddr)
{
   ASSERT(GlobalAddr_IsMemAddr(gaddr));

   return (u32) gaddr;
}

static INLINE u64
GlobalAddrMakeAddr(u32 id, u32 off)
{
   u64 gaddr = id;

   //DEBUG_MSG(0, "id=0x%x off=0x%x\n", id, off);

   gaddr <<= 32;
   //DEBUG_MSG(0, "gaddr after shift: 0x%16.16llx\n", gaddr);
   gaddr |= off;
   //DEBUG_MSG(0, "gaddr after or: 0x%16.16llx\n", gaddr);

   return gaddr;
}

static INLINE int
GlobalAddr_IsInAddrSpace(u64 gaddr, struct MmStruct *mm)
{
   u32 mm_id = GlobalAddrMakeMemId(mm);

   return GlobalAddrGetId(gaddr) == mm_id;
}

static INLINE u64
GlobalAddr_MakeMemAddr(const struct MmStruct *mm, u32 vaddr)
{
   /* The upper bit indicates that the global address is
    * from a memory object, and not from an inode object. */

   return GlobalAddrMakeAddr(GlobalAddrMakeMemId(mm), vaddr);
}

static INLINE u64
GlobalAddr_MakeInodeAddr(struct InodeStruct *inodp, u32 off)
{
   return GlobalAddrMakeAddr(GlobalAddrMakeInodeId(inodp), off);
}


#if 0
extern u64     
GlobalAddr_FromVirt(struct MmStruct *mm_ptr, const ulong vaddr, 
      const int isRead);

extern size_t
GlobalAddr_FromRange(struct MmStruct *mm_ptr, u64 *gAddrA, 
      const ulong vaddr, const size_t len, const int isRead);
#endif

extern size_t
GlobalAddr_FromRange2(struct MmStruct *mm_ptr, 
      struct GAddrRange *rangeA, int *maxNrRangesP, const ulong vaddr, 
      const size_t len, const int isRead);

#if 0
extern void
GlobalAddr_FromVma(struct MmStruct *mm_ptr, u64 *gAddrA, 
      const struct VmaStruct *vmaP, const ulong off, const size_t len, 
      const int isRead);
#endif
