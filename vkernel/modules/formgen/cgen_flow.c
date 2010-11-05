/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

#define TAINT_DEBUG 1

#if TAINT_DEBUG

#define TAINT_MSG(s, ...) \
   lprintf(CURRENT_LFD, "Taint --- " s, ##__VA_ARGS__);

#else
#error "XXX"
#endif


#define KEY2STR(key) \
   (TaintMap_IsKeyTmp(key) ? "t" : \
    (TaintMap_IsKeyReg(key) ? "r" : \
     (TaintMap_IsKeyConst(key) ? "c" : "m")))

#define USE_SMAP 0
#if USE_SMAP
#warning "the smap is slower than map for large data sets"
#endif

static const int wantsComments = 1;

int isTaintInitialized = 0;

struct TaintPage {
   struct MapField64 pageMap;

   struct ListHead byteList;
   size_t byteListLen;
};

struct TaintByte {
#if USE_SMAP
   SMapHdr hdr;
#else
   /* @key must be 64 bits to accommodate our 64-bit global addresses */
   struct MapField64 addrMap;
#endif

   /* Could be a byteVar or undefined code, so must be generic. */
   void *data;
   struct TaintPage *pageP;

   struct ListHead pgByteList;
};

#if USE_SMAP
#define MAX_NR_ENTRIES 262139 
static SHAREDAREA SMap memMap = {
   .size = 0,
   .entry_size = sizeof(struct TaintByte),
   .max_nr_entries = MAX_NR_ENTRIES,
   .array = NULL,
};
#else
static SHAREDAREA struct MapStruct *memMapP = NULL;
#endif
SYNCH_DECL_INIT(static SHAREDAREA, tntMemLock);


struct ASpaceProtStat *
TaintMap_IsPageProtOn()
{
   struct ASpaceProtStat *nodeP;

   nodeP = Map_Find64(VA(cgProtStatusMapP), pageMap, current->mm->id, nodeP);

   return nodeP;
}

static INLINE struct TaintByte*
TaintByteFind(u64 key)
{

#if USE_SMAP
   return (struct TaintByte*) SMap_Lookup(&memMap, key);
#else
   ASSERT_KPTR(memMapP);
   struct TaintByte *byteP = NULL;
   return Map_Find64(memMapP, addrMap, key, byteP);
#endif
}

static INLINE struct TaintByte*
TaintMapAddUniqueNode(u64 key)
{
   struct TaintByte *byteP;

#if DEBUG
   {
      u32 vaddr = (u32) key;

      ASSERT(SYNCH_IS_LOCKED(&tntMemLock));

      if (GlobalAddr_IsMemAddr(key)) {
         /* Lower 32-bits should be a valid user-space virtual address. */
         ASSERT(Task_IsAddrInUser(vaddr));
      }
   }
#endif

#if DEBUG
   /* All original taint is presumed to have been removed before
    * new taint was installed. */
   byteP = TaintByteFind(key);

   ASSERT_MSG(!byteP, "Inserting node with duplicate key 0x%llx\n", key);
#endif

#if USE_SMAP
   byteP = (struct TaintByte*) SMap_Insert(&memMap, key);
#else
   ASSERT_KPTR(memMapP);
   byteP = malloc(sizeof(*byteP)); 
   Map_NodeInit64(&byteP->addrMap, key);
   Map_Insert64(memMapP, addrMap, key, byteP);
#endif
   byteP->pageP = NULL;
   List_Init(&byteP->pgByteList);

   return byteP;
}


/*
 * -----------------------------------------------------------
 * TaintMapTaintByte ---
 *
 * Summary:
 *
 *    Taints the byte at location @key. If the key
 *    represents a location in RAM, then it should be the
 *    global address for that location.
 *
 * -----------------------------------------------------------
 */
static INLINE struct TaintByte *
TaintMapTaintByte(u64 key, void *data) 
{
   struct TaintByte *byteP = NULL;
   ASSERT(!TaintMap_IsPageProtOn());

   ASSERT(data || !data);

   DEBUG_MSG(7, "Inserting key 0x%16.16llx\n", key);
   byteP = TaintMapAddUniqueNode(key);

   ASSERT(GlobalAddrGetId(key) != 0);

   byteP->data = data;

   return byteP;
}

void
TaintMap_TaintMem(const struct Task *tskP, const u64 gaddr, 
                  const size_t len, void **dataPA)
{
   int i;

   /* 
    * CAREFUL: Don't hold the taintMemLock and then acquire
    * the vma lock (which GlobalAddr_FromVirt()) does as that
    * will deadlock with the code in TaintMapVmaUnmap(), which
    * tries to acquire the taintMemLock while holding the
    * vma lock.
    *
    * We avoid this deadlock situation because we require
    * that the client pass in the gaddrs.
    */

   SYNCH_LOCK(&tntMemLock);

   ASSERT_KPTR(dataPA);

   for (i = 0; i < len; i++) {
      struct TaintByte *byteP;
      struct TaintPage *pgP = NULL;
      u64 key = gaddr+i;

      ASSERT_KPTR(dataPA[i]);

      byteP = TaintMapTaintByte(key, dataPA[i]);
      ASSERT_KPTR(byteP);

      if (GlobalAddr_IsMemAddr(key)) {
         u32 vaddr = (u32) key;
         /* Lower 32-bits should be a valid user-space virtual address. */
         ASSERT(Task_IsAddrInUser(vaddr));
         struct MapStruct *pgMapP = tskP->mm->tntMemPgMapP;
         ASSERT_KPTR(pgMapP);
         pgP = Map_Find64(pgMapP, pageMap, PAGE_START(vaddr), pgP);
         if (!pgP) {
            pgP = malloc(sizeof(*pgP));
            Map_NodeInit64(&pgP->pageMap, PAGE_START(vaddr));
            List_Init(&pgP->byteList);
            pgP->byteListLen = 0;
            Map_Insert64(pgMapP, pageMap, pgP->pageMap.key64, pgP);
            DEBUG_MSG(5, "Adding page 0x%x (key 0x%x)\n",
                  pgP, pgP->pageMap.key64);
#if MAX_NR_VCPU > 1 && PRODUCT
#error "XXX: invalidate protections on other VCPUs"
#error "XXX: synchronize access to the page map"
#endif
         }
      } else {
         /* XXX: page of inode object must be placed in page taint list,
          * and when protection is enabled, all mappings backed by inode
          * object must be protected. */
         ASSERT_UNIMPLEMENTED(0);
      }

      DEBUG_MSG(5, "Linking to page 0x%x (key 0x%x)\n",
            pgP, pgP->pageMap.key64);
      byteP->pageP = pgP;
      List_AddTail(&byteP->pgByteList, &pgP->byteList);
      pgP->byteListLen++;
   }

   SYNCH_UNLOCK(&tntMemLock);
}

static INLINE int
TaintMapUntaintByte(const struct Task *tskP, const u64 key, void **dataP)
{
   int byteUntainted = 0;
   struct TaintByte *byteP;

   ASSERT(!TaintMap_IsPageProtOn());
   ASSERT_KPTR(dataP);

#if USE_SMAP
   byteP = (struct TaintByte *) SMap_Remove(&memMap, key);
#else
   byteP = TaintByteFind(key);
#endif

   //DEBUG_MSG(0, "Attempting to untaint key 0x%llx\n", key);

   if (byteP) {
      DEBUG_MSG(5, "Deleting key 0x%llx\n", key);

      *dataP = byteP->data;

      if (byteP->pageP) {
         List_Del(&byteP->pgByteList);
         if (--byteP->pageP->byteListLen == 0) {
            DEBUG_MSG(5, "Freeing page 0x%x (key 0x%x).\n", 
                  byteP->pageP, byteP->pageP->pageMap.key64)
            ASSERT(List_IsEmpty(&byteP->pageP->byteList));
#if MAX_NR_VCPU > 1 && PRODUCT
#error "XXX: invalidate protections on other VCPUs"
#error "XXX: synchronize access to the pagemap"
#endif
            struct MapStruct *pgMapP = tskP->mm->tntMemPgMapP;
            ASSERT_KPTR(pgMapP);
            Map_Remove(pgMapP, pageMap, byteP->pageP);
            memset(byteP->pageP, 0, sizeof(*(byteP->pageP)));
            free(byteP->pageP);
            byteP->pageP = NULL;
         }
      }

#if !USE_SMAP
      Map_Remove(memMapP, addrMap, byteP);
      free(byteP);
#endif
      byteP = NULL;

      byteUntainted = 1;

#if DEBUG
      /* No other node with same key should exist in RAM. */

      byteP = TaintByteFind(key);

      ASSERT_MSG(!byteP, "Duplicate node detected at key 0x%llx\n", key);
#endif
   } else {
      *dataP = NULL;
   }

   return byteUntainted;
}

size_t
TaintMap_UntaintMem(const struct Task *tskP, const u64 startGaddr, 
                    const size_t len, void **nDataA)
{
   size_t i, bytesUntainted = 0;

   ASSERT_KPTR(nDataA);

   SYNCH_LOCK(&tntMemLock);

   for (i = 0; i < len; i++) {
      const u64 gaddr = startGaddr+i;
      ASSERT_KPTR(&nDataA[i]);

      if (TaintMapUntaintByte(tskP, gaddr, &nDataA[i])) {
         bytesUntainted++;
      }
   }

   SYNCH_UNLOCK(&tntMemLock);

   return bytesUntainted;
}

static INLINE int
TaintMapIsByteTainted(const u64 key, void **dataPP)
{
   struct TaintByte *node;

   DEBUG_MSG(7, "Looking up key 0x%llx\n", key);

   node = TaintByteFind(key);

   if (node) {
      if (dataPP) *dataPP = node->data;
   } else {
      if (dataPP) *dataPP = NULL;
   }

   return node != NULL;
}

size_t
TaintMap_IsMemRangeTainted(const u64 start_gaddr, const size_t len, 
                       void **dataPA)
{
   size_t i, nr_bytes_tainted = 0;

   DEBUG_MSG(5, "gaddr=0x%llx len=%lu\n", start_gaddr, len);

   SYNCH_LOCK(&tntMemLock);

   for (i = 0; i < len; i++) {
      if (TaintMapIsByteTainted(start_gaddr+i, 
               dataPA ? &dataPA[i] : NULL)) {
         nr_bytes_tainted++;
      }
   }

   SYNCH_UNLOCK(&tntMemLock);

   DEBUG_MSG(5, "nr_bytes_tainted=%d\n", nr_bytes_tainted);

   return nr_bytes_tainted;
}

size_t
TaintMap_AreMemRangesTainted(const struct GAddrRange *gaddr_ranges, 
                        const int nr_ranges, void **dataPA)
{
   int i;
   size_t pos = 0, nr_bytes_tainted = 0;
   for (i = 0; i < nr_ranges; i++) {
      nr_bytes_tainted += 
         TaintMap_IsMemRangeTainted(gaddr_ranges[i].start, 
               gaddr_ranges[i].len, dataPA ? &dataPA[pos] : NULL );
      pos += gaddr_ranges[i].len;
   }

   return nr_bytes_tainted;
}


/* ---------- Local taint ---------- */

static void
TaintMapTaintLocal(FastMap *fmP, UInt idx, size_t len, void **dataPA)
{
   size_t i;
   ASSERT_KPTR(dataPA);

   for (i = 0; i < len; i++) {
      ASSERT(dataPA[i]);

      FastMap_Insert(fmP, idx+i, dataPA[i]);
   }
}

void
TaintMap_TaintReg(struct Task *tskP, UInt off, size_t len, void **dataPA)
{
   ASSERT(off < MAX_NR_REGS);

   TaintMapTaintLocal(tskP->fmRegTntP, off, len, dataPA);
}

void
TaintMap_TaintTmp(IRTemp id, TCode tc)
{
   ASSERT(id < MAX_NR_TMPS);
   DEBUG_ONLY(TaintMap_VerifyTCode(tc);)

   TaintMapTaintLocal(current->fmTmpTntP, id, 1, (void**)&tc);
   ASSERT(FastMap_Find(current->fmTmpTntP, id) == (void*)tc);
}


int
TaintMap_UntaintReg(struct Task *tskP, UInt off, size_t len, void **dataPA)
{
   ASSERT(off < MAX_NR_REGS);
   ASSERT_KPTR(dataPA);

   size_t i, bytesUntainted = 0;

   /* No locking necessary since we are updating the
    * task-local symbolic map. */

   for (i = 0; i < len; i++) {
      void *data = FastMap_Remove(tskP->fmRegTntP, off+i);

      dataPA[i] = data;

      if (data) {
         bytesUntainted++;
      } 
   }

   ASSERT(bytesUntainted <= len);

   return bytesUntainted;
}

void
TaintMap_UntaintTmp(IRTemp id)
{
   FastMap_Remove(current->fmTmpTntP, id);
}


int
TaintMap_IsRegTainted(const struct Task *tskP, UInt off, size_t len, void **dataPA)
{
   ASSERT(off >= 0);
   ASSERT(off < MAX_NR_REGS);

   int i, isTainted = 0;

   ASSERT(isTaintInitialized);
   ASSERT(dataPA || !dataPA);

   /* No locking necessary since we are updating the
    * task-local symbolic map. */

   for (i = 0; i < len; i++) {
      void *dataP = FastMap_Find(tskP->fmRegTntP, off+i);
      if (dataPA) {
         dataPA[i] = dataP;
      }

      if (dataP) {
         isTainted = 1;
      } 
   }

   DEBUG_MSG(7, "isTainted=%d off=0x%x len=%d\n", isTainted, off, len);

   return isTainted;
}

TCode
TaintMap_IsTmpTainted(IRTemp id)
{
   void *dataPA[1];
   TCode tc;

   ASSERT((Int)id >= 0);
   ASSERT(id < MAX_NR_TMPS);

   dataPA[0] = FastMap_Find(current->fmTmpTntP, id);

   tc = (TCode) dataPA[0];

   DEBUG_MSG(7, "tc=%d id=%d\n", tc, id);

   DEBUG_ONLY(TaintMap_VerifyTCode(tc););

   return tc;
}


#if 0
void
TaintMap_EnablePageProt()
{
   if (!TaintMap_IsPageProtOn()) {
      struct TaintPage *pgP;
      struct MapStruct *pgMapP = current->mm->tntMemPgMapP;
      
      ASSERT_KPTR(pgMapP);

      list_for_each_entry(pgP, &pgMapP->list, pageMap.list) {
         ASSERT(PAGE_ALIGNED(pgP->pageMap.key64));
         ASSERT(pgP->pageMap.key64 >= PAGE_SIZE);
         int res;

#if MAX_NR_VCPU > 1
#error "XXX: should enable protections only for current cpu and \
         not all cpus, which is what sys_mprotect does."
#endif
         DEBUG_MSG(5, "protecting page 0x%llx\n", pgP->pageMap.key64);
         res = mprotect((void*)(ulong)pgP->pageMap.key64, PAGE_SIZE, PROT_NONE);
         ASSERT(!res);
      }

      struct ASpaceProtStat *newP = malloc(sizeof(*newP));
      int id = current->mm->id;
      Map_NodeInit64(&newP->pageMap, id);
      Map_Insert64(VA(cgProtStatusMapP), pageMap, id, newP);
   } else {
      DEBUG_MSG(5, "Protection already enabled.\n");
   }
}

void
TaintMap_DisablePageProt()
{
   struct TaintPage *pgP;
   struct ASpaceProtStat *psP;

   if ((psP = TaintMap_IsPageProtOn())) {
      int res;
      struct MapStruct *pgMapP = current->mm->tntMemPgMapP;
      ASSERT_KPTR(pgMapP);

      list_for_each_entry(pgP, &pgMapP->list, pageMap.list) {
         ASSERT(pgP->pageMap.key64 >= PAGE_SIZE);
         /* XXX: will vmaP go away while we're using it? */
         //vmaP = lookup(pgP->key);
         //ASSERT_UNIMPLEMENTED(0)
         WARN_XXX(0);
         int prot = PROT_READ | PROT_WRITE;

#if MAX_NR_VCPU > 1
#error "XXX: should disable protections only for current cpu and \
         not all cpus, which is what sys_mprotect does."
#endif
         DEBUG_MSG(5, "unprotecting page 0x%llx\n", pgP->pageMap.key64);
         res = mprotect((void*)(ulong)pgP->pageMap.key64, PAGE_SIZE, prot);
         ASSERT(!res);
      }

      Map_Remove(VA(cgProtStatusMapP), pageMap, psP);
      free(psP);
   } else {
      DEBUG_MSG(5, "protection already off\n");
   }
}

int
TaintMap_IsAddrProtected(ulong addr)
{
   struct TaintPage *pgP;

   struct MapStruct *pgMapP = current->mm->tntMemPgMapP;
   ASSERT_KPTR(pgMapP);

   pgP = Map_Find64(pgMapP, pageMap, PAGE_START(addr), pgP);

   return pgP != NULL;
}
#endif

void
TaintMap_OnTaskFork(struct Task *tskP)
{
   tskP->fmRegTntP = FastMap_Create(MAX_NR_REGS);
   tskP->fmTmpTntP = FastMap_Create(MAX_NR_TMPS);

   /* Each address space needs it own page map. */
   ASSERT_KPTR(tskP->mm);

   if (!Task_IsThread(tskP)) {
      ASSERT(tskP->mm->users == 1);
      tskP->mm->tntMemPgMapP = Map_Create(0);
   } else {
      ASSERT(tskP->mm->users > 1);
      ASSERT_KPTR(tskP->mm->tntMemPgMapP);
   }
}

void
TaintMap_OnTaskExit(struct Task *tskP)
{
   uint size;
#if USE_SMAP
   size = memMap.size;
#else
   size = memMapP->size;
#endif
   DEBUG_MSG(0, "# mem nodes: %d\n", size);
   ASSERT_KPTR(tskP->fmRegTntP);
   ASSERT_KPTR(tskP->fmTmpTntP);
   ASSERT(tskP->fmRegTntP->size == 0);
   ASSERT(tskP->fmTmpTntP->size >= 0);

   FastMap_Destroy(tskP->fmRegTntP);
   FastMap_Destroy(tskP->fmTmpTntP);
   tskP->fmRegTntP = NULL;
   tskP->fmTmpTntP = NULL;

   ASSERT_KPTR(tskP->mm);

   DEBUG_MSG(5, "Destroying page map.\n");

   if (tskP->mm->users == 0) {
      struct MapStruct *mapP = tskP->mm->tntMemPgMapP;
      struct TaintPage *pgP;

      ASSERT_KPTR(mapP);
      Map_Destroy(mapP, pageMap, pgP);
      tskP->mm->tntMemPgMapP = NULL;
   } 
}

void
TaintMap_Fini()
{
   int i;

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpuP = VCPU_Ptr(i);

      struct ASpaceProtStat *nodeP;
      Map_Destroy(vcpuP->cgProtStatusMapP, pageMap, nodeP);
   }
}

int
TaintMap_Init()
{
   int i;

#if USE_SMAP
   memMap.array = malloc(sizeof(struct TaintByte)*MAX_NR_ENTRIES);
   SMap_Init(&memMap);
#else
   memMapP = Map_Create(16);
#endif

   isTaintInitialized = 1;

   TaintMap_OnTaskFork(current);

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpuP = VCPU_Ptr(i);
      vcpuP->cgProtStatusMapP = Map_Create(0);
   }

   return 0;
}
