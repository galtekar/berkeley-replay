#include "vkernel/public.h"
#include "../private.h"
#include "private.h"

SHAREDAREA struct MapStruct *tntMemMap = NULL;
SHAREDAREA struct SynchLock tntMemLock = SYNCH_LOCK_INIT;

int isTaintInitialized = 0;

static IRSB*
TaintMapInstrument(void *opaque, IRSB *bbIn, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{
   int i;
   IRSB *bbOut;
   ulong currInsAddr = 0, currInsLen = 0;

   ASSERT(bbIn->stmts_used > 0);

   bbOut = emptyIRSB();
   bbOut->tyenv = deepCopyIRTypeEnv(bbIn->tyenv);
   bbOut->jumpkind = bbIn->jumpkind;
   bbOut->next = deepCopyIRExpr(bbIn->next);

   for (i = 0; i < bbIn->stmts_used; i++) {
      IRStmt *st = bbIn->stmts[i];
      if (st->tag == Ist_IMark) {
         currInsAddr = st->Ist.IMark.addr;
         currInsLen = st->Ist.IMark.len;
      }
      
      if (!currInsAddr) {
         ASSERT(!currInsLen);
         /* Skip instrumentation of IR preamble if it exists 
          * (e.g., self-check preamble if self-checking is turned on). */
         addStmtToIRSB(bbOut, st);
         continue;
      }

      TaintMap_IRStmt(bbOut, st);
      addStmtToIRSB(bbOut, st);  

      ASSERT(currInsAddr);
   }

   return bbOut;
}

static void
TaintMapFork(struct Task *tsk)
{
   struct TaintNode *node;

   DEBUG_MSG(5, "Forking the thread symbolic map.\n");
   tsk->tntMap = Map_Create(0);

   /* Child tsk inherits the task-local taint state. */
   list_for_each_entry(node, &current->tntMap->list, list) {
      ASSERT(!TaintMap_IsKeyMem(node->key));
      TaintMapAddNode(tsk->tntMap, node->key);
   }
}

static void
TaintMapExit(struct Task *tsk)
{
   struct TaintNode *node;

   DEBUG_MSG(0, "Local: %d nodes Global: %d nodes.\n", 
         tsk->tntMap->size, tntMemMap->size);
   ASSERT(tsk->tntMap);
   Map_Destroy(tsk->tntMap, node);
   tsk->tntMap = NULL;
}

#if DEBUG
static void
TaintMapDump(struct MapStruct *map)
{
   if (map == tntMemMap) {
      ASSERT(Synch_IsLocked(&tntMemLock));
   }

   struct TaintNode *node;

   DEBUG_MSG(0, "Dump of symolic map:\n");
   list_for_each_entry(node, &map->list, list) {
      DEBUG_MSG(0, "key: 0x%16.16llx\n", node->key);
   }
}
#endif


static void
TaintMapVmaUnmap(const struct VmaStruct *vma, ulong istart, size_t ilen)
{
   int count = 0;

   ASSERT(vma->file || !vma->file);
   ASSERT(istart >= vma->start && (istart+ilen) <= (vma->start+vma->len));

   /* Note that we clear all taint nodes in the vma region
    * regardless of whether the region is backed by a file
    * or not. Clearly we should clear all taint for the region
    * if the vma is not backed by a file -- the region can
    * never be accessed again and hence there is no danger
    * of tainted data propagating further.
    *
    * If the vma is backed by the file, we must still clear
    * taint in case the region is a private mapping.
    * Private file mappings are akin to non-file-backed
    * mappings except they are initialized with the contents
    * of the backing file on demand. Once these private mappings
    * are unmapped, their tainted contents can never be accessed
    * again. 
    *
    * Note that the vma could be backed by a shared file object,
    * in which case there is no harm in clearing the address space
    * region it occupies -- there should be memory objects
    * mapped to those locations.
    */

   int byte;

   DEBUG_MSG(0, "ivma: 0x%x:0x%x\n", istart, istart+ilen);

   SYNCH_LOCK(&tntMemLock);

   DEBUG_MSG(0, "Mem map has %d nodes.\n", tntMemMap->size);
#if DEBUG
   if (0) TaintMapDump(tntMemMap);
#endif

   for (byte = istart; byte < (istart+ilen); byte++) {
      struct TaintNode *node;
      u64 gaddr = GlobalAddr_MakeMemAddr(current->mm, byte);

      //DEBUG_MSG(0, "gaddr: 0x%16.16llx\n", gaddr);
      node = TaintNodeFind(tntMemMap, gaddr);
      if (node) {
         //DEBUG_MSG(0, "gaddr: 0x%16.16llx\n", gaddr);
         Map_Remove(tntMemMap, node);
         count++;
      }
   }

   SYNCH_UNLOCK(&tntMemLock);

#if DEBUG
   if (vma->flags & MAP_SHARED) {
      ASSERT(count == 0);
   }

   DEBUG_MSG(0, "Freed %d taint nodes.\n", count);
#endif
}

static struct Module mod = {
   .name          = "Taint Flow",
   .modeFlags     = 0xFFFFFFFF,
   .onStartFn     = NULL,
   .onTermFn      = NULL,
   .onForkFn      = TaintMapFork,
   .onExitFn      = TaintMapExit,
   .onVmaUnmapFn  = TaintMapVmaUnmap,
   .instrFn       = TaintMapInstrument,
   .order         = MODULE_ORDER_FIRST
};

int
TaintMap_Init()
{
   tntMemMap = Map_Create(0);

   /* Check that we have enough room for a large number of temps
    * (possible in some IRSBs) each of X86_MAX_ACCESS_LEN bytes. */
   ASSERT(((Key_TmpEnd - Key_TmpStart) / X86_MAX_ACCESS_LEN) >= 1024);

   Module_Register(&mod);

   isTaintInitialized = 1;

   TaintMapFork(current);

   return 0;
}
