#include "vkernel/public.h"
#include "private.h"

static struct UndoByte *
UndoByteGet(struct UndoByte *ubP)
{
   ASSERT(ubP->count >= 0);

   ubP->count++;

   return ubP;
}

static struct UndoByte *
UndoByteAlloc()
{
   struct UndoByte *ubP = malloc(sizeof(*ubP));

   ubP->count = 0;

   return UndoByteGet(ubP);
}

static void
UndoByteFree(struct UndoByte *ubP)
{
   ASSERT(ubP->count == 0);
   free(ubP);
}

static void
UndoBytePut(struct UndoByte *ubP)
{
   ASSERT(ubP->count > 0);
   ubP->count--;

   if (ubP->count == 0) {
      UndoByteFree(ubP);
   }
}

static void
cgCkptSaveByte(struct cgCkpt *ckptP, const MapAddrKind kind, const MapAddr addr)
{
   struct UndoByte *ubP = NULL;

   if (!Map_Find64(ckptP->undoMapP, addrMap, addr, ubP)) {
      ubP = UndoByteAlloc();
      Map_NodeInit64(&ubP->addrMap, addr);

      struct MAddrRange mr = { .kind = kind, .start = addr, .len = 1 };
      cgMap_Read(&mr, &ubP->byteP);

      Map_Insert64(ckptP->undoMapP, addrMap, addr, ubP);
   } else {
      /* Looks like we saved the original byte for this location already,
       * so nothing more to do. */
   }
}

void
cgCkpt_UnionWrSet(struct MapStruct *dstSetP, const struct cgCkpt *srcCkptP)
{
   ASSERT_KPTR(dstSetP);
   ASSERT_KPTR(srcCkptP->undoMapP);

   struct UndoByte *sP = NULL; 

   MAP_FOR_EACH_ENTRY_SAFE_DO(srcCkptP->undoMapP, addrMap, sP) {
      struct WriteByte *wbP;
      if (!Map_Find64(dstSetP, addrMap, sP->addrMap.key64, wbP)) {
         wbP = malloc(sizeof(*wbP));
         Map_NodeInit64(&wbP->addrMap, sP->addrMap.key64);
         Map_Insert64(dstSetP, addrMap, sP->addrMap.key64, wbP);
      }
   } END_MAP_FOR_EACH_ENTRY_SAFE;
}

void
cgCkpt_Restore(const struct cgCkpt *ckptP)
{
   struct UndoByte *ubP;

   D__;

#if 0
   /* Changing the registers while inside the TC may confuse VEX, so don't 
    * do it. 
    *
    * We'll try doing this for the TC for now, and see what happens. */
   ASSERT(!current->is_in_code_cache);
#endif

   list_for_each_entry(ubP, Map_GetList(ckptP->undoMapP), addrMap.list) {
      const u64 addr = ubP->addrMap.key64;
      struct CgByte *bP = ubP->byteP;

      const struct MAddrRange mr = { 
         .kind = addr < PAGE_SIZE ? Mk_Reg : Mk_Gaddr,
         .start = addr, .len = 1 };
      cgMap_Write(&mr, &bP);
   }
}

void
cgCkpt_Free(struct cgCkpt *ckptP)
{
   ASSERT_KPTR(ckptP);
   ASSERT_KPTR(ckptP->undoMapP);

   struct UndoByte *ubP = NULL;

   MAP_FOR_EACH_ENTRY_SAFE_DO(ckptP->undoMapP, addrMap, ubP) {
      cgByte_Put(ubP->byteP);
      ubP->byteP = NULL;

      Map_Remove(ckptP->undoMapP, addrMap, ubP);
      UndoBytePut(ubP);
      ubP = NULL;
   } END_MAP_FOR_EACH_ENTRY_SAFE;

   ASSERT(Map_GetSize(ckptP->undoMapP) == 0);
   Map_Destroy(ckptP->undoMapP, addrMap, ubP);

   free(ckptP);
   ckptP = NULL;
}

struct cgCkpt *
cgCkpt_Alloc()
{
   struct cgCkpt *ckptP = malloc(sizeof(*ckptP));

   ckptP->undoMapP = Map_Create(0);
   List_Init(&ckptP->stack);

   return ckptP;
}


/* ------------ Ckpt stack management ------------- */


void
cgCkptStack_Push(struct cgCkpt *ckptP)
{
   ASSERT_KPTR(ckptP);

   List_Push(&curr_vcpu->undoStack, stack, ckptP);
}

struct cgCkpt *
cgCkptStack_Pop()
{
   struct cgCkpt *ckptP;
   
   ckptP = List_Pop(&curr_vcpu->undoStack, stack, ckptP);

   ASSERT_KPTR(ckptP);

   return ckptP;
}

struct cgCkpt *
cgCkptStack_PeekTop()
{
   struct cgCkpt *ckptP;

   ckptP = List_PeekTop(&curr_vcpu->undoStack, stack, ckptP);

   return ckptP;
}

void
cgCkptStack_GetWriteSet(struct MapStruct *dstP)
{
   ASSERT_KPTR(dstP);

   struct cgCkpt *ckptP;
   struct ListHead *headP = &curr_vcpu->undoStack;

   ASSERT(!List_IsEmpty(headP));

   list_for_each_entry(ckptP, headP, stack) {
      cgCkpt_UnionWrSet(dstP, ckptP);
   }
}

void
cgCkptStack_PushNew()
{
   struct cgCkpt *ckptP = cgCkpt_Alloc();
   cgCkptStack_Push(ckptP);
}

void
cgCkptStack_OnPreUpdate(const struct MAddrRange *rP)
{
   int i;

   DEBUG_MSG(5, "start=0x%llx len=%d\n", rP->start, rP->len);

   struct cgCkpt *ckptP = cgCkptStack_PeekTop();
   if (!ckptP) {
      /* We've completed a join point, and are about to execute a join
       * event (e.g., syscall).  We could be here due to a PUT to the
       * syscall IP. 
       *
       * XXX: Would not including these puts in subsequent ckpts cause
       * a problem? I can't think of any right now. */
      ASSERT(!curr_vcpu->isJoinPending);
      return;
   }

   for (i = 0; i < rP->len; i++) {
      cgCkptSaveByte(ckptP, rP->kind, rP->start+i);
   }
}

void
cgCkptStack_Init()
{
   int i;

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpuP = VCPU_Ptr(i);

      vcpuP->bbSetP = NULL;
      List_Init(&vcpuP->undoStack);
   }
}
