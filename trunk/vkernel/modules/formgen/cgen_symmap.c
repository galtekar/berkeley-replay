#include "vkernel/public.h"
#include "private.h"

/*
 * ----- Summary -----
 *
 * This modules tracks the constraint variables corresponding to VEX
 * temporary variables through guest state (registers and memory).
 *
 * We need this because of the nature of VEX IR. It translates one IRSB
 * at a time, and communicates computations to the next IRSB by writing
 * temporary state to registers or memory. But when a subsequent IRSB
 * references a previously written state location, we need to be able to
 * tie to a previously generates constraint variable. And this module
 * lets us do that.
 */

/* --------------- Condition variables --------------- */

static INLINE void
cgDestroyCv(struct CondVar *cvP)
{
   ASSERT(cvP->count == 0);
   free(cvP);
}

static INLINE struct CondVar *
cgMakeCv(CondVarTag tag, u64 name, size_t len)
{
   struct CondVar *cvP = malloc(sizeof(*cvP));

   cvP->tag = tag;
   cvP->vcpu = curr_vcpu->id;
   cvP->bbExecCount = VA(bbExecCount);
   cvP->count = 0;
   cvP->len = len;
   if (tag == CondVar_Origin) {
      /* We declare the origin only on first use. Turns out that
       * programs don't always use all of their inputs! */
      cvP->isDeclared = 0;
   } else {
      cvP->isDeclared = 1;
   }
   cvP->name = name;

   return cvP;
}


/* --------------- Byte varaibles --------------- */

static INLINE struct ByteVar *
cgMakeByteVar(struct CondVar *cvP, size_t byte)
{
   struct ByteVar *bvP = malloc(sizeof(*bvP));

   ASSERT_PTR(cvP);

   cvP->count++;
   ASSERT(cvP->count > 0);

   bvP->cvP = cvP;
   bvP->byte = byte;
   bvP->count = 0;

   return bvP;
}

static INLINE void
cgDestroyByteVar(struct ByteVar *bvP)
{
   ASSERT_KPTR(bvP);
   ASSERT_KPTR(bvP->cvP);

   ASSERT(bvP->count == 0);

#if MAX_NR_VCPU > 1 && PRODUCT
#error "XXX: get and put of byte and cvars need to be locked properly"
#endif
   bvP->cvP->count--;

   if (bvP->cvP->count == 0) {
      cgDestroyCv(bvP->cvP);
   }

   bvP->cvP = NULL;
   free(bvP);
   bvP = NULL;
}

struct ByteVar *
cg_GetByteVar(struct ByteVar *bvP)
{
   bvP->count++;

   ASSERT_MSG(bvP->count <= 10, "possible memory leak");

   return bvP;
}

int
cg_PutByteVar(struct ByteVar *bvP)
{
   //DEBUG_MSG(0, "count=%d\n", bvP->count);

   bvP->count--;

   ASSERT(bvP->count >= 0);

   if (bvP->count == 0) {
      cgDestroyByteVar(bvP);
      bvP = NULL;

      return 1;
   }

   return 0;
}



#if 0
static INLINE void
cgDestroyBVs(void **dataPA, size_t len)
{
   int i;

   for (i = 0; i < len; i++) {
      void *dataP = dataPA[i];

      if (dataP) {
         struct ByteVar *bvP = (struct ByteVar *)dataP;

         ASSERT_KPTR(bvP);

         cg_PutByteVar(bvP);
      }
   }
}
#endif

/* --------------- Symbolic bytes --------------- */

static INLINE struct CgByte *
cgByteMakeSymbolicWork(struct ByteVar *bvP)
{
   struct CgByte *bP = malloc(sizeof(*bP));
   bP->count = 0;
   bP->kind = Cbk_Symbolic;
   bP->Data.bvP = cg_GetByteVar(bvP);

   return cgByte_Get(bP);
}


static INLINE struct CgByte *
cgByteMakeConcreteWork(uchar val)
{
   struct CgByte *bP = malloc(sizeof(*bP));
   bP->count = 0;
   bP->kind = Cbk_Concrete;
   bP->Data.val = val;

   return cgByte_Get(bP);
}


struct CondVar *
cgByte_MakeSymbolic(const CondVarTag tag, const u64 name, 
                   size_t len, struct CgByte **bytePA)
{
   struct CondVar *cvP = cgMakeCv(tag, name, len);

#if DEBUG
   switch (tag) {
   case CondVar_Tmp:
      break;
   case CondVar_Origin:
      break;
   case CondVar_JointWrite:
   case CondVar_ArrayWrite:
      ASSERT(len == 1);
      break;
   case CondVar_CAS:
      break;
   default:
      ASSERT_MSG(0, "tag=0x%x", tag);
      break;
   };
#endif

   ASSERT_KPTR(cvP);

   int i;

   for (i = 0; i < len; i++) {
      struct ByteVar *bvP = cgMakeByteVar(cvP, i);

      bytePA[i] = cgByteMakeSymbolicWork(bvP);
   }

   return cvP;
}

void
cgByte_MakeOrigin(const size_t len, struct CgByte **bytePA)
{

   if (1) {
      size_t i;
      for (i = 0; i < len; i++) {
         cgByte_MakeSymbolic(CondVar_Origin, VA(originCounter)++,
               1, &bytePA[i]);
      }
   } else {
      cgByte_MakeSymbolic(CondVar_Origin, VA(originCounter)++,
            len, bytePA);
   }
}

void
cgByte_MakeConcrete(const char *valA, size_t len, struct CgByte **bytePA)
{
   int i;

   for (i = 0; i < len; i++) {
      DEBUG_MSG(7, "valA[%d]=%d\n", i, valA[i]);
      bytePA[i] = cgByteMakeConcreteWork(valA[i]);
   }
}


/* ---------- Symbolic map operations ---------- */

int
cgMap_Read(const struct MAddrRange *srcRangeP, struct CgByte **bytePA)
{
   ASSERT_KPTR(srcRangeP);
   ASSERT_KPTR(bytePA);

   int err = 0, i;
   const struct MAddrRange *rP = srcRangeP;

   D__;

   ASSERT(rP->kind == Mk_Reg || rP->kind == Mk_Gaddr);

   struct ByteVar **bvPA = malloc(sizeof(*bvPA) * rP->len);

   if (rP->kind == Mk_Reg) {
      ASSERT(rP->start < PAGE_SIZE);
      TaintMap_IsRegTainted(current, rP->start, rP->len, (void**)bvPA);
   } else {
      TaintMap_IsMemRangeTainted(rP->start, rP->len, (void**)bvPA);
   }

   for (i = 0; i < rP->len; i++) {
      struct ByteVar *bvP = bvPA[i];

      struct CgByte *bP = malloc(sizeof(*bP));
      bP->count = 0;

      if (bvP) {
         bP->kind = Cbk_Symbolic;
         bP->Data.bvP = cg_GetByteVar(bvP);
      } else {
         uchar byteVal;
         if (rP->kind == Mk_Reg) {
            Task_CopyFromRegs(&byteVal, rP->start, 1);
         } else {
#if PRODUCT
#error "XXX: virtual address of non-address space objects cannot be recovered by GAddr. So this is wrong."
#endif
            ulong vAddr = GlobalAddr_GetVAddr(rP->start+i);
            err = copy_from_user(&byteVal, (void*)vAddr, 1);
            ASSERT_UNIMPLEMENTED(!err);
         }

         bP->kind = Cbk_Concrete;
         bP->Data.val = byteVal;
      }

      bytePA[i] = cgByte_Get(bP);
   }

   free(bvPA);
   bvPA = NULL;

   return err;
}

static size_t
cgMapClear(struct Task *tskP, const struct MAddrRange *rP)
{
   ASSERT(rP->len > 0);
   ASSERT(MAX_NR_REGS <= PAGE_SIZE);

   size_t nrBytesCleared = 0, i;

   for (i = 0; i < rP->len; i++) {
      const u64 addr = rP->start + i;

      struct ByteVar *bvP = NULL;

      if (rP->kind == Mk_Reg) {
         ASSERT(addr < PAGE_SIZE);
         TaintMap_UntaintReg(tskP, addr, 1, (void**)&bvP);
      } else {
         ASSERT(addr >= PAGE_SIZE);
         ASSERT(tskP == current);
         TaintMap_UntaintMem(tskP, addr, 1, (void**)&bvP);
      }

      if (bvP) {
         nrBytesCleared++;
         cg_PutByteVar(bvP);
         //DEBUG_MSG(0, "addr=0x%llx wasFreed=%d\n", addr, wasFreed);
         bvP = NULL;
      }
   }

   return nrBytesCleared;
}

int
cgMap_Write(const struct MAddrRange *dstRangeP, struct CgByte **bytePA)
{
   const struct MAddrRange *rP = dstRangeP;

   ASSERT(rP->kind == Mk_Reg || rP->kind == Mk_Gaddr);

   int err = 0, i;

   DEBUG_MSG(5, "start=0x%llx len=%lu\n", rP->start, rP->len);

   cgMapClear(current, rP);

   for (i = 0; i < rP->len; i++) {
      struct CgByte *bP = bytePA[i];
      struct ByteVar *bvP = NULL;
      MapAddr addr = rP->start + i;

      if (bP->kind == Cbk_Symbolic) {
         bvP = cg_GetByteVar(bP->Data.bvP);
         ASSERT_KPTR(bvP);
      }

#define OMIT_CONCRETE_WRITE 0
      if (rP->kind == Mk_Reg) {
         ASSERT(addr < PAGE_SIZE);
         if (bP->kind == Cbk_Symbolic) {
            ASSERT_KPTR(bvP);
            TaintMap_TaintReg(current, addr, 1, (void**)&bvP);
         } else {
            ASSERT(bP->kind == Cbk_Concrete);
#if !OMIT_CONCRETE_WRITE
            Task_CopyToRegs(addr, &bP->Data.val, 1);
#endif
         }
      } else {
         ASSERT(addr >= PAGE_SIZE);
         if (bP->kind == Cbk_Symbolic) {
            ASSERT_KPTR(bvP);
            TaintMap_TaintMem(current, addr, 1, (void**)&bvP);
         } else {
#if PRODUCT
#error "XXX: virtual address of non-address space objects cannot be recovered by GAddr. So this is wrong."
#endif
            const ulong vAddr = GlobalAddr_GetVAddr(addr);
            ASSERT(bP->kind == Cbk_Concrete);
            ASSERT_UPTR((void*)vAddr);
#if OMIT_CONCRETE_WRITE
            err = 0;
#else
            err = copy_to_user((void*)vAddr, &bP->Data.val, 1);
#endif
            ASSERT(err || !err);
         }
      } 
   }

   return err;
}


/*
 * Updates the range with new symbolic values. Intended to be called
 * on guest updates (e.g., puts, stores, syscalls writes).
 */

void
cgMap_UpdateMAddr(const struct MAddrRange *dstRangeA, const int nrRanges,
             struct CgByte **bytePA)
{
   ASSERT_KPTR(dstRangeA);
   ASSERT(nrRanges == 1);
   ASSERT_KPTR(bytePA);

   int i, pos = 0;
   for (i = 0; i < nrRanges; i++) {
      const struct MAddrRange *rP = &dstRangeA[i];

      //cgCkptStack_OnPreUpdate(rP);

      cgMap_Write(rP, &bytePA[pos]);
      pos += rP->len;
   }
}

void
cgMap_UpdateGAddr(const struct GAddrRange *dstRangeA, const int nrRanges,
             struct CgByte **bytePA)
{
   int i, pos = 0;

   for (i = 0; i < nrRanges; i++) {
      const struct GAddrRange *grP = &dstRangeA[i];
      
      struct MAddrRange mr = { .kind = Mk_Gaddr, .start = grP->start,
         .len = grP->len };

      cgMap_UpdateMAddr(&mr, 1, &bytePA[pos]);
      pos += grP->len;
   }
}


void
cgMap_UpdateVAddr(const ulong vaddr, struct CgByte **bytePA, const size_t len)
{
   ASSERT_UPTR((void*)vaddr);
   ASSERT(len > 0);
   ASSERT_KPTR(bytePA);

   struct GAddrRange gaddrRanges[MAX_NR_RANGES];
   int nrRanges = MAX_NR_RANGES;

   const int isRead = 0;
   GlobalAddr_FromRange2(current->mm, gaddrRanges, &nrRanges, vaddr, len, isRead);
   ASSERT(nrRanges <= MAX_NR_RANGES);

   cgMap_UpdateGAddr(gaddrRanges, nrRanges, bytePA);
}

void
cgMap_WriteOrigin(const ulong vaddr, const size_t len)
{
   ASSERT(len > 0);

   STATS_ONLY(cgProf_NrTaintedInBytes += len);

   struct CgByte **bytePA = malloc(sizeof(*bytePA) * len);

   cgByte_MakeOrigin(len, bytePA);
   cgMap_UpdateVAddr(vaddr, bytePA, len);

   cgByte_PutAll(bytePA, len);

   free(bytePA);
   bytePA = NULL;
}



/* ------------------ Process management ------------------- */

/* XXX: should we track taint across files, including
 * shared memory segments? yes, we also need to destroy
 * taint when the corresponding inode has been destroyed. */
/*
 * Summary:
 *    Gets called whenever pages get unmapped, including
 *    when the address-space gets torn down on a
 *    sys_exit().
 */
void
cgMap_OnVmaUnmap(const struct VmaStruct *vmaP, ulong start, size_t len)
{
   ASSERT(vmaP->file || !vmaP->file);
   ASSERT(start >= vmaP->start && (start+len) <= (vmaP->start+vmaP->len));
   ASSERT(PAGE_ALIGNED(start));
   ASSERT(PAGE_ALIGNED(len));

   int nrBytesCleared = 0;

   DEBUG_MSG(5, "Clearing region [0x%x:0x%x].\n", start, start+len);

   /* Note that we clear all taint nodes in the vmaP region
    * regardless of whether the region is backed by a file
    * or not. Clearly we should clear all taint for the region
    * if the vmaP is not backed by a file -- the region can
    * never be accessed again and hence there is no danger
    * of tainted data propagating further.
    *
    * If the vmaP is backed by the file, we must still clear
    * taint in case the region is a private mapping.
    * Private file mappings are akin to non-file-backed
    * mappings except they are initialized with the contents
    * of the backing file on demand. Once these private mappings
    * are unmapped, their tainted contents can never be accessed
    * again. 
    *
    * Note that the vmaP could be backed by a shared file object,
    * in which case there is no harm in clearing the address space
    * region it occupies (but not the file object itself--observe
    * that we're doing a MakeMemAddr and not a MakeInodeAddr or 
    * FromVirt) -- there should be memory objects mapped to those
    * locations.
    */

   struct GAddrRange grA[2];
   int nrRanges = 2;
   const int isRead = 1;
   GlobalAddr_FromRange2(current->mm, grA, &nrRanges, start, len, isRead);
   /* [start, len] is in the same vma and we're reading, so should only 
    * span one range. */
   ASSERT(nrRanges == 1);

   struct GAddrRange *grP = &grA[0];

   struct MAddrRange mr = { .kind = Mk_Gaddr, .start = grP->start,
      .len = grP->len };

   nrBytesCleared = cgMapClear(current, &mr);

#if DEBUG
   if (vmaP->flags & MAP_SHARED) {
      ASSERT(nrBytesCleared == 0);
   }

   DEBUG_MSG(0, "[0x%x:0x%x] %d bytes untainted.\n", 
         start, start+len, nrBytesCleared);
#endif
}

/*
 * Summary:
 *    The child inherits the parent's memory state, and hence the 
 *    corresponding symbolic variables. 
 *
 *    The inherit must be done at fork time and not at thread start
 *    time, since by then the symbolic map could've changed.
 *
 * XXX:
 *    Copying should be done on-demand; COW-style.
 */
static void
cgMapInheritVmaSymbolicState(const struct VmaStruct *vmaP, void *argP)
{
   struct Task *tskP = argP;

   ASSERT_KPTR(tskP);
   ASSERT_KPTR(tskP->mm);
   ASSERT_KPTR(tskP->mm->tntMemPgMapP);
   ASSERT(tskP != current);
   ASSERT(PAGE_ALIGNED(vmaP->start))
   ASSERT(PAGE_ALIGNED(vmaP->len));

   struct GAddrRange grA[2];
   int nrRanges = 2;
   const int isRead = 1;
   GlobalAddr_FromRange2(current->mm, grA, &nrRanges, vmaP->start, vmaP->len, isRead);
   /* [start, len] is in the same vma and we're reading, so should only 
    * span one range. */
   ASSERT(nrRanges == 1);

   struct GAddrRange *grP = &grA[0];
   ASSERT(grP->len == vmaP->len);

   DEBUG_MSG(5, "Copying memory state at vma 0x%x:0x%x\n", vmaP->start, 
         vmaP->start+vmaP->len);

   size_t i;
   for (i = 0; i < grP->len; i++) {
      struct ByteVar *bvP = NULL;
      const u64 gaddr = grP->start+i;

      if (TaintMap_IsMemRangeTainted(gaddr, 1, (void**)&bvP)) {
         ASSERT_KPTR(bvP);
         struct ByteVar *newBvP = cg_GetByteVar(bvP);

         u64 gaddrChild = GlobalAddr_MakeMemAddr(tskP->mm, vmaP->start+i);
         TaintMap_TaintMem(tskP, gaddrChild, 1, (void**)&newBvP);
      }
   }
}

static void
cgMapInheritRegs(struct Task *childP)
{
   D__;

   size_t i;
   for (i = 0; i < MAX_NR_REGS; i++) {
      struct ByteVar *bvP = NULL;

      /* Child should inherit's parent's byteVars. */
      if (TaintMap_IsRegTainted(current, i, 1, (void**)&bvP)) {
         ASSERT_KPTR(bvP);

         struct ByteVar *newBvP = cg_GetByteVar(bvP);
         TaintMap_TaintReg(childP, i, 1, (void**)&newBvP);
      }
   }
}

/*
 * Summary:
 *    The child inherits the parent's register (threads and processes)
 *    and private memory symbolic state (threads by default, processes
 *    need extra work).
 *
 *    Must be done at fork time rather than at thread start time, since
 *    the registers would've changed at the latter time.
 *    XXX: explain how they would've changed
 *
 *    Makes sure that constraint variable reference counts are updated.
 */
void
cgMap_OnTaskFork(struct Task *childP)
{
   ASSERT_KPTR(childP->mm);

   TaintMap_OnTaskFork(childP);

   if (childP == current) {
      /* Nothing to inherit. */
      ASSERT(childP == &initTask);
      return;
   }

   cgMapInheritRegs(childP);

   if (!Task_IsThread(childP)) {
      /* New address space; child inherits parent's memory symboic 
       * values. */
      Vma_Iterate(&cgMapInheritVmaSymbolicState, childP);
   } else {
      /* Child uses the same addresses space as parent, so no additional
       * work need be done. */
   }
}

/*
 * Summary:
 *
 * Frees all symbolic register values. 
 */
void
cgMap_OnTaskExit(struct Task *tskP)
{
   const struct MAddrRange mr = { .kind = Mk_Reg, .start = 0, 
      .len = MAX_NR_REGS };
   cgMapClear(tskP, &mr);
   TaintMap_OnTaskExit(tskP);
}
