#include "vkernel/public.h"
#include "private.h"

SHAREDAREA struct MapStruct *unresSetP = NULL;
SHAREDAREA struct MapStruct *cfgMapP = NULL;

typedef enum {
   Nk_NonBranch,
   Nk_Cond,
   Nk_Direct,
   Nk_Indirect,
} NodeKind;

typedef enum {
   Ns_Unresolved, /* Not all successor has been hooked up yet. */
   Ns_Pending, /* Pending exploration of successors. */
   Ns_Resolved, /* All successors have been hooked up. */
} NodeStatus;

#define MAX_PARENTS 3

typedef u64 CFGNodeID;

struct CFGNode {
   struct MapKey64 cfg;
   struct MapKey64 unres;

   NodeStatus status;

   NodeKind kind; 

   /* CFG is not, in general, a tree (a node may have multiple parents);
    * hence we need multiple sibling lists. */
   struct ListHead siblings[MAX_PARENTS];
   int nrParents;

   struct ListHead children;

   struct ListHead stack[2];
};

#if 0

static INLINE u64
CFGNodeMkId(ulong insnAddr, int brId)
{
   u64 res = ((u64)insnAddr << 32) | brId;

   return res;
}

static INLINE ulong
CFGNodeGetInsnAddr(CFGNodeID id)
{
#if !DEBUG
#error "XXX: doesn't work for 64-bit address spaces"
#endif
   return (id >> 32) & 0xFFFFFFFF;
}

static struct CFGNode *
CFGNodeAlloc()
{
   struct CFGNode *nodeP = malloc(sizeof(*nodeP));

   memset(nodeP, 0, sizeof(*nodeP));

   return nodeP;
}


static void
CFGNodeLink(struct CFGNode *srcP, struct CFGNode *dstP)
{
   ASSERT(dstP->nrParents < MAX_PARENTS);

   struct ListHead *sibP = &dstP->siblings[dstP->nrParents++];

   List_AddTail(sibP, &srcP->children);
}

static struct CFGNode *
CFGFind(CFGNodeID id)
{
   struct CFGNode *nP;

   nP = Map_Find64(cfgMapP, cfg, id, nP);

   return nP;
}

static struct CFGNode *
CFGNodeGet(ulong dstAddr, int brId)
{
   struct CFGNode *dstP;
   CFGNodeID id = CFGNodeMkId(dstAddr, brId);

   if (!(dstP = CFGFind(id))) {
      dstP = CFGNodeAlloc();
      Map_NodeInit64(&dstP->cfg, id);
      dstP->kind = Nk_NonBranch;
      dstP->status = Ns_Unresolved;

      int i;
      for (i = 0; i < MAX_PARENTS; i++) {
         List_Init(&dstP->siblings[i]);
      }
      dstP->nrParents = 0;

      List_Init(&dstP->children);
      List_Init(&dstP->stack[0]);
      List_Init(&dstP->stack[1]);

      Map_Insert64(cfgMapP, cfg, id, dstP);
   }

   return dstP;
}
#endif

#if 0
/*
 * Summary:
 *
 * Computes the feasible subgraph of the cfg. One can obtain the set of
 * all paths from @src to @dst by performing a DFS traversal of this
 * feasible subgraph.
 *
 * We compute the subgraph using DFS. Exporation along a CFG path stops 
 * when we reach a dead end, a previously visited backwards branch 
 * (signifying a loop), or the sink node.
 */
struct CFGNode *
CFG_FindFeasibleSubCFG(CFGNodeID src, CFGNodeID sink)
{
   struct CFGNode *startNodeP = CFGNodeFind(src), *nP;

   LIST_HEAD(dfsStack);
   LIST_HEAD(pathStack);

   Stack_Push(&dfsStack, stack[0], startNodeP);

   while (Stack_Pop(&dfsStack, stack[0], nP)) {
      Stack_Push(&pathStack, stack[1], nP);

      if (nP->id == sink) {
         list_for_each_entry(eP, currPathP) {
            if (eP->next) {
               CFGLink(feasibleGraph, eP, eP->next);
            }
         }
      } else {
         list_for_each_entry(succP, nP) {
            /* Explore loops only once. */
#error "XXX: once per path"
            if (!(IsBackward(succP) && succP->wasVisited)) {
               Stack_Push(stackP, succP);
            }
         }
      }
   }

   return startNodeP;
}

static int
CFGUpdateWork(struct ListHead *stackP, ulong currInsAddr, int subNodeId, ulong exitDstAddr)
{
   struct CFGNode *prevNodeP, *currP;

   prevNodeP = Stack_Pop(stackP, prevNodeP);
   ASSERT(prevNodeP->Status == Ns_Pending);

   ASSERT(currInsAddr);
   currP = CFGNodeGet(currInsAddr, subNodeId);
   CFGLink(prevNodeP, currP);
   /* All successors have been linked. */
   prevNodeP->status = Ns_Resolved;

   if (currP->status != Ns_Unresolved) {
      /* Pending or resolved; we've been here before, so we are done. */
      return 0;
   }

   if (exitDstAddr == 1) {
      /* No sucessors, because target is indirect and thus statically 
       * unknown. */
      currP->status = Ns_Resolved;
   } else {
      /* Has successors, either 1 or 2, the latter for exits. */
      
      if (exitDstAddr != 0) {
         /* TWo successors possible. */
         ASSERT_UPTR((void*)exitDstAddr);
         struct CFGNode *dstP = CFGNodeGet(exitDstAddr, 0);
         CFGLink(currP, dstP);

         if (dstP->status == Ns_Unresolved) {
            dstP->status = Ns_Pending;
            Stack_Push(stackP, dstP);
         } 
      }

      /* So we don't push it multiple times. */
      currP->status = Ns_Pending; 
      Stack_Push(stackP, currP);
   }

   return 1;
}
#endif

static IRSB *
CFGInstrument(void *opaque, IRSB *bbP, VexGuestLayout *layout,
      VexGuestExtents *extents, IRType gWorTy, IRType hWordTy)
{

   ppIRSB(bbP);
#if 0
   ListHead *stackP = (ListHead*) argP;
   ASSERT_KPTR(stackP);

   int i, subNodeId = 0, nodeCount = 0;
   struct CFGNode *prevNodeP, *currP;
   ulong currInsAddr = 0, currInsLen = 0;

   ASSERT(Map_Find(currP));

   for (i = 0; i < bbIn->stmts_used; i++) {
      IRStmt *stP = bbIn->stmts[i];

      if (stP->tag == Ist_IMark || stP->tag == Ist_Exit) {

         if (stP->tag == Ist_IMark) {
            currInsAddr = stP->Ist.IMark.addr;
            currInsLen = stP->Ist.IMark.len;
            subNodeId = 0;
         } 

         /* The first node has already been added (top of stack). */
         if (nodeCount > 0) {
            ulong exitAddr = stP->tag == Ist_Exit ? 
               stP->Ist.Exit.dst.Ico.U32 : 0;
            if (!CFGAddNode(stackP, currInsAddr, subNodeId, exitAddr)) {
               return;
            }
         }

         subNodeId++;
         nodeCount++;
      }
   }

   ulong exitAddr = BinTrns_IsIndirectExit(bbP) ? 1 : ConstVal(bbP);
   nP = CFGAddNode(stackP, currInsAddr, subNodeId, exitAddr);
#endif

   return bbP;
}


#if 0
static void
CFGExpandGraph(struct ListHead *dfsStackP)
{
   struct CFGNode *nP;

   while ((nP = Stack_PeekTop(dfsStackP, nP))) {
      if (nP within range) {
         /* XXX: what if it straddles? */
         BT_Translate(currP->insnAddr, &CFGInstrument, &unresStack);
      } else {
         /* Target is not in this vma, so we must defer translation to
          * when the vma is mapped in. */
         nP = Stack_Pop(&unresStack, np);
         List_AddTail(nP, &leftOverList);
      }
   }
}

static INLINE int
AddrInRange(ulong addr, ulong start, size_t len)
{
   return start <= addr && addr < (start + len);
}


static void
CFGResolveNodes(ulong start, size_t len)
{
   LIST_HEAD(dfsStack);

   struct CFGNode *nP;

   list_for_each_entry(nP, Map_GetList(unsesSetP), list) {
      if (AddrInRage(CFGNodeGetInsnAddr(nP->id), start, len)) {
         nP = Map_Remove(unresSetP, unres, nP);
         Stack_Push(&dfsStack, nP);
      }
   }
   
   CFGExpandGraph(&dfsStack);

   while ((nP = Stack_Pop(&dfsStack, nP))) {
      ASSERT(nP->status != Ns_Resolved);
      Map_InsertNoDup64(unresSetP, unres, nP);
   }
}
#endif

#define VEX_CODE_BUFSZ 60000

/* Where we hold translated code before copying it into
 * the translation cache. Necessary b/c we need to determine
 * the size of the code block before placing the translated
 * code in the code cache (otherwise we must assume some
 * large upper bound and that's wastefull of memory) */
static uchar tc_staging_buf[VEX_CODE_BUFSZ];

void
CFG_OnProtFault(const ulong faultAddr)
{
   int codeLen = 0;
   VexGuestExtents vge;

   BT_Translate(faultAddr, tc_staging_buf, VEX_CODE_BUFSZ, &codeLen, 
         &vge, &CFGInstrument, NULL);
}

void
CFG_OnVmaMap(const struct VmaStruct *vmaP)
{
   ASSERT_UNIMPLEMENTED(0);

   if (vmaP->prot & PROT_EXEC) {
      /* XXX: this apparently fires */
      ASSERT(!(vmaP->prot & PROT_WRITE));

      DEBUG_MSG(5, "vma: start=0x%x len=0x%x prot=0x%x file=%s\n",
            vmaP->start, vmaP->len, vmaP->prot, 
            vmaP->file ? File_Name(vmaP->file) : "none");

      //mprotect((void*)vmaP->start, vmaP->len, PROT_NONE);
   }

#if 0
   struct CFGNode *nP;

   nP = CFGNodeGet(addr, 0);
   Map_InsertNoDup64(unresSetP, unres, nP);

   CFGResolveNodes(PAGE_START(addr), PAGE_SIZE);
#endif
}

void
CFG_Init()
{
#if 0
   unresSetP = Map_Create(0);
   cfgMapP = Map_Create(0);
#endif
}

#if 0
static void
CFGDel(ulong start, ulong end)
{
   for_all_cfg_nodes() {
      if (InRange(nodP, start, end)) {
         Unlink(nodP, parents);
         Put_unresovled_nodes_in_unresolved_list;

         Unlink(nodP, children);
      }
   }
}

void
CFG_OnVmaUnmap(start, len)
{
   CFGDel(start, end);
}
#endif
