#include "vkernel/public.h"
#include "private.h"


#if MAX_NR_VCPU > 1 && PRODUCT
#error "XXX: needs to be locked or made atomic"
#else
SHAREDAREA u64 cgProf_NrTaintedInBytes = 0;
SHAREDAREA u64 cgProf_NrTaintedOutBytes = 0;
SHAREDAREA u64 cgProf_NrTotalInBytes = 0;
SHAREDAREA u64 cgProf_NrTotalOutBytes = 0;
#endif


static SHAREDAREA struct MapStruct *cgBinMapP = NULL;
SYNCH_DECL_INIT(static SHAREDAREA, cgBinMapLk);


struct PageNode {
   struct MapField pgNo;
};


void
cgProf_AddAccess(const ProfAccessKind kind, const ulong vaddr)
{
   //struct CgenInsnNode *cP = cgGetInsnProf();
   const ulong pgNo = PAGE_NUM(vaddr);

   struct PageNode *pgP = NULL;
  
   if (!Map_Find(curr_vcpu->pgAccessMapP, pgNo, pgNo, pgP)) {
      pgP = malloc(sizeof(*pgP));
      Map_NodeInit(&pgP->pgNo, pgNo);
      Map_Insert(curr_vcpu->pgAccessMapP, pgNo, pgNo, pgP);
   }

#if 0
   if (kind == Pak_Read) {
   } else {
      ASSERT(kind == Pak_Write);
   }
#endif
}

/* XXX: we need to create on resume and destroy on exit to ensure that
 * map is destroyed when vcpu terminates. */
#define RESET_PERIOD 300
void
cgProf_OnResumeUserMode()
{
   struct PageNode *pgP;

   if (curr_vcpu->resumeUserCount % RESET_PERIOD == 0) {

      if (curr_vcpu->pgAccessMapP) {
         int nrPagesAccessedSinceLastSystemEvent = 
            Map_GetSize(curr_vcpu->pgAccessMapP);
         curr_vcpu->maxNrPagesAccessedBetweenSystemEvents = 
            MAX(curr_vcpu->maxNrPagesAccessedBetweenSystemEvents,
                  nrPagesAccessedSinceLastSystemEvent);

         STATS_MSG("Accessed %d pages in previous system segment.\n", 
               nrPagesAccessedSinceLastSystemEvent);
         Map_Destroy(curr_vcpu->pgAccessMapP, pgNo, pgP);
      }

      curr_vcpu->pgAccessMapP = Map_Create(0);
   }

   curr_vcpu->resumeUserCount++;
}

/*
 * Update instruction node stats for the DSO/executable that
 * maps to this EIP.
 */
void
cgProf_MoveToInsn(const HWord eip)
{
   struct CgenFileNode *filNodP;
   struct CgenInsnNode *insnNodP;
   const char defFilename[] = "?";
   const char *fileNameP;
   ulong fileIno;

   ASSERT_KPTR(cgBinMapP);

   if (Task_IsAddrInImage(eip)) {
      ASSERT(Task_IsAddrInVDSO(eip));
      /* XXX: VDSO insns don't have an associated VMaStruct, but
       * they should since they are part of user-level
       * code. */
      ASSERT_KPTR(current->cgCurrInsnP);
      ASSERT_KPTR(current->cgCurrBinP);
      WARN_XXX(0);
      return;
   }

   UNORDERED_LOCK(&current->mm->vmaLock);
   const struct VmaStruct *vmaP = Vma_FindIntersect(current->mm, eip, 1);
   UNORDERED_UNLOCK(&current->mm->vmaLock);
   ASSERT_KPTR(vmaP);

   ulong fileOff = PAGE_SIZE*vmaP->pgoff + (eip - vmaP->start);

   if (vmaP->file) {
      fileNameP = Dentry_Name(File_Dentry(vmaP->file));
      ASSERT_KPTR(fileNameP);

      fileIno = File_Inode(vmaP->file)->inoMap.keyLong;
   } else {
      fileNameP = defFilename;
      fileIno = current->mm->id;
      ASSERT(fileOff == eip);
   }

#if 0
   DEBUG_MSG(0, "vmaP->pgoff=%lu fileOff=%lu\n", 
         vmaP->pgoff, fileOff);
#endif
#if MAX_NR_VCPU > 1 && PRODUCT
   #error "XXX: replace with reader/write lock, heavy contention\n"
#endif

   SYNCH_LOCK(&cgBinMapLk);

   Map_Find64(cgBinMapP, fileMap, fileIno, filNodP);

   if (!filNodP) {
      filNodP = malloc(sizeof(*filNodP));
      memset(filNodP, 0, sizeof(*filNodP));
      Map_NodeInit64(&filNodP->fileMap, fileIno);
      strncpy(filNodP->name, fileNameP, sizeof(filNodP->name)-1);
      int i;
      for (i = 0; i < cg_OptNumBBoxReg; i++) {
         const struct CgenBBoxRegion *rP = &cg_OptBBoxRegA[i];
         if (strstr(fileNameP, rP->dsoName)) {
            //ASSERT_MSG(0, "fileNameP=%s dsoName=%s\n",
            //      fileNameP, rP->dsoName);
            filNodP->isUnconstrained = 1;
            break;
         }
      }

      filNodP->insnMapP = Map_Create(0);
      Map_Insert64(cgBinMapP, fileMap, fileIno, filNodP);
   }


   Map_Find64(filNodP->insnMapP, offMap, fileOff, insnNodP);

   if (!insnNodP) {
      insnNodP = malloc(sizeof(*insnNodP));
      memset(insnNodP, 0, sizeof(*insnNodP));
      Map_NodeInit64(&insnNodP->offMap, fileOff);
      Map_Insert64(filNodP->insnMapP, offMap, fileOff, insnNodP);
   }
   ASSERT_KPTR(insnNodP);
   insnNodP->nrExec++;

   SYNCH_UNLOCK(&cgBinMapLk);

   current->cgCurrBinP = filNodP;
   current->cgCurrInsnP = insnNodP;
}


void
cgProf_Init()
{
   int i;

   cgBinMapP = Map_Create(0);

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpuP = VCPU_Ptr(i);

      vcpuP->pgAccessMapP = NULL;
      vcpuP->maxNrPagesAccessedBetweenSystemEvents = 0;
      vcpuP->resumeUserCount = 0;
   }
}

static void
cgProfOutputResults()
{
   int nrStaticInsns = 0, nrTaintedStaticInsns = 0;
   struct CgenFileNode *filNodP = NULL;

   STATS_MSG(" ----- BEGIN Constraint profile (per Insn) -----\n");
   list_for_each_entry(filNodP, &cgBinMapP->list, fileMap.list) {
      struct CgenInsnNode *insnNodP = NULL;

      list_for_each_entry(insnNodP, &filNodP->insnMapP->list, offMap.list) {
         STATS_MSG("[Prof] %s 0x%llx %llu %llu\n", 
               filNodP->name, insnNodP->offMap.key64, insnNodP->nrCnstr,
               insnNodP->nrExec);

         if (insnNodP->nrCnstr > 0) {
            nrTaintedStaticInsns++;
         }
      }

      nrStaticInsns += Map_GetSize(filNodP->insnMapP);

      Map_Destroy(filNodP->insnMapP, offMap, insnNodP);
   }

   STATS_MSG("frac. insns tainted = %d/%d\n", nrTaintedStaticInsns, nrStaticInsns);
   STATS_MSG(" ----- END Constraint profile -----\n");

   Map_Destroy(cgBinMapP, fileMap, filNodP);
   cgBinMapP = NULL;
}


void
cgProf_Fini()
{
   int i;

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpuP = VCPU_Ptr(i);

      STATS_MSG("maxNrPagesAccessedBetweenSystemEvents=%d\n",
            vcpuP->maxNrPagesAccessedBetweenSystemEvents);
   }

   cgProfOutputResults();

   STATS_MSG("frac. nrTaintedInBytes = %llu / %llu\n", 
         cgProf_NrTaintedInBytes,
         cgProf_NrTotalInBytes);
   STATS_MSG("frac. nrTaintedOutBytes = %llu / %llu\n", 
         cgProf_NrTaintedOutBytes,
         cgProf_NrTotalOutBytes);
}
