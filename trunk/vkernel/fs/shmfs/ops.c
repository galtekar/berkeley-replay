#include "vkernel/public.h"
#include "private.h"


/* 
 * ----------------------------------------
 *
 * Inode ops.
 *
 * ----------------------------------------
 */

static long
ShmFsNamedCreate(struct ShmStruct *shmp)
{
   int err;


   if (!VCPU_IsReplaying()) {
      err = SysOps_ShmGet(IPC_PRIVATE, shmp->size, shmp->flags);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);

      if (!err) {

         err = SysOps_ShmGet(IPC_PRIVATE, shmp->size, shmp->flags);
         /* XXX: if we can't allocate the resource during replay,
          * what should we do? fail gracefully? */
         ASSERT_UNIMPLEMENTED(!err);
      }
   }

   if (!err) {
      shmp->shmid = err;
      ASSERT(shmp->shmid >= 0);
   }

   return err;
}

static long
ShmFs_create(struct InodeStruct *dir, struct DentryStruct *dentryp, int mode, void *data)
{
   int err = 0;
   struct ShmStruct *shmp;
   struct InodeStruct *inodp;

   shmp = (struct ShmStruct *) data;

   if (!shmp->isAnon) {
      err = ShmFsNamedCreate(shmp);
      if (err) {
         goto out;
      }
   }

   inodp = Inode_Get(dir->sb, dentryp->name, shmp->ino);
   inodp->data = data;
   inodp->minor = (shmp->isAnon) ? 
      InodeMinor_ShmAnon : InodeMinor_ShmNamed;

   /* Make sure we aren't grabbing some existing inode. 
    * This inode should be brand new (and the INode_Get
    * should've missed in the inode cache). */
   ASSERT(inodp->count == 1);

   Dentry_Instantiate(dentryp, inodp);

out:
   return err;
}

static const struct InodeOps ShmFs_Iops = {
   .create =      &ShmFs_create
};


/* 
 * ----------------------------------------
 *
 * File ops.
 *
 * ----------------------------------------
 */
 

static ulong
ShmFs_mmap(struct FileStruct *filp, struct VmaStruct *vma)
{
   int err = 0, res;
   ulong raddr = -1;
   struct InodeStruct *inodp = File_Inode(filp);
   struct ShmStruct *shmp = ShmFs_GetStruct(inodp);

   /* No need to log/replay results of these address-space
    * operations. We expect them to always succeed. We're
    * in trouble if they don't or some reason. */

   switch (Inode_GetMinor(inodp)) {
   case InodeMinor_ShmNamed:
      ASSERT(shmp->shmid > 0);
      res = SysOps_ShmAt(shmp->shmid, (void*)vma->start, 0, &raddr);
      ASSERT(!SYSERR(res));
      ASSERT(raddr == vma->start);
      break;
   case InodeMinor_ShmAnon:
      ASSERT(shmp->shmid == 0);
      ASSERT(PAGE_ALIGNED(vma->len));
      res = syscall(SYS_mmap2, vma->start, vma->len, vma->prot,
            MAP_FIXED | MAP_ANONYMOUS | MAP_SHARED, -1, 0);
      ASSERT(res == vma->start);
      break;
   default:
      ASSERT(0);
      break;
   }

   return err;
}

static const struct FileOps ShmFs_Fops = {
   .mmap =        &ShmFs_mmap,
};

/* 
 * ----------------------------------------
 *
 * Superblock ops.
 *
 * ----------------------------------------
 */


struct InodeStruct *
ShmFs_alloc_inode(struct SuperBlockStruct *sb)
{
   struct InodeStruct *inodp;

   inodp = Inode_GenericAlloc(sb);
   inodp->i_op = &ShmFs_Iops;
   inodp->f_op = &ShmFs_Fops;
   inodp->major = InodeMajor_Shm;

   return inodp;
}

void
ShmFs_free_inode(struct InodeStruct *inodp)
{
   struct ShmStruct *shmp = ShmFs_GetStruct(inodp);

   ShmFs_Free(shmp);

   Inode_GenericFree(inodp);
}

static void
ShmFsNamedDestroy(struct InodeStruct *inodp)
{
   int err;
   struct ShmStruct *shmp = ShmFs_GetStruct(inodp);

   ASSERT(shmp->shmid > 0);

   /* No need to synch: since we are dropping the last reference,
    * it shouldn't be accessible through a table somewhere, and hence
    * there is no worry of a concurrent lookup... */
   err = SysOps_ShmCtl64(shmp->shmid, IPC_RMID, NULL);

   /* XXX: For the remove to be successfull, Linux performs several checks
    * before actually removing the segment from its internal data structures.
    * These checks include segment permission checks and a check of whether
    * the segment has already been removed. We assume that all of these checks
    * be performed upstream such that the detach is error-free. */
   ASSERT(!err);

   inodp->data = NULL;
}

static void
ShmFs_drop_inode(struct InodeStruct *inodp)
{
   if (Inode_GetMinor(inodp) == InodeMinor_ShmNamed) {
      ShmFsNamedDestroy(inodp);
   }
}

static struct SuperBlockOps ShmFs_SbOps = {
   .alloc_inode =       &ShmFs_alloc_inode,
   .free_inode =        &ShmFs_free_inode,
   .drop_inode =        &ShmFs_drop_inode,
};

struct SuperBlockStruct *
ShmFs_GetSb()
{
   return SuperBlock_AllocPseudo("shmfs", &ShmFs_SbOps);
}

SHAREDAREA struct SuperBlockStruct *sbShm;

static int
ShmFs_Init()
{
   DEBUG_MSG(5, "ShmFs\n");

   sbShm = ShmFs_GetSb();

   return 0;
}

FS_INITCALL(ShmFs_Init);
