#include "vkernel/public.h"
#include "private.h"


struct ShmStruct *
ShmFs_Alloc()
{
   struct ShmStruct *shmp;

   shmp = SharedArea_Malloc(sizeof(*shmp));
   memset(shmp, 0, sizeof(*shmp));

   return shmp;
}

void
ShmFs_Free(struct ShmStruct *shmp)
{
   memset(shmp, 0, sizeof(*shmp));
   SharedArea_Free(shmp, sizeof(*shmp));
}


struct ShmStruct *
ShmFs_GetStruct(struct InodeStruct *inodp)
{
   struct ShmStruct *shmp = (struct ShmStruct *) inodp->data;

   ASSERT(Inode_GetMajor(inodp) == InodeMajor_Shm);

   ASSERT(shmp);

   return shmp;
}

/* 0 is invalid, and 1 is reserved for the root inode. */
static SHAREDAREA uint shmGen = 2;

/* Create an unlinked file object with inode corresponding to a shared mapping. */
struct FileStruct *
ShmFs_Create(size_t size, int flags, int isAnon)
{
   int err;
   struct DentryStruct *root = sbShm->root, *dentryp;
   struct FileStruct *filp;
   struct ShmStruct *shmp;
   char name[32];
   ino_t ino;
  

   Inode_Lock(root->inode);

   /* NOTE: we protect the shmCount increment with the rot inode lock */
   ino = shmGen++;
   snprintf(name, sizeof(name), "shmem:%lu", ino);

   dentryp = Dentry_Open(root, name, O_CREAT | O_EXCL);
   if (IS_ERR(dentryp)) {
      filp = (struct FileStruct *)dentryp;
      goto out;
   }

   shmp = ShmFs_Alloc();
   shmp->size = size;
   shmp->flags = flags;
   shmp->isAnon = isAnon;
   shmp->ino = ino;

   err = VFS_create(root->inode, dentryp, MODE_PERM(flags), (void*) shmp);
   if (err) {
      filp = ERR_PTR(err);
      goto out_frees;
   }

   filp = File_DentryOpen(dentryp, O_RDWR, 0);
   if (IS_ERR(filp)) {
      /* XXX: you need to somehow clean up the recently created file (call sys_unlink?) */
      ASSERT_UNIMPLEMENTED(0);
      goto out_frees;
   }

   goto out_putd;

out_frees:
   ShmFs_Free(shmp);
out_putd:
   Dentry_Put(dentryp);
out:
   Inode_Unlock(root->inode);
   return filp;
}

int 
ShmFs_CreateAnonymous(struct VmaStruct *vma)
{
   int err = 0;
   struct FileStruct *filp;

   ASSERT(vma);

   filp = ShmFs_Create(vma->len, 0, 1);
   if (IS_ERR(filp)) {
      err = PTR_ERR(filp);
      goto out;
   }

   ASSERT(filp);
   ASSERT(!vma->file);

   vma->file = filp;
   vma->ops = NULL;

out:
   return err;
}
