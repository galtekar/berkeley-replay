#include "vkernel/public.h"
#include "private.h"

#if 0
#undef DEBUG_MSG
#define DEBUG_MSG(lvl, s, ...) \
		   CUSTOM_PRINTF(0, CURRENT_LFD, s, ##__VA_ARGS__);
#endif

static void
DentryLock(struct DentryStruct *dentryp)
{
   ORDERED_LOCK(&dentryp->lock);
}

static void
DentryUnlock(struct DentryStruct *dentryp)
{
   ORDERED_UNLOCK(&dentryp->lock);
}

void
Dentry_Instantiate(struct DentryStruct *base, struct InodeStruct *inodp)
{
   /* Dentries should never be reused... */
   ASSERT(base->inode == NULL);

   base->inode = inodp;
}

struct DentryStruct *
Dentry_Get(struct DentryStruct *dentryp)
{
   ASSERT_KPTR(dentryp);

   DentryLock(dentryp);

   /* Should NOT do a get on a dropped dentry -- it is no
    * longer allocated and so this would be an invalid
    * pointer. */
   ASSERT(dentryp->count > 0);

   dentryp->count++;

   ASSERT(dentryp->name);

   DEBUG_MSG(5, "name=%s count=%d\n", dentryp->name, dentryp->count);

   DentryUnlock(dentryp);

   return dentryp;
}

static struct DentryStruct *
DentryAlloc(struct DentryStruct *parent, const char *name)
{
   ASSERT_KPTR(name);

   size_t nameLen = strlen(name)+1;

   struct DentryStruct *dentryp = SharedArea_Malloc(sizeof(*dentryp));
   memset(dentryp, 0, sizeof(*dentryp));

   dentryp->count = 1;
  
   dentryp->name = SharedArea_Malloc(nameLen);
   strncpy(dentryp->name, name, nameLen);

   ORDERED_LOCK_INIT(&dentryp->lock, "dentry");

   /* The root inode doesn't have a parent. */
   ASSERT(parent || !parent);

   if (parent) {
      dentryp->parent = Dentry_Get(parent);
   }

   DEBUG_MSG(5, "count=%d\n", dentryp->count);
   ASSERT(dentryp->count == 1);

   return dentryp;
}

struct DentryStruct *
Dentry_AllocRoot(struct InodeStruct *root_inode)
{
   struct DentryStruct *dentryp;

   ASSERT(root_inode);

   dentryp = DentryAlloc(NULL, "/");

   if (dentryp) {
      dentryp->parent = dentryp;
      Dentry_Instantiate(dentryp, root_inode);
   }

   return dentryp;
}

static void
DentryFree(struct DentryStruct *dentryp)
{
   memset(dentryp, 0, sizeof(*dentryp));
   SharedArea_Free(dentryp, sizeof(*dentryp));
}

void
Dentry_Put(struct DentryStruct *dentryp)
{
   ASSERT_KPTR(dentryp);


   DentryLock(dentryp);

   int count = --dentryp->count;

#if DEBUG
   DEBUG_MSG(5, "dentryp=0x%x name=%s count=%d\n", 
         dentryp, dentryp->name, count);
#endif
   ASSERT(count >= 0);

   DentryUnlock(dentryp);

   ASSERT_KPTR(dentryp->name);

   if (!count) {
      if (dentryp->inode) {
         Inode_Put(dentryp->inode);
         dentryp->inode = NULL;
      }

      /* XXX: For now, we expect only one level of recursion, since the parent
       * is the mount root. This may well change later... */
      ASSERT_KPTR(dentryp->parent);
      Dentry_Put(dentryp->parent);

      DentryFree(dentryp);
      dentryp = NULL;
   }
}

struct DentryStruct *
Dentry_Lookup(struct DentryStruct *dir, const char *name)
{
   int err;
   struct DentryStruct *dentryp;
   struct InodeStruct *idir = dir->inode;

   ASSERT(Inode_IsLocked(idir));

   /* XXX: do a cache lookup for the dentry to be more memory efficient */

   dentryp = DentryAlloc(dir, name);

   DEBUG_MSG(5, "name=%s count=%d\n", dentryp->name, dentryp->count);

   /* We must pass in the name because Linux doesn't provide an
    * easy way to lookup a file by inode number. Also, we expect
    * Inode_Lookup to fill in dentry with the proper inode. */
   err = Inode_Lookup(idir, dentryp);

   DEBUG_MSG(5, "name=%s count=%d\n", dentryp->name, dentryp->count);

   if (err) {
      ASSERT(!dentryp->inode);
      /* Don't do a put -- the dentryp->inode is not initialized */
      Dentry_Put(dentryp);
      dentryp = ERR_PTR(err);
   } else {
      ASSERT_PTR(dentryp->inode);
      ASSERT(dentryp->inode->i_op);
      ASSERT(dentryp->inode->f_op);
   }

   return dentryp;
}



/* 
 * Takes DentryStruct for the base rather than path to help special
 * filesystems.
 */
struct DentryStruct *
Dentry_Open(struct DentryStruct *dir, const char *path, int flags)
{
   int err;
   struct DentryStruct *dentryp;

   ASSERT(Inode_IsLocked(dir->inode));

   D__;

   dentryp = Dentry_Lookup(dir, path);

   D__;

   if (!(flags & O_CREAT)) {
      goto out;
   }

   if (!IS_ERR(dentryp)) {
      D__;
      /* File already exists. */
      if(flags & O_EXCL) {
         err = -EEXIST;
         goto error_out;
      }
   } else {
      D__
      dentryp = DentryAlloc(dir, path);
   }

   D__;

   goto out;

error_out:
   /* No need to remove entry from cache -- we never inserted it. */
   Dentry_Put(dentryp);
   dentryp = ERR_PTR(err);
out:
   return dentryp;
}
