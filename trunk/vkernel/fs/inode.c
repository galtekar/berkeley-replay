#include "vkernel/public.h"
#include "private.h"

#if 0
#undef DEBUG_MSG
#define DEBUG_MSG(lvl, s, ...) \
		   CUSTOM_PRINTF(0, CURRENT_LFD, s, ##__VA_ARGS__);
#endif

struct InodeStruct *
Inode_GenericAlloc(struct SuperBlockStruct *sb)
{
   struct InodeStruct *inodp;

   inodp = malloc(sizeof(*inodp));
   memset(inodp, 0, sizeof(*inodp));
   inodp->sb = sb;
   ORDERED_LOCK_INIT(&inodp->lock, "inode");
   inodp->count = 1;
   Map_NodeInit(&inodp->inoMap, 0);

   DEBUG_MSG(5, "inodp=0x%x\n", inodp);

   return inodp;
}

void
Inode_GenericFree(struct InodeStruct *inodp)
{
   ASSERT_KPTR(inodp);

   memset(inodp, 0, sizeof(*inodp));

   DEBUG_MSG(5, "inodp=0x%x\n", inodp);
   free(inodp);
   inodp = NULL;
}

static struct InodeStruct *
InodeAlloc(struct SuperBlockStruct *sb, ino_t ino)
{
   struct InodeStruct *inodp;

   inodp = sb->ops->alloc_inode(sb);
   inodp->inoMap.keyLong = ino;

   return inodp;
}

static void
InodeFree(struct InodeStruct *inodp)
{
   inodp->sb->ops->free_inode(inodp); 
}


#if 0
static INLINE u64 
IcacheHashId(struct SuperBlockStruct *sb, ino_t ino)
{
   u64 id;

   DEBUG_MSG(5, "ino=%d\n", ino);
   ASSERT(ino > 0);

   id = sb->id;
   id <<= 32;
   id |= ino;

   return id;
}
#endif

static void
IcacheInsert(struct InodeStruct *inodp)
{
   struct SuperBlockStruct *sb = inodp->sb;

   ASSERT_KPTR(sb);

#if 0
   Map_Insert(sb->inodeMap, 
         IcacheHashId(sb, Inode_Ino(inodp)), inodp);
#else
   Map_Insert(sb->inodeMap, inoMap, Inode_Ino(inodp), inodp);
#endif
}

static void
IcacheRemove(struct InodeStruct *inodp)
{
   struct SuperBlockStruct *sb = inodp->sb;

   ASSERT(sb);

   /* This shouldn't deallocate inodp, but should
    * simply remove it from the map. */
   Map_Remove(sb->inodeMap, inoMap, inodp);

   ASSERT(inodp);
}

struct InodeStruct *
IcacheFind(struct SuperBlockStruct *sb, ino_t ino)
{
   struct InodeStruct *inodp;

#if 0
   Map_Find(sb->inodeMap, IcacheHashId(sb, ino), inodp);
#else
   Map_Find(sb->inodeMap, inoMap, ino, inodp);
#endif

   return inodp;
}

/* XXX: ideally, we should need only the @ino, but Linux won't
 * let us lookup files by ino from user space and so we also 
 * need the name. */
struct InodeStruct *
Inode_Get(struct SuperBlockStruct *sb, const char *name, ino_t ino)
{
   ASSERT_KPTR(sb);
   ASSERT_KPTR(name);

   int err;
   struct InodeStruct *inodp;

#if DEBUG
   if (sb->root) {
      /* This function doesn't really need the parent inode lock,
       * but we verify that it is locked, since this is on
       * the Path_Resolve code path. */
      ASSERT(Inode_IsLocked(sb->root->inode)); 
   } else {
      /* We're initializing the superblock, so sb->root shouldn't
       * be filled in yet. */
   }
#endif

   /* Protects against concurrent Inode_Puts. */
   Super_Lock(sb);

   DEBUG_MSG(5, "Looking up ino %d.\n", ino);
   inodp = IcacheFind(sb, ino);

   if (inodp) {
      DEBUG_MSG(5, "Cache hit.\n");
      ASSERT_KPTR(inodp->sb);
      inodp->count++;
   } else {
      DEBUG_MSG(5, "Cache miss.\n");
      inodp = InodeAlloc(sb, ino);
      ASSERT_KPTR(inodp->sb);

      /* Special filesystems needn't implement this. */
      if (sb->ops->read_inode) {
         err = sb->ops->read_inode(inodp, name);
         DEBUG_MSG(5, "err=%d\n", err);
         if (err) {
            InodeFree(inodp);
            inodp = ERR_PTR(err);
            goto out;
         }
      }

      IcacheInsert(inodp);
   }

   Super_Unlock(sb);

   ASSERT_PTR(inodp->i_op);
   ASSERT_PTR(inodp->f_op); /* may be relaxed, if necessary */

out:
   return inodp;
}

void
Inode_Put(struct InodeStruct *inodp)
{
   ASSERT_KPTR(inodp);
   /* Should never have an inode reference if 0 count. */
   ASSERT(inodp->count > 0);

   struct SuperBlockStruct *sb = inodp->sb;
   ASSERT_KPTR(sb);

   Super_Lock(sb);

   int count = --inodp->count;

   if (count == 0) {
      IcacheRemove(inodp);
   }

   Super_Unlock(sb);

   DEBUG_MSG(5, "count=%d\n", count);

   if (count == 0) {
      if (sb->ops->drop_inode) {
         sb->ops->drop_inode(inodp);
      }

      D__;
      ASSERT_KPTR(sb->ops->free_inode);

      D__;
      sb->ops->free_inode(inodp);
   }
}

int
Inode_Lookup(struct InodeStruct *dir, struct DentryStruct *dentryp)
{
   int err = -ENOENT;

   if (dir->i_op->lookup) {
      err = dir->i_op->lookup(dir, dentryp);
   }

   if (!err) {
      ASSERT_PTR(dentryp->inode);
      ASSERT(dentryp->inode->i_op);
      ASSERT(dentryp->inode->f_op);
   }

   DEBUG_MSG(5, "err=%d\n", err);

   return err;
}

void
Inode_InitSpecial(struct InodeStruct *inodp, struct kstat64 *statp)
{
   ASSERT(inodp->i_op);
   ulong mode = statp->st_mode;

   inodp->mode = mode;
   inodp->dev = statp->st_dev;
   inodp->rdev = statp->st_rdev;

   /* 
    * NOTE: sysfs is 0:0 */
   ASSERT(inodp->dev || !inodp->dev);
   ASSERT(inodp->rdev || !inodp->rdev);

   if (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)) {
      /* Nothing needs to be done -- use the default operations
       * set in alloc_inode callback. */
   } else if (S_ISFIFO(mode)) {
      inodp->f_op = &Fifo_Fops;
   } else if (S_ISSOCK(mode)) {
      /* Linux doesn't allow sys_open()s of a SOCK file (must be done via
       * connect on a AF_UNIX socket) and so we don't allow it either. */
      inodp->f_op = &BadSock_Fops;
   } else {
      ASSERT(S_ISCHR(mode) || S_ISBLK(mode));
      ASSERT(statp->st_dev);
      Device_InitInode(inodp, statp->st_rdev);
   }
}
