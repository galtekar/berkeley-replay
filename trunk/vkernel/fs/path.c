#include "vkernel/public.h"
#include "private.h"

#if 0
#undef DEBUG_MSG
#define DEBUG_MSG(lvl, s, ...) \
		   CUSTOM_PRINTF(0, CURRENT_LFD, s, ##__VA_ARGS__);
#endif


/*
 * Routines to obtain a dentry from dfd and path.
 */

void
Path_Init(struct PathStruct *ps, const char *pathname, 
                 struct DentryStruct *dentryp, int lookupFlags)
{
   char *pstr;
   size_t pathLen = strlen(pathname)+1;

   ASSERT(ps);
   ASSERT(pathLen <= PATH_MAX);


   pstr = SharedArea_Malloc(pathLen);
   strncpy(pstr, pathname, pathLen);

   ps->pathname = pstr;
   ps->dentry = dentryp;
   ps->flags = lookupFlags;
}

void
Path_Instantiate(struct PathStruct *ps, struct DentryStruct *dentry)
{
   ASSERT(ps->pathname);
   ps->dentry = dentry;
}

void
Path_Release(struct PathStruct *ps)
{
   ASSERT(ps);
   ASSERT(ps->pathname);
   ASSERT(ps->dentry || !ps->dentry);


   SharedArea_Free((void*)ps->pathname, 0);

   if (ps->flags & LOOKUP_LOCK) {
      struct InodeStruct *parent = sbRoot->root->inode;
      ASSERT(Inode_IsLocked(parent));
      Inode_Unlock(parent);
   }

   if (ps->dentry) {
      Dentry_Put(ps->dentry);
   } else {
      /* This could happen if a new dentry cannot
       * be created after a path lookup with
       * INTENT_CREATE. */
   }
}

static struct DentryStruct *
PathGetRoot(UNUSED const char *pathname)
{
   /* Root cannot be unlinked. So no need to check for existance. */
   return sbRoot->root;
}


static int
VFS_readlink(struct DentryStruct *dentryp, char *buf, int buflen)
{
   int err;
   struct InodeStruct *inodp = dentryp->inode;

   err = -EINVAL;
   if (inodp->i_op->readlink) {
      err = inodp->i_op->readlink(dentryp, buf, buflen);
   } 

   return err;
}


/*
 * Not static because used by sys_getcwd to resolve dentry without 
 * obtaining the fs lock (because doing so would cause deadlock).
 */
int
Path_Resolve(const char *pathname, int lookupFlags, struct PathStruct *ps)
{
   int err, jmpCnt = 0;
   struct DentryStruct *dentryp, *mntRoot;
   const char *p = pathname;
   char *tmpStr, *follPath;

   DEBUG_MSG(5, "pathname=%s flags=0x%x\n", pathname, lookupFlags);

   follPath = SharedArea_Malloc(PATH_MAX);
   tmpStr = SharedArea_Malloc(PATH_MAX);

   ASSERT(ps);
   ps->dentry = NULL;

   mntRoot = PathGetRoot(pathname);
   ASSERT(mntRoot);

   /* I'm too lazy to implement recursive locking; hence this
    * hack to avoid locking -- should be used only if we already
    * have the parent lock. */
   if (lookupFlags & LOOKUP_LOCK) {
      /* XXX: explain why we must acquire the lock and why we unlock
       * it on only on path release -- inode existance test and 
       * operation on inode must
       * be atomic. Otherwise, it could be deleted in between, which
       * would then result in non-deterministic results. */
      Inode_Lock(mntRoot->inode);
   }

   Inode_IsLocked(mntRoot->inode);


   if (lookupFlags & LOOKUP_PARENT) {
      /* For now, the parent of any directory is the root of
       * the filesystem. This simplifies locking of complicated
       * operations such as sys_rename. */

      dentryp = Dentry_Get(mntRoot);

      ASSERT_PTR(dentryp);
   } else {
follow:
      D__;
      dentryp = Dentry_Lookup(mntRoot, p);

      if (IS_ERR(dentryp)) {
         if (lookupFlags & LOOKUP_INTENT_CREATE) {
            dentryp = NULL;
            goto init_out;
         } else {
            err = PTR_ERR(dentryp);
            goto error_out;
         }
      }
   }

   D__;
   ASSERT_PTR(dentryp);
   ASSERT_PTR(Dentry_Inode(dentryp));
   ASSERT_PTR(Dentry_Inode(dentryp)->i_op);
   ASSERT_PTR(Dentry_Inode(dentryp)->f_op);

   /* Why do link resolution at vkernel level? Why not let the
    * Linux kernel do it? The answer is that the vkernel needs
    * to know what inode it is accessing -- the inode corresponding
    * to the link or that corresponding to the link target?
    * If Linux does the resolution we can't be sure which is
    * being accessed.
    * We must know which inode is accessed in order to identify
    * races.
    */
   if (lookupFlags & (LOOKUP_FOLLOW | LOOKUP_READLINK)) {
      char *lnkp, *targp;
      int linkMax;

      ASSERT(!(lookupFlags & LOOKUP_PARENT));
      ASSERT(!(lookupFlags & LOOKUP_INTENT_CREATE));
      ASSERT(dentryp);

      strncpy(tmpStr, dentryp->name, PAGE_SIZE);
      lnkp = strrchr(tmpStr, '/');
      ASSERT(lnkp);
      lnkp++;
      *lnkp = 0;

      /* -1 to make room for the null terminator -- sys_readlink
       * doesn't do this for us */
      linkMax = PATH_MAX - strlen(tmpStr) - 1;
      ASSERT(linkMax >= 0);
      err = VFS_readlink(dentryp, lnkp, linkMax);
      if (err < 0 && err != -EINVAL) {
         goto out_putd;
      }

      if (err != -EINVAL) {
         /* null terminate since sys_readlink doesn't do so */
         ASSERT(err > 0);
         lnkp[err] = 0;

         if (jmpCnt >= 7) {
            err = -ELOOP;
            goto out_putd;
         }

         /* The symlink is an absolute path, so no need to prepend
          * the parent dir. */
         if (lnkp[0] == '/') {
            targp = lnkp;
         } else {
            targp = tmpStr;
         }

         DEBUG_MSG(5, "targp=%s\n", targp);

         err = MiscOps_CanonizePath(targp, follPath);
         ASSERT(!err);

         p = follPath;

         if (lookupFlags & LOOKUP_FOLLOW) {
            Dentry_Put(dentryp);
            dentryp = NULL;

            /* Go again: we should stop when we hit a non-symlink;
             * note that this can take many iterations--and there
             * is a danger of looping, so implement a cutoff. */
            jmpCnt++;
            goto follow;
         } else {
            ASSERT(lookupFlags & LOOKUP_READLINK);
         }
      } else {
         if (lookupFlags & LOOKUP_READLINK) {
            ASSERT(err == -EINVAL);
            goto out_putd;
         }
      }
   }

init_out:
   err = 0;

   Path_Init(ps, p, dentryp, lookupFlags);

   goto out;

out_putd:
   ASSERT(!IS_ERR(dentryp));
   Dentry_Put(dentryp);
error_out:
   if (lookupFlags & LOOKUP_LOCK) {
      Inode_Unlock(mntRoot->inode);
   }
out:
   ASSERT_PTR(follPath);
   ASSERT_PTR(tmpStr);
   SharedArea_Free(follPath, PATH_MAX);
   SharedArea_Free(tmpStr, PATH_MAX);
   return err;
}

static int
PathExpand(int dfd, const char __user *path, char *expPath)
{
   int err;
   char *dirPath;

   /* XXX: no need to allocate PATH_MAX bytes every time. */
   dirPath = SharedArea_Malloc(PATH_MAX);
   dirPath[0] = 0;

   DEBUG_MSG(5, "path=%s\n", path);
   if (path[0] == '\0') {
      err = -ENOENT;
      goto out;
   }

   /* Prepend dfd iff path is a relative path. */
   if (path[0] != '/') {
      if (dfd == AT_FDCWD) {
         Fs_Lock(current->fs);
         /* name is read-only and thus no need to grab the inode lock. */
         strncpy(dirPath, current->fs->cwd->name, PATH_MAX);
         Fs_Unlock(current->fs);
      } else {
         struct FileStruct *file;

         file = File_Get(dfd);
         if (file) {
            strncpy(dirPath, file->dentry->name, PATH_MAX);
            File_Put(file);
         } else {
            err = -EBADF;
            goto out;
         }
      }

      strncat(dirPath, "/", 1);
   }

   strncat(dirPath, path, PATH_MAX - (strlen(dirPath)+1));

   err = MiscOps_CanonizePath(dirPath, expPath);
   ASSERT(!err);


out:
   SharedArea_Free(dirPath, PATH_MAX);
   return err;
}

int
Path_Lookup(int dfd, const char *pathname, int lookupFlags, 
      struct PathStruct *ps)
{
   int err;
   char *expPath;

   expPath = SharedArea_Malloc(PATH_MAX);

   err = PathExpand(dfd, pathname, expPath);
   if (err) {
      D__;
      goto out;
   }

   err = Path_Resolve(expPath, lookupFlags, ps);
   if (err) {
      D__;
      ASSERT(!ps->dentry);
      goto out;
   }

#if DEBUG
   if (!(lookupFlags & LOOKUP_INTENT_CREATE)) {
      ASSERT(ps->dentry);
   }

   if (ps->dentry) {
      ASSERT_PTR(ps->dentry);
      ASSERT_PTR(Dentry_Inode(ps->dentry));
      ASSERT(ps->dentry->inode->count > 0);
      ASSERT_PTR(ps->dentry->inode->i_op);
      ASSERT_PTR(ps->dentry->inode->f_op);
   }
#endif

out:
   SharedArea_Free(expPath, PATH_MAX);
   DEBUG_MSG(5, "err=%d\n", err);
   return err;
}


int
VFS_create(struct InodeStruct *dir, struct DentryStruct *dentryp, 
      int mode, void *data)
{
   int err;

   err = -EINVAL;
   if (dir->i_op->create) {
      err = dir->i_op->create(dir, dentryp, mode, data); 
   }

   return err;
}


/* Intended for use by sys_open. */
int
Path_Open(int dfd, const char *pathname, int flags, int mode, int should_follow,
      struct PathStruct *ps)
{
   int err;

   DEBUG_MSG(5, "dfd=%d pathname=%s %s %s\n", dfd, pathname,
         flags & O_CREAT ? "creat" : "-",
         flags & O_EXCL ? "excl" : "-");

   ASSERT(ps);

   if (!(flags & O_CREAT)) {
      err = Path_Lookup(dfd, pathname, LOOKUP_LOCK | 
            (should_follow ? LOOKUP_FOLLOW : 0), ps);
   } else {
      struct DentryStruct *dentryp;
      /*
       * In order for operations on the parent to succeed, it must not
       * be unlinked in between the time we look it up and then modify it
       * (e.g., add a directory or open a file in it). Hence the parent lookup
       * and the subsequent modification must be atomic.
       *
       * To provide atomicity, we require that the parent lock be held
       * throughout the parent lookup and dentry create/inode create steps
       * below.
       */

      err = Path_Lookup(dfd, pathname, LOOKUP_INTENT_CREATE | LOOKUP_LOCK, ps);
      if (err) {
         goto out;
      }

      if (ps->dentry) {
         D__;
         if (flags & O_EXCL) {
            D__;
            err = -EEXIST;
            goto out_prel;
         }

         ASSERT(ps->dentry->inode);
         ASSERT(ps->dentry->inode->i_op);
         ASSERT(ps->dentry->inode->f_op);
      } else {
         /* Doesn't exist, so we must create it. */
         D__;

         /* Parent is still locked, which was done as part of 
          * Path_Lookup(). */
         dentryp = Dentry_Open(sbRoot->root/*ps->dentry->parent*/, 
               ps->pathname, flags);
         if (IS_ERR(dentryp)) {
            err = PTR_ERR(dentryp);
            goto out_prel;
         }

         err = VFS_create(sbRoot->root->inode, dentryp, mode, NULL);
         if (err) {
            goto out_prel;
         }

         Path_Instantiate(ps, dentryp);
      }

      goto out;

out_prel:
      Path_Release(ps);
   }
out:
   return err;
}
