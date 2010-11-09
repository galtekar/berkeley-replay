#include "vkernel/public.h"

/*
 * Design notes:
 *
 * RdFS -- Read Deterministic File System
 *
 */

#if 0
#undef DEBUG_MSG
#define DEBUG_MSG(lvl, s, ...) \
		   CUSTOM_PRINTF(0, CURRENT_LFD, s, ##__VA_ARGS__);
#endif


/* 
 * ----------------------------------------
 *
 * Inode ops.
 *
 * ----------------------------------------
 */

/* File and directory operations. */

long
RdFs_lstat(struct DentryStruct *dentryp, struct kstat64 *statp)
{
   return ReadDet_lstat(Dentry_Name(dentryp), statp);
}

typedef struct {
   char *readlinkBufP;
} InodeData;

long
RdFs_readlink(struct DentryStruct *dentryp, char *buf, int bufsize)
{
   DEBUG_MSG(5, "dentryp->name=%s\n", dentryp->name);

   /* A hack so that readlinks to /proc/self/exe see the right binary
    * name, rather than the vkernel binary. 
    *
    * XXX: We wouldn't have this problem if we didn't emulate exec. */
   const char *datP = Dentry_Inode(dentryp)->data;

   if (datP) {
      strncpy(buf, datP, bufsize);
      //strncpy(buf, "/bin/cool", bufsize);

      return strlen(buf)+1;
   } else {
      return ReadDet_readlink(Dentry_Name(dentryp), buf, bufsize);
   }
}

long
RdFs_lgetxattr(struct DentryStruct *dentryp, char *kname, void *kvalue, 
                      size_t size)
{
   return ReadDet_lgetxattr(Dentry_Name(dentryp), kname, kvalue, size);
}

long
RdFs_lsetxattr(struct DentryStruct *dentryp, char *kname, void *kvalue, size_t size, 
                      int flags)
{
   return ReadDet_lsetxattr(Dentry_Name(dentryp), kname, kvalue, size, flags);
}

long
RdFs_llistxattr(struct DentryStruct *dentryp, char *klist, size_t size)
{
   return ReadDet_llistxattr(Dentry_Name(dentryp), klist, size);
}

long
RdFs_lremovexattr(struct DentryStruct *dentryp, char *kname)
{
   return ReadDet_lremovexattr(Dentry_Name(dentryp), kname);
}

long
RdFs_chmod(struct DentryStruct *dentryp, mode_t mode)
{
   return ReadDet_chmod(Dentry_Name(dentryp), mode);
}

long
RdFs_lchown(struct DentryStruct *dentryp, uid_t uid, gid_t gid)
{
   return ReadDet_lchown(Dentry_Name(dentryp), uid, gid);
}

long
RdFs_access(struct DentryStruct *dentryp, int mode)
{
   return ReadDet_access(Dentry_Name(dentryp), mode);
}

long
RdFs_chdir(struct DentryStruct *dentryp)
{
   return ReadDet_chdir(Dentry_Name(dentryp));
}

long
RdFs_utimes(struct DentryStruct *dentryp, struct timeval *ktimes)
{
   return ReadDet_utimes(Dentry_Name(dentryp), ktimes);
}


/* Directory-only operations. */
static int
RootFsNameToIno(const char *name, ino_t *ino)
{
   int err;
   struct kstat64 sbuf;

   err = ReadDet_lstat(name, &sbuf);
   if (err) {
      goto out;
   }

   *ino = sbuf.st_ino;

out:
   DEBUG_MSG(5, "name=%s err=%d ino=%lu\n", name, err, *ino);
   return err;
}

long
RdFs_lookup(struct InodeStruct *dir, struct DentryStruct *dentryp)
{
   long err = 0;
   struct InodeStruct *inodp;
   ino_t ino = 0;

#if 0
   pid_t pid;
#endif
   
   DEBUG_MSG(5, "looking up %s, pid=%d\n", Dentry_Name(dentryp), current->pid);

   err = RootFsNameToIno(Dentry_Name(dentryp), &ino);
   if (err) {
      goto out;
   }

#if 0
   if (sscanf(Dentry_Name(dentryp), "/proc/%d/exe", &pid) == 1 &&
         pid == current->pid) {
      D__;
      struct DentryStruct *dentryP = Vma_GetExecDentry();
      ASSERT_KPTR(dentryP);
      ino = Dentry_Inode(dentryP)->key;
      Dentry_Put(dentryP);
      dentryP = NULL;
   } else {
#endif
      D__;
      inodp = Inode_Get(dir->sb, Dentry_Name(dentryp), ino);

      if (IS_ERR(inodp)) {
         err = PTR_ERR(inodp);
         goto out;
      }
#if 0
   }
#endif

   ASSERT(inodp);
   ASSERT(inodp->i_op);
   ASSERT(inodp->f_op);

   Dentry_Instantiate(dentryp, inodp);

out:
   DEBUG_MSG(5, "lookup: ino=%d err=%d\n", ino, err);
   return err;
}


long
RdFs_mknod(struct InodeStruct *dir, struct DentryStruct *dentryp, int mode, 
      uint dev)
{
   int err;

   err = ReadDet_mknod(Dentry_Name(dentryp), mode, dev);

   DEBUG_MSG(5, "err=%d\n", err);

   if (err) {
      goto out;
   }

   err = RdFs_lookup(dir, dentryp);

out:
   return err;
}


long
RdFs_create(struct InodeStruct *dir, struct DentryStruct *dentryp,
      int mode, UNUSED void *data)
{
   /* The file may be created without write permissions, but
    * with FMODE_WRITE.
    *
    * rw permissions guarantees that sys_open won't fail.
    *
    * XXX: security problem -- opens a window in which anybody
    * can read the file.
    *
    * */
   int tmpMode = 0666 | S_IFREG;

   ASSERT(!data);

   DEBUG_MSG(5, "requested mode=0x%x, initial mode=0x%x\n", 
         mode, tmpMode);

   /* The requested mode will be set after we sys_open the file. */

   return RdFs_mknod(dir, dentryp, tmpMode, 0);
}


long
RdFs_link(struct DentryStruct *old_entry, struct InodeStruct *dir, 
      struct DentryStruct *dentryp, int flags)
{
   int err;

   /* NOTE: only linkat supports flags arg. */
   err = ReadDet_link(old_entry->name, Dentry_Name(dentryp), flags);
   if (err) {
      goto out;
   }

   err = RdFs_lookup(dir, dentryp);

out:
   return err;
}


long
RdFs_symlink(const char *koldname, struct InodeStruct *dir, 
             struct DentryStruct *dentryp)
{
   int err;

   err = ReadDet_symlink(koldname, Dentry_Name(dentryp));
   DEBUG_MSG(5, "oldname=%s new_entry=%s err=%d\n",
         koldname, Dentry_Name(dentryp), err);

   if (err) {
      goto out;
   }

   err = RdFs_lookup(dir, dentryp);

out:
   return err;
}


long
RdFs_mkdir(struct InodeStruct *dir, struct DentryStruct *dentryp, int mode)
{
   int err;

   err = ReadDet_mkdir(Dentry_Name(dentryp), mode);
   if (err) {
      goto out;
   }

   err = RdFs_lookup(dir, dentryp);

out:
   return err;
}


long
RdFs_unlink(UNUSED struct InodeStruct *dir, struct DentryStruct *dentryp)
{
   return ReadDet_unlink(Dentry_Name(dentryp));
}


long
RdFs_rmdir(UNUSED struct InodeStruct *dir, struct DentryStruct *dentryp)
{
   return ReadDet_rmdir(Dentry_Name(dentryp));
}


long
RdFs_rename(struct DentryStruct *old_dentry,
            UNUSED struct InodeStruct *new_dir, struct DentryStruct *new_dentry)
{
   DEBUG_MSG(5, "old=%s new=%s\n", old_dentry->name,
         new_dentry->name);
   return ReadDet_rename(old_dentry->name, new_dentry->name);
}

long
RdFs_truncate(struct DentryStruct *dentryp, loff_t length)
{
   DEBUG_MSG(5, "name=%s\n", dentryp->name);
   return ReadDet_truncate64(dentryp->name, length);
}

static const struct InodeOps RdFs_Iops = {
   .lookup =         &RdFs_lookup,
   .create =         &RdFs_create,
   .lstat =          &RdFs_lstat,
   .readlink =       &RdFs_readlink,
   .lgetxattr =      &RdFs_lgetxattr,
   .lsetxattr =      &RdFs_lsetxattr,
   .llistxattr =     &RdFs_llistxattr,
   .lremovexattr =   &RdFs_lremovexattr,
   .chmod =          &RdFs_chmod,
   .lchown =         &RdFs_lchown,
   .access =         &RdFs_access,
   .chdir =          &RdFs_chdir,
   .link =           &RdFs_link,
   .symlink =        &RdFs_symlink,
   .unlink =         &RdFs_unlink,
   .mkdir =          &RdFs_mkdir,
   .rmdir =          &RdFs_rmdir,
   .mknod =          &RdFs_mknod,
   .utimes =         &RdFs_utimes,
   .rename =         &RdFs_rename,
   .truncate =       &RdFs_truncate,
};


/* 
 * ----------------------------------------
 *
 * File ops.
 *
 * ----------------------------------------
 */

/*
 * Major problem: In the rfd-per-inode scheme, all accesses to the underlying
 * file must go through the rfd stored in the inode. Now if two tasks want to
 * do I/O to the same file through two different file objects but at different
 * offsets, then they must serialize access to the rfd. That is, the rfd can
 * read from only one offset at a given time, and hence each task would need
 * to lock read/writes to file to ensure that the data it is reading is truly
 * from the offset specified in the corresponding file object.
 *
 * This is a log-mode issue that exists regardless of whether we log the 
 * contents of read or if we read directly from the file.
 *
 * XXX: for now, we address this by storing the linux fd inside each vkernel
 * file object.
 */

/* Linux sys_open can block, for example, if someone else
 * holds a leased lock. */

static int
RdFs_open(struct FileStruct *filp, int mode)
{
   int fd, err, flags, isProcFile;
   struct DentryStruct *dentryp = File_Dentry(filp);
   int dev = Dentry_Inode(dentryp)->dev;


   /* The file has already been created by the vkernel
    * VFS create op (if the request was for O_CREAT). Now we just 
    * want to get a Linux kernel handle on it. */
   flags = filp->flags & ~(O_CREAT | O_EXCL);

   /* Direct IO requires that the buffers meet special alignment
    * requirements. Since we read/write to/from the mmaped-logfile, we
    * most likely will not meet these alignment requirements, hence
    * causing subsequent read/writes to this fd to return a -EINVAL.
    * This happened with Cloudstore/KFS. So we don't support direct IO
    * for the moment. */
   flags = flags & ~(O_DIRECT);

   DEBUG_MSG(5, "filp->flags=0x%x flags=0x%x\n", filp->flags, flags);
#define FL(x) ((flags & x) ? 1 : 0)
   DEBUG_MSG(5, "O_RDWR=%d O_WRONLY=%d O_RDONLY=%d O_DIRECTORY=%d "
                "O_LARGEFILE=%d "
                "\n",
         FL(O_RDWR), FL(O_WRONLY), FL(O_RDONLY), FL(O_DIRECTORY),
         FL(O_LARGEFILE));


   filp->orig_rfd = fd = err = ReadDet_open(Dentry_Name(dentryp), flags, 0);

#if 1
   if (!err && filp->flags & O_CREAT) {
      /* The file was created with liberal permissions so that
       * we can open the file for either reading/writing
       * without failing due to permission problems. But now
       * that we've opened the file, we must set the requested
       * create permission. 
       *
       * The ``tar'' program needs this to work correctly, see BUG 11.
       */
      err = RdFs_chmod(filp->dentry, mode);
      //ASSERT_MSG(err == -EPERM || !err, "err=%d", err);
      ASSERT_MSG(!err, "err=%d", err);
   }
#endif

   isProcFile = (dev == 3);

   /* XXX: we need to ensure that the file contents are identical
    * during replay. */
   /* ----- mmaped files require that we open the file again -----
    * XXX: but file may not exist at replay time (e.g, temp files in gcc) */
   /* XXX: we can't reopen proc files -- not likely to be there during
    * replay. this is a temporary hack */
   if (VCPU_IsReplaying()) {
      if (!SYSERR(err) && !isProcFile &&
            /* Don't recreate file during replay. */
            !(filp->flags & O_CREAT)) {

         fd = syscall(SYS_open, Dentry_Name(dentryp), filp->flags, mode);
         DEBUG_MSG(5, "err=%d fd=%d\n", err, fd);

         /*
          * XXX: file may not exist during replay. For now,
          * assume that it does and is in it's original form -- 
          * otherwise mmap will not work and/or replay may diverge. */
         //ASSERT_UNIMPLEMENTED(!SYSERR(fd));
      } else {
         fd = -1;
      }
   }

   filp->rfd = fd;

   {
      DEBUG_MSG(5, "filp->rfd=%d dev=%d -- %d:%d isProcFile=%d\n", 
            filp->rfd, dev, MAJOR(dev), MINOR(dev), isProcFile);
   }

   /* Return log-mode return val. */
   return err;
}

void
RdFs_release(struct FileStruct *filp)
{
   int err = 0;

#if DEBUG
   if (!VCPU_IsReplaying()) {
      ASSERT(filp->rfd >= 0);
   } else {
      ASSERT(filp->rfd >= 0 || filp->rfd < 0);
   }
#endif

   if (filp->rfd >= 0) {
      DEBUG_MSG(5, "rfd=%d\n", filp->rfd);
      err = SysOps_Close(filp->rfd);
      filp->rfd = -1;
      DEBUG_MSG(5, "err=%d\n", err);

#if 0
#if DEBUG
      /* The close may not always succeed and that's okay.
       * What could happen is that a parent may File_Put
       * files mmaped by the child when it frees up its
       * vmas on a successfull wait(). But if the child
       * address space has already been destroyed, then Linux
       * automatically removes the fd entries and hence 
       * filp->rfd may no longer be valid by the time the parent
       * tries to close it. */
      if (err) {
         ASSERT(err == -EBADF);
      }
#endif
#else
      //ASSERT(!err);
#endif
   } else {
      /* XXX: for now, proc files don't have backing
       * descriptors during replay. */
   }
}

int
RdFs_ioctl(UNUSED struct FileStruct *file, uint cmd, UNUSED ulong arg)
{
   int res;

   DEBUG_MSG(5, "cmd=0x%x\n", cmd);
   //res = syscall(SYS_ioctl, file->rfd, cmd, arg);
   switch (cmd) {
      /* XXX: Some programs try to perform tty ioctls on non-tty
       * devices...is that our fault? */
   case TCGETS:
   case TCSETS:
   case TIOCGWINSZ:
   case TIOCSWINSZ:
   case TIOCGPGRP:
      res = -EINVAL;
      break;

   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }


   return res;
}

/* @flags used only for sockets -- look in sockfs/ops.c */
ssize_t
RdFs_io(const int ioReqFlags, const struct FileStruct *filp, struct msghdr *kmsgp, 
        UNUSED const int flags, loff_t pos)
{
   int err;

   err = ReadDet_io(ioReqFlags, filp, filp->rfd, kmsgp, 0, 
            0, pos);

   DEBUG_MSG(5, "err=%d\n", err);

   return err;
}

int
RdFs_llseek(struct FileStruct *filp, loff_t offset, int origin, loff_t *result)
{
   return ReadDet_llseek(filp->rfd, offset, origin, result);
}

int
RdFs_readdir(struct FileStruct* filp, void *buf, filldir_t filler, size_t size)
{
   return ReadDet_readdir(filp->rfd, buf, filler, size);
}

/* 
 * Why do we need both lock and flock VFS routines, especially if they 
 * both invoke the same underlying locking mechanism implemented in 
 * the Linux kernel? Because the interface checks done by the two are
 * different. fnctl locks can be acquired only if the target fd was
 * opened in write mode, but with flock, the open mode doesn't seem to
 * matter. This makes a difference in Hyperspace (part of Hypertable), 
 * in which a call to flock will fail if we invoke fcntl lock rather than 
 * sys_flock.
 */
int
RdFs_lock(struct FileStruct *filp, uint cmd, void *l)
{
   return ReadDet_lock(filp->rfd, cmd, l);
}

int
RdFs_flock(struct FileStruct *filp, uint cmd)
{
   return ReadDet_flock(filp->rfd, cmd);
}

int 
RdFs_fsync(struct FileStruct *filp, int datasync)
{
   return ReadDet_fsync(filp->rfd, datasync);
}

int
RdFs_setfl(struct FileStruct *filp, int flags)
{
   return ReadDet_setfl(filp->rfd, flags);
}

ulong
RdFs_mmap(struct FileStruct *filp, struct VmaStruct *vma)
{
   ulong err;

   Vma_Print(vma);

   ASSERT(!(vma->flags & MAP_ANONYMOUS));

   if (VCPU_IsReplaying()) {
      /* XXX: are you trying to mmap a file that doesn't exist
       * anymore? -- this can happen during replay and it's
       * a fundamental problem with the way we deal with files.
       * It has to be fixed at some point. 
       *
       * This problem breaks:
       *    o OpenJDK-6 replay, because it tries to
       *    update performance data (hsperfdata) efficiently. But this can
       *    be turned of a la 'java -XX:-UsePerfData'. 
       *
       *    o Hyperspace (part of Hypertable), because it relies on
       *    BerkeleyDB, which mmaps db files.
       *
       */
      ASSERT_UNIMPLEMENTED(filp->rfd >= 0);
   } else {
      /* All mmapable files should have a backing descriptor. */
      ASSERT(filp->rfd >= 0);
   }

   err = syscall(SYS_mmap2, vma->start, vma->len, vma->prot,
            (vma->flags & MAP_SHARED ? MAP_SHARED : MAP_PRIVATE) | MAP_FIXED, 
            filp->rfd, vma->pgoff);

   if (err != vma->start) {
      DEBUG_MSG(5, "rfd=%d err=%d, vma->start=0x%x\n", 
            filp->rfd, err, vma->start);
      //sleep(10000);
   }
   /* Since we manage the address space, we should get what we want. */
   ASSERT(err == vma->start);

   return 0;
}

long
RdFs_fstat(struct FileStruct *filp, struct kstat64 *statp)
{
   return ReadDet_fstat(filp->rfd, statp);
}

long
RdFs_ftruncate(struct FileStruct *filp, loff_t length)
{
   return ReadDet_ftruncate64(filp->rfd, length);
}


static const struct FileOps RdFs_Fops = {
   .open =        &RdFs_open,
   .release =     &RdFs_release,
   .io =          &RdFs_io,
   .readdir =     &RdFs_readdir,
   .llseek =      &RdFs_llseek,
   .ioctl =       &RdFs_ioctl,
   .lock =        &RdFs_lock,
   .flock =       &RdFs_flock,
   .fsync =       &RdFs_fsync,
   .setfl =       &RdFs_setfl,
   .mmap =        &RdFs_mmap,
   .fstat =       &RdFs_fstat,
   .ftruncate =   &RdFs_ftruncate,
   .select =      NULL,
};


/* 
 * ----------------------------------------
 *
 * Superblock ops.
 *
 * ----------------------------------------
 */

struct InodeStruct *
RootFs_alloc_inode(struct SuperBlockStruct *sb)
{
   struct InodeStruct *inodp; 

   inodp = Inode_GenericAlloc(sb);

   ASSERT_KPTR(inodp->sb);
   inodp->i_op = &RdFs_Iops;
   inodp->f_op = &RdFs_Fops;
   inodp->major = InodeMajor_File;

   return inodp;
}

void
RootFs_free_inode(struct InodeStruct *inodp)
{
   ASSERT(inodp);

   D__;

   if (inodp->data) {
      ASSERT_KPTR(inodp->data);
      free(inodp->data);
      inodp->data = NULL;
   }
   Inode_GenericFree(inodp);
}

int
RootFs_read_inode(struct InodeStruct *inodp, const char *name)
{
   int err;
   struct kstat64 sbuf;

   /* Use lstat (link stat) rather than plain stat. The former
    * doesn't follow symlinks, which is what we need since we
    * follow them internally. */
   err = ReadDet_lstat(name, &sbuf);
   if (err) {
      goto out;
   }

   DEBUG_MSG(5, "name=%s mode=0x%x dev=%llu rdev=%llu\n", 
         name, sbuf.st_mode, sbuf.st_dev, sbuf.st_rdev);

   Inode_InitSpecial(inodp, &sbuf);

   ASSERT(inodp->i_op);
   ASSERT(inodp->f_op);

out:
   return err;
}


long
RootFs_statfs(struct DentryStruct *dentryp, struct statfs64 *statp)
{
   return ReadDet_statfs(Dentry_Name(dentryp), statp);
}

static struct SuperBlockOps RootFs_SbOps = {
   .alloc_inode =       &RootFs_alloc_inode,
   .free_inode =        &RootFs_free_inode,
   .read_inode =        &RootFs_read_inode,
   .statfs =            &RootFs_statfs,
};


struct SuperBlockStruct *
RootFs_GetSb()
{
   int err;
   struct SuperBlockStruct *sb;
   struct InodeStruct *inodp;
   struct DentryStruct *dentryp;
   ino_t ino = 0;
   const char fsRoot[] = "/";

   sb = SuperBlock_Alloc("rootfs");
   sb->ops = &RootFs_SbOps;

   err = RootFsNameToIno(fsRoot, &ino);
   ASSERT(err >= 0);
   
   inodp = Inode_Get(sb, fsRoot, ino);
   ASSERT(!IS_ERR(inodp));

   D__;

   dentryp = Dentry_AllocRoot(inodp);

   sb->root = dentryp;

   D__;

   return sb;
}

#define PROC_EXE_ENABLED 1

static void
RootFsMakeExeProcFile(struct Task *tskP)
{
#if DEBUG
   ASSERT(tskP->pid > 0);
   if (tskP != current) {
      ASSERT(tskP->pid != current->pid);
   }
#endif

   char exeName[64];
   snprintf(exeName, sizeof(exeName), "/proc/%d/exe", tskP->pid);

   Inode_Lock(sbRoot->root->inode);
   tskP->procExe = Dentry_Lookup(sbRoot->root, exeName);

   DEBUG_MSG(5, "tskP->pid=%d tskP->procExe=0x%x\n", tskP->pid, tskP->procExe);
   ASSERT(tskP->procExe->count == 1);

#if 1
   /* Now set the readlink data for the inode to point to the
    * current executable's path. */
   struct DentryStruct *edP;
   edP = Vma_GetExecDentry();
   ASSERT_KPTR(edP);
   ASSERT_MSG(edP->count >= 2, "count=%d\n", edP->count);
   size_t buflen = strlen(edP->name) + 1;

   struct InodeStruct *inodP = Dentry_Inode(tskP->procExe);

   /* XXX: ideally, this should be done under SB lock; too lazy to make
    * changes, so deferring. */
   inodP->data = malloc(buflen);
   strncpy(inodP->data, edP->name, buflen);
   DEBUG_MSG(5, "inodP->data=%s\n", inodP->data);
   Dentry_Put(edP);
#endif
   Inode_Unlock(sbRoot->root->inode);
}

#if 1
void
RootFs_Fork(struct Task *tskP)
{
#if PROC_EXE_ENABLED
   if (tskP != current) {
      RootFsMakeExeProcFile(tskP);
   } else {
      /* The exe file already created in the initial exec. */
      ASSERT(current == &initTask);
      ASSERT(current->procExe);
   }
#endif
}

void
RootFs_Exit(struct Task *tskP)
{
#if PROC_EXE_ENABLED
   D__;
   ASSERT_KPTR(tskP->procExe);

   Dentry_Put(tskP->procExe);
   tskP->procExe = NULL;
#endif
}

/* 
 * Summary:
 *
 * Many apps (e.g., java, hypertable) use the location of the
 * executable as a starting point to find libraries and such. So we
 * need to make this return the right binary. 
 *
 * We can't simply do a match on /proc/self/exe and return the appropriate 
 * inode, since other tasks may try to determine by looking at your pid. 
 * This means that we must pre-install an inode corresponding to 
 * /proc/self/exe that contains the readlink path string for the current
 * binary.
 *
 * XXX: admittedly, we wouldn't have to do this if we didn't emulate
 * exec. Rethink that design decision.
 */

void
RootFs_Exec()
{
#if PROC_EXE_ENABLED
   struct DentryStruct *dP = current->procExe;

   D__;

   if (dP) {
      D__;
      ASSERT_KPTR(dP);
      Dentry_Put(dP);
      dP = current->procExe = NULL;
   }

   RootFsMakeExeProcFile(current);
#endif
}
#endif

SHAREDAREA struct SuperBlockStruct *sbRoot = NULL;

static int
RootFs_Init()
{
   sbRoot = RootFs_GetSb();

   return 0;
}

FS_INITCALL(RootFs_Init);
