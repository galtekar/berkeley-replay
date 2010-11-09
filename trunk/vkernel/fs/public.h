#pragma once

/*
 * ----------------------------------------------------------------------
 * Design notes:
 *
 * o  An inode is our in-memory representation of a file. But it does
 *    not describe all characteristics of a file. For example, the vkernel
 *    inode does not store the ACLs of an ext3 file. Thus, permission
 *    checks can only be done with Linux's help.
 *    
 */

#include "vkernel/public.h"

struct SuperBlockStruct;
struct InodeStruct;
struct DentryStruct;
struct FileStruct;
struct Task;
struct VmaStruct;

struct SuperBlockOps {
   /* Allocate an inode object, including fs-specific data. */
   struct InodeStruct *    (*alloc_inode)(struct SuperBlockStruct *);
   /* Deallocate an inode object, including fs-sepcific data. */
   void                    (*free_inode)(struct InodeStruct *);
   void                    (*drop_inode)(struct InodeStruct *);
   int                     (*read_inode)(struct InodeStruct *, const char *);
   long                    (*statfs)(struct DentryStruct*, struct statfs64*);
};

struct SuperBlockStruct {
   /* Uniquely identifies the fs instance. This id concatenated
    * with inode number serves as unique id for files entities. */
   short                   id;
   char                    fsname[32]; 
   struct MapStruct        *inodeMap;
   struct DentryStruct     *root;
   struct SuperBlockOps    *ops;
   /* XXX: Why does this need to be a rep lock? */
   struct RepLockStruct lock;
};

struct SuperBlockStruct *  SuperBlock_Alloc(const char *);
void                       SuperBlock_Free(struct SuperBlockStruct *);
struct SuperBlockStruct *  SuperBlock_AllocPseudo(const char *, 
                              struct SuperBlockOps *);

static INLINE void
Super_Lock(struct SuperBlockStruct *sb)
{
   ORDERED_LOCK(&sb->lock);
}

static INLINE void
Super_Unlock(struct SuperBlockStruct *sb)
{
   ORDERED_UNLOCK(&sb->lock);
}


#if 0
typedef 
   enum { 
      Irk_KernRead, 
      Irk_KernWrite, 
      Irk_UserRead, 
      Irk_UserWrite 
   } IOReqKind;
#endif
#define IOREQ_READ   (1 << 0)
#define IOREQ_KERN   (1 << 1)

/*
 * This is the "filldir" function type, used by readdir() to let
 * the kernel specify what kind of dirent layout it wants to have.
 * This allows the kernel to read directories into kernel space or
 * to have different dirent layouts depending on the binary type.
 */
typedef int (*filldir_t)(void *, const char *, int, loff_t, ino_t, unsigned);

extern int  no_llseek(struct FileStruct *file, loff_t offset, 
                  int origin, loff_t *result);

struct FileOps {
   /* XXX: :Make read-only args const, as in mmap below. */

   /* Some file objects (such as those backed by a Linux inode) need a linux
    * file-descriptor to do their work. That fd is typically opened in this
    * callback. */
   int      (*open)(struct FileStruct *, int mode);
   /* We need release -- e.g., to close a backing pipe fd when all
    * refs at put()ed, or to close a backing Linux fd when we close
    * the file object. */
   void     (*release)(struct FileStruct *); 
   ssize_t  (*io)(const int, const struct FileStruct *, struct msghdr *, 
                  const int flags, loff_t pos);
   int      (*ioctl)(struct FileStruct*, uint, ulong);
	int      (*readdir) (struct FileStruct*, void *, filldir_t, size_t);
	int      (*llseek)(struct FileStruct *, loff_t, int, loff_t *);
   /* XXX: we implement this to avoid emulating it in the vkernel, but would
    * an emulation be cleaner? */
   int      (*setfl)(struct FileStruct *, int);
   int      (*lock)(struct FileStruct *, uint, void *);
   int      (*flock)(struct FileStruct *, uint);
   int      (*fsync)(struct FileStruct *, int);
   ulong    (*mmap)(struct FileStruct *, struct VmaStruct *);
   long     (*fstat)(struct FileStruct *, struct kstat64 *);
   long     (*ftruncate)(struct FileStruct *, loff_t length);
   int      (*select)(const struct FileStruct *, const int is_read, const int should_block);
};


struct InodeOps {
   /* Directory entry operations (i.e., modification of directory inodes). */
   long   (*lookup)(struct InodeStruct *dir, struct DentryStruct *dentryp);
   long   (*create)(struct InodeStruct *, struct DentryStruct *, int mode, void *data);
   long   (*mknod)(struct InodeStruct *, struct DentryStruct *, int mode, uint dev);
   long   (*link)(struct DentryStruct*, struct InodeStruct *, struct DentryStruct *, int);
   long   (*symlink)(const char *, struct InodeStruct *, struct DentryStruct *);
   long   (*mkdir)(struct InodeStruct *, struct DentryStruct *, int);
   long   (*unlink)(struct InodeStruct *, struct DentryStruct *);
   long   (*rmdir)(struct InodeStruct *, struct DentryStruct *);
   long   (*rename)(struct DentryStruct *, struct InodeStruct *, struct DentryStruct *);

   /* Operations on the inodes or data objects described by
    * the inodes. */
   long   (*lstat)(struct DentryStruct*, struct kstat64*);
   long   (*readlink)(struct DentryStruct *, char *, int);
   long   (*lgetxattr)(struct DentryStruct *, char *, void *, size_t);
   long   (*lsetxattr)(struct DentryStruct *, char *, void *, size_t, int);
   long   (*llistxattr)(struct DentryStruct *, char *, size_t);
   long   (*lremovexattr)(struct DentryStruct *, char *);
   long   (*chmod)(struct DentryStruct *, mode_t);
   long   (*lchown)(struct DentryStruct *, uid_t, gid_t);
   long   (*utimes)(struct DentryStruct *, struct timeval *);
   long   (*truncate)(struct DentryStruct *, loff_t);

   /* We can't merge these because they truly do different things.
    * chdir checks that target is a directory and has execute
    * permissions using the fd uid/gid. But access doesn't check
    * that its a dir and rather uses the real uid/gid. */
   long   (*access)(struct DentryStruct *, int);
   long   (*chdir)(struct DentryStruct *);
};


typedef enum {
   InodeMinor_ShmNamed,
   InodeMinor_ShmAnon,
} InodeMinor;

/* Represents a data object. */
struct InodeStruct {
   /* Inode number uniquely identifies each file object. */
   struct MapField inoMap;

   void *data;

   struct SuperBlockStruct *sb;
   const struct InodeOps      *i_op;
   const struct FileOps       *f_op;

   ulong     mode;
   ulong     dev;
   ulong     rdev; /* for device files only */
   InodeMajor major;
   InodeMinor minor;

   /* XXX: Why make this a rep lock? */
   struct RepLockStruct lock;

   /* Protected by superblock lock. Must be updated
    * atomically with entry and removal from superblock's 
    * inode-cache. */
   int count; 
};

extern void    Inode_Put(struct InodeStruct *);
extern int     Inode_Lookup(struct InodeStruct *, struct DentryStruct *);
extern void    Inode_InitSpecial(struct InodeStruct *inodp, 
                  struct kstat64 *sbufp);
extern struct InodeStruct * Inode_Get(struct SuperBlockStruct *sb, 
                  const char *name, ino_t ino);
extern struct InodeStruct *   Inode_GenericAlloc(struct SuperBlockStruct *sb);
extern void   Inode_GenericFree(struct InodeStruct *inodp);


static INLINE ulong
Inode_Ino(const struct InodeStruct *inodp)
{
   return inodp->inoMap.keyLong;
}

static INLINE dev_t
Inode_Dev(const struct InodeStruct *inodp)
{
   return inodp->dev;
}

static INLINE dev_t
Inode_RDev(const struct InodeStruct *inodp)
{
   return inodp->rdev;
}

static INLINE InodeMajor
Inode_GetMajor(const struct InodeStruct *inodp)
{
   return inodp->major;
}

static INLINE InodeMinor
Inode_GetMinor(const struct InodeStruct *inodp)
{
   return inodp->minor;
}

static INLINE void
Inode_Lock(struct InodeStruct *inodp)
{
   ORDERED_LOCK(&inodp->lock);
}

static INLINE void
Inode_Unlock(struct InodeStruct *inodp)
{
   ORDERED_UNLOCK(&inodp->lock);
}

static INLINE int
Inode_IsLocked(struct InodeStruct *inodp)
{
   return ORDERED_IS_LOCKED(&inodp->lock);
}


struct DentryStruct {
   char                 *name;
   struct InodeStruct   *inode;
   struct DentryStruct  *parent;

   struct RepLockStruct lock;
   int                  count;
};

extern struct DentryStruct *  Dentry_Open(struct DentryStruct *dir, 
                                 const char *path, int flags);
extern struct DentryStruct *  Dentry_Lookup(struct DentryStruct *dir, 
                                 const char *name);
extern struct DentryStruct *  Dentry_Get(struct DentryStruct *dentryp);
extern void                   Dentry_Put(struct DentryStruct *dentryp);
extern struct DentryStruct *  Dentry_AllocRoot(struct InodeStruct *root_inode);
extern void    Dentry_Instantiate(struct DentryStruct *base, struct InodeStruct *inodp);

static INLINE struct InodeStruct *
Dentry_Inode(const struct DentryStruct *dentry)
{
   return dentry->inode;
}

static INLINE const char *
Dentry_Name(const struct DentryStruct *dentry)
{
   ASSERT(dentry->name);

   return dentry->name;
}

typedef enum {
   Chk_Unknown = 0xc001,
   Chk_Control,
   Chk_MaybeControl,
   Chk_Data,
   Chk_MaybeData,
} ChannelKind;

struct FileStruct {
   struct RepLockStruct lock;

   int                     count;

   /* File object may be associated with multiple vfds in different
    * file tables, so doesn't make sense to have vfd identifier stored. 
    * 
    * int vfd;
    *
    * */

   struct DentryStruct      *dentry;
   const struct FileOps    *f_op;

   /* This state may be in the backing fd, if there is one.
    * But there might not be. More importantly, we need quick
    * access to it from instrumentation routines. */
   loff_t pos;

   int flags;

   /* All access checks on file reference by file object is done on this field. */
#define FMODE_READ   0x1
#define FMODE_WRITE  0x2
   int accMode;

   struct ListHead epoll_item_list;

   /* 
    * Linux file descriptor.
    *
    * This is our connection to the file through Linux. A key design
    * question is, should we have a separate connection to the
    * file for each vkernel file object or should we have just one
    * (unified) connection?
    *
    * The unified connection model permits a clean abstraction of
    * the filesystem, where all access to the file goes through
    * just 1 fd, which can then be stored in the vkernel inode
    * corresponding to the file. This mechanism would simulate
    * Linux's clean abstraction of "inode as data object".
    * But it also poses several challenges that appear to require
    * considerable emulation effort or non-trivial kernel support:
    *
    *
    *    o  Once a Linux file object is opened in
    *       a particular access mode, that access mode cannot be changed.
    *       This is a problem becasue a task having only read access may open the file
    *       FMODE_READ, but if another task wants to access the file read/write,
    *       then the connection cannot be upgraded to FMODE_READ/FMODE_WRITE.
    *
    *       We address this by closing and reopening the connection under
    *       the parent lock, once we know that the file still exists. 
    *
    *    o  When a task opens a file, we must ensure that it returns EPERM
    *       whenever Linux return EPERM.
    *
    *       We address this by opening the file under the parent lock,
    *       once we know that the file still exists. If the open succeeds,
    *       then we close the old inode fd and replace it with the new one.
    *
    *
    *    o  Must emulate async notifications if more that one task
    *       open(O_ASYNC)s the file.
    *
    *    o  One task may open file in O_DIRECT mode while another may open
    *       the same file without O_DIRECT. Supporting both modes may
    *       call for emulating caching.
    *
    *       We could write a device-driver routine for this. For now, we can
    *       ignore it because it is a performance issue.
    *
    *    o  Must synch access to the unified fd's file offset since
    *       two tasks may write to the same file but at different 
    *       offsets.
    *
    *       This can be synchronized through the target inode's lock.
    *
    * 
    *
    *
    * We chose the separate connection scheme.
    *
    */
   int rfd;

   /* During replay we need to know the Linux fd assigned during logging.
    * This is used mainly to ensure deterministic vfd<-->rfd translation. */
   int orig_rfd;

   struct TokenBucket classTB; /* control-plane classifier */

   ChannelKind channel_kind;
};


extern struct FileStruct * 
File_Open(int dfd, const char *path, int flags, int mode, int should_follow);
extern struct FileStruct *
File_DentryOpen(struct DentryStruct *dentryp, int flags, int mode);
extern struct FileStruct*  
File_Get(uint vfd);
extern int  
File_Close(struct FileStruct *filp);
extern void 
File_Put(struct FileStruct *file);
extern loff_t  
File_Seek(struct FileStruct *filp, loff_t offset, uint origin);
extern ssize_t
File_KernRead(struct FileStruct *filp, void *buf, size_t len, loff_t pos);
extern ssize_t
File_KernWrite(struct FileStruct *filp, void *buf, size_t len, loff_t pos);
extern void
File_MarkFileByIno(VkPlaneTag kind, ulong dev, ulong ino);
extern void
File_MarkFileByFd(int fd, VkPlaneTag tag);

static INLINE struct DentryStruct *
File_Dentry(const struct FileStruct *filp)
{
   struct DentryStruct *dentryp;

   dentryp = filp->dentry;

   ASSERT(dentryp);

   return dentryp;
}

static INLINE void
File_Lock(struct FileStruct *filp)
{
   ORDERED_LOCK(&filp->lock);
}

static INLINE void
File_Unlock(struct FileStruct *filp)
{
   ORDERED_UNLOCK(&filp->lock);
}

static INLINE int
File_IsLocked(struct FileStruct *filp)
{
   return ORDERED_IS_LOCKED(&filp->lock);
}

static INLINE struct FileStruct *
File_GetFile(struct FileStruct *filp)
{
   ASSERT(filp);

   File_Lock(filp);

   filp->count++;

   DEBUG_MSG(5, "name=%s count=%d\n", File_Dentry(filp)->name, filp->count);

   File_Unlock(filp);

   return filp;
}

static INLINE struct InodeStruct *
File_Inode(const struct FileStruct *filp)
{
   struct DentryStruct *dentryp = File_Dentry(filp);
   
   return Dentry_Inode(dentryp);
}

static INLINE const char *
File_Name(const struct FileStruct *filp)
{
   ASSERT_KPTR(filp);

   struct DentryStruct *dentryp = File_Dentry(filp);

   return Dentry_Name(dentryp);
}


struct FdTableStruct {
   /* XXX: int maxFdSet -- as far as I can tell, this holds
    * teh same values as maxFds. But this is probably not always
    * the case, otherwise it wouldn't exist in the Linux kernel. */
   uint                  maxFds;
   struct FileStruct **  vfdTable;

   fd_set *closeOnExec;
   fd_set *openFds;
};

/* XXX: we need to grow the fdarray on demand, like Linux. */
#define NR_OPEN_DEFAULT BITS_PER_LONG*8

struct FilesStruct {
   int                  count;
   struct FdTableStruct *fdt;
   struct FdTableStruct fdtab;
   struct RepLockStruct lock;
   struct FileStruct    *vfdArray[NR_OPEN_DEFAULT];
   uint                  nextFd;
   fd_set closeOnExecInit, openFdsInit;
};

struct FileSysStruct {
   /* We must shadow the filesys struct to support virtual directories. */
   struct DentryStruct *cwd;
#if 0
   int umask;
#endif

   struct RepLockStruct lock;
   int count;
};

static INLINE void
Files_Lock(struct FilesStruct *files)
{
   ORDERED_LOCK(&files->lock);
}

static INLINE void
Files_Unlock(struct FilesStruct *files)
{
   ORDERED_UNLOCK(&files->lock);
}

static INLINE int
Files_IsLocked(const struct FilesStruct *files)
{
   return ORDERED_IS_LOCKED(&files->lock);
}

static INLINE struct FileStruct*
Files_LookupUnlocked(const struct FilesStruct *files, const uint vfd)
{
   struct FileStruct *file = NULL;
   const struct FdTableStruct *fdt = files->fdt;

   if (vfd < fdt->maxFds) {
      file = fdt->vfdTable[vfd];
   }

   return file;
}



extern int      Files_Fork(ulong cloneFlags, struct Task *tsk);
extern void     Files_Exit(struct Task *tsk);
extern void     Files_Exec();
extern int      FileSys_Fork(ulong cloneFlags, struct Task *tsk);
extern void     FileSys_Exit(struct Task *tsk);
extern void     FileSys_Exec();


#define LOOKUP_PARENT         (1 << 0)
#define LOOKUP_LOCK           (1 << 1)
#define LOOKUP_FOLLOW         (1 << 2)
#define LOOKUP_INTENT_CREATE  (1 << 3)
#define LOOKUP_READLINK       (1 << 4)

struct PathStruct {
   const char *pathname;
   struct DentryStruct *dentry;
   int flags;
};

extern int  Path_Open(int dfd, const char *pathname, int flags, int mode,
      int should_follow,
               struct PathStruct *ps);
extern int  Path_Lookup(int dfd, const char *pathname, int lookupFlags, 
               struct PathStruct *ps);
extern int  Path_Resolve(const char *pathname, int lookupFlags, 
               struct PathStruct *ps);
extern void Path_Init(struct PathStruct *ps, const char *pathname, 
                 struct DentryStruct *dentryp, int lookupFlags);
extern void Path_Instantiate(struct PathStruct *ps, 
               struct DentryStruct *dentry);
extern void Path_Release(struct PathStruct *ps);


extern int
File_OpenFd(int dfd, const char *path, int flags, int mode, int should_follow);
/* XXX: vk shouldn't call syscalls directly... */
extern SyscallRet sys_dup(uint fildes);
extern int FileSys_Chdir(const char * todir);
extern SyscallRet sys_close(uint vfd);

typedef int (*SelectCallback)(int res, const struct SyscallArgs *args);
extern int Select_WaitLoop(struct SyscallArgs *args, SelectCallback cb);
extern int
Select_DefaultTaggedFop(const tsock_socket_info_t *s_info, const int is_read, 
             const int should_block);
extern int
Select_DefaultUntaggedFop(const struct FileStruct *filP, const int is_read,
               const int should_block);
