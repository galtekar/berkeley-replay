#include "vkernel/public.h"
#include "private.h"

/* 
 * Design notes:
 *
 * Must perform permission checks only on emulated operations -- those that do
 * not necessarily involve a corresponding Linux call. Currently that includes all
 * ops except shmctl(IPC_INFO/SHM_INFO/SHM_LOCK/SHM_UNLOCK).
 *
 *
 * We emulate *_STAT, *_INFO functions because (1) our emulation of shared
 * segment create/destroy operations is not in synch with the kernel's and
 * (2) we don't want vkernel tasks to see segments installed by non-vkernel
 * tasks.
 *
 *
 */

#error "Are destroyed segments inherited on fork?"
   /* Yes: see ipc/shm.c/shm_open */
#error "Should shm_nattch, shm_atime, and shm_lpid be updated on fork? and how?"
   /* As expected -- See ipc/shm.c/shm_open */
#error "What if euid changes and violates segment permissions for attach?"
   /* XXX: don't think euid can change as such */

static int
ShmLookupByKey(key_t key, struct IpcStruct **ipc)
{
   int err = 0;
   struct IpcStruct *tipc;

   ASSERT(ipc);
   ASSERT(Ipc_IsLocked());

   tipc = Ipc_LookupByKey(key);

   if (!tipc || tipc->kind != IpcKind_Shm) {
      err = -EINVAL;
   } else {
      *ipc = tipc;
   }

   return err;
}

static int
ShmLookupById(int shmid, struct IpcStruct **ipc)
{
   int err = 0;
   struct IpcStruct *tipc;

   ASSERT(ipc);
   ASSERT(Ipc_IsLocked());

   tipc = Ipc_LookupById(shmid);

   if (!tipc || tipc->kind != IpcKind_Shm) {
      err = -EINVAL;
   } else {
      *ipc = tipc;
   }

   return err;
}

static int
ShmLookupByIdx(int idx, struct IpcStruct **ipc)
{
   int err = 0;
   struct IpcStruct *tipc;

   ASSERT(ipc);
   ASSERT(Ipc_IsLocked());

   tipc = Ipc_LookupByIdx(idx);

   if (!tipc || tipc->kind != IpcKind_Shm) {
      err = -EINVAL;
   } else {
      *ipc = tipc;
   }

   return err;
}

static void
ShmAttachWork(int shmid)
{
   int err;

   struct IpcStruct *ipc = NULL;

   Ipc_Lock();

   err = ShmLookupById(shmid, &ipc);
   ASSERT(!SYSERR(err));
   ASSERT(ipc);

   ipc->Un.Shm.numAttached++;
   ipc->Un.Shm.attachTime = Ipc_GetTime();
   ipc->Un.Shm.lastPid = current->tgid;

   Ipc_Unlock();
}

/* Invoked when we dup the addreses space (e.g., on a fork) 
 * or split (e.g., due to partial munmap/mprotect) IPC shm VMAs. */
static void
ShmOpenCallback(struct VmaStruct *vma)
{
   ShmAttachWork(File_InodeId(vma->file));
}

static void
ShmDestroyUnlocked(struct IpcStruct *ipc)
{
   ASSERT(PAGE_ALIGNED(ipc->size));


   /* File should already have been released. */
   ASSERT(ipc->filp);
   ASSERT(ipc->filp->rid == -1);

   Ipc_Remove(ipc);

   Ipc_Destroy(ipc);
}

/* Invoked when we remove VMAs backed by IPC shm segs. When the
 * last atachee detaches, and if the segment was removed, then
 * we actually remove it from our lists and free it, thus
 * emulating Linux's behavior. */
static void
ShmCloseCallback(struct VmaStruct *vma)
{
   int shmid;
   struct IpcStruct *ipc = NULL;

#error "shmid is no longer stored in id, grab it from private data field?"
   shmid = File_InodeId(vma->file);

   Ipc_Lock();

   err = ShmLookupById(shmid, &ipc);
   ASSERT(!SYSERR(err));
   ASSERT(ipc);

   ipc->Un.Shm.lastPid = current->tgid;
   ipc->Un.Shm.numAttached--;
   ipc->Un.Shm.detachTime = Ipc_GetTime();

   /* Ideally, we would remove the segment from our ipc
    * table upon sys_shmctl(IPC_RMID). But Linux semantics
    * dictates the segment be visible (and attachable) until
    * the last atachee detaches, at which point the segment
    * can be truly destroyed. This is that point. */
   if (ipc->Un.Shm.numAttached == 0 &&
         ipc->perm.mode & SHM_DEST) {
      ShmDestroyUnlocked(ipc);
   }

   Ipc_Unlock();
}

const struct VmaOps shmVmOps = {
   .open =  &ShmOpenCallback,
   .close = &ShmCloseCallback,
};

static int
ShmMmap(struct FileStruct *filp, struct VmaStruct *vma)
{
   int err = 0, res;
   struct InodeStruct *inodp = File_Inode(filp);

   ASSERT(inodp->minor == InodeMinor_ShmNamed);
   ASSERT(inodp->id != -1);
   ASSERT(filp->rid != -1);

   err = ShMem_Mmap(filp, vma);
   ASSERT(err == 0);

   vma->ops = &shmVmOps;

   ShmAttachWork(inodp->id);

   return err;
}

const struct FileOps shmFileOps = {
   .mmap =  &ShmMmap,
   .open =  &ShMem_OpenCallback,
   .release = &ShMem_ReleaseCallback,
};




/* Returns virtual shmid of newly created segment. */
static int
ShmCreate(key_t key, size_t size, int shmFlags)
{
   struct IpcStruct *ipc;
   struct FileStruct *filp = NULL;
   char shmName[64];
   int err, shmid, res;

   ASSERT(PAGE_ALIGNED(size));
   ASSERT(Ipc_IsLocked());

   /* No need to perform permission checks or system limit checks
    * here since ShMem_Create will take care of it. */

   /* Name must be unique and path for unique inode no assignment. */
   res = snprintf(shmName, sizeof(shmName), "/dev/vk/sysv/%x-%d\n", key, ipcSeq);
   ASSERT(res < sizeof(shmName));

   /* The creation may fail if, for instance, the number
    * IPC shmem segments exceeds the system maximum or there
    * is no additional memory. These events are beyond our
    * control environment and thus we replay them. */
   err = ShMem_Create(shmName, size, shmFlags, &filp);
   if (SYSERR(err)) {
      goto out;
   }

   if (shmFlags & SHM_HUGETLB) {
      /* XXX: HUGETLB seems to be supported only on custom-compiled kernels. */
      ASSERT_UNIMPLEMENTED(0);
   } else {
      filp->f_op = &shmFileOps;
   }

   shmid = filp->inode->id;

   ipc = Ipc_Create(IpcKind_Shm, key, shmid, filp->inode->rid, 
                    size, shmFlags, filp);

   ipc->Un.Shm.attachTime = 0;
   ipc->Un.Shm.detachTime = 0;
   /* This really is the thread group id, not the task id. */
   ipc->Un.Shm.creatorPid = current->tgid;
   ipc->Un.Shm.lastPid = 0;
   ipc->Un.Shm.numAttached = 0;

   Ipc_Insert(ipc);

   err = shmid;

out:
   return err;
}

/* Return virtual shmid of existing or newly created segment. */
int
Shm_Get(key_t key, size_t size, int shmFlags)
{
   int err;
   struct IpcStruct *ipc;

   ASSERT_UNIMPLEMENTED(!(shmFlags & SHM_HUGETLB));

   Ipc_Lock();

   if (key == IPC_PRIVATE) {
      err = ShmCreate(key, size, shmFlags);
   } else if (ShmLookupByKey(key, &ipc)) {
      /* Note that, under this policy, a task cannot attach to 
       * non-vkernel segments. */
      if (!(shmFlags & IPC_CREAT)) {
         err = -ENOENT;
      } else {
         err = ShmCreate(key, size, shmFlags);
      }
   } else if ((shmFlags & IPC_CREAT) && (shmFlags & IPC_EXCL)) {
      err = -EEXIST;
   } else {
      ASSERT(ipc);

      if (Ipc_CheckPerm(ipc, shmFlags)) {
         err = -EACCES;
      } else {
         err = ipc->id;
         ASSERT(err != -1);
      }
   }

   Ipc_Unlock();

   return err;
}

static int
ShmRemove(struct IpcStruct *ipc)
{
   int err = 0;

   ASSERT(Ipc_IsLocked());
   ASSERT(ipc->filp);

   /* We don't use VFS for permission checks since the inode
    * doesn't store owner and creator info about the segment. */
   if (ipc->owner != current->euid && ipc->creator != current->euid && 
#error "Need to shadow task capabilities."
         !capable(CAP_SYS_ADMIN)) {
      err = -EPERM;
      goto out;
   }

   if (ipc->perm.mode & SHM_DEST) {
      err = -EIDRM;
      goto out;
   }

   File_Put(ipc->filp);
   ipc->filp = NULL;

   if (ipc->Un.Shm.numAttached) {
      /* Linux wants future lookups by key to this segment to fail;
       * we emulate. */
      ipc->perm.key = IPC_PRIVATE;
      ipc->perm.mode |= SHM_DEST;
   } else {
      ASSERT(Ipc_IsLocked());
      ShmDestroyUnlocked(ipc);
   }

out:
   return err;
}

static int
ShmGetFile(int vshmid, struct FileStruct **filp)
{
   int err = 0;
   struct IpcStruct *ipc;

   ASSERT(filep);

   Ipc_Lock();

   err = ShmLookupById(vshmid, &ipc);
   if (SYSERR(err)) {
      goto out;
   }

   /* Must get a reference before giving up the lock. Otherwise,
    * another task may concurrently destory the segment, in which
    * case out handle of ipc would no longer be valid, and the file
    * object may have already been deallocated. */
   *filp = File_Get(ipc->filp);

   ASSERT(filp);

out:
   Ipc_Unlock();
   return err;
}


int
Shm_Attach(int vshmid, void  *shmaddr, int shmflg, ulong *raddr)
{
   int err;
   struct FileStruct *filp = NULL;

   ASSERT(raddr);

   /* No need to do permission check here since it will be done as part
    * of the underlying syscall. */

   err = ShmGetFile(vshmid, &filp);
   if (SYSERR(err)) {
      goto out;
   }

   ASSERT(filp);

   err = UserMem_ShmAt(filp, shmaddr, shmflg, raddr);

   /* We expect the recently-created vma region to obtain a reference
    * to this file object. */
   File_Put(filp);

out:
   return err;
}

int 
Shm_Detach(void __user *shmaddr)
{
   int err;

   err = UserMem_ShmDt(shmaddr);

   return err;
}

static int
ShmLock(const struct IpcStruct *ipc, int isLock)
{
   int err;

   ASSERT(Ipc_IsLocked());
   ASSERT(ipc->file);

   /* The success of this call depends on the availability of resources
    * beyond the vkernel's control, and thus may not be deterministic. 
    * Hence we should log the return value. */

   if (!Task_IsReplaying()) {

      /* XXX: should we try to lock-in the pages during replay? */
      err = SysOps_ShmCtl(ipc->rid, isLock ? SHM_LOCK : SHM_UNLOCK, NULL);

      if (Task_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!SYSERR(err)) {
      if (isLock) {
         ipc->perm.mode |= SHM_LOCKED;
      } else {
         ipc->perm.mode &= ~SHM_LOCKED;
      }
   }

out:
   return err;
}

static INLINE ulong 
copy_shmid_to_user(void __user *buf, struct shmid64_ds *in, int version)
{
   switch(version) {
   case IPC_64:
      return copy_to_user(buf, in, sizeof(*in));
   case IPC_OLD:
      {
         struct shmid_ds out;

         ipc64_perm_to_ipc_perm(&in->shm_perm, &out.shm_perm);
         out.shm_segsz	= in->shm_segsz;
         out.shm_atime	= in->shm_atime;
         out.shm_dtime	= in->shm_dtime;
         out.shm_changeTime	= in->shm_changeTime;
         out.shm_cpid	= in->shm_cpid;
         out.shm_lpid	= in->shm_lpid;
         out.shm_nattch	= in->shm_nattch;

         return copy_to_user(buf, &out, sizeof(out));
      }
   default:
      return -EINVAL;
   }
}

static int
ShmStat(struct IpcStruct *ipc, int cmd, char __user *ubuf)
{
   int err = 0, version;
   struct shmid64_ds kbuf;

   version = Ipc_ExtractVersion(&cmd);

   memset(&kbuf, 0, sizeof(kbuf));

   if (Ipc_CheckPerm(ipc->perm, S_IRUGO)) {
      err = -EACCES;
      goto out;
   }

   if (cmd == SHM_STAT) {
      err = ipc->id;
   }

   kbuf.perm = ipc->perm;

   kbuf.shm_segsz =  ipc->size;

   kbuf.shm_changeTime =  ipc->changeTime;
   kbuf.shm_atime =  ipc->Un.Shm.attachTime;
   kbuf.shm_dtime =  ipc->Un.Shm.detachTime;
   kbuf.shm_cpid =   ipc->Un.Shm.creatorPid;
   kbuf.shm_lpid =   ipc->Un.Shm.lastPid;
   kbuf.shm_nattch = ipc->Un.Shm.numAttached;

   if (copy_shmid_to_user(ubuf, &kbuf, version)) {
      err = -EFAULT;
      goto out;
   }

out:
   return err;
}

static int
ShmDoInfo(int rid, int cmd, char *kbuf, size_t bufSz)
{
   int err;

   if (!Task_IsReplaying()) {
#error "Implement SysOps methods."
      err = SysOps_ShmCtl(rid, cmd, kbuf);

      if (Task_IsLogging()) {
         DO_WITH_LOG_ENTRY_DATA(JustRetval, SYSERR(err) ? 0 : bufSz) {
            entryp->ret = err;
            if (!SYSERR(err)) {
               memcpy(datap, kbuf, bufSz);
            }
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
         if (!SYSERR(err)) {
            memcpy(kbuf, datap, bufSz);
         }
      } END_WITH_LOG_ENTRY(SYSERR(err) ? 0 : bufSz);
   }

   ASSERT(!SYSERR(err));

   return err;
}

static INLINE ulong 
copy_shminfo_to_user(void __user *buf, struct shminfo64 *in, int version)
{
	switch(version) {
	case IPC_64:
		return copy_to_user(buf, in, sizeof(*in));
	case IPC_OLD:
	    {
		struct shminfo out;

		if(in->shmmax > INT_MAX)
			out.shmmax = INT_MAX;
		else
			out.shmmax = (int)in->shmmax;

		out.shmmin	= in->shmmin;
		out.shmmni	= in->shmmni;
		out.shmseg	= in->shmseg;
		out.shmall	= in->shmall; 

		return copy_to_user(buf, &out, sizeof(out));
	    }
	default:
		return -EINVAL;
	}
}


static int
ShmSystemInfo(struct IpcStruct *ipc, int cmd, char __user *ubuf)
{
   int err, version;
   struct shminfo64 kinfo;

   ASSERT(Ipc_IsLocked());
   ASSERT(ipc->file);

   version = Ipc_ExtractVersion(&cmd);

   err = ShmDoInfo(ipc->rid, cmd, &kinfo, sizeof(kinfo));

   if (copy_shminfo_to_user(ubuf, &kinfo, version)) {
      err = -EFAULT;
      goto out;
   }

   /* Must return the *index* of the highest used entry. */
   err = Ipc_HighestIdx(IpcKind_Shm);

out:
   return err;
}

static int
ShmSegmentInfo(struct IpcStruct *ipc, int cmd, char __user *ubuf)
{
   int err;
   struct shm_info kinfo;

   ASSERT(Ipc_IsLocked());
   ASSERT(ipc->file);

   err = ShmDoInfo(ipc->rid, cmd, &kinfo, sizeof(kinfo));

   /* Fixup the info so that it describes just those segments
    * in the vkernel. */
#error "How would you fixup swap attempts and successes?"
   kinfo.shm_tot = PAGE_NUM(Ipc_GetTotal(IpcKind_Shm));

   if (copy_to_user(ubuf, &kinfo, sizeof(kinfo))) {
      err = -EFAULT;
      goto out;
   }
  
   /* Must return the *index* of the highest used entry. */
   err = Ipc_HighestIdx(IpcKind_Shm);

out:
   return err;
}

static int
ShmSet(const struct IpcStruct *ipc, void __user *ubuf)
{
   int err;
   struct shmid64_ds kbuf;

   /* Does Linux invalidate violating attachees on permission change?
    * Apparently not. It seems that the change applies only to
    * future operations. */

   if (copy_from_user(&kbuf, ubuf, bufSz)) {
      err = -EFAULT;
      goto out;
   }

   if (!Task_IsReplaying()) {
      err = SysOps_ShmCtl(ipc->rid, IPC_SET, &kbuf);

      if (Task_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!SYSERR(err)) {
      ipc->perm.uid = kbuf.shm_perm.uid;
      ipc->perm.gid = kbuf.shm_perm.gid;
      ipc->perm.mode = (ipc->perm.mode & ~S_IRWXUGO) | (kbuf.shm_perm.mode & S_IRWXUGO);
      ipc->changeTime = Ipc_GetTime();
   }

out:
   return err;
}


int 
Shm_Ctl(int id, int cmd, struct shmid_ds __user *ubuf)
{
   int err;
   struct IpcStruct *ipc = NULL;

   Ipc_Lock();

   if (cmd == SHM_STAT) {
      /* Like IPC_STAT, but vshmid is an index into Linux's shm array. */
      err = ShmLookupByIdx(id, &ipc);
   } else {
      err = ShmLookupById(id, &ipc);
   }

   if (SYSERR(err)) {
      goto out_unlock;
   }


   ASSERT(ipc);

   switch (cmd) {
   case IPC_SET:
      err = ShmSet(ipc, buf);
      break;
   case IPC_RMID:
      err = ShmRemove(ipc);
      break;
   case SHM_STAT:
   case IPC_STAT:
      err = ShmStat(ipc, cmd, buf);
      break;
   case IPC_INFO:
      err = ShmSystemInfo(ipc, cmd, buf);
      break;
   case SHM_INFO:
      err = ShmSegmentInfo(ipc, cmd, buf);
      break;
   case SHM_LOCK:
   case SHM_UNLOCK:
      err = ShmLock(ipc, cmd == SHM_LOCK);
      break;
   default:
      err = -EINVAL;
      goto out_put;
      break;
   }

out_unlock:
   Ipc_Unlock();
out:
   return err;
}
