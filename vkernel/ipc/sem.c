/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

static int
SemLookupByKey(key_t key, struct IpcStruct **ipc)
{
   int err = 0;
   struct IpcStruct *tipc;

   ASSERT(ipc);
   ASSERT(Ipc_IsLocked());

   tipc = Ipc_LookupByKey(key);

   if (!tipc || tipc->kind != IpcKind_Sem) {
      err = -EINVAL;
   } else {
      *ipc = tipc;
   }

   return err;
}

static int
SemLookupById(int semid, struct IpcStruct **ipc)
{
   int err = 0;
   struct IpcStruct *tipc;

   ASSERT(ipc);
   ASSERT(Ipc_IsLocked());

   tipc = Ipc_LookupById(semid);

   if (!tipc || tipc->kind != IpcKind_Sem) {
      err = -EINVAL;
   } else {
      *ipc = tipc;
   }

   return err;
}

static int
SemLookupByIdx(int idx, struct IpcStruct **ipc)
{
   int err = 0;
   struct IpcStruct *tipc;

   ASSERT(ipc);
   ASSERT(Ipc_IsLocked());

   tipc = Ipc_LookupByIdx(idx);

   if (!tipc || tipc->kind != IpcKind_Sem) {
      err = -EINVAL;
   } else {
      *ipc = tipc;
   }

   return err;
}


static int
SemCreate(key_t key, int nsems, int shmFlags)
{
   int err = 0, semid, rsemid = -1;
   struct IpcStruct *ipc;

   ASSERT(Ipc_IsLocked());

   if (!VCPU_IsReplaying()) {
      rsemid = semid = SysOps_SemGet(IPC_PRIVATE, nsems, shmFlags & S_IRWXUGO);
      ASSERT_UNIMPLEMENTED(!SYSERR(semid));

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = semid;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      /* We don't create a backing semaphore set during replay. */
      DO_WITH_LOG_ENTRY(JustRetval) {
         semid = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   DEBUG_MSG(5, "key=0x%x semid=%d\n", key, semid);

   /* XXX: what if SemGet failed? */
   ipc = Ipc_Create(IpcKind_Sem, key, semid, rsemid, nsems, shmFlags, NULL);

   ipc->Un.Sem.opTime = 0;

   Ipc_Insert(ipc);

   err = semid;

   return err;
}

int
Sem_Get(key_t key, int nsems, int semFlags)
{
   int err;
   struct IpcStruct *ipc;

   Ipc_Lock();

   if (key == IPC_PRIVATE) {
      err = SemCreate(key, nsems, semFlags);
   } else if (SemLookupByKey(key, &ipc)) {
      if (!(semFlags & IPC_CREAT)) {
         err = -ENOENT;
      } else {
         err = SemCreate(key, nsems, semFlags);
      }
   } else if ((semFlags & IPC_CREAT) && (semFlags & IPC_EXCL)) {
      err = -EEXIST;
   } else {
      ASSERT(ipc);

      if (0 /*Ipc_CheckPerm(ipc, shmFlags)*/) {
         err = -EACCES;
      } else {
         err = ipc->idMap.keyLong;
         ASSERT(err != -1);
      }
   }

   Ipc_Unlock();

   return err;
}

static int
SemRemove(struct IpcStruct *ipc)
{
   int err = 0;

   ASSERT(Ipc_IsLocked());

   Ipc_Remove(ipc);

   if (!VCPU_IsReplaying()) {
      union semun karg;

      karg.val = 0;

      /* With IPC_RMID, Linux immediately removes the semaphore.
       * This is unlike the shared segment remove operation, 
       * which keeps segments around until the last atachee detaches. */
      ASSERT(ipc->rid != -1);
      err = SysOps_SemCtl64(ipc->rid, -1, IPC_RMID, karg);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!err) {
      Ipc_Destroy(ipc);
      ipc = NULL;
   }

   return err;
}

int
Sem_TimedOp(int vsemid, struct sembuf __user *tsops, uint nsops,
            const struct timespec __user *timeout)
{
   int err;
   struct IpcStruct *ipc = NULL;
   struct SyscallArgs args;
   int wasInterrupted, isSignalPending;
   struct sembuf *ksops;
   struct timespec ktimeout;
   size_t opSz;


   if (nsops < 1) {
      err = -EINVAL;
      goto out;
   }

#define SEMOPM  32	        /* <= 1 000 max num of ops per semop call */
   if (nsops > SEMOPM) {
      err = -E2BIG;
      goto out;
   }

   if (timeout) {
      if (Task_CopyFromUser(&ktimeout, timeout, sizeof(*timeout))) {
         err = -EFAULT;
         goto out;
      }
   }

   opSz = sizeof(*tsops) * nsops;
   ksops = SharedArea_Malloc(opSz);

   if (Task_CopyFromUser(ksops, tsops, opSz)) {
      err = -EFAULT;
      goto out_free;
   }

   Ipc_Lock();

   err = SemLookupById(vsemid, &ipc);
   if (SYSERR(err)) {
      Ipc_Unlock();
      goto out_free;
   }

   args.eax = SYS_ipc;
   args.ebx = SEMTIMEDOP;
   args.ecx = ipc->rid;
   args.edx = nsops;
   args.edi = (ulong) &ksops;
   args.ebp = (ulong) &ktimeout;

   /* Must release before sleeping to avoid deadlock. */
   Ipc_Unlock();

   do {
      Task_SetCurrentState(TASK_INTERRUPTIBLE);
      err = Sched_BlockingRealSyscall(NULL, &args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      } else if (VCPU_IsReplaying()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            err = entryp->ret;
         } END_WITH_LOG_ENTRY(0);
      }

      wasInterrupted = (err == -EINTR);
      isSignalPending = Task_TestSigPending(current, 1);

   } while (wasInterrupted && !isSignalPending);

   /* @timeout is NOT a value-result parm, so no need to
    * copy back in to user-space */
out_free:
   SharedArea_Free(ksops, opSz);
out:
   return err;
}


static int
SemValOp(struct IpcStruct *ipc, int semnum, int cmd, union semun arg)
{
   int err;

   ASSERT(cmd == GETVAL || cmd == SETVAL);
   ASSERT(Ipc_IsLocked());

   if (!VCPU_IsReplaying()) {

      err = SysOps_SemCtl64(ipc->rid, semnum, cmd, arg);

      if (VCPU_IsLogging()) {

         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return err;
}

static INLINE ulong 
copy_semid_to_user(void __user *buf, struct semid64_ds *in, int version)
{
   switch(version) {
   case IPC_64:
      return Task_CopyToUser(buf, in, sizeof(*in));
   case IPC_OLD:
      {
#if 0
         struct semid_ds out;

         ipc64_perm_to_ipc_perm(&in->sem_perm, &out.sem_perm);

         out.sem_otime	= in->sem_otime;
         out.sem_changeTime	= in->sem_changeTime;
         out.sem_nsems	= in->sem_nsems;

         return Task_CopyToUser(buf, &out, sizeof(out));
#endif
         ASSERT_UNIMPLEMENTED(0);
         return 0;
      }
   default:
      return -EINVAL;
   }
}

static int
SemStat(struct IpcStruct *ipc, int cmd, int version, char __user *ubuf)
{
   int err = 0;
   struct semid64_ds kbuf;

   memset(&kbuf, 0, sizeof(kbuf));

   ASSERT(Ipc_IsLocked());
#if 0
   if (Ipc_CheckPerm(ipc->perm, S_IRUGO)) {
      err = -EACCES;
      goto out;
   }
#endif

   if (cmd == SEM_STAT) {
      err = ipc->idMap.keyLong;
   }

   kbuf.sem_perm = ipc->perm;
   kbuf.sem_nsems =  ipc->size;
   //kbuf.sem_otime = ipc->Un.opTime;
   //kbuf.sem_changeTime = ipc->changeTime;

   if (copy_semid_to_user(ubuf, &kbuf, version)) {
      err = -EFAULT;
      goto out;
   }

out:
   return err;
}

static int
SemGetAll(struct IpcStruct *ipc, ushort __user *uarray)
{
   int nsems, err;
   ushort *karray;
   size_t karraySz;

   ASSERT(Ipc_IsLocked());

   /* We don't create a semaphore during replay, so the size
    * of the semaphore set (nsems) must be shadowed. */
   nsems = ipc->size;

   karraySz = sizeof(ushort) * nsems;
   karray = SharedArea_Malloc(karraySz);

   if (!VCPU_IsReplaying()) {
      union semun karg;

      karg.array = karray;
      err = SysOps_SemCtl64(ipc->rid, -1, GETALL, karg);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY_DATA(JustRetval, SYSERR(err) ? 0 : karraySz) {
            entryp->ret = err;
            if (!SYSERR(err)) {
               memcpy(datap, karray, karraySz);
            }
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
         if (!SYSERR(err)) {
            memcpy(karray, datap, karraySz);
         }
      } END_WITH_LOG_ENTRY(SYSERR(err) ? 0 : karraySz);
   }

   if (!err) {
      if (Task_CopyToUser(uarray, karray, karraySz)) {
         err = -EFAULT;
         goto out;
      }
   }

out:
   SharedArea_Free(karray, karraySz);
   return err;
}

static int
SemSetAll(struct IpcStruct *ipc, ushort __user *uarray)
{
   int nsems, err;
   ushort *karray;
   size_t karraySz;

   ASSERT(Ipc_IsLocked());

   /* We don't create a semaphore during replay, so the size
    * of the semaphore set (nsems) must be shadowed. */
   nsems = ipc->size;

   karraySz = sizeof(ushort) * nsems;
   karray = SharedArea_Malloc(karraySz);

   if (Task_CopyFromUser(karray, uarray, karraySz)) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      union semun karg;

      karg.array = karray;
      err = SysOps_SemCtl64(ipc->rid, -1, SETALL, karg);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

out:
   SharedArea_Free(karray, karraySz);
   return err;
}

static int
SemGetSingle(struct IpcStruct *ipc, int cmd)
{
   int err;

   ASSERT(Ipc_IsLocked());

   if (!VCPU_IsReplaying()) {
      union semun karg;

      karg.val = 0;
      err = SysOps_SemCtl64(ipc->rid, -1, cmd, karg);
      /* 
       * XXX: If segment no longer exists (b/c non-vkernel task deleted it), 
       * then make ipc table consistent.
       */

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return err;
}

static inline unsigned long copy_semid_from_user(struct semid64_ds *out, void __user *buf, int version)
{
	switch(version) {
	case IPC_64:
      {
         if(Task_CopyFromUser(out, buf, sizeof(*out)))
            return -EFAULT;

         return 0;
      }
   case IPC_OLD:
      {
#if 0
         struct semid_ds tbuf_old;

         if(Task_CopyFromUser(&tbuf_old, buf, sizeof(tbuf_old)))
            return -EFAULT;

         out->uid	= tbuf_old.sem_perm.uid;
         out->gid	= tbuf_old.sem_perm.gid;
         out->mode	= tbuf_old.sem_perm.mode;
#endif
         ASSERT_UNIMPLEMENTED(0);

         return 0;
      }
   default:
      return -EINVAL;
   }
}

static int
SemSet(struct IpcStruct *ipc, int version, union semun arg)
{
   int err;
   struct semid64_ds kbuf;

   if (copy_semid_from_user(&kbuf, arg.buf, version)) {
      err = -EFAULT;
      goto out;
   }

   if (!VCPU_IsReplaying()) {
      union semun karg;

      karg.buf = &kbuf;
      err = SysOps_SemCtl64(ipc->rid, -1, IPC_SET, karg);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = err;
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!err) {
      ipc->perm.uid = kbuf.sem_perm.uid;
      ipc->perm.gid = kbuf.sem_perm.gid;
      ipc->perm.mode = (ipc->perm.mode & ~S_IRWXUGO) | (kbuf.sem_perm.mode & S_IRWXUGO);
      //ipc->changeTime = Ipc_GetTime();
   }

out:
   return err;
}

static int
SemDoInfo(int cmd, struct seminfo *kinfo)
{
   int err;
   size_t bufSz = sizeof(*kinfo);

   if (!VCPU_IsReplaying()) {
      union semun karg;

      karg.__buf = kinfo;

      err = SysOps_SemCtl64(0, -1, cmd, karg);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY_DATA(JustRetval, SYSERR(err) ? 0 : bufSz) {
            entryp->ret = err;
            if (!SYSERR(err)) {
               memcpy(datap, kinfo, bufSz);
            }
         } END_WITH_LOG_ENTRY(0);
      }

   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         err = entryp->ret;
         if (!SYSERR(err)) {
            memcpy(kinfo, datap, bufSz);
         }
      } END_WITH_LOG_ENTRY(SYSERR(err) ? 0 : bufSz);
   }

   DEBUG_MSG(5, "err=%d\n", err);
   ASSERT(!SYSERR(err));

   return err;
}

static int
SemInfo(int cmd, union semun arg)
{
   int err;
   struct seminfo kinfo;

   Ipc_Lock();

   memset(&kinfo, 0, sizeof(kinfo));
   err = SemDoInfo(cmd, &kinfo);

   if (cmd == SEM_INFO) {
      kinfo.semusz = Ipc_Num(IpcKind_Sem);
      kinfo.semaem = Ipc_GetTotal(IpcKind_Sem);
   } else if (cmd == IPC_INFO) {
      /* Nothing to do. */
   } else {
      ASSERT(0);
   }

   ASSERT(!BAD_ADDR(arg.__buf));
   if (Task_CopyToUser(arg.__buf, &kinfo, sizeof(kinfo))) {
      err = -EFAULT;
      goto out;
   }

   /* Must return the *index* of the highest used entry. */
   err = Ipc_HighestIdx(IpcKind_Sem);

out:
   Ipc_Unlock();
   DEBUG_MSG(5, "err=%d\n", err);
   return err;
}



/*
 * @id could be an index (for SEM_STAT) or semid.
 */
static int
SemMain(int id, int semnum, int cmd, int version, union semun arg)
{
   int err;
   struct IpcStruct *ipc = NULL;

   DEBUG_MSG(5, "id=%d semnum=%d cmd=%d version=%d\n",
         id, semnum, cmd, version);

   Ipc_Lock();

   if (cmd == SEM_STAT) {
      err = SemLookupByIdx(id, &ipc);
   } else {
      err = SemLookupById(id, &ipc);
   }

   if (SYSERR(err)) {
      DEBUG_MSG(5, "Lookup of %d failed.\n", id);
      goto out_unlock;
   }

   ASSERT(ipc);

   switch (cmd) {
   case GETALL:
      err = SemGetAll(ipc, arg.array);
      break;
   case SETALL:
      err = SemSetAll(ipc, arg.array);
      break;
   case GETVAL:
   case SETVAL:
      err = SemValOp(ipc, semnum, cmd, arg);
      break;
   case GETPID:
   case GETNCNT:
	case GETZCNT:
      err = SemGetSingle(ipc, cmd);
      break;
   case SEM_STAT:
	case IPC_STAT:
      err = SemStat(ipc, cmd, version, arg.buf);
      break;
	case IPC_RMID:
      err = SemRemove(ipc);
      break;
	case IPC_SET:
      err = SemSet(ipc, version, arg);
      break;
   default:
      err = -EINVAL;
      break;
   }

out_unlock:
   Ipc_Unlock();

   DEBUG_MSG(5, "cmd=%d err=%d\n", cmd, err);
   return err;
}

int
Sem_Ctl(int id, int semnum, int cmd, union semun arg)
{
   int err, version;

   version = Ipc_ExtractVersion(&cmd);

   DEBUG_MSG(5, "cmd=%d\n", cmd);

   switch (cmd) {
   case IPC_INFO:
   case SEM_INFO:
      err = SemInfo(cmd, arg);
      D__;
      break;
   default:
      err = SemMain(id, semnum, cmd, version, arg);
      break;
   }
   D__;

   DEBUG_MSG(5, "cmd=%d err=%d\n", cmd, err);
   return err;
}
