#include "vkernel/public.h"
#include "private.h"



/*
 * Design notes:
 *
 * All ipc objects (shmem, sems, msgqs) are visible to vkernel tasks. But only those created
 * with vkernel tasks (ie., those objects that are vkernel-visible)
 * may be shmget()ed of shmat()ed.
 *
 * 
 * XXX: If non-vkernel task destroys vkernel ipc objects, then the inode will
 * hold an invalid reference to the object, and all operations on that
 * object will fail.
 *
 *
 * XXX: If non-vkernel task attaches and modifies vkernel ipc objects, then
 * we lose read-determinism even with the serial scheduler, since
 * we cannot guaratee that modifications to objects will occur
 * in the same order.
 *
 * A possible fix to both is to create the objects as a priviledged user,
 * thereby disallowing non-privelidged users from destorying or attahcing
 * to it. But this is not effective if a priviledged user is running the
 * vkernel, since another priviledged but non-vkernel task could still
 * destory/attach the objects.
 *
 * Another options is to detect when segments have been removed by
 * non-vkernel tasks and then recover by making our internal tables
 * consistent. But that doesn't guarantee correct replay, since
 * the loss of ipc object state will introduce non-determinism.
 *
 * What we really need is a mechanism that prevents non-vkernel
 * segments from screwing with vkernel segments.
 *
 * XXX: syscall segment operations may fail if task has insufficient
 * priviledge. For example, the task may try to remove an ipc object
 * for which it has no ownership.
 */

SHAREDAREA struct MapStruct *ipcMap = NULL;
SHAREDAREA struct RepLockStruct ipcLock = SYNCH_ORDERED_LOCK_INIT(ipcLock, "ipc");
SHAREDAREA int numShm = 0, numSem = 0, numMsg = 0;
SHAREDAREA size_t totalShmBytes = 0, totalSemCount = 0;
SHAREDAREA ushort ipcSeq = 0;

struct IpcStruct*
Ipc_LookupById(int shmid)
{
   struct IpcStruct *ipc;

   ASSERT(Ipc_IsLocked());

   return Map_Find(ipcMap, idMap, shmid, ipc);
}

struct IpcStruct*
Ipc_LookupByKey(key_t key)
{
   struct IpcStruct *ipc = NULL;

   ASSERT(Ipc_IsLocked());

   list_for_each_entry(ipc, &ipcMap->list, idMap.list) {
      if (ipc->perm.key == key) {
         break;
      }
   }

   return ipc;
}

struct IpcStruct*
Ipc_LookupByIdx(int idx)
{
   int i = 0;
   struct IpcStruct *ipc = NULL;

   ASSERT(Ipc_IsLocked());

   list_for_each_entry(ipc, &ipcMap->list, idMap.list) {
      if (idx == i) {
         break;
      }
      i++;
   }

   return ipc;
}

void
Ipc_Insert(struct IpcStruct *ipc)
{
   ASSERT(Ipc_IsLocked());

   DEBUG_MSG(5, "Inserting ipc id=%d\n", ipc->idMap.keyLong);

   Map_Insert(ipcMap, idMap, ipc->idMap.keyLong, ipc);

   switch (ipc->kind) {
   case IpcKind_Shm:
      numShm++;
      totalShmBytes += ipc->size;
      break;
   case IpcKind_Sem:
      numSem++;
      totalSemCount += ipc->size;
      break;
   case IpcKind_Msg:
      numMsg++;
      break;
   default:
      ASSERT(0);
      break;
   };
}

void
Ipc_Remove(struct IpcStruct *ipc)
{
   ASSERT(Ipc_IsLocked());

   DEBUG_MSG(5, "Removing ipc id=%d\n", ipc->idMap.keyLong);

   Map_Remove(ipcMap, idMap, ipc);

   switch (ipc->kind) {
   case IpcKind_Shm:
      numShm--;
      totalShmBytes -= ipc->size;
      break;
   case IpcKind_Sem:
      numSem--;
      totalSemCount -= ipc->size;
      break;
   case IpcKind_Msg:
      numMsg--;
      break;
   default:
      ASSERT(0);
      break;
   };
}

int
Ipc_Num(IpcKind kind)
{
   int count = 0;

   ASSERT(Ipc_IsLocked());

   switch (kind) {
   case IpcKind_Shm:
      count = numShm;
      break;
   case IpcKind_Sem:
      count = numSem;
      break;
   case IpcKind_Msg:
      count = numMsg;
      break;
   default:
      ASSERT(0);
      break;
   };

   return count;
}

int
Ipc_HighestIdx(IpcKind kind)
{
   int idx = Ipc_Num(kind) - 1;

   return MAX(0, idx);
}

size_t
Ipc_GetTotal(IpcKind kind)
{
   size_t total = 0;

   ASSERT(Ipc_IsLocked());

   switch (kind) {
   case IpcKind_Shm:
      total = totalShmBytes;
      break;
   case IpcKind_Sem:
      total = totalSemCount;
      break;
   case IpcKind_Msg:
      ASSERT_UNIMPLEMENTED(0);
      break;
   default:
      ASSERT(0);
      break;
   };

   return total;
}

static ushort
IpcNextSeq()
{
   ASSERT(Ipc_IsLocked());

   /* XXX: we wrap on overflow -- does Linux do the same? must be emulate? */
   ipcSeq++;

   return ipcSeq;
}

int 
Ipc_ExtractVersion(int *cmd)
{
   if (*cmd & IPC_64) {
      D__;
      *cmd ^= IPC_64;
      return IPC_64;
   } else {
      D__;
      return IPC_OLD;
   }
}


time_t
Ipc_GetTime()
{
   time_t err;

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_time, 0);

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

   ASSERT(!SYSERR(err));

   return err;
}

/* XXX */
#if 0
int
Ipc_CheckPerm(struct IpcPerm *permp, int mode)
{
   /* flag will most probably be 0 or S_...UGO from <linux/stat.h> */
   int requested_mode, granted_mode, err;

   if (unlikely((err = audit_ipc_obj(ipcp))))
      return err;
   requested_mode = (flag >> 6) | (flag >> 3) | flag;
   granted_mode = ipcp->mode;
   if (current->euid == ipcp->cuid || current->euid == ipcp->uid)
      granted_mode >>= 6;

#error "Do we have to shadow the `am I in this group check'?"
   else if (in_group_p(ipcp->cgid) || in_group_p(ipcp->gid))
      granted_mode >>= 3;
   /* is there some bit set in requested_mode but not in granted_mode? */
   if ((requested_mode & ~granted_mode & 0007) && 
#error "Shadow capabilities -- perhaps always return false for now?"
         !capable(CAP_IPC_OWNER))
      return -1;
}
#endif


struct IpcStruct*
Ipc_Create(IpcKind kind, key_t key, int id, int rid, size_t size, int shmFlags, 
           struct FileStruct *filp)
{
   struct IpcStruct *ipc;

   ipc = SharedArea_Malloc(sizeof(*ipc));
   ASSERT_UNIMPLEMENTED(ipc);

   ipc->kind = kind;
   ipc->file = filp;

   ipc->idMap.keyLong = id; /* shmid, semid, or msgid */
   ipc->rid = rid;

   ipc->size = size;

   ipc->perm.key = key;
#if 0
   ipc->perm.uid = current->euid;
   ipc->perm.gid = current->egid;
   ipc->perm.cuid = current->euid;
   ipc->perm.cgid = current->egid;
#else
   ipc->perm.uid = 0;
   ipc->perm.gid = 0;
   ipc->perm.cuid = 0;
   ipc->perm.cgid = 0;
#endif
   ipc->perm.mode = (shmFlags & S_IRWXUGO);
   ipc->perm.seq = IpcNextSeq();

   //ipc->ctime = Ipc_GetTime();

   return ipc;
}

void
Ipc_Destroy(struct IpcStruct *ipc)
{
   ipc->file = NULL;
   SharedArea_Free(ipc, sizeof(*ipc));
   ipc = NULL;
}



SYSCALLDEF(sys_ipc, uint call, int first, int second, int third, void __user *ptr, long fifth)
{
   int version;

   version = call >> 16; /* hack for backward compatibility */
   call &= 0xffff;

   DEBUG_MSG(5, "call=%d\n", call);


   switch (call) {
	case SEMOP:
      fifth = 0;
	case SEMTIMEDOP:
      return Sem_TimedOp(first, (struct sembuf __user *)ptr, second,
            (const struct timespec __user *)fifth);
	case SEMGET:
      return Sem_Get(first, second, third);
   case SEMCTL: {
      union semun fourth;
      if (!ptr) {
         D__;
         return -EINVAL;
      }
      if (__get_user(fourth.__pad, (void __user * __user *) ptr)) {
         return -EFAULT;
      }
      return Sem_Ctl(first, second, third, fourth);
   }
	case MSGSND:
	case MSGRCV:
	case MSGGET:
	case MSGCTL:
      ASSERT_UNIMPLEMENTED(0);
      break;
	case SHMAT:
#if 0
      switch (version) {
      default: {
         ulong raddr;
         ret = Shm_Attach(first, (char __user *) ptr, second, &raddr);
         if (ret) {
            return ret;
         }
         return __put_user(raddr, (ulong __user *) third);
      }
      case 1:
         ASSERT_UNIMPLEMENTED(0);
         break;
      }
#endif
   case SHMDT: 
#if 0
      return Shm_Detach((char __user *) ptr);
#endif
   case SHMGET:
#if 0
      return Shm_Get(first, second, third);
#endif
	case SHMCTL:
#if 0
      return Shm_Ctl(first, second, (struct shmid_ds __user *) ptr);
#endif
      ASSERT_UNIMPLEMENTED(0);
      break;
   default:
      return -ENOSYS;
   }

   return -ENOSYS;
}

static int
Ipc_Init()
{
   ipcMap = Map_Create(0);

   return 0;
}

CORE_INITCALL(Ipc_Init);
