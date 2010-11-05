/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#pragma once

#include "vkernel/public.h"
#include "private.h"


typedef enum {
   IpcKind_Shm,
   IpcKind_Sem,
   IpcKind_Msg
} IpcKind;

struct IpcStruct {
   struct MapField idMap;

   ulong rid;
   size_t size; /* for Sem, numsems */

   IpcKind kind;

   struct ipc64_perm perm;
   struct FileStruct *file;

   time_t changeTime;

   union {
      struct {
         time_t attachTime, detachTime;
         pid_t creatorPid, lastPid;
         int numAttached;
      } Shm;

      struct {
         time_t opTime;
      } Sem;

      /* XXX: Msg */
   } Un;
};

extern struct RepLockStruct ipcLock;

static INLINE int
Ipc_IsLocked()
{
   return ORDERED_IS_LOCKED(&ipcLock);
}

static INLINE void
Ipc_Lock()
{
   ORDERED_LOCK(&ipcLock);
}

static INLINE void
Ipc_Unlock()
{
   ORDERED_UNLOCK(&ipcLock);
}

extern struct IpcStruct*   Ipc_LookupById(int shmid);
extern struct IpcStruct*   Ipc_LookupByKey(key_t key);
extern struct IpcStruct*   Ipc_LookupByIdx(int idx);
extern void                Ipc_Insert(struct IpcStruct *ipc);
extern void                Ipc_Remove(struct IpcStruct *ipc);
extern int                 Ipc_Num(IpcKind kind);
extern int                 Ipc_HighestIdx(IpcKind kind);
extern size_t              Ipc_GetTotal(IpcKind kind);
extern int                 Ipc_ExtractVersion(int *cmd);
extern time_t              Ipc_GetTime();
extern struct IpcStruct*   Ipc_Create(IpcKind kind, key_t key, int id, 
                              int rid, size_t size, int shmFlags, 
                              struct FileStruct *filp);
extern void                Ipc_Destroy(struct IpcStruct *ipc);

extern int  Sem_TimedOp(int vsemid, struct sembuf __user *tsops, uint nsops,
               const struct timespec __user *timeout);
extern int  Sem_Get(key_t key, int nsems, int semFlags);
extern int  Sem_Ctl(int id, int semnum, int cmd, union semun arg);
