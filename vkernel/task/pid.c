/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <errno.h>

#include "vkernel/public.h"

#include "private.h"

static SHAREDAREA struct HListHead   *pidHash = NULL;


static INLINE ulong
PidHashFn(ulong addr)
{
   return Hash_Long(addr, DEFAULT_HASH_SHIFT);
}

struct Pid*
Pid_Alloc(int nr)
{
   struct Pid *pid;
   enum PidType type;

   pid = (struct Pid*) SharedArea_Malloc(sizeof(*pid));
   ASSERT_UNIMPLEMENTED(pid);

   pid->nr = nr;
   ASSERT(pid->nr > 0);

   for (type = 0; type < PIDTYPE_MAX; type++) {
      HList_HeadInit(&pid->tasks[type]);
   }

   HList_AddHead(&pid->pidChain, &pidHash[PidHashFn(pid->nr)]);

   DEBUG_MSG(5, "pid->nr=%d\n", pid->nr);

   return pid;
}

void
Pid_Free(struct Pid *pid)
{
   HList_Del(&pid->pidChain);
   SharedArea_Free(pid, sizeof(*pid));
}

struct Pid*
Pid_Find(int nr)
{
   struct Pid *pid;
   struct HListNode *elem;

   ASSERT(nr > 0);

   hlist_for_each_entry(pid, elem, &pidHash[PidHashFn(nr)], pidChain) {
      ASSERT(pid);

      if (pid->nr == nr) {
         DEBUG_MSG(5, "nr=%d found\n", nr);
         return pid;
      }
   }

   DEBUG_MSG(5, "nr=%d not found\n", nr);
   return NULL;
}

/*
 * Attach @task to the list of tasks that use pid @nr
 * as its pid @type.
 */
void
Pid_Attach(struct Task *task, enum PidType type, int nr)
{
   struct PidLink *pid_link;
   struct Pid *pid;

#if 0
   /* Disabled because it's called from Pid_Init for
    * the init process without the lock (which is safe since
    * there is no other thread at that point). */
   ASSERT_TASKLIST_LOCKED();
#endif

   ASSERT(nr > 0);
   pid_link = &task->pids[type];
   pid_link->pid = pid = Pid_Find(nr);
   ASSERT(pid);
   D__;
   HList_AddHead(&pid_link->node, &pid->tasks[type]);
}

void
Pid_Detach(struct Task *task, enum PidType type)
{
   struct PidLink *pid_link;
   struct Pid *pid;
   int tmp;

   ASSERT_TASKLIST_LOCKED();


   pid_link = &task->pids[type];
   ASSERT(pid_link);

   pid = pid_link->pid;
   ASSERT(pid);

   DEBUG_MSG(6, "type=%d nr=%d\n", type, pid->nr);

   HList_Del(&pid_link->node);
   pid_link->pid = NULL;

   /*
    * Deallocate if not being used for some other pid type.
    */
   for (tmp = 0; tmp < PIDTYPE_MAX; tmp++) {
      if (!HList_Empty(&pid->tasks[tmp])) {
         return;
      }
   }

   Pid_Free(pid);
}

static int
Pid_Init()
{
   int i, pidHashSize;

   pidHashSize = 1 << DEFAULT_HASH_SHIFT;

   pidHash = (struct HListHead*) 
      SharedArea_Malloc(pidHashSize * sizeof(*pidHash));
   ASSERT_UNIMPLEMENTED(pidHash);

   for (i = 0; i < pidHashSize; i++) {
      HList_HeadInit(&pidHash[i]);
   }

   return 0;
}

CORE_INITCALL(Pid_Init);

/**
 * sys_getpid - return the thread group id of the current process
 *
 * Note, despite the name, this returns the tgid not the pid.  The tgid and
 * the pid are identical unless CLONE_THREAD was was not specified on clone() in
 * which case the tgid is the same in all threads of the same group.
 *
 * This is SMP safe as current->tgid does not change; other tasks do not
 * modify it.
 */
SYSCALLDEF(sys_getpid) 
{
   return current->tgid;
}

/* Uniquely identifies this task - not really a "pid" */
SYSCALLDEF(sys_gettid)
{
   return current->pid;
}

SYSCALLDEF(sys_getpgid, pid_t pid)
{
   pid_t pgid;

   /* Another task could change our pgid via 
    * a call to sys_setpgid. */
   ACQUIRE_TASKLISTLOCK();

   if (!pid) {
       pgid = Task_ProcessGroup(current);
   } else {
      ASSERT_UNIMPLEMENTED(0);
      pgid = -EINVAL;
   }

   RELEASE_TASKLISTLOCK();

   return pgid;
}

SYSCALLDEF(sys_getpgrp)
{
   return sys_getpgid(0);
}

SYSCALLDEF(sys_getppid)
{
   pid_t pid;

   /*
    * The parent may change from underneath us -- for example,
    * if it dies and we get reparented with init.
    */
   ACQUIRE_TASKLISTLOCK();
   
   pid = current->realParent->tgid;

   RELEASE_TASKLISTLOCK();

   return pid;
}

/* Set @pid's process group to @pgid. */
static void
PidSetPgrp(pid_t pid, pid_t pgid)
{
   struct Task *p;

   ACQUIRE_TASKLISTLOCK();

   /* XXX: for now both pid and pgid must be in the vkernel domain,
    * meaning they must've been created by a vkernel task */
   ASSERT_UNIMPLEMENTED(Pid_Find(pgid));
   p = Task_GetByPid(pid);
   ASSERT_UNIMPLEMENTED(p);

   Pid_Detach(p, PIDTYPE_PGID);
   p->signal->pgrp = pgid;
   Pid_Attach(p, PIDTYPE_PGID, Task_ProcessGroup(p));

   RELEASE_TASKLISTLOCK();
}

SYSCALLDEF(sys_setpgid, pid_t pid, pid_t pgid)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      struct SyscallArgs args;
      args.eax = Task_GetCurrentRegs()->R(eax);
      args.ebx = pid;
      args.ecx = pgid;
      ret = Task_RealSyscall(&args);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!pid) {
      /* 
       * The group leader never changes and thus the read of
       * the groupLeader needn't be protected by a lock. 
       * Moreover, the pointer always points to the leader's
       * task struct (which may be in zombie state) so long as at 
       * least 1 group member is alive.
       */
      pid = current->groupLeader->pid;
   }
   if (!pgid) {
      pgid = pid;
   }


   if (!SYSERR(ret)) {
      PidSetPgrp(pid, pgid);
   }

   return ret;
}

SYSCALLDEF(sys_getsid, pid_t pid)
{
  /* XXX: do we need to shadow the sid? */ 
#ifdef SHADOWED_SID
   pid_t rpid;

   /* Another task may concurrent call sys_setsid, in which
    * case, without the task lock, there will be a read-write
    * race. */
   ACQUIRE_TASKLISTLOCK();

   rpid = current->signal->session;

   RELEASE_TASKLISTLOCK();

   return rpid;
#else
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_getsid, pid);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
#endif
}

/* XXX: maybe we'll want to shadow the session id as well at some point... */
#ifdef SHADOWED_SID
static void 
PidSetSpecialPids(pid_t session, pid_t pgrp)
{
   struct Task *curr = current->groupLeader;

   if (curr->signal->session != session) {
		Pid_Detach(curr, PIDTYPE_SID);
		curr->signal->session = session;
		Pid_Attach(curr, PIDTYPE_SID, session);
	}
	if (Task_ProcessGroup(curr) != pgrp) {
		Pid_Detach(curr, PIDTYPE_PGID);
		curr->signal->pgrp = pgrp;
		Pid_Attach(curr, PIDTYPE_PGID, pgrp);
	}
}
#endif


SYSCALLDEF(sys_setsid)
{
#ifdef SHADOWED_SID
  	struct Task *groupLeader = current->groupLeader;
	pid_t session;
	int err = -EPERM;

   ACQUIRE_TASKLISTLOCK();

	/* Fail if I am already a session leader */
	if (groupLeader->signal->leader)
		goto out;

	session = groupLeader->pid;
	/* Fail if a process group id already exists that equals the
	 * proposed session id.
	 *
	 * Don't check if session id == 1 because kernel threads use this
	 * session id and so the check will always fail and make it so
	 * init cannot successfully call setsid.
	 */
	if (session > 1 && 
         Task_GetByPidType(Pid_Find(session), PIDTYPE_PGID))
		goto out;

	groupLeader->signal->leader = 1;
	PidSetSpecialPids(session, session);
	err = Task_ProcessGroup(groupLeader);
   {
      SyscallRet sysres = syscall(SYS_setsid);
      ASSERT(sysres > 0);
   }
out:
   RELEASE_TASKLISTLOCK();
	return err;
#else
   SyscallRet ret;
   pid_t pgid = current->pid;

   if (!VCPU_IsReplaying()) {
      ret = syscall(SYS_setsid);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!SYSERR(ret)) {
      PidSetPgrp(pgid, pgid);
   }

   return ret;
#endif
}

/* Only this task can change its own *id, so
 * no need to worry about locking. */
SYSCALLDEF(sys_getuid)
{

   /* NOTE: we could log the result of the syscall and replay it,
    * but since we shadow the uid, there is no need to do so. */

   /* We shadow the Linux uid -- it's needed by various
    * syscall emulations (e.g., our emulation of sys_wait). */

   return current->uid;
}

static INLINE SyscallRet
IdGet(int sysno)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(sysno);
      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

SYSCALLDEF(sys_geteuid)
{
   return IdGet(SYS_geteuid);
}

SYSCALLDEF(sys_getegid)
{
   return IdGet(SYS_getegid);
}

SYSCALLDEF(sys_getgid)
{
   return IdGet(SYS_getgid);
}

static SyscallRet
IdGetRes(int sysno, uid_t __user *rid, uid_t __user *eid, uid_t __user *sid)
{
   uid_t __rid, __eid, __sid;
   SyscallRet ret;


   if (!VCPU_IsReplaying()) {
      /* Should always be successfull, so no need to log the retval. */
      ret = syscall(sysno, &__rid, &__eid, &__sid);
      ASSERT(!SYSERR(ret));

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(sys_getresid) {
            entryp->rid = __rid;
            entryp->eid = __eid;
            entryp->sid = __sid;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(sys_getresid) {
         __rid = entryp->rid;
         __eid = entryp->eid;
         __sid = entryp->sid;
      } END_WITH_LOG_ENTRY(0);
   }

	if (!(ret = __put_user(__rid, rid)) &&
	    !(ret = __put_user(__eid, eid)))
		ret = __put_user(__eid, sid);

   /* Shadowed uid should be in synch with Linux's uid. */
   ASSERT(__rid == current->uid);

   return ret;
}

SYSCALLDEF(sys_getresuid, uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
{
   return IdGetRes(SYS_getresuid, ruid, euid, suid);
}

SYSCALLDEF(sys_getresgid, uid_t __user *rgid, uid_t __user *egid, uid_t __user *sgid)
{
   return IdGetRes(SYS_getresgid, rgid, egid, sgid);
}


static SyscallRet
IdSet(int sysno, uid_t id)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      ret = syscall(sysno, id);
      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

SYSCALLDEF(sys_setuid, uid_t uid)
{
   SyscallRet ret;

   /* We need to keep our shadow uid in sync. */
   ret = IdSet(SYS_setuid, uid);
  
   if (!SYSERR(ret)) {
      /* current->uid is should be task local, so no locks
       * are necessary. */
      current->uid = uid;
   }

   return ret;
}

SYSCALLDEF(sys_setgid, uid_t gid)
{
   return IdSet(SYS_setgid, gid);
}


SYSCALLDEF(sys_setfsuid, uid_t uid)
{
   return IdSet(SYS_setfsuid, uid);
}

SYSCALLDEF(sys_setfsgid, uid_t gid)
{
   return IdSet(SYS_setfsgid, gid);
}

static SyscallRet
IdSetRes(int sysno, uid_t rid, uid_t eid, uid_t sid)
{
   SyscallRet ret;

   if (!VCPU_IsReplaying()) {
      /* Should always be successfull, so no need to log the retval. */
      ret = syscall(sysno, rid, eid, sid);
      ASSERT(!SYSERR(ret));

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(JustRetval) {
            entryp->ret = ret;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(JustRetval) {
         ret = entryp->ret;
      } END_WITH_LOG_ENTRY(0);
   }

   return ret;
}

SYSCALLDEF(sys_setresuid, uid_t ruid, uid_t euid, uid_t suid)
{
   SyscallRet ret;

   ret = IdSetRes(SYS_setresuid, ruid, euid, suid);

   /* CAREFUL: if any of the parms is -1, then it should not be changed. */
   if (!SYSERR(ret) && ((short)ruid) != -1) {
      current->uid = ruid;
   }

   return ret;
}

SYSCALLDEF(sys_setresgid, gid_t rgid, gid_t egid, gid_t sgid)
{
   return IdSetRes(SYS_setresgid, rgid, egid, sgid);
}

SYSCALLDEF(sys_setreuid, uid_t ruid, uid_t euid)
{
   return sys_setresuid(ruid, euid, -1);
}

SYSCALLDEF(sys_setregid, gid_t rgid, gid_t egid)
{
   return sys_setresgid(rgid, egid, -1);
}

