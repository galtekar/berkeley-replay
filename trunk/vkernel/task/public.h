#pragma once

/* Our segmentation register (TSS stands for Task State Segment). This is
 * where we keep our task struct. */
#define TSS gs
/*
 * cloning flags:
 */
#define CSIGNAL         0x000000ff  /* signal mask to be sent at exit */
#define CLONE_VM        0x00000100  /* set if VM shared between processes */
#define CLONE_FS        0x00000200  /* set if fs info shared between processes */
#define CLONE_FILES     0x00000400  /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800  /* set if signal handlers and blocked signals shared */
#define CLONE_PTRACE    0x00002000  /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK     0x00004000  /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT    0x00008000  /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD    0x00010000  /* Same thread group? */
#define CLONE_NEWNS     0x00020000  /* New namespace group? */
#define CLONE_SYSVSEM   0x00040000  /* share system V SEM_UNDO semantics */
#define CLONE_SETTLS    0x00080000  /* create a new TLS for the child */
#define CLONE_PARENT_SETTID   0x00100000  /* set the TID in the parent */
#define CLONE_CHILD_CLEARTID  0x00200000  /* clear the TID in the child */
#define CLONE_DETACHED     0x00400000  /* Unused, ignored */
#define CLONE_UNTRACED     0x00800000  /* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID 0x01000000  /* set the TID in the child */
#define CLONE_STOPPED      0x02000000  /* Start in stopped state */
#define CLONE_NEWUTS    0x04000000  /* New utsname group? */
#define CLONE_NEWIPC    0x08000000  /* New ipcs */

#define ERESTARTSYS  512
#define ERESTARTNOINTR  513
#define ERESTARTNOHAND  514   /* restart if no handler.. */
#define ERESTART_RESTARTBLOCK 516 /* restart by calling sys_restart_syscall */

#define TASK_RUNNING          (1 << 0) /* eligible for runqueue placement */
#define TASK_INTERRUPTIBLE    (1 << 1) /* about to make blocking syscall */
#define TASK_UNINTERRUPTIBLE  (1 << 2) /* XXX */
#define TASK_STOPPED          (1 << 3)
#define TASK_TRACED           (1 << 4)
#define EXIT_ZOMBIE           (1 << 5)
#define EXIT_DEAD             (1 << 6)
#define TASK_DEAD             (1 << 7) /* about to be descheduled forever */
#define TASK_WAITQUEUE        (1 << 8) /* task is in wait queue */

#define PT_PTRACED   0x00000001

/* Signal pending flags. Concurrently accessed and thus must be
 * stored in a separate word from TIF flags. */
#define TSF_SIGPENDING        (1 << 0)


/* Accessed only by owner task. No concurrent accesses. */

#define TIF_INTR_PENDING      (1 << 8)  /* is an (IPI/signal) pending? */
#define TIF_RESTORE_SIGMASK   (1 << 9)  /* restore signal mask in do_signal() (for sigsuspend()) */
#define TIF_BT_MODE           (1 << 16) /* are we in bt mode (1) or de mode (0)? */
#define TIF_SYSCALL           (1 << 17) /* are we handling a trap into the vkernel? */
#define TIF_TSCCALL           (1 << 18)
#define TIF_PREEMPT_PENDING   (1 << 19) /* are we awaiting preemption notification? */
#define TIF_PMI_PENDING       (1 << 20) /* are we awaiting a PMI? */
#define TIF_IO_PENDING        (1 << 21) /* blocked on a Linux syscall? */

#define TIF_PREEMPT_TIMER     (1 << 22)
#define TIF_PREEMPT_FAULT     (1 << 23)


#define TIF_SINGLE_STEP       (1 << 24)
#define TIF_INSEMU            (1 << 25)
#define TIF_ENTER_DEBUG_LOOP  (1 << 26)

#define TIF_PREEMPT           (TIF_PREEMPT_TIMER | TIF_PREEMPT_FAULT)
#define TIF_CALL_MASK         (TIF_SYSCALL | TIF_TSCCALL)


/*
 * Bits in flags field of signal_struct.
 */
#define SIGNAL_STOP_STOPPED   0x00000001 /* job control stop in effect */
#define SIGNAL_STOP_DEQUEUED  0x00000002 /* stop signal dequeued */
#define SIGNAL_STOP_CONTINUED 0x00000004 /* SIGCONT since WCONTINUED reap */
/* Indicates group exit is in progress. Set when task does a
 * group exit or when it receives a fatal signal. */
#define SIGNAL_GROUP_EXIT     0x00000008


/* Careful in picking the GDT entry we use. 6 is used by
 * glibc's %gs based TLS and 7 by Wine. So we pick 8. Note that we
 * should not pick -1, which will make the kernel pick a
 * different unused entry every time this function is called,
 * when really, we want to use the same entry for all threads.
 * Recall that the kernel, upon context-switch, modifies this GDT entry
 * to match that of the thread's TLS setting.
 *
 * See Ingo's patch for details: http://lwn.net/Articles/5851/.
 */
#define VK_TLS_ENTRY_NR 8

/*
 * XXX: More than 4K leads to under-utilized memory, but:
 *
 *    o in some places in libckpt, we allocate way more than that
 *    on the stack.
 *
 *    o LibVEX seems to need lots of stack space when doing
 *    translation (4K isn't enough for it). This could be a bug
 *    with the way our signal stack is setup, though.
 *
 *    o Valgrind seems to require more than 4K stack space.
 *    We need Valgrind to find bugs.
 */
#define VK_STACKSZ (0x1 << 13)

/* We must reserve certain signals for vkernel use.
 * Some are for user mode and others are for kernel mode. */
#define SIG_RESERVED_USER    10 /* SIGUSR1 */
#define SIG_RESERVED_KERNEL  12 /* SIGUSR2 */
/* Sent to us by our kernel mod for emulation, PMI notifications, etc.
 * We chose SIGILL since we want to detect if/when vkernel issues
 * a rdtsc or FP/SSE insn when it is not supported to
 * (i.e., error-detection). */
#define SIG_RESERVED_TRAP    SIGILL

#define sigmask(sig) (1 << ((sig) - 1))

/* Capability flags. */
#define CAP_HARD_BRCNT     (1 << 0) /* hardware branch counting */
#define CAP_PMI            (1 << 1) /* interrupt on counter overflow */
#define CAP_FPUandTSC_EMU  (1 << 2)

#ifndef __ASSEMBLER__

#include <limits.h>
#include <assert.h>
#include <elf.h>

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/resource.h>
#include <sys/ptrace.h>

#include "libcommon/public.h"
#include "vkernel/vkernel.lds.h"
#include "vkernel/bt/public.h"
#include "vkernel/vcpu/public.h"
#include "libperfctr.h"

/**************************************************
 **************************************************/


#define SYSCALLAREA      __attribute__ ((section (".syscall")))
#define SYSCALLDEF(sysname, ...) \
   SYSCALLAREA SyscallRet sysname(__VA_ARGS__)

/* We borrow Linux's distributed initialization technique --
 * no single file contains a list of initialization routines.
 * The list is generated by linker at compile time, based
 * on the following function annotations. */

typedef int (*initcall_t)(void);
typedef int (*finicall_t)(void);

#define __define_initcall(level,fn) \
   static initcall_t __initcall_##fn __attribute_used__ \
   __attribute__((__section__(".initcall" level ".init"))) = fn

#define __define_finicall(level,fn) \
   static finicall_t __finicall_##fn __attribute_used__ \
   __attribute__((__section__(".finicall" level ".fini"))) = fn

#define PRECORE_INITCALL(fn)     __define_initcall("0", fn)
#define CORE_INITCALL(fn)        __define_initcall("1", fn)
#define POSTCORE_INITCALL(fn)    __define_initcall("2", fn)
#define BT_INITCALL(fn)          __define_initcall("3", fn)
#define MODULE_INITCALL(fn)      __define_initcall("4", fn)
#define FS_INITCALL(fn)          __define_initcall("5", fn)
#define DEVICE_INITCALL(fn)      __define_initcall("6", fn)

#define FINICALL(fn)             __define_finicall("0", fn)




#if 1
#define ASSERT_TASKLIST_LOCKED()    ASSERT(ORDERED_IS_LOCKED(&taskListLock))
#define ACQUIRE_TASKLISTLOCK()      ORDERED_LOCK(&taskListLock)
#define RELEASE_TASKLISTLOCK()      ORDERED_UNLOCK(&taskListLock)

#define ASSERT_SIGLOCK_LOCKED(t)    ASSERT(ORDERED_IS_LOCKED(&t->sigHand->sigLock))
#define ACQUIRE_SIGLOCK(t)          ({ ASSERT_KPTR(t->sigHand); ORDERED_LOCK(&t->sigHand->sigLock); })
#define RELEASE_SIGLOCK(t)          ({ ASSERT_KPTR(t->sigHand); ORDERED_UNLOCK(&t->sigHand->sigLock); })
#endif


#if DEBUG
#define ASSERT_PTR(p) ASSERT_MSG((Task_IsKPtr(p)), \
      "non-vkernel pointer: 0x%x\n", p)
#define ASSERT_KPTR(p) ASSERT_PTR(p)
#define ASSERT_UPTR(p) ASSERT_MSG((Task_IsUPtr(p)), \
      "non-user pointer: 0x%x\n", p)
#define ASSERT_KPTR_NULL(p) ASSERT_MSG((p == NULL || Task_IsKPtr(p)), \
      "non-vkernel pointer: 0x%x\n", p)
#define ASSERT_UPTR_NULL(p) ASSERT_MSG((p == NULL || Task_IsUPtr(p)), \
      "non-user pointer: 0x%x\n", p)
#define ASSERT_NULL_PTR(p) ASSERT_MSG(p == NULL, "non-null pointer: 0x%x\n", p)
#else
#define ASSERT_PTR(p)
#define ASSERT_KPTR(p)
#define ASSERT_UPTR(p)
#define ASSERT_KPTR_NULL(p) 
#define ASSERT_UPTR_NULL(p) 
#define ASSERT_NULL_PTR(p)
#endif

static INLINE int
Task_IsAddrInImage(ulong addr)
{
   return (__IMAGE_START <= addr && addr < __IMAGE_END);
}

static INLINE int
Task_IsAddrInVDSO(ulong eip)
{
   return (__VDSO_TEXT_START <= eip && eip < __VDSO_TEXT_END);
}


static INLINE int
Task_IsAddrInUser(ulong addr)
{
   return (addr >= 0 && !Task_IsAddrInImage(addr)) ||
          Task_IsAddrInVDSO(addr);
}

static INLINE int
Task_IsAddrInKernel(ulong eip)
{
   return (__VKERNEL_TEXT_START <= eip && eip < __VKERNEL_TEXT_END);
}


static INLINE int
Task_IsKPtr(const void *ptr)
{
   return Task_IsAddrInImage((ulong)ptr);
}

static INLINE int
Task_IsUPtr(const void *ptr)
{
   return Task_IsAddrInUser((ulong)ptr);
}






enum PidType {
   PIDTYPE_PID,
   PIDTYPE_PGID,
   PIDTYPE_MAX
};

struct Pid {
   int nr;

   /*
    * lists of tasks that use this pid.
    */
   struct HListHead tasks[PIDTYPE_MAX];

   /*
    * list of tasks that hashed into this bucked (i.e., a chain).
    */
   struct HListNode pidChain;
};

struct PidLink {
   struct HListNode   node;
   struct Pid         *pid;
};


struct Exception {
   /*
    * Ordering of these fields matter!
    */

   /* Program counter value when signal occurs. */
   ulong addr;

   /* Program counter value to jump to after signal. */
   ulong fixup;

   /* For which signals does this rule apply? You
    * can use the sigmask() macro to specify a signal mask.
    *
    * CAREFUL: you can mask only the first 32 sigs with a uint mask. */
   uint sigmask;
};

struct ThreadContext {
   ucontext_t uc;

   /* thread-local storage state */
   struct LinuxSegmentDesc tls_descs[GDT_ENTRY_TLS_ENTRIES]; /* tls segment descriptors */
};

struct CloneArgs {
   /* Thread's clone() parameters. */
   int                                 flags;

   /* Child thread's stack. */
   void*                               stack;

   /* Pid of parent. */
   pid_t __user *                      ptid;

   /* TLS descriptor pointer. */
   struct LinuxSegmentDesc __user *    tlsDescp;

   /* The actual descriptor we copy from user-level. */
   struct LinuxSegmentDesc tlsDesc;

   /* tid of child set by kernel, cleared by kernel on thread termination. */
   pid_t __user *                      ctid;
};


typedef SyscallRet(*SyscallFn)(struct SyscallArgs);

extern const SyscallFn sys_call_table[NR_SYSCALLS];


struct TaskStack {

   /* XXX: use a stack dummy to verify that stack didnt't overflow */

   /*
    * There is one vkernel stack, used both for syscalls and
    * for preemption signals.
    */
   char               stack[VK_STACKSZ];

   /* 12-byte pad to ensure that &state.un.frame falls right
    * on the Linux sigframe. */
   uint pad[3];

   /*
    * Should be at the base of the stack so that Linux will
    * automatically init the task context upon signal frame setup.
    */
   union {
      struct rt_sigframe frame;
      TaskArchState      arch;
   } un;

   /* ---- Stack bottom, execution starts here ---- */
};

struct MmStruct {
   /* How many threads sharing the address space? */
   uint users;

   /* Each address space gets a unique identifier, which forms
    * the higher order bits of global addresses of locations
    * within the address space. This is necessary for race-detection. */
   uint id;

   struct ListHead         vmaList;
   struct RepLockStruct    vmaLock;

   ulong brkStart, brkEnd;

   struct VmaStruct *cached_vma;

   /* ---- Breakpoint modules ---- */
   struct MapStruct *brkptSiteMap;
   struct SynchLock  brkptSiteLock;
   int isRelativeBrkptPending;

   struct MapStruct *tntMemPgMapP;

   DEBUG_ONLY(int isAllocated;)
};

struct SigPending {
   struct ListHead      list;
   sigset_t             signal;
};

struct SigHand {
   int                  count;
   /* Careful: We want _NSIG (the number of all signals, including real-time)
    * and not NSIG (usually 32). We will receive signals with number
    * >= 32. */
   struct sigaction     action[_NSIG];

   /* protects private and shared sig queues */
   struct RepLockStruct sigLock;
};


/*
 * May be shared with other tasks via CLONE_SIGHAND. Shared
 * by all tasks in a thread group (via CLONE_THREAD).
 */
struct Signal {
   /*
    * How many tasks are sharing this? Tells us when it's safe
    * to deallocate.
    */
   int                     count;

   /* Signals directed to the thread group end up in this queue -- anybody
    * in the thread group can receive it */
   struct SigPending       sharedPending;

   /* Need this to ensure all threads in group stop before signalling
    * parent. */
   int                     groupStopCount;
   int                     groupExitCode;
   struct Task             *groupExitTask;
   int                     flags;

   /* Parent's put themselves in this queue when sys_wait()ing
    * on children. Children wake up waiting parent in this queue. */
   struct WaitQueueHead    waitChildExitQueue;

   /* Job Control IDs */

   /* Thread groups may shared the same pgrp, but they may
    * have different struct Signals. */
   pid_t                   pgrp;
#if 0
   pid_t                   session; /* session id */

   int                     leader; /* boolean -- session leader or not? */
#endif
};

struct RestartBlockStruct {
   long(*fn)(struct RestartBlockStruct *);
   ulong arg0, arg1, arg2, arg3, arg4;
};


/* Aligning the task_struct to a power of 2 makes it easy to obtain
 * a pointer to it just by looking at the value of %esp in kernel
 * context. */
#define TASK_SIZE POW2_ROUND_UP(sizeof(struct Task))
struct Task {
   /*
    * The stack should be first to ensure that it is page-aligned.
    */
   struct TaskStack stack;


   struct rt_sigframe * frameP;

   /* Used for reference counting of task struct by Task_Get()/Task_Put().
    * Needed because we don't know for certain whether the task or
    * the parent will be the last user of the task struct. */
   atomic_t count;

   /* Needed for our signal restarting mechanism, where
    * the restart action depends on the type of syscall
    * issued, which in turn can be determined by looking
    * at the original value of eax.
    *
    * Careful: must be a signed value, since it can be -1
    * to indicate that we didn't come from a syscall. */
   long orig_eax;

   /* sys_sigaltstack() decriptor we used to setup the task's
    * vkernel stack. */
   stack_t           sigstack_ss;

   /* Monitor-assigned task id (used to name log/debug files); > 0. */
   pid_t             id;
   /* Originally assigned by Linux, but same during logging and replay; > 0. */
   pid_t             pid;  /* task pid seen by applications */
   pid_t             tgid;
   /* Linux-assigned pid -- likely to be different during logging/replay modes; > 0 */
   pid_t             realPid;
   uid_t             realUid;  /* real uid */

   /* Why do we need to shadow the uid? Because emulated syscalls need this
    * value to setup user-level data structures. For example, sys_wait
    * emulation (notably WaitNoReapCopyout) writes the uid to userspace via a
    * pointer parameter. This value needs to be the same during logging
    * and replay. */
   uid_t             uid;

#if 0
   /* XXX: do we need to shadow this? */
   /* real pid; shared by threads cloned with CLONE_THREAD */
   pid_t             realTgid;
#endif

   /* Argument passed to the clone function. Once it's filled in, it
    * should not be modified. */
   struct CloneArgs  cloneArgs;
   volatile uint cloneFutex;

   /* Thread's ctid address -- not necessarily same as the
    * ctid address passed to clone, since the set_tid_address
    * syscall can change it. */
   int __user              *setChildTID;
   int __user              *clearChildTID;

#if 0
   /* BUG: These should really be in libckpt's TLS. */
   /* Use for any per-thread temporary stacks one
    * might need to create. */
   void              *tmpstk;
   struct ThreadContext ctx;
#endif

   /*
    * TASK_RUNNING, TASK_INTERRUPTIBLE, etc.
    */
   volatile int      state;
   int               ptrace;
   /*
    * TIF_SYSCALL, TIF_PREEMPT, etc.
    */
   volatile int      flags;

   /*
    * TSF_SIGPENDING, etc.
    */
   int               sigFlags;

   /*
    * Signals.
    */
   struct SigHand    *sigHand;   /* may be shared with CLONE_SIGHAND/THREAD */
   struct Signal     *signal;    /* may be shared with CLONE_THREAD */
   struct SigPending pending;
   sigset_t          blocked;
   sigset_t          realBlocked;/* for sys_rt_sigtimedwait */
   sigset_t          origMask, savedSigmask;
   ulong             sas_ss_sp;
   size_t            sas_ss_size;
   long              exitState;
   int               exitCode, pdeathSignal, exitSignal;
   struct RestartBlockStruct restartBlock;
   /* Used to queue signals from Linux received while we're
    * blocked in a Linux syscall. */
   struct ListHead   sigq;
   timer_t           preemptTimerId, snoopTimerId;

   /* XXX: when to fill in there vals? */
   ulong             error_code, cr2, trap_no;
#if 0
   sigset_t          sigAtomicSet;
   ucontext_t        sigAtomicCtx;
#endif

   /*
    * Task relationships.
    */

   /* Protected by the task lock. */
   struct ListHead   children, sibling;
   /* Global task list of thread-group leaders: protected by task lock */
   struct ListHead   tasks;

   /* Thread group members: protected by siglock since it is shared by all
    * members of group (using the task lock would be too conservative). */
   struct ListHead threadGroup;

   /* Protected by tasklist lock. */
   struct Task       *parent, *realParent;

   /*
    * Set when task is cloned and never subsequently changed.
    * Thus reads to this needn't acquire the task lock.
    * If the group leader dies and other group members
    * remain, then the leader reamains non-repable and in
    * zombie state until all members die. Hence the pointer
    * always points to a valid task struct.
    */
   struct Task *groupLeader;

   struct PidLink    pids[PIDTYPE_MAX];


   /*
    * Files.
    */
   struct FileSysStruct *fs;
   struct FilesStruct   *files;
   struct DentryStruct *procExe;

   /*
    * Scheduler.
    */
   struct ListHead   runList, *array /* points to runqueue, if scheduled */;
   struct ListHead   blockList;
   /* VCPU this task is running on */
   struct VCPU       *vcpu;
   struct SynchCond  schedCond;


   /*
    * Exec.
    */

   ulong personality; /* shadow of Linux's personality */
   void __user *arg_start; /* start of argv strings (not pointers) */

   /* We maintain info about the task's probable stack to
    * optimize race detection -- namely accesses to the stack
    * are ommitted. */
   ulong stack_addr; /* lowest-most address of stack. */
   ulong stack_size; /* size of entire stack mapping */
   ulong saved_auxv[AT_VECTOR_SIZE];

   /*
    * Memory/address space management.
    */
   struct MmStruct *mm;
#if 1
   struct MapStruct *stBrkptMap;
   struct MapStruct *dyBrkptMap;
   int insnStepCount;
   BkptCbFn insnStepCb;
   void *insnStepArg;
#else
   struct MapStruct *nfyMap;
#endif

   /* Branch countdown to next context-switch request. */
   ulong ticksToPreempt;
   struct BinTransStruct bt;
   int race_fd;

   /* Memory sharing protocol. */
   int msp_fd;


   /* ----- Constraint generation  ----- */
   FastMap *fmRegTntP;
   FastMap *fmTmpTntP;
   void *tntTmpA;
   int isInsnUnconstrained;
   u64 cg_IP_bbstart, cg_IP_bblen;

   /* For blackbox mode. */
   void *cgCurrBinP;
   /* For blackbox mode and instruction profiling. */
   void *cgCurrInsnP;
   /* ---------------------------------- */


   /* Branch counting -- used for software instruction
    * counting emulation. */
   uint vperfPageIdx;
   struct vperfctr *perfctr;
   volatile const struct perfctr_cpu_state *perf_cpu_state;
   /* task's virtual brcnt on entry to vkernel */
   ullong brCntOnEntry;
   DEBUG_ONLY(ullong lastBrCnt;)
   DEBUG_ONLY(uint iter;)
   /* running sum of #branches executed by vkernel code;
    * subtracted from raw hw brcnt to get #br executed by app
    * and not vkernel. */
   ullong vkBrCnt;
   /* #branches executed by guest when in bt mode */
   ullong softBrCnt;

   /* Single step mode. */
   ulong ssLastEip;

   VkEventTag dbgRespEv;
   /* -------------------------- */

   int is_in_code_cache;

   struct LinuxSegmentDesc crew_desc[3];
};


#define current      Task_GetCurrentTask()
#define curr_vcpu    Task_GetVCPU(current)
extern struct Task               initTask, startupTask, *childReaperTask;
extern struct RepLockStruct      taskListLock;
extern ulong                     totalClones;
extern int                       nr_threads;

extern struct Pid*   Pid_Alloc(int nr);
extern void          Pid_Attach(struct Task *task, enum PidType type, int nr);
extern void          Pid_Detach(struct Task *task, enum PidType type);
extern struct Pid*   Pid_Find(int nr);

/*
 * Task.
 */
/* how to get the current stack pointer from C */
register ulong currentStackPointer asm("esp");

static INLINE struct Task*
Task_GetCurrentTask(void) {
   struct Task* ret;
   ASSERT(sizeof(struct Task) <= TASK_SIZE);

   /* This is the same trick used in the Linux kernel: it assumes
    * that our Task struct lies at the base of the vkernel stack,
    * which we should be on when calling this function. */
   ret = (struct Task*)(currentStackPointer & ~(TASK_SIZE - 1));

   /* must be TASK_SIZE aligned */
   ASSERT((ulong)ret % TASK_SIZE == 0);

   return ret;
}

static INLINE TaskRegs*
Task_GetRegs(struct Task *tsk)
{
   return &tsk->stack.un.arch.vex;
}

static INLINE TaskRegs*
Task_GetCurrentRegs(void)
{
   return Task_GetRegs(current);
}
#define curr_regs (Task_GetCurrentRegs())

static INLINE char
Task_GetRegByte(TaskRegs *regP, off_t idx)
{
   ASSERT(idx < sizeof(TaskRegs));
   return *((char*)regP + idx);
} 

static INLINE int
Task_GetMemByte(const struct Task *tsk_ptr, const ulong addr, 
                uchar *byte_ptr )
{
   ASSERT_KPTR(tsk_ptr);
  
   int err = 0;
   const int aspace_id = tsk_ptr->mm->id;

   if (aspace_id == current->mm->id) {
      /* Fast-path. */
      if ((err = copy_from_user(byte_ptr, (void*)addr, sizeof(*byte_ptr)))) {
         err = -EFAULT;
      }
   } else {
      ulong word = 0;

      /* XXX: try reading through /dev/mem if this is too slow. */
      err = SysOps_ptrace(PTRACE_PEEKDATA, tsk_ptr->pid, (void*)addr,
            &word);
      ASSERT_MSG(err != -ESRCH, "Are you attached to the task?");
      ASSERT(err == 0 || err == -EIO);
      *byte_ptr = (char) word;
   }

   return err;
}


static INLINE ulong
Task_GetStackBase(struct Task *tsk)
{
   return ((ulong)tsk->stack.stack);
}

static INLINE int
Task_IsInTaskStack()
{
   return (Task_GetStackBase(current) <= currentStackPointer &&
           currentStackPointer < (Task_GetStackBase(current) + VK_STACKSZ));
}

static INLINE int
Task_IsThreadGroupLeader(struct Task *t)
{
   //ASSERT_SIGLOCK_LOCKED(t);

   return t == t->groupLeader;
}

static INLINE int
Task_IsThreadGroupEmpty(struct Task *t)
{
   /* We should be holding the siglock, but there are cases
    * where it is okay not to hold it -- when forking a new
    * process for example. */
   //ASSERT_SIGLOCK_LOCKED(t);

   return List_IsEmpty(&t->threadGroup);
}

static INLINE struct Task*
Task_NextThread(struct Task *t) {
   //ASSERT_SIGLOCK_LOCKED(t);

   return list_entry(t->threadGroup.next, struct Task, threadGroup);
}

#define while_each_thread(g, t) \
   while ((t = Task_NextThread(t)) != g)

#define do_each_task_pid(who, type, task)          \
   do {                       \
      struct HListNode *pos___;           \
      struct Pid *pid___ = Pid_Find(who);       \
      if (pid___ != NULL)              \
         hlist_for_each_entry((task), pos___,   \
                              &pid___->tasks[type], pids[type].node) {

#define while_each_task_pid(who, type, task)          \
   }                 \
   } while (0)


#define do_each_pid_task(pid, type, task)          \
   do {                       \
      struct HListNode *pos___;           \
      if (pid != NULL)              \
         hlist_for_each_entry((task), pos___,   \
                              &pid->tasks[type], pids[type].node) {

#define while_each_pid_task(pid, type, task)          \
   }                 \
   } while (0)

#define next_task(p) list_entry((p)->tasks.next, struct Task, tasks)

#define for_each_process(p) \
   for (p = &initTask ; (p = next_task(p)) != &initTask ; )


static INLINE struct Task *
Task_GetByPidType(struct Pid *pid, enum PidType type) {
   struct Task *result = NULL;
   if (pid) {
      struct HListNode *first;
      first = pid->tasks[type].first;
      if (first)
         result = hlist_entry(first, struct Task, pids[(type)].node);
   }
   return result;
}

static INLINE struct Task *
Task_GetByPid(int nr) {
   return Task_GetByPidType(Pid_Find(nr), PIDTYPE_PID);
}

static INLINE void
Task_AddParent(struct Task *t)
{
   List_AddTail(&t->sibling, &t->parent->children);
}

static INLINE void
Task_RemoveParent(struct Task *t)
{
   List_DelInit(&t->sibling);
}

static INLINE int
Task_TestFlag(struct Task *t, int flag)
{
   return t->flags & flag;
}

static INLINE void
Task_SetCurrentFlag(int flag)
{
   current->flags |= flag;
}

static INLINE void
Task_ClearCurrentFlag(int flag)
{
   current->flags &= ~flag;
}

static INLINE int
Task_IsStateValid(int state)
{
   return
      (state == TASK_INTERRUPTIBLE ||
       /* When waiting in a waitqueue, we still want to be woken
        * up when we get a signal. Hence the task interruptible. */
       state == (TASK_INTERRUPTIBLE | TASK_WAITQUEUE) ||
       state == TASK_RUNNING ||
       state == TASK_STOPPED ||
       state == TASK_DEAD);
}

static INLINE int
Task_IsDescheduled(int state)
{
   return state & (TASK_DEAD | TASK_STOPPED | TASK_WAITQUEUE);
}

static INLINE void
Task_SetCurrentState(int state)
{
   current->state = state;
}

static INLINE int
Task_GetCurrentState()
{
   /* Only @current can change its own state, so
    * process order guarantees determinism. */
   return current->state;
}

static INLINE pid_t
Task_ProcessGroup(struct Task *tsk)
{
   return tsk->signal->pgrp;
}

static INLINE int
Task_IsAddrInAppStack(ulong addr)
{
   ulong stack_start = current->stack_addr,
                       stack_end = current->stack_addr + current->stack_size;
   ASSERT(Task_IsAddrInUser(stack_start));
   ASSERT(stack_start < stack_end);
   return (stack_start <= addr && addr < stack_end);
}

static INLINE int
Task_IsAddrInCodeCache(ulong eip)
{
   return (eip >= __TC_START && eip < __TC_END);
}

static INLINE int
Task_IsThread(struct Task *tsk)
{
   return (tsk->cloneArgs.flags & CLONE_VM);
}

static INLINE struct VCPU *
Task_GetVCPU(struct Task *tsk) {
   ASSERT(tsk->vcpu);
   return tsk->vcpu;
}




extern ulong         Task_Clone(struct CloneArgs*, struct SyscallArgs *);
extern void          Task_Start();
extern void          Task_Exec();
extern int           Task_Savei387(struct _fpstate *fpstate);
extern ASMLINKAGE SyscallRet Task_RealClone(const struct SyscallArgs *);
extern ASMLINKAGE SyscallRet Task_RealSyscall(const struct SyscallArgs *);
extern ASMLINKAGE SyscallRet Task_ChildSyscall(const struct SyscallArgs *);
extern ASMLINKAGE SyscallRet Task_BlockingRealSyscall(const struct SyscallArgs *);
extern void REGPARM(1) Task_Put(struct Task *);
extern void Task_SafeDisableEmu();
extern void Task_SafeEnableEmu();


/*
 * Signals.
 */

extern void          Signal_SelfExit();
extern int           Signal_SigProcMask(int how, const sigset_t *set,
                                        sigset_t *oldset);
extern SyscallRet    Signal_BlockingRealSyscall(
   const struct SyscallArgs *args);
extern void          Signal_ProcessQueuedSignals();

static INLINE int
Task_TestSigPending(struct Task *tsk, int useSiglock)
{
   int res;

#if DEBUG
   if (!useSiglock) {
      ASSERT_SIGLOCK_LOCKED(tsk);
   }
#endif

   if (useSiglock) {
      ACQUIRE_SIGLOCK(tsk);
   }

   res = tsk->sigFlags & TSF_SIGPENDING;

   if (useSiglock) {
      RELEASE_SIGLOCK(tsk);
   }

   return res;
}

static INLINE void
Task_SetSigPending(struct Task *tsk, int useSiglock)
{
#if DEBUG
   if (!useSiglock) {
      ASSERT_SIGLOCK_LOCKED(tsk);
   }
#endif

   if (useSiglock) {
      ACQUIRE_SIGLOCK(tsk);
   }

   tsk->sigFlags |= TSF_SIGPENDING;

   if (useSiglock) {
      RELEASE_SIGLOCK(tsk);
   }
}

static INLINE void
Task_ClearSigPending(struct Task *tsk, int useSiglock)
{
   if (useSiglock) {
      ACQUIRE_SIGLOCK(tsk);
   }

   tsk->sigFlags &= ~TSF_SIGPENDING;

   if (useSiglock) {
      RELEASE_SIGLOCK(tsk);
   }
}

/* XXX: should be in private.h and made static INLINE. */
extern int     Signal_IsTimerSig(const siginfo_t *si);
extern int     Signal_IsPreemptSig(const siginfo_t *si);
extern int     Signal_IsSnoopSig(const siginfo_t *si);
extern int     Signal_IsIPISig(const siginfo_t *si);
extern int     Signal_IsCrashSig(int signr);
extern int     Signal_IsBlocked(ulong mask);
extern int     Signal_IsKernelMaskEnabled();

extern ulong sigMask;


/*
 * Kernel syscall entry-points.
 */
extern ASMLINKAGE void  Gate_SignalHardBrCnt();
extern ASMLINKAGE void  Gate_SignalSoftBrCnt();
extern ASMLINKAGE void  Gate_vsyscall();
extern ASMLINKAGE void  Gate_vsigreturn();
extern ASMLINKAGE void  Gate_vrt_sigreturn();

/*
 * MAX_ARG_PAGES defines the number of pages allocated for arguments
 * and envelope for the new program. 32 should suffice, this gives
 * a maximum env+arg of 128kB w/4KB pages!
 */
#define MAX_ARG_PAGES 32
#define MAX_ARG_BYTES (PAGE_SIZE*MAX_ARG_PAGES-sizeof(void *))
#define BINPRM_BUF_SIZE 128
struct LinuxBinPrm {
   ulong p;
   int argc, envc;
   struct FileStruct *file;
   char *stack_base;
   char buf[BINPRM_BUF_SIZE];
   char *tmpArgs;
   char * filename;  /* Name of binary as seen by procps */
   char * interp;    /* Name of the binary really executed. Most
               of the time same as filename, but could be
               different for binfmt_{misc,script} */
   int sh_bang;
};


/* Branch counting support. */
extern void     BrCnt_SelfInit();
extern void     BrCnt_OnPMI(uint);
extern int      BrCnt_IsPMISig(siginfo_t *);

/*
 * CAREFUL: Don't output to the debug log here since the debug log
 * print routines invoke this function and hecne doing so would
 * lead to recursion (of the infinite-segv kind).
 */
static INLINE ullong
BrCnt_Get()
{
   ullong res;

   /* The software branch count is collected in BT mode. */
   res = (current->brCntOnEntry - current->vkBrCnt) + current->softBrCnt;

   return res;
}

extern int  Task_GetState(struct Task *t);


/*
 * Exit.
 */
extern void          Exit_DoGroupExit(int exitCode);
extern void          Exit_Die();


/* Machine capabilities. */
extern int      Cap_Test(int flag);
extern void     Cap_Set(int flag);
extern struct   perfctr_info Cap_PerfInfo;

extern long sys_set_thread_area(struct LinuxSegmentDesc __user *u_info);
extern long sys_futex(u32 __user *uaddr, int op, u32 val,
                      struct timespec __user *utime, u32 __user *uaddr2, u32 val3);

extern int hasAppExecutionBegun;
extern int isSharedAreaInitialized;

extern u64          InsnEmu_DoRDTSC();

extern Elf32_auxv_t *auxV;

/* ----- Copying to/from userspace memory. ----- */

typedef 
   enum { 
      Sk_SysIO=0xc001,
      Sk_Generic,
      Sk_Zero,
   } SourceKind;

struct MsgTag {
   uuid_t   uuid;
   uint64_t msg_idx;
   uint64_t vclock;
};

struct CopySource {
   SourceKind tag;

   const char *logDataP;
   size_t loggedLen;

   union {
      struct {
         const struct FileStruct *filP;
         const tsock_chunk_t *chunk_ptr;
         int msg_flags;
      } SysIO;
   } Un;
};

extern void
Task_IovCopyToKernel(
      const struct iovec *vec, 
      ulong vlen, 
      const char *src, 
      ulong bytesToCopy);

/* ----------- User-space/vkernel communication wrappers ---------- */

extern int
Task_CopyToUser(void __user *toP, const void *fromP, size_t n);
extern int
Task_CopyFromUser(void *toP, const void __user *fromP, size_t n);
extern long
Task_UserStringNCopy(char *toP, const char __user *fromP, size_t n);
extern char *
Task_GetName(const char __user *fromP);
extern void
Task_PutName(char *strP);
extern size_t
Task_CountUserStringLen(char __user *strP, size_t maxLen);
extern size_t
Task_ClearUser(void __user *toP, size_t len);

static INLINE void
Task_CopyFromRegs(void *bufP, int off, size_t len)
{
   ASSERT((off+len) < sizeof(*curr_regs));

   const char *offP = (char*)curr_regs + off;
   ASSERT_KPTR(offP);

   memcpy(bufP, offP, len);
}

static INLINE void
Task_CopyToRegs(int off, const void *bufP, size_t len)
{
   ASSERT((off+len) < sizeof(*curr_regs));

   char *offP = (char*)curr_regs + off;
   ASSERT_KPTR(offP);

   memcpy(offP, bufP, len);
}

/* XXX: needs to invoke Task_CopyFrom/To/User; but
 * difficult because these are used on kernel memory
 * (e.g., Execve) */
#define __put_user(x,ptr)						\
({								\
 	int __ret_pu;						\
	__typeof__(*(ptr)) __pus_tmp = x;			\
	__ret_pu=0;						\
	if(Task_CopyToUser(ptr, &__pus_tmp,		\
				sizeof(*(ptr))) != 0)		\
 		__ret_pu=-EFAULT;				\
 	__ret_pu;						\
 })

#define __get_user(x,ptr)						\
({								\
   int __ret_pu = 0;        \
	if(Task_CopyFromUser(&(x), ptr,		\
				sizeof(x)) != 0)		\
 		__ret_pu=-EFAULT;				\
 	__ret_pu;						\
 })

extern void
Task_WriteRegs(const TaskRegs *regP, uint off, size_t len);

#define Task_WriteReg(__regP, x, val) { \
   __regP->R(x) = (val); \
   Task_WriteRegs(__regP, offsetof(VexGuestX86State, R(x)), \
         sizeof(__regP->R(x))); \
}

extern int Task_IsDebugLevel(int lvl);


#endif
