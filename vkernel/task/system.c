/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

#include <getopt.h>


ulong* entryESP = NULL;
int isSharedAreaInitialized = 0;
Elf32_auxv_t *auxV = NULL;

static int argc = -1;
static char **argv, **evp;

int hasAppExecutionBegun = 0;

STATS_DECLARE_TIMER(totalTime);


static SHAREDAREA struct FileSysStruct initFs =
{
   .count = 1,
   .lock = SYNCH_ORDERED_LOCK_INIT(initFs.lock, "filesys"),
   .cwd = NULL, /* should be dynamically initialized with a call to
                     sys_chdir */
};

static SHAREDAREA struct FilesStruct initFiles =
{
   .count = 1,
   .fdt = &initFiles.fdtab,
   .fdtab = {
      .maxFds = NR_OPEN_DEFAULT,
      .vfdTable = &initFiles.vfdArray[0],
      .closeOnExec = &initFiles.closeOnExecInit,
      .openFds = &initFiles.openFdsInit,
   },
   .lock = SYNCH_ORDERED_LOCK_INIT(initFiles.lock, "files"),
   .nextFd = 0,
   .closeOnExecInit = { { 0, } },
   .openFdsInit = { { 0, } },

   .vfdArray = { NULL, },
};

static SHAREDAREA struct Signal initSignals =
{
   .count = 1,
   .waitChildExitQueue = 
      __WAIT_QUEUE_HEAD_INITIALIZER(initSignals.waitChildExitQueue),
   .sharedPending = {
      .list = LIST_HEAD_INIT(initSignals.sharedPending.list),
      .signal = {{0}}},
   .pgrp = 0, /* should be dynamically initialized (syscall invoke required) */
};

static SHAREDAREA struct SigHand initSigHand =
{
   .count = 1,
   .action = { { .sa_handler = NULL, }  },
   .sigLock = SYNCH_ORDERED_LOCK_INIT(initSigHand.sigLock, "signal"),
};

static SHAREDAREA struct MmStruct initMm =
{
   .id = 0,
   .users = 1,
   .cached_vma = NULL,
   .brkptSiteMap = NULL,
};

/* Must be aligned to a power of 2 so that the ``current''
 * macro can work. */
SHAREDAREA ALIGN(TASK_SIZE) struct Task initTask =
{
   /* Process management */
   .state = TASK_RUNNING,
   .id = 1,
   .pid = 0,   /* must be initialized dynamically */
   .realPid = 0, /* ditto */
   .tgid = 0,  /* ditto */
   .uid = 0,   /* ditto */
   .flags = 0,
   .sigFlags = 0,
   .realParent = &initTask,
   .parent = &initTask,
   .tasks = LIST_HEAD_INIT(initTask.tasks),
   .children = LIST_HEAD_INIT(initTask.children),
   .sibling = LIST_HEAD_INIT(initTask.sibling),
   .threadGroup = LIST_HEAD_INIT(initTask.threadGroup),
   .groupLeader = &initTask,
   .cloneFutex = 1, /* not used for init task, but still no need to wait */

   /* Signals */
   .signal = &initSignals,
   .sigHand = &initSigHand,
   .pending = {
      .list = LIST_HEAD_INIT(initTask.pending.list),
      .signal = {{0}}},
   .blocked = {{0}},
   .restartBlock = { .fn = NULL, },
   .sigq = LIST_HEAD_INIT(initTask.sigq),

   /* Scheduler */
   .runList = LIST_HEAD_INIT(initTask.runList),
   .blockList = LIST_HEAD_INIT(initTask.blockList),
   .array = NULL,
   .vcpu = &vcpuArray[0],
   .schedCond = { /* init thread needn't be signalled by anybody */
      .lock = SYNCH_LOCK_INIT,
      .woken_seq = 0,
      .wakeup_seq = 1,
      .total_seq = 1 
   },

   /* Files */
   .files = &initFiles,
   .fs = &initFs,
   .procExe = NULL,

   /* Exec */
   .personality = 0,
   .stack_addr = 0,
   .stack_size = 0,
   .arg_start = NULL,

   /* Memory management */
   .mm = &initMm,
#if 0
   .nfyMap = NULL,
#endif

   /* Hardware branch counting. */
   .perfctr = NULL,
   .brCntOnEntry = 0,
   .vkBrCnt = 0,
   .vperfPageIdx = 0,

   /* Single step. */
   .ssLastEip = 0,
   
   .is_in_code_cache = 0,
};


static void
SystemExecApp()
{
   const int MAX_NUM_ARGS = 256;
   char **execArgv = malloc(sizeof(char*)*MAX_NUM_ARGS),
        **execEnvv = NULL;
   
   int execArgc = MAX_NUM_ARGS, execEnvc = MAX_NUM_ARGS;

   DEBUG_MSG(5, "argListLen=%d\n", env.argListLen);
   MiscOps_RestoreArgv(env.argList, env.argListLen, execArgv, &execArgc);
   ASSERT_MSG(env.argListCount == execArgc, "count=%d argc=%d\n",
         env.argListCount, execArgc);

#if DEBUG
   int i;
   for (i = 0; i < execArgc; i++) {
      DEBUG_MSG(5, "%d: %s\n", i, execArgv[i]);
   }
#endif

   if (env.flags & ENV_SHOULD_INHERIT) {
      execEnvv = malloc(sizeof(char*)*MAX_NUM_ARGS);
      MiscOps_RestoreArgv(env.envList, env.envListLen,
            execEnvv, &execEnvc);
      DEBUG_MSG(5, "execEnvc=%d\n", execEnvc);
      ASSERT(env.envListCount == execEnvc);
   }

   if (Exec_DoExecve(execArgv[0], execArgv, execEnvv) < 0) {
      FATAL("%s not found\n", execArgv[0]);
   }

   free(execArgv);
   if (execEnvv) { 
      ASSERT(env.flags & ENV_SHOULD_INHERIT);
      free(execEnvv);
   }

   execArgv = NULL;
   execEnvv = NULL;
}

void
System_StartThread()
{
#if 0
   char *filename = argv
   char *argv[] = { session.initBin, NULL };
#endif
   struct Pid *pid;
   char *cwd = SharedArea_Malloc(PAGE_SIZE);
   int err;
   

   ASSERT(current->id == 1);
 
   current->realPid = gettid();

   /* May not hold if we are being ptrac()ed. */
   ASSERT(current->realPid == getpgrp() ||
          current->realPid != getpgrp());
   current->realUid = getuid();
   /* XXX: this will cause bash to enter single-user mode. */
   //current->realUid = 1;

   if (!VCPU_IsReplaying()) {
      /* XXX: no reason we must start in cwd. Could start at
       * the root dir. */
      if (!getcwd(cwd, PAGE_SIZE)) {
         FATAL("Current working directory is invalid.\n");
      }

      DO_WITH_LOG_ENTRY(init) {
         entryp->initPid = current->realPid;
         entryp->initUid = current->realUid;
         strncpy(entryp->initCwd, cwd, PAGE_SIZE);
      } END_WITH_LOG_ENTRY(0);

      current->pid = current->realPid;
      current->uid = current->realUid;

   } else {
      DO_WITH_LOG_ENTRY(init) {
         current->pid = entryp->initPid;
         current->uid = entryp->initUid;
         strncpy(cwd, entryp->initCwd, PAGE_SIZE);
      } END_WITH_LOG_ENTRY(0);
   }
   DEBUG_MSG(5, "cwd=%s\n", cwd);
   /* XXX: cwd may not be chdir'able, if for example, we did a
    * su before starting the vkernel, and as a result, a path
    * component in the cwd is non-executable for the target user. */
   err = FileSys_Chdir(cwd);
   if (err < 0) {
      FATAL("Can't sys_chdir to cwd=%s\n", cwd);
   }
   SharedArea_Free(cwd, PAGE_SIZE);
   cwd = NULL;

   current->signal->pgrp = current->pid;
   current->tgid = current->pid;
   pid = Pid_Alloc(current->pid);
   ASSERT(pid->nr);
   Pid_Attach(current, PIDTYPE_PGID, Task_ProcessGroup(current));
   Pid_Attach(current, PIDTYPE_PID, current->pid);

   DEBUG_MSG(5, "pid=%d realPid=%d\n", current->pid, current->realPid);

   /* XXX: why must we set this? A: so that we deliver signals on
    * exit... see gate.S */
   Task_SetCurrentFlag(TIF_SYSCALL);

   SystemExecApp();

   /* Enable only at the very end to ensure that the task log has
    * been set up -- you'll get assertion failures otherwise. */
   RepSynch_Enable();

   D__;
}

static void
CloseInheritedFds()
{
#if 0
   int i;

   /* Close any inherited controlling terminals. We'll
    * need to reopen them with sys_open, so that the
    * corresponding file-structs are backed by controlling fds. */
   for (i = 0; i < 3; i++) {
      SysOps_Close(i);
   }
#endif
}


static void
SystemInitRest()
{
   /*
    * current should point to the init task struct.
    */
   ASSERT(current == &initTask);
   ASSERT(current->sigHand == &initSigHand);
   ASSERT(current->signal == &initSignals);

   /* 
    * Put it on the runqueue.
    */
   ASSERT(Task_GetCurrentState() == TASK_RUNNING);
   Sched_WakeNewTask(current);

   /* Open stdin, stdio, and stderr for the init process. */
   {
      int i, err;

#if 0
      /* XXX: shouldn't cast to __user * */
      res = File_OpenFd(AT_FDCWD, (const char *) session.ttyName, O_RDWR, 0);
      DEBUG_MSG(5, "res=%d\n", res);
      ASSERT(res == 0);
      (void) sys_dup(0);
      (void) sys_dup(0);
#else
      //printf("cool\n");
      /* We can't simply open /dev/tty since we may not have
       * permissions to. This could happen for example when we're
       * initiated over an ssh connection, in which case fds 0,1, and
       * 2 are mapped to pipes. Hence use the ttys given to us. */
      for (i = 0; i < 3; i++) {

         ASSERT( strlen(session.tty_name) );

         /* Don't follow links, in case we're opening the proc fd.
          * That may link to something like "pipe[34343]", which is
          * not an lstat'able file. */
         err = File_OpenFd(AT_FDCWD, session.tty_name, O_RDWR, 0, 0);
         ASSERT(err == i);
      }
#endif
   }
}


static void
InitDoCalls()
{
   initcall_t *call;
   extern initcall_t __initcall_start[], __initcall_end[];

   for (call = __initcall_start; call < __initcall_end; call++) {
      int res;

      res = (*call)();
   }
}

static void
InitDoSanityChecks()
{
#if DEBUG
   /* Make sure that VEX guest state offsets match that of 
    * the sigcontext in a struct rt_sigframe. This premits
    * Linux to fill in the vex guest state for us, thus
    * saving us the work on translating between the two. */
#define C(x, y) \
   ASSERT(offsetof(VexGuestX86State, x) == \
          offsetof(struct rt_sigframe, uc.uc_mcontext.y));

   C(guest_GS, gs);
   C(guest_FS, fs);
   C(guest_ES, es);
   C(guest_DS, ds);
   C(guest_EDI, edi);
   C(guest_ESI, esi);
   C(guest_EBP, ebp);
   C(guest_ESP, esp);
   C(guest_EBX, ebx);
   C(guest_EDX, edx);
   C(guest_ECX, ecx);
   C(guest_EAX, eax);
   C(guest_EIP, eip);
   C(guest_CS, cs);
   C(guest_CC_DEP1, eflags);
   C(guest_SS, ss);

   /* Register state should be right on top of the stack base. */
   {
      char * stack_highest = (char *) current->stack.stack + 
         sizeof(current->stack.stack);
      ASSERT(sizeof(current->stack.stack) >= 1024); /* a bare-minimum */
      ASSERT(sizeof(current->stack.stack) == VK_STACKSZ);
      ASSERT((void*) curr_regs == (void*) &current->stack.un.arch);
      ASSERT(stack_highest+sizeof(current->stack.pad) == 
            (char*) &current->stack.un.arch);
   }

   if (0) {
      DEBUG_MSG(5, "Size of various kernel structs:\n"
                "struct rt_sigframe : %d\n"
                "struct sigframe    : %d\n"
                "struct siginfo     : %d\n"
                "struct ucontext    : %d\n"
                "struct sigcontext  : %d\n"
                "struct _fpstate    : %d\n"
                "stack_t            : %d\n"
                "sigset_t           : %d\n",
                sizeof(struct rt_sigframe),
                sizeof(struct sigframe),
                sizeof(struct siginfo),
                sizeof(struct ucontext),
                sizeof(struct sigcontext),
                sizeof(struct _fpstate),
                sizeof(stack_t),
                sizeof(sigset_t)
         );
   }

   /* Our definitions should be the same size as those in Linux. */
   ASSERT(sizeof(struct rt_sigframe) == 892);
   ASSERT(sizeof(struct sigframe) == 732);
   ASSERT(sizeof(struct siginfo) == 128);
   ASSERT(sizeof(struct ucontext) == 116);
   ASSERT(sizeof(struct sigcontext) == 88);
   ASSERT(sizeof(struct _fpstate) == 624);
   ASSERT(sizeof(stack_t) == 12);
   ASSERT(sizeof(sigset_t) == _NSIG_WORDS*WORD_SIZE);
   ASSERT(sizeof(sigset_t) == 8);
#endif
}

void
System_Init() 
{
   ASSERT(isSharedAreaInitialized);
   ASSERT(current == &initTask);

   Task_DebugInit();

   InitDoSanityChecks();

   /* Lock routines access this field and so we must init early. */
   current->realPid = gettid();

   /* Not absolutely necessary, but makes things consistent --
    * prevents asserts from firing. */
   ACQUIRE_TASKLISTLOCK();

   InitDoCalls();

   RELEASE_TASKLISTLOCK();

   SystemInitRest();

   CloseInheritedFds();

   STATS_START_TIMER(totalTime);
}



static void
SystemPrintUsage()
{
   printf(
          "Berkeley Deterministic Hypervisor\n"
          "Copyright (C) University of California. All rights reserved.\n\n"
          "Usage: bdr-kernel [options] [target] ...\n"
         );
   printf("Available options:\n");
   printf("-c,--conf=FILE     Alternate configuration file\n");
   printf("-h,--help=STRING   Gives help on a particular module\n");
   printf("-m,--modules=LIST  List of modules to use\n");
   printf("-o,--opts=STRING   Overriding config options\n");

   struct ModDesc ** modPP;

   printf("\nAvailable modules:\n");
   for (modPP = __mod_desc_start; modPP < __mod_desc_end; modPP++) {
      struct ModDesc *modP = (*modPP);

      printf("%10s   %s\n", modP->name, modP->desc);
   }
}



#if 0
static int
SystemParseOptions()
{
   int err = 0, i = 1;
   struct ModDesc *modP;
   char **subCmdArgv = NULL;
   const int MAX_NUM_ARGS = 256;

   subCmdArgv = malloc(sizeof(char*) * MAX_NUM_ARGS);

   if (argc <= 1) {
      goto error_out;
   }

   //DLOG("argc=%d\n", argc);

   while (i < argc) {
      int subCmdArgc = MAX_NUM_ARGS;

      //DLOG("i=%d argv[i]=%s\n", i, argv[i]);
      MiscOps_Tokenize(argv[i], &subCmdArgc, subCmdArgv);
      //printf("i=%d argv[i]=%s\n", i, argv[i]);

      ASSERT(subCmdArgv[0]);

      if ((modP = Module_Lookup(subCmdArgv[0]))) {
         /* must reset since other mods may have invoked getopt() */
         optind = 0;
         err = modP->parseOptionsFn(subCmdArgc, subCmdArgv);

         if (err) {
            goto out;
         }
      } else {
         eprintf("unknown command: '%s'\n", subCmdArgv[0]);
         goto error_out;
      }

      i++;
   }

   goto out;

error_out:
   SystemPrintUsage();
   err = -1;
out:
   ASSERT(subCmdArgv);
   free(subCmdArgv);
   subCmdArgv = NULL;
   return err;
}
#endif

#if 0

static int
SystemOptLookup(char *argBuf, size_t bufSz, char **optA, int nrOpts, const char *keyStr)
{
   printf("nrOpts=%d key=%s\n", nrOpts, keyStr);
   int i;
   for (i = 0; i < nrOpts; i++) {
      char *s = optA[i];
      char *p = strchr(optA[i], '=');
      ASSERT(p > s);

      if (strncmp(s, keyStr, p-s) == 0) {
         strncpy(argBuf, p+1, bufSz);
         printf("argBuf=%s\n", argBuf);
         return i;
      }
   }

   return -1;
}
#endif

static void
SystemPrintUsageForModule(char *modName)
{
   struct ModDesc *mdP = Module_Lookup(modName);

   if (mdP) {
      struct ModOpt *oP = mdP->optA;

      printf("%s : %s\n\n", modName, mdP->desc);

      printf("Available options:\n\n");

      printf("%-22s  %-6s  %-7s  %s\n", "Key", "Type", "Default", 
            "Summary");
      printf("----------------------------------------------------------------------------\n");
      while (oP->setOptCb != NULL) {
         printf("%-22s  %-6s  %-7s  %s\n", oP->key, 
               oP->kind == Opk_Bool ? "Bool" : 
                  oP->kind == Opk_Int ? "Int" : "String",
               oP->defValue,
               oP->helpStr);
         oP++;
      }

   } else {
      SystemPrintUsage();
   }
}

static int
SystemLoadModWork(const struct Pair *optA, const int nrOpts, struct ModDesc * modP)
{
   int err = 0;
   struct ModDesc **depModP = NULL;

   /* Load dependencies first; shouldn't be too many dependencies so
    * recursion should be okay. */
   for (depModP = modP->depA; *depModP != NULL; depModP++) {
      if (SystemLoadModWork(optA, nrOpts, *depModP)) {
         err = -1;
         goto out;
      }
   }

   struct ModOpt *oP = modP->optA;
   int idx = 0;

   while (oP->setOptCb != NULL) {
      const char *valueP;
      int i;

#if !DEBUG
      /* XXX: We need to scan each provided option for the given module,
       * and report any unmatched options. */
#endif
      //printf("oP->key=%s\n", oP->key);
      if ((i = MiscOps_PairLookup(optA, nrOpts, oP->key)) != -1) {
         ASSERT(i >= 0);
         valueP = optA[i].value;
      } else {
         valueP = oP->defValue;
      }

      if (oP->setOptCb(idx, valueP)) {
         SystemPrintUsageForModule(modP->name);
         err = -1;
         goto out;
      }

      oP++;
      idx++;
   }

   /* XXX: What should happen if some optinos were never matched?
   */

   modP->isLoaded = 1;

out:
   return err;
}

/*
 * Are any of the conflicting modules loaded?
 */
static struct ModDesc *
SystemCheckForModConflicts(struct ModDesc *modP)
{
   struct ModDesc **confModP = NULL;

   for (confModP = modP->confA; *confModP != NULL; confModP++) {
      if (Module_IsLoaded(*confModP)) {
         return *confModP;
      }
   }

   return NULL;
}


static int
SystemLoadMod(struct Pair *optA, const int nrOpts, struct ModDesc *modP) 
{
   struct ModDesc *confModP = NULL;
   ASSERT_KPTR(modP);

   if ((confModP = SystemCheckForModConflicts(modP))) {
      eprintf("module %s conflicts with module %s\n", modP->name, 
            confModP->name);
      return -1;
   } else {
      return SystemLoadModWork(optA, nrOpts, modP);
   }

   return -1;
}

static int
SystemParseOptions()
{
   int err = 0;

   struct Pair *optA = NULL;
   const int MAX_OPTS = 256;
   int nrOpts = 0;
   const int MAX_MODULES = 10;
   //char modNameList[MAX_MODNAME_LEN*MAX_MODULES];
   char *modNamePtrs[MAX_MODULES];
   int nrMods = 0;

   optA = malloc(sizeof(*optA) * MAX_OPTS);

   while (1) {
      int c, option_index = 0;
      static struct option long_options[] = {
         {"config", 1, NULL, 'c'},
         {"help", 1, NULL, 'h'},
         {"modules", 1, NULL, 'm'},
         {"opts", 1, NULL, 'o'},
         {0, 0, NULL, 0}
      };
      c = getopt_long(argc, argv, "c:h:m:o:", long_options, &option_index);
      if (c == -1) {
         break;
      }

      switch (c) {
      case 'c':
         break;
      case 'h':
         ASSERT(optarg);
         SystemPrintUsageForModule(optarg);
         err = -1;
         goto out;
         break;
      case 'm':
         /* XXX: this may be called multiple times, so append
          * module names, taking care not to replace existing ones.
          * */
         /* XXX: parse options for only the modules in this list. */
         nrMods = MAX_MODULES;
         MiscOps_Tokenize(optarg, ",", &nrMods, modNamePtrs);
         break;
      case 'o':
         nrOpts = MAX_OPTS;
         if (MiscOps_ParsePair(optarg, optA, &nrOpts)) {
            /* XXX: not a key/value list */
            ASSERT_UNIMPLEMENTED(0);
         }
         break;
      case '?': /* unrecognized options */
      default:
         err = -1;
         break;
      }
   }

   if (err) {
      goto usage_out;
   }

   int i;
#if DEBUG
   for (i = 0; i < nrOpts; i++) {
      ASSERT(strlen(optA[i].key));
   }
#endif

   for (i = 0; i < nrMods; i++) {
      const char *modName = modNamePtrs[i];
      struct ModDesc *modP = Module_Lookup(modName);

      if (modP) {
         if (SystemLoadMod(optA, nrOpts, modP)) {
            err = -1;
            SystemPrintUsageForModule(modP->name);
            goto out;
         }

         if (modP->doneFn) {
#if DEBUG
            int argsLeft = argc-optind;
            ASSERT(argsLeft >= 0);
#endif
            if (modP->doneFn(argc-optind, &argv[optind])) {
               err = -1;
               SystemPrintUsageForModule(modP->name);
               goto out;
            }
         }
      } else {
         eprintf("unknown module %s\n", modName);
         err = -1;
         goto usage_out;
      }
   }

   /* XXX: eventually require neither module be loaded; that'll
    * be useful for measuring bare instrumentation costs. */
   if (!Module_IsLoaded(MODULE_PTR(Record)) && 
       !Module_IsLoaded(MODULE_PTR(Replay))) {
      FATAL("must select at least one of Record or Replay modules");
#if 0
      if (SystemLoadMod(optA, nrOpts, MODULE_PTR(Record))) {
         ASSERT_UNIMPLEMENTED(0);
      }
#endif
   }

   goto out;

usage_out:
   SystemPrintUsage();
out:
   free(optA);
   optA = NULL;

   return err;
}


void
System_PreInit()
{
   extern char** environ;

   ASSERT(current == &startupTask);

   /* ----- Init the startup task ----- */

   /* Lock routines use this (e.g., those invoked by
    * SharedArea_*), so we must init early. */
   current->realPid = gettid();

   /* ----- Setup basic facilities ------ */

   argc = *entryESP;
   argv = (char**)(entryESP+1);

   /* The AUXV comes after the environment variables. */
   evp = &argv[argc+1];
   environ = &argv[argc+1];

   while(*evp++ != (void*)0);

   auxV = (Elf32_auxv_t*) evp;


#define USE_SAFE_MALLOC 0
#define SHAREDAREA_SIZE (__SHAREDAREA_HEAP_END - __SHAREDAREA_HEAP_START)
   ASSERT(SHAREDAREA_SIZE > 0);
   DEBUG_MSG(7, "SHAREDAREA_SIZE=%d\n", SHAREDAREA_SIZE);

   SharedArea_Init(SHAREDAREA_SIZE, USE_SAFE_MALLOC);
   isSharedAreaInitialized = 1;

   if (SystemParseOptions(argc, argv)) {
      exit(-1);
   }

   /* ----- Init the init task ----- */

   memset(&initTask.stack.un, 0, sizeof(initTask.stack.un));
   LibVEX_GuestX86_initialise(&initTask.stack.un.arch.vex);
}


static void
StatsDoLog()
{
   int i, j;
   u64 aggStats[MAX_ENTRY_TYPES] = { 0 };
   //u64 summaryStats[5] = { 0 };
   u64 totalBytes = 0;

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpu = VCPU_Ptr(i);
      u64 *stats = vcpu->replayLog.stats;

      for (j = 0; j < MAX_ENTRY_TYPES; j++) {
         aggStats[j] += stats[j];
      }
   }

   STATS_MSG("Aggregate VCPU log stats:\n");
   for (i = 0; i < MAX_ENTRY_TYPES; i++) {
      if (strlen(entryId2Str[i]) > 0) {
         STATS_MSG("%3d. %16.16s --> %llu\n", i, entryId2Str[i], aggStats[i]);
      }

      totalBytes += aggStats[i];
   }

   STATS_MSG("Total bytes: %llu\n", totalBytes);
}

static void
StatsOnShutdown()
{
   STATS_MSG("total time: %lu s %lu us\n",
         STATS_ELAPSED_SEC(totalTime), STATS_ELAPSED_USEC(totalTime));

   StatsDoLog();
}

extern finicall_t __finicall_start[], __finicall_end[];

static void
FiniDoCalls()
{
   finicall_t *call;

   for (call = __finicall_start; call < __finicall_end; call++) {
      int res;

      res = (*call)();
   }
}

void
System_Shutdown()
{
   DEBUG_MSG(0, "System is going down.\n");

   Module_OnShutdown();

#if STATS
   StatsOnShutdown();
#endif

   FiniDoCalls();

   exit(0);
}
