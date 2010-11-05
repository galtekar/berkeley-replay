#include <python2.6/Python.h>
#include "private.h"

#include <sys/syscall.h>
#include <errno.h>

static pid_t gdbPid = -1;
static void* childPlayP = NULL;
static struct siginfo lastSigInfo;

#define ROFF(r) offsetof(struct user_regs_struct, r)

#if DEBUG
static const char *
PtraceReqToStr(enum __ptrace_request req) {
#define STR(r) case r: return #r
   switch (req) {
      STR(PTRACE_TRACEME);
      STR(PTRACE_PEEKTEXT);
      STR(PTRACE_PEEKDATA);
      STR(PTRACE_PEEKUSER);
      STR(PTRACE_POKETEXT);
      STR(PTRACE_POKEDATA);
      STR(PTRACE_POKEUSER);
      STR(PTRACE_CONT);
      STR(PTRACE_KILL);
      STR(PTRACE_SINGLESTEP);
      STR(PTRACE_ATTACH);
      STR(PTRACE_DETACH);
      STR(PTRACE_SYSCALL);
      STR(PTRACE_SETOPTIONS);
      STR(PTRACE_GETEVENTMSG);
      STR(PTRACE_GETSIGINFO);
      STR(PTRACE_SETSIGINFO);
      STR(PTRACE_GETREGS);
      STR(PTRACE_SETREGS);
      STR(PTRACE_GETFPREGS);
      STR(PTRACE_SETFPREGS);
   default:
      ASSERT_MSG(0, "req=%d", req);
      break;
   };
#undef STR

   return NULL;
}
#endif

int
PtrEmu_Attach(pid_t pid, long *eaxP)
{
   if (!BDR_Open(pid)) {
      /* Not a BDR task. */
      DEBUG_MSG(2, "Pid %d is not a BDR task\n", pid);
      return 0;
   }

   *eaxP = 0;

   return 1;
}

int
PtrEmu_Detach(BDR *bdrP)
{
   BDR_Close(bdrP);

   return 0;
}

int
PtrEmu_Resume(BDR *bdrP, enum __ptrace_request req, long sig)
{
   DEBUG_MSG(2, "Resume: ss=%d sig=%d\n", req == PTRACE_SINGLESTEP, sig);

   ASSERT_UNIMPLEMENTED(sig == 0);

   if (req == PTRACE_SINGLESTEP) {
#if 0
      long val;
      if (BDR_GetReg(bdrP, &val, ROFF(eip)) != sizeof(val)) {
         ASSERT_UNIMPLEMENTED(0);
      }

      DEBUG_MSG(2, "eip=0x%lx\n", val);
#else
#endif
   }

   BDR_Resume(bdrP, req, sig);

   return 0;
}

int
PtrEmu_GetSigInfo(const BDR *bdrP, struct siginfo __child *siP)
{
   ASSERT(bdrP);
   ASSERT_UNIMPLEMENTED(siP);

   copy_to_child(gdbPid, siP, &lastSigInfo, sizeof(*siP));

   return 0;
}


int
PtrEmu_GetRegs(const BDR *bdrP, struct user_regs_struct __child *uregsP)
{
   struct user_regs_struct uregs;

   BDR_GetRegs(bdrP, (char*)&uregs, 0, sizeof(*uregsP));

   copy_to_child(gdbPid, uregsP, &uregs, sizeof(*uregsP));

   return 0;
}

int
PtrEmu_PeekUsr(const BDR *bdrP, long addr, long data)
{
   int err = 0;
   long val = 0;

   if ((addr & (sizeof(data) - 1)) || addr < 0 ||
         (ulong)addr >= sizeof(struct user)) {
      err = -EIO;
      goto out;
   }


   if ((ulong)addr < sizeof(struct user_regs_struct)) {
      /* Trying to access a register. */
      if (BDR_GetRegs(bdrP, (char*)&val, addr, sizeof(val))) {
         ASSERT_UNIMPLEMENTED(0);
      }
   } else if ((ulong)addr >= offsetof(struct user, u_debugreg[0]) &&
         (ulong)addr <= offsetof(struct user, u_debugreg[7])) {
      /* XXX: Accessing a debug register. 
       * These registers can never be symbolic, so return their real
       * value. But how do we do that if we're not ptrace-attached to
       * the child? For now assume the real val is 0. 
       *
       *
       * XXX: why not return -EIO instead, so that GDB invariants aren't
       * violated? */
      DEBUG_MSG(2, "reading debug regs unimplemented.\n");
      //ASSERT_UNIMPLEMENTED(0);
   } else {
      /* Any other location returns 0. */
   }
   
   copy_to_child(gdbPid, (long __child *)data, &val, sizeof(val));

out:
   return err;
}

int
PtrEmu_PeekMem(const BDR *bdrP, ulong addr, long __child *udataP)
{
   int err = -EIO;
   long val;
   size_t len = sizeof(val);


   if (!BDR_ReadMem(bdrP, (char*)&val, addr, len)) {
      DEBUG_MSG(2, "val=0x%lx\n", val);
      /* XXX: copy_to_child may fail... */
      copy_to_child(gdbPid, udataP, &val, len);
      err = 0;
   }

   return err;
}

static INLINE int
differsByByte(long a, long b, long val, int *offP)
{
   uint i;

   for (i = 0; i < sizeof(a); i++) {
      long ideal = ((a & ~(0xFF << i*8)) | (val << i*8));
      DEBUG_MSG(2, "a=0x%lx b=0x%lx ideal=0x%lx\n", a, b, ideal);
      if ((a ^ b) == (a ^ ideal))  {
         *offP = i;
         return 1;
      }
   }

   return 0;
}

/* XXX: we need a more reliable way of detecting breakpoint requests.
 * Would check that the writes are to the text segment suffice? */
int
PtrEmu_PokeMem(const BDR *bdrP, ulong addr, long data)
{
   int err = -EIO;
   long old;
   size_t len = sizeof(old);
   ulong brkptAddr = 0;
   int off = 0;

   if ((err = BDR_ReadMem(bdrP, (char*)&old, addr, len))) {
      goto out;
   }

   DEBUG_MSG(3, "old=0x%lx new=0x%lx\n", old, data);


   if (old ^ data) {
      if (differsByByte(old, data, 0xCC, &off)) {
         brkptAddr = addr + off;

         DEBUG_MSG(3, "SET Brkpt\n");

         if (BDR_SetBrkpt(bdrP, brkptAddr)) {
            /* Success. */
            err = 0;
         }
      } else {
         //ASSERT_UNIMPLEMENTED(0);
         
         /* GDB tries to write something into pthreads apps. Pretend
          * like it succeeded. */
         err = 0;
      }
   } else {
      DEBUG_MSG(3, "RM Brkpt\n");

      err = 0;
      int numRemoved = 0;
      for (brkptAddr = addr; brkptAddr < addr+sizeof(data); brkptAddr++) {
         numRemoved += (BDR_RmBrkpt(bdrP, brkptAddr) != 0);
      }
      /* XXX: is it an error if none are removed? */
   }

out:
   return err;
}

int
SysEmuPtrace(struct user_regs_struct *regsP, enum __ptrace_request req, 
      pid_t pid, void __child *addrP, void __child *dataP)
{
   int isEmu = 1;

   long *eaxP = &regsP->eax;

   DEBUG_MSG(2, "[0x%lx] ptrace call: req=%s pid=%d addr=%p data=%p\n",
         regsP->eip, PtraceReqToStr(req), pid, addrP, dataP);

   if (req == PTRACE_ATTACH) {
      if (!PtrEmu_Attach(pid, eaxP)) {
         isEmu = 0;
         goto out;
      }
   } else {
      BDR *bdrP;

      if (!(bdrP = BDR_Lookup(pid))) {
         /* Not a BDR task, or not attached. */
         isEmu = 0;
         goto out;
      }

      switch (req) {
      case PTRACE_DETACH:
         *eaxP = PtrEmu_Detach(bdrP);
         break;
      case PTRACE_CONT:
      case PTRACE_SINGLESTEP:
         *eaxP = PtrEmu_Resume(bdrP, req, (long)dataP);
         break;
      case PTRACE_GETREGS:
         *eaxP = PtrEmu_GetRegs(bdrP, (struct user_regs_struct __child *)dataP);
         break;
      case PTRACE_SETOPTIONS:
         /* XXX: we need notification on vfork/clone/exec/exit. */
         *eaxP = 0;
         break;
      case PTRACE_GETEVENTMSG:
         ASSERT_UNIMPLEMENTED(0);
         break;
      case PTRACE_GETSIGINFO:
         *eaxP = PtrEmu_GetSigInfo(bdrP, (struct siginfo __child *)dataP);
         break;
      case PTRACE_SETSIGINFO:
         ASSERT_UNIMPLEMENTED(0);
         break;
      case PTRACE_PEEKUSER:
         *eaxP = PtrEmu_PeekUsr(bdrP, (long)addrP, (long)dataP);
         break;
      case PTRACE_PEEKTEXT:
      case PTRACE_PEEKDATA:
         /* XXX: state may be read through /proc/%d/mem for long words */
         *eaxP = PtrEmu_PeekMem(bdrP, (ulong)addrP, (long*)dataP);
         break;
      case PTRACE_POKETEXT:
      case PTRACE_POKEDATA:
         *eaxP = PtrEmu_PokeMem(bdrP, (ulong)addrP, (long)dataP);
         break;
#if 0
      case PTRACE_POKEUSER:
         break;
      case PTRACE_GETFPREGS:
         break;
#endif
      default:
         ASSERT_UNIMPLEMENTED(0);
         break;
      }
   }

out:
   DEBUG_MSG(2, "isEmu=%d eax=0x%lx\n", isEmu, *eaxP);
   return isEmu;
}

static int
SysEmuWaitPid(struct user_regs_struct *regsP, pid_t pid, int __child *statusP, int options)
{
#define WAIT_STOPPED 0x7f
#define WAIT_SIGSHIFT 8
   int isEmu = 1;
   long *eaxP = &regsP->eax;
   BDR *bdrP = NULL;
   VKDbgEvent ev;
   pid_t resPid;

   DEBUG_MSG(2, "waitpid: pid=%d nohang=%d\n", pid, options & WNOHANG);

   ASSERT_UNIMPLEMENTED(pid == -1 || pid > 0);
   if (pid != -1 && !(bdrP = BDR_Lookup(pid))) {
      isEmu = 0;
      goto out;
   }

   *eaxP = 0;

   if ((resPid = BDR_WaitForEvent(bdrP, &ev, !(options & WNOHANG)))) {
      int statVal = 0;

      DEBUG_MSG(2, "got event %s\n", VK_DbgEventToStr(ev));
      switch (ev) {
      case Dek_AttachSuccess:
         statVal = (SIGSTOP << WAIT_SIGSHIFT) | WAIT_STOPPED;
         break;
      case Dek_BrkptHit:
         statVal = (SIGTRAP << WAIT_SIGSHIFT) | WAIT_STOPPED;
         memset(&lastSigInfo, 0, sizeof(lastSigInfo));
         /* XXX: fill in the remaining siginfo: look in linux/kernel/signal.c
          * for more info on what should go in. */
         lastSigInfo.si_signo = SIGTRAP;
         lastSigInfo.si_pid = resPid;
         break;
      default:
         ASSERT_UNIMPLEMENTED(0);
         break;
      }

      if (statusP) {
         copy_to_child(gdbPid, statusP, &statVal, sizeof(*statusP));
      }
      *eaxP = resPid;
   }

out:
   DEBUG_MSG(2, "isEmu=%d res=%d\n", isEmu, *eaxP);
   return isEmu;
}

static pid_t
IsProcFile(const char *strP, const char *nameP)
{
   char nameBuf[256];
   pid_t pid;

   if (sscanf(strP, "/proc/%d/%s", &pid, nameBuf) == 2) {
      if (strcmp(nameBuf, nameP) == 0) {
         return pid;
      }
   }

   return 0;
}

static int
SysEmuReadLink(long *eaxP, const char __child *chPathP, char __child *chBufP, 
               int bufsiz)
{
   int isEmu = 0;
   pid_t pid;
   char *tmpPath = (char*)malloc(PATH_MAX);
   char *exePath = (char*)malloc(PATH_MAX);
   int len = 0;

   strncpy_from_child(gdbPid, tmpPath, chPathP, PATH_MAX);

   if ((pid = IsProcFile(tmpPath, "exe"))) {
      snprintf(tmpPath, PATH_MAX, "%s/%d/exe", VK_PROC_DIR, pid);

      len = readlink(tmpPath, exePath, PATH_MAX);
   }

   if (len > 0) {
      /* readlink does not append a null-byte. */
      ASSERT_UNIMPLEMENTED(bufsiz >= 0);
      len = MIN(len, bufsiz);
      copy_to_child(gdbPid, chBufP, exePath, len);

      *eaxP = len;
      isEmu = 1;
   }

   free(tmpPath);
   tmpPath = NULL;
   free(exePath);
   exePath = NULL;

   return isEmu;
}

#if 0
static int
SysEmuSigSuspendIn(struct user_regs_struct *regsP, sigset_t *newP, 
                   size_t setsize)
{

   /* Execute the sigsuspend. */
   return 0;
}

static void
SysEmuSigSuspendOut()
{
   BDR_MakeAllSync();
}
#endif

/* 
 * Have child execute syscall no matter what; but if the target is a
 * BDR task, then open the BDR auxv. 
 */
static int
SysEmuOpen(struct user_regs_struct *regsP, const char __child *path, 
           int flags, int mode)
{
   pid_t pid;
   char *tmpPath = (char*)malloc(PATH_MAX);

   strncpy_from_child(gdbPid, tmpPath, path, PATH_MAX);

   DEBUG_MSG(2, "Opening %s\n", tmpPath);

   if ((pid = IsProcFile(tmpPath, "auxv"))) {
      snprintf(tmpPath, PATH_MAX, "%s/%d/auxv", VK_PROC_DIR, pid);

      if (!access(tmpPath, R_OK)) {
         /* Make the kernel use BDR's auxv. */
         DEBUG_MSG(2, "Opening auxv for BDR pid %d\n", pid);
         ASSERT(childPlayP);
         ASSERT_UNIMPLEMENTED((size_t)strlen(tmpPath)+1 <= (size_t)PAGE_SIZE);
         copy_to_child(gdbPid, childPlayP, tmpPath, PAGE_SIZE);
         regsP->ebx = (long)childPlayP;
      }
   } else if (IsProcFile(tmpPath, "mem")) {
      /* Don't want GDB to access child mem through /proc/%d/mem
       * because (1) we don't yet interecept those reads, and (2) it can't
       * access proc unless its ptrace attached. */
      regsP->eax = -ENOENT;
   }

   free(tmpPath);
   tmpPath = NULL;

   return 0;
}

int
HandleSysEnter(struct user_regs_struct *rP)
{
   int isEmu = 0;

   DEBUG_MSG(2, "syscall=%s\n", get_syscall_name(rP->orig_eax));

   long arg[6] = { rP->ebx, rP->ecx, rP->edx, rP->esi, rP->edi, rP->ebp };

   switch (rP->orig_eax) {
   case SYS_ptrace:
      isEmu = SysEmuPtrace(rP, (enum __ptrace_request) rP->ebx, 
            rP->ecx, (void*) rP->edx, (void*) rP->esi);
      break;
   case SYS_waitpid:
      isEmu = SysEmuWaitPid(rP, rP->ebx, (int*)rP->ecx, rP->edx);
      break;
   case SYS_waitid:
   case SYS_wait4:
      ASSERT_UNIMPLEMENTED(0);
      break;
   case SYS_readlink:
      isEmu = SysEmuReadLink(&rP->eax, (const char *)arg[0], (char*)arg[1], arg[2]);
      break;
   case SYS_readlinkat:
      ASSERT_UNIMPLEMENTED(0);
      break;
   case SYS_open:
      isEmu = SysEmuOpen(rP, (const char*)arg[0], arg[1], arg[2]);
      break;
   case SYS_openat:
      ASSERT_UNIMPLEMENTED(0);
      break;
#if 0
      /* XXX: don't think we need to intercept these... */
   case SYS_rt_sigsuspend:
      isEmu = SysEmuSigSuspend(rP, (sigset_t *)arg[0], (size_t)arg[1]);
      break;
   case SYS_sigsuspend:
      ASSERT_UNIMPLEMENTED(0);
      break;
#endif
   default:
      break;
   }

   return isEmu;
}

void
HandleSysExit(int wasEmu, struct user_regs_struct *regsP)
{
   switch (regsP->orig_eax) {
#if 0
   case SYS_rt_sigsuspend:
   case SYS_sigsuspend:
#endif
   case SYS_ptrace:
   case SYS_waitpid:
   case SYS_waitid:
   case SYS_wait4:
#if 0
      printf("[0x%lx] sysno=%s isEmu=%d eax=0x%lx ebx=0x%lx "
             "ecx=0x%lx edx=0x%lx\n",
            GET_REG(gdbPid, eip),
            get_syscall_name(regsP->orig_eax),
            wasEmu,
            GET_REG(gdbPid, eax),
            GET_REG(gdbPid, ebx),
            GET_REG(gdbPid, ecx),
            GET_REG(gdbPid, edx)
            );
#endif
      break;
   default:
      break;
   }
}

static void
HandleTrap(const int trapCount)
{
   if (trapCount == 0) {
      /* Trap for some other reason. */
      Ptrace(PTRACE_SETOPTIONS, gdbPid, NULL, 
            (void*)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT));

      /* Setup the playground segment. */
      childPlayP = (void*)make_child_playground(gdbPid, (void*)GET_REG(gdbPid, eip));
      DEBUG_MSG(2, "Mmapped child playground at %p.\n", childPlayP);
   } else {
   }
}

void 
PrintUsage(int argc, char** argv) {
   printf("DCR Ptrace Stub\n");
   printf("usage: %s [executable]\n", argv[0]);
}

/*
 * GDB waits in a sigreturn for its child to stop (which will result in
 * a SIGCHLD sent to GDB). We need to emulate that behavior and
 * synthesize a SIGCHLD for GDB. 
 */
static void
OnSigIOCb(int sig, siginfo_t *siP, void *ucP)
{
   DEBUG_ONLY(int fd = siP->si_fd;)

   DEBUG_MSG(2, "sig=%d fd=%d code=%d\n", sig, fd, siP->si_code);
   ASSERT(sig == SIGIO);

   extern int BDR_IsMsgPending();
   if (BDR_IsMsgPending()) {
      ASSERT(gdbPid > 0);
      kill(gdbPid, SIGCHLD);
   }

   DEBUG_MSG(2, "done\n");

#if 0
   /* 
    * xXX: For some reason, si_code is 128....should be between 1 and 6
    */
   switch (siP->si_code) {
   case POLL_IN:
   case POLL_PRI:
   case POLL_MSG:
      {
      }
      break;
   case POLL_OUT:
      ASSERT_UNIMPLEMENTED(0);
      break;
   case POLL_ERR:
      ASSERT_UNIMPLEMENTED(0);
      break;
   case POLL_HUP:
      ASSERT_UNIMPLEMENTED(0);
      break;
   default:
      //ASSERT_UNIMPLEMENTED(0);
      break;
   }
#endif
}

static int trapCount = 0, isSysEnter = 1;
static int wasEmu = -1;

static void
EnterTraceLoop()
{
   /* ----- Wait for child to deliver messages. ----- */
   pid_t pid;
   sigset_t set, oset;

   sigemptyset(&set);
   sigaddset(&set, SIGIO);

   while (1) {
      int status = 0;

      pid = waitpid(gdbPid, &status, __WALL);
      if (pid < 0) {
         continue;
      } else if (pid == 0) {
         ASSERT(0);
      }

      ASSERT(pid == gdbPid);

      /* Don't want the I/O handler to fire when we're talking to
       * BDR in the debug loop. */
      sigprocmask(SIG_BLOCK, &set, &oset);

      ulong data = 0;

      if (WIFEXITED(status)) {
         DEBUG_MSG(2, "child has exited\n");
         break;
      } else if (WIFSIGNALED(status) || WIFSTOPPED(status)) {
         if (WIFSIGNALED(status)) {
            DEBUG_MSG(2, "child was signalled with %d\n", WTERMSIG(status));
         } else if (WIFSTOPPED(status)) {
            DEBUG_MSG(5, "stopped\n");
            switch (WSTOPSIG(status)) {
            case SIGTRAP:
               HandleTrap(trapCount);
               trapCount++;
               break;
            case (SIGTRAP | 0x80):
               {
                  struct user_regs_struct regs;

                  if (isSysEnter) {
                     save_gregs(gdbPid, &regs);

                     wasEmu = HandleSysEnter(&regs);
                     ASSERT(wasEmu == 0 || wasEmu == 1);
                     //printf("wasEmu=%d\n", wasEmu);

                     if (wasEmu) {
                        /* Syscall is emulated, skip it; can't use
                         * SYSEMU, since that skips all syscalls; so
                         * just do a dummy invocation of getpid instead. */
                        SET_REG(gdbPid, orig_eax, SYS_getpid);
                     } else {
                        /* We may have changed the syscall argument;
                         * make sure the child sees the updated vals. */
                        restore_gregs(gdbPid, &regs);
                     }
                  } else {
                     /* SysExit */
                     ASSERT(wasEmu == 0 || wasEmu == 1);

                     if (wasEmu) {
                        /* Use the emulated results. */
                        restore_gregs(gdbPid, &regs);
                     }

                     HandleSysExit(wasEmu, &regs);

                     wasEmu = -1;
                  }

                  /* Will get called on syscall entrance and exit. 
                   * Which one is this? */
                  isSysEnter ^= 1;
               }
               break;
            case (SIGTRAP | (PTRACE_EVENT_EXIT << 8)):
               DEBUG_MSG(2, "childing exiting\n");
               break;
            default:
               DEBUG_MSG(2, "stopped by signal %d\n",
                     WSTOPSIG(status));
               data = WSTOPSIG(status);
               break;
            }
         }

         Ptrace(PTRACE_SYSCALL, gdbPid, NULL, (void*)data);
      } else {
         DEBUG_MSG(2, "some other reason\n");
         ASSERT(0);
      }
      
      sigprocmask(SIG_SETMASK, &oset, NULL);
   }
}

#if 0
int
main(int argc, char **argv)
{

   if (argc < 2) {
      PrintUsage(argc, argv);
      exit(-1);
   }

   Debug_Init("dbg.log", NULL, DEBUG_VERBOSE);
   debug_level = 3;

   BDR_Init();

   /* ----- Prep the child for tracing ----- */

   char *exeFilename = argv[1];

   if (!(gdbPid = fork())) {
      Ptrace(PTRACE_TRACEME, 0, 0, 0);
      if (execvp(exeFilename, &argv[1]) == -1) {
         FATAL("execve failed for '%s'\n", argv[3]);
      }
   }

   /* ----- Initialize ----- */

   close(0);


   /* Don't want to die when we ctrl+c/q GDB. */
   signal(SIGINT, SIG_IGN);
   signal(SIGQUIT, SIG_IGN);
   struct sigaction sa;
   memset(&sa, 0, sizeof(sa));
   sa.sa_sigaction = &OnSigIOCb;
   sa.sa_flags = SA_SIGINFO;
   sigaction(SIGIO, &sa, NULL);

   EnterTraceLoop();

   DEBUG_MSG(2, "Program terminated.\n");
   Debug_Exit();

   return 0;
}
#endif

static PyMethodDef StubMethods[] = {
#if 0
   { "pack", py_pack, METH_VARARGS, "Packs a message." },
   { "unpack", py_unpack, METH_VARARGS, "Unpacks a message." },
#endif

   { NULL, NULL, 0, NULL }
};

static void
PyDefInt(PyObject *m, const char *name, int val)
{
   PyObject *tmp, *d;
   d = PyModule_GetDict(m);

   tmp = PyInt_FromLong(val);
   PyDict_SetItemString(d, name, tmp);
   Py_DECREF(tmp);
}

PyMODINIT_FUNC
initmsg_stub(void)
{
   PyObject *m;

   m = Py_InitModule("ptrace", StubMethods);
}
