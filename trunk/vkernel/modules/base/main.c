#include "vkernel/public.h"

#include "private.h"

/* XXX: rename to "struct Options" */
struct Session session = {
   .dir         = "",
   .tty_name     = ""
};

/* XXX: rename to "struct Session" */
struct Environment env = {
   .flags = 0,
   .recorded_bytes = 0,
   .is_value_det = 1,
   .start_vclock = 0,
   .end_vclock = 0,
};

#if 0
static void
BaseLink(const char *oldP, const char *nameP)
{
   int res;
   DECL_LINK_PATH(nameP);

   res = symlink(oldP, ssnLink);
   ASSERT(res == 0);
}

void
Base_Unlink(const char *nameP)
{
   int res;
   DECL_LINK_PATH(nameP);

   res = unlink(ssnLink);
   ASSERT(res == 0 || res != 0);
}

static void
BaseLinkExe()
{
   ASSERT_KPTR(current->procExe);
   struct InodeStruct *inodP = Dentry_Inode(current->procExe);
   const char *exeLink = inodP->data;
   ASSERT_KPTR(exeLink);
   BaseLink(exeLink, "exe");
}

static void
BaseLinkAuxv()
{
   int res, fd;
   DECL_LINK_PATH("auxv");

   ASSERT_KPTR(current->saved_auxv);

   fd = open(ssnLink, O_RDWR | O_CREAT | O_EXCL, S_IRUSR);
   ASSERT_UNIMPLEMENTED(fd >= 0);

   size_t len = sizeof(current->saved_auxv);
   ASSERT(len == sizeof(ulong)*AT_VECTOR_SIZE);
   res = write(fd, current->saved_auxv, len);
   ASSERT_UNIMPLEMENTED(res == len);

   res = close(fd);
   ASSERT_UNIMPLEMENTED(res == 0);
}

static void
BaseOnTaskStart()
{
   char ssnProcDir[256];

   snprintf(ssnProcDir, sizeof(ssnProcDir), "%s/%d",
         VK_PROC_DIR, current->realPid);

   if (MiscOps_MakeDir(ssnProcDir, 1, 0)) {
      FATAL("error making session entry");
   }

   BaseLink(session.dir, "session");

   if (current != &initTask) {
      BaseLinkExe();
      BaseLinkAuxv();
   } else {
      /* Init will link his on exec. */
   } 

#if 0
   Server_OnTaskStart();
#endif
}

static void
BaseOnTaskTerm()
{
   int res;
   char ssnProcDir[256];

   snprintf(ssnProcDir, sizeof(ssnProcDir), "%s/%d",
         VK_PROC_DIR, current->realPid);

   Base_Unlink("session");
   Base_Unlink("exe");
   Base_Unlink("auxv");

   res = rmdir(ssnProcDir);
   //ASSERT(res == 0);
   
#if 0
   Server_OnTaskTerm();
#endif
}

static void
BaseOnTaskExec()
{
   /* Executable has changed; refresh the vk-proc entry. */
   Base_Unlink("exe");
   BaseLinkExe();

   Base_Unlink("auxv");
   BaseLinkAuxv();

#if 0
   Server_OnExec();
#endif
} 
#endif

static void
BaseOnShutdown()
{
   if (VCPU_IsLogging()) {

      int i;
      for (i = 0; i < NR_VCPU; i++) {
         struct VCPU *vP = VCPU_Ptr(i); 

         env.recorded_bytes += vP->replayLog.size;
      }

      ModRecord_Shutdown();
   } 

   Server_Shutdown();
}

static struct Module mod = {
   .name          = "Session",
   .modeFlags     = 0xFFFFFFFF,
   .onStartFn     = Server_OnTaskStart,
   .onTermFn      = Server_OnTaskExit,
   .onPreSysFn    = Server_OnPreSyscall,
   .onPostSysFn   = Server_OnPostSyscall,
   .onFileEventFn = Server_OnFileEvent,
   .onShutdownFn  = BaseOnShutdown,
   .onResumeUserFn = Server_OnResumeUser,
   .order     = MODULE_ORDER_PRECORE,
};

static void 
BaseReadEnv() 
{
   Elf32_auxv_t *ap;


   /* Obtain the auxv from that linux gives to us. What we
    * end up using will be very similar, though not idential
    * (due to VDSO issues), to this. */
   ASSERT(auxV);
   ap = auxV;
   while (ap->a_type != AT_NULL) {
      DEBUG_MSG(8, "type=%d old=0x%x\n", ap->a_type, ap->a_un.a_val);

      env.auxv[ap->a_type] = ap->a_un.a_val;

      switch (ap->a_type) {
      case AT_PLATFORM:
         strncpy(env.platform, (char*)ap->a_un.a_val, MAX_PLATFORM_LEN);
         DEBUG_MSG(8, "platform=%s\n", env.platform);
         break;
      default:
         break;
      }

      ap++;
   }

   /* Obtain the environment that linux gives us. The user may, at his
    * option, choose to ignore this environment. */
   ASSERT(environ);
   env.envListLen = sizeof(env.envList);
   int err = MiscOps_SaveArgv(env.envList, &env.envListLen, environ, 
                              &env.envListCount);
   ASSERT(!err);
   err = err;
}

/*
 * Make sure address-space randomization is turned off. 
 * XXX: vkernel crashes if this is turned on and the original 
 * environment (auxv, cmdline, etc.) is restored. */
static void
BaseDoChecks()
{
   int oldval = 0;
   size_t oldlen = sizeof(oldval);
   int name[] = {1, 68} /* kern randomize */;
   int err;

   struct __sysctl_args args = { 
      .name = name, 
      .nlen = 2,
      .oldval = &oldval,
      .oldlenp = &oldlen,
      .newval = 0,
      .newlen = 0,
   };

   err = syscall(SYS__sysctl, &args);
   
   if (!err) {
      if (oldval != 0) {
         FATAL("address-space randomization must be turned off\n");
      }
   } else {
      FATAL("can't tell if randomization is on or not.\n");
   }
}

static int
BaseInit()
{
   BaseDoChecks();
   BaseReadEnv();

   Module_Register(&mod);

   /* XXX: change to "InitSessionDir" */
   if (VCPU_IsLogging()) {
      ModRecord_Init();
   } else if (VCPU_IsReplaying()) {
      ModReplay_Init();
   } else {
      ASSERT_UNIMPLEMENTED(0);
   }

   Server_Init();

   return 0;
}


enum { Opt_EnvInherit, Opt_DbgLvl, Opt_DbgPause,
   Opt_ClassRate, Opt_ClassBurst, Opt_ClassUseAnnotations, Opt_TtyName,
   Opt_CtrlHost, Opt_CtrlPort, Opt_DE_Enabled, Opt_IpcTags_Enabled, Opt_TtyOutOnReplay, Opt_TtyReplay_Enabled};

static int
ParseOpt(int opt, const char *arg)
{
   switch (opt) {
   case Opt_EnvInherit:
      if (Arg_ParseBool(arg)) {
         env.flags |= ENV_SHOULD_INHERIT;
      } else {
         env.flags &= ~ENV_SHOULD_INHERIT;
      }
      break;
   case Opt_DbgLvl:
      debug_level = atoi(arg);
      if (debug_level < 0 || debug_level > 100) {
         return 1;
      }
      break;
   case Opt_DbgPause:
      dbgPauseOnAbort = Arg_ParseBool(arg);
      break;
   case Opt_ClassRate:
      session.optClassSpec.rate = Arg_ParseLong(arg);
      break;
   case Opt_ClassBurst:
      session.optClassSpec.size = Arg_ParseLong(arg);
      break;
   case Opt_ClassUseAnnotations:
      session.optUseAnnotations = Arg_ParseBool(arg);
      break;
   case Opt_TtyName:
      strncpy(session.tty_name, arg, MAX_TTYNAME);
      break;
   case Opt_CtrlHost:
      strncpy(session.ctrl_host, arg, sizeof(session.ctrl_host));
      break;
   case Opt_CtrlPort:
      // string because could be a unix domain path
      strncpy(session.ctrl_port, arg, sizeof(session.ctrl_port));
      break;
   case Opt_DE_Enabled:
      // XXX: vcpuMode should really be moved into struct Session
      // and renamed to session_mode
      if (Arg_ParseBool(arg)) {
         vcpuMode |= VCPU_MODE_DE_ENABLED;
      } else {
         vcpuMode &= ~(VCPU_MODE_DE_ENABLED);
      }
      break;
   case Opt_IpcTags_Enabled:
      session.opt_enable_ipc_tagging = Arg_ParseBool(arg);
      break;
   case Opt_TtyReplay_Enabled:
      session.opt_tty_replay = Arg_ParseBool(arg);
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   };

   return 0;
}

static int
ModParseDone(const int argc, char **argv)
{
   int err = 0;

   if (session.optClassSpec.size == -1) {
      session.optClassSpec.size = MIN(LONG_MAX, 
            (ullong)session.optClassSpec.rate*10);
   }
   session.optClassSpec.size = MAX(session.optClassSpec.rate, 
         session.optClassSpec.size);
   return err;
}

static struct ModOpt optA[] = {

   [Opt_EnvInherit] = { "Base.Env.Inherit", ParseOpt, Opk_Bool, "1",
      "Inherit environment variables from parent shell" },

   [Opt_DbgLvl] = { "Base.Debug.Level", ParseOpt, Opk_Int, "0",
      "Default debugging level (max 10)" },

   [Opt_DbgPause] = { "Base.Debug.PauseOnAbort", ParseOpt, Opk_Bool, 
         "0",
      "Wait for debugger to attach on abort" },

   [Opt_ClassRate] = { "Base.Classifier.Rate", ParseOpt, Opk_Int, "max",
      "Maximum control plane channel data rate (Bps)" },

   [Opt_ClassBurst] = { "Base.Classifier.Burst", ParseOpt, Opk_Int, "-1",
      "Maximum control plane burst (Bytes)" },

   [Opt_ClassUseAnnotations] = { "Base.Classifier.UseAnnotations",
      ParseOpt, Opk_Bool, "0",
      "Use plane classification source-code annotations" },

   [Opt_TtyName] = { "Base.TtyName", ParseOpt, Opk_Str, "/dev/tty",
      "Tty to send recv I/O" },

   [Opt_CtrlHost] = { "Base.CtrlHost", ParseOpt, Opk_Str, "",
      "Hostname/address of global controller" },

   [Opt_CtrlPort] = { "Base.CtrlPort", ParseOpt, Opk_Str, "40070",
      "Port nubmer of controller" },

   [Opt_DE_Enabled] = { "Base.DirectExecutionEnabled", ParseOpt, Opk_Bool,
      "1", "Enable direct execution where its supported" },

   [Opt_IpcTags_Enabled] = { "Base.IpcTagsEnabled", ParseOpt, Opk_Bool,
      "1", "Enable IPC tags" },

   [Opt_TtyReplay_Enabled] = { "Base.TtyReplayEnabled", ParseOpt, Opk_Bool, "0", "Output to tty on replay" },

   { "", NULL, Opk_Bool, "", "" },
};

static struct ModDesc *depA[] = { NULL };
static struct ModDesc *confA[] = { NULL };

PRECORE_INITCALL(BaseInit);
MODULE_BASIC(
      Base,
      "Base system functionality",
      depA,
      confA,
      optA,
      ModParseDone);
