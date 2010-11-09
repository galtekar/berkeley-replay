#include <vkernel/public.h>
#include "private.h"

#include <strings.h>

/* XXX: should be a module callback. */
void
ModRecord_OnFileOpen(struct FileStruct *filP)
{
   /* ----- Setup data-rate calculation vars ----- */

   TokenBucket_Init(&filP->classTB, session.optRecSpec);
}

int
ModRecord_Shutdown()
{
   int fd;

   DEBUG_MSG(5, "session.dir=%s\n", session.dir);
   ASSERT(strlen(session.dir));

   env.end_vclock = MAX(get_sys_micros(), curr_vcpu->vclock);
   ASSERT(env.end_vclock >= env.start_vclock);

   fd = ModSession_Open(session.dir, 1);
   if (fd >= 0) {
      int err;
      DEBUG_MSG(5, "environ=%s\n", env.envList);
      err = write(fd, &env, sizeof(env));
      ASSERT(err == sizeof(env));
      close(fd);
   } else {
      FATAL("error opening session file");
   }

   return 0;
}


int
ModRecord_Init()
{
   int isDefault = 0;

   if (!strlen(session.dir)) {
      ModSession_GetDefaultDir(session.dir, sizeof(session.dir));
      isDefault = 1;
   }

   //printf("session.dir=%s\n", session.dir);

   if (MiscOps_MakeDir(session.dir, 1, isDefault)) {
      FATAL("error making session dir '%s'", session.dir);
   }

   //eprintf("starting recording %s\n", session.dir); 
   ModHistory_Append(session.dir);

   env.start_vclock = get_sys_micros();

   return 0;
}

enum { Opt_RecDir, Opt_RecTarget, Opt_RecMaxRate, Opt_RecMaxBurst };

static int
ModParseOpt(int opt, const char *arg)
{
   //printf("opt=%d arg=%s (%d)\n", opt, arg, strlen(arg));
   switch (opt) {
   case Opt_RecDir:
      strncpy(session.dir, arg, sizeof(session.dir));
      break;
   case Opt_RecTarget:
      strncpy(env.argList, arg, sizeof(env.argList));
      env.argListLen = strlen(arg) + 1;
      break;
   case Opt_RecMaxRate:
      session.optRecSpec.rate = Arg_ParseLong(arg);
      break;
   case Opt_RecMaxBurst:
      session.optRecSpec.size = Arg_ParseLong(arg);
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

   VCPU_SetModeFlag(VCPU_MODE_LOG);

   if (argc) {
      DEBUG_MSG(7, "argc=%d\n", argc);
      env.argListLen = sizeof(env.argList);
      err = MiscOps_SaveArgv(env.argList, &env.argListLen, argv, 
            &env.argListCount);
      ASSERT(!err);
   } else {
      ASSERT(strlen(env.argList));
   }

#if 0
   if (env.recTokenBucketSize < env.recTokenBucketRate) {
      FATAL("bucket size must be greater than or equal to token fill rate\n");
   }
#endif

   if (session.optRecSpec.size == -1) {
      session.optRecSpec.size = MIN(LONG_MAX, (ullong)session.optRecSpec.rate*10);
   }

   session.optRecSpec.size = MAX(session.optRecSpec.size, 
         session.optRecSpec.rate);

   return err;
}

static struct ModOpt optA[] = {
   [Opt_RecDir] = { "Record.Dir", ModParseOpt, Opk_Str, "",
      "Directory to save/restore recordings" },

   [Opt_RecTarget] = { "Record.Target", ModParseOpt, Opk_Str, "/bin/sh",
      "Program to record" },

   [Opt_RecMaxRate] = { "Record.MaxRate", ModParseOpt, Opk_Int, "100000",
      "Maximum recording rate (Bps)" },

   [Opt_RecMaxBurst] = { "Record.MaxBurst", ModParseOpt, Opk_Int, "-1",
      "Maximum tolerated burst (i.e., size of token bucket) (Bytes)" },


   { "", NULL, Opk_Bool, "", "" },
};

extern struct ModDesc MODULE_VAR(Base);
extern struct ModDesc MODULE_VAR(Replay);

static struct ModDesc *depA[] = { &MODULE_VAR(Base), NULL };
static struct ModDesc *confA[] = { &MODULE_VAR(Replay), NULL };

MODULE_BASIC(
      Record,
      "Records a program run",
      depA,
      confA,
      optA,
      ModParseDone);
