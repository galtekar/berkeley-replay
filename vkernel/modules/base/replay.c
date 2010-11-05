/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <vkernel/public.h>

#include "private.h"

#if 0
static void
ModReplayPrintUsage()
{
   printf("replay: Replays a previously recorded program run\n");
   printf("usage: replay [session-dir | index]\n"
          "  where session-dir is a directory containting the recording,\n"
          "  and index is a history index (see 'history' subcommand).\n"
          "\n"
          "  If no session-dir or index is specified, then the most\n"
          "  recent recording, if any, will be replayed.\n\n"
         );

   printf("  -o,--overwrite        Overwrite existing debug logfiles if needed\n"
          "  -t,--tty=TTY          Dump output to device TTY (e.g., /dev/tty1)\n");
}

static int
ModReplayParseOptions(int argc, char ** argv)
{
   int c, err = 0;

   VCPU_SetModeFlag(VCPU_MODE_REPLAY);

   while (1) {
      int option_index = 0;
      static struct option long_options[] = {
         {"overwrite", 0, NULL, 'o'},
         {"tty", 1, NULL, 't'},
         {0, 0, NULL, 0}
      };
      c = getopt_long(argc, argv, "ot:", long_options, &option_index);
      if (c == -1) {
         break;
      }

      switch (c) {
      case 'o':
         session.flags |= SF_TRUNCATELOGS;
         break;
      case 't':
         strncpy(session.ttyName, optarg, sizeof(session.ttyName));
         break;
      case '?': /* unrecognized options */
      default:
         err = -1;
         break;
      }
   }

   if (!err) {
      if (optind < argc && strlen(argv[optind])) {
         char *sId = argv[optind];

         optind++;

         if (ModHistory_LookupByStr(sId, session.dir, 
                  sizeof(session.dir))) {
            //eprintf("invalid session (see 'history' subcommand for "
            //        "valid sessions)\n");
            err = -1;
            goto out;
         }
      } else {
         if (ModHistory_Lookup(-1, session.dir, 
                  sizeof(session.dir))) {
            eprintf("no previous recordings found\n");
            err = -1;
            goto out;
         }
      }
      eprintf("replaying recording %s\n", session.dir);
   }

   if (err == -1) {
      ModReplayPrintUsage();
   }

out:
   return err;
}
#endif

int
ModReplay_Init()
{
   int fd;

   ASSERT(strlen(session.dir));
   fd = ModSession_Open(session.dir, 0);
   if (fd >= 0) {
      UNUSED ssize_t len = read(fd, &env, sizeof(env));
      ASSERT( len == sizeof(env) );
      close(fd);
   } else {
      FATAL("error opening session file from dir %s\n", session.dir);
   }

   return 0;
}


static int
ModParseDone(const int argc, char **argv)
{
   int err = 0;

   VCPU_SetModeFlag(VCPU_MODE_REPLAY);

   if (argc == 0) {
      extern int ModHistory_Show();
      ModHistory_Show();
      err = -1;
   } else if (argc == 1) {
      if (strcmp(argv[0], "last") == 0) {
         if (ModHistory_Lookup(-1, session.dir, sizeof(session.dir))) {
            eprintf("no previous recordings found\n");
            err = 1;
         }
      } else if (ModHistory_LookupByStr(argv[0], session.dir, 
               sizeof(session.dir))) {
         err = -1;
      } 
   } else {
      err = -1;
   }

   return err;
}

static struct ModOpt optA[] = {

   { "", NULL, Opk_Bool, "", "" },
}
;
extern struct ModDesc MODULE_VAR(Base);
extern struct ModDesc MODULE_VAR(Record);

static struct ModDesc *depA[] = { &MODULE_VAR(Base), NULL };
static struct ModDesc *confA[] = { &MODULE_VAR(Record), NULL };

MODULE_BASIC(
      Replay,
      "Replays a recorded run",
      depA,
      confA,
      optA,
      ModParseDone);
