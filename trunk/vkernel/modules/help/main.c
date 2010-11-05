/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"

#if 0
static void
ModHelpPrintUsage()
{
   printf("help: Provides help on a given subcommand.\n"
          "usage: help <subcommand>\n");
}

static void
ModHelpPrintHelp()
{
   struct ModDesc **modPP;

   printf("Usage: bdr '<subcommand> [options]' ...\n"
          "Berkeley Deterministic Replay (BDR) command-line client v. 1.0 beta\n"
          "Type \"bdr 'help <subcommand>'\" for help on a specific subcommand.\n\n"
         );

   printf("Available subcommands:\n");

   printf("  Basic:\n");
   for (modPP = __modbasic_desc_start; modPP < __modbasic_desc_end; modPP++) {
      printf("  %9s - %s\n", (*modPP)->name, (*modPP)->desc);
   }

   printf("\n  Advanced:\n");
   for (modPP = __modadv_desc_start; modPP < __modadv_desc_end; modPP++) {
      printf("  %9s - %s\n", (*modPP)->name, (*modPP)->desc);
   }

   printf("\n  Analysis:\n");
   for (modPP = __modanalysis_desc_start; modPP < __modanalysis_desc_end; modPP++) {
      printf("  %9s - %s\n", (*modPP)->name, (*modPP)->desc);
   }

   printf("\n"
          "Sample usage:\n"
          "  To record: \"bdr 'record /bin/ls'\"\n"
          "  To replay: \"bdr replay\"\n"
          "    with race detection: \"bdr racer replay\"\n" 
          "    with debug-trace enabled: \"bdr debug replay\"\n"
          "  To verify determinism:\n"
          "    (1) \"bdr check 'record /bin/ls'\" and (2) \"bdr check replay\"\n"

          );

}

static int
ModHelpParseOptions(int argc, char **argv)
{
   ASSERT(argv >= 0);

   //printf("argc=%d 1=%s\n", argc, argv[1]);
   if (argc > 1) {
      char *modName = argv[1];
      struct ModDesc *modDescP;

      modDescP = Mod_LookupDesc(modName);
      if (modDescP) {
         ASSERT(modDescP->printUsageFn);
         modDescP->printUsageFn();
      } else {
         printf("help: invalid subcommand: '%s'\n", modName);
         ModHelpPrintHelp();
      }
   } else {
      ModHelpPrintHelp();
   }

   return -1;
}


MODULE_BASIC(help,
            "Provides help with a subcommand",
            &ModHelpParseOptions,
            &ModHelpPrintUsage);

#define STDOUT 1

#define BANNER(s) \
	lprintf(STDOUT, \
         s " (%d-vcpu%s, %s, %s, %s)\n", \
         MAX_NR_VCPU, \
         VCPU_IsReplaying() ? "-rep" : (VCPU_IsLogging() ? "-log" : ""), \
         DEBUG ? "debug" : "release", \
         __DATE__, __TIME__);

static void
ModVersionPrintUsage()
{
   printf("help: Provides version and copyright info.\n"
          "usage: version\n");
}

static int
ModVersionParseOptions(int argc, char **argv)
{
   BANNER("Berkeley Deterministic Replay (BDR)");

   printf("\n"
          "Copyright (C) 2005-2009 The Regents of the University of California.\n"
          "SmartFuzz is Copyright (C) 2009 The Regents of the University of California.\n"
          "LibVEX is Copyright (C) 2004-2009, and GNU GPL'd, by OpenWorks LLP.\n"
         );

   return -1;
}
#endif
