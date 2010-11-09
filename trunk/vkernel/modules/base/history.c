#include <vkernel/public.h>

#include "private.h"

/* XXX: should be an option. */
#define HISTORY_FILENAME "." RELEASE_NAME "_history"

static void
ModHistoryGetPath(char *histPath, size_t bufSz)
{
   char homePath[256];

   EnvVar_Str("HOME", homePath, sizeof(homePath));

   if (strlen(homePath)) {
      snprintf(histPath, bufSz, "%s/%s", homePath, HISTORY_FILENAME);
   } else {
      snprintf(histPath, bufSz, "./%s", HISTORY_FILENAME);
   }
}

static FILE *
ModHistoryOpen(char *mode)
{
   FILE *fp;
   char histPath[256];
   ModHistoryGetPath(histPath, sizeof(histPath));

   fp = fopen(histPath, mode);

   if (!fp) {
      char localHistPath[256];

      snprintf(localHistPath, sizeof(localHistPath), "./%s", HISTORY_FILENAME);

      eprintf("error opening %s\n", histPath);
      fp = fopen(localHistPath, mode);
      if (!fp) {
         eprintf("error opening %s\n", localHistPath);
      }
   }

   return fp;
}

void
ModHistory_Append(char *sesPath)
{
   FILE *fp;

   ASSERT(sesPath);
   ASSERT(strlen(sesPath));

   fp = ModHistoryOpen("a");

   if (!fp) {
      FATAL("can't append to history file\n");
   }

   fprintf(fp, "%s\n", sesPath);

   fclose(fp);
   fp = NULL;
}

int
ModHistory_Lookup(int idx, char *sesPath /* OUT */, size_t bufSz)
{
   int err = -1, i = 0;
   FILE *fp;

   ASSERT(sesPath);
   ASSERT(idx >= -1);

   if (!(fp = ModHistoryOpen("r+"))) {
      goto out;
   }

   while (fscanf(fp, "%s\n", sesPath) != EOF) {
      if (i == idx) {
         err = 0;
         goto close_out;
      }
      i++;
   }

   if (idx == -1) {
      err = 0;
   }

   if (err) {
      eprintf("invalid index %d, use 'history' subcommand to get indexes\n", idx);
   }

close_out:
   fclose(fp);
   fp = NULL;
out:
   return err;
}

int
ModHistory_LookupByStr(const char *str, char *sesPath /* OUT */, size_t bufSz)
{
   int err = 0;

   if (str[0] != '/') {
      int idx;

      idx = atoi(str);

      if (idx < -1) {
         eprintf("invalid index %d, use 'history' subcommand to get indexes\n", idx);
         goto error_out;
      }

      err = ModHistory_Lookup(idx, sesPath, bufSz);
   } else {
      strncpy(sesPath, str, bufSz);
   }

   /* Verify the session path exists. */
   if (!err) {
      int fd;

      //printf("sesPath=%s\n", sesPath);
      fd = ModSession_Open(sesPath, 0);
      if (fd >= 0) {
         close(fd);
      } else {
         eprintf("error opening session directory (does it exist?)\n");
         goto error_out;
      }
   }

   goto out;

error_out:
   err = -1;
out:
   return err;
}

static void
ModInfoGet(char *sesPath, struct Environment *eInfoP)
{
   char sesInfoPath[256];
   int res, fd;

   ASSERT(eInfoP);

   snprintf(sesInfoPath, sizeof(sesInfoPath), "%s/%s", sesPath, 
         SESSION_FILENAME);

   fd = open(sesInfoPath, O_RDONLY);
   if (fd < 0) {
      FATAL("error opening '%s'\n", sesInfoPath);
   }

   res = read(fd, eInfoP, sizeof(*eInfoP));
   ASSERT(res == sizeof(*eInfoP));

   close(fd);
}

static void
ModInfoShow(int i, char *sesPath) 
{
   struct Environment *eP = malloc(sizeof(*eP));

   ModInfoGet(sesPath, eP);

   ASSERT(eP->argListLen > 0);

   printf("%4d %c %lu %-30s %-30s\n", 
         i, 
         eP->is_value_det ? 'v' : 'c',
         eP->recorded_bytes,
         eP->argList,
         sesPath);

   free(eP);
}

#if 0
static void
ModInfoPrintUsage()
{
   printf("info: Shows info about a recording\n");
   printf("usage: info <session-dir | index>\n"
         "\n"
         "examples:\n"
         "  'info /tmp/replay-session' to get info on recording in /tmp/replay-session\n"
         "  'info 4' to get info on the fifth session in recording history\n"
         );
}

static int
ModInfoParseOptions(int argc, char ** argv)
{
   int err = 0;
   char sesPath[256];

   if (argv[1] && strlen(argv[1])) {
      char *sesStr = argv[1];

      //printf("sesStr=%s\n", sesStr);
      if (!ModHistory_LookupByStr(sesStr, sesPath, sizeof(sesPath))) {
         ModInfoShow(sesPath);
      } else {
         goto out;
      }
   } else {
      eprintf("info: must specify a session identifier\n");
      err = -1;
   }
  
   if (err) {
      ModInfoPrintUsage();
   }

out:
   return -1;
}


static void
ModHistoryPrintUsage()
{
   printf("history: Shows a history of recordings\n");
   printf("usage: history\n"
          "\n"
          "  To clear the history, delete ~/%s.\n",
         HISTORY_FILENAME);
}

static int
ModHistoryParseOptions(int argc, char ** argv)
{
   int i = 0;
   char sesPath[256];
   FILE *fp;

   fp = ModHistoryOpen("r");
   
   if (fp) {
      while (fscanf(fp, "%s\n", sesPath) != EOF) {
         printf("  %3d", i);
         ModInfoShow(sesPath);
         i++;
      }

      fclose(fp);
      fp = NULL;
   } else {
      eprintf("no history found\n");
   }

   return -1;
}
#endif

int
ModHistory_Show()
{
   int i = 0;
   char sesPath[256];
   FILE *fp;

   fp = ModHistoryOpen("r");
   
   if (fp) {
      while (fscanf(fp, "%s\n", sesPath) != EOF) {
         ModInfoShow(i, sesPath);
         i++;
      }

      fclose(fp);
      fp = NULL;
   } else {
      eprintf("no history found\n");
   }

   return 0;
}
