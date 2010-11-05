#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define PATH_MAX 4096

#include "libcommon/public.h"

unsigned long* entryESP = NULL;
static int argc;
static char **argv;
static char **evp;
static Elf32_auxv_t *auxV;


void sigint_handler(int signr)
{
   printf("SIGINT!\n");
#if 0
   /* Kill all processes. */
	fprintf(stdout, "shutdown: sending all processes the TERM signal...\r\n");
	kill(-1, SIGTERM);
	sleep(3);
	fprintf(stdout, "shutdown: sending all processes the KILL signal.\r\n");
	(void) kill(-1, SIGKILL);
#endif
}

void sigchld_handler(int signr)
{
   printf("SIGCHLD! returning to %p \n", __builtin_return_address(0));
}

void
execute_command(const char *cmd)
{
   int res;
   printf("Execing '%s'.\n", cmd);
   res = execve(cmd, NULL, NULL);
   perror("execve failed");
   exit(-1);
}

void
Init_Pre()
{
   argc = *entryESP;
   argv = (char**)(entryESP+1);
   int i;
   Elf32_auxv_t *ap;

   /* The AUXV comes after the environment variables. */
   evp = &argv[argc+1];

   while(*evp++ != (void*)0);

   auxV = (Elf32_auxv_t*) evp;

#if 0
   /* Quick code to determine return value behavior
    * of bitops in bitset is full. */
   {
      char buf[2];
      int res;

      memset(buf, 0xFF, sizeof(buf));
      res = Bit_FindNextZeroBit(buf, sizeof(buf), 0);

      printf("res=%d\n", res);
      exit(-1);
   }
#endif

#if 0
   res = open("/dev/tty0", O_RDWR);
   assert(res != -1);
#endif
   printf("argc=%d\n", argc);

   for (i = 0; i < argc; i++) {
      printf("argv[%d]=%s\n", i, argv[i]);
   }


   printf("sizeof(sigset_t)=%d\n", sizeof(sigset_t));
   printf("auxv=0x%lx\n", (ulong)auxV);

   assert(auxV);
   ap = auxV;
   while (ap->a_type != AT_NULL) {
      printf("type=%d val=0x%lx\n", ap->a_type, ap->a_un.a_val);

#if 1
      switch (ap->a_type) {
      case AT_EXECFD:
         break;
      case AT_SYSINFO:
         break;

      case AT_BASE:
         break;

      case AT_ENTRY:
         break;

      case AT_PHDR:
         break;

      case AT_PHENT:
         break;

      case AT_PHNUM:
         break;

      case AT_PLATFORM:
         printf("platform=%s\n", (char*)ap->a_un.a_val);
         break;

      default:
         break;
      }
#endif

      ap++;
   }

   signal(SIGINT, sigint_handler);
   signal(SIGCHLD, sigchld_handler);

   while (1) {
      char cmd[4096], *c = cmd;
      char *retval = NULL;
      //int retval;

      printf("%% ");
      retval = fgets(cmd, sizeof(cmd), stdin);
      //retval = scanf("%s", cmd);

      if (ferror(stdin) || feof(stdin)) {
         clearerr(stdin);
         printf("\n");
         continue;
      }

      //printf("retval=0x%lx\n", (ulong)retval);
      if (retval) {
         int err;
         char *nlp, *canCmd;
         nlp = strchr(cmd, '\n');
         *nlp = 0;

         canCmd = malloc(PATH_MAX);

         if (cmd[0] == '/') {
            err = MiscOps_CanonizePath(cmd, canCmd);
            if (!err) {
               printf("cmd=%s\n", canCmd);
               c = canCmd;
            }
         }

         if (strlen(retval)) {
            pid_t pid = fork();

            if (pid) {
               int status;
               wait(&status);
               if (WIFSIGNALED(status)) {
                  int signr = WTERMSIG(status);
                  printf("%s\n", sys_siglist[signr]);
               }
            } else {
               /* child */
               execute_command(c);
            }
         }

         free(canCmd);
      }
   }
}
