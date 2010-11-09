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

#include "libcommon/public.h"

ulong entryESP;

void
Init(int argc, char **argv)
{
   int i, status;
   pid_t pid;
   char *eargv[] = {"/usr/bin/test", NULL};
   char *eenvp[] = {NULL};

   if (argc != 2) {
      printf("usage: test-bin <num-iters>\n");
      exit(-1);
   }

   int n = atoi(argv[1]);

   for (i = 0; i < n; i++) {
      pid = fork();

      if (pid) {
         /* Parent */
         wait(&status);
      } else {
         /* Child */
         execve("/usr/bin/test", eargv, eenvp);
         assert(0);
         exit(0);
      }
   }
}
