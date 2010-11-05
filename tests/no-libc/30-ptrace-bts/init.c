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
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <errno.h>

#include "libcommon/public.h"
#include "ptrace-bts.h"

static void
usage()
{
   printf("usage: bts_trace <program> [args] ...\n");
}

static int
Ptrace(int req, pid_t pid, void *addr, void *data)
{
   int err;

   err = ptrace(req, pid, addr, data);

   if (err < 0) {
      printf("errno=%d\n", errno);
      perror("ptrace");
      exit(-1);
   }

   return err;
}

static void
StartBTS(pid_t pid)
{
   struct ptrace_bts_config cfg = { 
      .size = (1 << 16) /* 64K, could be higher, but must change ulimit */, 
      .flags = PTRACE_BTS_O_TRACE | PTRACE_BTS_O_ALLOC,
      .signal = 0,
      .bts_size = 0 };

   Ptrace(PTRACE_BTS_CONFIG, pid, &cfg, (void*) (sizeof(cfg)));
}

void
Init(int argc, char *argv[])
{
   int err;
   pid_t pid;


   if (argc < 2) {
      usage();
      exit(-1);
   }

   pid = fork();

   if (pid) {
      int status;

      while (1) {
         if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid");
            exit(-1);
         }

         if (WIFEXITED(status)) {
            printf("child has exited\n");
            break;
         } else if (WIFSIGNALED(status) || WIFSTOPPED(status)) {
            if (WIFSIGNALED(status)) {
               printf("child was signalled\n");
            } else if (WIFSTOPPED(status)) {
               printf("child was stopped\n");

               switch (WSTOPSIG(status)) {
               case SIGTRAP:
                  printf("child probably did an execve, starting BTS!\n");
                  StartBTS(pid);
                  break;
               default:
                  break;
               };
            }

            Ptrace(PTRACE_CONT, pid, NULL, NULL);
         } else {
            printf("some other reason\n");
         }
      }

      exit(0);

   } else {
      /* child */
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);

      err = execv(argv[1], &argv[1]);
      perror("execv");
      exit(-1);
   }
}
