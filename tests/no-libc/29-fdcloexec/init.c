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

#include "libcommon/public.h"

void
Init(int argc, char *argv[])
{
   int i, fd;
   printf("argc=%d\n", argc);
#if 0
   for (i = 0; i < argc; i++) {
      printf("arg%i: %s\n", i, argv[i]);
   }
#endif
   if (argc == 1) {
      pid_t pid;

      /* parent */
      fd = open("./test-bin", O_RDONLY, 0);
      printf("fd=%d, cloexec=%d\n", fd, fcntl(fd, F_GETFD, FD_CLOEXEC));
      fcntl(fd, F_SETFD, FD_CLOEXEC);
      //fcntl(fd, F_SETFD, 0);

      pid = fork();

      if (pid) {
         wait(NULL);
         close(fd);
      } else {
         execl("./test-bin", "dummy", NULL);
      }
   } else {
      /* child */
      int err;
      char buf[3];

      printf("child program!\n");

      err = read(3, buf, sizeof(buf));
      if (err < 0) {
         perror("Success!");
      } else {
         assert(err == sizeof(buf));
         printf("Failure!\n");
      }
   }
}
