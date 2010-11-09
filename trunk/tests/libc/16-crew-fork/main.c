
/* Test liblog/libreplay's threading support. */
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/unistd.h>

#include <sys/types.h>
#include <linux/unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>

#include <shpt.h>

int fd = -1;

int 
main(int argc, char **argv)
{
   int i;
   int use_shpt = 1, err;

   if (argc == 2) {
      use_shpt = atoi(argv[1]);
   }

   //sigaction(SIGUSR1, &act, NULL);
   signal(SIGUSR1, SIG_IGN);

   if (use_shpt) {
      fd = open("/dev/shpt", O_RDONLY);
      if (fd < 0) {
         printf("SHPT not detected (cannot open /dev/shpt).\n");
         goto work;
      }
      err = ioctl(fd, SHPT_IOCTL_START);
      if (err != 0) {
         printf("cannot start SHPT: %d\n", err);
         exit(-1);
      }
   }

work:
   printf("Forking a process.\n");
   pid_t pid = fork();

   if (pid) {
      printf("Parent.\n");
      wait(NULL);

      if (fd >= 0) {
         close(fd);
      }
   } else {
      printf("Child.\n");
   }

   return 0;
}
