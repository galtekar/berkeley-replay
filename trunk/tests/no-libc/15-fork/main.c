#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

int
Init()
{
   int i = 0;

   printf("pid=%d pgrp=%d\n", getpid(), getpgrp());
   for (i = 0; i < 10000; i++) {
      if (fork()) {
         waitpid(-1, NULL, 0);
      } else {
         /* Child. */
         exit(-1);
      }
   }

   return 0;
}
