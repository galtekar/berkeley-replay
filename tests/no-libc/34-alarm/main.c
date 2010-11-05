#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void update_progress()
{
   printf("progress!\n");

   alarm(1);
}

int
Init()
{
   signal(SIGALRM, update_progress);
   alarm(1);

   while (1) {
      sleep(100000);
   }

   return 0;
}
