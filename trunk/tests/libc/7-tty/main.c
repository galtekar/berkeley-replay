#include <pty.h>
#include <stdio.h>
#include <utmp.h>

int 
main() 
{
   int amaster;
   pid_t pid;
   char slavepts[256];

   pid = forkpty(&amaster, slavepts, NULL, NULL);
   if (pid) {
      printf("master fd=%d slavepts=%s\n", amaster, slavepts);
   } else {
   }


   return 0;
}
