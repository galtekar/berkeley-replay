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

/*
 * Useful for testing log rotation. Child will rotate
 * log many times. After parent reaps child, parent's log
 * window should be updated to the most recent rotation.
 */

ulong entryESP;

void
Init_Pre()
{
   pid_t pid;
   int s = 0;

   void *shmp;
   int *array;

   shmp = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
   assert(shmp != (void*)MAP_FAILED);
   memset(shmp, 0, PAGE_SIZE);

   array = (int *) shmp;

   pid = fork();

   if (pid) {
      /* Parent */
      //*array = 1;
      memset(shmp, 0x0, PAGE_SIZE);
      wait(NULL);
   } else {
      /* Child */
      int r, s;
      char *b;

      r = *array;

#if 1
      if (r == 1) {
         printf("cool!\n");
      }
#endif

#if 0
      b = (char*)&r;
      *b = 0;
      //*(b+1) = 0;
      //*(b+2) = 0;
      //*(b+3) = 0;
#endif
#if 0
      array[r] = 2;
#endif
   }
}
