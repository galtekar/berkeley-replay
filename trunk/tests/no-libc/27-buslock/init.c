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

ulong entryESP;

void
Init_Pre()
{
   pid_t pid;

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
      *array = 1;

      wait(NULL);

      *array = 0;
   } else {
      /* Child */
      int b = 1;

      __asm__ __volatile__ ("lock; addl $1, %0;" 
            : "=m" (*array));

      if (b == 1) {
         printf("cool!\n");
      }
   }
}
