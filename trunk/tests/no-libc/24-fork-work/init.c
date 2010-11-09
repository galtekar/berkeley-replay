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

   pid = fork();

   if (pid) {
      /* Parent */
      wait(NULL);
   } else {
      /* Child */
      int i = 0;

      for (i = 0; i < 1000000; i++) {
      }
   }
}
