#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <vk.h>

void
Init()
{
   unsigned long long i = 0, n = 900000000;

   while (i < n) {
      int pid;

      //pid = getpid();
      //printf("pid=%d\n", getpid());
      i++;
   }
}
