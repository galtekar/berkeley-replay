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

//#include "libcommon/public.h"

void
Init(int argc, char *argv[])
{
   char buf[256];
   unsigned int n, o;

   read(0, buf, sizeof(buf));

#if 0
   if (strcmp(buf, "cool\n") == 0) {
      printf("match!\n");
   }
#endif

   n = atoi(buf);
   //n = buf[0];
   

   printf("n=%d\n", n);

#if 0
   if (n > 10) {
      printf("larger\n");
   } else {
      printf("smaller\n");
   }
#endif
#if 0
   {
      char c = buf[0];
      printf("%c %c %c %c\n", c, c, c, c);
   }
#endif
#if 0
   {
      char c = buf[0];
      unsigned int n = c;

      printf("%d\n", n);
   }
#endif
#if 0
   o = n*n/n;

   if (o == 48) {
      printf("cool!\n");
   }
#endif

#if 0
   if (n % 48 == 0) {
      printf("got it!\n");
   }

   if (buf[0] == 'a') {
      printf("cool!\n");
   }

   if (buf[0] > 'a') {
      printf("fool!\n");
   }
#endif
}
