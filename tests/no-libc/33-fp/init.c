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
   char buf[256];
   double d;

   read(0, buf, sizeof(buf));

   d = atof(buf);

   printf("%f\n", d);
}
