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

ulong entryESP;

void
Init_Pre()
{
   int i, fd;

   for (i = 0; i < 100000; i++) {
      fd = open("/bin/ls", O_RDONLY);
      close(fd);
   }
}
