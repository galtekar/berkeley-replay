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
   int i, fd, len;
   char buf[512];

   fd = open("/bin/ls", O_RDONLY);

   for (i = 0; i < 100000; i++) {
      lseek(fd, 0, SEEK_SET);
      len = read(fd, buf, sizeof(buf));
   }

   close(fd);
}
