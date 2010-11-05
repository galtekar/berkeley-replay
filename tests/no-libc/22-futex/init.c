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
   int err = 0, futex = 0;

   err = syscall(SYS_futex, &futex, FUTEX_WAIT, 0, 0, 0, 0);

   printf("err=%d\n", err);
}
