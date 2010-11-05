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

void handler(int sig)
{
}

void
Init_Pre()
{
   sigset_t set, uset, oset;
   int sig, res;

   memset(&set, 0, sizeof(set));
   memset(&oset, 0, sizeof(oset));

   sigaddset(&set, SIGQUIT);
   sigaddset(&set, SIGINT);
   sigfillset(&uset);

   signal(SIGQUIT, handler);
   //signal(SIGINT, handler);
   //sigprocmask(SIG_SETMASK, &uset, &oset);
   res = sigprocmask(SIG_UNBLOCK, &uset, &oset);
   assert(res == 0);
   printf("oset=0x%x:0x%x\n", oset.sig[0], oset.sig[1]);
   sig = sigwaitinfo(&set, NULL);

   printf("sig=%d\n", sig);
}
