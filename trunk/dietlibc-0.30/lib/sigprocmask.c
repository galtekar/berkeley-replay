#include <signal.h>
#include <stdio.h>

#define PIN_HACK 0

int __rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldsetm, long nr);

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
#if PIN_HACK
   int ret;
   unsigned long dummy=0xdeadbeef;
   volatile char pad[256];
   sigset_t oldsettemp;

   pad[0]=1;

   printf("CALLING SIGPROCMASK\n");
   ret = __rt_sigprocmask(how, set, &oldsettemp, _NSIG/8);

   if (!ret && oldset) {
      printf("COPYING\n");
      memcpy(oldset, &oldsettemp, sizeof(*oldset));
   }

   return ret;
#else
  return __rt_sigprocmask(how, set, oldset, _NSIG/8);
#endif
}
