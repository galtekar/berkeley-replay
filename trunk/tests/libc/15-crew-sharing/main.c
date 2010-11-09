
/* Test liblog/libreplay's threading support. */
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/unistd.h>

#include <sys/types.h>
#include <linux/unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <signal.h>

#include <shpt.h>

int nr_pages = 1;
char *buf = NULL;
int use_shpt = 1;

#define PAGE_SIZE 4096

#if 0
static int
sgetcpu()
{
   return ioctl(fd, SHPT_IOCTL_SMP_ID);
}
#endif

pid_t first_tid = 0;

static int
gettid()
{
   return syscall(SYS_gettid);
}

static void
sighandler(int sig, siginfo_t *si, ucontext_t *ucp)
{
   const struct sigcontext *scp = &ucp->uc_mcontext;
   shpt_event_t events[256];
   int i, count, nr_events;

   count = read(si->si_fd, (void*)events, sizeof(events));

   if (gettid() == first_tid && count > 0) {
      nr_events = count / sizeof(events[0]);
      printf("Got %d events (next ts=%llu)\n", nr_events, si->si_int);
#if 1
      for (i = 0; i < nr_events; i++) {
         shpt_event_t *e = &events[i];
         printf("kind=%s vaddr=0x%lx pfn=%lu timestamp=%llu src_cpu=%d\n",
               e->kind == SHPT_EV_UPGRADE ? "UP" : "DO",
               e->vaddr,
               e->pfn,
               e->timestamp,
               e->cpu_id);
      }
#endif
   }

#if 0
   printf("Got data: signo=%d code=%d fd=%d count=%d\n", si->si_signo, 
         si->si_code, si->si_fd, count);
#endif

#if 0
   switch (si->si_code) {
   case SI_SHPT_UPGRADE:
      printf("Upgrade: cpu=%d eip=0x%lx\n", cpu, scp->eip);
      break;
   case SI_SHPT_DOWNGRADE:
      printf("Downgrade: cpu=%d eip=0x%lx\n", cpu, scp->eip);
      break;
   default:
      printf("Unrecognized code: 0x%x\n", si->si_code);
      break;
   }
#endif
}

static void
work(int cpu_id)
{
   int i, j;
   int tmp;

   printf("Touching all %d pages...", nr_pages);
   for (j = 0; j < 200000000; j++) {
      if (j % 10000000 == 0) {
         printf("cpu_id: %d j: %d\n", cpu_id, j);
      }
      for (i = 0; i < nr_pages; i++) {
         buf[PAGE_SIZE*i] = 0;
         //tmp = buf[PAGE_SIZE*i];
      }
   }
   printf("done.\n");
}

static void
safe_fcntl(int fd, int cmd, int arg)
{
   int err;

   err = fcntl(fd, cmd, arg);
   if (err < 0) {
      printf("shpt: fcntl error (%d), cmd=0x%x arg=0x%x\n", err, cmd, arg);
      exit(-1);
   }
}

static int
shpt_open()
{
   int fd, err = 0;

   fd = open("/dev/shpt", O_RDONLY | O_NONBLOCK);
   if (fd < 0) {
      printf("SHPT not detected (cannot open /dev/shpt).\n");
      exit(-1);
   }

   safe_fcntl(fd, F_SETFL, O_ASYNC | O_NONBLOCK);
   safe_fcntl(fd, F_SETOWN, gettid());
   safe_fcntl(fd, F_SETSIG, SIGUSR1);

   sleep(3);

   printf("Starting...\n");

   err = ioctl(fd, SHPT_IOCTL_START);
   if (err != 0) {
      printf("cannot start SHPT: %d\n", err);
      exit(-1);
   }

   return fd;
}

static void* 
start_routine(void* arg)
{
   int cpu_id = (int) arg, fd;
   cpu_set_t set;
   CPU_ZERO(&set);
   CPU_SET(cpu_id, &set);
   sched_setaffinity(0, sizeof(set), &set);

   if (cpu_id == 0) {
      first_tid = gettid();
   }
   fd = shpt_open();
   work(cpu_id);
   if (fd >= 0) {
      close(fd);
   }
   return NULL;
}

static void
setup(void)
{
   /* Allocate a chunk and touch each page in it. This should
    * stress the page fault handler and shadow demand page mechanism. */

   buf = mmap(NULL, PAGE_SIZE*nr_pages, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   assert(buf != (char*)-1);

   printf("Buffer allocated at %p, %d pages\n", buf, nr_pages);
}

int 
main(int argc, char **argv)
{
   int i, num_threads = 1;
   struct sigaction act;

   memset(&act, 0, sizeof(act));
   act.sa_sigaction = sighandler;
   act.sa_flags = SA_SIGINFO;

   if (argc == 2) {
      use_shpt = atoi(argv[1]);
   }

   setup();

   sigaction(SIGUSR1, &act, NULL);


   {
      pthread_t tid[num_threads];

      for (i = 0; i < num_threads; i++) {
         if (pthread_create(&tid[i], NULL, &start_routine, 
                  (void*)(i+1)) != 0) {
            perror("pthread_create");
            exit(-1);
         }
      }

      start_routine((void*)0);

      for (i = 0; i < num_threads; i++) {
         if (pthread_join(tid[i], NULL) != 0) {
            perror("pthread_join");
            //exit(-1);
         }
      }
   }

   return 0;
}
