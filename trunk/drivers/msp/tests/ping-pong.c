
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

#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/unistd.h>

#include <sys/types.h>
#include <linux/unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>

int nr_pages = 1;
char *buf = NULL;

#define PAGE_SIZE 4096

static void
sighandler(int sig, siginfo_t *si, void *sc)
{
}

static void
work(int cpu_id)
{
   int i, j;

   printf("Touching all %d pages...", nr_pages);
   for (j = 0; j < 200000000; j++) {
      if (j % 10000000 == 0) {
         printf("cpu_id: %d j: %d\n", cpu_id, j);
      }
      for (i = 0; i < nr_pages; i++) {
         buf[PAGE_SIZE*i] = 0;
      }
   }
   printf("done.\n");
}

static void* 
start_routine(void* arg)
{
   int cpu_id = (int) arg;
   cpu_set_t set;
   CPU_ZERO(&set);
   CPU_SET(cpu_id, &set);
   sched_setaffinity(0, sizeof(set), &set);

   work(cpu_id);
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
   int i, fd = -1, num_threads = 1;
   int use_shpt = 1, err;
   struct sigaction act = {
      .sa_handler = NULL,
      .sa_sigaction = sighandler,
      .sa_mask = 0,
      .sa_flags = SA_SIGINFO,
      .sa_restorer = NULL,
   };

   if (argc == 2) {
      use_shpt = atoi(argv[1]);
   }

   setup();

   sigaction(SIGUSR1, &act, NULL);

   if (use_shpt) 
      fd = open("/dev/shpt", O_RDONLY);
      if (fd < 0) {
         printf("SHPT not detected (cannot open /dev/shpt).\n");
      }
      err = ioctl(fd, SHPT_IOCTL_START);
      if (err != 0) {
         printf("cannot start SHPT: %d\n", err);
         exit(-1);
      }
   }


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

   if (fd >= 0) {
      close(fd);
   }

   return 0;
}
