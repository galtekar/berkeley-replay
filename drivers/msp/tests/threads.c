/* Test liblog/libreplay's threading support. */
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
#define _GNU_SOURCE
#include <sched.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>

int nr_pages = 100;
char *buf = NULL;

#define PAGE_SIZE 4096

static void
work(void)
{
   int i, j;

   printf("Touching all %d pages...", nr_pages);
   for (j = 0; j < 20000000; j++) {
      for (i = 0; i < nr_pages; i++) {
         buf[PAGE_SIZE*i] = 0;
      }
   }
   printf("done.\n");
}

static void* 
start_routine(void* arg)
{
   work();
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
   int i, fd, num_threads;

   if (argc != 2) {
      num_threads = 1;
   } else {
      num_threads = atoi(argv[1]);
   }

   fd = open("/dev/shpt", O_RDONLY);
   if (fd < 0) {
      printf("SHPT not detected (cannot open /dev/shpt).\n");
   }

   setup();

   {
      pthread_t tid[num_threads];

      for (i = 0; i < num_threads; i++) {
         if (pthread_create(&tid[i], NULL, &start_routine, 
                  (void*)&tid[i]) != 0) {
            perror("pthread_create");
            exit(-1);
         }
      }

      start_routine(NULL);

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
