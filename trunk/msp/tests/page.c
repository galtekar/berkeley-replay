#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define PAGE_SIZE 409

int nr_pages = 100;
char *buf = NULL;

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

static void
work(void)
{
   int i;

   printf("Touching all %d pages...", nr_pages);
   for (i = 0; i < nr_pages; i++) {
      buf[PAGE_SIZE*i] = 0;
   }
   printf("done.\n");
}

int
main(int argc, char **argv)
{
   int fd;
   pid_t pid = 1;

   if (argc >= 2) {
      nr_pages = atoi(argv[1]);
   }

   fd = open("/dev/shpt", O_RDONLY);
   if (fd < 0) {
      printf("SHPT not detected (cannot open /dev/shpt).\n");
   }

   setup();

   //pid = fork();

   work();

   if (pid) {
      //wait(NULL);
      if (fd >=0) {
         close(fd);
      }
   }

   return 0;
}
