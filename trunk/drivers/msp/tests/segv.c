#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define PAGE_SIZE 409

int nr_pages = 100;

static void
work(void)
{
   printf("Segfaulting...\n");
   char *p = NULL;
   *p = 0;
}

int
main(int argc, char **argv)
{
   int fd;

   if (argc >= 2) {
      nr_pages = atoi(argv[1]);
   }

   fd = open("/dev/shpt", O_RDONLY);
   if (fd < 0) {
      printf("SHPT not detected (cannot open /dev/shpt).\n");
   }

   work();

   if (fd >=0) {
      close(fd);
   }

   return 0;
}
