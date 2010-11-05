#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>

#include "libcommon/public.h"


static void
write_sparse_file(char *filename)
{
   int res, fd;
   char buf[4096] = { 0 };

   printf("Testing %s.\n", filename);

   fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
   assert(fd >= 0);

   lseek(fd, 8192, SEEK_SET);

   write(fd, buf, sizeof(buf));

   res = close(fd);
   assert(res == 0);
}

void
Init()
{
   write_sparse_file("./sparse_file");
}
