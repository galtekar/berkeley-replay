#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>

#include "libcommon/public.h"

/* ----- Test that lseek returns expected values ----- */

static void
seek(int fd, int new_pos, int whence, int expected_res)
{
   int res;

   res = lseek(fd, new_pos, whence);
   if (res != expected_res) {
      printf("  %d: lseek expected result %d but got %d\n", whence, expected_res, res);
      //abort();
   }
}

static void
verify_seek(char *filename, int new_pos, int *expect)
{
   int res, fd;

   printf("Testing %s.\n", filename);

   fd = open(filename, O_RDONLY);
   assert(fd >= 0);

   seek(fd, new_pos, SEEK_SET, expect[0]);
   seek(fd, 0, SEEK_CUR, expect[1]);

   res = close(fd);
   assert(res == 0);
}

void
Init()
{
   const int new_pos = 200;

   int random_expect[] = { new_pos, new_pos };
   verify_seek("/dev/random", new_pos, random_expect);

   verify_seek("/dev/urandom", new_pos, random_expect);

   int null_expect[] = { 0, 0 };
   verify_seek("/dev/null", new_pos, null_expect);

   verify_seek("/dev/full", new_pos, null_expect);

   //verify_seek("/dev/zero", new_pos, 0);
}
