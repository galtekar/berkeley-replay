#include <stdio.h>
#include <assert.h>

typedef int (*fn_t)(void *);

extern int tst_threads(void *arg);

fn_t fna[] = {
   tst_threads,
   NULL,
};

int
main(int argc, char **argv)
{
   int id = -1;

   if (argc != 2) {
      assert(0);
   }

   id = atoi(argv[1]);
   fnp = fna[id];
   fnp(argc, argv);

   return 0;
}
