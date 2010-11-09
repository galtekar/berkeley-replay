#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>

typedef unsigned long long u64;

static void
fpcopy(u64 *to, u64 *from, size_t count)
{
   if (from > to) {
      printf ("h1\n");
      while (count-- > 0) {
         __asm__ volatile("fildll (%0); fistpll (%1)"
               :
               : "r" (from), "r" (to)
               : "memory" );
         ++from;
         ++to;
      }
   } else { 
      printf ("h2\n");
      while (count-- > 0) {
         __asm__ volatile("fildll (%0,%2,8); fistpll (%1,%2,8)"
               :
               : "r" (from), "r" (to), "r" (count)
               : "memory" );
      }
   } 
}


static void
verify(char *str, u64 *p, size_t len, u64 val)
{
   int i;

   printf("verify: %s\n", str);

   for (i = 0; i < len; i++) {
      if (p[i] != val) {
         printf("%d : %llx\n", i, p[i]);
      }
   }
}

int
Init()
{
#define LEN 1
//#define MAGIC 0xfeadbeefdeadbe06LLU
#define MAGIC 0x01000000c0011dd4LLU

   int i;
   u64 numbers_copy[LEN] = { 0 };
   u64 numbers[LEN];

   assert(sizeof(u64) == 8);

   for (i = 0; i < LEN; i++) {
      numbers[i] = MAGIC;
   }


#if 0
   verify("1", numbers, LEN, MAGIC);
   verify("2", numbers_copy, LEN, 0);
#endif

   fpcopy(numbers_copy, numbers, LEN);

   verify("3", numbers, LEN, MAGIC);
   verify("4", numbers_copy, LEN, MAGIC);

   return 0;
}
