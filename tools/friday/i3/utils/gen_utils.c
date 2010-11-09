#include "gen_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>

#define UMILLION 1000000ULL

/**********************************************************************/

/* f_rand: return a random double between 0.0 and 1.0 */
double f_rand(void)
{
    int64_t l, r;

    l = (int64_t) (random() & ((1 << 26) - 1));
    r = (int64_t) (random() & ((1 << 27) - 1));
    return ((l << 27) + r) / (double)(1LL << 53);
}

/**********************************************************************/

/* funif_rand: Return a random number between a and b */
double funif_rand(double a, double b)
{
    return a + (b - a) * f_rand();
}

/**********************************************************************/

/* n_rand: return a random integer in [0, n),
   borrowed from Java Random class */
int n_rand(int n)
{
    int bits, val;

    assert(n >= 0);   /* n must be positive */

    /* Special case: power of 2 */
    if ((n & -n) == n)
	return random() & (n - 1);

    do {
	bits = random();
	val = bits % n;
    } while (bits - val + (n - 1) < 0);
    return val;
}

/**********************************************************************/

/* unif_rand: return a random integer number in the interval [a, b) */
int unif_rand(int a, int b)
{
    return a + n_rand(b - a);
}

/**********************************************************************/

/* getusec: return wall time in usec */
uint64_t wall_time(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/**********************************************************************/

void sub_wall_time(struct timeval *tv, uint64_t a, uint64_t b)
{
  if (a < b) {
    tv->tv_sec = tv->tv_usec = 0;
  } else {
    tv->tv_sec = (a - b) / UMILLION;
    tv->tv_usec = (a - b) % UMILLION;
  }
}

#ifdef _ARCH_PPC
uint64_t get_cycles(void)
{
    exit(-1);
}
#else
#define rdtscll(val) \
     __asm__ __volatile__("rdtsc" : "=A" (val))

uint64_t get_cycles(void)
{
    uint64_t ret;
    rdtscll(ret);
    return ret;
}
#endif
