#include <stdio.h>
#include <stdlib.h>
#include "alloc.h"
#include "error.h"

#define ALIGNMENT 16 /* XXX: assuming that this alignment is enough */
#define SPACE 2048 /* must be multiple of ALIGNMENT */

typedef union { char irrelevant[ALIGNMENT]; double d; } aligned;
static aligned realspace[SPACE / ALIGNMENT];
#define space ((char *) realspace)
static unsigned int avail = SPACE; /* multiple of ALIGNMENT; 0<=avail<=SPACE */

#define NUM_CHANNELS 9

static int numallocs[] = {0,0,0,0,0,0,0,0,0};
static int numfrees[] = {0,0,0,0,0,0,0,0,0};

/*@null@*//*@out@*/char *alloc(n)
unsigned int n;
{
  numallocs[0]++;
  char *x;
  //n = ALIGNMENT + n - (n & (ALIGNMENT - 1)); /* XXX: could overflow */
  //if (n <= avail) { avail -= n; return space + avail; }
  x = malloc(n);
  if (!x) errno = error_nomem;
  //printf("DJBDNS: DBG: assigned %ld\t%d\n", (unsigned long)x, n);
  fflush(stdout);
  return x;
}

void alloc_free(x)
char *x;
{
  numfrees[0]++;
  //if (x >= space && x < space+SPACE)
  //return; /* XXX: assuming that pointers are flat */
  free(x);
}

char *alloc_channel(unsigned int n, int c) {
  numallocs[c]++;
  numallocs[0]--;
  if (n > 0) {
    return alloc(n);
  }
  else {
    return 0;
  }
}

void alloc_free_channel(char *x, int c) {
  numfrees[c]++;
  numfrees[0]--;
  alloc_free(x);
}

void printAllocStats(int reset) {
  int i;
  printf("DJBDNS: DBG:");
  for (i=0; i<NUM_CHANNELS; i++) {
    printf(" A%d %d F%d %d", i, numallocs[i], i, numfrees[i]);
    if (reset) {
      numallocs[i] = 0;
      numfrees[i] = 0;
    }
  }
  printf("\n");
  fflush(stdout);
}
