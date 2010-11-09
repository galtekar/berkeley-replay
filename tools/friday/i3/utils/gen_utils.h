#ifndef _GEN_UTILS_H
#define _GEN_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#ifdef __APPLE__
#include <inttypes.h>  // Need uint8_t
#endif
#include <sys/time.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>

#ifndef min
#define max(x, y) ((x) > (y) ? (x) : (y))
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

double	f_rand(void);
double	funif_rand(double a, double b);
int	n_rand(int n);
int	unif_rand(int a, int b);
uint64_t wall_time(void);
void sub_wall_time(struct timeval *tv, uint64_t a, uint64_t b);
uint64_t get_cycles(void);

#endif
