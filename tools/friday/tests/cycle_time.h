#ifndef CLOCK_H
#define CLOCK_H

#include <inttypes.h>

/* Read a microsecond timer directly from the CPU.
 * Avoid gettimeofday(), because NTP makes the system time jump.
 */
extern uint64_t get_cpu_ticks();

extern double us_per_cycle;

#endif
