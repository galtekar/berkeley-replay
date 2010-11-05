#ifndef CLOCK_H
#define CLOCK_H

#include <inttypes.h>

/* Converts from cycles to microseconds as a double. */
#define C2USD(val) ((double)((double)(val) / (double)__ll_cycles_per_us))

/* Return the number of microseconds since the epoch.
 * Uses gettimeofday().
 */
extern uint64_t get_sys_micros();

/* Read a microsecond timer directly from the CPU.
 * Avoid gettimeofday(), because NTP makes the system time jump.
 */
extern uint64_t get_cpu_micros();

/* Sets the us_per_cycle and cycles_per_us variables. */
extern void set_cycles_per_us();

/* Number of clock cycles in a microsecond. */
extern uint64_t __ll_cycles_per_us;

extern uint64_t __ll_cpu_mhz;
#endif
