#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/time.h>
#ifdef __APPLE__
#include <mach/mach_time.h>  // mach_absolute_time, mach_timebase_info
#else	// Assume Linux/x86
#define rdtscll(val) \
__asm__ __volatile__("rdtsc" : "=A" (val))
#endif

#include "debug.h"

#define BUF_SIZE 4096

/* Number of clock cycles in a microsecond. */
uint64_t __ll_cycles_per_us = 0;

/* Cpu clock speed in MHz. */
uint64_t __ll_cpu_mhz = 0;

/* Try to find the clock tick to microsecond conversion rate. */
void set_cycles_per_us() {
	char buf[BUF_SIZE];
	FILE *cpuinfo;	// Input/output file
	__ll_cpu_mhz = 0;

	/* This function should be invoked until after the libc pointers
	 * have been initialized (i.e., until after liblog's constructor
	 * executes). */
	ASSERT(fopen != NULL);

	cpuinfo = fopen("/proc/cpuinfo", "r");
	while( ! feof( cpuinfo ) ) {
		if( fgets( buf, BUF_SIZE, cpuinfo ) ) {
			if( 1 == sscanf( buf,  "cpu MHz\t\t: %llu\n", &__ll_cpu_mhz ) ) {
				break;
			}
		}
	}
	ASSERT( 0 != __ll_cpu_mhz );

	__ll_cycles_per_us = __ll_cpu_mhz;
}  

/* Return the number of microseconds since the epoch.
 * Uses gettimeofday(). */
uint64_t get_sys_micros() {
	struct timeval tv;

	if (gettimeofday(&tv, NULL ) != 0) {
		perror("gettimeofday");
		exit(-1);
	}

	return (tv.tv_sec * 1000000ULL + tv.tv_usec);
}

/* Read a microsecond timer directly from the CPU.
 * Avoid gettimeofday(), because NTP makes the system time jump. */
uint64_t get_cpu_micros() {
	uint64_t cycles;

	if( __ll_cycles_per_us == 0 ) {
		// Only set once; assume clock rate doesn't change.
		set_cycles_per_us();
	}

	rdtscll(cycles);

	return (uint64_t)(cycles / __ll_cycles_per_us);
}
