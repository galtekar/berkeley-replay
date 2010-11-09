#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
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

#include "logreplay.h"
#include "libc_pointers.h"
#include "gcc.h"

#define BUF_SIZE 4096

/* Number of microseconds per clock cycle */
HIDDEN double __ll_us_per_cycle = 0;

/* Number of clock cycles in a microsecond. */
HIDDEN uint64_t __ll_cycles_per_us = 0;

/* Cpu clock speed in MHz. */
HIDDEN double __ll_cpu_mhz = 0;

/* Try to find the clock tick to microsecond conversion rate. */
void HIDDEN set_us_per_cycle() {
  
#ifdef __APPLE__
	mach_timebase_info_data_t tb_info;
	assert( KERN_SUCCESS == mach_timebase_info( &tb_info ) );
	__ll_us_per_cycle = ((double)tb_info.numer)/((double)tb_info.denom);
	__ll_us_per_cycle /= 1000;
#else	// Assume Linux/x86
	char buf[BUF_SIZE];
	FILE *cpuinfo;	// Input/output file
	__ll_cpu_mhz = 0;

	/* This function should be invoked until after the libc pointers
	 * have been initialized (i.e., until after liblog's constructor
	 * executes). */
	assert(__LIBC_PTR(fopen) != NULL);

	cpuinfo = (*__LIBC_PTR(fopen))("/proc/cpuinfo", "r");
	while( ! (*__LIBC_PTR(feof))( cpuinfo ) ) {
		if( (*__LIBC_PTR(fgets))( buf, BUF_SIZE, cpuinfo ) ) {
			if( 1 == sscanf( buf,  "cpu MHz\t\t: %lf\n", &__ll_cpu_mhz ) ) {
				break;
			}
		}
	}
	assert( 0 != __ll_cpu_mhz );
	__ll_us_per_cycle = 1.0/__ll_cpu_mhz;
	__ll_cycles_per_us = __ll_cpu_mhz;
#endif
}  

/* Return the number of microseconds since the epoch.
 * Uses gettimeofday(). */
uint64_t HIDDEN get_sys_micros() {
	struct timeval tv;

	if ((*__LIBC_PTR(gettimeofday))(&tv, NULL ) != 0) {
		perror("gettimeofday");
		exit(-1);
	}

	return (tv.tv_sec * 1000000ULL + tv.tv_usec);
}

/* Read a microsecond timer directly from the CPU.
 * Avoid gettimeofday(), because NTP makes the system time jump. */
uint64_t HIDDEN get_cpu_micros() {
	uint64_t cycles;

	if( __ll_us_per_cycle == 0 ) {
		// Only set once; assume clock rate doesn't change.
		set_us_per_cycle();
	}
#ifdef __APPLE__  
	cycles = mach_absolute_time();
#else	// Assume Linux/x86
	rdtscll(cycles);
#endif
	return (uint64_t)(cycles*__ll_us_per_cycle);
}
