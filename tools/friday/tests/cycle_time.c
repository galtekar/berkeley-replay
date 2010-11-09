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

#define BUF_SIZE 4096

/* Number of microseconds per clock cycle */
double us_per_cycle = 0;


/* Try to find the clock tick to microsecond conversion rate. */
static void set_us_per_tick()
{
#ifdef __APPLE__
	mach_timebase_info_data_t tb_info;
	assert( KERN_SUCCESS == mach_timebase_info( &tb_info ) );
	us_per_cycle = ((double)tb_info.numer)/((double)tb_info.denom);
	us_per_cycle /= 1000;
#else	// Assume Linux/x86
	char buf[BUF_SIZE];
	FILE *cpuinfo;	// Input/output file
	double cpu_mhz = 0;
	cpuinfo = fopen("/proc/cpuinfo", "r");
	while( ! feof( cpuinfo ) ) {
		if( fgets( buf, BUF_SIZE, cpuinfo ) ) {
			if( 1 == sscanf( buf,  "cpu MHz\t\t: %lf\n", &cpu_mhz ) ) {
				break;
			}
		}
	}
	assert( 0 != cpu_mhz );
	us_per_cycle = 1.0/cpu_mhz;
#endif
}  

/* Read a microsecond timer directly from the CPU.
 * Avoid gettimeofday(), because NTP makes the system time jump. */
uint64_t get_cpu_ticks()
{
	uint64_t cycles;
	if( us_per_cycle == 0 ) {
		// Only set once; assume clock rate doesn't change.
		set_us_per_tick();
	}
#ifdef __APPLE__  
	cycles = mach_absolute_time();
#else	// Assume Linux/x86
	rdtscll(cycles);
#endif
	return (uint64_t)(cycles);
}
