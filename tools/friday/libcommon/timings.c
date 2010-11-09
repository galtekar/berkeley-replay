#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "logreplay.h"
#include "libc_pointers.h"
#include "timings.h"

#include "gcc.h"

static char timer_str[MAX_NUM_WRAPPERS][MAX_TIMER_NAME_SIZE];

static char subtimer_str[][MAX_TIMER_NAME_SIZE] = { "_wrapper", 
	"_wrapper_call", "_cosched", "_shm_write", "_hex_encode", 
	"_entry_creation", "_entry_to_logger", "_other", "_call_libc" };

static char ckpttimer_str[][MAX_TIMER_NAME_SIZE] = { "_rotate_log_if_time", 
	"_logger_rotate", "_drop_checkpoint", "_ckpt_save", "_read_self_regions" };

static int __num_wrapper_timers = 0;

/* Stores timers for microbenchmarking purposes. */
HIDDEN wrapper_timer_t __wrapper_timer[MAX_NUM_WRAPPERS];
HIDDEN ckpt_timer_t __ckpt_timer;

/* Will be set to a an unlikely value when set. */
HIDDEN int64_t timers_have_been_initialized = 0;

int HIDDEN alloc_new_wrapper_timer(char* name) {
	int ret;

	ret = __num_wrapper_timers;

	/* Set the timer's name. */
	strcpy(timer_str[ret], name);

	__num_wrapper_timers++;

	assert(__num_wrapper_timers < MAX_NUM_WRAPPERS);

	return ret;
}

void HIDDEN init_timers() {
	/* Initialize the timers. */
	int i, j;
	int num_subtimers = sizeof(wrapper_timer_t) / sizeof(my_timer_t);
	my_timer_t* t;


	set_us_per_cycle();

	memset(__wrapper_timer, 0x0, sizeof(__wrapper_timer));
	memset(&__ckpt_timer, 0x0, sizeof(__ckpt_timer));

	/* Initialize the wrapper timers. */
	num_subtimers = sizeof(wrapper_timer_t) / sizeof(my_timer_t);
	for (i = 0; i < MAX_NUM_WRAPPERS; i++) {
		for (j = 0; j < num_subtimers; j++) {
			t = ((my_timer_t*)&__wrapper_timer[i]) + j;

			t->best = UINT64_MAX;
		}
	} 

	/* Initialize the checkpoint timer. */
	num_subtimers = sizeof(ckpt_timer_t) / sizeof(my_timer_t);
	for (j = 0; j < num_subtimers; j++) {
		t = ((my_timer_t*)&__ckpt_timer) + j;

		t->best = UINT64_MAX;
	}

	/* Highly unlikely the garbage memory has this value. */
	timers_have_been_initialized = 0xfeedbeaddeadbeefLL;
}

void HIDDEN print_timing_stats() {
	int i, j;
	my_timer_t* t;
	int num_subtimers;
	FILE* fp = stdout;

	(*__LIBC_PTR(fprintf))(fp,
			"\n\n"
			"==============================================================\n"
#if REPORT_CYCLES
			"Micro-benchmarks (cycles [us]) \n"
#else
			"Micro-benchmarks (microsecond units) \n"
#endif
			"CPU MHz: %f\n"
			"us_per_cycle: %f\n"
			"cycles_per_us: %llu\n"
			"format: (count, cumulative, avg, min)\n"
			"==============================================================\n"
			"\n",
			__ll_cpu_mhz, __ll_us_per_cycle, __ll_cycles_per_us);

	(*__LIBC_PTR(fprintf))(fp, "[_ckpt_timer]\n");
	num_subtimers = sizeof(ckpt_timer_t) / sizeof(my_timer_t);
	for (j = 0; j < num_subtimers; j++) {
		uint64_t avg, best;
		t = ((my_timer_t*)&__ckpt_timer) + j;

		avg = t->count != 0 ? t->cumulative / t->count : 0;

		best = t->best == UINT64_MAX ? 0 : t->best;

		(*__LIBC_PTR(fprintf))(fp, "%19s: ", ckpttimer_str[j]);
#if REPORT_CYCLES
		(*__LIBC_PTR(fprintf))(fp, "(%6llu, %6llu [%6.2f], %6llu [%6.2f], %6llu [%6.2f])\n",
				t->count, t->cumulative, C2USD(t->cumulative),
				avg, C2USD(avg), best, C2USD(best));
#else
		(*__LIBC_PTR(fprintf))(fp, "(%9llu, %9.2f, %9.2f, %9.2f)\n",
				t->count, t->cumulative, C2USD(t->cumulative),
				C2USD(avg), C2USD(best));
#endif
	}

	(*__LIBC_PTR(fprintf))(fp, "\n");

	num_subtimers = sizeof(wrapper_timer_t) / sizeof(my_timer_t);
	for (i = 0; i < __num_wrapper_timers; i++) {
		(*__LIBC_PTR(fprintf))(fp, "[%s]\n", timer_str[i]);
		for (j = 0; j < num_subtimers; j++) {
			uint64_t avg, best;
			t = ((my_timer_t*)&__wrapper_timer[i]) + j;

			avg = t->count != 0 ? t->cumulative / t->count : 0;

			best = t->best == UINT64_MAX ? 0 : t->best;

			(*__LIBC_PTR(fprintf))(fp, "%17s: ", subtimer_str[j]);
#if REPORT_CYCLES
			(*__LIBC_PTR(fprintf))(fp, "(%6llu, %6llu [%6.2f], %6llu [%6.2f], %6llu [%6.2f])\n",
					t->count, t->cumulative, C2USD(t->cumulative),
					avg, C2USD(avg), best, C2USD(best));
#else
			(*__LIBC_PTR(fprintf))(fp, "(%9llu, %9.2f, %9.2f, %9.2f)\n",
					t->count, C2USD(t->cumulative),
					C2USD(avg), C2USD(best));
#endif
		}
		(*__LIBC_PTR(fprintf))(fp, "\n");
	}
}
