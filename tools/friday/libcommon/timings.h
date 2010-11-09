#ifndef TIMINGS_H
#define TIMINGS_H

#define MAX_NUM_WRAPPERS 256
#define MAX_TIMER_NAME_SIZE 256

/* Finally, at the third level, each subtimer, has a set of collection
 * values. Note that the name timer_t is already used by <time.h> . */
typedef struct my_timer {
	uint64_t start;	/* Temporary that stores start of timing. */
	uint64_t end;	/* Temporary that stores end of timing. */
	uint64_t diff;	/* Temporary that stroes the diff between end and start. */
	uint64_t best;	/* The best time seen so far for this subtimer. */
	uint64_t cumulative;	/* The total amount of time spent on subtimer. */
	uint64_t count;	/* The number of observations made on this subtimer. */
} my_timer_t;

typedef struct wrapper_timer {
	my_timer_t _wrapper;
	my_timer_t _wrapper_call;
	my_timer_t _cosched;
	my_timer_t _shm_write;
	my_timer_t _hex_encode;
	my_timer_t _entry_creation; 
	my_timer_t _entry_to_logger;
	my_timer_t _other;
	my_timer_t _call_libc;
} wrapper_timer_t;

typedef struct ckpt_timer {
	my_timer_t _rotate_log_if_time;
	my_timer_t _logger_rotate;
	my_timer_t _drop_checkpoint;
	my_timer_t _ckpt_save;
	my_timer_t _read_self_regions;
} ckpt_timer_t;

/* Stores timer structure. */
extern wrapper_timer_t __wrapper_timer[MAX_NUM_WRAPPERS];
extern ckpt_timer_t __ckpt_timer;

/* Guess what this function does? */
extern void print_timing_stats();

extern void init_timers();

extern int alloc_new_wrapper_timer(char* name);

extern int64_t timers_have_been_initialized;


/* These wrappers should be carefully constructed so as to avoid imposing
 * undue overhead. We don't want to get as accurate measurements as
 * possible. */

/* CPU cycle counter. */
#define CLOCK(val) __asm__ __volatile__("rdtsc" : "=A" (val))

#if ENABLE_TIMINGS || 1
/* Begin timing. A is the timer, B is the subtimer. */
#define __START_WRAPPER_TIMER(a, b) { \
	/* For our micro-benchmark timers. */ \
	if (timers_have_been_initialized == 0xfeedbeaddeadbeefLL) { \
	CLOCK(__wrapper_timer[(a)].b.start); \
	} \
}

/* Stop the timer, and store minimal statistics. */
#define __STOP_WRAPPER_TIMER(a, b) { \
	if (timers_have_been_initialized == 0xfeedbeaddeadbeefLL) { \
	CLOCK(__wrapper_timer[(a)].b.end); \
	/* Do a minimal amount of work here. There may be enclosing
	 * timers (i.e., nested timers). */ \
	__wrapper_timer[(a)].b.diff = __wrapper_timer[(a)].b.end -  \
		__wrapper_timer[(a)].b.start; \
	__wrapper_timer[(a)].b.best = __wrapper_timer[(a)].b.diff <  \
		__wrapper_timer[(a)].b.best ? \
						__wrapper_timer[(a)].b.diff : \
						__wrapper_timer[(a)].b.best; \
	__wrapper_timer[(a)].b.cumulative += __wrapper_timer[(a)].b.diff; \
	__wrapper_timer[(a)].b.count++; \
	} \
}

/* Begin timing. A is the timer, B is the subtimer. */
#define __START_CKPT_TIMER(b) { \
		if (timers_have_been_initialized == 0xfeedbeaddeadbeefLL) { \
		CLOCK(__ckpt_timer.b.start); \
		} \
}

/* Stop the timer, and store minimal statistics. */
#define __STOP_CKPT_TIMER(b) { \
		if (timers_have_been_initialized == 0xfeedbeaddeadbeefLL) { \
	CLOCK(__ckpt_timer.b.end); \
	/* Do a minimal amount of work here. There may be enclosing
	 * timers (i.e., nested timers). */ \
	__ckpt_timer.b.diff = __ckpt_timer.b.end - \
		__ckpt_timer.b.start; \
	__ckpt_timer.b.best = __ckpt_timer.b.diff < \
		__ckpt_timer.b.best ? \
					__ckpt_timer.b.diff : __ckpt_timer.b.best; \
	__ckpt_timer.b.cumulative += __ckpt_timer.b.diff; \
	__ckpt_timer.b.count++; \
		} \
}

#else
#define __START_WRAPPER_TIMER(a, b)
#define __STOP_WRAPPER_TIMER(a, b)
#define __START_CKPT_TIMER(b)
#define __STOP_CKPT_TIMER(b)
#endif

#endif
