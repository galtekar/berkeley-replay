#ifndef SYNCOPS_H
#define SYNCOPS_H

#include <pthread.h>

#define FUTEX_WAIT (0)
#define FUTEX_WAKE (1)
#define FUTEX_FD (2)
#define FUTEX_REQUEUE (3)

typedef struct my_cond {
	/* Lock associated with the condition variable. */
	pthread_mutex_t lock;

	unsigned int woken_seq;
	unsigned int wakeup_seq;
	unsigned int total_seq;
} my_cond_t;

typedef struct my_barrier {
	int count;

	pthread_mutex_t mutex;
	my_cond_t cond;

} my_barrier_t;


/* Barrier. */
extern void my_barrier_init(my_barrier_t *b);
extern void my_barrier_wait(my_barrier_t* b, int num_threads);

/* Condition variables. */
extern void my_cond_init(my_cond_t* pcv);
extern void my_cond_wait(my_cond_t* pcv, pthread_mutex_t* mut);
extern void my_cond_signal(my_cond_t* pcv);
extern void my_cond_broadcast(my_cond_t* pcv);

#endif
