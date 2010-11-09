/* Do condition variables work between Linux processes? The answer is no,
 * as this little test demonstrates. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <assert.h>
#include <pthread.h>

#include <sched.h>

#include <sys/mman.h>

long *shared = NULL;

int main() {

	int i = 0;
	long r = 0;
	pthread_mutex_t* mut;
	pthread_cond_t* cond;
	char* shmptr;

	shared = (long*) mmap(0x0, getpagesize(), PROT_READ | PROT_WRITE, 
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert(shared);

	shmptr = (char*)shared;

	/* 1st chunk of shared memory is used for the lock. */
	mut = (pthread_mutex_t*) shared;
	shmptr += sizeof(pthread_mutex_t);

	
	/* 2nd chunk used for condition variable. */
	cond = (pthread_cond_t*)shmptr;
	shmptr += sizeof(pthread_cond_t);

	/* 2nd chunk is used for the actual data. */
	shared = (long*)shmptr;

	/* Initialize the syncrhonization variables. */
	pthread_mutex_init(mut, NULL);
	pthread_cond_init(cond, NULL);

	fork();

	pthread_mutex_lock(mut);
	for (i = 0; i < 100; i++) {
		r = random();
		printf("[%d:%d]: %ld\n", getpid(), getpgrp(), r);

		*shared = r;

		/* Handoff the CPU to the other process. */
		pthread_cond_signal(cond);
		pthread_cond_wait(cond, mut);
		printf("here\n");
	}

	return 0;
}
