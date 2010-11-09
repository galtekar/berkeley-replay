#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <assert.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/wait.h>

long *shared = NULL;

int main() {

	int i = 0;
	long r = 0;
	pthread_mutex_t* mut;
	pid_t pid;

#if 0
	shared = (long*) mmap((void*)0x55053000, getpagesize(), PROT_READ | PROT_WRITE,
		MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, 0, 0);
#else
	shared = (long*) mmap(0x0, getpagesize(), PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, 0, 0);
#endif
	if (shared == (void*)-1) {
		perror("mmap");
		exit(-1);
	}

	/* 1st chunk of shared memory is used for the lock. */
	mut = (pthread_mutex_t*) shared;
	pthread_mutex_init(mut, NULL);

	/* 2nd chunk is used for the actual data. */
	shared = (long*)((char*)shared + sizeof(pthread_mutex_t));

	pid = fork();

	for (i = 0; i < 1000000; i++) {
		r = random();
		printf("[%d]: %d %ld\n", getpid(), i, r);

		pthread_mutex_lock(mut);
		*shared = r;
		pthread_mutex_unlock(mut);
	}

	if (pid) {
		/* We need this so that our test script will not prematurely
		 * perform a diff. This can happen if the parent process
		 * terminates before the child does. */
		wait(0);
	}

	return 0;
}
