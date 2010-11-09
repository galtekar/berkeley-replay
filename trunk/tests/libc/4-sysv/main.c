#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>

long *shared = NULL;

int main() {

	int i = 0, shmid, pid;
	long r = 0;
	pthread_mutex_t* mut;

	if ((shmid = shmget(IPC_PRIVATE, 1024, 0644 | IPC_CREAT)) == -1) {
		perror("shmget");
		exit(-1);
	}

	if ((shared = shmat(shmid, NULL, 0)) == (void*)-1) {
		perror("shmat");
		exit(-1);
	}

	/* 1st chunk of shared memory is used for the lock. */
	mut = (pthread_mutex_t*) shared;

	/* 2nd chunk is used for the actual data. */
	shared = (long*)((char*)shared + sizeof(pthread_mutex_t));

	/* After fork, child should inherit the attached shared memory
	 * segment from the parent (according to man shmat (2)). */
	pid = fork();

	for (i = 0; i < 10; i++) {
		r = random();
		printf("[%d:%d]: %ld\n", getpid(), getpgrp(), r);

		pthread_mutex_lock(mut);
		*shared = r;
		pthread_mutex_unlock(mut);

		sleep(1);
	}

	if (pid) {
		wait(0);
	}

	return 0;
}
