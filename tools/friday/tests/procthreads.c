/* Fork multiple processes, each with multiple threads. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <linux/unistd.h>

static void* start_routine(void* arg) {
	int i;

	for (i = 0; i < 10; i++) {
		printf("pid %d tid %lu says hello\n", getpid(), pthread_self());
		sleep(1);
	}

	//pthread_exit(NULL);

	return NULL;
}

int main(int argc, char** argv) {
	int num_threads;
	int num_procs;
	int i, status;

	if (argc != 3) {
		/*printf("usage: %s [num_threads]\n", argv[0]);
		exit(-1);*/
		num_threads = 128;
		num_procs = 2;
	} else {
		num_procs = atoi(argv[1]);
		num_threads = atoi(argv[2]);
	}

	{
		pthread_t tid[num_threads];
		int pid[num_procs-1];

		for (i = 0; i < num_procs-1; i++) {
			if ((pid[i] = fork())) {

			} else {
				break;
			}
		}

		for (i = 0; i < num_threads; i++) {
			int errnosv;
			if (pthread_create(&tid[i], NULL, &start_routine,
						(void*)&tid[i]) != 0) {
				errnosv = errno;
				perror("pthread_create");
				printf("errno=%d\n", errno);
				exit(-1);
			}
		}

		for (i = 0; i < num_threads; i++) {
			pthread_join(tid[i], NULL);
		}

		for (i = 0; i < num_procs-1; i++) {
			if (pid[i]) {
				/* We need this so that our test script will not prematurely
				 * perform a diff. This can happen if the parent process
				 * terminates before the child does. */
				waitpid(pid[i], &status, 0);
			}
		}
	}

	return 0;
}
