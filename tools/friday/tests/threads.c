/* Test liblog/libreplay's threading support. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <linux/unistd.h>

static void* start_routine(void* arg) {
	int i;

	for (i = 0; i < 10; i++) {
		printf("tid %lu says hello\n", pthread_self());
		sleep(1);
	}

	pthread_exit(NULL);

	return NULL;
}

int main(int argc, char** argv) {
	int num_threads;
	int i;

	if (argc != 2) {
		/*printf("usage: %s [num_threads]\n", argv[0]);
		exit(-1);*/
		num_threads = 32;
	} else {
		num_threads = atoi(argv[1]);
	}

{
	pthread_t tid[num_threads];

	for (i = 0; i < num_threads; i++) {
		if (pthread_create(&tid[i], NULL, &start_routine, 
			(void*)&tid[i]) != 0) {
			perror("pthread_create");
			exit(-1);
		}
	}
	
	for (i = 0; i < num_threads; i++) {
		if (pthread_join(tid[i], NULL) != 0) {
			perror("pthread_join");
			exit(-1);
		}
	}

}

	return 0;
}
