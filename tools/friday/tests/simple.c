/* Simple test application that calls random() several times, while
 * getting SIGALRMS from a period timer that fires. SIGINT is also caught,
 * just to test handler affinity. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>

#define STABILIZE_PERIOD 3000000

int global = 2;

void stabilize() {
	printf("stabilize\n");
}

void sig_int_handler(int sig) {
	printf("sig_int_handler\n");
}

int main(int argc, char** argv) {

	int i = 0;
	long r = 0;

	struct itimerval timer, otimer;
	struct sigaction act;
	struct timeval tv;
	struct timezone tz;

#if 1
	timer.it_interval.tv_sec  = STABILIZE_PERIOD / 1000000;
	timer.it_interval.tv_usec = STABILIZE_PERIOD % 1000000;

	timer.it_value.tv_sec  = STABILIZE_PERIOD / 1000000;
	timer.it_value.tv_usec = STABILIZE_PERIOD % 1000000;
#endif

	setitimer(ITIMER_REAL, &timer, &otimer);

	act.sa_handler = stabilize;
	signal(SIGALRM, (void*) stabilize);
	sigaction(SIGALRM, &act, NULL);

	//signal(SIGINT, (void*) sig_int_handler);


	for (i = 0; i < 1000000; i++) {
		r = random();
		gettimeofday(&tv, &tz);
		printf("[%d]: %d %ld %d %d\n", getpid(), i, r, time(NULL), tv.tv_sec);

		sleep(1);
		global = i;

	}

	return 0;
}
