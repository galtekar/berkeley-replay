/* Simple test application that calls random() several times, while
 * getting SIGALRMS from a period timer that fires. SIGINT is also caught,
 * just to test handler affinity. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#define STABILIZE_PERIOD 3000000

void stabilize(int sig) {
	printf("stabilize\n");
}

void sig_int_handler(int sig) {
	printf("sig_int_handler\n");
}

int main() {

	int i = 0;
	long r = 0;

	struct itimerval timer, otimer;

	timer.it_interval.tv_sec  = STABILIZE_PERIOD / 1000000;
	timer.it_interval.tv_usec = STABILIZE_PERIOD % 1000000;

	timer.it_value.tv_sec  = STABILIZE_PERIOD / 1000000;
	timer.it_value.tv_usec = STABILIZE_PERIOD % 1000000;

	setitimer(ITIMER_REAL, &timer, &otimer);

	signal(SIGALRM, stabilize);
	signal(SIGINT, sig_int_handler);

	for (i = 0; i < 10; i++) {
		r = random();
		printf("[%d]: %d %d\n", getpid(), i, r);
		sleep(1);
	}

	return 0;
}
