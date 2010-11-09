/* This program measures the time it takes to call a nondeterministic function,
 * which in this case is chosen to be the ``time'' function. This should
 * be wrapped, so you can measure overhead by running this without liblog
 * and then running it with liblog. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <dlfcn.h>

#include <assert.h>

#include "cycle_time.h"

#define NUM_WARMUP_ITERS 1000
#define NUM_ITERS 10000


int i = 0;
uint64_t time_before, time_after, delta, min_delta = INT64_MAX;
uint64_t running_sum = 0;
uint64_t warm_running_sum = 0;
double warm_avg_time, avg_time;
struct hostent *hp;

void measure_sendto(int packet_size) {
	struct sockaddr_in sout, dest;
	int s, j;
	char buf[packet_size];

	min_delta = INT64_MAX;


	memset(&sout, 0x0, sizeof(sout));
	sout.sin_family = AF_INET;
	sout.sin_port = htons(0);
	sout.sin_addr.s_addr = htonl(INADDR_ANY);


	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = 20000;
	dest.sin_addr.s_addr = *((in_addr_t*)hp->h_addr);

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket failed");
		exit(-1);
	}

	if (bind(s, (struct sockaddr *) &sout, sizeof(sout)) < 0) {
		perror("bind failed");
		exit(-1);
	}

	/* Warmup. */
	for (i = 0; i < NUM_WARMUP_ITERS; i++) {
	for (j = 0; j < packet_size; j++) {
		buf[j] = (char)rand();
	}
		time_before = get_cpu_ticks();
		if (sendto(s, buf, sizeof(buf), 0, (struct sockaddr*)&dest,
			sizeof(dest)) < 0) {
				perror("sendto failed");
				exit(-1);
		}
		time_after = get_cpu_ticks();

		delta = time_after - time_before;
		if (delta < min_delta) min_delta = delta;
		warm_running_sum += delta;
	}

	/* The real thing. */
	for (i = 0; i < NUM_ITERS; i++) {
	for (j = 0; j < packet_size; j++) {
		buf[j] = (char)rand();
	}
		time_before = get_cpu_ticks();
		if (sendto(s, buf, sizeof(buf), 0, (struct sockaddr*)&dest,
			sizeof(dest)) < 0) {
				perror("sendto failed");
				exit(-1);
		}
		time_after = get_cpu_ticks();
		delta = time_after - time_before;
		if (delta < min_delta) min_delta = delta;
		running_sum += delta;
	}
	
	avg_time = (double)running_sum / (double)NUM_ITERS;
	warm_avg_time = (double)warm_running_sum / (double)NUM_WARMUP_ITERS;

#if 0
	printf("warm up average time: %f micros (%f cycles)\n", 
		warm_avg_time * us_per_cycle, warm_avg_time);
	printf("steady state average time: %f micros (%f cycles)\n", 
		avg_time * us_per_cycle, avg_time);
#endif
	printf("minimum time over all: %f micros (%llu cycles)\n",
		min_delta * us_per_cycle, min_delta);

	close(s);
}

int main(int argc, char** argv) {
	int packet_size = 1024;

	if (argc == 2) {
		packet_size = atoi(argv[1]);
	}

	/* The objective is to send google a few packets. */

	hp = gethostbyname("localhost");

	printf("Measuring sendto()...\n");
	printf("packet_size = %d\n", packet_size);

	measure_sendto(packet_size);


	return 0;
}
