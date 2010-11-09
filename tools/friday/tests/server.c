/* This program measures the time it takes to call a nondeterministic function,
 * which in this case is chosen to be the ``time'' function. This should
 * be wrapped, so you can measure overhead by running this without liblog
 * and then running it with liblog. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <dlfcn.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <assert.h>

#include "cycle_time.h"

struct hostent *hp;

static int (*__my_rand)(void);

void work(int count) {
}

void my_usleep(int count) {
	int i;
	int j;

	for (j = 0; j < count; j++)
		for (i = 0; i < 20; i++) {
			work(i);
		}
}

int main(int argc, char** argv) {
	struct sockaddr_in sout, dest;
	int s;
	int num_packets;
	int num_bytes = 0x1 << 30;
	int i, packet_size = 1024;
	struct timeval start, stop;
	int count = 0;
	char hostname[256];

	strcpy(hostname, "gautam.kicks-ass.org");

	if (argc == 3) {
		strcpy(hostname, argv[1]);
		packet_size = atoi(argv[2]);
		//num_bytes = atoi(argv[3]);
	} else if (argc > 1) {
		fprintf(stderr, "usage: %s <host> <packet_size>\n", argv[0]);
		exit(-1);
	}

	num_packets = num_bytes / packet_size;

	printf("Sending %d packets, each of size %d, for a total of %d bytes.\n",
			num_packets, packet_size, num_bytes);

	hp = gethostbyname(hostname);
	assert(hp != NULL);

	memset(&sout, 0x0, sizeof(sout));
	sout.sin_family = AF_INET;
	sout.sin_port = htons(0);
	sout.sin_addr.s_addr = htonl(INADDR_ANY);


	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(20000);
	dest.sin_addr.s_addr = *((in_addr_t*)hp->h_addr);

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket failed");
		exit(-1);
	}

	if (bind(s, (struct sockaddr *) &sout, sizeof(sout)) < 0) {
		perror("bind failed");
		exit(-1);
	}

	{
		/* Get a pointer to libc's rand() function. We don't want
		 * to have our calls to rand logged. */
		void *rh = NULL;

		rh = dlopen("libc.so.6", RTLD_NOW);

		*(void **) (&__my_rand) = dlsym(rh, "rand");

		assert(__my_rand != NULL);
	}

	{
		char buf[packet_size];
		float transferred = 0.0;
		int j;

		memset(buf, 0x0, sizeof(buf));
#if 0
		/* Initialize the buffer with random data. This was also
		 * warm-up the cache. */
		printf("Randomizing bytes.\n");
		for (j = 0; j < bytes; j += sizeof(int)) {
			*((int*)(buf+j)) = (*__my_rand)();
		}
#endif

#if 0
		for (j = 0; j < packet_size; j += sizeof(int)) {
			*(((int*)(buf+j))) = (*__my_rand)();	
		}
#endif


		gettimeofday(&start, NULL);

		for (i = 0; i < num_packets; i++) {
			int n;

			n = 0;
#if 0
		for (j = 0; j < packet_size; j += sizeof(int)) {
			*(((int*)(buf+j))) = (*__my_rand)();	
		}
#endif

			do {
				count++;
				int t = sendto(s, buf, packet_size - n, 0, 
						(struct sockaddr*)&dest, sizeof(dest));
				if (t <= 0) {
					perror("sendto failed");
					exit(-1);
				}

				n += t;
			} while (n < packet_size);

			transferred = (float) i / (float) num_packets;
			///fprintf(stderr, "%4.2f\b\b\b\b", transferred);
		}
	}

	gettimeofday(&stop, NULL);

	{
		int tt_sec, tt_usec;

		tt_usec = (stop.tv_sec*1000000 + stop.tv_usec) - 
			(start.tv_sec*1000000 + start.tv_usec);
		printf("Done with transfer [%d (us), %d (s)].\n", tt_usec, tt_usec/1000000);
		printf("Packet size [%d].\n", packet_size);
		printf("Number of sendto calls [%d].\n", count);
		printf("Number of packets sent [%d].\n", num_packets);
	}

	return 0;
}
