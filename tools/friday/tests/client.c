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
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <assert.h>

#include "cycle_time.h"

int main(int argc, char** argv) {
	struct sockaddr_in sout, from;
	int s, fromlen = sizeof(int);
	int num_packets = 0x1 << 30;
	int i, packet_size = 1024;
	struct timeval start, stop;

	if (argc == 3) {
		packet_size = atoi(argv[1]);
		num_packets = atoi(argv[2]);
	} else if (argc > 1) {
		fprintf(stderr, "usage: %s [packet_size] [num_packets]\n", argv[0]);
		exit(-1);
	}

	memset(&sout, 0x0, sizeof(sout));
	sout.sin_family = AF_INET;
	sout.sin_port = htons(20000);
	sout.sin_addr.s_addr = htonl(INADDR_ANY);

	memset(&from, 0, sizeof(from));

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket failed");
		exit(-1);
	}

	if (bind(s, (struct sockaddr *) &sout, sizeof(sout)) < 0) {
		perror("bind failed");
		exit(-1);
	}

	{
		char buf[packet_size];
		float transferred = 0.0;

		memset(buf, 0x0, sizeof(buf));
		for (i = 0; i < num_packets; i++) {
			int n;

			n = 0;

			do {
				int r = recvfrom(s, buf, packet_size - n, 0, 
						(struct sockaddr*)&from,
						&fromlen);

				if (r <= 0) {
					perror("recvfrom failed");
					exit(-1);
				}

				n += r;
			} while (n < packet_size);	

			if (i == 0) {
				/* Start the timer. */
				gettimeofday(&start, NULL);
			}

			transferred = (float) i / (float) num_packets;
			//fprintf(stderr, "%4.2f", transferred);
		}

		/* Stop the timer. */
		gettimeofday(&stop, NULL);
	}

	{
		long transfer_time = stop.tv_sec - start.tv_sec;
		printf("Done with transfer [%d].\n", transfer_time);
	}

	return 0;
}
