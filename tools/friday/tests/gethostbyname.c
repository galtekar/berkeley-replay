/* Tests the gethostbyname wrappers, which are complicated. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
extern int h_errno;

int main(int argc, char** argv) {

	struct hostent* h;
	char host_name[256];
	int i;

	/* Loop for good measure. */
	for (i = 0; i < 10; i++) {
		if (argc != 2) {
			/*printf("usage: %s [hostname]\n", argv[0]);
			  exit(-1);*/
			strcpy(host_name, "www.google.com");
		} else {
			strcpy(host_name, argv[1]);
		}

		h = gethostbyname(host_name);
		if (!h) {

			printf("error: %s\n", hstrerror(h_errno));
		}

		if (h) {
			printf("h_name=%s h_addrtype=%d h_length=%d\n",
					h->h_name, h->h_addrtype, h->h_length);
		}
	}

	return 0;
}
