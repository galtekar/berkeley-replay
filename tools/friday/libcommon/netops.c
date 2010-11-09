#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>


#include "errops.h"
#include "gcc.h"
#include "libc_pointers.h"

/* Sends a message to the log server. Work like send(), but ensures
 * that all LEN bytes are sent. */
ssize_t HIDDEN barf(int network, char* buf, size_t len)  {
	size_t bytes_written = 0;
	ssize_t bytes_out;
	char *bufp;

	/* TODO: avoid copying by using sendmsg()!! */

	bufp = buf;
	while (bytes_written < len) {
		if ((bytes_out = (*__LIBC_PTR(send))(network, bufp, 
						len - bytes_written, 0)) < 0) {
			perror("send");

			if (errno != EINTR) {
				fatal("barf: can't send data\n");
			}
		}

		bufp += bytes_out;
		bytes_written += bytes_out;
	}

	return len;
}

/* Reads LEN bytes from socket NETWORK info BUF. It works just like
 * recv() except that it ensures that you get all LEN bytes. */
ssize_t HIDDEN snarf(int network, void* buf, size_t len, int flags) {
	int packet_len;
	char *bufp = buf;
	size_t received_so_far = 0;

	while (received_so_far < len) {
		errno = 0;
		packet_len = (*__LIBC_PTR(recv))(network, bufp, len - received_so_far,
				flags);

		if (packet_len > 0) {
			/* Place the incoming data in the appropriate place in the buffer. */
			bufp += packet_len;

			/* Update how much we have received so far. */
			received_so_far += packet_len;
		} else {
			/* recv() may have been interrupted by a system call. In such a
			 * case, try again rather than returning. */
			if (errno != EINTR) {
				if (packet_len < 0) perror("recv");
				return packet_len;
			}
		}
	}

	assert(received_so_far == len);

	return received_so_far;
}
