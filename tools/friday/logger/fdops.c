#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"

/* Sends a message to the log server. Work like send(), but ensures
 * that all LEN bytes are sent. */
ssize_t safe_write(int fd, char* buf, size_t len)  {
	size_t bytes_written = 0;
	ssize_t bytes_out;
	char *bufp;

	/* TODO: avoid copying by using sendmsg()!! */

	bufp = buf;
	while (bytes_written < len) {
		if ((bytes_out = write(fd, bufp, 
						len - bytes_written)) < 0) {
			perror("send");

			if (errno != EINTR) {
				return -1;
			}
		}

		bufp += bytes_out;
		bytes_written += bytes_out;
	}

	return len;
}

/* Reads LEN bytes from socket FD info BUF. It works just like
 * recv() except that it ensures that you get all LEN bytes. */
ssize_t safe_read(int fd, void* buf, size_t len) {
	int packet_len;
	char *bufp = buf;
	size_t received_so_far = 0;

	while (received_so_far < len) {
		errno = 0;
		packet_len = read(fd, bufp, len - received_so_far);

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
