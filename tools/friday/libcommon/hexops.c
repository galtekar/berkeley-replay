#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "errops.h"
#include "gcc.h"

/* Reads size bytes froom in_buf, converts them to ascii hex, and stores
 * resulting string in out_buf. */
void HIDDEN hex_encode(void* in_buf, char* out_buf, size_t size) {
	char *src, *dst;
	int i = 0;

	assert(in_buf != NULL);
	assert(out_buf != NULL);
	assert(size > 0);

	src = in_buf;
	dst = out_buf;

	while (i < size) {
		sprintf(dst, "%.2hhx", *src);

		src++;
		dst += 2;

		i++;
	}

	/* Terminate the string. */
	*dst = 0;

	assert(strlen(out_buf) == 2*size);
}

/* Converts a hex string in in_buf into binary, for at most size bytes,
 * and stores the result in out_buf. */
void HIDDEN hex_decode(char* in_buf, void* out_buf, size_t size) {
	char *src, *dst;
	int i = 0;

	assert(in_buf != NULL);
	assert(out_buf != NULL);
	assert(size > 0);

	assert(strlen(in_buf) % 2 == 0);
	//printf("here: strlen=%d size=%d\n", strlen(in_buf), size);

	src = in_buf;
	dst = out_buf;

	while (i < size) {
		if (sscanf(src, "%2hhx", dst) != 1) {
			fatal("hex_decode: malformed hex string: %s\n", in_buf);
		}

		dst++;
		src += 2;/* We just read in 2 hex characters, which equals 1 byte */

		i++;
	}
}
