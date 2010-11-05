#include <stdio.h>
#include <string.h>

#include "errops.h"
#include "debug.h"

/* Reads size bytes froom in_buf, converts them to ascii hex, and stores
 * resulting string in out_buf. */
void hex_encode(char* out_buf, const size_t out_size, const char* in_buf, 
                const size_t size) 
{
	const char *src;
   char *dst;
	int i = 0;

	ASSERT(in_buf != NULL);
	ASSERT(out_buf != NULL);
	ASSERT(size > 0);

	src = in_buf;
	dst = out_buf;

	while (i < size && dst < (out_buf+out_size)) {
		sprintf(dst, "%.2hhx", *src);

		src++;
		dst += 2;

		i++;
	}

	/* Terminate the string. */
	*dst = 0;

	ASSERT(strlen(out_buf) == 2*size);
}

/* Converts a hex string in in_buf into binary, for at most size bytes,
 * and stores the result in out_buf. */
void hex_decode(char* out_buf, const size_t out_size, const void* in_buf, 
                const size_t size) 
{
	const char *src;
   char *dst;
	int i = 0;

	ASSERT(in_buf != NULL);
	ASSERT(out_buf != NULL);
	ASSERT(size > 0);

	ASSERT(strlen(in_buf) % 2 == 0);
	//printf("here: strlen=%d size=%d\n", strlen(in_buf), size);

	src = in_buf;
	dst = out_buf;

	while (i < size && dst < (out_buf + out_size)) {
		if (sscanf(src, "%2hhx", dst) != 1) {
			FATAL("hex_decode: malformed hex string: %s\n", in_buf);
		}

		dst++;
		src += 2;/* We just read in 2 hex characters, which equals 1 byte */

		i++;
	}
}
