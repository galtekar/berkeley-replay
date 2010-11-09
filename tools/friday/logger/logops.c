#include <assert.h>
#include <string.h>

#include <sys/time.h>

#include "logreplay.h"
#include "patterns.h"
#include "hexops.h"

#define DEBUG 1

/* Expand the fast log entries into struct definitions. */
#define FASTLOGENTRY(name, ...) typedef struct name##_entry { \
	__VA_ARGS__ \
} name##_entry_t;
#include "fastlogentries.h"

static char io_buf[LOG_BUF_SIZE];

char* __str_string(int64_t vclock, void* ptr) {
	char* e = ptr;

	strcpy(io_buf, e);

	return io_buf;
}

char* __str_ctx_switch(int64_t vclock, void* ptr) {
	ctx_switch_entry_t* e = (ctx_switch_entry_t*) ptr;

	sprintf( io_buf, "<switch pid=%d tid=%lu/>\n",
			e->id.pid, e->id.tid);

	return io_buf;
}

char* __str__errno(int64_t vclock, void* ptr) {
	_errno_entry_t* e = (_errno_entry_t*) ptr;

	sprintf( io_buf, __ERRNO_PAT, e->eval);

	return io_buf;
}

char* __str_time(int64_t vclock, void* ptr) {
	time_entry_t* e = (time_entry_t*) ptr;

	sprintf( io_buf, __TIME_PAT, e->ret, vclock );

	return io_buf;
}

char* __str_random(int64_t vclock, void* ptr) {
	random_entry_t* e = (random_entry_t*) ptr;

	sprintf( io_buf, __RANDOM_PAT, e->ret, vclock );

	return io_buf;
}

char* __str_send(int64_t vclock, void* ptr) {
	send_entry_t* e = (send_entry_t*) ptr;

	char buf_ascii[LOG_BUF_SIZE];

	/* Convert interesting bits to strings for logging. */
	if (e->ret > 0) {
		assert((e->ret*2)+1 < sizeof(buf_ascii));
		hex_encode((void*)(e+1), buf_ascii, e->ret);
	} else {
		strncpy(buf_ascii, "NULL", sizeof(buf_ascii));
	}

	sprintf( io_buf, __LOG_SEND_PAT, e->ret,
#if LOG_SEND_DATA || 1
					buf_ascii,
#else
					"-",
#endif
					e->tag.tag_str, e->tag.vclock,
					vclock);

	return io_buf;
}

char* __str_sendto(int64_t vclock, void* ptr) {
	sendto_entry_t* e = (sendto_entry_t*) ptr;

	const struct sockaddr_in *sin;
	char addr_ascii[LOG_BUF_SIZE];

	/* Determine the ASCII/readable version of the destination address
	 * so that we can log it. */
	assert( e->to.sa_family == AF_INET );
	sin = (const struct sockaddr_in *)&e->to;
	strncpy( addr_ascii, inet_ntoa(sin->sin_addr),
			LOG_BUF_SIZE-1 /* - 1 so that the result will be NULL-terminated. */);

	sprintf( io_buf, __LOG_SENDTO_PAT, e->ret,
					addr_ascii, ntohs(sin->sin_port),
					e->tag.tag_str, e->tag.vclock,
					vclock);

	return io_buf;
}

char* __str_recv(int64_t vclock, void* ptr) {
	recv_entry_t* e = (recv_entry_t*) ptr;

	char buf_ascii[LOG_BUF_SIZE];

	/* Convert interesting bits to strings for logging. */
	if (e->ret > 0) {
		assert((e->ret*2)+1 < sizeof(buf_ascii));
		hex_encode((void*)(e+1), buf_ascii, e->ret);
	} else {
		strncpy(buf_ascii, "NULL", sizeof(buf_ascii));
	}

	sprintf( io_buf, __LOG_RECV_PAT, e->ret,
					buf_ascii,
					e->tag.tag_str, e->tag.vclock,
					vclock);

	return io_buf;
}

char* __str_read(int64_t vclock, void* ptr) {
	read_entry_t* e = (read_entry_t*) ptr;

	char buf_ascii[LOG_BUF_SIZE];

	/* Convert interesting bits to strings for logging. */
	if (e->ret > 0) {
		assert((e->ret*2)+1 < sizeof(buf_ascii));
		hex_encode((void*)(e+1), buf_ascii, e->ret);
	} else {
		strncpy(buf_ascii, "NULL", sizeof(buf_ascii));
	}

	sprintf( io_buf, __LOG_READ_PAT, e->ret,
					buf_ascii,
					e->tag.tag_str, e->tag.vclock,
					vclock);

	return io_buf;
}

char* __str_recvfrom(int64_t vclock, void* ptr) {
	recvfrom_entry_t* e = (recvfrom_entry_t*) ptr;

	const struct sockaddr_in *sin;
	char buf_ascii[LOG_BUF_SIZE];
	char addr_ascii[LOG_BUF_SIZE];

	/* Determine the ASCII/readable version of the destination address
	 * so that we can log it. */
	sin = (const struct sockaddr_in *)&e->from;
	strncpy( addr_ascii, inet_ntoa(sin->sin_addr),
			LOG_BUF_SIZE-1 /* - 1 so that the result will be NULL-terminated. */);

	/* Convert interesting bits to strings for logging. */
	if (e->ret > 0) {
		assert((e->ret*2)+1 < sizeof(buf_ascii));
		hex_encode((void*)(e+1), buf_ascii, e->ret);
	} else {
		strncpy(buf_ascii, "NULL", sizeof(buf_ascii));
	}

	sprintf( io_buf, __LOG_RECVFROM_PAT, e->ret,
					addr_ascii, ntohs(sin->sin_port),
					buf_ascii,
					e->tag.tag_str, e->tag.vclock,
					vclock);

	return io_buf;
}

char* __str_select(int64_t vclock, void* ptr) {
	select_entry_t* e = (select_entry_t*) ptr;

	char readfds_hex_str[(sizeof(fd_set) * 2) + 1];
	char writefds_hex_str[(sizeof(fd_set) * 2) + 1];
	char exceptfds_hex_str[(sizeof(fd_set) * 2) + 1];
	char timeout_hex_str[(sizeof(struct timeval) * 2) + 1];

	strcpy(readfds_hex_str, "NULL");
	strcpy(writefds_hex_str, "NULL");
	strcpy(exceptfds_hex_str, "NULL");
	strcpy(timeout_hex_str, "NULL");

	hex_encode(&e->readfds, readfds_hex_str, sizeof(fd_set));
	hex_encode(&e->writefds, writefds_hex_str, sizeof(fd_set));
	hex_encode(&e->exceptfds, exceptfds_hex_str, sizeof(fd_set));
	hex_encode(&e->timeout, timeout_hex_str, sizeof(struct timeval));

	/* After select returns, it will modify readfds, writefds, exceptfds,
	 * and, in the case of Linux, timeout as well. We need to log those
	 * returned values. */

	sprintf( io_buf, __SELECT_PAT, e->ret,
			readfds_hex_str, writefds_hex_str, exceptfds_hex_str,
			timeout_hex_str, errno, vclock );

	return io_buf;
}

char* __str_gettimeofday(int64_t vclock, void* ptr) {
	gettimeofday_entry_t* e = (gettimeofday_entry_t*) ptr;
	FLAT_STR(struct timeval, tv);
	FLAT_STR(struct timezone, tz);

	hex_encode(&e->tv, tv_flat_str, sizeof(struct timeval));

	hex_encode(&e->tz, tz_flat_str, sizeof(struct timezone));

	sprintf( io_buf, __GETTIMEOFDAY_PAT,
			e->ret, tv_flat_str, tz_flat_str, vclock );

	return io_buf;
}

char* __str_fwrite(int64_t vclock, void* ptr) {
	fwrite_entry_t* e = (fwrite_entry_t*) ptr;

	sprintf( io_buf, __FWRITE_PAT, e->ret,
			vclock );

	return io_buf;
}

char* __str_fflush(int64_t vclock, void* ptr) {
	fflush_entry_t* e = (fflush_entry_t*) ptr;

	sprintf( io_buf, __FFLUSH_PAT, e->ret,
			vclock );

	return io_buf;
}

char* __str_fputs(int64_t vclock, void* ptr) {
	fputs_entry_t* e = (fputs_entry_t*) ptr;

	sprintf( io_buf, __FPUTS_PAT, e->ret,
			vclock );

	return io_buf;
}

char* __str_ferror(int64_t vclock, void* ptr) {
	ferror_entry_t* e = (ferror_entry_t*) ptr;

	sprintf( io_buf, __FERROR_PAT, e->ret,
			vclock );

	return io_buf;
}
