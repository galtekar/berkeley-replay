/* IMPORTANT: DO NOT place inclusion headers in this file. They were
 * left out on purpose so that we can include this file in multiple
 * places in the same file. */
#include "logreplay.h"

FASTLOGENTRY(string,
	//char dummy;	/* Not actually used. */
);

FASTLOGENTRY(ctx_switch, 
	thread_id_t id;
);

FASTLOGENTRY(_errno,
	int eval;
);

FASTLOGENTRY(time,
	time_t ret;
);

FASTLOGENTRY(random,
	long int ret;
);

FASTLOGENTRY(sendto,
	ssize_t ret;
	struct sockaddr to;
	tag_t tag;
);

FASTLOGENTRY(recvfrom,
	ssize_t ret;
	struct sockaddr from;
	tag_t tag;
);

FASTLOGENTRY(send,
	ssize_t ret;
	tag_t tag;
);

FASTLOGENTRY(recv,
	ssize_t ret;
	tag_t tag;
);

FASTLOGENTRY(read,
	ssize_t ret;
	tag_t tag;
);

FASTLOGENTRY(fwrite,
	ssize_t ret;
);

FASTLOGENTRY(fflush,
	ssize_t ret;
);

FASTLOGENTRY(fputs,
	ssize_t ret;
);

FASTLOGENTRY(ferror,
	ssize_t ret;
);

#if 0
FASTLOGENTRY(fgets,
	ssize_t ret;
);
#endif


FASTLOGENTRY(gettimeofday,
	ssize_t ret;
	struct timeval tv;
	struct timezone tz;
);

FASTLOGENTRY(select,
	ssize_t ret;
	fd_set readfds;
	fd_set writefds;
	fd_set exceptfds;
	struct timeval timeout;
);
