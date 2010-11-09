#ifndef FAST_LOGGING_H
#define FAST_LOGGING_H

extern void init_fast_logging();

#define DEBUG 1
#include "debug.h"

#undef FASTLOGENTRY
#define FASTLOGENTRY(name, ...) extern int __ll_##name##_id;
#include "fastlogentries.h"

/* Expand the fast log entry defintions into struct definitions. */
#undef FASTLOGENTRY
#define FASTLOGENTRY(name, ...) typedef struct __ll_##name##_entry { \
   __VA_ARGS__ \
} __ll_##name##_entry_t;
#include "fastlogentries.h"

/* This macro gets a chunk of logger shared memory big enough to
 * fit the data structure A and data of size D, and provides a pointer. */
#define GET_SHM_CHUNK_DATA(a, d) \
 	logentry_header_t* hdrp; \
	int pos_after_this_entry; \
	__ll_##a##_entry_t* e; \
	void* dptr = NULL; \
	\
	/* If after writing this log entry to shared memory, we still
	 * have space in the shared segment, then we needn't force a
	 * flush. */ \
	DEBUG_MSG(3, "get_shm_chunk_data: shmpos=%d addr=0x%x\n", *_private_info.shmpos, _private_info.shmpos); \
	assert(d < LOG_BUF_SIZE); \
	\
	pos_after_this_entry = (*_private_info.shmpos + sizeof(logentry_header_t) + sizeof(__ll_##a##_entry_t) + d); \
	if (pos_after_this_entry >= (_shared_info->shmsize - sizeof(long))) { \
		/* We've run out of space in the shared memory segment.
		 * Thus, we need to ask the logger to flush the contents
		 * of the segment to disk. */ \
		/* Detach from the old shared segment. */  \
		if ((*__LIBC_PTR(shmdt))((void*)_private_info.shmpos) != 0) { \
			fatal("can't detach from the old shared memory segment\n"); \
		} \
		\
		send_log_flush_msg(_shared_info->vclock); \
		/* Reattach to the new shared segment as specified in the ack for 
		 * the log flush message. */ \
		if ((_private_info.shmpos = (int*)(*__LIBC_PTR(shmat))(_shared_info->shmid, \
				(void *) 0, 0)) == (void*)-1) { \
			perror("fast logging:"); \
			fatal("can't attach to new shared segment handed out by log server\n"); \
		} \
		\
		_private_info.shmdata = (char*)_private_info.shmpos + sizeof(int); \
		*_private_info.shmpos = 0; \
	} \
	\
	assert(_private_info.shmdata); \
	assert(_private_info.shmpos); \
	\
	/* Set pointers after obtaining a new segment. */ \
	hdrp = (logentry_header_t*)&_private_info.shmdata[*_private_info.shmpos]; \
	assert(hdrp != NULL); \
	e = (__ll_##a##_entry_t*)&_private_info.shmdata[*_private_info.shmpos + sizeof(logentry_header_t)]; \
	assert(e != NULL); \
	/* The log entry comes immediately after the header, and its
	 * type depends on the log entry type (see entry_types.h). 
	 */ \
	hdrp->id = __ll_##a##_id; \
	hdrp->size = sizeof(__ll_##a##_entry_t) + d; \
	hdrp->vclock = _shared_info->vclock; \
	\
	assert(hdrp->id < num_fastlogentries); \
	\
	*_private_info.shmpos += sizeof(logentry_header_t) + sizeof(__ll_##a##_entry_t); \
	dptr = (void*)&_private_info.shmdata[*_private_info.shmpos]; \
	*_private_info.shmpos += d;

#define GET_SHM_CHUNK(a) GET_SHM_CHUNK_DATA(a, 0)

extern int num_fastlogentries;

#endif
