#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <syscall.h>
#include <signal.h>
#include <pthread.h>

#define __USE_GNU
#include <ucontext.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <arpa/inet.h>

#include "patterns.h"
#include "libc_pointers.h"
#include "log.h"
#include "sendlog.h"
#include "lwrap_sigs.h"
#include "util.h"
#include "lwrap.h"
#include "timers.h"

#include "logreplay.h"
#include "tmalloc.h"
#include "misc.h"
#include "errops.h"
#include "hexops.h"

#define DEBUG 0

/* BSD shared memory support. */
void* log_mmap(void* start, size_t length, int prot, int flags, int fd, off_t offset) {

	void* ret;

#if DEBUG
	dprintf("calling log_mmap()\n");
	printf("start=0x%x length=%d prot=0x%x flags=0x%x fd=%d offste=%d\n",
		start, length, prot, flags, fd, offset);
#endif

	__CALL_LIBC(ret, mmap, start, length, prot, flags, fd, offset);	

	advance_vclock();

	if (!LOG( __MMAP_PAT, (unsigned long)ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			"mmap\n");
	}

	POST_WRAPPER_CLEANUP();
	
	return ret;
}

int log_munmap(void* start, size_t length) {

	int ret;

#if DEBUG
	dprintf("calling log_munmap()\n");
#endif

	__CALL_LIBC(ret, munmap, start, length);

	advance_vclock();

	if (!LOG( __MUNMAP_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			"munmap\n");
	}

	POST_WRAPPER_CLEANUP();
	
	return ret;
}


/* System V shared memory support. */
int log_shmget(key_t key, size_t size, int shmflg) {
	int ret;

#if DEBUG
	dprintf("calling log_shmget()\n");
#endif

	__CALL_LIBC(ret, shmget, key, size, shmflg);

	advance_vclock();

	if (!LOG( __SHMGET_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			"shmget\n");
	}

	POST_WRAPPER_CLEANUP();
	
	return ret;
}

void* log_shmat(int shmid, const void *shmaddr, int shmflg) {
	void* ret;

#if DEBUG
	dprintf("calling log_shmat()\n");
#endif

	__CALL_LIBC(ret, shmat, shmid, shmaddr, shmflg);

	advance_vclock();

	if (!LOG( __SHMAT_PAT, (unsigned long)ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			"shmat\n");
	}

	POST_WRAPPER_CLEANUP();
	
	return ret;
}

int log_shmdt(const void *shmaddr) {
	int ret;

#if DEBUG
	dprintf("calling log_shmdt()\n");
#endif

	__CALL_LIBC(ret, shmdt, shmaddr);

	advance_vclock();

	if (!LOG( __SHMDT_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			"shmdt\n");
	}

	POST_WRAPPER_CLEANUP();
	
	return ret;
}
