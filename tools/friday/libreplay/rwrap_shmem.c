#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <syscall.h>
#include <signal.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "libc_pointers.h"
#include "logreplay.h"
#include "errops.h"
#include "misc.h"
#include "hexops.h"
#include "patterns.h"

#include "replay.h"
#include "util.h"

/* BSD shared memory support. */
void * replay_mmap(void *start, size_t length, int prot , int flags, int fd,
		off_t offset) {

	void *old_ret, *ret;

	/* pthread_create, for example, invokes mmap. Hence the following. */
	__PREDICATED_CALL_LIBC(ret, mmap, start, length, prot, flags, fd, offset);

	

	//lprintf("mmap 1 (start=0x%x, length=%d, prot=0x%x, flags=0x%x, fd=%d)\n",
		//start, length, prot, flags, fd);
	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __MMAP_PAT, (long*)&old_ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore mmap\n" );
	}

	//lprintf("mmap 1.5 libc_mmap=0x%x old_ret=0x%x\n", __LIBC_PTR(mmap), old_ret);

	/* Observe that we must ask for the same mmap page as that requested
	 * during original execution. Hence the MAP_FIXED. */
	ret = (*__LIBC_PTR(mmap))(old_ret, length, prot, flags | MAP_FIXED, fd, offset);

	//printf("old_ret=0x%x ret=0x%x\n", old_ret, ret);
	/* Make sure we got the same address as the original mmap call. 
	 * Otherwise, all bets are off. */
	assert(ret == old_ret);

	TRAP();

	return ret;
}

int replay_munmap(void *start, size_t length) {

	int old_ret, ret;

	/* pthread_join, for example, invokes munmap. Hence the following. */
	__PREDICATED_CALL_LIBC(ret, munmap, start, length);

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __MUNMAP_PAT, &old_ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore munmap\n" );
	}

	ret = (*__LIBC_PTR(munmap))(start, length);

	/* We should get the same return value as during original execution. */
	assert(ret == old_ret);

	TRAP();

	return ret;
}

int replay_shmget(key_t key, size_t size, int shmflg) {

	int old_ret, ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SHMGET_PAT, &old_ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore shmget\n" );
	}

	ret = (*__LIBC_PTR(shmget))(key, size, shmflg);

	/* We should get the same return value as during original execution. */
	//assert(ret == old_ret);
	/* NOTE: the above assertion is naturally not valid, since if key
	 * == IPC_PRIVATE, then shmget will return an shmid that may differ 
	 * from that of the original execution. */

	TRAP();

	return ret;
}

void* replay_shmat(int shmid, const void *shmaddr, int shmflg) {
	
	void* old_ret, *ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SHMAT_PAT, (long*)&old_ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore shmat\n" );
	}

	/* Try to attach the segment to the same place as it was attached
	 * during logging. We don't use shmaddr since that may be NULL. 
	 * The attachment address chosen by shmat in such a case will be
	 * stored in old_ret. */
	/* Ignore the above comment for now. This remains a bug. */
	ret = (*__LIBC_PTR(shmat))(shmid, shmaddr, shmflg);

	//perror("shmat");
	warning("BUG (FIX THIS SOMEHOW!): replay_shmat() ret=%p old_ret=%p\n", ret, old_ret);
	
	/* We should get the same return value as during original execution. */
	//assert(ret == old_ret);

	TRAP();

	return ret;
}

int replay_shmdt(const void *shmaddr) {
	int old_ret, ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SHMDT_PAT, &old_ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore shmdt\n" );
	}

	ret = (*__LIBC_PTR(shmdt))(shmaddr);

	/* NOTE: old_ret and ret do not necessarily have to be equal since 
	 * shmdt is often called to clean up a segment even though it may 
	 * not exist. This is done for good measure, and therefore sometimes 
	 * fails if the segment has already been cleaned up. */

	TRAP();

	return ret;
}

#define LOG_MUTEX 0


int replay_pthread_mutex_lock(pthread_mutex_t* mutex) {
	int ret;

#if LOG_MUTEX
	if (! LOG_TO_BUF() || (sscanf(libreplay_io_buf, __PTHREAD_MUTEX_LOCK_PAT, &ret, 
					&_shared_info->vclock) != 2)) {
		stop_replay("could not restore pthread_mutex_lock\n");
	}
#endif
	ret = __LIBC_PTR(pthread_mutex_lock)(mutex);

	TRAP();

	return ret;
}

int replay_pthread_mutex_unlock(pthread_mutex_t* mutex) {
	int ret;

#if LOG_MUTEX
	if (! LOG_TO_BUF() || (sscanf(libreplay_io_buf, __PTHREAD_MUTEX_UNLOCK_PAT, &ret,
					&_shared_info->vclock) != 2)) {
		stop_replay("could not restore pthread_mutex_unlock\n");
	}
#endif

	ret = __LIBC_PTR(pthread_mutex_unlock)(mutex);

	TRAP();

	return ret;
}
