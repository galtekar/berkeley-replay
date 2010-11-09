#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>
#include <assert.h>
#include <errno.h>
#include <syscall.h>
#include <signal.h>
#include <pthread.h>
#include <grp.h>

#define __USE_GNU
#include <ucontext.h>

#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "libc_pointers.h"
#include "logger.h"
#include "log.h"
#include "sendlog.h"
#include "cosched.h"
#include "lwrap_sigs.h"
#include "timers.h"
#include "fast_logging.h"

#include "hexops.h"
#include "errops.h"
#include "misc.h"
#include "structops.h"

#define DEBUG 1

int log_getrlimit(int resource, struct rlimit *rlim) {
	int ret;
	char buf_hex_str[sizeof(struct rlimit) * 2 + 1];
	__CALL_LIBC(ret, getrlimit, resource, rlim);

	advance_vclock();

	if (rlim) {
		hex_encode(rlim, buf_hex_str, sizeof(struct rlimit));
	} else {
		strcpy(buf_hex_str, "NULL");
	}

	if (!LOG( __GETRLIMIT_PAT, ret,
					buf_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getrlimit\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_getrusage(int who, struct rusage *usage) {
	int ret;
	char buf_hex_str[sizeof(struct rusage) * 2 + 1];
	__CALL_LIBC(ret, getrusage, who, usage);

	advance_vclock();

	if (usage) {
		hex_encode(usage, buf_hex_str, sizeof(struct rusage));
	} else {
		strcpy(buf_hex_str, "NULL");
	}

	if (!LOG( __GETRUSAGE_PAT, ret,
					buf_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getrusage\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct group * log_getgrnam(const char *name) {
	struct group* ret;
	struct group_flat ret_flat;
	char buf_hex_str[sizeof(struct group_flat) * 2 + 1];

	__CALL_LIBC(ret, getgrnam, name);

	if (ret) {
		struct_encode_group(ret, &ret_flat);
		hex_encode(&ret_flat, buf_hex_str, sizeof(struct group_flat));
	} else {
		strcpy(buf_hex_str, "NULL");
	}

	advance_vclock();

	if (!LOG( __GETGRNAM_PAT,
					buf_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getgrnam\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct group * log_getgrgid(gid_t gid) {
	struct group* ret;
	struct group_flat ret_flat;
	char buf_hex_str[sizeof(struct group_flat) * 2 + 1];

	__CALL_LIBC(ret, getgrgid, gid);

	if (ret) {
		struct_encode_group(ret, &ret_flat);
		hex_encode(&ret_flat, buf_hex_str, sizeof(struct group_flat));
	} else {
		strcpy(buf_hex_str, "NULL");
	}

	advance_vclock();

	if (!LOG( __GETGRGID_PAT,
					buf_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getgrgid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct passwd* log_getpwnam(const char* name) {
	struct passwd* ret;
	struct passwd_flat ret_flat;
	char buf_hex_str[sizeof(struct passwd_flat) * 2 + 1];

	__CALL_LIBC(ret, getpwnam, name);

	if (ret) {
		struct_encode_passwd(ret, &ret_flat);
		hex_encode(&ret_flat, buf_hex_str, sizeof(struct passwd_flat));
	} else {
		strcpy(buf_hex_str, "NULL");
	}

	advance_vclock();

	if (!LOG( __GETPWNAM_PAT,
					buf_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getpwnam\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct passwd* log_getpwuid(uid_t uid) {
	struct passwd* ret;
	struct passwd_flat ret_flat;
	char buf_hex_str[sizeof(struct passwd_flat) * 2 + 1];

	__CALL_LIBC(ret, getpwuid, uid);

	if (ret) {
		struct_encode_passwd(ret, &ret_flat);
		hex_encode(&ret_flat, buf_hex_str, sizeof(struct passwd_flat));
	} else {
		strcpy(buf_hex_str, "NULL");
	}

	advance_vclock();

	if (!LOG( __GETPWUID_PAT,
					buf_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getpwuid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_uname(struct utsname *buf) {
	int ret;
	char buf_hex_str[sizeof(struct utsname) * 2 + 1];
	__CALL_LIBC(ret, uname, buf);

	advance_vclock();

	if (buf) {
		hex_encode(buf, buf_hex_str, sizeof(struct utsname));
	} else {
		strcpy(buf_hex_str, "NULL");
	}

	if (!LOG( __UNAME_PAT, ret,
					buf_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"uname\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_ioctl(int d, unsigned long int request, va_list args) {
	int ret;
	char* argp;
	char argp_hex_str[(sizeof(struct ifreq) * 2) + 1];


	/* TODO: Right now, we assume that the third argument
	 * is a char* . */
#if 1
	//va_start(args, request);
	argp = va_arg(args, void*);
	//va_end(args);
#endif

	__CALL_LIBC(ret, ioctl, d, request, argp);

	if (ret != -1) /* Success. Some data should be returned. */ {
		/* Interpret the third argument as a struct ifreq. */
		hex_encode(argp, argp_hex_str, sizeof(struct ifreq));
	} else {
		/* Default value of the data. */
		strcpy(argp_hex_str, "NULL");
	}

	advance_vclock();

	if (!LOG( __IOCTL_PAT, ret, request,
					argp_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"ioctl\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

time_t log_time(time_t *t) {
	time_t ret;

	__CALL_LIBC(ret, time, t);

	advance_vclock();

	__START_WRAPPER_TIMER(__LIBC_TIMER(time), _shm_write);
	GET_SHM_CHUNK(time);
	e->ret = ret;
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(time), _shm_write);

	POST_WRAPPER_CLEANUP();

	return ret;
}

char* log_ctime(const time_t *timep) {
	char* ret;

	/* Careful: ctime returns a pointer to a string that is
	 * statically allocated in libc's address space. */
	__CALL_LIBC(ret, ctime, timep);

	advance_vclock();

	{
	  char ret_copy[strlen(ret)+2];

	  if (ret) {
	    strcpy( ret_copy, ret );
	    assert( ret_copy[strlen(ret)-1] == '\n' );
	    // Do not log the newline.
	    ret_copy[strlen(ret)-1] = '\0';
	  } else {
	    strcpy(ret_copy, "NULL");
	  }

	  if (!LOG( __LOG_CTIME_PAT,
				      ret_copy, _shared_info->vclock )) {
	    fatal("can't communicate with logger process on ctime\n");
	  }
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

#if 0
/* This is called by i3_server for some reason. */
struct tm* log_localtime_r(const time_t *timep, struct tm *result) {
	struct tm* ret;
	char result_hex_str[sizeof(struct tm) * 2 + 1];

	ret = log_localtime_r(timep, result);

	advance_vclock();

	if (ret) {
		hex_encode(result, result_hex_str, sizeof(struct tm));
	} else {
		strcpy(result_hex_str, "NULL");
	}

	if (!LOG(__LOCALTIME_R_PAT, ret,
					result_hex_str, _pinfo.vclock )) {
		fatal("can't communicate with logger process on "
				"localtime_r\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}
#endif

pthread_t log_pthread_self(void) {
	pthread_t ret;

	__CALL_LIBC(ret, pthread_self);

	advance_vclock();

	if (!LOG( __PTHREAD_SELF_PAT,
			ret, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"pthread_self\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

pid_t log_getpid(void) {
	pid_t ret;

	__CALL_LIBC(ret, getpid);

	advance_vclock();

#if LOG_GETPID
	if (!LOG( __GETPID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getpid\n");
	}

	POST_WRAPPER_CLEANUP();
#endif

	return ret;
}

pid_t log_getpgrp(void) {
	pid_t ret;

	__CALL_LIBC(ret, getpgrp);

	advance_vclock();

	if (!LOG( __GETPGRP_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getpgrp\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

pid_t log_getpgid(pid_t pid) {
	pid_t ret;

	__CALL_LIBC(ret, getpgid, pid);

	advance_vclock();

	if (!LOG( __GETPGID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"getpgid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

#if WRAP_GETTID
pid_t log_gettid(void) {
	pid_t ret;

	__CALL_LIBC(ret, gettid);

	advance_vclock();

	if (!LOG( __GETTID_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"gettid\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}
#endif

int log_nanosleep(const struct timespec *req, struct timespec *rem) {
	pid_t ret;
	FLAT_STR(struct timespec, rem);


	__CALL_LIBC(ret, nanosleep, req, rem);

	if (rem) {
		hex_encode(rem, rem_flat_str, sizeof(struct timespec));
	} else {
		strcpy(rem_flat_str, "NULL");
	}

	advance_vclock();

	if (!LOG( __NANOSLEEP_PAT, ret,
					rem_flat_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"nanosleep\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

unsigned int log_sleep(unsigned int seconds) {
	unsigned int ret;

	__STOP_WRAPPER_TIMER(__LIBC_TIMER(sleep), _wrapper_call);

	/* BUG: LOG_AND_DELIVER_QUEUED_SIGNALS does a handoff. So
	 * does __ASYNC_CALL. We need only one handoff. One
	 * way to fix this might be to pull out the handoff in
	 * LOG_AND_D... It should really be seperate from the signal
	 * logging and delivering functionality. */
	/* FIXED: LOG_AND_DELIVER_QUEUED_SIGNALS no longer does
	 * the handoff. It is now done by the top-level wrapper
	 * function, for this wrapper, which resides in overlord.c. */
	/* NOTA BENE: We moved LOG_AND_DELIVER_QUEUED_SIGNALS out of
	 * all the second-level wrappers and into the top-level
	 * wrappers. */

	__START_WRAPPER_TIMER(__LIBC_TIMER(sleep), _call_libc);
	__ASYNC_CALL(ret, sleep, seconds);
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(sleep), _call_libc);

	__START_WRAPPER_TIMER(__LIBC_TIMER(sleep), _other);
	advance_vclock();
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(sleep), _other);

	{
		__START_WRAPPER_TIMER(__LIBC_TIMER(sleep), _entry_creation);
		LOG(__SLEEP_PAT, ret,
				_shared_info->vclock );
		__STOP_WRAPPER_TIMER(__LIBC_TIMER(sleep), _entry_creation);
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

void log_openlog(const char *ident, int option, int facility) {
	__CALL_LIBC_1(openlog, ident, option, facility);

	advance_vclock();

	/* Don't log, since this is deterministic. But we wrap it since
	 * we may want to intercept it during replay. */

	POST_WRAPPER_CLEANUP();
}

void log_syslog(int priority, const char *format, va_list ap) {
	__CALL_LIBC_1(vsyslog, priority, format, ap);

	advance_vclock();
	/* Don't log, since this is deterministic. But we wrap it since
	 * we may want to intercept it during replay. */

	POST_WRAPPER_CLEANUP();
}

void log_closelog(void) {
	__CALL_LIBC_1(closelog);

	advance_vclock();
	/* Don't log, since this is deterministic. But we wrap it since
	 * we may want to intercept it during replay. */

	POST_WRAPPER_CLEANUP();
}

void log_vsyslog(int priority, const char *format, va_list ap) {
	__CALL_LIBC_1(vsyslog, priority, format, ap);

	advance_vclock();
	/* Don't log, since this is deterministic. But we wrap it since
	 * we may want to intercept it during replay. */

	POST_WRAPPER_CLEANUP();
}


long log_random() {
	long ret;

	/* Call the libc random function. */
	__CALL_LIBC(ret, random);

	advance_vclock();

	__START_WRAPPER_TIMER(__LIBC_TIMER(random), _shm_write);
	GET_SHM_CHUNK(random);
	e->ret = ret;
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(random), _shm_write);

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_rand() {
	int ret;

	/* Call the libc random function. */
	__CALL_LIBC(ret, rand);

	advance_vclock();

	{
		if (!LOG(__RAND_PAT, ret,
				_shared_info->vclock )) {
			fatal("can't communicate with logger process on random()\n");
		}
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_gethostname(char *name, size_t len) {
	int ret;

	__CALL_LIBC(ret, gethostname, name, len);

	advance_vclock();

	if (!LOG( __GETHOSTNAME_PAT, ret,
					name ? name : "NULL", _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"gethostname\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_sethostname(const char *name, size_t len) {
	int ret;

	__CALL_LIBC(ret, sethostname, name, len);

	advance_vclock();

	if (!LOG( __SETHOSTNAME_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"sethostname\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_gettimeofday(struct timeval *tv, struct timezone *tz) {
	int ret;

	/* Call the libc gettimeofday function. */
	__CALL_LIBC(ret, gettimeofday, tv, tz);

	advance_vclock();

	__START_WRAPPER_TIMER(__LIBC_TIMER(gettimeofday), _shm_write);
	GET_SHM_CHUNK(gettimeofday);
	e->ret = ret;
	if (tv) memcpy(&e->tv, tv, sizeof(struct timeval));
	if (tz) memcpy(&e->tz, tz, sizeof(struct timezone));
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(gettimeofday), _shm_write);

	POST_WRAPPER_CLEANUP();

	return ret;
}
