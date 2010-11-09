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
#include <time.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "logreplay.h"
#include "errops.h"
#include "misc.h"
#include "hexops.h"
#include "patterns.h"

#include "replay.h"
#include "util.h"
#include "structops.h"

struct group_flat getgrnam_group_flat;
struct group getgrnam_group;

struct group* replay_getgrnam(const char* name) {
	char buf_hex_str[sizeof(struct group_flat) * 2 + 1];
	struct group* ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETGRNAM_PAT,
					buf_hex_str, &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getgrnam\n" );
	}

	if (strcmp(buf_hex_str, "NULL") != 0) {
		hex_decode(buf_hex_str, &getgrnam_group_flat,
			sizeof(struct group_flat));

		struct_decode_group(&getgrnam_group, &getgrnam_group_flat);

		ret = &getgrnam_group;
	} else {
		ret = NULL;
	}

	TRAP();

	return ret;
}

struct group_flat getgrgid_group_flat;
struct group getgrgid_group;

struct group* replay_getgrgid(gid_t uid) {
	char buf_hex_str[sizeof(struct group_flat) * 2 + 1];
	struct group* ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETGRGID_PAT,
					buf_hex_str, &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getgrgid\n" );
	}

	if (strcmp(buf_hex_str, "NULL") != 0) {
		hex_decode(buf_hex_str, &getgrgid_group_flat,
			sizeof(struct group_flat));

		struct_decode_group(&getgrgid_group, &getgrgid_group_flat);

		ret = &getgrgid_group;
	} else {
		ret = NULL;
	}

	TRAP();

	return ret;
}

struct passwd_flat getpwnam_passwd_flat;
struct passwd getpwnam_passwd;

struct passwd* replay_getpwnam(const char* name) {
	char buf_hex_str[sizeof(struct passwd_flat) * 2 + 1];
	struct passwd* ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETPWNAM_PAT,
					buf_hex_str, &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getpwnam\n" );
	}

	if (strcmp(buf_hex_str, "NULL") != 0) {
		hex_decode(buf_hex_str, &getpwnam_passwd_flat,
			sizeof(struct passwd_flat));

		struct_decode_passwd(&getpwnam_passwd, &getpwnam_passwd_flat);

		ret = &getpwnam_passwd;
	} else {
		ret = NULL;
	}

	TRAP();

	return ret;
}

struct passwd_flat getpwuid_passwd_flat;
struct passwd getpwuid_passwd;

struct passwd* replay_getpwuid(uid_t uid) {
	char buf_hex_str[sizeof(struct passwd_flat) * 2 + 1];
	struct passwd* ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETPWUID_PAT,
					buf_hex_str, &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getpwuid\n" );
	}

	if (strcmp(buf_hex_str, "NULL") != 0) {
		hex_decode(buf_hex_str, &getpwuid_passwd_flat,
			sizeof(struct passwd_flat));

		struct_decode_passwd(&getpwuid_passwd, &getpwuid_passwd_flat);

		ret = &getpwuid_passwd;
	} else {
		ret = NULL;
	}

	TRAP();

	return ret;
}



void replay_openlog (const char *ident, int option, int facility) {
	/* TODO: redirect the log output somewhere? */
}

void replay_syslog (int priority, const char *format, va_list ap) {
	/* TODO: redirect the log output somewhere? */
}

void replay_closelog (void) {
	/* TODO: redirect the log output somewhere? */
}

void replay_vsyslog (int priority, const char *format, va_list ap) {
	/* TODO: redirect the log output somewhere? */
}

int replay_isatty (int desc) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __ISATTY_PAT, &ret,
				&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore isatty\n" );
	}

	TRAP();

	return ret;
}
int replay_getrusage (int who, struct rusage *usage) {
	int ret;
	char buf_hex_str[sizeof(struct rusage) * 2 + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETRUSAGE_PAT, &ret,
					buf_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore getrusage\n" );
	}

	if (usage) {
		hex_decode(buf_hex_str, usage, sizeof(struct rusage));
	}

	TRAP();

	return ret;
}

int replay_getrlimit(int resource, struct rlimit *rlim) {
	int ret;
	char buf_hex_str[sizeof(struct rlimit) * 2 + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETRLIMIT_PAT, &ret,
					buf_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore getrlimit\n" );
	}

	if (rlim) {
		hex_decode(buf_hex_str, rlim, sizeof(struct rlimit));
	}

	TRAP();

	return ret;
}

int replay_nanosleep(const struct timespec *req, struct timespec *rem) {
	int ret;
	char buf_hex_str[sizeof(struct timespec) * 2 + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __NANOSLEEP_PAT, &ret,
					buf_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore nanosleep\n" );
	}

	if (rem) {
		hex_decode(buf_hex_str, rem, sizeof(struct timespec));
	}

	TRAP();

	return ret;
}

int replay_uname(struct utsname *buf) {
	int ret;
	char buf_hex_str[sizeof(struct utsname) * 2 + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __UNAME_PAT, &ret,
					buf_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore uname\n" );
	}

	if (buf) {
		hex_decode(buf_hex_str, buf, sizeof(struct utsname));
	}

	TRAP();

	return ret;
}

int replay_ioctl(int d, unsigned long int request, va_list args) {
	int ret;
	char *argp;
	char argp_hex_str[(sizeof(struct ifreq) * 2) + 1];

	

	/* Assume that the third arg is a char* for now. */
	argp = va_arg(args, char*);

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __IOCTL_PAT, &ret,
					&request, argp_hex_str, &_shared_info->vclock ) != 4) ) {
		stop_replay( "could not restore ioctl\n" );
	}

	if (ret != -1) /* On success, figure out what data it gave us. */ {
		hex_decode(argp_hex_str, argp, sizeof(struct ifreq));
	}

	TRAP();

	return ret;
}

time_t replay_time(time_t *t) {
	time_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __TIME_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore time\n" );
	}

	if (t) {
		*t = ret;
	}

	TRAP();

	return ret;
}

char* replay_ctime(const time_t *timep) {
  	static char ret_buf[LOG_BUF_SIZE];
	char * ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __REPLAY_CTIME_PAT,
				       ret_buf, &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore ctime\n" );
	}
	if( strcmp( ret_buf, "NULL" ) == 0 ) {
	  ret = NULL;
	} else {
	  ret = ret_buf;
	  assert( strlen(ret) < LOG_BUF_SIZE-2 );
	  assert( ret[strlen(ret)-1] != '\n' );
	  ret[strlen(ret)] = '\n';
	  ret[strlen(ret)+1] = '\0';
	}
	TRAP();

	return ret;
}

#if 0
struct tm* replay_localtime_r(const time_t *timep, struct tm *result) {
	struct tm* ret;
	char t_hex_str[sizeof(struct tm) * 2 + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __LOCALTIME_R_PAT, &ret,
					t_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore localtime_r\n" );
	}

	if (ret) {
		int size = (sizeof(t_hex_str) - 1) / 2;
		hex_decode(t_hex_str, ret, size);

		assert(ret == result);
	}

	TRAP();

	return ret;
}
#endif

pthread_t replay_pthread_self(void) {
	pthread_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf,
		__PTHREAD_SELF_PAT, &ret, &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore pthread_self\n" );
	}

	TRAP();

	return ret;
}

pid_t replay_getpid(void) {
	pid_t ret;

	

#if LOG_GETPID

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETPID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getpid\n" );
	}

	assert(ret == _my_tinfo->log_mode_id.pid);

	TRAP();
#else
	ret = _my_tinfo->log_mode_id.pid;
#endif

	return ret;
}

pid_t replay_tcgetpgrp(int fd) {
	pid_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __TCGETPGRP_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore tcgetpgrp\n" );
	}

	TRAP();

	return ret;
}

pid_t replay_getpgrp(void) {
	pid_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETPGRP_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getpgrp\n" );
	}

	TRAP();

	return ret;
}

pid_t replay_getpgid(pid_t pid) {
	pid_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETPGID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getpgid\n" );
	}

	TRAP();

	return ret;
}

unsigned int replay_sleep(unsigned int seconds) {
	unsigned int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SLEEP_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore sleep\n" );
	}

	TRAP();

	return ret;
}



long replay_random() {
	long ret;

	

	if( ! LOG_TO_BUF() ||
			(sscanf( libreplay_io_buf, __RANDOM_PAT, &ret, &_shared_info->vclock ) != 2) ) {

		stop_replay( "could not restore random\n" );
	}

	/* Observe how the TRAP is the last instruction before the return.
	 * To keep things consistent, make sure you place TRAPs at the end
	 * of all wrapper functions. */
	TRAP();

	return ret;
}

int replay_rand() {
	int ret;

	

	if( ! LOG_TO_BUF() ||
			(sscanf( libreplay_io_buf, __RAND_PAT, &ret, &_shared_info->vclock ) != 2) ) {

		stop_replay( "could not restore rand\n" );
	}

	/* Observe how the TRAP is the last instruction before the return.
	 * To keep things consistent, make sure you place TRAPs at the end
	 * of all wrapper functions. */
	TRAP();

	return ret;
}

int replay_gettimeofday(struct timeval *tv, struct timezone *tz) {
	int ret;
	FLAT_STR(struct timeval, tv);
	FLAT_STR(struct timezone, tz);

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, 
		__GETTIMEOFDAY_PAT, &ret, tv_flat_str, tz_flat_str,
					&_shared_info->vclock ) != 4) ) {
		stop_replay( "could not restore gettimeofday\n" );
	}

	if (tv) {
		hex_decode(tv_flat_str, tv, sizeof(struct timeval));
	}

	if (tz) {
		hex_decode(tz_flat_str, tz, sizeof(struct timezone));
	}
	
	TRAP();

	return ret;
}

int replay_gethostname(char *name, size_t len) {
	int ret;
	char host_name[4096];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETHOSTNAME_PAT, &ret,
								   host_name, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore gethostname\n" );
	}

	if (strcmp(host_name, "NULL") != 0) {
		strcpy(name, host_name);
	}

	TRAP();

	return ret;
}

int replay_sethostname(const char *name, size_t len) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETHOSTNAME_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore sethostname\n" );
	}

	TRAP();

	return ret;
}

int replay_setfsuid(uid_t fsuid) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETFSUID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setfsuid\n" );
	}

	TRAP();

	return ret;
}

int replay_setuid(uid_t uid) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETUID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setuid\n" );
	}

	TRAP();

	return ret;
}

pid_t replay_setsid(void) {
	pid_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETSID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setsid\n" );
	}

	TRAP();

	return ret;
}

int replay_setpgid(pid_t pid, pid_t pgid) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETPGID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setpgid\n" );
	}

	TRAP();

	return ret;
}

int replay_setgid(gid_t gid) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETGID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setgid\n" );
	}

	TRAP();

	return ret;
}

int replay_setfsgid(uid_t fsgid) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETFSGID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setfsgid\n" );
	}

	TRAP();

	return ret;
}

int replay_setreuid(uid_t ruid, uid_t euid) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETREUID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setreuid\n" );
	}

	TRAP();

	return ret;
}

int replay_setregid(gid_t rgid, gid_t egid) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETREGID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setregid\n" );
	}

	TRAP();

	return ret;
}

int replay_setpgrp(void) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETPGRP_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setpgrp\n" );
	}

	TRAP();

	return ret;
}

int replay_tcsetpgrp(int fd, pid_t pgrp) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __TCSETPGRP_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore tcsetpgrp\n" );
	}

	TRAP();

	return ret;
}

gid_t replay_getgid(void) {
	gid_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETGID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getgid\n" );
	}

	TRAP();

	return ret;
}

gid_t replay_getegid(void) {
	gid_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETEGID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getegid\n" );
	}

	TRAP();

	return ret;
}

uid_t replay_getuid(void) {
	uid_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETUID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getuid\n" );
	}

	TRAP();

	return ret;
}

uid_t replay_geteuid(void) {
	uid_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETEUID_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore geteuid\n" );
	}

	TRAP();

	return ret;
}
