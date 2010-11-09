#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <syscall.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>

#define __USE_GNU
#include <ucontext.h>
#include <dlfcn.h>

#define __USE_LARGEFILE64
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "libc_pointers.h"
#include "logger.h"
#include "log.h"
#include "sendlog.h"
#include "lwrap_sigs.h"
#include "lwrap.h"
#include "timers.h"

#include "logreplay.h"
#include "patterns.h"
#include "misc.h"
#include "errops.h"
#include "hexops.h"
#include "dllops.h"
#include "msg_coding.h"
#include "structops.h"

#include "fast_logging.h"

#define DEBUG 0

void* log_dlopen(const char *filepath, int flag) {
	void* ret;
	char base_name[1024];
	char new_filepath[1024];
	char const *fp;

	__CALL_LIBC(ret, dlopen, filepath, flag);

	if (ret && _private_info.done_with_init) {
		/* Extract the shared library's name. */
		if ((fp = strrchr(filepath, '/')) != NULL) {
		  fp++;		// Skip the '/'
		} else {
		  fp = filepath;	// then take full string.
		}
		/* Build a new filename similar to log, ckpt names. */
		construct_lib_filename_base(_private_info.log_path,
					    _private_info.log_prefix,
					    _private_info.tag_str,
					    _private_info.orig_pgid,
					    _private_info.log_epoch,
					    base_name, sizeof(base_name));
		/* Final format is <prefix>.<libname>.lib */
		snprintf(new_filepath, sizeof(new_filepath),
			 "%s.%s.lib", base_name, fp );
		if( DEBUG ) lprintf("copying %s to %s\n",
				    filepath, new_filepath );
		/* Copy the file. */
		{
			char cmd_str[256];
			int rval;

			sprintf(cmd_str, "cp %s %s\n", filepath, new_filepath);
			/* We don't want the child process to use liblog. */
			unsetenv("LD_PRELOAD");
			__INTERNAL_CALL_LIBC_2(rval, system, cmd_str);
			if (rval == -1) {
				perror("system");
				fatal("can't copy shared library %s to "
						"%s\n", filepath, new_filepath);
			}
		}
	}

	return ret;
}

ssize_t log_getline(char **lineptr, size_t *n, FILE *stream) {
	UNIMPLEMENTED_LOG_WRAPPER(getline);

	return 0;
}

ssize_t log_getdelim(char **lineptr, size_t *n, int delim, FILE *stream) {
	UNIMPLEMENTED_LOG_WRAPPER(getdelim);

	return 0;
}

void log_setbuf(FILE *stream, char *buf) {
	__CALL_LIBC_1(setbuf, stream, buf);

	advance_vclock();

	if (!LOG( __SETBUF_PAT,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "setbuf\n");
	}

	POST_WRAPPER_CLEANUP();
}

void log_setbuffer(FILE *stream, char *buf, size_t size) {
	__CALL_LIBC_1(setbuffer, stream, buf, size);

	advance_vclock();

	if (!LOG( __SETBUFFER_PAT,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "setbuffer\n");
	}

	POST_WRAPPER_CLEANUP();
}

void log_setlinebuf(FILE *stream) {
	__CALL_LIBC_1(setlinebuf, stream);

	advance_vclock();

	if (!LOG( __SETLINEBUF_PAT,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "setlinebuf\n");
	}

	POST_WRAPPER_CLEANUP();
}

int log_setvbuf(FILE *stream, char *buf, int mode , size_t size) {
	int ret;

	__CALL_LIBC(ret, setvbuf, stream, buf, mode, size);

	advance_vclock();

	if (!LOG(__SETVBUF_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "setvbuf\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct dirent* log_readdir(DIR *dir) {
	struct dirent* ret;
	char dirent_hex_str[sizeof(struct dirent)*2 + 1];

	__CALL_LIBC(ret, readdir, dir);

	advance_vclock();

	if (ret) {
		/* struct dirent is a flat structure, so we needn't do anything
		 * special before we serialize it to disk. */
		hex_encode(ret, dirent_hex_str, sizeof(struct dirent));
	} else {
		strncpy(dirent_hex_str, "NULL", sizeof(dirent_hex_str));
	}

	if (!LOG(__READDIR_PAT, ret,
					dirent_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "readdir\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

struct dirent64* log_readdir64(DIR *dir) {
	struct dirent64* ret;
	char dirent_hex_str[sizeof(struct dirent64)*2 + 1];

	__CALL_LIBC(ret, readdir64, dir);

	advance_vclock();

	if (ret) {
		/* struct dirent is a flat structure, so we needn't do anything
		 * special before we serialize it to disk. */
		hex_encode(ret, dirent_hex_str, sizeof(struct dirent64));
	} else {
		strncpy(dirent_hex_str, "NULL", sizeof(dirent_hex_str));
	}

	if (!LOG(__READDIR64_PAT, ret,
					dirent_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "readdir64\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

/* We assume that DIR is opaque to the user and that he does not inspect
 * it. */
DIR* log_opendir(const char *name) {
	DIR* ret;

	__CALL_LIBC(ret, opendir, name);

	advance_vclock();

	if (!LOG(__OPENDIR_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "opendir\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_truncate(const char *path, off_t length) {
	int ret;

	__CALL_LIBC(ret, truncate, path, length);

	advance_vclock();

	if (!LOG(__TRUNCATE_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "truncate\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_ftruncate(int fd, off_t length) {
	int ret;

	__CALL_LIBC(ret, ftruncate, fd, length);

	advance_vclock();

	if (!LOG(__FTRUNCATE_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "ftruncate\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}


int log_chmod(const char *path, mode_t mode) {
	int ret;

	__CALL_LIBC(ret, chmod, path, mode);

	advance_vclock();

	if (!LOG(__CHMOD_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "chmod\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fchmod(int fildes, mode_t mode) {
	int ret;

	__CALL_LIBC(ret, fchmod, fildes, mode);

	advance_vclock();

	if (!LOG(__FCHMOD_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "fchmod\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_closedir(DIR *dir) {
	int ret;

	__CALL_LIBC(ret, closedir, dir);

	advance_vclock();

	if (!LOG(__CLOSEDIR_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "closedir\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_dirfd(DIR *dir) {
	int ret;

	__CALL_LIBC(ret, dirfd, dir);

	advance_vclock();

	if (!LOG(__DIRFD_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "dirfd\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

void log_rewinddir(DIR *dir) {
	__CALL_LIBC_1(rewinddir, dir);

	advance_vclock();

	if (!LOG(__REWINDDIR_PAT,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "rewinddir\n");
	}

	POST_WRAPPER_CLEANUP();
}

int log_scandir(const char *dir, struct dirent ***namelist,
				int(*filter)(const struct dirent *),
				int(*compar)(const void*, const void*)) {

	assert(0);

	return 0;
}

void log_seekdir(DIR *dir, off_t offset) {

	__CALL_LIBC_1(seekdir, dir, offset);

	advance_vclock();

	if (!LOG( __SEEKDIR_PAT,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "seekdir\n");
	}

	POST_WRAPPER_CLEANUP();
}

off_t log_telldir(DIR *dir) {
	int ret;

	__CALL_LIBC(ret, telldir, dir);

	advance_vclock();

	if (!LOG( __TELLDIR_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "telldir\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_chdir(const char* path) {
	int ret;

	__CALL_LIBC(ret, chdir, path);

	advance_vclock();

	if (!LOG( __CHDIR_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "chdir\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fchdir(int fd) {
	int ret;

	__CALL_LIBC(ret, fchdir, fd);

	advance_vclock();

	if (!LOG( __FCHDIR_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "fchdir\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

char* log_getcwd(char* buf, size_t size) {
	char* ret;

	__CALL_LIBC(ret, getcwd, buf, size);

	advance_vclock();

	if (!LOG( __GETCWD_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getcwd\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

char * log_get_current_dir_name(void) {
	char* ret;

	__CALL_LIBC(ret, get_current_dir_name);

	advance_vclock();

	if (!LOG( __GET_CURRENT_DIR_NAME_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "get_current_dir_name\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

char * log_getwd(char *buf) {
	char* ret;

	__CALL_LIBC(ret, getwd, buf);

	advance_vclock();

	if (!LOG( __GETWD_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getwd\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_rmdir(const char *pathname) {
	int ret;

	__CALL_LIBC(ret, rmdir, pathname);

	advance_vclock();

	if (!LOG( __RMDIR_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "rmdir\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_mkdir(const char *pathname, mode_t mode) {
	int ret;

	__CALL_LIBC(ret, mkdir, pathname, mode);

	advance_vclock();

	if (!LOG( __MKDIR_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "mkdir\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_rename(const char *oldpath, const char *newpath) {
	int ret;

	__CALL_LIBC(ret, rename, oldpath, newpath);

	advance_vclock();

	if (!LOG( __RENAME_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "rename\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_link(const char *oldpath, const char *newpath) {
	int ret;

	__CALL_LIBC(ret, link, oldpath, newpath);

	advance_vclock();

	if (!LOG( __LINK_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "link\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log___xmknod(int ver, const char *pathname, mode_t mode, dev_t* dev) {
	int ret;

	__CALL_LIBC(ret, __xmknod, ver, pathname, mode, dev);

	advance_vclock();

	if (!LOG( __MKNOD_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "mknod\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data) {
	int ret;

	__CALL_LIBC(ret, mount, source, target, filesystemtype, mountflags, data);

	advance_vclock();

	if (!LOG( __MOUNT_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "mount\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_umount(const char *target) {
	int ret;

	__CALL_LIBC(ret, umount, target);

	advance_vclock();

	if (!LOG( __UMOUNT_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "umount\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_umount2(const char *target, int flags) {
	int ret;

	__CALL_LIBC(ret, umount2, target, flags);

	advance_vclock();

	if (!LOG( __UMOUNT2_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "umount2\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

mode_t log_umask(mode_t mask) {
	int ret;

	__CALL_LIBC(ret, umask, mask);

	advance_vclock();

	if (!LOG( __UMASK_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "umask\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_mkfifo(const char *pathname, mode_t mode) {
	int ret;

	__CALL_LIBC(ret, mkfifo, pathname, mode);

	advance_vclock();

	if (!LOG( __MKFIFO_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "mkfifo\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_close(int fd) {
	int ret;

	__CALL_LIBC(ret, close, fd);

	advance_vclock();

	if (!LOG( __CLOSE_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "close\n");
	}

	if (ret == 0) {
		clear_socket_state( fd );
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_unlink(const char* pathname) {
	int ret;

	__CALL_LIBC(ret, unlink, pathname);

	advance_vclock();

	if (!LOG( __UNLINK_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "unlink\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_utime(const char *filename, const struct utimbuf *buf) {
	int ret;

	/* Call the libc gettimeofday function. */
	__CALL_LIBC(ret, utime, filename, buf);

	advance_vclock();
	if (!LOG( __UTIME_PAT, 
		ret, _shared_info->vclock )) {
		fatal("can't communicate with logger process on utime()\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fcntl(int fd, int cmd, va_list ap) {
	int ret;
	char buf_hex_str[sizeof(struct flock) * 2 + 1];

	/* Linux fcntl has three forms:
		int fcntl(int fd, int cmd);
		int fcntl(int fd, int cmd, long arg);
		int fcntl(int fd, int cmd, struct flock *lock);
	 */

	{
		long arg;
		struct flock* lock;
		/*
		 * We need to figure out which one these is being called.
		 * This is done by inspecting the value of cmd.
		 */
		strcpy(buf_hex_str, "NULL");

		switch (cmd) {
			/* Should we interpret the 3rd arg as a long ? */
		case F_DUPFD:
		  if( DEBUG ) lprintf("log_fcntl: F_DUPFD\n");
		case F_SETFD:
		  if( DEBUG ) lprintf("log_fcntl: FSETFD\n");
		case F_SETFL:
		  if( DEBUG ) lprintf("log_fcntl: FSETFL\n");
			arg = va_arg(ap, long);
			__CALL_LIBC(ret, fcntl, fd, cmd, arg);

			if( (cmd == F_DUPFD) && (ret >= arg) ) {

				dup_socket_state( fd, ret );
			}
			break;
			/* Should we interpret the 3rd arg as a struct flock* ? */
		case F_GETLK:
		case F_SETLK:
		case F_SETLKW:
		  if( DEBUG ) lprintf("log_fcntl: flock interpreted\n");
			lock = va_arg(ap, struct flock*);
			__CALL_LIBC(ret, fcntl, fd, cmd, lock);
			/* arg may be null if the third paramter was not specified. */
			if (lock) {
				hex_encode(lock, buf_hex_str, sizeof(struct flock));
			} 
			break;

			/* Don't interpret the 3rd arg at all. */
		case F_GETFD:
		case F_GETFL:
			__CALL_LIBC(ret, fcntl, fd, cmd);
			break;

			/* These are unsupported/unimplemented commands. */
		default:
			assert(0);
			break;
		}
	}


	advance_vclock();

	if (!LOG( __FCNTL_PAT, ret,
								buf_hex_str, _shared_info->vclock)) {
		fatal("can't communicate with logger process on "
			  "fcntl\n");
	}

	if( DEBUG ) lprintf("log_fcntl: done\n");

	POST_WRAPPER_CLEANUP();

	return ret;
}


#if WRAP_FILES

int log_feof(FILE* stream) {
	int ret;

	__CALL_LIBC(ret, feof, stream);

	advance_vclock();

	if (!LOG( __FEOF_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "feof\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_ferror(FILE* stream) {
	int ret;

	__CALL_LIBC(ret, ferror, stream);

	advance_vclock();

	__START_WRAPPER_TIMER(__LIBC_TIMER(ferror), _shm_write);
	GET_SHM_CHUNK(ferror);
	e->ret = ret;
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(ferror), _shm_write);

	POST_WRAPPER_CLEANUP();

	return ret;

}

int log_fileno(FILE* stream) {
	int ret;

	__CALL_LIBC(ret, fileno, stream);

	advance_vclock();

	if (!LOG( __FILENO_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "fileno\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log___xstat(int ver, const char *file_name, struct stat* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat) * 2) + 1];

	__CALL_LIBC(ret, __xstat, ver, file_name, buf);

	advance_vclock();

	hex_encode((void*) buf, stat_str_hex, sizeof(struct stat));

	if (!LOG( __XSTAT_PAT, ret,
								stat_str_hex, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "__xstat\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log___fxstat(int ver, int filedes, struct stat* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat) * 2) + 1];

	__CALL_LIBC(ret, __fxstat, ver, filedes, buf);

	advance_vclock();

	hex_encode((void*) buf, stat_str_hex, sizeof(struct stat));

	if (!LOG( __FXSTAT_PAT, ret,
								stat_str_hex, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "__fxstat\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log___lxstat(int ver, const char* file_name, struct stat* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat) * 2) + 1];

	__CALL_LIBC(ret, __lxstat, ver, file_name, buf);

	advance_vclock();

	hex_encode((void*) buf, stat_str_hex, sizeof(struct stat));

	if (!LOG( __LXSTAT_PAT, ret,
								stat_str_hex, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "__lxstat\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_dup(int oldfd) {
	int ret;

	__CALL_LIBC(ret, dup, oldfd);

	if( ret > 0 ) {
		dup_socket_state( oldfd, ret );
	}

	advance_vclock();

	if (!LOG( __DUP_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "dup\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log___xstat64(int ver, const char *file_name, struct stat64* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat64) * 2) + 1];

	__CALL_LIBC(ret, __xstat64, ver, file_name, buf);

	advance_vclock();

	hex_encode((void*) buf, stat_str_hex, sizeof(struct stat64));

	if (!LOG( __XSTAT64_PAT, ret,
								stat_str_hex, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "__xstat64\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log___fxstat64(int ver, int filedes, struct stat64* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat64) * 2) + 1];

	__CALL_LIBC(ret, __fxstat64, ver, filedes, buf);

	advance_vclock();

	hex_encode((void*) buf, stat_str_hex, sizeof(struct stat64));

	if (!LOG( __FXSTAT64_PAT, ret,
								stat_str_hex, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "__fxstat64\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log___lxstat64(int ver, const char* file_name, struct stat64* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat64) * 2) + 1];

	__CALL_LIBC(ret, __lxstat64, ver, file_name, buf);

	advance_vclock();

	hex_encode((void*) buf, stat_str_hex, sizeof(struct stat64));

	if (!LOG( __LXSTAT64_PAT, ret,
								stat_str_hex, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "__lxstat64\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_dup2(int oldfd, int newfd) {
	int ret;

	__CALL_LIBC(ret, dup2, oldfd, newfd);

	if( ret > 0 ) {
		dup_socket_state( oldfd, ret );
	}

	advance_vclock();

	if (!LOG( __DUP2_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "dup2\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

FILE* log_fdopen(int filedes, const char *mode) {
	FILE* ret=NULL;

	__CALL_LIBC(ret, fdopen, filedes, mode);

	advance_vclock();

	if (!LOG( __FDOPEN_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "fdopen\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

FILE* log_freopen(const char *path, const char *mode, FILE *stream) {
	FILE* ret=NULL;

	__CALL_LIBC(ret, freopen, path, mode, stream);

	advance_vclock();

	if (!LOG( __FREOPEN_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "freopen\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}


FILE *log_fopen(const char *path, const char *mode) {
	FILE* ret = NULL;

	__CALL_LIBC(ret, fopen, path, mode);

	advance_vclock();

	if (!LOG( __FOPEN_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "fopen\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

FILE* log_fopen64 (const char * filename, const char * modes) {
	FILE* ret = NULL;

	__CALL_LIBC(ret, fopen64, filename, modes);

	advance_vclock();

	if (!LOG( __FOPEN64_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "fopen64\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

FILE* log_freopen64 (const char * filename, const char * modes, FILE * stream) {
	FILE* ret=NULL;

	__CALL_LIBC(ret, freopen64, filename, modes, stream);

	advance_vclock();

	if (!LOG( __FREOPEN64_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "freopen64\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}


int log_open(const char *path, int flags, va_list args) {
	int ret;
	mode_t mode = 0;

	/* The man page list two definitions for open.

	   int open(const char *pathname, int flags);
	   int open(const char *pathname, int flags, mode_t mode);

	   However, there is only one definition--a variadic one.
	   */

	assert( __LIBC_PTR(open) != NULL );

#if DEBUG
	lprintf("calling open(%s, %x, %lx)\n", path, flags, mode);
#endif
	if (flags & O_CREAT) mode = va_arg(args, mode_t);
	__CALL_LIBC(ret, open, path, flags, mode);

	advance_vclock();

	if (!LOG( __OPEN_PAT, ret, path,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "open\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_open64(const char *path, int flags, va_list args) {
	int ret;
	mode_t mode = 0;

	/* The man page list two definitions for open.

	   int open(const char *pathname, int flags);
	   int open(const char *pathname, int flags, mode_t mode);

	   However, there is only one definition--a variadic one.
	   */

	assert( __LIBC_PTR(open) != NULL );

#if DEBUG
	lprintf("calling open64(%s, %x, %lx)\n", path, flags, mode);
#endif
	if (flags & O_CREAT) mode = va_arg(args, mode_t);
	__CALL_LIBC(ret, open, path, flags, mode);

	advance_vclock();

	if (!LOG( __OPEN64_PAT, ret, path,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "open64\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_creat(const char *path, mode_t mode) {
	int ret;

	assert( __LIBC_PTR(creat) != NULL );

#if DEBUG
	lprintf("calling creat(%s, %lx)\n", path, mode);
#endif
	__CALL_LIBC(ret, creat, path, mode);

	advance_vclock();

	if (!LOG( __CREAT_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "creat\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fclose(FILE *stream) {
	int ret, fd;

	__CALL_LIBC(ret, fclose, stream);

	advance_vclock();

	if (!LOG( __FCLOSE_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "fclose\n");
	}

	/* Mark this file descriptor as a network socket */
	fd = __LIBC_PTR(fileno)(stream);

	/* Note that the stream may or may not be valid, and thus we can't
	 * assume that fd > 0. */
	if (fd != -1) {
		clear_socket_state( fd );
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fflush(FILE *stream) {
	int ret;

	__CALL_LIBC(ret, fflush, stream);

	advance_vclock();

	__START_WRAPPER_TIMER(__LIBC_TIMER(fflush), _shm_write);
	GET_SHM_CHUNK(fflush);
	e->ret = ret;
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(fflush), _shm_write);

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fgetc(FILE* stream) {
	int ret;

	__CALL_LIBC(ret, fgetc, stream);

	advance_vclock();

	if (!LOG( __FGETC_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "fgetc\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_getc(FILE* stream) {
	int ret;

	__CALL_LIBC(ret, getc, stream);

	advance_vclock();

	if (!LOG( __GETC_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getc\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_getchar(void) {
	int ret;

	__CALL_LIBC(ret, getchar);

	advance_vclock();

	if (!LOG( __GETCHAR_PAT, ret,
								_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
			  "getchar\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

char *log_gets(char *s) {
	char* ret;
	char s_hex_str[s ? strlen(s)+1 : 32];

	__CALL_LIBC(ret, gets, s);

	if (s) {
		hex_encode(s, s_hex_str, strlen(s)+1);
	} else {
		strncpy(s_hex_str, "NULL", sizeof(s_hex_str));
	}

	advance_vclock();

	if (!LOG( __GETS_PAT, ret,
								s_hex_str, _shared_info->vclock )) {
			  fatal("can't communicate with logger process on "
									"gets\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_ungetc(int c, FILE *stream) {
	int ret;

	__CALL_LIBC(ret, ungetc, c, stream);

	advance_vclock();

	if (!LOG( __UNGETC_PAT, ret,
											  _shared_info->vclock )) {
			  fatal("can't communicate with logger process on "
									"ungetc\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

/* TODO: Why is am reading from the stream? Why not just get the
 * data from s once fgets has been called? */
char* log_fgets(char *s, int size, FILE* stream) {
	char* ret;
			long pos_before, pos_after;

		  __INTERNAL_CALL_LIBC_2(pos_before, ftell, stream);
		  __CALL_LIBC(ret, fgets, s, size, stream);
		  __INTERNAL_CALL_LIBC_2(pos_after, ftell, stream);
		  assert(pos_after - pos_before >= 0);

		  advance_vclock();

		  {
					 char read_str[pos_after - pos_before];
					 char read_str_hex[(pos_after - pos_before) * 2 + 1];

					 /* Get the bytes that were read. */
					 __INTERNAL_CALL_LIBC_1(fseek, stream, pos_before, SEEK_SET);
					 __INTERNAL_CALL_LIBC_1(fread, read_str, pos_after - pos_before, 1, stream);

					 /* We should be back at the original position. */
					 {
								long tpos;
								__INTERNAL_CALL_LIBC_2(tpos, ftell, stream);
								assert(tpos == pos_after);
					 }

					 if( pos_after == pos_before ) {
								/* Looks like nothing was read. */
								strcpy( read_str_hex, NO_HEX_DATA );
					 } else {
								//(*__LIBC_PTR(fprintf))(stderr, "len=%d\n", pos_after - pos_before);
								/* Something was read. Package it up in hex. */
								hex_encode(read_str, read_str_hex, pos_after - pos_before);
					 }

					 if (!LOG( __LOG_FGETS_PAT, ret,
																read_str_hex, _shared_info->vclock )) {
								fatal("can't communicate with logger process on "
													 "fgets\n");
					 }
		  }

		  POST_WRAPPER_CLEANUP();

		  return ret;
}

int log_fscanf(FILE *stream, const char *format, va_list args) {
		  int ret;
		  //va_list args;
		  long pos_before, pos_after;

		  __INTERNAL_CALL_LIBC_2(pos_before, ftell, stream);
		  __CALL_LIBC(ret, vfscanf, stream, format, args);
		  __INTERNAL_CALL_LIBC_2(pos_after, ftell, stream);
		  assert(pos_after - pos_before >= 0);

		  //(*__LIBC_PTR(fprintf))("format=%s ret=%d pos_before=%d pos_after=%d\n", format, ret, pos_before, pos_after);

		  advance_vclock();

		  {
					 char read_str[pos_after - pos_before];
					 char read_str_hex[(pos_after - pos_before) * 2 + 1];

		if( pos_after == pos_before ) {
			strcpy( read_str_hex, NO_HEX_DATA );
		} else {

			/* Get the bytes that were read. */
			__INTERNAL_CALL_LIBC_1(fseek, stream, pos_before, SEEK_SET);
			__INTERNAL_CALL_LIBC_1(fread, read_str, pos_after - pos_before, 1, stream);
			//printf("read_str=%s\n", read_str);

			/* We should be back at the original position. */
			{
				long tpos;

				__INTERNAL_CALL_LIBC_2(tpos, ftell, stream);
				assert(tpos == pos_after);
			}

			hex_encode(read_str, read_str_hex, pos_after - pos_before);
		}


		if (!LOG( __LOG_FSCANF_PAT, ret,
						read_str_hex, _shared_info->vclock )) {
			fatal("can't communicate with logger process on "
					"fscanf\n");
		}
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_vfscanf(FILE *stream, const char *format, va_list ap) {
		  int ret;
		  //va_list args;
		  long pos_before, pos_after;

		  __INTERNAL_CALL_LIBC_2(pos_before, ftell, stream);
		  __CALL_LIBC(ret, vfscanf, stream, format, ap);
		  __INTERNAL_CALL_LIBC_2(pos_after, ftell, stream);
		  assert(pos_after - pos_before >= 0);

		  //(*__LIBC_PTR(fprintf))("format=%s ret=%d pos_before=%d pos_after=%d\n", format, ret, pos_before, pos_after);

		  advance_vclock();

		  {
					 char read_str[pos_after - pos_before];
					 char read_str_hex[(pos_after - pos_before) * 2 + 1];

		if( pos_after == pos_before ) {
			strcpy( read_str_hex, NO_HEX_DATA );
		} else {

			/* Get the bytes that were read. */
			__INTERNAL_CALL_LIBC_1(fseek, stream, pos_before, SEEK_SET);
			__INTERNAL_CALL_LIBC_1(fread, read_str, pos_after - pos_before, 1, stream);
			//printf("read_str=%s\n", read_str);

			/* We should be back at the original position. */
			{
				long tpos;

				__INTERNAL_CALL_LIBC_2(tpos, ftell, stream);
				assert(tpos == pos_after);
			}

			hex_encode(read_str, read_str_hex, pos_after - pos_before);
		}


		if (!LOG( __LOG_VFSCANF_PAT, ret,
						read_str_hex, _shared_info->vclock )) {
			fatal("can't communicate with logger process on "
					"vfscanf\n");
		}
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fprintf(FILE *stream, const char *format, va_list args) {
	int ret;

	__CALL_LIBC(ret, vfprintf, stream, format, args);

	advance_vclock();

	if (!LOG( __FPRINTF_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"fprintf\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_vfprintf(FILE *stream, const char *format, va_list ap) {
	int ret;

	__CALL_LIBC(ret, vfprintf, stream, format, ap);

	advance_vclock();

	if (!LOG( __VFPRINTF_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"vfprintf\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fputc(int c, FILE *stream) {
	int ret;

	__CALL_LIBC(ret, fputc, c, stream);

	advance_vclock();

	if (!LOG( __FPUTC_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"fputc\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fputs(const char *s, FILE *stream) {
	int ret;

	__CALL_LIBC(ret, fputs, s, stream);

	advance_vclock();

#if USE_FAST_LOGGING
	__START_WRAPPER_TIMER(__LIBC_TIMER(fputs), _shm_write);
	GET_SHM_CHUNK(fputs);
	e->ret = ret;
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(fputs), _shm_write);
#else
	if (!LOG( __FPUTS_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"fputs\n");
	}
#endif

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_putc(int c, FILE *stream) {
	int ret;

	__CALL_LIBC(ret, putc, c, stream);

	advance_vclock();

	if (!LOG( __PUTC_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"putc\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

size_t log_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;
	char read_data[size * nmemb];
	char read_hex_str[(size*nmemb)*2 + 1];

	__CALL_LIBC(ret, fread, ptr, size, nmemb, stream);

	assert(!(*__LIBC_PTR(ferror))(stream));

	advance_vclock();

	memcpy(read_data, ptr, size*ret);

	if( ret == 0 ) {
		strcpy( read_hex_str, NO_HEX_DATA );
	} else {
		hex_encode(read_data, read_hex_str, size*ret);
	}

	if (!LOG( __LOG_FREAD_PAT, ret,
					read_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"fread\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

size_t log_fwrite(const  void  *ptr,  size_t  size,  size_t  nmemb,  FILE
		*stream) {
	size_t ret;

	__CALL_LIBC(ret, fwrite, ptr, size, nmemb, stream);

	advance_vclock();

	__START_WRAPPER_TIMER(__LIBC_TIMER(fwrite), _shm_write);
	GET_SHM_CHUNK(fwrite);
	e->ret = ret;
	__STOP_WRAPPER_TIMER(__LIBC_TIMER(fwrite), _shm_write);

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fgetpos(FILE* stream, fpos_t* pos) {
	int ret;
	char pos_hex_str[sizeof(fpos_t)*2 + 1];

	__CALL_LIBC(ret, fgetpos, stream, pos);

	advance_vclock();

	assert(pos != NULL);
	hex_encode(pos, pos_hex_str, sizeof(fpos_t));

	if (!LOG( __FGETPOS_PAT, ret,
					pos_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"fgetpos\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

long log_ftell(FILE* stream) {
	long ret;

	__CALL_LIBC(ret, ftell, stream);

	advance_vclock();

	if (!LOG( __FTELL_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"ftell\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_fseek(FILE* stream, long offset, int whence) {
	int ret;

	__CALL_LIBC(ret, fseek, stream, offset, whence);

	advance_vclock();

	if (!LOG( __FSEEK_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"fseek\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

off_t log_lseek(int fildes, off_t offset, int whence) {
	off_t ret;

	__CALL_LIBC(ret, lseek, fildes, offset, whence);

	advance_vclock();

	if (!LOG( __LSEEK_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"lseek\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

off_t log_lseek64(int fildes, off_t offset, int whence) {
	off_t ret;

	__CALL_LIBC(ret, lseek64, fildes, offset, whence);

	advance_vclock();

	if (!LOG( __LSEEK64_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"lseek64\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

ssize_t log_readv(int fd, const struct iovec* vector, int count) {
	ssize_t ret;

	UNIMPLEMENTED_LOG_WRAPPER(readv);

	return ret;
}

ssize_t log_writev(int fd, const struct iovec* vector, int count) {
	ssize_t ret;

	UNIMPLEMENTED_LOG_WRAPPER(writev);

	return ret;
}
#endif /* WRAP_FILES */
