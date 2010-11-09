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
#include <fcntl.h>

#define __USE_LARGEFILE64
#include <sys/stat.h>
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
#include "misc.h"
#include "patterns.h"
#include "errops.h"
#include "hexops.h"

#include "replay.h"
#include "util.h"

#define DEBUG 0

extern int vsscanf(const char *str, const char *format, va_list ap);

void* replay_dlopen(const char *filepath, int flag) {
	void* ret;
	char base_name[1024];
	char new_filepath[1024];
	char const *fp;

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

	if( DEBUG ) {
	  lprintf("replay_dlopen: filepath=%s new_filepath=%s\n",
		  filepath, new_filepath);
	}
	ret = (*__LIBC_PTR(dlopen))(new_filepath, flag);

	return ret;
}

ssize_t replay_getline(char **lineptr, size_t *n, FILE *stream) {
	UNIMPLEMENTED_REPLAY_WRAPPER(getline);

	return 0;
}

ssize_t replay_getdelim(char **lineptr, size_t *n, int delim, FILE *stream) {
	UNIMPLEMENTED_REPLAY_WRAPPER(getdelim);

	return 0;
}


static struct dirent static_dirent;

struct dirent* replay_readdir(DIR *dir) {
	struct dirent* retval;
	char dirent_hex_str[sizeof(struct dirent)*2 + 1];
	struct dirent* ret = NULL;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __READDIR_PAT, &retval,
								   dirent_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore readdir\n" );
	}

	if (strcmp(dirent_hex_str, "NULL") != 0) {
		hex_decode(dirent_hex_str, &static_dirent, 
				   sizeof(struct dirent));

		ret = &static_dirent;
	}

	TRAP();

	return ret;
}

static struct dirent64 static_dirent64;

struct dirent64* replay_readdir64(DIR *dir) {
	struct dirent64* retval;
	char dirent_hex_str[sizeof(struct dirent64)*2 + 1];
	struct dirent64* ret = NULL;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __READDIR64_PAT, 
					&retval, dirent_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore readdir64\n" );
	}

	if (strcmp(dirent_hex_str, "NULL") != 0) {
		hex_decode(dirent_hex_str, &static_dirent64, 
				   sizeof(struct dirent64));

		ret = &static_dirent64;
	}

	TRAP();

	return ret;
}

void replay_setbuf(FILE *stream, char *buf) {
	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETBUF_PAT,
								   &_shared_info->vclock ) != 1) ) {
		stop_replay( "could not restore setbuf\n" );
	}

	TRAP();
}

void replay_setbuffer(FILE *stream, char *buf, size_t size) {
	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETBUFFER_PAT,
								   &_shared_info->vclock ) != 1) ) {
		stop_replay( "could not restore setbuffer\n" );
	}

	TRAP();
}

void replay_setlinebuf(FILE *stream) {
	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETLINEBUF_PAT,
								   &_shared_info->vclock ) != 1) ) {
		stop_replay( "could not restore setlinebuf\n" );
	}

	TRAP();
}

int replay_setvbuf(FILE *stream, char *buf, int mode , size_t size) {
	int ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETVBUF_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setvbuf\n" );
	}

	TRAP();

	return ret;
}


int replay_truncate(const char *path, off_t length) {
	int ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __TRUNCATE_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore truncate\n" );
	}

	TRAP();

	return ret;
}

int replay_ftruncate(int fd, off_t length) {
	int ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FTRUNCATE_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore ftruncate\n" );
	}

	TRAP();

	return ret;
}

int replay_chmod(const char *path, mode_t mode) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __CHMOD_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore chmod\n" );
	}

	TRAP();

	return ret;
}

int replay_fchmod(int fildes, mode_t mode) {
	int ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FCHMOD_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fchmod\n" );
	}

	TRAP();

	return ret;
}

int replay_utime(const char *filename, const struct utimbuf *buf) {
	int ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __UTIME_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore utime\n" );
	}

	TRAP();

	return ret;
}


DIR* replay_opendir(const char *name) {
	DIR* ret;

	/* INCOMPLETE: Must read in DIR structure as well. */
	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __OPENDIR_PAT, &ret,
								 &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore opendir\n" );
	}

	TRAP();

	return ret;
}

int replay_closedir(DIR *dir) {
	int ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __CLOSEDIR_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore closedir\n" );
	}

	TRAP();

	return ret;
}

int replay_dirfd(DIR *dir) {
	int ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __DIRFD_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore dirfd\n" );
	}

	TRAP();

	return ret;
}

void replay_rewinddir(DIR *dir) {
	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __REWINDDIR_PAT,
								   &_shared_info->vclock ) != 1) ) {
		stop_replay( "could not restore rewinddir\n" );
	}

	TRAP();

	return;
}

int replay_scandir(const char *dir, struct dirent ***namelist,
		   int(*filter)(const struct dirent *),
		   int(*compar)(const struct dirent **, const struct dirent **)) {
	assert(0);

	return 0;
}

void replay_seekdir(DIR *dir, off_t offset) {
	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SEEKDIR_PAT,
								   &_shared_info->vclock ) != 1) ) {
		stop_replay( "could not restore seekdir\n" );
	}

	TRAP();

	return;
}

off_t replay_telldir(DIR *dir) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __TELLDIR_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore telldir\n" );
	}

	TRAP();

	return ret;
}

char replay_get_current_dir_name_buf[1024];

char * replay_get_current_dir_name(void) {
	char *buf;

	buf = replay_get_current_dir_name_buf;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GET_CURRENT_DIR_NAME_PAT, buf,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore get_current_dir_name\n" );
	}

	TRAP();

	return buf;
}

char * replay_getwd(char *buf) {
	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETWD_PAT, buf,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getcwd\n" );
	}

	TRAP();

	return buf;
}

int replay_rmdir(const char *pathname) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __RMDIR_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore rmdir\n" );
	}

	TRAP();
	
	return ret;
}

int replay_mkdir(const char *pathname, mode_t mode) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __MKDIR_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore mkdir\n" );
	}

	TRAP();
	
	return ret;
}

int replay_rename(const char *oldpath, const char *newpath) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __RENAME_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore rename\n" );
	}

	TRAP();
	
	return ret;
}

int replay_link(const char *oldpath, const char *newpath) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __LINK_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore link\n" );
	}

	TRAP();
	
	return ret;
}

int replay___xmknod(int ver, const char *pathname, mode_t mode, dev_t* dev) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __MKNOD_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore __xmknod\n" );
	}

	TRAP();
	
	return ret;
}

int replay_mount(const char *source, const char *target, const char *filesys_temtype, unsigned long mountflags, const void *data) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __MOUNT_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore mount\n" );
	}

	TRAP();
	
	return ret;
}

int replay_umount(const char *target) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __UMOUNT_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore umount\n" );
	}

	TRAP();
	
	return ret;
}

int replay_umount2(const char *target, int flags) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __UMOUNT2_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore umount2\n" );
	}

	TRAP();
	
	return ret;
}

mode_t replay_umask(mode_t mask) {
	mode_t ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __UMASK_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore chdir\n" );
	}

	TRAP();
	
	return ret;
}

int replay_mkfifo(const char *pathname, mode_t mode) {
	assert(0);
	return 0;
}

int replay_chdir(const char* path) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __CHDIR_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore chdir\n" );
	}

	TRAP();

	return ret;
}

int replay_fchdir(int fd) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FCHDIR_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fchdir\n" );
	}

	TRAP();

	return ret;
}

char* replay_getcwd(char* buf, size_t size) {

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __GETCWD_PAT, buf,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getcwd\n" );
	}

	TRAP();

	return buf;
}

int replay_unlink(const char* pathname) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __UNLINK_PAT, &ret,
								   &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore unlink\n" );
	}

	TRAP();

	return ret;
}

int replay_fcntl(int fd, int cmd, va_list ap) {
	int ret;
	struct flock* arg;
	char buf_hex_str[sizeof(struct flock)*2 + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FCNTL_PAT, &ret,
								   buf_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore fcntl\n" );
	}

	if (strcmp(buf_hex_str, "NULL") != 0) {
		printf("replay_fcntl: flock interpreted\n");
		arg = va_arg(ap, struct flock*);

		if (arg) hex_decode(buf_hex_str, arg, sizeof(struct flock));
	}


	TRAP();

	return ret;
}

#if WRAP_FILES

int replay___fxstat(int ver, int filedes, struct stat* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat) * 2) + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FXSTAT_PAT, &ret,
					stat_str_hex, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore __fxstat\n" );
	}

	hex_decode(stat_str_hex, (void*) buf, sizeof(struct stat));

	TRAP();

	return ret;
}

int replay___lxstat(int ver, const char* file_name, struct stat* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat) * 2) + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __LXSTAT_PAT, &ret,
					stat_str_hex, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore __lxstat\n" );
	}

	hex_decode(stat_str_hex, (void*) buf, sizeof(struct stat));

	TRAP();

	return ret;
}

int replay___xstat(int ver, const char* file_name, struct stat* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat) * 2) + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __XSTAT_PAT, &ret,
					stat_str_hex, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore __xstat\n" );
	}

	hex_decode(stat_str_hex, (void*) buf, sizeof(struct stat));

	TRAP();

	return ret;
}

int replay___fxstat64(int ver, int filedes, struct stat64* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat64) * 2) + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FXSTAT64_PAT, &ret,
					stat_str_hex, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore __fxstat64\n" );
	}

	hex_decode(stat_str_hex, (void*) buf, sizeof(struct stat));

	TRAP();

	return ret;
}

int replay___lxstat64(int ver, const char* file_name, struct stat64* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat64) * 2) + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __LXSTAT64_PAT, &ret,
					stat_str_hex, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore __lxstat64\n" );
	}

	hex_decode(stat_str_hex, (void*) buf, sizeof(struct stat64));

	TRAP();

	return ret;
}

int replay___xstat64(int ver, const char* file_name, struct stat64* buf) {
	int ret;
	char stat_str_hex[(sizeof(struct stat64) * 2) + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __XSTAT64_PAT, &ret,
					stat_str_hex, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore __xstat64\n" );
	}

	hex_decode(stat_str_hex, (void*) buf, sizeof(struct stat64));

	TRAP();

	return ret;
}

int replay_dup(int oldfd) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __DUP_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore dup\n" );
	}

	TRAP();

	return ret;
}

int replay_dup2(int oldfd, int newfd) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __DUP2_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore dup2\n" );
	}

	TRAP();

	return ret;
}

FILE* replay_fdopen(int fildes, const char *mode) {
	FILE* ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FDOPEN_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fdopen\n" );
	}

	TRAP();

	return ret;
}

FILE* replay_freopen(const char *path, const char *mode, FILE *stream) {
	FILE* ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FREOPEN_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore freopen\n" );
	}

	TRAP();

	return ret;
}

FILE* replay_fopen(const char *path, const char *mode) {
	FILE* ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FOPEN_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fopen\n" );
	}

	TRAP();

	return ret;
}

FILE* replay_freopen64(const char *path, const char *mode, FILE *stream) {
	FILE* ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FREOPEN64_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore freopen64\n" );
	}

	TRAP();

	return ret;
}

FILE* replay_fopen64(const char *path, const char *mode) {
	FILE* ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FOPEN64_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fopen64\n" );
	}

	TRAP();

	return ret;
}

int replay_open(const char *path, int flags, va_list args) {
	int ret;
	char mypath[4096];

#if DEBUG
	lprintf("replay_open: path=%s\n", path);
#endif

#if 0
	if (overlord_should_call_through) {
		mode_t mode = 0;
		if (flags & O_CREAT) mode = va_arg(args, mode_t);
		ret = __LIBC_PTR(open)(path, flags, mode);
		return ret;
	}
#endif

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __OPEN_PAT, &ret,
					mypath, &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore open\n" );
	}

	TRAP();

	return ret;
}

int replay_open64(const char *path, int flags, va_list args) {
	int ret;
	char mypath[4096];

#if DEBUG
	lprintf("replay_open: path=%s\n", path);
#endif

#if 0
	if (overlord_should_call_through) {
		mode_t mode = 0;
		if (flags & O_CREAT) mode = va_arg(args, mode_t);
		ret = __LIBC_PTR(open)(path, flags, mode);
		return ret;
	}
#endif

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __OPEN64_PAT, &ret,
					mypath, &_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore open64\n" );
	}

	TRAP();

	return ret;
}

int replay_creat(const char *path, mode_t mode) {
	int ret;

	

#if DEBUG
	lprintf("replay_creat: path=%s\n", path);
#endif

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __CREAT_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore creat\n" );
	}

	TRAP();

	return ret;
}

int replay_feof(FILE* stream) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FEOF_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore feof\n" );
	}

	TRAP();

	return ret;
}

int replay_ferror(FILE* stream) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FERROR_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore ferror\n" );
	}

	TRAP();

	return ret;
}

int replay_fileno(FILE* stream) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FILENO_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fileno\n" );
	}

	TRAP();

	return ret;
}

int replay_fclose(FILE *stream) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FCLOSE_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fclose\n" );
	}

	TRAP();

	return ret;
}

int replay_close(int fd) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __CLOSE_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore close\n" );
	}

	TRAP();

	return ret;
}

int replay_fflush(FILE *stream) {
	int ret, new_ret;

	

	if (_private_info.done_with_execution) {
		return (*__LIBC_PTR(fflush))(stream);
	}

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FFLUSH_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fflush\n" );
	}
	if (stream == stderr || stream == stdout) {
		__INTERNAL_CALL_LIBC_2(new_ret, fflush, stream);
		assert(new_ret == ret);
	}

	TRAP();

	return ret;
}

int replay_fgetc(FILE* stream) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf,
				__FGETC_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fgetc\n" );
	}

	TRAP();

	return ret;
}

int replay_getc(FILE* stream) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf,
				__GETC_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getc\n" );
	}

	TRAP();

	return ret;
}

int replay_getchar(void) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf,
				__GETCHAR_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore getchar\n" );
	}

	TRAP();

	return ret;
}

int replay_ungetc(int c, FILE* stream) {
	int ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf,
				__UNGETC_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore ungetc\n" );
	}

	TRAP();

	return ret;
}

char* replay_gets(char* s) {
	char* ret;
	char s_hex_str[getpagesize()];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf,
				__GETS_PAT, &ret, s_hex_str,
					&_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore gets\n" );
	}

	if (s) { 
		if (strcmp(s_hex_str, "NULL") != 0) {
			hex_decode(s_hex_str, s, strlen(s_hex_str) / 2);
		}
	}

	TRAP();

	return ret;
}

char* replay_fgets(char *s, int size, FILE* stream)
{
	char* ret;
	char read_data_hex[size*2 + 1];
	char read_data[size];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __REPLAY_FGETS_PAT, &ret,
					read_data_hex, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore fgets\n" );
	}

	if( strcmp( NO_HEX_DATA, read_data_hex ) == 0 ) {
		/* It appears that nothing was logged, and thus we can only
		 * assume that nothing was read during logging. */
		read_data[0] = '\0';	// Nothing scanned
		return NULL;
	} else {
		assert((strlen(read_data_hex) / 2) <= size);
		//(*__LIBC_PTR(fprintf))(stderr, "len=%d\n", strlen(read_data_hex) / 2);
		hex_decode(read_data_hex, read_data, strlen(read_data_hex) / 2);
	}

	/* Copy the read data in the specified buffer. */
	memcpy(s, read_data, strlen(read_data_hex) / 2);

	/* Null-terminate the buffer, just like fgets does (see man page). */
	s[(strlen(read_data_hex) / 2)] = 0;
	//(*__LIBC_PTR(fprintf))(stderr, "alen=%d\n", strlen(s));

	TRAP();

	return s;
}

int replay_fscanf(FILE *stream, const char *format, va_list args) {
	int ret;
	char read_data_hex[LOG_BUF_SIZE];
	char read_data[LOG_BUF_SIZE];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __REPLAY_FSCANF_PAT, &ret,
					read_data_hex, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore fscanf\n" );
	}

	if( strcmp( NO_HEX_DATA, read_data_hex ) == 0 ) {
		read_data[0] = '\0';	// Nothing scanned
	} else {
		hex_decode(read_data_hex, read_data, strlen(read_data_hex) / 2);
	}

	vsscanf(read_data, format, args);

	TRAP();

	return ret;
}

int replay_vfscanf(FILE *stream, const char *format, va_list args) {
	int ret;
	char read_data_hex[LOG_BUF_SIZE];
	char read_data[LOG_BUF_SIZE];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __REPLAY_VFSCANF_PAT, &ret,
					read_data_hex, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore vfscanf\n" );
	}

	if( strcmp( NO_HEX_DATA, read_data_hex ) == 0 ) {
		read_data[0] = '\0';	// Nothing scanned
	} else {
		hex_decode(read_data_hex, read_data, strlen(read_data_hex) / 2);
	}

	vsscanf(read_data, format, args);

	TRAP();

	return ret;
}

int replay_fprintf(FILE *stream, const char *format, va_list args) {
	int ret, new_ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FPRINTF_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fprintf\n" );
	}

	if (stream == stderr || stream == stdout) {
		__INTERNAL_CALL_LIBC_2(new_ret, vfprintf, stream, format, args);
		//assert(new_ret == ret);
	}

	TRAP();

	return ret;
}

int replay_vfprintf(FILE *stream, const char *format, va_list ap) {
	int ret, new_ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __VFPRINTF_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore vfprintf\n" );
	}

	if (stream == stderr || stream == stdout) {
		__INTERNAL_CALL_LIBC_2(new_ret, vfprintf, stream, format, ap);
		//assert(new_ret == ret);
	}

	TRAP();

	return ret;
}

int replay_fputc(int c, FILE *stream) {
	int ret, new_ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FPUTC_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fputc\n" );
	}
	if (stream == stderr || stream == stdout) {
		__INTERNAL_CALL_LIBC_2(new_ret, fputc, c, stream);
		assert(new_ret == ret);
	}

	TRAP();

	return ret;
}

int replay_fputs(const char *s, FILE *stream) {
	int ret, new_ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FPUTS_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fputc\n" );
	}
	if (stream == stderr || stream == stdout) {
		__INTERNAL_CALL_LIBC_2(new_ret, fputs, s, stream);
		assert(new_ret == ret);
	}

	TRAP();

	return ret;
}

int replay_putc(int c, FILE *stream) {
	int ret, new_ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __PUTC_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore putc\n" );
	}
	if (stream == stderr || stream == stdout) {
		__INTERNAL_CALL_LIBC_2(new_ret, putc, c, stream);
		assert(new_ret == ret);
	}

	TRAP();

	return ret;
}

size_t replay_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;
	char read_hex_str[(size*nmemb)*2 + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __REPLAY_FREAD_PAT, &ret,
					read_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore fread\n" );
	}

	if( strcmp( NO_HEX_DATA, read_hex_str ) != 0 && ret > 0) {
		hex_decode(read_hex_str, ptr, size*ret);
	}

	TRAP();

	return ret;
}

size_t replay_fwrite(const  void  *ptr,  size_t  size,  size_t  nmemb,  FILE *stream) {
	size_t ret, new_ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FWRITE_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fwrite\n" );
	}

	if (stream == stderr || stream == stdout) {
		__INTERNAL_CALL_LIBC_2(new_ret, fwrite, ptr, size, nmemb, stream);
		assert(new_ret == ret);
	}

	TRAP();

	return ret;
}

size_t replay_fgetpos(FILE* stream, fpos_t *pos) {
	size_t ret;
	char pos_hex_str[sizeof(fpos_t)*2 + 1];

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FGETPOS_PAT, &ret,
					pos_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore fgetpos\n" );
	}

	assert(strcmp(NO_HEX_DATA, pos_hex_str) != 0);

	hex_decode(pos_hex_str, pos, sizeof(fpos_t));

	TRAP();

	return ret;
}

long replay_ftell(FILE* stream) {
	long ret;

	

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FTELL_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore ftell\n" );
	}

	TRAP();

	return ret;
}

int replay_fseek(FILE* stream, long offset, int whence) {
	int ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __FSEEK_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore fseek\n" );
	}

	TRAP();

	return ret;
}

off_t replay_lseek(int fildes, off_t offset, int whence) {
	off_t ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __LSEEK_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore lseek\n" );
	}

	TRAP();

	return ret;
}

off_t replay_lseek64(int fildes, off_t offset, int whence) {
	off_t ret;

	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __LSEEK64_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore lseek64\n" );
	}

	TRAP();

	return ret;
}

ssize_t replay_readv(int fd, const struct iovec* vector, int count) {
	ssize_t ret;

	assert(0);

	return ret;
}

ssize_t replay_writev(int fd, const struct iovec* vector, int count) {
	ssize_t ret;

	assert(0);

	return ret;
}

#endif /* WRAP_FILES */
