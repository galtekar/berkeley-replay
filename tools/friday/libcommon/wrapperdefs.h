/* IMPORTANT: DO NOT place inclusion headers in this file. They were
 * left out on purpose so that we can include this file in multiple
 * places in the same file. */
#define __USE_LARGEFILE64
#include <stdarg.h>
#include <netdb.h>
#include <unistd.h>
#include <utime.h>
#define __USE_GNU
#include <signal.h>

#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/poll.h>

#include <dirent.h>

/*
 * WRAPPERDEF is for non-variadic functions that have non-void return values.
 * WRAPPERDEF_VARG is for variadic functions that have non-void return
 * values. Do not include the ``...''--it will be automatically appended.
 * WRAPPERDEF_NORET is for non-variadic functions with void return values.
 * WRAPPERDEF_NORET_VARG is for varidatic function with void return values.
 */

/* Process. */
WRAPPERDEF(pid_t, getpid, ());
WRAPPERDEF(pid_t, getpgrp, ());
WRAPPERDEF(pid_t, getpgid, (pid), pid_t pid);
WRAPPERDEF(pid_t, fork, ());
WRAPPERDEF(int, nanosleep, (req, rem), const struct timespec *req, struct timespec *rem);
WRAPPERDEF(unsigned int, sleep, (seconds), unsigned int seconds);
WRAPPERDEF(pid_t, wait, (status), int* status);
WRAPPERDEF(pid_t, waitpid, (pid, status, options), pid_t pid, int* status, int options);
WRAPPERDEF(int, system, (string), const char* string);
WRAPPERDEF_NORET(abort, ());
WRAPPERDEF(char*, getenv, (name), const char *name);
WRAPPERDEF(int, setfsuid, (fsuid), uid_t fsuid);
WRAPPERDEF(int, setuid, (uid), uid_t uid);
WRAPPERDEF(pid_t, setsid, ());
WRAPPERDEF(int, setpgid, (pid, pgid), pid_t pid, pid_t pgid);
WRAPPERDEF(int, setgid, (gid), gid_t gid);
WRAPPERDEF(int, setfsgid, (fsgid), uid_t fsgid);
WRAPPERDEF(int, setreuid, (ruid, euid), uid_t ruid, uid_t euid);
WRAPPERDEF(int, setregid, (rgid, egid), gid_t rgid, gid_t egid);
WRAPPERDEF(int, setpgrp, ());
WRAPPERDEF(pid_t, tcgetpgrp, (fd), int fd);
WRAPPERDEF(int, tcsetpgrp, (fd, pgrp), int fd, pid_t pgrp);
WRAPPERDEF(gid_t, getgid, ());
WRAPPERDEF(gid_t, getegid, ());
WRAPPERDEF(uid_t, getuid, ());
WRAPPERDEF(uid_t, geteuid, ());
WRAPPERDEF(int, kill, (pid, sig), pid_t pid, int sig);
WRAPPERDEF(int, killpg, (pgrp, sig), int pgrp, int sig);
WRAPPERDEF_VARG(int, execl, arg, (path, arg, args), const char *path, const char *arg);
WRAPPERDEF(int, execvp, (file, argv), const char *file, char *const argv[]);


/* Authentication. */
WRAPPERDEF(struct passwd*, getpwnam, (name), const char *name);
WRAPPERDEF(struct passwd*, getpwuid, (uid), uid_t uid);
WRAPPERDEF(struct group *, getgrnam, (name), const char *name);
WRAPPERDEF(struct group *, getgrgid, (gid), gid_t gid);

/* Misc. */
WRAPPERDEF(int, getrlimit, (resource, rlim), int resource, struct rlimit *rlim);
WRAPPERDEF(int, getrusage, (who, usage), int who, struct rusage *usage);
WRAPPERDEF(int, isatty, (desc), int desc);
WRAPPERDEF_NORET(openlog, (ident, option, facility), const char *ident, int option, int facility);
WRAPPERDEF_NORET_VARG(syslog, format, (priority, format, args), int priority, const char *format);
WRAPPERDEF_NORET(closelog, ());
WRAPPERDEF_NORET(vsyslog, (priority, format, ap), int priority, const char *format, va_list ap);
WRAPPERDEF(int, uname, (buf), struct utsname *buf);
WRAPPERDEF_VARG(int, ioctl, request, (d, request, args), int d, unsigned long int request);
WRAPPERDEF(time_t, time, (t), time_t *t);
WRAPPERDEF(char*, ctime, (timep), const time_t *timep);
WRAPPERDEF(unsigned int, alarm, (seconds), unsigned int seconds);
WRAPPERDEF(int, setitimer, (which, value, ovalue), int which, const struct itimerval *value,
		struct itimerval *ovalue);
WRAPPERDEF(long, random, ());
WRAPPERDEF(int, rand, ());
WRAPPERDEF(int, gettimeofday, (tv, tz), struct timeval *tv, struct timezone *tz);
WRAPPERDEF(int, gethostname, (name, len), char *name, size_t len);
WRAPPERDEF(int, sethostname, (name, len), const char *name, size_t len);

/* Files. */
WRAPPERDEF_NORET(setbuf, (stream, buf), FILE *stream, char *buf);
WRAPPERDEF_NORET(setbuffer, (stream, buf, size), FILE *stream, char *buf, size_t size);
WRAPPERDEF_NORET(setlinebuf, (stream), FILE *stream);
WRAPPERDEF(int, setvbuf, (stream, buf, mode, size), FILE *stream, char *buf, int mode , size_t size);
WRAPPERDEF(int, dup, (oldfd), int oldfd);
WRAPPERDEF(int, dup2, (oldfd, newfd), int oldfd, int newfd);
WRAPPERDEF(FILE*, fopen, (path, mode), const char *path, const char *mode);
WRAPPERDEF(FILE*, fdopen, (fildes, mode), int fildes, const char *mode);
WRAPPERDEF(FILE*, freopen, (path, mode, stream), const char *path, const char *mode, FILE *stream);
WRAPPERDEF(FILE*, fopen64, (filename, modes), const char * filename, const char * modes);
WRAPPERDEF(FILE*, freopen64, (filename, modes, stream), const char * filename, const char * modes, FILE * stream);
WRAPPERDEF(int, __xstat, (ver, file_name, buf), int ver, const char *file_name, struct stat *buf);
WRAPPERDEF(int, __fxstat, (ver, filedes, buf), int ver, int filedes, struct stat *buf);
WRAPPERDEF(int, __lxstat, (ver, file_name, buf), int ver, const char *file_name, struct stat *buf);
WRAPPERDEF(int, __xstat64, (ver, file_name, buf), int ver, const char *file_name, struct stat64 *buf);
WRAPPERDEF(int, __fxstat64, (ver, filedes, buf), int ver, int filedes, struct stat64 *buf);
WRAPPERDEF(int, __lxstat64, (ver, file_name, buf), int ver, const char *file_name, struct stat64 *buf);
WRAPPERDEF(char*, getcwd, (buf, size), char* buf, size_t size);
WRAPPERDEF(char *, get_current_dir_name, ());
WRAPPERDEF(char *, getwd, (buf), char *buf);
WRAPPERDEF(int, rmdir, (pathname), const char *pathname);
WRAPPERDEF(int, mkdir, (pathname, mode), const char *pathname, mode_t mode);
WRAPPERDEF(int, rename, (oldpath, newpath), const char *oldpath, const char *newpath);
WRAPPERDEF(int, link, (oldpath, newpath), const char *oldpath, const char *newpath);
WRAPPERDEF(int, __xmknod, (ver, pathname, mode, dev), int ver, const char *pathname, mode_t mode, dev_t* dev); /* Listed as ``mknod'' in man page, but in header files as ``__xmknod''. */
WRAPPERDEF(int, mount, (source, target, filesystemtype, mountflags, data), const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);
WRAPPERDEF(int, umount, (target), const char *target);
WRAPPERDEF(int, umount2, (target, flags), const char *target, int flags);
WRAPPERDEF(mode_t, umask, (mask), mode_t mask);
WRAPPERDEF(int, mkfifo, (pathname, mode), const char *pathname, mode_t mode);
WRAPPERDEF(int, chdir, (path), const char* path);
WRAPPERDEF(int, fchdir, (fd), int fd);
WRAPPERDEF(int, unlink, (pathname), const char* pathname);
WRAPPERDEF_VARG(int, fcntl, cmd, (fd, cmd, args), int fd, int cmd);
WRAPPERDEF(int, feof, (stream), FILE *stream);
WRAPPERDEF(int, fileno, (stream), FILE *stream);
WRAPPERDEF(int, ferror, (stream), FILE *stream);
WRAPPERDEF(void*, dlopen, (filename, flag), const char *filename, int flag);
WRAPPERDEF_VARG(int, open, flags, (path, flags, args), const char *path, int flags);
WRAPPERDEF_VARG(int, open64, flags, (path, flags, args), const char *path, int flags);
WRAPPERDEF(int, creat, (path, mode), const char *path, mode_t mode);
WRAPPERDEF(int, fclose, (stream), FILE *stream);
WRAPPERDEF(int, close, (fd), int fd);
WRAPPERDEF(int, fflush, (stream), FILE *stream);
WRAPPERDEF(char*, fgets, (s, size, stream), char *s, int size, FILE* stream);
WRAPPERDEF(int, fgetc, (stream), FILE* stream);
WRAPPERDEF(int, getc, (stream), FILE *stream);
WRAPPERDEF(int, getchar, ());
WRAPPERDEF(char*, gets, (s), char *s);
WRAPPERDEF(int, ungetc, (c, stream), int c, FILE *stream);
WRAPPERDEF_VARG(int, fscanf, format, (stream, format, args), FILE *stream, const char *format);
WRAPPERDEF(int, vfscanf, (stream, format, ap), FILE *stream, const char *format, va_list ap);
WRAPPERDEF_VARG(int, fprintf, format, (stream, format, args), FILE *stream, const char *format);
WRAPPERDEF(int, vfprintf, (stream, format, ap), FILE *stream, const char *format, va_list ap);
WRAPPERDEF(int, fputc, (c, stream), int c, FILE *stream);
WRAPPERDEF(int, fputs, (s, stream), const char *s, FILE *stream);
WRAPPERDEF(int, putc, (c, stream), int c, FILE *stream);
WRAPPERDEF(size_t, fread, (ptr, size, nmemb, stream), void *ptr, size_t size, size_t nmemb, FILE *stream);
WRAPPERDEF(size_t, fwrite, (ptr, size, nmemb, stream), const  void  *ptr,  size_t  size,  size_t  nmemb,  FILE *stream);
WRAPPERDEF(int, fgetpos, (stream, pos), FILE* stream, fpos_t *pos);
WRAPPERDEF(long, ftell, (stream), FILE* stream);
WRAPPERDEF(int, fseek, (stream, offset, whence), FILE *stream, long offset, int whence);
WRAPPERDEF(off_t, lseek, (fildes, offset, whence), int fildes, off_t offset, int whence);
WRAPPERDEF(off_t, lseek64, (fildes, offset, whence), int fildes, off_t offset, int whence);
WRAPPERDEF(ssize_t, read, (fd, buf, count), int fd, void* buf, size_t count);
WRAPPERDEF(ssize_t, write, (fd, buf, count), int fd, const void* buf, size_t count);
//WRAPPERDEF(ssize_t, readv, (fd, vector, count), int fd, const struct iovec* vector, int count);
//WRAPPERDEF(ssize_t, writev, (fd, vector, count), int fd, const struct iovec* vector, int count);
WRAPPERDEF(struct servent*, getservent, ());
WRAPPERDEF(struct servent*, getservbyname, (name, proto), const char *name, const char *proto);
WRAPPERDEF(struct servent*, getservbyport, (port, proto), int port, const char *proto);
WRAPPERDEF_NORET(setservent, (stayopen), int stayopen);
WRAPPERDEF_NORET(endservent, ());
WRAPPERDEF(ssize_t, getline, (lineptr, n, stream), char **lineptr, size_t *n, FILE *stream);
WRAPPERDEF(ssize_t, getdelim, (lineptr, n, delim, stream), char **lineptr, size_t *n, int delim, FILE *stream);
WRAPPERDEF(int, chmod, (path, mode), const char *path, mode_t mode);
WRAPPERDEF(int, fchmod, (fildes, mode), int fildes, mode_t mode);
WRAPPERDEF(int, truncate, (path, length), const char *path, off_t length);
WRAPPERDEF(int, ftruncate, (fd, length), int fd, off_t length);
WRAPPERDEF(struct dirent*, readdir, (dir), DIR *dir);
WRAPPERDEF(struct dirent64*, readdir64, (dir), DIR *dir);
WRAPPERDEF(int, utime, (filename, buf), const char *filename, const struct utimbuf *buf);
WRAPPERDEF(DIR*, opendir, (name), const char *name);
WRAPPERDEF(int, closedir, (dir), DIR *dir);
WRAPPERDEF(int, dirfd, (dir), DIR *dir);
WRAPPERDEF_NORET(rewinddir, (dir), DIR *dir);
WRAPPERDEF(int, scandir, (dir, namelist, filter, compar), const char *dir, struct dirent ***namelist,
			int (*filter)(const struct dirent *),
			int (*compar)(const void *, const void *));
WRAPPERDEF_NORET(seekdir, (dir, offset), DIR *dir, off_t offset);
WRAPPERDEF(off_t, telldir, (dir), DIR *dir);

/* Shared memory. */
WRAPPERDEF(void*, mmap, (start, length, prot, flags, fd, offset), void* start, size_t length, int prot, int flags, int fd, off_t offset);
WRAPPERDEF(int, munmap, (start, length), void* start, size_t length);
WRAPPERDEF(int, shmget, (key, size, shmflg), key_t key, size_t size, int shmflg);
WRAPPERDEF(void*, shmat, (shmid, shmaddr, shmflg), int shmid, const void *shmaddr, int shmflg);
WRAPPERDEF(int, shmdt, (shmaddr), const void *shmaddr);

/* Signals. */
WRAPPERDEF(__sighandler_t, signal, (signum, handler), int signum, __sighandler_t handler);
WRAPPERDEF(int, sigaction, (signum, act, oldact), int signum, const struct sigaction *act, 
	struct sigaction *oldact);
WRAPPERDEF(int, sigprocmask, (how, set, oldset), int how, const sigset_t *set, sigset_t *oldset);
WRAPPERDEF(int, sigpending, (set), sigset_t *set);
WRAPPERDEF(int, sigsuspend, (mask), const sigset_t *mask);

/* Sockets. */
WRAPPERDEF(int, listen, (s, backlog), int s, int backlog);
WRAPPERDEF(int, accept, (s, addr, addrlen), int s, struct sockaddr *addr, socklen_t *addrlen);
WRAPPERDEF(int, connect, (sockfd, serv_addr, addrlen), int  sockfd,  const  struct sockaddr *serv_addr, socklen_t addrlen);
WRAPPERDEF(int, bind, (sockfd, my_addr, addrlen), int sockfd, const struct sockaddr* my_addr, socklen_t addrlen);
WRAPPERDEF(int, pipe, (filedes), int filedes[2]);
WRAPPERDEF(int, socketpair, (domain, type, protocol, sv), int domain, int type, int protocol, int sv[2]);
WRAPPERDEF(int, socket, (domain, type, protocol), int domain, int type, int protocol);
WRAPPERDEF(int, poll, (ufds, nfds, timeout), struct pollfd *ufds, nfds_t nfds, int timeout);
WRAPPERDEF(int, select, (n, readfds, writefds, exceptfds, timeout), int   n,   fd_set   *readfds,  fd_set  *writefds,  fd_set *exceptfds, struct timeval *timeout);
WRAPPERDEF(ssize_t, recvfrom, (s, buf, len, flags, from, fromlen), int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
WRAPPERDEF(ssize_t, recv, (s, buf, len, flags), int s, void *buf, size_t len, int flags);
WRAPPERDEF(ssize_t, sendto, (socket, msg, len, flags, to, tolen), int  socket,  const  void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);
WRAPPERDEF(ssize_t, send, (socket, msg, len, flags), int socket, const void *msg, size_t len, int flags);
WRAPPERDEF(struct hostent*, gethostbyname, (name), const char *name);
WRAPPERDEF(struct protoent*, getprotoent, ());
WRAPPERDEF(struct protoent*, getprotobyname, (name), const char *name);
WRAPPERDEF(struct protoent*, getprotobynumber, (proto), int proto);
WRAPPERDEF_NORET(setprotoent, (stayopen), int stayopen);
WRAPPERDEF_NORET(endprotoent, ());
WRAPPERDEF(int, getsockopt, (s, level, optname, optval, optlen), int  s, int level, int optname, void *optval, socklen_t *optlen);
WRAPPERDEF(int, setsockopt, (s, level, optname, optval, optlen), int s, int  level,  int  optname, const  void  *optval, socklen_t optlen);

/* Threads. */
WRAPPERDEF(pthread_t, pthread_self, ());
WRAPPERDEF(int , pthread_create, (thread, attr, start_routine, arg), pthread_t *thread, const pthread_attr_t *attr, 
	void * (*start_routine)(void *), void * arg);
WRAPPERDEF(int, pthread_join, (th, thread_return), pthread_t th, void **thread_return);
WRAPPERDEF_NORET(pthread_exit, (retval), void* retval);
WRAPPERDEF(int, pthread_mutex_lock, (mutex), pthread_mutex_t* mutex);
WRAPPERDEF(int, pthread_mutex_unlock, (mutex), pthread_mutex_t* mutex);
