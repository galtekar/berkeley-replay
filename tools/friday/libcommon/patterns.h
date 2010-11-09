#ifndef PATTERNS_H
#define PATTERNS_H

#include "logreplay.h"


#define NO_HEX_DATA "-"


#define __EXECVP_PAT "<execvp r=%d vc=\"%llu\"/>\n"

#define __GETRLIMIT_PAT "<getrlimit r=%d limit=%s vc=\"%llu\"/>\n"
#define __GETRUSAGE_PAT "<getrusage r=%d limit=%s vc=\"%llu\"/>\n"

#define __NANOSLEEP_PAT "<nanosleep r=%d rem=%s vc=\"%llu\"/>\n"
#define __OPENLOG_PAT "<openlog vc=\"%llu\"/>\n"
#define __SYSLOG_PAT "<syslog vc=\"%llu\"/>\n"
#define __CLOSELOG_PAT "<closelog vc=\"%llu\"/>\n"
#define __VSYSLOG_PAT "<vsyslog vc=\"%llu\"/>\n"
#define __TRUNCATE_PAT "<truncate r=%d vc=\"%llu\"/>\n"
#define __FTRUNCATE_PAT "<ftruncate r=%d vc=\"%llu\"/>\n"
#define __CHMOD_PAT "<chmod r=%d vc=\"%llu\"/>\n"
#define __FCHMOD_PAT "<fchmod r=%d vc=\"%llu\"/>\n"
#define __UTIME_PAT "<utime r=%d vc=\"%llu\"/>\n"
#define __SIGPROCMASK_PAT "<sigprocmask r=%d oldset=%s vc=\"%llu\"/>\n"
#define __SIGPENDING_PAT "<sigpending r=%d sigset=%s vc=\"%llu\"/>\n"
#define __SIGSUSPEND_PAT "<sigsuspend r=%d vc=\"%llu\"/>\n"
#define __ALARM_PAT "<alarm r=%d vc=\"%llu\"/>\n"


#define __SETFSUID_PAT "<setfsuid r=%d vc=\"%llu\"/>\n"
#define __SETUID_PAT "<setuid r=%d vc=\"%llu\"/>\n"
#define __SETSID_PAT "<setsid r=%d vc=\"%llu\"/>\n"
#define __SETPGID_PAT "<setpgid r=%d vc=\"%llu\"/>\n"
#define __SETGID_PAT "<setgid r=%d vc=\"%llu\"/>\n"
#define __SETFSGID_PAT "<setfsgid r=%d vc=\"%llu\"/>\n"
#define __SETREUID_PAT "<setreuid r=%d vc=\"%llu\"/>\n"
#define __SETREGID_PAT "<setregid r=%d vc=\"%llu\"/>\n"
#define __SETPGRP_PAT "<setpgrp r=%d vc=\"%llu\"/>\n"
#define __TCSETPGRP_PAT "<tcsetpgrp r=%d vc=\"%llu\"/>\n"
#define __TCGETPGRP_PAT "<tcgetpgrp r=%d vc=\"%llu\"/>\n"
#define __GETGID_PAT "<getgid r=%d vc=\"%llu\"/>\n"
#define __GETEGID_PAT "<getegid r=%d vc=\"%llu\"/>\n"
#define __GETUID_PAT "<getuid r=%d vc=\"%llu\"/>\n"
#define __GETEUID_PAT "<geteuid r=%d vc=\"%llu\"/>\n"
#define __ISATTY_PAT "<isatty r=%d vc=\"%llu\"/>\n"

#define __READDIR_PAT "<readdir r=%p dirent=%s vc=\"%llu\"/>\n"
#define __READDIR64_PAT "<readdir64 r=%p dirent=%s vc=\"%llu\"/>\n"
#define __OPENDIR_PAT "<opendir r=%p vc=\"%llu\"/>\n"
#define __CLOSEDIR_PAT "<closedir r=%d vc=\"%llu\"/>\n"
#define __DIRFD_PAT "<dirfd r=%d vc=\"%llu\"/>\n"
#define __REWINDDIR_PAT "<rewinddir vc=\"%llu\"/>\n"
#define __SEEKDIR_PAT "<seekdir vc=\"%llu\"/>\n"
#define __TELLDIR_PAT "<telldir r=%d vc=\"%llu\"/>\n"

#define __GETCWD_PAT "<getcwd r=\"%s\" vc=\"%llu\"/>\n"
#define __GETWD_PAT "<getwd r=\"%s\" vc=\"%llu\"/>\n"
#define __GET_CURRENT_DIR_NAME_PAT "<get_current_dir_name r=\"%s\" vc=\"%llu\"/>\n"
#define __RMDIR_PAT "<rmdir r=%d vc=\"%llu\"/>\n"
#define __MKDIR_PAT "<mkdir r=%d vc=\"%llu\"/>\n"
#define __RENAME_PAT "<rename r=%d vc=\"%llu\"/>\n"
#define __LINK_PAT "<link r=%d vc=\"%llu\"/>\n"
#define __MKNOD_PAT "<mknod r=%d vc=\"%llu\"/>\n"
#define __MOUNT_PAT "<mount r=%d vc=\"%llu\"/>\n"
#define __UMOUNT_PAT "<umount r=%d vc=\"%llu\"/>\n"
#define __UMOUNT2_PAT "<umount2 r=%d vc=\"%llu\"/>\n"
#define __UMASK_PAT "<umask r=%d vc=\"%llu\"/>\n"
#define __MKFIFO_PAT "<mkfifo r=%d vc=\"%llu\"/>\n"

#define __GETS_PAT "<gets r=%p buf=%s vc=\"%llu\"/>\n"
#define __GETC_PAT "<getc r=%d vc=\"%llu\"/>\n"
#define __GETCHAR_PAT "<getchar r=%d vc=\"%llu\"/>\n"
#define __UNGETC_PAT "<ungetc r=%d vc=\"%llu\"/>\n"

#define __GETSOCKOPT_PAT "<getsockopt r=%d optval=%d vc=\"%llu\"/>\n"
#define __SETSOCKOPT_PAT "<setsockopt r=%d vc=\"%llu\"/>\n"

#define __GETPROTOENT_PAT "<getprotoent r=%ld flat_str=%s vc=\"%llu\"/>\n"
#define __GETPROTOBYNAME_PAT "<getprotobyname r=%ld flat_str=%s vc=\"%llu\"/>\n"
#define __GETPROTOBYNUMBER_PAT "<getprotobynumber r=%ld flat_str=%s vc=\"%llu\"/>\n"

#define __GETSERVENT_PAT "<getservent r=%ld flat_str=%s vc=\"%llu\"/>\n"
#define __GETSERVBYNAME_PAT "<getservbyname r=%ld flat_str=%s vc=\"%llu\"/>\n"
#define __GETSERVBYPORT_PAT "<getservbyport r=%ld flat_str=%s vc=\"%llu\"/>\n"

#define __GETPWNAM_PAT "<getpwnam r=%s vc=\"%llu\"/>\n"
#define __GETPWUID_PAT "<getpwuid r=%s vc=\"%llu\"/>\n"
#define __GETGRNAM_PAT "<getgrnam r=%s vc=\"%llu\"/>\n"
#define __GETGRGID_PAT "<getgrgid r=%s vc=\"%llu\"/>\n"

#define __XSTAT_PAT "<stat r=\"%d\" stat_str_hex=%s vc=\"%llu\"/>\n"
#define __FXSTAT_PAT "<fstat r=\"%d\" stat_str_hex=%s vc=\"%llu\"/>\n"
#define __LXSTAT_PAT "<lstat r=\"%d\" stat_str_hex=%s vc=\"%llu\"/>\n"
#define __XSTAT64_PAT "<stat64 r=\"%d\" stat_str_hex=%s vc=\"%llu\"/>\n"
#define __FXSTAT64_PAT "<fstat64 r=\"%d\" stat_str_hex=%s vc=\"%llu\"/>\n"
#define __LXSTAT64_PAT "<lstat64 r=\"%d\" stat_str_hex=%s vc=\"%llu\"/>\n"


#define __CHDIR_PAT "<chdir r=\"%d\" vc=\"%llu\"/>\n"
#define __FCHDIR_PAT "<fchdir r=\"%d\" vc=\"%llu\"/>\n"
#define __UNLINK_PAT "<unlink r=\"%d\" vc=\"%llu\"/>\n"

#define __IOCTL_PAT "<ioctl r=\"%d\" request=\"%lu\" data=%s vc=\"%llu\"/>\n"

#define __FCNTL_PAT "<fcntl r=\"%d\" flock=%s vc=\"%llu\"/>\n"

#define __LISTEN_PAT "<listen r=\"%d\" vc=\"%llu\"/>\n"

#define __LOG_ACCEPT_PAT "<accept r=\"%d\" f=\"%s:%hu\" vc=\"%llu\"/>\n"

#define __REPLAY_ACCEPT_PAT "<accept r=\"%d\" f=\"%[^:]:%hu\" vc=\"%llu\"/>\n"

#define __CONNECT_PAT "<connect r=\"%d\" vc=\"%llu\"/>\n"

#define __TIME_PAT "<time r=\"%lu\" vc=\"%llu\"/>\n"

#define __LOG_CTIME_PAT "<ctime r=\"%s\" vc=\"%llu\"/>\n"
#define __REPLAY_CTIME_PAT "<ctime r=\"%[^\"]\" vc=\"%llu\"/>\n"

#define __GETPID_PAT "<getpid r=\"%d\" vc=\"%llu\"/>\n"
#define __GETPGRP_PAT "<getpgrp r=\"%d\" vc=\"%llu\"/>\n"
#define __GETPGID_PAT "<getpgid r=\"%d\" vc=\"%llu\"/>\n"

#define __GETTID_PAT "<gettid r=\"%d\" vc=\"%llu\"/>\n"

#define __PTHREAD_SELF_PAT "<pthread_self r=\"%lu\" vc=\"%llu\"/>\n"

#define __SLEEP_PAT "<sleep r=\"%u\" vc=\"%llu\"/>\n"

#define __BIND_PAT "<bind r=\"%d\" vc=\"%llu\"/>\n"
#define __PIPE_PAT "<pipe r=\"%d\" vc=\"%llu\"/>\n"

#define __SOCKETPAIR_PAT "<socketpair r=\"%d\" domain=\"%d\" type=\"%d\" protocol=\"%d\" sv1=\"%d\" sv2=\"%d\" vc=\"%llu\"/>\n"

#define __SOCKET_PAT "<socket r=\"%d\" domain=\"%d\" type=\"%d\" protocol=\"%d\" vc=\"%llu\"/>\n"

/* Shared memory support. */
#define __MMAP_PAT "<mmap r=\"0x%lx\" vc=\"%llu\"/>\n"
#define __MUNMAP_PAT "<munmap r=\"0x%x\" vc=\"%llu\"/>\n"
#define __SHMGET_PAT "<shmget r=\"0x%x\" vc=\"%llu\"/>\n"
#define __SHMAT_PAT "<shmat r=\"0x%lx\" vc=\"%llu\"/>\n"
#define __SHMDT_PAT "<shmdt r=\"0x%x\" vc=\"%llu\"/>\n"
#define __PTHREAD_MUTEX_LOCK_PAT "<pthread_mutex_lock r=\"%d\" vc=\"%llu\"/>\n"
#define __PTHREAD_MUTEX_UNLOCK_PAT "<pthread_mutex_unlock r=\"%d\" vc=\"%llu\"/>\n"

#define __FORK_PAT "<fork r=\"%d\" tid=\"%lu\" vc=\"%llu\"/>\n"
#define __KILL_PAT "<kill r=\"%d\" vc=\"%llu\"/>\n"
#define __KILLPG_PAT "<killpg r=\"%d\" vc=\"%llu\"/>\n"

#define __RANDOM_PAT "<random r=\"0x%lx\" vc=\"%llu\"/>\n"
#define __RAND_PAT "<rand r=\"%d\" vc=\"%llu\"/>\n"

#define __POLL_PAT "<poll r=\"%d\" pollfd=%s vc=\"%llu\"/>\n"

#define __SELECT_PAT "<select r=\"%d\" readfds=%s writefds=%s exceptfds=%s timeout=%s e=\"%d\" vc=\"%llu\"/>\n"

#define __GETTIMEOFDAY_PAT "<gettimeofday r=\"%d\" timeval=%s timezone=%s vc=\"%llu\"/>\n"

#define __REPLAY_RECVFROM_PAT "<recvfrom r=\"%d\" f=\"%[^:]:%hu\" bytes=\"%[0-9a-fNUL]\" tag=\"%[^@]@%llu\" vc=\"%llu\"/>\n"

#define __REPLAY_RECV_PAT "<recv r=\"%d\" bytes=%s tag=\"%[^@]@%llu\" vc=\"%llu\"/>\n"

#define __LOG_RECVFROM_PAT "<recvfrom r=\"%d\" f=\"%s:%hu\" bytes=\"%s\" tag=\"%s@%llu\" vc=\"%llu\"/>\n"

#define __LOG_RECV_PAT "<recv r=\"%d\" bytes=%s tag=\"%s@%llu\" vc=\"%llu\"/>\n"

#define __REPLAY_SENDTO_PAT "<sendto r=\"%d\" t=\"%[^:]:%hu\" tag=\"%[^@]@%llu\" vc=\"%llu\"/>\n"

#define __REPLAY_SEND_PAT "<send r=\"%d\" bytes=\"%[0-9a-fNUL]\" tag=\"%[^@]@%llu\" vc=\"%llu\"/>\n"

#define __LOG_SENDTO_PAT "<sendto r=\"%d\" t=\"%s:%hu\" tag=\"%s@%llu\" vc=\"%llu\"/>\n"

#define __LOG_SEND_PAT "<send r=\"%d\" bytes=\"%s\" tag=\"%s@%llu\" vc=\"%llu\"/>\n"

#define __SIGNAL_PAT "<signal signum=\"%d\" pc=\"0x%x\" context=%s vc=\"%llu\"/>\n"

#define __SIGSEGV_PAT "<signal signum=\"%d\" pc=\"0x%x\" vc=\"%llu\"/>\n"


#define __SETBUF_PAT "<setbuf vc=\"%llu\"/>\n"
#define __SETBUFFER_PAT "<setbuffer vc=\"%llu\"/>\n"
#define __SETLINEBUF_PAT "<setlinebuf vc=\"%llu\"/>\n"
#define __SETVBUF_PAT "<setvbuf r=\"%d\" vc=\"%llu\"/>\n"

#define __FOPEN_PAT "<fopen r=\"%p\" vc=\"%llu\"/>\n"
#define __FDOPEN_PAT "<fdopen r=\"%p\" vc=\"%llu\"/>\n"
#define __FREOPEN_PAT "<freopen r=\"%p\" vc=\"%llu\"/>\n"
#define __FOPEN64_PAT "<fopen64 r=\"%p\" vc=\"%llu\"/>\n"
#define __FREOPEN64_PAT "<freopen64 r=\"%p\" vc=\"%llu\"/>\n"
#define __DUP_PAT "<dup r=\"%d\" vc=\"%llu\"/>\n"
#define __DUP2_PAT "<dup2 r=\"%d\" vc=\"%llu\"/>\n"

#define __OPEN_PAT "<open r=\"%d\" path=\"%s\" vc=\"%llu\"/>\n"
#define __OPEN64_PAT "<open64 r=\"%d\" path=\"%s\" vc=\"%llu\"/>\n"

#define __CREAT_PAT "<creat r=\"%d\" vc=\"%llu\"/>\n"

#define __FEOF_PAT "<feof r=\"%d\" vc=\"%llu\"/>\n"

#define __FCLOSE_PAT "<fclose r=\"%d\" vc=\"%llu\"/>\n"

#define __CLOSE_PAT "<close r=\"%d\" vc=\"%llu\"/>\n"

#define __FFLUSH_PAT "<fflush r=\"%d\" vc=\"%llu\"/>\n"


#define __LOG_FGETS_PAT "<fgets r=\"%p\" read_data=\"%s\" vc=\"%llu\"/>\n"
#define __REPLAY_FGETS_PAT "<fgets r=\"%p\" read_data=\"%[0-9a-f-]\" vc=\"%llu\"/>\n"
#define __FGETC_PAT "<fgetc r=\"%d\" vc=\"%llu\"/>\n"

#define __LOG_FSCANF_PAT "<fscanf r=\"%d\" read_data=\"%s\" vc=\"%llu\"/>\n"
#define __REPLAY_FSCANF_PAT "<fscanf r=\"%d\" read_data=\"%[0-9a-f-]\" vc=\"%llu\"/>\n"

#define __LOG_VFSCANF_PAT "<vfscanf r=\"%d\" read_data=\"%s\" vc=\"%llu\"/>\n"
#define __REPLAY_VFSCANF_PAT "<vfscanf r=\"%d\" read_data=\"%[0-9a-f-]\" vc=\"%llu\"/>\n"
#define __FPRINTF_PAT "<fprintf r=\"%d\" vc=\"%llu\"/>\n"

#define __VFPRINTF_PAT "<vfprintf r=\"%d\" vc=\"%llu\"/>\n"

#define __FPUTC_PAT "<fputc r=\"%d\" vc=\"%llu\"/>\n"

#define __FPUTS_PAT "<fputs r=\"%d\" vc=\"%llu\"/>\n"

#define __PUTC_PAT "<putc r=\"%d\" vc=\"%llu\"/>\n"

#define __LOG_FREAD_PAT "<fread r=\"%d\" read_data=\"%s\" vc=\"%llu\"/>\n"
#define __REPLAY_FREAD_PAT "<fread r=\"%d\" read_data=\"%[0-9a-f-]\" vc=\"%llu\"/>\n"

//#define __LOG_READ_PAT "<read r=\"%d\" read_data=\"%s\" vc=\"%llu\"/>\n"
//#define __REPLAY_READ_PAT "<read r=\"%d\" read_data=\"%[0-9a-f-]\" vc=\"%llu\"/>\n"
#define __REPLAY_READ_PAT "<read r=\"%d\" bytes=%s tag=\"%[^@]@%llu\" vc=\"%llu\"/>\n"
#define __LOG_READ_PAT "<read r=\"%d\" bytes=%s tag=\"%s@%llu\" vc=\"%llu\"/>\n"

#define __FWRITE_PAT "<fwrite r=\"%d\" vc=\"%llu\"/>\n"

#define __WRITE_PAT "<write r=\"%d\" vc=\"%llu\"/>\n"

#define __FGETPOS_PAT "<fgetpos r=\"%d\" pos=%s vc=\"%llu\"/>\n"

#define __UNAME_PAT "<uname r=\"%d\" buf=%s vc=\"%llu\"/>\n"

#define __GETHOSTNAME_PAT "<gethostname r=\"%d\" name=%s vc=\"%llu\"/>\n"
#define __SETHOSTNAME_PAT "<sethostname r=\"%d\" vc=\"%llu\"/>\n"


#define __GETHOSTBYNAME_PAT "<gethostbyname r=%ld hostent_flat=%s vc=\"%llu\"/>\n"

#define __PTHREAD_CREATE_PAT "<pthread_create r=%d pid=%d tid=%lu vc=\"%llu\"/>\n"
#define __PTHREAD_JOIN_PAT "<pthread_join r=%d pid=%ld tid=%lu vc=\"%llu\"/>\n"

#define __PTHREAD_EXIT_PAT "<pthread_exit vc=\"%llu\"/>\n"

#define __SETITIMER_PAT "<setitimer r=%d vc=\"%llu\"/>\n"

#define __WAIT_PAT "<wait r=%d status=%d vc=\"%llu\"/>\n"

#define __WAITPID_PAT "<waitpid r=%d status=%d vc=\"%llu\"/>\n"

#define __FILENO_PAT "<fileno r=%d vc=\"%llu\"/>\n"

#define __FERROR_PAT "<ferror r=%d vc=\"%llu\"/>\n"

#define __SYSTEM_PAT "<system r=%d vc=\"%llu\"/>\n"

#define __ABORT_PAT "<abort vc=\"%llu\"/>\n"

#define __LOG_GETENV_PAT "<getenv r=\"%s\" name=\"%s\" vc=\"%llu\"/>\n"
#define __REPLAY_GETENV_PAT "<getenv r=\"%[^\"]\" name=\"%*[^\"]\" vc=\"%llu\"/>\n"

#define __FTELL_PAT "<ftell r=%ld vc=\"%llu\"/>\n"

#define __FSEEK_PAT "<fseek r=%d vc=\"%llu\"/>\n"
#define __LSEEK_PAT "<lseek r=%d vc=\"%llu\"/>\n"
#define __LSEEK64_PAT "<lseek64 r=%d vc=\"%llu\"/>\n"

#define __ERRNO_PAT "<errno e=%d/>\n"
#endif
