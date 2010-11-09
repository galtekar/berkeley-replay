#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <syscall.h>


#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#define __USE_GNU
#include <signal.h>

#include "logreplay.h"
#include "replay.h"
#include "misc.h"
#include "patterns.h"
#include "gcc.h"
#include "hexops.h"
#include "util.h"
#include "errops.h"
#include "tmalloc.h"
#include "libc_pointers.h"

#define DEBUG 1
#include "debug.h"

void* alt_stack = NULL;

/* Save the handler specified for sig in the corresponding bin. */
static int save_signal_handler(int sig, const struct sigaction* act,
		struct sigaction* old_act) {

	if ( ! (0 < sig && sig < NSIG) ) return -1;

	if (old_act) *old_act = _private_info.orig_handlers[sig-1];

	/* According to the man-page, act can be NULL. */
	if (act) _private_info.orig_handlers[sig-1] = *act;

	return 1;
}

static void replay_segv_handler(int signum, siginfo_t *sip, ucontext_t *scp) {

	/* This handler may be called on a SIGBUS or SIGHUP, which we don't
	 * handle or understand. */
	assert(signum == SIGSEGV);

#if 1
	/* Debugger should install a breakpoint here. The debugger should look 
	 * at scp->uc_mcontext.cr2 (see ucontext.h for details) for memory location
	 * which caused the fault. */

	DEBUG_MSG(2, "\n");
	DEBUG_MSG(2, "************************************************************\n");
	DEBUG_MSG(2, "* LIBREPLAY caught SIGSEGV:                                *\n");
	DEBUG_MSG(2, "*                                                          *\n");
	DEBUG_MSG(2, "* PID: %5d    CR2: 0x%8.8lx   EIP: 0x%8.8x          *\n",
			syscall(SYS_getpid), scp->uc_mcontext.cr2,
			scp->uc_mcontext.gregs[REG_EIP]);
	DEBUG_MSG(2, "************************************************************\n");
	hook_for_gdb( LL_HOOK_SEGV, scp );
#endif

	return;
}

/* Revert to the default handler for all (possible) signals. */
void HIDDEN libreplay_default_signal_handlers() {
	int i;
	struct sigaction sa;

	for (i = 0; i < NSIG; i++) {
		memset(&sa, 0x0, sizeof(sa));
		sigemptyset(&sa.sa_mask);

		/* We are not allowed to catch some signals; that's okay. */
		__LIBC_PTR(signal)(i, SIG_DFL);

		/* IMPORTANT: sigaction must be called through the libc function,
		 * since the semantics change if you invoke it directly via the
		 * syscall interface. In particular, sininfo_t doesn't seemed to
		 * to get passed to the signal handler if you use syscall. */
	}

	return;
}

static void sigusr1_handler(int signum) {
	/* We assume the app doesn't make use of this signal, and therefore
	 * we assume it is available for use as a ``take checkpoint''
	 * signal (and we use it as that). */
	assert(!_private_info.orig_handlers[signum - 1].sa_handler);

	/* This process should be the checkpoint slave, not master. */
	assert(_private_info.is_ckpt_master == 0);

	/* Write a new checkpoint. */
	if (!libreplay_drop_checkpoint(_shared_info->vclock)) {

		/* Wait until all processes have dropped a checkpoint. We 
		 * don't want this proc to modify shared state before
		 * others have had a chance to take a checkpoint, since that
		 * would result in inconsistent state on recovery. */
		my_barrier_wait(&_shared_info->proc_ckpt_barrier,
				_shared_info->num_procs);
	} else {
		/* We should never make it here, since we do a longjmp
		 * in libreplay:start_replay():restore_threads() on 
		 * non-ckpt-master threads. */
		assert(0);
	}
}

void HIDDEN libreplay_install_signal_handlers() {
	int i;
	struct sigaction sa;

	for (i = 0; i < NSIG; i++) {
		memset(&sa, 0x0, sizeof(sa));
		sigemptyset(&sa.sa_mask);

		switch (i) {
			case SIGSEGV: 
				{
					if ((alt_stack = tmalloc(SIGSTKSZ)) == NULL) {
						fatal("Can't allocate the alternate signal stack!\n");
					}

					alt_stack = (char*)alt_stack + SIGSTKSZ - 4;

#if 1
					{
						stack_t s;
						const int size = SIGSTKSZ;

						s.ss_sp = tmalloc(size);
						s.ss_flags = SS_ONSTACK;
						s.ss_size = size - 32 /* slack */;
						if (s.ss_sp) {
							if (sigaltstack(&s, NULL) != 0) {
								fatal("Can't specify an alternate signal stack!\n");
							}
						} else {
							fatal("Can't allocate alternate signal stack.\n");
						}
					}
#endif

					sa.sa_sigaction = (void (*) (int, siginfo_t*, void*)) replay_segv_handler;
					sigemptyset(&sa.sa_mask);
#if 1
					sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
#else
					sa.sa_flags = SA_SIGINFO;
#endif
					__LIBC_PTR(sigaction)(i, &sa, NULL);
				}
				break;
			case SIGUSR1:
				sa.sa_handler = &sigusr1_handler;
				sigemptyset(&sa.sa_mask);
				sa.sa_flags = 0;
				__LIBC_PTR(sigaction)(i, &sa, NULL);
				break;
			default:
				break;
		}
	}

	assert(alt_stack != NULL);

	return;
}

/* Signals are more complicated to handle, and that's why it's 
 * isolated from the other wrappers. Note that the same
 * wrapper is used for both log and replay modes, since the
 * signal handling logic in both modes is essentially the same. */
sighandler_t replay_signal(int signum, sighandler_t handler) {
	struct sigaction act, old_act;

	if (!_private_info.done_with_init) {
		/* A library is calling signal(), so call through. We use the
		 * syscall since the libc pointers haven't been initialized yet. */
		return (sighandler_t) syscall(SYS_signal, signum, handler);
	}

	/* Key point: don't actually install the signal, just keep
	 * track of what handler we should forward the signal to once
	 * it is received. Recall that we've installed covert signal
	 * handlers for all the signals. */

	/* Save the original signal handler so that we can invoke it later. */
	act.sa_handler = handler;
	save_signal_handler(signum, &act, &old_act);

	/* Return the previous value of the signal handler. */
	return old_act.sa_handler;
}

int replay_sigaction(int signum, const struct sigaction *act, struct sigaction
		*oldact) {

	return save_signal_handler(signum, act, oldact);
}

int replay_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	int ret;
	char buf_hex_str[sizeof(sigset_t) * 2 + 1];



	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SIGPROCMASK_PAT, &ret,
					buf_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore sigprocmask\n" );
	}

	if (oldset) {
		hex_decode(buf_hex_str, oldset, sizeof(sigset_t));
	}

	TRAP();

	return ret;
}

int replay_sigpending(sigset_t *set) {
	int ret;
	char buf_hex_str[sizeof(sigset_t) * 2 + 1];



	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SIGPENDING_PAT, &ret,
					buf_hex_str, &_shared_info->vclock ) != 3) ) {
		stop_replay( "could not restore sigpending\n" );
	}

	if (set) {
		hex_decode(buf_hex_str, set, sizeof(sigset_t));
	}

	TRAP();

	return ret;
}

int replay_sigsuspend(const sigset_t *mask) {
	int ret;



	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SIGSUSPEND_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore sigsuspend\n" );
	}

	TRAP();

	return ret;
}

int replay_setitimer(int which, const struct itimerval *value,
		struct itimerval *ovalue) {

	int ret;



	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __SETITIMER_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore setitimer\n" );
	}

	/* We don't want to actually set the timer. If we do, then
	 * we may get a SIGALRM. This is bad, because it may not happen
	 * at the exact same point as that of the original execution. Instead,
	 * deliver SIGALRMs based on what the log tells us. Thus, this
	 * function basically does nothing, except pretend like it
	 * succeeded. */

	return ret;
}

unsigned int replay_alarm(unsigned int seconds) {
	unsigned int ret;



	if( ! LOG_TO_BUF() || (sscanf( libreplay_io_buf, __ALARM_PAT, &ret,
					&_shared_info->vclock ) != 2) ) {
		stop_replay( "could not restore alarm\n" );
	}

	/* We don't want to actually set the timer. If we do, then
	 * we may get a SIGALRM. This is bad, because it may not happen
	 * at the exact same point as that of the original execution. Instead,
	 * deliver SIGALRMs based on what the log tells us. Thus, this
	 * function basically does nothing, except pretend like it
	 * succeeded. */

	return ret;
}
