#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <assert.h>
#include <errno.h>
#include <syscall.h>
#define __USE_GNU
#include <signal.h>
#include <pthread.h>
#include <ckpt.h>

#include <sched.h>

#define __USE_GNU
#include <ucontext.h>

#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <linux/unistd.h>

#include "logger.h"
#include "log.h"
#include "sendlog.h"
#include "cosched.h"
#include "lwrap.h"
#include "timers.h"

#include "logreplay.h"
#include "libc_pointers.h"
#include "tmalloc.h"
#include "patterns.h"
#include "misc.h"
#include "errops.h"
#include "hexops.h"
#include "gcc.h"

#define DEBUG 1
#include "debug.h"

struct tailhead head;

extern char* strsignal(int sig);

/* Save the handler specified for sig in the corresponding bin. */
static int save_signal_handler(int sig, const struct sigaction* act,
	struct sigaction* old_act) {

	if ( ! (0 < sig && sig < NSIG) ) return -1;

	if (old_act) *old_act = _private_info.orig_handlers[sig-1];

	/* According to the man-page, act can be NULL. */
	if (act) _private_info.orig_handlers[sig-1] = *act;

	return 1;
}

static void sig_segv_handler(int signum, siginfo_t *sip, ucontext_t *scp) {
	printf("************************************************************\n");
	printf("* LIBLOG caught SIGSEGV:                                   *\n");
	printf("*                                                          *\n");
	printf("* PID: %5ld    CR2: 0x%8.8lx   EIP: 0x%8.8x          *\n",
			syscall(SYS_getpid), scp->uc_mcontext.cr2, 
			scp->uc_mcontext.gregs[REG_EIP]);
	printf("************************************************************\n");

	fatal("sig_segv_handler\n");

	return;
}

static void sig_bus_handler(int signum, siginfo_t *sip, ucontext_t *scp) {
	printf("liblog SIGBUS caught:\n");
	printf("-----------------------------------------\n");
	printf("CR2: 0x%lx\tEIP: 0x%x\n",
			scp->uc_mcontext.cr2, scp->uc_mcontext.gregs[REG_EIP]);

	fatal("sig_bus_handler\n");

	return;
}

/* This is the signal handler through which all signals are processed before
 * being handed to the application. The application should be oblivious
 * to the fact that we are snooping in on its signals. Thus, this handler 
 * is ``covert''.*/
static void covert_signal_handler(int signum, siginfo_t *si, ucontext_t *uc) {

	struct signal_entry* se;

	DEBUG_MSG(3, "received SIGNAL=%s\n", sys_siglist[signum]);

	switch (signum) {
		case SIGUSR1:
			/* We assume the app doesn't make use of this signal, and therefore
			 * we assume it is available for use as a ``take checkpoint''
			 * signal (and we use it as that). */
			assert(!_private_info.orig_handlers[signum - 1].sa_handler);

			assert(_private_info.is_ckpt_master == 0);

			/* Detach from the current segment, if we already have one. */
			if (_private_info.shmpos != NULL) {
				if ((*__LIBC_PTR(shmdt))((void*)_private_info.shmpos) != 0) {
					fatal("can't detach from the old shared memory segment\n");
				}
			}

			DEBUG_MSG(3, "detached segment at 0x%x\n", _private_info.shmpos);

			/* Attach to the shared memory segment (to which we will write out
			 * log entries). _shared_info->shmid set already be set by the
			 * master process. */
			assert(_shared_info->shmid != -1);
			if ((_private_info.shmpos = (int*)(*__LIBC_PTR(shmat))(_shared_info->shmid,
							(void *) 0, 0)) == (void*)-1) {
				fatal("can't attach to shared segment handed out by log server\n");
			}

			DEBUG_MSG(3, "attaching new segment %d to 0x%x\n", _shared_info->shmid,
					_private_info.shmpos);

			/* Everything after the first word is log entries. */
			_private_info.shmdata = (char*)_private_info.shmpos + sizeof(int);
			assert(_private_info.shmdata != NULL);

			/* Tell libckpt to ignore this shared memory segment, since we
			 * use it to keep log entries that needn't be checkpointed
			 * (because they go in the log). That is, we want libckpt
			 * to checkpoint only those shared memory segments allocated by
			 * the __application__, and not those allocated by liblog. */
			ckpt_mask_region((void*)_private_info.shmpos,
					_shared_info->shmsize);

			/* The master process should've reset the shared memory
			 * position by now. */
			assert(*_private_info.shmpos == 0);

			/* By unsetting this variable, we get exclusive access
			 * to the CPU while taking the checkpoint. That is, if
			 * drop_checkpoint() or any of its sub functions makes
			 * a system call, we won't get switched out, since 
			 * INVOKE_COSCHEDULER() will do nothing when this var
			 * is 0. */
			assert( _private_info.done_with_init == 1 );
			_private_info.done_with_init = 0;

			/* Write a new checkpoint. */
			if (!liblog_drop_checkpoint(_shared_info->vclock)) {

				_private_info.done_with_init = 1;

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

			break;
#if UNFINISHED_CODE
		case SIGPROF:
			/* Profiling in Linux is done by periodically issuing a SIGPROF
			 * signal. We need to deliver this right away. */
			assert(_private_info.orig_handlers[signum - 1]);
			(*(_private_info.orig_handlers)[signum - 1])(signum);
			break;
#endif
		case SIGBUS:
		case SIGSEGV: 
			/* We have a special handler for these and hence we should never 
			 * be here. */
			assert(0);
			break;
		default:
			DEBUG_MSG(2, "got signal %d, putting in queue\n", signum);
			/* Enqueue the signal for later delivery. */
			se = (struct signal_entry*)tmalloc(sizeof(struct signal_entry));
			se->sig = signum;

			memcpy(&se->si, si, sizeof(siginfo_t));
			memcpy(&se->uc, uc, sizeof(ucontext_t));

			TAILQ_INSERT_TAIL(&head, se, entries);
			_private_info.num_pending_sigs++;
			break;
	}

	return;
}

void HIDDEN log_and_deliver_queued_signals() {
	struct signal_entry *np, *p, s;
	sigset_t block_set, old_set;
	static int in_handler = 0;
	struct sigaction* act;

	/* The ascii hex form of the binary data requires twice as much
	 * storate space, plus 1 for the null terminator. */
	static char entry_hex_str[(sizeof(struct signal_entry) * 2) + 1];

	assert(_private_info.num_pending_sigs);

	_private_info.num_pending_sigs = 0;

	if( !_private_info.done_with_init ) {
		/* Do not try anything until our data structures
			are fully initialized. */
		return;
	}

	/* Don't process signals if some other wrapper is in the midst
	 * of doing so. */
	if (in_handler) return;

	in_handler = 1;

	/* MASK ALL SIGNALS! We don't want another signal added to the
	 * queue while we are running through it. This might cause the
	 * new signal to get lost, for example, if it arrives right 
	 * before we clear the queue. */

	/* BUG FIX: DON't MASK ***ALLL**** SIGNALS!!. We need to deliver
	 * SIGSEGV right away, since they indicate shared memory accesses! */

	/* TODO: What other signals need to be delivered right away? */
	sigfillset(&block_set);
	sigdelset(&block_set, SIGSEGV);
	(*__LIBC_PTR(sigprocmask))(SIG_BLOCK, &block_set, &old_set);

	/* For each signal in the list, log the signal to disk. Do this first
	 * so that all the signals we are going to process end up in the log
	 * before any of the wrapper functions called in one of the
	 * handlers. */
	for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
		/* Encode the signal data in hex, so that we we can recover
		 * it during replay. 
		 * BUG (!!) struct signal_entry is not flattened! Some of the
		 * fields will be garbage on replay. */
		hex_encode(np, entry_hex_str, sizeof(struct signal_entry));

		/* Log the signal to disk. */
		advance_vclock();

		//printf("logging %d\n", np->sig);
		if (!LOG(__SIGNAL_PAT, np->sig, 
					np->uc.uc_mcontext.gregs[REG_EIP], entry_hex_str,
					_shared_info->vclock )) {
			fatal("can't communicate with logger process on SIGNAL\n");
		}
	}

	/* For each signal in the list, remove the signal from the list and then
	 * call the corresponding signal handler. */
	np = head.tqh_first;
	while (np != NULL) {
		s = *np;

		/* Move to the next node, --- before removing the current node ----. */
		np = np->entries.tqe_next;

		/* Remove the signal entry before calling the handler. This is
		 * crucial, since the signal handler may invoke one of our
		 * wrapper functions, which in turn will call this function again.
		 * The danger is that on this second call, we will process the
		 * the same signal. We want to avoid this situation. */
		p = head.tqh_first;
		TAILQ_REMOVE(&head, head.tqh_first, entries);
		tfree(p);

		act = &_private_info.orig_handlers[s.sig - 1];

		/* Call the application-specified signal handler, if it exists.
		 * If the app did install a handler, we have to
		 * be careful about which handler to invoke--there are two
		 * options sa_handler or sa_sigaction, and only one of those 
		 * can be used. The sa_flags should tell us which is being used. */
		if ((act->sa_flags & SA_SIGINFO)) {
			if (act->sa_sigaction) { 
				DEBUG_MSG(3, "sig_segv_handler: forwarding %s "
						"to the application sa_sigaction\n", strsignal(s.sig));
				/* We want to ensure that the system calls in the app
				 * handler are logged. Hence, we disable overlord call through. */
				{
					int old1 = overlord_should_call_through;
					int old2 = is_in_library;
					overlord_should_call_through = 0;
					is_in_library = 0;
					act->sa_sigaction(s.sig, &s.si, (void*) &s.uc); 
					overlord_should_call_through = old1;
					is_in_library = old2;
				}
			} else { assert (0); }
		} else {
			if (act->sa_handler == SIG_DFL) {
				switch (s.sig) {
					case SIGCHLD:
						/* This is not an error. The child is simply exiting.
						 * So don't quit. */
						break;
					default:
						quit("got signal %d/%s\n",
								s.sig, strsignal(s.sig));
						if (!_private_info.about_to_exit) exit(-1);
						break;
				}
			} else if (act->sa_handler == SIG_IGN) {
				/* Ignore the signal, although this seems very unwise of
				 * the programmer. */

				/* SIGPIPE is commonly ignored. */
			} else {
				DEBUG_MSG(3, "log_and_deliver_signals: forwarding %s "
						"to the application sa_handler\n", strsignal(s.sig));
				assert(act->sa_handler != NULL);
				/* We want to ensure that the system calls in the app
				 * handler are logged. Hence, we disable overlord call through. */
				{
					int old1 = overlord_should_call_through;
					int old2 = is_in_library;
					overlord_should_call_through = 0;
					is_in_library = 0;
					act->sa_handler(s.sig);
					overlord_should_call_through = old1;
					is_in_library = old2;
				}
			}
		} 
	}

	in_handler = 0;
	/* UNMASK SIGNALS! */
	(*__LIBC_PTR(sigprocmask))(SIG_SETMASK, &old_set, NULL);

	/*****************************************************************/

	/* We don't want system calls made by libc functions to synchronize
	 * with other threads. Thus, only top-level libc funtion calls
	 * should invoke the scheduler. */
	if (is_in_libc) return;
}


/* Install a handler for all (possible) signals. */
void HIDDEN install_signal_handlers() {
	int i, ret;	
	struct sigaction sa;

	for (i = 0; i < NSIG; i++) {
		memset(&sa, 0x0, sizeof(sa));

		/* Some signals, such as SIGSEGV and SIGBUS, require their own 
		 * handlers, rather than the catch-all covert_signal_handler.
		 * Also, we don't know want to catch some signals (such as SIGPROF).
		 * Handle these special cases here. */
		switch (i) {
			case SIGKILL: /* Don't even try. */
			case SIGSTOP: /* Don't even try. */
			case SIGTSTP:
			case SIGPROF: /* Profiling libraries use this in a way I
								* don't understand yet. */
				/* Don't install a signal for SIGPROF. */
				continue;
				break;
			case SIGSEGV:
				/* SIGSEGV has its own handler since we
				 * need to ensure it is minimal (in order to avoid hanging), yet
				 * produces useful debugging output. */
				sa.sa_sigaction = (void (*) (int, siginfo_t*, void*)) 
					sig_segv_handler;
				sigemptyset(&sa.sa_mask);
				sa.sa_flags = SA_SIGINFO;
				break;
			case SIGBUS:
				sa.sa_sigaction = (void (*) (int, siginfo_t*, void*)) 
					sig_bus_handler;
				sigemptyset(&sa.sa_mask);
				sa.sa_flags = SA_SIGINFO;
				break;
			case SIGABRT: /* Don't try to handle it -- we may hang. */
				continue;
				break;
			default:
				/* covert_signal_handler is our catch-all signal handler. */
				sa.sa_sigaction = (void (*) (int, siginfo_t*, void*)) 
					covert_signal_handler;
				sigemptyset(&sa.sa_mask);
				sa.sa_flags = SA_SIGINFO;
				break;
		}

		/* We are not allowed to catch some signals; that's okay. */
		if ((ret = __LIBC_PTR(sigaction)(i, &sa, NULL)) != 0) continue;

		/* IMPORTANT: sigaction must be called through the libc function,
		 * since the semantics change if you invoke it directly via the
		 * syscall interface. In particular, sininfo_t doesn't seem to
		 * to be passed to the signal handler if you use syscall. */
	}

	/* We maintain a queue of pending signals, so that we can control
	 * exactly when they are delivered. */
	TAILQ_INIT(&head);	

	return;
}

/* Signals are more complicated to handle, and that's why it's 
 * isolated from the other wrappers. Note that the same
 * wrapper is used for both log and replay modes, since the
 * signal handling logic in both modes is essentially the same. */
sighandler_t log_signal(int signum, sighandler_t handler) {
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

int log_sigaction(int signum, const struct sigaction *act, struct sigaction
		*oldact) {

	return save_signal_handler(signum, act, oldact);
}

/* Nothing fancy here. Just call through. */
int log_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	int ret;
	char buf_hex_str[sizeof(sigset_t) * 2 + 1];
	__CALL_LIBC(ret, sigprocmask, how, set, oldset);

	advance_vclock();

	if (oldset) {
		hex_encode(oldset, buf_hex_str, sizeof(sigset_t));
	} else {
		strcpy(buf_hex_str, "NULL");
	}

	if (!LOG( __SIGPROCMASK_PAT, ret,
				buf_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"sigprocmask\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_sigpending(sigset_t *set) {
	int ret;
	char buf_hex_str[sizeof(sigset_t) * 2 + 1];
	__CALL_LIBC(ret, sigpending, set);

	advance_vclock();

	if (set) {
		hex_encode(set, buf_hex_str, sizeof(sigset_t));
	} else {
		strcpy(buf_hex_str, "NULL");
	}

	if (!LOG( __SIGPENDING_PAT, ret,
					buf_hex_str, _shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"sigpending\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_sigsuspend(const sigset_t *mask) {
	int ret;

	__CALL_LIBC(ret, sigsuspend, mask);

	advance_vclock();

	if (!LOG( __SIGSUSPEND_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"sigsuspend\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

int log_setitimer(int which, const struct itimerval *value,
		struct itimerval *ovalue) {

	int ret;

	/* Nothing tricky here. The tricky stuff happens during replay,
	 * where we don't want the app to set the timer, because if it
	 * does, then we will get SIGALRMs deliveried to us. */

	__CALL_LIBC(ret, setitimer, which, value, ovalue);

	advance_vclock();

	if (!LOG( __SETITIMER_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"setitimer\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}

unsigned int log_alarm(unsigned int seconds) {
	int ret;

	/* Nothing tricky here. The tricky stuff happens during replay,
	 * where we don't want the app to set the timer, because if it
	 * does, then we will get SIGALRMs deliveried to us. */

	__CALL_LIBC(ret, alarm, seconds);

	advance_vclock();

	if (!LOG( __ALARM_PAT, ret,
					_shared_info->vclock )) {
		fatal("can't communicate with logger process on "
				"alarm\n");
	}

	POST_WRAPPER_CLEANUP();

	return ret;
}
