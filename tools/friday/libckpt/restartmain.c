#include <signal.h>
#include <stdlib.h>
#include <getopt.h>

#define __USE_GNU
#include <sys/ucontext.h>
#undef __USE_GNU

#include "sys.h"
#include "ckpt.h"
#include "ckptimpl.h"

/* Setup a SIGSEGV handler, in case libckpt fails. This will help
 * us debug the problem. */
static void libckpt_sig_segv_handler(int signum, siginfo_t *sip, ucontext_t *scp) {
	printf("libckpt SIGSEGV caught:\n");
	printf("-----------------------\n");
	printf("CR2: 0x%lx		EIP: 0x%x\n",
			scp->uc_mcontext.cr2, scp->uc_mcontext.gregs[REG_EIP]);
}

static void install_sig_segv_handler() {
	struct sigaction sa;

	/* Set the SIGSEGV handler. */
	memset(&sa, 0x0, sizeof(sa));
	sa.sa_sigaction = (void (*) (int, siginfo_t*, void*)) libckpt_sig_segv_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;

	sigaction(SIGSEGV, &sa, NULL);
}

static void print_usage(int argc, char* argv[]) {
		fprintf(stderr, "usage: %s [options] <ckpt_file>\n", argv[0]);
		fprintf(stderr, "OPTIONS:\n");
		fprintf(stderr, "   -i, --info\n\tShows interesting info about the checkpoint.\n");
}

int main(int argc, char *argv[]) {
	int c;
	int option_index = 0;

	static int should_show_info = 0;

	install_sig_segv_handler();

	/* Turn off write buffering on stdout. Why do we do this? */
	setvbuf(stdout, (char*)NULL, _IONBF, 0);

	while (1) {
		static struct option long_options[] = {
			{"info", 0, &should_show_info, 'i'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "i",
				long_options, &option_index);

		if (c == -1) break;

		switch (c) {
			case 'i':
				should_show_info = 1;
				break;
			default:
				break;
		}
	}

	if(optind < argc) {
		if (should_show_info) {
			ckpt_info(argv[optind]);
		} else {
			ckpt_restart(argv[optind]);

			/* ckpt_restart() should not return. */
			libckpt_fatal("restart failed\n");
			assert(0);
		}
	} else {
		print_usage(argc, argv);
	}

	exit(1);
}
