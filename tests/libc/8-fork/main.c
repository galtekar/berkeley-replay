#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <syscall.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>


void init() {
}

int main(int argc, char** argv) {
	int num_procs;
	int i = 0, status;
	long r = 0;


	if (argc != 2) {
		num_procs = 50;
	} else {
		num_procs = atoi(argv[1]);
	}

	{
		pid_t pid[num_procs-1];
		/* Fork num_proc processes. */
		for (i = 0; i < num_procs-1; i++) {
			if ((pid[i] = fork())) {
			} else {
				break;
			}
		}

      init();

		for (i = 0; i < num_procs-1; i++) {
			if (pid[i]) {
				/* We need this so that our test script will not prematurely
				 * perform a diff. This can happen if the parent process
				 * terminates before the child does. */
				waitpid(pid[i], &status, 0);
			}
		}
	}

	return 0;
}
