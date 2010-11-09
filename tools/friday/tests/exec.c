#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <syscall.h>

#include <sys/wait.h>

int main(int argc, char** argv) {
#if 0
	int num_procs;
	int i = 0;
	pid_t pid;

	if (argc != 2) {
		num_procs = 0;
	} else {
		num_procs = atoi(argv[1]);
	}

	/* Fork num_proc processes. */
	for (i = 0; i < num_procs-1; i++) {
		if ((pid = fork())) {
		} else {
			break;
		}
	}
#endif
#if 1
	execl("./shared", "shared", NULL);
#endif

	return 0;
}
