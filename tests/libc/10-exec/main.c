#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <syscall.h>
#include <sys/ptrace.h>

#include <sys/wait.h>

int main(int argc, char** argv) {
	if (fork()) {
		wait(NULL);
	} else {
		int ret = execl(argv[1], argv[1], NULL);

		perror("execl");

	}

	return 0;
}
