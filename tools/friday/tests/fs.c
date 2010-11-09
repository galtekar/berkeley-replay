#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <syscall.h>

#include <sys/stat.h>

int main(int argc, char** argv) {

	struct stat sbuf;

	stat("/etc/passwd", &sbuf);

	return 0;
}
