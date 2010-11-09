#include "sys.h"
#include "ckpt.h"
#include "ckptimpl.h"

static int open_ckpt_filestream(char *name) {
	int fd;

	fd = open(name, O_CREAT|O_TRUNC|O_WRONLY, 0600);

	if(0 > fd){
		fprintf(stderr, "cannot open checkpoint file %s: %s\n",
				name, strerror(errno));
		return -1;
	}

	return fd;
}

int ckpt_open_stream(char *name) {
	return open_ckpt_filestream(name);
}

void ckpt_close_stream(int fd) {
	close(fd);
}
