#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <assert.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/wait.h>

volatile long *shared = NULL;

int main() {

	int i = 0, j = 0;
	pid_t pid;

	shared = (long*) mmap(0x0, getpagesize(), PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, 0, 0);
   printf("shared=0x%x\n", shared);
	if (shared == (void*)-1) {
		perror("mmap");
		exit(-1);
	}

	/* 2nd chunk is used for the actual data. */
	shared = (long*)((char*)shared + sizeof(pthread_mutex_t));

	pid = fork();

   for (i = 0; i < 1; i++) {
#if 1
      printf("%d: i = %d\n", getpid(), i);
      fflush(stdout);
#endif
      for (j = 0; j < 100000000; j++) {
         *shared = i;
      }
   }

   if (pid) {
      /* We need this so that our test script will not prematurely
       * perform a diff. This can happen if the parent process
       * terminates before the child does. */
      wait(0);
   }

   printf("%d: exiting\n", getpid());

   return 0;
}
