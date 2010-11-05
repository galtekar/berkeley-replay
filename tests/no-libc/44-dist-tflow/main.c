#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdio.h>

#include "libcommon/public.h"

/*
 *  * This program creates a pair of connected sockets, then forks
 *  and
 *   * communicates over them.  This is very similar to communication
 *   with pipes;
 *    * however, socketpairs are two-way communications objects.
 *    Therefore,
 *     * this program can send messages in both directions.
 *      */


void
Init(int argc, char **argv)
{
   int sockets[2], child;
   char buf[1024];
   int in_fd, out_fd;

   assert(argc == 2);

   if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
      perror("opening stream socket pair");
      exit(1);
   }

   in_fd = open(argv[1], O_RDONLY);
   assert(in_fd >= 0);

   out_fd = open("out", O_RDWR | O_CREAT, 0600);
   assert(out_fd >= 0);

   if ((child = fork()) == -1)
      perror("fork");
   else if (child) {   /* This is the parent. */
      close(sockets[0]);
      if (read(in_fd, buf, 1024) < 0)
         perror("reading input file");
      if (write(sockets[1], buf, sizeof(buf)) < 0)
         perror("writing stream message");
      printf("parent done\n");
      close(sockets[1]);
      wait(NULL);
   } else {        /* This is the child. */
      close(sockets[1]);
      if (read(sockets[0], buf, 1024) < 0)
         perror("reading stream message");
      if (write(out_fd, buf, sizeof(buf)) < 0)
         perror("writing stream message");
      printf("child done\n");
      close(sockets[0]);
   }
}
