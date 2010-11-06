#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdio.h>

#include "libcommon/public.h"

#define DATA1 "In Xanadu, did Kublai Khan . . ."
#define DATA2 "A stately pleasure dome decree . . ."


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
Init()
{
   int sockets[2], child;
   char peek_buf[1024] = { 0 };
   char buf[1024] = { 0 };


   if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
      perror("opening stream socket pair");
      exit(1);
   }

   int flags = MSG_PEEK;


   if ((child = fork()) == -1)
      perror("fork");
   else if (child) {   /* This is the parent. */
      close(sockets[0]);
      // Exercise tsocket's back to back MSG_PEEK recv code
      if (recv(sockets[1], peek_buf, 1024, flags) < 0)
         perror("reading stream message");
      if (recv(sockets[1], peek_buf, 1024, flags) < 0)
         perror("reading stream message");
      if (recv(sockets[1], buf, 1024, 0) < 0)
         perror("reading stream message");

      assert(strcmp(peek_buf, buf) == 0);
      printf("-->%s %s\n", peek_buf, buf);
      if (write(sockets[1], DATA2, sizeof(DATA2)) < 0)
         perror("writing stream message");
      close(sockets[1]);
      wait(NULL);
   } else {        /* This is the child. */
      close(sockets[1]);
      if (write(sockets[0], DATA1, sizeof(DATA1)) < 0)
         perror("writing stream message");
      if (recv(sockets[0], buf, 1024, 0) < 0)
         perror("reading stream message");
      printf("-->%s\n", buf);
      close(sockets[0]);
   }
}