#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

int
Init()
{
   int err, sfd, efd;
   struct epoll_event evnt;

   sfd = socket(PF_INET, SOCK_STREAM, 0);

#if 0
   efd = epoll_create(32);

   evnt.events = EPOLLIN;
   evnt.data.ptr = NULL;
   err = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &evnt);

   printf("sfd=%d efd=%d err=%d\n", sfd, efd, err);

   close(efd);
#endif

   close (sfd);

   return 0;
}
