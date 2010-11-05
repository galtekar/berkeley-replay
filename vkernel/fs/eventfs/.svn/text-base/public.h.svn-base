#pragma once


struct EpollStruct;

struct EpollOps {
   int   (*ctl)(struct EpollStruct *ep, struct FileStruct *filp, int op, 
                struct epoll_event *kevent);
   int   (*wait)(struct EpollStruct *ep, struct epoll_event *vevents, 
                 int maxevents, int timeout);
};

struct EpollStruct {
   int fd, orig_fd;
   int size; /* hint to Linux kernel given in epoll_create */
   struct MapStruct *map;
   const struct EpollOps *ops;
   ino_t ino;

   /* Concurrent access to the same epoll fd. */
   struct RepLockStruct lock;
};

extern int  Epoll_RealToVirt(struct EpollStruct *ep, 
                struct epoll_event *vevents, int maxevents, 
                struct epoll_event *revents, int revCount);
extern void Epoll_Release(struct FileStruct *);
