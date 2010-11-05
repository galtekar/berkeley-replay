#pragma once

#include "vkernel/public.h"
#include "vkernel/fs/private.h"

extern struct SuperBlockStruct *sbEpoll;

struct EpollStruct;

struct EpollItemStruct {
   struct MapField rfdMap;

   int vfd;
   struct FileStruct *file;
   struct epoll_event event;

   struct EpollStruct *ep;

   /* Links his epi to @file's list of epi's
    * Use: to aid in cleanup when file is closed. */
   struct ListHead file_link;
};

extern struct EpollStruct *    Epoll_GetStruct(struct InodeStruct *inodp);
extern void                    Epoll_Free(struct EpollStruct *ep);
