#pragma once

#include "vkernel/public.h"
#include "vkernel/fs/private.h"


extern struct SuperBlockStruct *sb_event;

struct event_data {
   int fd, orig_fd;
   unsigned int count_initval;
   int flags;
   ino_t ino;
};
