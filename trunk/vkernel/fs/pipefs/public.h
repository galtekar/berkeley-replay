#pragma once

#include "vkernel/public.h"

struct PipeStruct {
   int orig_fds[2];
   int fds[2];
   tsock_socket_info_t tsock[2];
};

extern struct PipeStruct *
Pipe_GetStruct(struct InodeStruct *inodp);

extern const struct FileOps Fifo_Fops;
