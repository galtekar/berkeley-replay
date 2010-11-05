#pragma once

#include "vkernel/public.h"
#include "vkernel/fs/private.h"

extern struct SuperBlockStruct *sbShm;


extern void                ShmFs_Free(struct ShmStruct *shmp);
