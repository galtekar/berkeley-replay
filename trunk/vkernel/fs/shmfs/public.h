#pragma once

#include "vkernel/public.h"

struct ShmStruct {
   ulong shmid;

   /* For named segment, this in the flags argument to sys_shmget.
    * For unnamed segment, this is the flags argument to mmap. */
   int flags;
   size_t size;
   int isAnon;
   ino_t ino;
};

extern struct ShmStruct *  ShmFs_GetStruct(struct InodeStruct *inodp);
extern struct FileStruct * ShmFs_Create(size_t size, int flags, int isAnon);
extern int   ShmFs_CreateAnonymous(struct VmaStruct *vma);
