#pragma once

#include "vkernel/public.h"
#include "vkernel/dev/rd-os/public.h"

#define DEV_MAJOR_MEM         1       /* Memory devices (null, random, etc.). */
#define DEV_MAJOR_TTY	      4
#define DEV_MAJOR_TTYSYN      5
#define DEV_MAJOR_PTMX        5
#define DEV_MAJOR_UNIX98PTS   136

#define DEV_MINOR_PTMX        2

typedef void (*devinit_t)(struct InodeStruct *);

struct DeviceStruct {
   uint major;
   devinit_t init;
};

extern void Device_Register(const struct DeviceStruct *);
extern void Device_InitInode(struct InodeStruct *, ulong rdev);
