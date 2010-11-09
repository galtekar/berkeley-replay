#pragma once

#include "vkernel/public.h"

extern struct SuperBlockStruct *sbRoot;

extern void RootFs_Fork(struct Task *);
extern void RootFs_Exit(struct Task *);
extern void RootFs_Exec();
