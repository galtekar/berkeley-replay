#pragma once

#include "thread.h"
#include "misc.h"

extern VOID ReplayCheck_ThreadStart(ThreadId pid);

extern VOID ReplayCheck_ThreadFinish();

extern VOID ReplayCheck_Fork(Thread *t);

extern VOID ReplayCheck_Instruction(INS ins);
