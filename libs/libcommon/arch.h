#pragma once

#define __x86__

#ifdef __x86__
#include "x86.h"
#else
#error "unknown arch"
#endif
