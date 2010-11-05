/*
 * Copyright (C) 2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#pragma once

#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/personality.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/sem.h>
#include <sys/times.h>
#include <unistd.h>
#include <getopt.h>

#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <vk.h>

/* Ordering matters. libcommon header takes precedence over
 * vkernel headers. */
#include "libcommon/public.h"
#include "vkernel/macros.h"
#include "vkernel/task/public.h"
#include "vkernel/mem/public.h"
#include "vkernel/vcpu/public.h"
#include "vkernel/vcpu/log.h"

#include "vkernel/fs/public.h"
#include "vkernel/fs/shmfs/public.h"
#include "vkernel/fs/rootfs/public.h"
#include "vkernel/fs/sockfs/public.h"
#include "vkernel/fs/epollfs/public.h"
#include "vkernel/fs/pipefs/public.h"

#include "vkernel/dev/public.h"
#include "vkernel/bt/public.h"
#include "vkernel/vkernel.lds.h"

#include "libvex.h"
#include "libvex_guest_x86.h"
#include "libvex_trc_values.h"
#include "libvex_emwarn.h"
#include "VEX/priv/main_globals.h"

#include "libperfctr.h"

/* Modules */
#include "vkernel/bt/race/public.h"
#include "vkernel/modules/check/public.h"
//#include "vkernel/bt/taint/public.h"
#include "vkernel/modules/public.h"
#include "vkernel/modules/base/public.h"
#include "vkernel/modules/formgen/public.h"

#define TRUE 1
#define FALSE 0
