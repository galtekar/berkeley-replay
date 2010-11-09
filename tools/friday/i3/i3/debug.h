/***************************************************************************
                          i3_debug.h  -  description
                             -------------------
    begin                : Mon Feb 10 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef I3_DEBUG_H
#define I3_DEBUG_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define I3_DEBUG
#define I3_DEBUG_LEVEL  10

#ifndef   I3_DEBUG
	#define   DEBUG(ARGS)
	#define   DEBUGN(ARGS)
	#define   DEBUG_NL(ARGS)
#else
	#define DEBUG(level, fmt,...)    if (level <= I3_DEBUG_LEVEL) printf(fmt, ##__VA_ARGS__);
	#define DEBUG_NL(level)          if (level <= I3_DEBUG_LEVEL) printf("\n");
#endif

#define ALERT(fmt,...)  printf("\n I3 ERROR: " fmt, ##__VA_ARGS__);

#endif
