#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "errops.h"
#include "compiler.h"
#include "syscall.h"

#if __GNUC__ < 4
#error "Must be compiled with GCC 4.0 or greater."
#endif

#define DEBUG_MAGIC 0xdeadbeef

#define SYSERR_ERRNO(err) (err*-1)
#define CURRENT_LFD     GetCurrentLogFd()

typedef void (*DebugFn)(int lvl, int fd, const char *fmt, ...);
extern DebugFn dbgFn;
#define CUSTOM_PRINTF   dbgFn

#define DEBUG_VERBOSE 1

/* To nuke existing defintions (e.g., from Pin). */
#undef ASSERT

/* ---------- Common to debug and release builds ---------- */

#define LOG(s, ...) lprintf(CURRENT_LFD, s, ##__VA_ARGS__)

#define ASSERT_UNIMPLEMENTED_MSG(expr, s, ...) \
   if (!(expr)) { \
      LOG("ASSERT_UNIMPLEMENTED(%s) failed at %s:%d.\n", \
         #expr, __FILE__, __LINE__); \
      LOG(s "\n", ##__VA_ARGS__); \
      Debug_Abort(); \
   }

#define ASSERT_UNIMPLEMENTED(expr) \
   ASSERT_UNIMPLEMENTED_MSG(expr, "");

#define NOTREACHED() ASSERT(0)

#define FATAL(s, ...) { \
   LOG("FATAL at %s:%d : " s "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
   Debug_Terminate(-1); \
}




#if DEBUG

/* ---------- For debug builds ---------- */

#define DEBUG_LEVEL(x) (debug_level >= (x))

#define DEBUG_MSG(lvl, s, ...) \
      if (verbosity == DEBUG_VERBOSE) { \
		   CUSTOM_PRINTF(lvl, CURRENT_LFD, "%-28.28s | " s, __PRETTY_FUNCTION__, ##__VA_ARGS__);  \
      } else { \
		   CUSTOM_PRINTF(lvl, CURRENT_LFD, s, ##__VA_ARGS__); \
      }

#define QUIET_DEBUG_MSG(lvl, s, ...) \
		CUSTOM_PRINTF(lvl, CURRENT_LFD, s, ##__VA_ARGS__);  \

#define DEBUG_HEXDUMP(lvl, s, b, l) \
   if (DEBUG_LEVEL(lvl)) { Debug_HexDump(s, b, l); }

#define D__ { DEBUG_MSG(5, "%s:%d\n", __FILE__, __LINE__); }

#define TR(l) { DEBUG_MSG(l, "%s:%d\n", __FILE__, __LINE__); }

#define DEBUG_ONLY(s) s

#define WARN_MSG(expr, s, ...) \
   if (!(expr)) { \
      lprintf(CURRENT_LFD, "WARN(%s) failed at %s:%d.\n", \
         #expr, __FILE__, __LINE__); \
      lprintf(CURRENT_LFD, s, ##__VA_ARGS__); \
   }

#define WARN(expr) WARN_MSG(expr, "")
#define WARN_XXX(expr) WARN_MSG(expr, "")

#define WARN_XXX_MSG(expr, s, ...) \
   WARN_MSG(expr, s, ##__VA_ARGS__)

/* Dumps to the log file rather than to stderr. */

#define ASSERT_MSG(expr, s, ...) \
   if (!(expr)) { \
      lprintf(CURRENT_LFD, "ASSERT(%s) failed at %s:%d.\n", \
         #expr, __FILE__, __LINE__); \
      lprintf(CURRENT_LFD, s "\n", ##__VA_ARGS__); \
      Debug_Abort(); \
   }

#define ASSERT(expr) ASSERT_MSG(expr, "")
#define ASSERT_COULDBE(expr) ASSERT((expr) || !(expr))

#define DLOG(s, ...) DEBUG_MSG(5, s, ##__VA_ARGS__)


#define WARN_UNIMPLEMENTED_MSG(expr, s, ...) \
   ASSERT_UNIMPLEMENTED_MSG(expr, s, ##__VA_ARGS__);

#define WARN_UNIMPLEMENTED(expr) \
   WARN_UNIMPLEMENTED_MSG(expr, "");

#else /* DEBUG */

/* ---------- For release builds ---------- */

#define D__
#define DEBUG_MSG(lvl, s, ...)
#define DEBUG_HEXDUMP(lvl, s, b, l)
#define DLOG(s, ...) 
#define DEBUG_ONLY(s)
#define ASSERT(expr) 
#define ASSERT_COULDBE(expr)
#define ASSERT_MSG(expr, s, ...)
#define DEBUG_LEVEL(x) 0
#define QUIET_DEBUG_MSG(lvl, s, ...)
#define WARN(expr)
#define WARN_XXX(expr)
#define WARN_MSG(expr, s, ...)
#define WARN_XXX_MSG(expr, s, ...)
#define WARN_UNIMPLEMENTED_MSG(expr, s, ...) \
   if (!(expr)) { \
      LOG("WARN_UNIMPLEMENTED: " s, ##__VA_ARGS__); \
   }
#define WARN_UNIMPLEMENTED(expr) \
   WARN_UNIMPLEMENTED_MSG(expr, "");
#endif




/* Current debug level. */
extern int debug_level;

/* Output function names? */
extern int verbosity;



#define NUM_TID (1 << 15)

extern int debugLogHash[NUM_TID];


static INLINE int
GetCurrentLogFd() 
{
   // XXX: this gettid() is very expensive given the frequency which
   // this function is invoked in debug builds; don't see an easy way
   // to avoid this though :-(
   return debugLogHash[gettid()];
}


extern int  Debug_Init(const char *idStr, DebugFn fn, int verbose);
extern void Debug_Exit();
extern void 
Debug_HexDump( char const * prefix, char const * buf, size_t buf_len );

extern int dbgPauseOnAbort;

static INLINE void 
Debug_Terminate(int code)
{
   if (dbgPauseOnAbort) {
      LOG("Waiting for attach...\n");
      sleep(10000);
   }
   exit(code);
}

static INLINE void 
Debug_Abort() { 
   /* CAUTION: Don't use raise() -- that'll send the SIBABRT to *some*
    * thread in the thread group. We want to send specifically to the
    * current thread. */
   syscall(SYS_tkill, gettid(), SIGABRT); 
   Debug_Terminate(127); 
}




#ifdef __cplusplus
}
#endif
