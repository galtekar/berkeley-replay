#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#define __USE_LARGEFILE64
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "errops.h"
#include "debug.h"
#include "hexops.h"
#include "misc.h"

#define DEFAULT_DEBUG_LEVEL 5

int debug_level = DEFAULT_DEBUG_LEVEL;
int verbosity = DEBUG_VERBOSE;
int dbgPauseOnAbort = 0;

int debugLogHash[] = { [0 ... NUM_TID-1] = -1 };

static void
DebugDefaultPrintf(int lvl, int fd, const char * fmt, ...)
{
   if (debug_level >= lvl) {
      va_list args;

      va_start(args, fmt);
      vlprintf(fd, fmt, args);
      va_end(args);
   }
}

DebugFn dbgFn = &DebugDefaultPrintf;

/* Okay to call this multiple times for a given thread. */
int 
Debug_Init(const char* filename, DebugFn fn, int verbose) {
   int fd;

   pid_t tid = gettid();
   verbosity = verbose;

   if (fn) {
      dbgFn = fn;
   }

   ASSERT(dbgFn);
   ASSERT(tid < NUM_TID);

   if (debugLogHash[tid] == -1) {
      fd = syscall(SYS_open, filename, 
            O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE, 0600);
      if (fd < 0) {
         FATAL("Can't create debug file %s: %s.\n", filename,
               strerror(fd*-1));
      }
      
      debugLogHash[tid] = fd;
   }

   ASSERT(debugLogHash[tid] >= 0);

   return debugLogHash[tid];
}

void 
Debug_Exit() {
   pid_t tid = gettid();

   ASSERT(debugLogHash[tid] >= 0);
   SysOps_Close(debugLogHash[tid]);
   debugLogHash[tid] = -1;
}

void 
Debug_HexDump( char const * prefix, char const * buf, size_t buf_len )
{
   ASSERT(buf_len <= 256); // Don't alloc too much on the stack
   char hex_buf[2*MAX(0,buf_len)+1]; // +1 for null-terminator
   if( buf_len <= 0 ) {
      hex_buf[0] = '\0';
   } else {
      hex_encode(hex_buf, sizeof(hex_buf), buf, buf_len );
   }
   lprintf(CURRENT_LFD, "%s[%d]: <%s>\n", prefix, buf_len, hex_buf);
}

#if 0
// unfinished, not needed
void
Debug_StringDump(char const * prefix, char const * str_p)
{
   char str_buf[256]; 

   strncpy(str_buf, str_p, sizeof(str_buf)-1);
   for (p = str_buf; 

   lprintf(CURRENT_LFD, "%s[%d]: <%s>\n", prefix, buf_len, hex_buf);
}
#endif
