#ifndef DEBUG_HEADER
#define DEBUG_HEADER

#if DEBUG
#define DEBUG_MSG(lvl, s, ...) if (debug_level >= lvl) lprintf(s, ##__VA_ARGS__)
#else
#define DEBUG_MSG(lvl, s, ...)
#endif

/* Global that stores the current debug level. */
extern int debug_level;

#endif
