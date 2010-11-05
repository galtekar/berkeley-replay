#pragma once

#include "debug.h"

#if STATS
#define STATS_ONLY(s) s
#define STATS_MSG(s, ...) \
      lprintf(CURRENT_LFD, "Stats --- " s, ##__VA_ARGS__);

#define STATS_DECLARE_TIMER(t) struct timeval stats_times_##t
#define STATS_START_TIMER(t) gettimeofday(&stats_times_##t, NULL)
#define STATS_ELAPSED_SEC(t) \
({ \
   struct timeval end; \
   gettimeofday(&end, NULL); \
   end.tv_sec - stats_times_##t.tv_sec; \
})

#define STATS_ELAPSED_USEC(t) \
({ \
   struct timeval end; \
   gettimeofday(&end, NULL); \
   end.tv_usec - stats_times_##t.tv_usec; \
})

#else

#define STATS_ONLY(s)
#define STATS_MSG(s, ...)
#endif
