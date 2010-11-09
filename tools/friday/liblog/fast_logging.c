#include "gcc.h"

#undef FASTLOGENTRY
#define FASTLOGENTRY(name, ...) HIDDEN int __ll_##name##_id;
#include "fastlogentries.h"

HIDDEN int num_fastlogentries = 0;

void HIDDEN init_fast_logging() {
	/* Assign a id number to each fast logging entry. 
	 * The logger shares the same id to entry mapping and therefore
	 * can lookup the corresponding function very quickly. */

#undef FASTLOGENTRY
#define FASTLOGENTRY(name, ...) { __ll_##name##_id = num_fastlogentries;  \
	num_fastlogentries++; }
#include "fastlogentries.h"
}
