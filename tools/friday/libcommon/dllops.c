#include "dllops.h"
#include "errops.h"
#include "gcc.h"

#define DEBUG 0

/*
 * Searches for a symbol in a list of libraries H and returns a pointer
 * to that symbol. */
HIDDEN void* my_dlsym(void* h, char* symname) {
	char *error;
	void *symptr = NULL;

	if( DEBUG ) lprintf( "my_dlsym: '%s'\n", symname );

	/* For some reason, this is casuing replay to fail
	 * in gdb. */
	//dlerror();    /* Clear any existing error */

		/* Get a pointer to the function with specified name. */
		symptr = dlsym(h, symname);
		if ((error = dlerror()) != NULL)  {
			fatal("%s\n", error);
		}

	/* NOTE: we don't close the library, but that's okay since
	 * libc is loaded for all programs and won't be unloaded 
	 * until termination. */

	return symptr;
}

HIDDEN void* my_dlopen(const char* filename, int flag) {
	void* handle;

	handle = dlopen(filename, flag);
	if (!handle) {
		fatal("%s\n", dlerror());
	}

	return handle;
}
