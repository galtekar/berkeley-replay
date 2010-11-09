#ifndef __LIBCOMMON_GCC
#define __LIBCOMMON_GCC

/**************************************************
 * GCC-specific flags. 
 **************************************************/

/* Tell GCC that the function doesn't return. */
#define NORETURN __attribute__ ((noreturn))

/* Tell GCC that the function should not be visible from
 * another module. */
//#define HIDDEN __attribute__ ((visibility ("hidden")))
/** Disable HIDDEN for now--we want to split libcommon out of
    libreplay. */
#define HIDDEN 

/* Tell GCC that the function cannot be overriden but should
 * be visible from another module. */
#define PROTECTED __attribute__ ((visibility ("protected")))

#endif
