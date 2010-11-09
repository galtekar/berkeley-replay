LIBS = -ldl -lpthread

noinst_LTLIBRARIES = libcommon.la

noinst_HEADERS = logreplay.h misc.h clock.h tmalloc.h errops.h hexops.h dllops.h netops.h libc_pointers.h syncops.h timings.h gcc.h patterns.h structops.h timers.h fastlogentries.h debug.h

libcommon_la_SOURCES = misc.c clock.c tmalloc.c errops.c hexops.c dllops.c netops.c libc_pointers.c syncops.c timings.c structops.c timers.c debug.c
libcommon_la_LIBADD =
libcommon_la_LDFLAGS = -static -Wl,--export-dynamic

CLEANFILES = core *.core *~ *.log.gz core.* *.ckpt
MAINTAINERCLEANFILES = Makefile.in
