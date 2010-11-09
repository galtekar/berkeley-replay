AM_CFLAGS = -DDEBUG_LEVEL=5
LIBS =
INCLUDES = -I../libcommon/ -I..

bin_PROGRAMS = loggerbin log2xmlbin

noinst_HEADERS = logger.h log.h logops.h util.h fdops.h hexops.h

loggerbin_SOURCES = logger.c log.c util.c fdops.c
loggerbin_LDADD = -lpthread

log2xmlbin_SOURCES = log2xml.c logops.c hexops.c util.c
log2xmlbin_LDADD = -ldl
log2xmlbin_LDFLAGS = -Wl,--export-dynamic

dist_bin_SCRIPTS = logger.py log2xml.pl

CLEANFILES = core *.core *~ *.log.gz core.* *.ckpt
MAINTAINERCLEANFILES = Makefile.in
