$(PROGRAMS): $(LDEPS)

noinst_LIBRARIES = libutils.a
noinst_HEADERS = byteorder.h  eprintf.h  gen_utils.h  inetfns.h  utils.h

libutils_a_SOURCES = byteorder.c  eprintf.c  gen_utils.c  inetfns.c

#EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
