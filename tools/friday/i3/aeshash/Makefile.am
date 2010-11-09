$(PROGRAMS): $(LDEPS)

noinst_LIBRARIES = libaes.a
noinst_HEADERS = aescpp.h  aes.h  aesopt.h

libaes_a_SOURCES = aescrypp.c  aescrypt.c  aeshash.c  aeskey.c \
		     aeskeypp.c  aestab.c
# aesxam.c

CLEANFILES = core *.core *~
MAINTAINERCLEANFILES = Makefile.in
