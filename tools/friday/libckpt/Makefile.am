LIBS =
INCLUDES = -I../libcommon/

lib_LTLIBRARIES = libckpt.la librestart.la
bin_PROGRAMS = ckpt_restart

noinst_HEADERS = ckptimpl.h sys.h
include_HEADERS = ckpt.h

libckpt_la_SOURCES = restart.c ckpt.c mem.c util.c config.c uri.c
libckpt_la_LDFLAGS = -shared -nostartfiles -version-info 0:0:0
libckpt_la_LIBADD = -ldl ../libcommon/libcommon.la

librestart_la_SOURCES = safe.c
librestart_la_LDFLAGS = -shared -Xlinker -Bsymbolic -version-info 0:0:0
librestart_la_LIBADD = /usr/lib/libc.a

ckpt_restart_SOURCES = restartmain.c 
ckpt_restart_LDFLAGS = -Xlinker --script=restart.script
ckpt_restart_LDADD = -ldl .libs/libckpt.a


EXTRA_DIST =
CLEANFILES = core *.core *~ *.log.gz core.* *.ckpt
MAINTAINERCLEANFILES = Makefile.in
