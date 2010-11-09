AM_CFLAGS = -DUSE_FAST_LOGGING -DDEBUG_LEVEL=0 #-O4 -DNDEBUG

LIBS = -lckpt -ldl 
INCLUDES = -I../libcommon -I../libckpt -I../logger

lib_LTLIBRARIES = liblog.la

noinst_HEADERS = log.h sendlog.h lwrap_sigs.h overlord.h cosched.h msg_coding.h fast_logging.h finish.h start.h

liblog_la_SOURCES = log.c hosts.c sendlog.c lwrap_misc.c lwrap_files.c lwrap_shmem.c lwrap_socks.c lwrap_sigs.c lwrap_threads.c lwrap_procs.c overlord.c msg_coding.c fast_logging.c finish.c start.c
liblog_la_LDFLAGS = -shared -fPIC -version-info 0:0:0 -L../libckpt -L../libcommon -Wl,--export-dynamic #-Wl,-zinitfirst
liblog_la_LIBADD = ../libcommon/libcommon.la

CLEANFILES = core *.core *~ *.log.gz core.* *.ckpt
MAINTAINERCLEANFILES = Makefile.in
