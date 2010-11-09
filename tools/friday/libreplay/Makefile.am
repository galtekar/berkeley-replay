AM_CFLAGS = -DDEBUG_LEVEL=0
LIBS = -lckpt -llog 
INCLUDES = -I../libcommon -I../libckpt

lib_LTLIBRARIES = libreplay.la

noinst_HEADERS = replay.h util.h ckptsupport.h rwrap_sigs.h

libreplay_la_SOURCES = replay.c replay_util.c rwrap_misc.c rwrap_files.c rwrap_socks.c rwrap_sigs.c rwrap_shmem.c rwrap_threads.c rwrap_procs.c mprotect.S ckptsupport.c
libreplay_la_LDFLAGS = -shared -fPIC -version-info 0:0:0 -Wl,--export-dynamic -L../liblog -L../libckpt

CLEANFILES = core *.core *~ *.log.gz core.* *.ckpt
MAINTAINERCLEANFILES = Makefile.in
