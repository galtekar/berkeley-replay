noinst_LIBRARIES = libi3.a
noinst_HEADERS = debug.h  i3_config.h  i3_header.h  i3_options.h \
		 i3_trigger.h  i3_addr.h  i3_fun.h  i3_id.h \
		 i3_stack.h  i3_utils.h  i3_api.h  i3.h  i3_misc.h \
		 i3_tcp_fns.h

utils_SOURCES = ../utils/byteorder.c
libi3_a_SOURCES = i3_addr.c    i3_id.c  i3_options.c \
		  i3_tcp_fns.c  i3_utils.c  i3_api.c  i3_header.c \
		  i3_misc.c  i3_stack.c  i3_trigger.c $(utils_SOURCES)
libi3_a_LIBADD = ../aeshash/libaes.a

#EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
