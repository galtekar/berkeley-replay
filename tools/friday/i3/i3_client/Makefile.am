noinst_LIBRARIES = libi3client.a
noinst_HEADERS = i3_client_api.h  i3_client_fun.h  i3_client_path.h \
		 trig_binheap.h  i3_client_callback.h  i3_client.h \
		 i3_client_pkt.h  trig_event_list.h  i3_client_context.h \
		 i3_client_id.h   i3_client_trigger.h \
		 http.h i3server_list.h ping.h ping_thread.h qsort.h
INCLUDES = -I../i3

libi3client_a_SOURCES = i3_client_api.c i3_client_id.c i3_client_trigger.c \
			i3_client_callback.c i3_client_path.c trig_binheap.c \
			i3_client_context.c i3_client_pkt.c trig_event_list.c \
			http.c i3server_list.c ping.c ping_thread.c qsort.c
libi3client_a_LIBADD = ../i3/libi3.a ../utils/libutils.a

#EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
