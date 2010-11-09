$(PROGRAMS): $(LDEPS)

DEPENDENCIES = ../chord/libchord.a ../i3/libi3.a \
	       ../aeshash/libaes.a ../utils/libutils.a
#ifneq ($(shell uname),Darwin) --- TODO
#       LDFLAGS = -lpthread -static
#       LDFLAGS = -lpthread
#endif

noinst_PROGRAMS = i3_server 
noinst_HEADERS = i3_id_cache.h  i3_news.h  i3_server_info.h  tcp_state.h \
		 i3_matching.h  i3_news_instrument.h  i3_server_pkt.h \
		 i3_monitor.h  i3_pushback.h  i3_server_utils.h \
		 i3_monitor_state.h  i3_server.h  nat_table.h 
INCLUDES = -I../i3 -I../chord

i3_server_SOURCES = i3_id_cache.c  i3_news.c  i3_server_info.c \
		    tcp_state.c i3_matching.c  i3_news_instrument.c \
		    i3_server_pkt.c  i3_monitor.c  i3_pushback.c \
		    i3_server_utils.c  i3_monitor_state.c  i3_server.c \
		    nat_table.c
i3_server_LDADD = ../i3/libi3.a ../chord/libchord.a \
		  ../aeshash/libaes.a ../utils/libutils.a $(LDADD) 

#EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo *.log.gz *.ckpt core.*
MAINTAINERCLEANFILES = Makefile.in
