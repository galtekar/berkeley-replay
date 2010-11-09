$(PROGRAMS): $(LDEPS) 

DEPENDENCIES = ../chord/libchord.a ../i3/libi3.a \
               ../i3_client/libi3client.a
INCLUDES = -I../i3 -I../i3_client -I../proxy_common

noinst_PROGRAMS =  i3_server_proxy check_key
noinst_HEADERS = dns_thread.h  fake_mngm.h i3_proxy.h

proxy_common_SOURCES = ../proxy_common/auth.cpp ../proxy_common/fake_log.c \
                       ../proxy_common/fake_mngm_common.c

i3_server_proxy_SOURCES = dns_thread.c  fake_mngm.c i3_proxy.c \
		   $(proxy_common_SOURCES)
i3_server_proxy_LDADD = ../i3_client/libi3client.a ../i3/libi3.a \
		 ../utils/libutils.a ../aeshash/libaes.a
i3_server_proxy_LDFLAGS = -lpthread -static -lxml2 -lm -lcrypt -lcrypto

check_key_SOURCES = check_key.cpp
check_key_LDFLAGS = -lm -lpthread -lcrypto -lcrypt

EXTRA_DIST = i3-server-proxy.xml
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
