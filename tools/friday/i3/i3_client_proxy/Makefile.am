$(PROGRAMS): $(LDEPS) 

DEPENDENCIES = ../chord/libchord.a ../i3/libi3.a \
               ../i3_client/libi3client.a ../aeshash/libaes.a
INCLUDES = -I../i3 -I../i3_client -I../proxy_common

noinst_PROGRAMS =  i3_client_proxy gen_key gen_pub gen_conf
noinst_HEADERS = addrbook.h  dns_thread.h  fake_mngm.h  \
		 i3_proxy.h win-service.h

proxy_common_SOURCES = ../proxy_common/auth.cpp ../proxy_common/fake_log.c \
                       ../proxy_common/fake_mngm_common.c

if USE_CYGWIN
WINSOURCES = win-service.c
WINLDFLAGS = -liphlpapi
else
WINSOURCES =
WINLDFLAGS =
endif

i3_client_proxy_SOURCES = addrbook.cpp  dns_thread.c fake_mngm.c \
		   i3_proxy.c $(proxy_common_SOURCES) $(WINSOURCES)
i3_client_proxy_LDADD = ../i3_client/libi3client.a ../i3/libi3.a \
		 ../utils/libutils.a ../aeshash/libaes.a
i3_client_proxy_LDFLAGS = -lpthread -static -lxml2 -lm -lcrypt -lcrypto $(WINLDFLAGS)

gen_key_SOURCES = gen_key.cpp
gen_key_LDFLAGS = -lm -lpthread -lcrypto -lcrypt

gen_conf_SOURCES = gen_conf.c
gen_conf_LDADD = ../i3/libi3.a ../aeshash/libaes.a ../i3_client/libi3client.a
gen_conf_LDFLAGS = -lm

gen_pub_SOURCES = gen_pub.c
gen_pub_LDADD = ../i3/libi3.a ../aeshash/libaes.a ../i3_client/libi3client.a
gen_pub_LDFLAGS = -lm

EXTRA_DIST = win-service.c i3-client-proxy.xml i3_addr_book.txt
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
