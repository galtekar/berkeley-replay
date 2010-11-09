$(PROGRAMS): $(LDEPS)

DEPENDENCIES = ../chord/libchord.a ../i3/libi3.a \
	       ../i3_client/libi3client.a ../aeshash/libaes.a

noinst_PROGRAMS = send_test recv_test send_path_test \
		  recv_path_test send middle test \
		  proxy_test ping_test
INCLUDES = -I../i3 -I../i3_client
MYLDADD = ../i3_client/libi3client.a ../i3/libi3.a \
	  ../utils/libutils.a ../aeshash/libaes.a
MYLDFLAGS = -lpthread -static -lxml2 -lm

send_test_SOURCES = send_test.c
send_path_test_SOURCES = send_path_test.c
recv_test_SOURCES = recv_test.c
ping_test_SOURCES = ping_test.c
recv_path_test_SOURCES = recv_path_test.c
send_SOURCES = send.c
test_SOURCES = test.c ../i3_server/i3_matching.c
middle_SOURCES = middle.c
#trig_test_SOURCES = trig_test.c
#explore_id_space_SOURCES = explore_id_space.c
proxy_test_SOURCES = proxy_test.c

send_test_LDADD = $(MYLDADD)
send_path_test_LDADD = $(MYLDADD)
recv_test_LDADD = $(MYLDADD)
ping_test_LDADD = $(MYLDADD)
recv_path_test_LDADD = $(MYLDADD)
send_LDADD = $(MYLDADD)
test_LDADD = $(MYLDADD)
middle_LDADD = $(MYLDADD)
#trig_test_LDADD = $(MYLDADD)
#explore_id_space_LDADD = $(MYLDADD)
proxy_test_LDADD = $(MYLDADD)

send_test_LDFLAGS = $(MYLDFLAGS)
send_path_test_LDFLAGS = $(MYLDFLAGS)
recv_test_LDFLAGS = $(MYLDFLAGS)
ping_test_LDFLAGS = $(MYLDFLAGS)
recv_path_test_LDFLAGS = $(MYLDFLAGS)
send_LDFLAGS = $(MYLDFLAGS)
test_LDFLAGS = $(MYLDFLAGS)
middle_LDFLAGS = $(MYLDFLAGS)
#trig_test_LDFLAGS = $(MYLDFLAGS)
#explore_id_space_LDFLAGS = $(MYLDFLAGS)
proxy_test_LDFLAGS = $(MYLDFLAGS)

EXTRA_DIST = test.xml
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in

