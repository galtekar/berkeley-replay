$(PROGRAMS): $(LDEPS) 

noinst_PROGRAMS =  i3ProxyMonitor
noinst_HEADERS = i3ProxyMonitor.h

if USE_CYGWIN
i3ProxyMonitor_SOURCES = i3ProxyMonitor.c
i3ProxyMonitor_LDFLAGS = -mwindows -mno-cygwin -lcomctl32 -lole32
i3ProxyMonitor_LDADD = i3ProxyMonitor.res
else
i3ProxyMonitor_SOURCES = 
endif

EXTRA_DIST = i3ProxyMonitor.res i3ProxyMonitor.h i3ProxyMonitor.c run_proxy.bat
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
