## Process this file with automake to produce Makefile.in

if USE_CYGWIN
DIRS = aeshash utils i3 i3_client proxy_common i3_client_proxy win32
SUBDIRS = $(DIRS)
else
DIRS = aeshash utils chord i3 i3_client i3_server \
       proxy_common i3_client_proxy i3_server_proxy examples
SUBDIRS = $(DIRS)
endif

CLEANFILES = core *.core *~

EXTRA_DIST = 
MAINTAINERCLEANFILES = aclocal.m4 install-sh mkinstalldirs \
	missing configure config.guess config.sub config.h.in \
	ltconfig ltmain.sh INSTALL COPYING Makefile.in stamp-h.in

