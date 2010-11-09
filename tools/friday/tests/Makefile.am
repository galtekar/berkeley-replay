LIBS =
INCLUDES =

noinst_PROGRAMS = simple cplusplus exec fork daemon shared gethostbyname sysv threads cond procthreads sendto fs server client fcntl malloc
noinst_HEADERS = cycle_time.h
noinst_SCRIPTS = run_tests

simple_SOURCES = simple.c
simple_LDFLAGS =
simple_LDADD =

cplusplus_SOURCES = cplusplus.cc
cplusplus_LDFLAGS =
cplusplus_LDADD =

fork_SOURCES = fork.c
fork_LDFLAGS =

fcntl_SOURCES = fcntl.c
fcntl_LDFLAGS =

fs_SOURCES = fs.c
fs_LDFLAGS =

exec_SOURCES = exec.c
exec_LDFLAGS =

daemon_SOURCES = daemon.c
daemon_LDFLAGS =

shared_SOURCES = shared.c
shared_LDFLAGS =

cond_SOURCES = cond.c
cond_LDFLAGS =

sysv_SOURCES = sysv.c
sysv_LDFLAGS =

threads_SOURCES = threads.c
threads_LDFLAGS = -lpthread

procthreads_SOURCES = procthreads.c
procthreads_LDFLAGS = -lpthread

gethostbyname_SOURCES = gethostbyname.c
gethostbyname_LDFLAGS =
gethostbyname_LDADD =

sendto_SOURCES = sendto.c cycle_time.c
sendto_LDFLAGS =

server_SOURCES = server.c
server_LDFLAGS = -ldl

client_SOURCES = client.c
client_LDFLAGS =

malloc_SOURCES = malloc.c
malloc_LDFLAGS =

TESTS = run_tests

EXTRA_DIST = run_tests
CLEANFILES = core *.core *~ *.log.gz core.* *.ckpt
MAINTAINERCLEANFILES = Makefile.in
