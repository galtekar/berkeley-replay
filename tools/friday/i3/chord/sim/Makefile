CFLAGS =  -g -Wall
CC   = gcc
GET  = 
REL  = 

ifdef CCURED
include ../../Makefile.ccured
endif

SRCS = event.c server.c sim.c in.c sim_util.c ../eprintf.c \
../pack.c ../sendpkt.c ../finger.c ../process.c ../stabilize.c ../util.c \
../api.c 
OBJS   = $(SRCS:.c=.o)

TRAFFIC_GEN_SRCS = traffic_gen.c sim_util.c ../util.c ../eprintf.c
TRAFFIC_GEN_OBJS   = $(TRAFFIC_GEN_SRCS:.c=.o)

INCLUDE_FILES = def.h event.h fun.h ../chord.h \

all: sim traffic_gen

sim: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o sim -lm -ll
traffic_gen: $(TRAFFIC_GEN_OBJS)
	$(CC) $(CFLAGS) $(TRAFFIC_GEN_OBJS) -o traffic_gen -lm -ll
depend: 
	makedepend $(CFLAGS) $(SRCS)
clean: 
	rm *.o ../*.o
sources: $(SRCS)

# DO NOT DELETE THIS LINE -- make depend depends on it.

