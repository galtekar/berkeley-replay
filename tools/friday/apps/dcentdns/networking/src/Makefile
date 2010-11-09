CC=gcc
#CPLUS=gfilt
CPLUS=gcc
HDRS=-I ../include -I /usr/local/ssl/include
CFLAGS=  -g -Wall -c -O0 $(HDRS) -DDEBUGHEAP -DDEBUG -mpreferred-stack-boundary=12
#CFLAGS=  -g -Wall -c $(HDRS)   -DDEBUG_HEAP 
#CFLAGS=-g -Wall -c $(HDRS)   -DDEBUG_HEAP -O0
LFLAGS=-g -Wall -L /usr/local/ssl/lib /usr/lib/libcrypto.a /usr/lib/gcc/i386-redhat-linux/4.0.2/libstdc++.a #-lcrypto 
#LFLAGS=-Wall -L /usr/local/ssl/lib -lcrypto -ldl  

#CSRCS=neighbor.c server.c message.c rsa.c keyedlist.c logger.c config.c eventq.c pv.c global.c scheduler.c  malloc.c checkpoint.c
#CSRCS=neighbor.c server.c message.c rsa.c keyedlist.c logger.c config.c eventq.c pv.c global.c scheduler.c  checkpoint.c router.c dvrouter.c lsrouter.c pvrouter.c
#CPLUSSRCS=neighbor.cpp server.cpp message.cpp rsa.cpp keyedlist.cpp logger.cpp config.cpp eventq.cpp pv.cpp global.cpp scheduler.cpp  checkpoint.cpp router.cpp dvrouter.cpp lsrouter.cpp pvrouter.cpp nodemap.cpp edgemap.cpp stringmap.cpp intmap.cpp intset.cpp
#CSRCS=malloc.c
CPLUSSRCS=neighbor.cpp server.cpp message.cpp rsa.cpp keyedlist.cpp logger.cpp config.cpp eventq.cpp pv.cpp global.cpp scheduler.cpp  checkpoint.cpp dc.cpp maxflow.cpp dnsmessage.cpp
COBJS:=$(CSRCS:.c=.o)
CPLUSOBJS:=$(CPLUSSRCS:.cpp=.o)
EXEC = tk

all:$(EXEC)

$(EXEC):$(COBJS) $(CPLUSOBJS)
	$(CPLUS) $(CPLUSOBJS) $(COBJS) -o $@ $(LFLAGS)

.c.o:
	$(CC) $(CSRCS) $(CFLAGS)

.cpp.o:
	$(CPLUS) $(CPLUSSRCS) $(CFLAGS)

clean:
	rm -f *.o $(EXEC)


	
