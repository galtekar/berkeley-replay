include ../Rules.mk

LEX=flex
YACC=bison
PREFIX=libconfig_yy
YFLAGS=--defines=grammar.h --name-prefix=$(PREFIX)
ifeq ($(BUILD), debug)
YFLAGS += --debug
endif
LFLAGS=-P$(PREFIX)
INCLUDES=-I../dietlibc-0.30/include
CFLAGS = -g -O2 -Wall -nostdinc $(INCLUDES)

OBJS = grammar.o scanner.o libconfig.o

libconfig.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

grammar.o: grammar.y

scanner.o: scanner.l grammar.o

clean: 
	rm -f $(OBJS) grammar.h grammar.c scanner.c scanner.h libconfig.a
