##
## PIN tools
##

##############################################################
#
# Here are some things you might want to configure
#
##############################################################

#TARGET_COMPILER?=ms
TARGET_COMPILER?=gnu
SOTOOL = 0

##############################################################
#
# include *.config files
#
##############################################################

ifeq ($(TARGET_COMPILER),gnu)
	include $(PINDIR)/makefile.gnu.config
   OPT=-O3 -fomit-frame-pointer
	LINKER?=${CXX} -L../../libcommon
	CXXFLAGS ?= -I../../libcommon/ -I../../VEX/pub -Wall -Wno-unknown-pragmas $(DBG) $(OPT)
	TOOLADDR = -Wl,--script=race.lds -Wl,--section-start,.interp=0x60048400 
endif

##############################################################
#
# Tools sets
#
##############################################################


EXTRA_LIBS = -lcrypto -lcommon_libc
EXTRA_LIBNAMES = ../../libcommon/libcommon_libc.a

ifeq ($(TARGET_OS),m)
    # syscall names on Mac yet to be fixed
    TOOL_ROOTS =
else 
    ifeq ($(TARGET),ia32)
       # can't handle 64 bit syscalls
       TOOL_ROOTS = race
    endif
endif

##############################################################
#
# build rules
#
##############################################################

TARGET = race

all: $(TARGET)
-include depend

CXXSOURCES = sharedheap.cpp misc.cpp vectorclock.cpp segment.cpp segmentqueue.cpp framepool.cpp shmsegmap.cpp pagetable.cpp channel.cpp thread.cpp race.cpp btrace.cpp replaycheck.cpp

CXXOBJECTS = $(CXXSOURCES:.cpp=.o)

OBJS = $(CXXOBJECTS)

## build rules

%.o : %.cpp
	$(CXX) -c $(CXXFLAGS) $(PIN_CXXFLAGS) ${OUTOPT}$@ $<

$(TARGET) : $(CXXOBJECTS) $(PIN_LIBNAMES) $(EXTRA_LIBNAMES)
	${LINKER} $(PIN_LDFLAGS) $(LINK_DEBUG) $(OBJS) ${LINK_OUT}$@ ${PIN_LPATHS} $(PIN_LIBS) -Wl,--start-group $(EXTRA_LIBS) -Wl,--end-group $(DBG)


## cleaning
clean:
	-rm -f *.o $(TARGET) *.out *.tested *.failed *.d *.lib *.exp depend

depend:
	g++ $(CXXFLAGS) $(PIN_CXXFLAGS) -M $(CXXSOURCES) -MF depend
