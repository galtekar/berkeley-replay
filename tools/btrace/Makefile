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

##############################################################
#
# include *.config files
#
##############################################################

ifeq ($(TARGET_COMPILER),gnu)
    include $(PIN_KIT)/source/tools/makefile.gnu.config
    OPT=-O3 -fomit-frame-pointer
    LINKER?=${CXX}
    CXXFLAGS ?= -Wall -Werror -Wno-unknown-pragmas $(DBG) $(OPT) -MMD
endif

ifeq ($(TARGET_COMPILER),ms)
    include $(PIN_KIT)/makefile.ms.config
    DBG?=
endif


TOOL_ROOTS = 2lev_btb 2lev_btb_rsb noinstrum 2lev_btb_stats 2lev_btb_rsb_stats t0 t1 t2 t3

TOOLS = $(TOOL_ROOTS:%=%$(PINTOOL_SUFFIX))

all:  tools  
tools: $(TOOLS)

## build rules

%.o : %.cpp
	$(CXX) ${COPT} $(CXXFLAGS) $(PIN_CXXFLAGS) ${OUTOPT}$@ $<
$(TOOLS): $(PIN_LIBNAMES)


$(TOOLS): %$(PINTOOL_SUFFIX) : %.o
	${LINKER} $(PIN_LDFLAGS) $(LINK_DEBUG) ${LINK_OUT}$@ $< ${PIN_LPATHS} $(PIN_LIBS) $(DBG)

## cleaning
clean:
	-rm -f *.o $(TOOLS) *.out *.tested *.failed *.d foobar $(TEST_APPS) *.exe ipf_branch *.obj *.exp *.lib *.manifest

-include *.d
