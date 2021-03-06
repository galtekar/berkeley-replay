KVER = $(shell uname -r)

RELEASE_NAME=bdr
#BUILD=debug
BUILD=release
STATS=all
VERSION=0.1

BUILD_DIR = $(ROOT_DIR)/build/x86-$(BUILD)
LIBS_DIR = $(ROOT_DIR)/libs
DRIVERS_DIR = $(ROOT_DIR)/drivers
PERFCTR_DIR = $(DRIVERS_DIR)/perfctr
MSP_DIR = $(DRIVERS_DIR)/msp
DIETLIBC_DIR = $(LIBS_DIR)/dietlibc
VEX_DIR = $(LIBS_DIR)/VEX
DRE_DIR = $(ROOT_DIR)/distributed/replay/engine
VKERNEL_BIN = $(ROOT_DIR)/distributed/bin/$(RELEASE_NAME)-kernel
INSTALL_DIR = $(ROOT_DIR)/distributed
DIST_NAME = $(RELEASE_NAME)-$(VERSION)


INCLUDES = -I$(ROOT_DIR)/include -I$(LIBS_DIR)/ -I$(DRIVERS_DIR)
CFLAGS += -g -Wall -Werror -Wundef -Wno-trigraphs -Wshadow -fno-common -fno-strict-aliasing -Wno-attributes -fno-stack-protector -DRELEASE_NAME=\"$(RELEASE_NAME)\"


ifeq ($(BUILD), release)
CFLAGS += -O2 -DDEBUG=0 -DPRODUCT=0
else
CFLAGS += -O0 -DDEBUG=1 -DPRODUCT=0
endif

ifeq ($(STATS), all)
CFLAGS += -DSTATS=1
else
CFLAGS += -DSTATS=0
endif

ifdef MAX_NR_VCPU
CFLAGS += -DMAX_NR_VCPU=$(MAX_NR_VCPU)
else
CFLAGS += -DMAX_NR_VCPU=1
endif

LIBGCC = $(shell $(CC) -print-libgcc-file-name)
