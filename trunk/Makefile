ROOT_DIR = $(shell readlink -f ./)
include Rules.mk

TEST_BIN=tests/regrtest/test.py
INSTALL=install

base:
	-$(MAKE) -C dietlibc-0.30 DEBUG=1
	-$(MAKE) -C VEX
	-$(MAKE) -C perfctr
	-$(MAKE) -C libcommon
	-$(MAKE) -C libcommon LIBC=glibc
	-$(MAKE) -C vkernel
	-$(MAKE) -C console

all: base
	#-$(MAKE) -C tests

# Most development is done on the vkernel and then libcommon
clean:
	-$(MAKE) -C libcommon LIBC=glibc clean
	-$(MAKE) -C libcommon clean
	-$(MAKE) -C vkernel clean
	-$(MAKE) -C console clean


# VEX is rarely updated/patched
reallyclean: clean
	-$(MAKE) -C tests clean
	-$(MAKE) -C VEX clean
	-$(MAKE) -C perfctr clean

# Dietlibc takes a while to compile and there is no need to
# recompile it unless something changes.
spotless: reallyclean
	-$(MAKE) -C dietlibc-0.30 clean

install: all
	$(INSTALL) -m444 include/vk.h /usr/include/vk.h
	$(INSTALL) -m444 include/vk-client-call.h /usr/include/vk-client-call.h
	$(INSTALL) -m777 $(BUILD_DIR)/dcr /usr/bin/dcr

check: base
	$(TEST_BIN) -f tests/regrtest/py-2.6.4.tests tests/regrtest/acts bin/dcr

cscope:
	find `pwd`/ -regex ".*/*\.\(cpp\|cc\|c\|h\|hpp\|S\)?" -type f > cscope.files
	cscope -qbk
