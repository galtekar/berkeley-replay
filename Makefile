ROOT_DIR = $(shell readlink -f ./)
include Rules.mk

TEST_BIN=tests/regrtest/test.py
INSTALL=install

all: base

base:
	-$(MAKE) -C $(LIBS_DIR)/dietlibc DEBUG=1
	-$(MAKE) -C $(LIBS_DIR)/VEX
	-$(MAKE) -C $(DRIVERS_DIR)/perfctr
	-$(MAKE) -C $(LIBS_DIR)/libcommon
	-$(MAKE) -C $(LIBS_DIR)/libcommon LIBC=glibc
	-$(MAKE) -C vkernel
	-$(MAKE) -C $(DRE_DIR)
	@echo "##### Success. Build complete."


dist: install distclean
	@echo "##### Preparing a disribution tarball."
	@tar -cf $(DIST_NAME).tar $(INSTALL_DIR)
	@gzip -f $(DIST_NAME).tar
	@echo "##### Success. Tarball $(DIST_NAME).tar.gz is ready."

distclean:
	rm -f $(DIST_NAME).tar.gz

installclean:
	rm -fr $(INSTALL_DIR)

# Most development is done on the vkernel and then libcommon
clean: installclean distclean
	-$(MAKE) -C $(LIBS_DIR)/libcommon LIBC=glibc clean
	-$(MAKE) -C $(LIBS_DIR)/libcommon clean
	-$(MAKE) -C vkernel clean
	-$(MAKE) -C $(DRE_DIR) clean
	rm -fr build


# VEX is rarely updated/patched
reallyclean: clean
	-$(MAKE) -C tests clean
	-$(MAKE) -C $(LIBS_DIR)/VEX clean
	-$(MAKE) -C $(DRIVERS_DIR)/perfctr clean


install: all installclean
	#$(INSTALL) -m444 include/vk.h /usr/include/vk.h
	#$(INSTALL) -m444 include/vk-client-call.h /usr/include/vk-client-call.h
	@echo "##### Installing to $(INSTALL_DIR) ."
	@cp -r distributed $(INSTALL_DIR)
	@mkdir $(INSTALL_DIR)/bin
	@cp $(VKERNEL_BIN) $(INSTALL_DIR)/bin
	@ln -s ../record/record.py $(INSTALL_DIR)/bin/$(RELEASE_NAME)-record
	@ln -s ../record/portserv.py $(INSTALL_DIR)/bin/$(RELEASE_NAME)-portserv
	@ln -s ../replay/plugins/replay.py $(INSTALL_DIR)/bin/$(RELEASE_NAME)-replay
	@ln -s ../replay/engine/drone.py $(INSTALL_DIR)/bin/$(RELEASE_NAME)-drone
	@ln -s replay/engine $(INSTALL_DIR)/engine
	@echo "##### Success."


# Dietlibc takes a while to compile and there is no need to
# recompile it unless something changes.
spotless: reallyclean cscope_clean
	-$(MAKE) -C $(LIBS_DIR)/dietlibc clean


check: base
	$(TEST_BIN) -f tests/regrtest/py-2.6.4.tests tests/regrtest/acts bin/dcr

cscope_clean:
	rm -f cscope.files cscope.in.out cscope.out cscope.po.out

cscope:
	find `pwd`/vkernel `pwd`/include `pwd`/libs -regex ".*/*\.\(cpp\|cc\|c\|h\|hpp\|S\)?" -type f > cscope.files
	cscope -qbk
