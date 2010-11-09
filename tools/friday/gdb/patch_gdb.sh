#!/bin/sh

export cvsdate=20040607

# ChangeLogs patches.
export patch0=/usr/src/redhat/SOURCES/gdb-6.1post-ChangeLog.patch
# ChangeLogs patches for doc.
export patch2=/usr/src/redhat/SOURCES/gdb-6.1post-ChangeLog-doc.patch
####### start patches from the previous Rexport pM.
# Silence gcc warnings.
export patch4=/usr/src/redhat/SOURCES/gdb-6.1post-gccwarn.patch

####### end patches from the previous Rexport pM.

# Fix watchpoint support.
export patch5=/usr/src/redhat/SOURCES/gdb-6.1post-watchpoint-fix.patch
# Thread fix.
export patch6=/usr/src/redhat/SOURCES/gdb-6.1post-thread-fix.patch
# Fix to allow using libunwind 0.97 and up.
export patch8=/usr/src/redhat/SOURCES/gdb-6.1post-libunwind.patch
# Fix to support applications calling clone directly
export patch9=/usr/src/redhat/SOURCES/gdb-6.1post-linlwp-aug2004.patch

####### Signal trampoline fixes
export patch10=/usr/src/redhat/SOURCES/gdb-6.1post-sig-ppc-jun2004.patch
export patch11=/usr/src/redhat/SOURCES/gdb-6.1post-sig-symtramp-jun2004.patch
export patch12=/usr/src/redhat/SOURCES/gdb-6.1post-sig-x86-jun2004.patch
export patch13=/usr/src/redhat/SOURCES/gdb-6.1post-sig-step-aug2004.patch
export patch14=/usr/src/redhat/SOURCES/gdb-6.1post-sig-infrun-sep2004.patch

####### ABI fixes and updates
export patch20=/usr/src/redhat/SOURCES/gdb-6.1post-abi-ppc64-oct2004.patch
export patch21=/usr/src/redhat/SOURCES/gdb-6.1post-abi-ppc64syscall-jun2004.patch
export patch22=/usr/src/redhat/SOURCES/gdb-6.1post-abi-wildframe-jun2004.patch
export patch23=/usr/src/redhat/SOURCES/gdb-6.1post-abi-ppc64main-aug2004.patch
export patch24=/usr/src/redhat/SOURCES/gdb-6.1post-frame-zeropc-sep2004.patch
export patch25=/usr/src/redhat/SOURCES/gdb-6.1post-abi-ppcdotsolib-oct2004.patch
export patch26=/usr/src/redhat/SOURCES/gdb-6.1post-abi-ppc64fpscr-oct2004.patch
export patch27=/usr/src/redhat/SOURCES/gdb-6.1post-abi-s390rewrite-oct2004.patch
export patch28=/usr/src/redhat/SOURCES/gdb-6.1post-abi-ppc64section-oct2004.patch
export patch29=/usr/src/redhat/SOURCES/gdb-6.1post-op-piece-warn-oct2004.patch

###### Testsuite merge, fixes, and local RH hack
export patch30=/usr/src/redhat/SOURCES/gdb-6.1post-test-merge-20040923.patch
# Work around out-of-date dejagnu that does not have kfail
export patch31=/usr/src/redhat/SOURCES/gdb-6.1post-test-rh-kfail.patch
# Match Red Hat version info
export patch32=/usr/src/redhat/SOURCES/gdb-6.1post-test-rh-version.patch
# Get selftest working with sep-debug-info
export patch33=/usr/src/redhat/SOURCES/gdb-6.1post-test-self-jul2004.patch
# Check that libunwind works - new test then fix
export patch34=/usr/src/redhat/SOURCES/gdb-6.1post-test-rh-libunwind.patch
export patch35=/usr/src/redhat/SOURCES/gdb-6.1post-test-rh-libunwindfix1.patch
# Generate the bigcore file from the running inferior et.al.
export patch36=/usr/src/redhat/SOURCES/gdb-6.1post-test-bigcoresingle-sep2004.patch
export patch37=/usr/src/redhat/SOURCES/gdb-6.1post-test-bigcore64-sep2004.patch
# Fix comment bug in sigstep.exp
export patch38=/usr/src/redhat/SOURCES/gdb-6.1post-test-sigstepcomment-oct2004.patch

##### VSYSCALL and PIE
export patch50=/usr/src/redhat/SOURCES/gdb-6.1post-vsyscall-jul2004.patch
export patch51=/usr/src/redhat/SOURCES/gdb-6.1post-pie-jul2004.patch
export patch52=/usr/src/redhat/SOURCES/gdb-6.1post-test-pie-oct2004.patch

##### Bigcore tweak
export patch60=/usr/src/redhat/SOURCES/gdb-6.1post-o-largefile-jul2004.patch

# Fix crasher in symtab
export patch70=/usr/src/redhat/SOURCES/gdb-6.1post-symtab-bob-jul2004.patch
# Add java inferior call support
export patch71=/usr/src/redhat/SOURCES/gdb-6.1post-java-infcall-aug2004.patch
# Add support for manually loaded/unloaded shlibs.
export patch72=/usr/src/redhat/SOURCES/gdb-6.1post-unload-aug2004.patch
# Fix stepping in threads
export patch73=/usr/src/redhat/SOURCES/gdb-6.1post-thread-step-sep2004.patch
# Add threaded watchpoint support
export patch74=/usr/src/redhat/SOURCES/gdb-6.1post-threaded-watchpoints-sep2004.patch
# Fix for thread_db_get_lwp
export patch75=/usr/src/redhat/SOURCES/gdb-6.1post-thread-get-lwp-oct2004.patch
# Fix for S/390 watchpoints under threads.
export patch76=/usr/src/redhat/SOURCES/gdb-6.1post-s390-watchpoints-oct2004.patch
# Fix for caching thread lwps for linux
export patch77=/usr/src/redhat/SOURCES/gdb-6.1post-lwp-cache-oct2004.patch

# Fix panic when stepping an solib call
export patch80=/usr/src/redhat/SOURCES/gdb-6.1post-infcall-step-jul2004.patch

# Apply patches defined above.
patch -p1 < $patch0 
patch -p1 < $patch2 
patch -p1 < $patch4 
patch -p1 < $patch5 
patch -p1 < $patch6 
patch -p1 < $patch8 
patch -p1 < $patch9 
patch -p1 < $patch10 
patch -p1 < $patch11 
patch -p1 < $patch12 
patch -p1 < $patch13 
patch -p1 < $patch14 

patch -p1 < $patch20 
patch -p1 < $patch21 
patch -p1 < $patch22 
patch -p1 < $patch23 
patch -p1 < $patch24 
patch -p1 < $patch25 
patch -p1 < $patch26 
patch -p1 < $patch27 
patch -p1 < $patch28 
patch -p1 < $patch29 

#patch -p1 < $patch30 
#patch -p1 < $patch31 
#patch -p1 < $patch32 
#patch -p1 < $patch33 
#patch -p1 < $patch34 
#patch -p1 < $patch35 
#patch -p1 < $patch36 
#patch -p1 < $patch37 
#patch -p1 < $patch38 

#patch -p1 < $patch50 
#patch -p1 < $patch51 
#patch -p1 < $patch52 

patch -p1 < $patch60 
patch -p1 < $patch70 
patch -p1 < $patch71 
patch -p1 < $patch72 
patch -p1 < $patch73 
patch -p1 < $patch74 
patch -p1 < $patch75 
patch -p1 < $patch76 
patch -p1 < $patch77 
patch -p1 < $patch80 

# Change the version that gets printed at GDB startup, so it is RedHat
# specific.
cat > gdb/version.in << _FOO
Red Hat Linux (Liblog special)
_FOO
