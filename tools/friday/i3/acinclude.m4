dnl
dnl KL: derived this from MW's SFR acinclude.m4 which in turn was
dnl derived this from Chord's acinclude.m4 file, which in turn
dnl came from DM's acinclude.m4 file for SFS. removed a bunch of macros
dnl that were only relevant to SFS. This file is included by configure.in 
dnl and provides macros used by configure.in
dnl

dnl
dnl Make sure that if we're building on a system in which gcc 2.96 is the
dnl default that we force the build to use gcc3. If gcc3 isn't installed,
dnl the build will (by design) break.
dnl 
AC_DEFUN(GCC_296_WORKAROUND,
[
    gccvers=`gcc --version`
    case $gccvers in
	2.96*) 
	    which gcc3 &> /dev/null
	    if test $? = 0; then
		CC="gcc3"
		CPP="gcc3 -E"
		CXX="g++3"
	    else
		AC_MSG_ERROR(If gcc 2.96 is the default compiler SFS requires gcc3 to compile. Please install gcc3.)
	    fi
	;;
    esac
])


