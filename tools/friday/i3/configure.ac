dnl Process this file with autoconf to produce a configure script.
dnl

AC_INIT(acinclude.m4)
AM_INIT_AUTOMAKE(i3, 0.1)
AM_CONFIG_HEADER(config.h)


dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX

AC_CANONICAL_HOST

AC_PROG_INSTALL
AC_PROG_LN_S

AM_DISABLE_SHARED
test -z "$target" && target=NONE
AM_PROG_LIBTOOL

dnl make sure that gcc 2.96 users use a different version of gcc
GCC_296_WORKAROUND

dnl check xml2 installation
AC_CHECK_PROG(XML2_CONFIG, xml2-config, yes, no)

if test x$XML2_CONFIG = xno
then
	AC_MSG_ERROR("Could not find xml2-config. libxml2 must be installed.")
fi

AC_CHECK_HEADERS(linux/if_tun.h)

AC_MSG_CHECKING("XML2 libs")
XML2_LIBS=`xml2-config --libs`
LIBS="$LIBS $XML2_LIBS"
AC_MSG_RESULT(yes)

AC_MSG_CHECKING("XML2 cflags")
XML2_CFLAGS=`xml2-config --cflags`
CFLAGS="$CFLAGS $XML2_CFLAGS"
AC_MSG_RESULT(yes)

# Check for OS specific stuff
AM_CONDITIONAL(USE_CYGWIN, false)
case "$host" in
    *-*-cygwin*)
    AM_CONDITIONAL(USE_CYGWIN, true)
    ;;
esac

dnl Search for OpenSSL
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
AC_ARG_WITH(ssl-dir,
	    [--with-ssl-dir=PATH Specify path to OpenSSL installation ],
	    [
	     if test "x$withval" != "xno" ; then
		 if test -d "$withval/lib"; then
		     if test -n "${need_dash_r}"; then
			 LDFLAGS="-L${withval}/lib -R${withval}/lib ${LDFLAGS}"
		     else
			 LDFLAGS="-L${withval}/lib ${LDFLAGS}"
		     fi
		 else
		     if test -n "${need_dash_r}"; then
			 LDFLAGS="-L${withval} -R${withval} ${LDFLAGS}"
		     else
			 LDFLAGS="-L${withval} ${LDFLAGS}"
		     fi
		 fi
		 if test -d "$withval/include"; then
		     CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
		 else
		     CPPFLAGS="-I${withval} ${CPPFLAGS}"
		 fi
	     fi
	     ]
	    )
LIBS="$LIBS -lcrypto"
AC_TRY_LINK_FUNC(RAND_add, AC_DEFINE([HAVE_OPENSSL], [], [Openssl]),
[
 dnl Check default openssl install dir
 if test -n "${need_dash_r}"; then
     LDFLAGS="-L/usr/local/ssl/lib -R/usr/local/ssl/lib ${saved_LDFLAGS}"
 else
     LDFLAGS="-L/usr/local/ssl/lib ${saved_LDFLAGS}"
 fi
 CPPFLAGS="-I/usr/local/ssl/include ${saved_CPPFLAGS}"
 AC_TRY_LINK_FUNC(RAND_add, AC_DEFINE(HAVE_OPENSSL),
 [
  AC_MSG_ERROR([*** Can't find recent OpenSSL libcrypto (see config.log for details) ***])
  ]
 )
 ]
)

dnl Determine OpenSSL header version
AC_MSG_CHECKING([OpenSSL header version])
AC_TRY_RUN(
	   [
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#define DATA "sslhver.temp"
int main(void) {
        FILE *fd;
        int rc;

        fd = fopen(DATA,"w");
        if(fd == NULL)
                exit(1);

        if ((rc = fprintf(fd ,"%x (%s)\n", OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_TEXT)) <0)
                exit(1);

        exit(0);
}
        ],
        [
                ssl_header_ver=`cat sslhver.temp`
                AC_MSG_RESULT($ssl_header_ver)
        ],
        [
                AC_MSG_RESULT(not found)
                AC_MSG_ERROR(OpenSSL version header not found.)
        ]
)

dnl Determine OpenSSL library version
AC_MSG_CHECKING([OpenSSL library version])
AC_TRY_RUN(
        [
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#define DATA "ssllver.temp"
int main(void) {
        FILE *fd;
        int rc;

        fd = fopen(DATA,"w");
        if(fd == NULL)
                exit(1);

        if ((rc = fprintf(fd ,"%x (%s)\n", SSLeay(), SSLeay_version(SSLEAY_VERSION))) <0)
                exit(1);

        exit(0);
}
        ],
        [
	 ssl_library_ver=`cat ssllver.temp`
	 AC_MSG_RESULT($ssl_library_ver)
	],
	[
	 AC_MSG_RESULT(not found)
	 AC_MSG_ERROR(OpenSSL library not found.)
	]
)


AC_MSG_CHECKING([Checking OpenSSL version])
AC_TRY_RUN(
        [
#include <string.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
int main(void) { exit(SSLeay() >= 0x90700f ? 0 : 1); }
        ],
        [
                AC_MSG_RESULT(yes)
        ],
        [
                AC_MSG_RESULT(no)
                AC_MSG_ERROR(You need Openssl version 0.9.7 or later)
        ]
)

dnl Sanity check OpenSSL headers
AC_MSG_CHECKING([whether OpenSSL's headers match the library])
AC_TRY_RUN(
        [
#include <string.h>
#include <openssl/opensslv.h>
int main(void) { exit(SSLeay() == OPENSSL_VERSION_NUMBER ? 0 : 1); }
        ],
        [
                AC_MSG_RESULT(yes)
        ],
        [
                AC_MSG_RESULT(no)
                AC_MSG_ERROR(Your OpenSSL headers do not match your library)
        ]
)

ETAGS_ARGS='-C /dev/null'
AC_SUBST(ETAGS_ARGS)


AC_OUTPUT(Makefile
	  aeshash/Makefile
	  chord/Makefile
	  examples/Makefile
	  i3/Makefile
	  i3_client/Makefile
	  i3_server/Makefile
	  proxy_common/Makefile
	  i3_client_proxy/Makefile
	  i3_server_proxy/Makefile
	  win32/Makefile
	  utils/Makefile)
