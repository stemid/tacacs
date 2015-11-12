dnl
dnl File:        configure.in
dnl Revision:    $Id: configure.ac,v 1.0 2014/11/17 12:44:29 olson Exp $
dnl Created:     2014/11/17
dnl Author:      Dave Olson <olson@cumulusnetworks.com>
dnl
dnl Process this file with autoconf to produce a configure script
dnl You need autoconf 2.59 or better!
dnl
dnl ---------------------------------------------------------------------------

AC_PREREQ(2.59)
AC_COPYRIGHT([
See the included file: COPYING for copyright information.
])
AC_INIT(audisp-tacplus, 1.0.0, [olson@cumulusnetworks.com])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([audisp-tacplus.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([config])

dnl --------------------------------------------------------------------
dnl Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL

# Add -Wall -Werror if we are using GCC.
if test "x$GCC" = "xyes"; then
      CFLAGS="$CFLAGS -Wall -Werror"
fi

dnl --------------------------------------------------------------------
dnl Checks for libraries. libpam_tacplus(-dev) has to have been installed before
dnl this is configured and built
AC_CHECK_LIB(tac, tac_connect)

dnl --------------------------------------------------------------------
dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([audit.h fcntl.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h])
AC_CHECK_HEADERS([tacplus/libtac.h])
AC_CHECK_HEADER(auparse.h, [], [AC_MSG_ERROR([audit dev missing missing. Install
                            libaudit-dev and/or libauparse-dev.])] )


dnl --------------------------------------------------------------------
dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl --------------------------------------------------------------------
dnl Checks for library functions.
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([gethostbyname gettimeofday inet_ntoa select socket])

dnl --------------------------------------------------------------------
dnl Generate made files
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
