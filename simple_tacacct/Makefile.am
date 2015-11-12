#  Copyright 2015 by Cumulus Networks, Inc
#  Dave Olson <olson@cumulusnetworks.com>

EXTRA_DIST = ChangeLog README

moduledir = @libdir@
module_LTLIBRARIES = libsimple_tacacct.la
ACLOCAL_AMFLAGS = -I config



libsimple_tacacct_la_SOURCES = simple_tacacct.c
libsimple_tacacct_la_CFLAGS = $(AM_CFLAGS)
libsimple_tacacct_la_LDFLAGS = -module -version-info 1:0:0 -shared
libsimple_tacacct_la_LIBADD = -ltacplus_map

# this is a test program, not to be installed.  Use 'make check' to build it.
acct_test_SOURCES = acct_test.c
acct_test_CFLAGS = $(AM_CFLAGS)
acct_test_LDADD = -ldl
check_PROGRAMS = acct_test

clean-generic:
	rm -rf autom4te*.cache 
	rm -f *.rej *.orig *.lang

MAINTAINERCLEANFILES = Makefile.in config.h.in configure aclocal.m4 \
                       config/config.guess  config/config.sub  config/depcomp \
                       config/install-sh config/ltmain.sh config/missing

# We don't want the .la file, nor the .so file; the dlopen should be against
# "libsimple_tacacct.so.1", and nobody should link against this shared library.
install-data-hook:
	rm -f $(DESTDIR)$(libdir)/libsimple_tacacct.so $(DESTDIR)$(libdir)/libsimple_tacacct.la

