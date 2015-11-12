###########################################################################
##
## Copyright 2014,2015 Cumulus Networks.  All rights reserved.
## Author: Dave Olson <olson@cumulusnetworks.com>
##
###########################################################################

ACLOCAL_AMFLAGS = -I config
AUTOMAKE_OPTIONS = subdir-objects

# This applies to all the libs, but it should only be for pam_tacplus.so
moduledir = @pamdir@

module_LTLIBRARIES = pam_tacplus.la
lib_LTLIBRARIES = libtacplus_map.la libtac.la

# make sure libs are built in the right order
libtacplus_map.la pam_tacplus.la: libtac.la

libtac_includedir = $(oldincludedir)/tacplus

libtac_include_HEADERS = \
libtac/include/tacplus.h \
libtac/include/libtac.h

nodist_libtac_include_HEADERS = \
libtac/include/cdefs.h

libtac_la_SOURCES = \
libtac/lib/acct_r.c \
libtac/lib/acct_s.c \
libtac/lib/attrib.c \
libtac/lib/authen_r.c \
libtac/lib/authen_s.c \
libtac/lib/author_r.c \
libtac/lib/author_s.c \
libtac/lib/connect.c \
libtac/lib/cont_s.c \
libtac/lib/crypt.c \
libtac/lib/hdr_check.c \
libtac/lib/header.c \
libtac/lib/magic.c \
libtac/lib/magic.h \
libtac/lib/md5.c \
libtac/lib/md5.h \
libtac/lib/messages.c \
libtac/lib/messages.h \
libtac/lib/read_wait.c \
libtac/lib/version.c \
libtac/lib/xalloc.c \
libtac/lib/xalloc.h \
$(libtac_include_HEADERS)
libtac_la_CFLAGS = $(AM_CFLAGS) -Ilibtac/include
libtac_la_LDFLAGS = -version-info 2:0:0 -shared -Wl,--no-undefined \
	-export-symbols-regex '^tac_'


pam_tacplus_la_SOURCES = pam_tacplus.h \
pam_tacplus.c \
support.h \
support.c
pam_tacplus_la_CFLAGS = $(AM_CFLAGS) -Ilibtac/include
pam_tacplus_la_LDFLAGS = -module -avoid-version -shared
pam_tacplus_la_LIBADD = -L.libs -ltac -ltacplus_map -lpam
# no versioning for this, since it's always installed as pam_tacplus.so
# and not ever used as a link library

libtacplus_map_la_SOURCES = map_tacplus_user.h  \
	map_tacplus_user.c
libtacplus_map_la_CFLAGS = $(AM_CFLAGS) -Ilibtac/include
libtacplus_map_la_LDFLAGS = -version-info 1:0:0 -shared  -Wl,--no-undefined
libtacplus_map_la_LIBADD = -L.libs -laudit

libtacplus_map_includedir = $(oldincludedir)/tacplus

libtacplus_map_include_HEADERS = \
	map_tacplus_user.h

EXTRA_DIST = pam_tacplus.spec sample.pam libtac.pc.in

MAINTAINERCLEANFILES = Makefile.in config.h.in configure aclocal.m4 \
                       config/config.guess  config/config.sub  config/depcomp \
                       config/install-sh config/ltmain.sh config/missing

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtac.pc


clean-generic:
	rm -rf autom4te*.cache 
	rm -f *.rej *.orig *.lang

# nobody links against the pam module, so no need for the .la
# Similiarly, since the libtac shared libraries are put into
# $libdir, which is a standard linker search, no need for the .la there
# either, and it clutters things up.
# Despite being nodist, nodist_libtac_include_HEADERS is getting installed...
install-data-hook:
	rm -f $(DESTDIR)$(pamdir)/pam_tacplus.la
	rm -f $(DESTDIR)$(libdir)/libtac.la $(DESTDIR)$(libdir)/libtacplus_map.la
	rm -f $(DESTDIR)$(libtac_includedir)/cdefs.h
	${INSTALL} -d $(DESTDIR)$(docdir)
	${INSTALL} -d $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 644 tacplus_servers $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 644 sample.pam $(DESTDIR)$(docdir)

