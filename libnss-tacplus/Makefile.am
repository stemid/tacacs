###########################################################################
##
## Copyright 2014,2015 Cumulus Networks.  All rights reserved.
## Author: Dave Olson <olson@cumulusnetworks.com>
##
###########################################################################

ACLOCAL_AMFLAGS = -I config

moduledir = @libdir@
module_LTLIBRARIES = libnss_tacplus.la

# we don't want our header installed, so just list it in SOURCES.

libnss_tacplus_la_SOURCES = \
nss_tacplus.c \
nss_tacplus.h

libnss_tacplus_la_CFLAGS = $(AM_CFLAGS)
# Version 2.0 because that's the NSS module version, and they must match
libnss_tacplus_la_LDFLAGS = -module -version-info 2:0:0 -shared
libnss_tacplus_la_LIBADD = -ltac -ltacplus_map

EXTRA_DIST = tacplus_nss.conf README ChangeLog

MAINTAINERCLEANFILES = Makefile.in config.h.in configure aclocal.m4 \
                       config/config.guess  config/config.sub  config/depcomp \
                       config/install-sh config/ltmain.sh config/missing

clean-generic:
	rm -rf autom4te*.cache 
	rm -f *.rej *.orig *.lang

# strip all but the NSS entry point, to avoid symbol pollution
# nobody will link against this plugin, so no need for .la
# for NSS, we don't need to install the libnss_tacplus.so.2.0.0
# since it's a plugin, so should remove the copy that libtool automatically installs.
# but the .so.2 is symlinked to that, so that should be cleaned up somehow.
# For debian installs, we just need to get the control files right.
install-data-hook:
	rm -f $(DESTDIR)$(libdir)/libnss_tacplus.la
	$(STRIP) --keep-symbol=_nss_tacplus_getpwnam_r --keep-symbol=_nss_tacplus_getpwuid_r $(DESTDIR)$(libdir)/libnss_tacplus.so 
	${INSTALL} -d $(DESTDIR)$(docdir)
	${INSTALL} -m 644 tacplus_nss.conf $(DESTDIR)$(sysconfdir)

