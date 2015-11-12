#  Copyright 2014, 2015 by Cumulus Networks, Inc
#  Dave Olson <olson@cumulusnetworks.com>

EXTRA_DIST = ChangeLog README audisp_tacplus.spec \
	audisp-tac_plus.conf audisp-tacplus.conf

audisp_tacplus_SOURCES = audisp-tacplus.c
audisp_tacplus_CFLAGS = -O
audisp_tacplus_LDADD = -lauparse -ltacplus_map
sbin_PROGRAMS = audisp-tacplus

clean-generic:
	rm -rf autom4te*.cache 
	rm -f *.rej *.orig *.lang

ACLOCAL_AMFLAGS = -I config

MAINTAINERCLEANFILES = Makefile.in config.h.in configure aclocal.m4 \
                       config/config.guess  config/config.sub  config/depcomp \
                       config/install-sh config/ltmain.sh config/missing

install-data-hook:
	${INSTALL} -d $(DESTDIR)$(sbindir)/
	${INSTALL} -m 755 audisp-tacplus $(DESTDIR)$(sbindir)
	${INSTALL} -d $(DESTDIR)$(sysconfdir)/audisp/plugins.d
	${INSTALL} -m 600 audisp-tac_plus.conf $(DESTDIR)$(sysconfdir)/audisp/
	${INSTALL} -m 644 audisp-tacplus.conf $(DESTDIR)$(sysconfdir)/audisp/plugins.d

