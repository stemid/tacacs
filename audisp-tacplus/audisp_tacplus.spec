%define audisp_tacplus_version 1.0.0
%define audisp_tacplus_release 1

Summary: Audit filtering tool for TACACS+ client systems
Name: audisp_tacplus
Version: %{audisp_tacplus_version}
Release: %{audisp_tacplus_release}
License: GPLv2+
Group: System Environment/Daemons
URL: http://cumulusnetworks.com/OLSON-FIXME
Source0: http://cumulusnetworks.com/OLSON-FIXME/audisp-tacplus/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: libtool
BuildRequires: kernel-headers >= 2.6.18
BuildRequires: automake >= 1.9
BuildRequires: autoconf >= 2.59
Requires(pre): coreutils

%description
The audisp_tacplus package contains a program to filter audit
logs via audisp, and send them to a TACACS+ server, to do
TACACS+ accounting.

%prep
%setup -q

%build
%configure --sbindir=/sbin --libdir=/%{_lib}
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{sbin,etc/{audispd/plugins.d}}
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/{man5,man8}
make DESTDIR=$RPM_BUILD_ROOT install

mkdir -p $RPM_BUILD_ROOT/%{_libdir}
# This winds up in the wrong place when libtool is involved
mv $RPM_BUILD_ROOT/%{_lib}/libaudit.a $RPM_BUILD_ROOT%{_libdir}
mv $RPM_BUILD_ROOT/%{_lib}/libauparse.a $RPM_BUILD_ROOT%{_libdir}
curdir=`pwd`

# On platforms with 32 & 64 bit libs, we need to coordinate the timestamp
touch -r ./audisp_tacplus.spec $RPM_BUILD_ROOT/etc/libaudit.conf

%check
make check

%clean
rm -rf $RPM_BUILD_ROOT

%post libs -p /sbin/ldconfig

%postun
if [ $1 -ge 1 ]; then
   /sbin/service auditd condrestart > /dev/null 2>&1 || :
fi


%files
%defattr(-,root,root,-)
%doc  README COPYING ChangeLog
%attr(644,root,root) %{_mandir}/man8/audispd-tacplus.8.gz
%attr(644,root,root) %{_mandir}/man5/audispd-tacplus.conf.5.gz
%attr(644,root,root) %{_mandir}/man5/audispd-tac_plus.conf.5.gz
%attr(750,root,root) /sbin/audisp-tacplus
%config(noreplace) %attr(640,root,root) /etc/audisp-tac_plus.conf /etc/audisp-tacplus.conf


%changelog
2014-11-07 audisp-tacplus v1.0.0 Dave Olson <olson@cumulusnetworks.com>
	First revision
