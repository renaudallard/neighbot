Name: neighbot
Version: 0.4.1
Release: 1%{?dist}
Summary: Network neighbor monitoring daemon

Group: System Environment/Daemons
License: BSD-2-Clause
URL: https://github.com/renaudallard/neighbot
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: gcc, make, libpcap-devel, systemd-rpm-macros

%description
Passively watches ARP and NDP traffic on all Ethernet interfaces, records
IP-to-MAC mappings, and alerts you when something changes. Like arpwatch,
but also handles IPv6. Single-threaded, single binary, no dependencies
beyond libpcap.

%prep
%setup -q

%build
make %{?_smp_mflags} CFLAGS="%{optflags}"

%install
rm -rf $RPM_BUILD_ROOT
make install PREFIX=/usr DESTDIR=$RPM_BUILD_ROOT
install -D -m 0644 neighbot.service $RPM_BUILD_ROOT%{_unitdir}/neighbot.service
sed -i 's|/usr/local/sbin|/usr/sbin|' $RPM_BUILD_ROOT%{_unitdir}/neighbot.service

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_sbindir}/neighbot
%doc
%{_mandir}/man8/neighbot.8.gz
%{_unitdir}/neighbot.service
%dir /var/neighbot
/var/neighbot/oui.txt

%post
if [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] && [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl --no-reload --quiet stop neighbot.service 2>/dev/null || :
fi

%postun
if [ -x /usr/bin/systemctl ]; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi

%changelog
* Wed Feb 25 2026 Renaud Allard <renaud@allard.it> 0.4.1-1
- Fix pledge violation on OpenBSD from pcap_stats ioctl

* Wed Feb 25 2026 Renaud Allard <renaud@allard.it> 0.4.0-1
- Async notifications, hardening flags, input validation, pcap drop logging

* Wed Feb 25 2026 Renaud Allard <renaud@allard.it> 0.3.7-1
- Initial packaging
