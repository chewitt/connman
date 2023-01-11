Name:       connman
Summary:    Connection Manager
Version:    1.32
Release:    1
License:    GPLv2
URL:        http://connman.net/
Source0:    %{name}-%{version}.tar.bz2
Source1:    main.conf
Source2:    01-require-home-mount-to-be-present.conf
Requires:   dbus >= 1.4
Requires:   wpa_supplicant >= 0.7.1
Requires:   ofono
Requires:   pacrunner
Requires:   connman-configs
Requires:   systemd
Requires:   iptables >= 1.6.1+git2
Requires:   iptables-ipv6 >= 1.6.1+git2
Requires:   libgofono >= 2.0.0
Requires:   libglibutil >= 1.0.21
Requires:   libdbusaccess >= 1.0.2
Requires:   libgsupplicant >= 1.0.17
Requires:   glib2 >= 2.62
Requires:   tayga >= 0.9.2
Requires(preun): systemd
Requires(post): systemd
Requires(postun): systemd
# license macro requires reasonably fresh rpm
BuildRequires:  rpm >= 4.11
BuildRequires:  pkgconfig(xtables) >= 1.6.1
BuildRequires:	pkgconfig(libiptc)
BuildRequires:  pkgconfig(glib-2.0) >= 2.62
BuildRequires:  pkgconfig(gthread-2.0) >= 2.16
BuildRequires:  pkgconfig(dbus-1) >= 1.4
BuildRequires:  openconnect
BuildRequires:  pkgconfig(openconnect) > 4
BuildRequires:  openvpn
BuildRequires:  readline-devel
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(libiphb)
BuildRequires:  pkgconfig(libgofono) >= 2.0.0
BuildRequires:  pkgconfig(libgofonoext)
BuildRequires:  pkgconfig(libglibutil) >= 1.0.21
BuildRequires:  pkgconfig(libdbuslogserver-dbus)
BuildRequires:  pkgconfig(libdbusaccess) >= 1.0.3
BuildRequires:  pkgconfig(libmce-glib)
BuildRequires:  pkgconfig(libgsupplicant) >= 1.0.17
BuildRequires:  ppp-devel
BuildRequires:  libtool
BuildRequires:  usb-moded-devel >= 0.86.0+mer31
BuildRequires:  libglibutil-devel
BuildRequires:  libdbusaccess-devel

%description
Connection Manager provides a daemon for managing Internet connections
within embedded devices running the Linux operating system.

%package wait-online
Summary:    Wait for network to be configured by ConnMan

%description wait-online
A systemd service that can be enabled so that the system waits until a
network connection is established before reaching network-online.target.

%package devel
Summary:    Development files for Connection Manager

%description devel
connman-devel contains development files for use with connman.

%package test
Summary:    Test Scripts for Connection Manager
Requires:   %{name} = %{version}-%{release}
Requires:   dbus-python
Requires:   pygobject2

%description test
Scripts for testing Connman and its functionality.

%package tools
Summary:    Development tools for Connection Manager
Requires:   %{name} = %{version}-%{release}

%description tools
Programs for debugging Connman

%package configs-mer
Summary:    Package to provide default configs for connman
Requires:   %{name} = %{version}-%{release}
Provides:   connman-configs

%description configs-mer
This package provides default configs for connman, such as
FallbackTimeservers.

%package doc
Summary:    Documentation for %{name}
Requires:   %{name} = %{version}-%{release}
Obsoletes:  %{name}-docs

%description doc
Man pages for %{name}.

%package vpn-scripts
Summary:    Connection Manager VPN scripts
Requires:   %{name} = %{version}-%{release}

%description vpn-scripts
This package provides PPP library and generic vpn-script script to be
used by L2TP, OpenConnect, PPTP and VPNC plugins.

%package plugin-vpn-l2tp
Summary:    Connection Manager L2TP VPN plugin
Requires:   %{name} = %{version}-%{release}
Requires:   %{name}-vpn-scripts
Requires:   xl2tpd
Requires:   ppp

%description plugin-vpn-l2tp
This package provides L2TP VPN plugin for connman.

%package plugin-vpn-openvpn
Summary:    Connection Manager OpenVPN VPN plugin
Requires:   %{name} = %{version}-%{release}
Requires:   %{name}-vpn-scripts
Requires:   openvpn

%description plugin-vpn-openvpn
This package provides OpenVPN VPN plugin for connman.

%package plugin-vpn-openconnect
Summary:    Connection Manager OpenConnect VPN plugin
Requires:   %{name} = %{version}-%{release}
Requires:   %{name}-vpn-scripts
Requires:   openconnect >= 2.5.2

%description plugin-vpn-openconnect
This package provides OpenConnect VPN plugin for connman.

%package plugin-vpn-pptp
Summary:    Connection Manager PPTP VPN plugin
Requires:   %{name} = %{version}-%{release}
Requires:   %{name}-vpn-scripts
Requires:   pptp
Requires:   ppp

%description plugin-vpn-pptp
This package provides PPTP VPN plugin for connman.

%package plugin-vpn-vpnc
Summary:    Connection Manager Cisco3000 (VPNC) VPN plugin
Requires:   %{name} = %{version}-%{release}
Requires:   %{name}-vpn-scripts
Requires:   vpnc

%description plugin-vpn-vpnc
This package provides Cisco3000 (VPNC) VPN plugin for connman.

%package plugin-vpn-openfortivpn
Summary:    Connection Manager PPTP VPN plugin
Requires:   %{name} = %{version}-%{release}
Requires:   %{name}-vpn-scripts
Requires:   openfortivpn
Requires:   ppp

%description plugin-vpn-openfortivpn
This package provides OpenFortiNet VPN plugin for connman.

%prep
%setup -q -n %{name}-%{version}/connman

%build
%reconfigure --disable-static \
    --with-version=%{version} \
    --enable-ethernet=builtin \
    --disable-wifi \
    --enable-bluetooth=builtin \
    --enable-openconnect \
    --enable-openvpn \
    --enable-vpnc \
    --enable-l2tp \
    --enable-pptp \
    --enable-openfortivpn \
    --enable-loopback=builtin \
    --enable-pacrunner=builtin \
    --enable-sailfish-vpn-access=builtin \
    --enable-client \
    --enable-test \
    --enable-sailfish-gps \
    --enable-sailfish-wakeup-timer \
    --enable-sailfish-debuglog \
    --enable-sailfish-ofono \
    --enable-sailfish-usb-tethering \
    --enable-sailfish-developer-mode \
    --enable-sailfish-wifi \
    --enable-sailfish-access \
    --enable-sailfish-counters \
    --enable-globalproxy \
    --disable-gadget \
    --disable-wispr \
    --with-systemdunitdir=%{_unitdir} \
    --enable-systemd \
    --with-tmpfilesdir=%{_prefix}/lib/tmpfiles.d \
    runstatedir=/run \
    --enable-blacklist-monitor \
    --enable-clat

%make_build

%check
make check

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_libdir}/%{name}/tools
cp -a tools/stats-tool %{buildroot}%{_libdir}/%{name}/tools
cp -a tools/*-test %{buildroot}%{_libdir}/%{name}/tools
cp -a tools/iptables-unit %{buildroot}%{_libdir}/%{name}/tools

mkdir -p %{buildroot}%{_sysconfdir}/connman/
cp -a %{SOURCE1} %{buildroot}%{_sysconfdir}/connman/

mkdir -p %{buildroot}/%{_unitdir}/multi-user.target.wants
ln -s ../connman.service %{buildroot}/%{_unitdir}/multi-user.target.wants/connman.service
ln -s ../connman-vpn.service %{buildroot}/%{_unitdir}/multi-user.target.wants/connman-vpn.service

mkdir -p %{buildroot}/%{_unitdir}/connman.service.d
cp -a %{SOURCE2} %{buildroot}/%{_unitdir}/connman.service.d/

mkdir -p %{buildroot}/%{_docdir}/%{name}-%{version}
install -m0644 -t %{buildroot}/%{_docdir}/%{name}-%{version} \
        AUTHORS ChangeLog README doc/*.txt

%preun
if [ "$1" -eq 0 ]; then
systemctl stop connman.service || :
fi

%post
# These should match connman_resolvconf.conf rules
%define connman_run_dir /run/connman
%define run_resolv_conf %{connman_run_dir}/resolv.conf
%define etc_resolv_conf %{_sysconfdir}/resolv.conf

mkdir -p %{connman_run_dir} || :
if [ -f %{etc_resolv_conf} -a ! -f %{run_resolv_conf} ]; then
cp %{etc_resolv_conf} %{run_resolv_conf} || :
fi
rm -f %{etc_resolv_conf} || :
ln -s %{run_resolv_conf} %{etc_resolv_conf} || :
# Remove directories created by mistake in release 3.0.2
for d in $(find /var/lib/connman -type d "(" -name "wifi_*" -o -name "ethernet_*_cable" ")") ; do
if [ ! -f $d/settings ] ; then
rm -fr $d
fi
done

systemctl daemon-reload || :
# Do not restart connman here or network breaks.
# We can't reload it either as connman doesn't
# support that feature.

%postun
if [ "$1" -eq 0 -a -L %{etc_resolv_conf} ]; then
rm %{etc_resolv_conf} || :
fi
systemctl daemon-reload || :

%files
%defattr(-,root,root,-)
%license COPYING
%{_sbindir}/connman-vpnd
%{_sbindir}/connmand
%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/plugins-vpn
%{_prefix}/lib/tmpfiles.d/connman_resolvconf.conf
%config %{_sysconfdir}/dbus-1/system.d/*.conf
%{_unitdir}/connman.service
%{_unitdir}/multi-user.target.wants/connman.service
%{_unitdir}/multi-user.target.wants/connman-vpn.service
%{_unitdir}/connman-vpn.service
%{_unitdir}/connman.service.d
/%{_datadir}/dbus-1/system-services/net.connman.vpn.service

%files wait-online
%{_sbindir}/connmand-wait-online
%{_unitdir}/connman-wait-online.service

%files devel
%defattr(-,root,root,-)
%{_includedir}/%{name}
%{_libdir}/pkgconfig/*.pc

%files test
%defattr(-,root,root,-)
%{_libdir}/%{name}/test

%files tools
%defattr(-,root,root,-)
%{_bindir}/connmanctl
%{_libdir}/%{name}/tools

%files configs-mer
%defattr(-,root,root,-)
%dir %{_sysconfdir}/connman
%config %{_sysconfdir}/connman/main.conf
%config %{_sysconfdir}/connman/vpn-dbus-access.conf

%files doc
%defattr(-,root,root,-)
%{_mandir}/man*/%{name}*.*
%{_docdir}/%{name}-%{version}

%files vpn-scripts
%defattr(-,root,root,-)
%license COPYING
%dir %{_libdir}/%{name}/scripts
%{_libdir}/%{name}/scripts/libppp-plugin.so
%{_libdir}/%{name}/scripts/vpn-script
%{_libdir}/%{name}/scripts/openvpn-script

%files plugin-vpn-l2tp
%defattr(-,root,root,-)
%license COPYING
%{_libdir}/%{name}/plugins-vpn/l2tp.so

%files plugin-vpn-openvpn
%defattr(-,root,root,-)
%license COPYING
%{_libdir}/%{name}/plugins-vpn/openvpn.so

%files plugin-vpn-openconnect
%defattr(-,root,root,-)
%license COPYING
%{_libdir}/%{name}/plugins-vpn/openconnect.so

%files plugin-vpn-pptp
%defattr(-,root,root,-)
%license COPYING
%{_libdir}/%{name}/plugins-vpn/pptp.so

%files plugin-vpn-vpnc
%defattr(-,root,root,-)
%license COPYING
%{_libdir}/%{name}/plugins-vpn/vpnc.so

%files plugin-vpn-openfortivpn
%defattr(-,root,root,-)
%license COPYING
%{_libdir}/%{name}/plugins-vpn/openfortivpn.so

