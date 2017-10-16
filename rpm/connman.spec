Name:       connman
Summary:    Connection Manager
Version:    1.31
Release:    1
Group:      Communications/ConnMan
License:    GPLv2
URL:        http://connman.net/
Source0:    %{name}-%{version}.tar.bz2
Source1:    main.conf
Requires:   dbus >= 1.4
Requires:   wpa_supplicant >= 0.7.1
Requires:   ofono
Requires:   pacrunner
Requires:   connman-configs
Requires:   systemd
Requires:   libgofono >= 2.0.0
Requires:   libglibutil >= 1.0.21
Requires:   libdbusaccess >= 1.0.2
Requires:   libgsupplicant >= 1.0.4
Requires(preun): systemd
Requires(post): systemd
Requires(postun): systemd
BuildRequires:  pkgconfig(xtables)
BuildRequires:  pkgconfig(glib-2.0) >= 2.28
BuildRequires:  pkgconfig(gthread-2.0) >= 2.16
BuildRequires:  pkgconfig(dbus-1) >= 1.4
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  openconnect
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
BuildRequires:  pkgconfig(libgsupplicant) >= 1.0.6
BuildRequires:  ppp-devel
BuildRequires:  libtool

%description
Connection Manager provides a daemon for managing Internet connections
within embedded devices running the Linux operating system.

%package wait-online
Summary:    Wait for network to be configured by ConnMan
Group:      Communications/ConnMan

%description wait-online
A systemd service that can be enabled so that the system waits until a
network connection is established before reaching network-online.target.

%package devel
Summary:    Development files for Connection Manager
Group:      Development/Libraries

%description devel
connman-devel contains development files for use with connman.

%package test
Summary:    Test Scripts for Connection Manager
Group:      Development/Tools
Requires:   %{name} = %{version}-%{release}
Requires:   dbus-python
Requires:   pygobject2

%description test
Scripts for testing Connman and its functionality

%package tools
Summary:    Development tools for Connection Manager
Group:      Development/Tools
Requires:   %{name} = %{version}-%{release}

%description tools
Programs for debugging Connman

%package configs-mer
Summary:    Package to provide default configs for connman
Group:      Development/Tools
Requires:   %{name} = %{version}-%{release}
Provides:   connman-configs

%description configs-mer
This package provides default configs for connman, such as
FallbackTimeservers.


%package docs
Summary:    Documentation for connman
Group:      Documentation
Requires:   %{name} = %{version}-%{release}
Requires:   %{name} = %{version}

%description docs
Documentation for connman.


%prep
%setup -q -n %{name}-%{version}/connman

%build
%reconfigure --disable-static \
    --enable-ethernet=builtin \
    --enable-wifi=builtin \
    --enable-bluetooth=builtin \
    --enable-openconnect=builtin \
    --enable-openvpn=builtin \
    --enable-vpnc=builtin \
    --enable-l2tp=builtin \
    --enable-pptp=builtin \
    --enable-loopback=builtin \
    --enable-pacrunner=builtin \
    --enable-client \
    --enable-test \
    --enable-sailfish-gps \
    --enable-sailfish-wakeup-timer \
    --enable-sailfish-debuglog \
    --enable-sailfish-ofono \
    --enable-sailfish-usb-tethering \
    --enable-sailfish-wifi \
    --enable-sailfish-access \
    --disable-gadget \
    --with-systemdunitdir=/%{_lib}/systemd/system \
    --enable-systemd \
    --with-tmpfilesdir=%{_libdir}/tmpfiles.d

make %{?_smp_mflags}

%check
make check

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_libdir}/%{name}/tools
cp -a tools/stats-tool %{buildroot}%{_libdir}/%{name}/tools
cp -a tools/*-test %{buildroot}%{_libdir}/%{name}/tools
cp -a tools/iptables-unit %{buildroot}%{_libdir}/%{name}/tools
cp -a tools/wispr %{buildroot}%{_libdir}/%{name}/tools

mkdir -p %{buildroot}%{_sysconfdir}/connman/
cp -a %{SOURCE1} %{buildroot}%{_sysconfdir}/connman/

mkdir -p %{buildroot}/%{_lib}/systemd/system/network.target.wants
ln -s ../connman.service %{buildroot}/%{_lib}/systemd/system/network.target.wants/connman.service

%preun
if [ "$1" -eq 0 ]; then
systemctl stop connman.service || :
fi

%post
# These should match connman_resolvconf.conf rules
%define connman_run_dir /var/run/connman
%define run_resolv_conf %{connman_run_dir}/resolv.conf
%define etc_resolv_conf %{_sysconfdir}/resolv.conf

mkdir -p %{connman_run_dir} || :
if [ -f %{etc_resolv_conf} -a ! -f %{run_resolv_conf} ]; then
cp %{etc_resolv_conf} %{run_resolv_conf} || :
fi
rm -f %{etc_resolv_conf} || :
ln -s %{run_resolv_conf} %{etc_resolv_conf} || :

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
%doc COPYING
%{_sbindir}/connman-vpnd
%{_sbindir}/connmand
%{_bindir}/connmanctl
%{_libdir}/%{name}/scripts/*
%{_libdir}/tmpfiles.d/connman_resolvconf.conf
%config %{_sysconfdir}/dbus-1/system.d/*.conf
/%{_lib}/systemd/system/connman.service
/%{_lib}/systemd/system/network.target.wants/connman.service
/%{_lib}/systemd/system/connman-vpn.service
/%{_datadir}/dbus-1/system-services/net.connman.vpn.service

%files wait-online
%{_sbindir}/connmand-wait-online
/%{_lib}/systemd/system/connman-wait-online.service

%files devel
%defattr(-,root,root,-)
%doc AUTHORS COPYING ChangeLog README
%{_includedir}/%{name}/*.h
%{_libdir}/pkgconfig/*.pc

%files test
%defattr(-,root,root,-)
%{_libdir}/%{name}/test/*

%files tools
%defattr(-,root,root,-)
%{_libdir}/%{name}/tools/*

%files configs-mer
%defattr(-,root,root,-)
%config %{_sysconfdir}/connman/main.conf

%files docs
%defattr(-,root,root,-)
%{_datadir}/man/man5/connman.conf.5.gz
%{_datadir}/man/man5/connman-service.config.5.gz
%{_datadir}/man/man5/connman-vpn-provider.config.5.gz
%{_datadir}/man/man5/connman-vpn.conf.5.gz
%{_datadir}/man/man8/connman.8.gz
%{_datadir}/man/man8/connman-vpn.8.gz
%{_datadir}/man/man1/connmanctl.1.gz
