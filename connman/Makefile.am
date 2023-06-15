
AM_MAKEFLAGS = --no-print-directory

noinst_LTLIBRARIES =

includedir = @includedir@/connman

include_HEADERS = include/log.h include/plugin.h \
			include/notifier.h include/service.h \
			include/resolver.h include/ipconfig.h \
			include/device.h include/network.h include/inet.h \
			include/storage.h include/provision.h \
			include/session.h include/ipaddress.h include/agent.h \
			include/inotify.h include/peer.h include/machine.h \
			include/technology.h include/iptables_ext.h \
			include/dbus.h gdbus/gdbus.h include/nat.h

if VPN
include_HEADERS += include/task.h include/setting.h \
			include/vpn-dbus.h
nobase_include_HEADERS = vpn/vpn-provider.h vpn/vpn-agent.h \
			vpn/plugins/vpn.h
endif

nodist_include_HEADERS = include/version.h

noinst_HEADERS = include/rtnl.h \
			include/dbus.h \
			include/provider.h include/vpn-dbus.h \
			include/utsname.h include/timeserver.h include/proxy.h \
			include/wakeup_timer.h include/access.h \
			include/setting.h \
			include/backtrace.h

local_headers = $(foreach file,$(include_HEADERS) $(nodist_include_HEADERS) \
			$(noinst_HEADERS), include/connman/$(notdir $(file)))


noinst_LTLIBRARIES += gdbus/libgdbus-internal.la

gdbus_libgdbus_internal_la_SOURCES = gdbus/gdbus.h \
				gdbus/mainloop.c gdbus/watch.c \
				gdbus/object.c gdbus/client.c gdbus/polkit.c

if BACKTRACE
backtrace_sources = src/backtrace.c
endif

gdhcp_sources = gdhcp/gdhcp.h gdhcp/common.h gdhcp/common.c gdhcp/client.c \
		gdhcp/server.c gdhcp/unaligned.h

gweb_sources = gweb/gweb.h gweb/gweb.c gweb/gresolv.h gweb/gresolv.c

if WISPR
gweb_sources += gweb/giognutls.h gweb/giognutls.c
else
gweb_sources += gweb/giognutls.h gweb/gionotls.c
endif

if BACKTRACE
backtrace_sources = src/backtrace.c
endif

shared_sources = src/shared/util.h src/shared/util.c \
		src/shared/arp.h src/shared/arp.c

if DATAFILES

if NMCOMPAT
nmcompat_conf = plugins/connman-nmcompat.conf
endif

dbusconfdir = @DBUS_CONFDIR@

dbusconf_DATA = src/connman.conf $(nmcompat_conf)

if VPN
dbusconf_DATA += vpn/connman-vpn-dbus.conf
dbusservicedir = @DBUS_DATADIR@
dbusservice_DATA = vpn/net.connman.vpn.service
endif

if SYSTEMD
systemdunitdir = @SYSTEMD_UNITDIR@
systemdunit_DATA = src/connman.service src/connman-wait-online.service

tmpfilesdir = @SYSTEMD_TMPFILESDIR@
nodist_tmpfiles_DATA = scripts/connman_resolvconf.conf

if VPN
systemdunit_DATA += vpn/connman-vpn.service
endif
endif
endif

service_files_sources = src/connman.service.in src/net.connman.service.in \
				vpn/connman-vpn.service.in \
				vpn/net.connman.vpn.service.in \
				src/connman-wait-online.service.in
service_files = src/connman.service src/net.connman.service \
				vpn/connman-vpn.service \
				vpn/net.connman.vpn.service \
				src/connman-wait-online.service

plugin_LTLIBRARIES =

plugin_objects =

builtin_modules =
builtin_sources =
builtin_libadd =
builtin_cflags =

noinst_PROGRAMS =
bin_PROGRAMS =

unit_objects =

MANUAL_PAGES =

sbin_PROGRAMS = src/connmand src/connmand-wait-online

src_connmand_SOURCES = $(gdhcp_sources) $(gweb_sources) $(backtrace_sources) \
			$(builtin_sources) $(shared_sources) src/connman.ver \
			src/main.c src/connman.h src/log.c \
			src/error.c src/plugin.c src/task.c \
			src/device.c src/network.c src/connection.c \
			src/manager.c src/service.c \
			src/clock.c src/timezone.c src/agent-connman.c \
			src/agent.c src/notifier.c src/provider.c \
			src/resolver.c src/ipconfig.c src/detect.c src/inet.c \
			src/dhcp.c src/dhcpv6.c src/rtnl.c src/proxy.c \
			src/utsname.c src/timeserver.c src/rfkill.c \
			src/storage.c src/dbus.c src/config.c \
			src/technology.c src/counter.c src/ntp.c \
			src/session.c src/tethering.c src/wpad.c src/wispr.c \
			src/iptables.c src/dnsproxy.c src/6to4.c \
			src/ippool.c src/bridge.c src/nat.c src/ipaddress.c \
			src/inotify.c src/firewall.c src/ipv6pd.c src/peer.c \
			src/peer_service.c src/machine.c src/util.c \
			src/wakeup_timer.c src/fsid.c \
			src/access.c vpn/vpn-settings.c vpn/vpn-util.c \
			src/sailfish_iptables_ext.c src/iptables-validate.c \
			src/login_manager.c

if SYSTEMD
src_connmand_SOURCES += src/systemd_login.c
endif

src_connmand_LDADD = gdbus/libgdbus-internal.la $(builtin_libadd) \
			@GIO_LIBS@ @GOBJECT_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @XTABLES_LIBS@ @GNUTLS_LIBS@ \
			@IPHB_LIBS@ @LIBIPTC_LIBS@ @DBUSACCESS_LIBS@ -lresolv -ldl -lrt

src_connmand_LDFLAGS = -Wl,--export-dynamic \
				-Wl,--version-script=$(srcdir)/src/connman.ver

src_connmand_wait_online_SOURCES = src/connmand-wait-online.c

src_connmand_wait_online_LDADD = gdbus/libgdbus-internal.la \
			@GLIB_LIBS@ @DBUS_LIBS@
if SAILFISH_COUNTERS
src_connmand_SOURCES += src/sailfish_datacounter.c \
			src/sailfish_datacounter_dbus.c \
			src/sailfish_datacounters.c \
			src/sailfish_datacounters_dbus.c \
			src/sailfish_datacounters_dbus_util.c \
			src/sailfish_datacounters_util.c \
			src/sailfish_datahistory.c \
			src/sailfish_datahistory_dbus.c \
			src/sailfish_datahistory_file.c \
			src/sailfish_datahistory_memory.c \
			src/sailfish_stats.c
else
src_connmand_SOURCES += src/jolla-stats.c
endif

if VPN
vpn_plugin_LTLIBRARIES =

vpn_plugin_objects =

builtin_vpn_modules =
builtin_vpn_sources =
builtin_vpn_libadd =
builtin_vpn_cflags =

sbin_PROGRAMS += vpn/connman-vpnd

vpn_connman_vpnd_SOURCES = $(builtin_vpn_sources) $(backtrace_sources) \
			$(gweb_sources) vpn/vpn.ver vpn/main.c vpn/vpn.h \
			src/log.c src/error.c src/plugin.c src/task.c \
			vpn/vpn-manager.c vpn/vpn-provider.c \
			vpn/vpn-provider.h vpn/vpn-rtnl.h \
			vpn/vpn-ipconfig.c src/inet.c vpn/vpn-rtnl.c \
			src/dbus.c src/storage.c src/ipaddress.c src/agent.c \
			vpn/access.c vpn/vpn-agent.c vpn/vpn-agent.h \
			src/inotify.c vpn/vpn-config.c src/fsid.c \
			vpn/vpn-settings.c vpn/vpn-util.c

vpn_connman_vpnd_LDADD = gdbus/libgdbus-internal.la $(builtin_vpn_libadd) \
				@GLIB_LIBS@ @DBUS_LIBS@ @GNUTLS_LIBS@ @DBUSACCESS_LIBS@ \
				-lresolv -ldl

vpn_connman_vpnd_LDFLAGS = -Wl,--export-dynamic \
				-Wl,--version-script=$(srcdir)/vpn/vpn.ver
endif

BUILT_SOURCES = $(local_headers) src/builtin.h $(service_files) \
	scripts/connman scripts/connman_resolvconf.conf

if VPN
BUILT_SOURCES += vpn/builtin.h
endif

CLEANFILES = src/connman.conf $(BUILT_SOURCES) $(service_files) \
	$(shell find . -name "*.gcda") $(shell find . -name "*.gcno")

statedir = $(runstatedir)/connman
vpn_statedir = $(runstatedir)/connman-vpn

if VPN
vpn_plugindir = $(libdir)/connman/plugins-vpn
endif

plugindir = $(libdir)/connman/plugins

scriptdir = $(libdir)/connman/scripts

storageroot = $(localstatedir)/lib

# Path in users' home dir to use as storage dir
userstorage = ".local/share/system/privileged"

configdir = ${sysconfdir}/connman

testconfigdir = "/tmp/connman_test"

if MAINTAINER_MODE
if VPN
build_vpn_plugindir = $(abs_top_srcdir)/vpn/plugins/.libs
endif
build_plugindir = $(abs_top_srcdir)/plugins/.libs
build_scriptdir = $(abs_top_srcdir)/scripts
else
build_plugindir = $(plugindir)
build_scriptdir = $(scriptdir)
if VPN
build_vpn_plugindir = $(vpn_plugindir)
endif
endif

AM_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@ @XTABLES_CFLAGS@ \
				@GNUTLS_CFLAGS@ $(builtin_cflags) \
				-DCONNMAN_PLUGIN_BUILTIN \
				-DPLUGINDIR=\""$(build_plugindir)"\" \
				-DSCRIPTDIR=\""$(build_scriptdir)"\" \
				-DDEFAULT_STORAGE_ROOT=\""$(storageroot)\"" \
				-DRUNSTATEDIR=\""$(runstatedir)"\" \
				-DCONFIGDIR=\""$(configdir)\""

if VPN
AM_CPPFLAGS = -I$(builddir)/include -I$(srcdir)/gdbus
else
AM_CPPFLAGS = -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus
endif

src_connmand_CFLAGS = @DBUS_CFLAGS@ @GIO_CFLAGS@ @GOBJECT_CFLAGS@ @GLIB_CFLAGS@ @XTABLES_CFLAGS@ \
				@GNUTLS_CFLAGS@ @IPHB_CFLAGS@ @DBUSACCESS_CFLAGS@ \
				$(builtin_cflags) \
				-DCONNMAN_PLUGIN_BUILTIN \
				-DSTATEDIR=\""$(statedir)"\" \
				-DPLUGINDIR=\""$(build_plugindir)"\" \
				-DSCRIPTDIR=\""$(build_scriptdir)"\" \
				-DDEFAULT_STORAGE_ROOT=\""$(storageroot)"\" \
				-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
				-DRUNSTATEDIR=\""$(runstatedir)"\" \
				-DCONFIGDIR=\""$(configdir)"\" \
				-DDEFAULT_VPN_STATEDIR=\""$(vpn_statedir)"\" \
				-I$(builddir)/src

EXTRA_DIST = src/genbuiltin src/connman-dbus.conf src/connman-polkit.conf \
				plugins/connman-nmcompat.conf \
				$(service_files_sources) scripts/connman.in

if VPN
vpn_connman_vpnd_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@ @DBUSACCESS_CFLAGS@ \
				$(builtin_vpn_cflags) \
				-DCONNMAN_PLUGIN_BUILTIN \
				-DDEFAULT_VPN_STATEDIR=\""$(vpn_statedir)"\" \
				-DPLUGINDIR=\""$(build_vpn_plugindir)"\" \
				-DSCRIPTDIR=\""$(build_scriptdir)"\" \
				-DDEFAULT_STORAGE_ROOT=\""$(storageroot)"\" \
				-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
				-DRUNSTATEDIR=\""$(runstatedir)"\" \
				-DCONFIGDIR=\""$(configdir)"\" \
				-I$(builddir)/vpn

endif

EXTRA_DIST += vpn/vpn-dbus.conf vpn/vpn-polkit.conf

script_DATA =
script_PROGRAMS =
script_LTLIBRARIES =

include Makefile.plugins

if CLIENT
bin_PROGRAMS += client/connmanctl

client_connmanctl_SOURCES = client/dbus_helpers.h client/dbus_helpers.c \
			client/services.h client/services.c \
			client/commands.h client/commands.c \
			client/input.h client/input.c \
			client/agent.h client/agent.c \
			client/peers.h client/peers.c \
			client/vpnconnections.h client/vpnconnections.c \
			client/main.c

client_connmanctl_LDADD = gdbus/libgdbus-internal.la @DBUS_LIBS@ @GLIB_LIBS@ \
				-lreadline -ldl
endif

noinst_PROGRAMS += unit/test-access unit/test-ippool \
	unit/test-sailfish_access unit/test-vpn-settings \
	unit/test-sailfish_iptables_ext unit/test-service \
	unit/test-globalproxy unit/test-firewall unit/test-iptables \
	unit/test-device unit/test-vpn_access unit/test-sailfish_vpn_access \
	unit/test-storage unit/test-systemd_login unit/test-vpn-util

if TEST_COVERAGE
COVERAGE_OPT = --coverage
endif

unit_test_ippool_SOURCES = $(backtrace_sources) src/log.c src/dbus.c \
					src/error.c src/ippool.c unit/test-ippool.c
unit_test_ippool_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS)
unit_test_ippool_LDADD = gdbus/libgdbus-internal.la \
				@GLIB_LIBS@ @DBUS_LIBS@ -ldl

unit_test_access_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS)
unit_test_access_SOURCES = unit/test-access.c src/access.c src/log.c \
				$(backtrace_sources)
unit_test_access_LDADD = @GLIB_LIBS@ -ldl

unit_test_vpn_access_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS)
unit_test_vpn_access_SOURCES = unit/test-vpn_access.c vpn/access.c src/log.c \
				$(backtrace_sources)
unit_test_vpn_access_LDADD = @GLIB_LIBS@ -ldl

unit_test_sailfish_access_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
			@DBUSACCESS_CFLAGS@
unit_test_sailfish_access_SOURCES = unit/test-sailfish_access.c \
			src/log.c src/access.c plugins/sailfish_access.c \
			$(backtrace_sources)
unit_test_sailfish_access_LDADD = @GLIB_LIBS@ @DBUSACCESS_LIBS@ -ldl

unit_test_vpn_settings_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
				-DDEFAULT_VPN_STATEDIR=\""$(vpn_statedir)"\"
unit_test_vpn_settings_SOURCES = $(backtrace_sources) unit/test-vpn-settings.c \
				vpn/vpn-settings.c src/log.c vpn/vpn-util.c
unit_test_vpn_settings_LDADD = @GLIB_LIBS@ -ldl

unit_test_vpn_util_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS)
unit_test_vpn_util_SOURCES = unit/test-vpn-util.c src/log.c vpn/vpn-util.c \
				$(backtrace_sources)
unit_test_vpn_util_LDADD = @GLIB_LIBS@ -ldl

unit_test_service_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
				-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
				-DSTATEDIR=\""$(statedir)"\"
unit_test_service_SOURCES = $(backtrace_sources) $(gdhcp_sources) \
				$(gweb_sources) $(shared_sources) \
				unit/test-service.c \
				src/connman.h src/log.c src/error.c src/task.c \
				src/device.c src/network.c \
				src/manager.c src/agent-connman.c src/clock.c \
				src/timezone.c src/agent.c src/notifier.c \
				src/resolver.c src/ipconfig.c src/detect.c \
				src/inet.c src/dhcp.c src/dhcpv6.c src/rtnl.c \
				src/proxy.c src/utsname.c src/timeserver.c \
				src/rfkill.c src/storage.c src/dbus.c \
				src/config.c src/technology.c src/counter.c \
				src/ntp.c src/wpad.c src/dnsproxy.c \
				src/6to4.c src/ippool.c src/ipaddress.c \
				src/inotify.c src/ipv6pd.c src/peer.c \
				src/peer_service.c src/machine.c src/util.c \
				src/wakeup_timer.c src/access.c
unit_test_service_LDADD = gdbus/libgdbus-internal.la $(builtin_libadd) \
				@GLIB_LIBS@ @DBUS_LIBS@ @GNUTLS_LIBS@ -lresolv \
				-ldl

unit_test_sailfish_iptables_ext_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
				-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
				 @DBUS_CFLAGS@
unit_test_sailfish_iptables_ext_SOURCES = $(backtrace_sources) \
				unit/test-sailfish_iptables_ext.c \
				src/log.c src/storage.c src/inotify.c \
				src/sailfish_iptables_ext.c src/error.c
unit_test_sailfish_iptables_ext_LDADD = gdbus/libgdbus-internal.la \
				@GLIB_LIBS@ @XTABLES_LIBS@ @LIBIPTC_LIBS@ \
				@DBUS_LIBS@ -ldl

unit_test_globalproxy_CFLAGS = -DDEFAULT_STORAGE_ROOT=\""$(storageroot)\"" \
				-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
				$(COVERAGE_OPT) $(AM_CFLAGS) @DBUS_CFLAGS@ @DBUSACCESS_CFLAGS@ \
				-DSTATEDIR=\""$(statedir)"\"
unit_test_globalproxy_SOURCES = unit/test-globalproxy.c \
				$(backtrace_sources) \
				src/connman.h src/log.c src/error.c \
				src/inotify.c src/storage.c src/dbus.c
unit_test_globalproxy_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ -ldl

unit_test_firewall_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) @DBUS_CFLAGS@ \
				@GLIB_CFLAGS@
unit_test_firewall_SOURCES = $(backtrace_sources) src/connman.h src/log.c \
				src/inotify.c src/dbus.c src/error.c \
				src/inet.c src/firewall.c \
				src/iptables-validate.c unit/test-firewall.c
unit_test_firewall_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ -ldl

unit_test_device_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) @GLIB_CFLAGS@
unit_test_device_SOURCES = $(backtrace_sources) src/connman.h src/log.c \
				src/inotify.c plugins/ethernet.c \
				src/device.c unit/test-device.c
unit_test_device_LDADD = @GLIB_LIBS@ -ldl

unit_test_iptables_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) @GLIB_CFLAGS@
unit_test_iptables_SOURCES = $(backtrace_sources) src/connman.h src/log.c \
				unit/test-iptables.c src/iptables.c
unit_test_iptables_LDADD = @GLIB_LIBS@ -ldl

unit_test_sailfish_vpn_access_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
			@DBUSACCESS_CFLAGS@
unit_test_sailfish_vpn_access_SOURCES = unit/test-sailfish_vpn_access.c \
			src/log.c vpn/access.c vpn/plugins/sailfish_access.c \
			$(backtrace_sources)
unit_test_sailfish_vpn_access_LDADD = @GLIB_LIBS@ @DBUSACCESS_LIBS@ -ldl

# Workaround for redefining the DEFAULT_STORAGE_ROOT
unit_test_storage_CFLAGS = -DDEFAULT_TMPDIR=\""$(testconfigdir)"\" \
				-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
				-include unit/test-storage_helper.h \
				$(COVERAGE_OPT) $(AM_CFLAGS) @DBUS_CFLAGS@ \
				@DBUSACCESS_CFLAGS@
unit_test_storage_SOURCES = unit/test-storage.c $(backtrace_sources) \
				src/connman.h src/log.c src/error.c \
				src/inotify.c src/storage.c src/technology.c
unit_test_storage_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ -ldl


unit_test_systemd_login_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS)
unit_test_systemd_login_SOURCES = unit/test-systemd_login.c \
				$(backtrace_sources) src/connman.h src/log.c \
				src/systemd_login.c
unit_test_systemd_login_LDADD = @GLIB_LIBS@ -ldl

TESTS = unit/test-access unit/test-vpn_access unit/test-ippool \
	unit/test-sailfish_access unit/test-vpn-settings \
	unit/test-sailfish_iptables_ext unit/test-service \
	unit/test-globalproxy unit/test-firewall unit/test-iptables \
	unit/test-device unit/test-sailfish_vpn_access unit/test-storage \
	unit/test-systemd_login unit/test-vpn-util

if SAILFISH_WAKEUP_TIMER
unit_test_sailfish_wakeup_timer_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS)
unit_test_sailfish_wakeup_timer_SOURCES = unit/test-sailfish_wakeup_timer.c \
				src/log.c src/wakeup_timer.c \
				plugins/sailfish_wakeup_timer.c \
				$(backtrace_sources)
unit_test_sailfish_wakeup_timer_LDADD = @GLIB_LIBS@ -lrt -ldl
noinst_PROGRAMS += unit/test-sailfish_wakeup_timer
TESTS += unit/test-sailfish_wakeup_timer
endif

if SAILFISH_COUNTERS
unit_test_sailfish_datacounter_CPPFLAGS = -I$(builddir)/src \
	@GLIBUTIL_CFLAGS@ $(AM_CPPFLAGS)
unit_test_sailfish_datacounter_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
	-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
	-DSTATS_SHORT_WRITE_PERIOD_SEC=1 \
	-DSTATS_LONG_WRITE_PERIOD_SEC=3 \
	-Ddatacounters_time_now=test_time_now \
	-Dgutil_time_notify_new=test_time_notify_new \
	-Dgutil_time_notify_ref=test_time_notify_ref \
	-Dgutil_time_notify_unref=test_time_notify_unref \
	-Dgutil_time_notify_add_handler=test_time_notify_add_handler \
	-Dgutil_time_notify_remove_handler=test_time_notify_remove_handler
unit_test_sailfish_datacounter_LDADD = gdbus/libgdbus-internal.la \
	@GLIBUTIL_LIBS@ @GOBJECT_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ -ldl
unit_test_sailfish_datacounter_SOURCES = unit/test-sailfish_datacounter.c \
	unit/test_timenotify.c src/sailfish_datacounter.c \
	src/sailfish_datacounters_util.c src/inotify.c src/storage.c \
	src/wakeup_timer.c src/log.c src/error.c src/dbus.c \
	$(backtrace_sources)
noinst_PROGRAMS += unit/test-sailfish_datacounter
TESTS += unit/test-sailfish_datacounter

unit_test_sailfish_datacounters_CPPFLAGS = -I$(builddir)/src \
	@GLIBUTIL_CFLAGS@ $(AM_CPPFLAGS)
unit_test_sailfish_datacounters_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
	-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
	-Ddatacounters_time_now=test_time_now \
	-Dgutil_time_notify_new=test_time_notify_new \
	-Dgutil_time_notify_ref=test_time_notify_ref \
	-Dgutil_time_notify_unref=test_time_notify_unref \
	-Dgutil_time_notify_add_handler=test_time_notify_add_handler \
	-Dgutil_time_notify_remove_handler=test_time_notify_remove_handler
unit_test_sailfish_datacounters_LDADD = gdbus/libgdbus-internal.la \
	@GLIBUTIL_LIBS@ @GOBJECT_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ -ldl
unit_test_sailfish_datacounters_SOURCES = unit/test-sailfish_datacounters.c \
	unit/test_timenotify.c src/sailfish_datacounters.c \
	src/sailfish_datacounter.c src/sailfish_datacounters_util.c \
	src/inotify.c src/storage.c src/wakeup_timer.c src/log.c src/error.c \
	src/dbus.c $(backtrace_sources)
noinst_PROGRAMS += unit/test-sailfish_datacounters
TESTS += unit/test-sailfish_datacounters

unit_test_sailfish_datahistory_CPPFLAGS = -I$(builddir)/src \
	@GLIBUTIL_CFLAGS@ $(AM_CPPFLAGS)
unit_test_sailfish_datahistory_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
	-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
	-DSTATS_SHORT_WRITE_PERIOD_SEC=1 \
	-DSTATS_LONG_WRITE_PERIOD_SEC=3 \
	-Ddatacounters_time_now=test_time_now \
	-Dgutil_time_notify_new=test_time_notify_new \
	-Dgutil_time_notify_ref=test_time_notify_ref \
	-Dgutil_time_notify_unref=test_time_notify_unref \
	-Dgutil_time_notify_add_handler=test_time_notify_add_handler \
	-Dgutil_time_notify_remove_handler=test_time_notify_remove_handler
unit_test_sailfish_datahistory_LDADD = gdbus/libgdbus-internal.la \
	@GLIBUTIL_LIBS@ @GOBJECT_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ -ldl
unit_test_sailfish_datahistory_SOURCES = unit/test-sailfish_datahistory.c \
	unit/test_timenotify.c src/sailfish_datacounter.c \
	src/sailfish_datacounters_util.c src/sailfish_datahistory.c \
	src/sailfish_datahistory_memory.c src/sailfish_datahistory_file.c \
	src/inotify.c src/storage.c src/wakeup_timer.c src/log.c src/error.c \
	src/dbus.c $(backtrace_sources)
noinst_PROGRAMS += unit/test-sailfish_datahistory
TESTS += unit/test-sailfish_datahistory
endif

if SAILFISH_DEVELOPER_MODE
unit_test_sailfish_developer_mode_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
				@GLIB_CFLAGS@
unit_test_sailfish_developer_mode_SOURCES = $(backtrace_sources) src/connman.h \
				src/log.c plugins/sailfish_developer_mode.c \
				unit/test-sailfish_developer_mode.c
unit_test_sailfish_developer_mode_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ -ldl
noinst_PROGRAMS += unit/test-sailfish_developer_mode
TESTS += unit/test-sailfish_developer_mode
endif

if BLACKLIST_MONITOR
unit_test_blacklist_monitor_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) \
				@GLIB_CFLAGS@
unit_test_blacklist_monitor_SOURCES = $(backtrace_sources) src/connman.h \
				src/log.c plugins/blacklist_monitor.c \
				unit/test-blacklist_monitor.c
unit_test_blacklist_monitor_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ -ldl
noinst_PROGRAMS += unit/test-blacklist_monitor
TESTS += unit/test-blacklist_monitor
endif

if CLAT
unit_test_clat_CFLAGS = $(COVERAGE_OPT) $(AM_CFLAGS) @GLIB_CFLAGS@
unit_test_clat_SOURCES = $(backtrace_sources) src/connman.h \
				src/log.c src/ipaddress.c unit/test-clat.c
unit_test_clat_LDADD = @GLIB_LIBS@ -ldl
noinst_PROGRAMS += unit/test-clat
TESTS += unit/test-clat
endif

if WISPR
noinst_PROGRAMS += tools/wispr

tools_wispr_SOURCES = $(gweb_sources) tools/wispr.c
tools_wispr_LDADD = @GLIB_LIBS@ @GNUTLS_LIBS@ -lresolv
endif

if TOOLS
noinst_PROGRAMS += tools/supplicant-test \
			tools/dhcp-test tools/dhcp-server-test \
			tools/addr-test tools/web-test tools/resolv-test \
			tools/dbus-test tools/polkit-test \
			tools/iptables-test tools/tap-test tools/wpad-test \
			tools/stats-tool tools/private-network-test \
			tools/session-test tools/iptables-unit \
			tools/dnsproxy-test tools/ip6tables-test

tools_supplicant_test_SOURCES = tools/supplicant-test.c \
			tools/supplicant-dbus.h tools/supplicant-dbus.c \
			tools/supplicant.h tools/supplicant.c
tools_supplicant_test_LDADD = gdbus/libgdbus-internal.la \
				@GLIB_LIBS@ @DBUS_LIBS@

tools_web_test_SOURCES = $(gweb_sources) tools/web-test.c
tools_web_test_LDADD = @GLIB_LIBS@ @GNUTLS_LIBS@ -lresolv

tools_resolv_test_SOURCES = gweb/gresolv.h gweb/gresolv.c tools/resolv-test.c
tools_resolv_test_LDADD = @GLIB_LIBS@ -lresolv

tools_wpad_test_SOURCES = gweb/gresolv.h gweb/gresolv.c tools/wpad-test.c
tools_wpad_test_LDADD = @GLIB_LIBS@ -lresolv

tools_stats_tool_LDADD = @GLIB_LIBS@

tools_dhcp_test_SOURCES = $(backtrace_sources) src/log.c src/util.c \
		 $(gdhcp_sources) src/inet.c tools/dhcp-test.c src/shared/arp.c \
		src/wakeup_timer.c
tools_dhcp_test_LDADD = @GLIB_LIBS@ -ldl

tools_dhcp_server_test_SOURCES =  $(backtrace_sources) src/log.c src/util.c \
		$(gdhcp_sources) src/inet.c tools/dhcp-server-test.c src/shared/arp.c \
		src/wakeup_timer.c 
tools_dhcp_server_test_LDADD = @GLIB_LIBS@ -ldl

tools_dbus_test_SOURCES = tools/dbus-test.c
tools_dbus_test_LDADD = gdbus/libgdbus-internal.la @GLIB_LIBS@ @DBUS_LIBS@

tools_polkit_test_LDADD = @DBUS_LIBS@

tools_iptables_test_CFLAGS = @DBUS_CFLAGS@
tools_iptables_test_SOURCES = $(backtrace_sources) src/log.c \
		src/inotify.c src/iptables.c tools/iptables-test.c \
		src/error.c src/dbus.c
tools_iptables_test_LDADD = gdbus/libgdbus-internal.la @GLIB_LIBS@ \
			@XTABLES_LIBS@ @LIBIPTC_LIBS@ @DBUS_LIBS@ -ldl

tools_ip6tables_test_CFLAGS = @DBUS_CFLAGS@
tools_ip6tables_test_SOURCES = $(backtrace_sources) src/log.c \
		src/inotify.c src/iptables.c tools/ip6tables-test.c \
		src/error.c src/dbus.c
tools_ip6tables_test_LDADD = gdbus/libgdbus-internal.la @GLIB_LIBS@ \
		@XTABLES_LIBS@ @LIBIPTC_LIBS@ @DBUS_LIBS@ -ldl

tools_private_network_test_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

tools_session_test_SOURCES = $(backtrace_sources) src/log.c src/dbus.c src/error.c \
		tools/session-test.c tools/session-utils.c tools/manager-api.c \
		tools/session-api.c tools/session-test.h
tools_session_test_LDADD = gdbus/libgdbus-internal.la \
				@GLIB_LIBS@ @DBUS_LIBS@ -ldl

tools_iptables_unit_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@ @XTABLES_CFLAGS@ \
		-DDEFAULT_USER_STORAGE=\""$(userstorage)"\" \
		-DIPTABLES_SAVE=\""${IPTABLES_SAVE}"\" \
		-DIP6TABLES_SAVE=\""${IP6TABLES_SAVE}"\" \
		-DDEFAULT_STORAGE_ROOT=\""$(storageroot)"\" \
		-DCONFIGDIR=\""$(testconfigdir)"\"
tools_iptables_unit_SOURCES = $(backtrace_sources) src/log.c src/storage.c \
		src/inotify.c src/iptables.c src/firewall.c src/nat.c \
		src/inet.c src/iptables-validate.c tools/iptables-unit.c \
		src/error.c src/dbus.c
tools_iptables_unit_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ @XTABLES_LIBS@ @LIBIPTC_LIBS@ -ldl

tools_dnsproxy_test_SOURCES = tools/dnsproxy-test.c
tools_dnsproxy_test_LDADD = @GLIB_LIBS@

endif

test_scripts = test/get-state test/list-services \
		test/monitor-services test/test-clock \
		test/simple-agent test/show-introspection test/test-compat \
		test/test-manager test/test-connman test/monitor-connman \
		test/connect-provider test/remove-provider \
		test/test-counter test/set-ipv4-method test/set-ipv6-method \
		test/get-services test/get-proxy-autoconfig test/set-proxy \
		test/enable-tethering test/disable-tethering test/backtrace \
		test/test-session test/p2p-on-supplicant \
		test/test-new-supplicant test/service-move-before \
		test/set-global-timeservers test/get-global-timeservers \
		test/set-nameservers test/set-domains test/set-timeservers \
		test/set-clock

test_scripts += test/vpn-connect test/vpn-disconnect test/vpn-get \
		test/monitor-vpn test/vpn-property

if TEST
testdir = $(pkglibdir)/test
test_SCRIPTS = $(test_scripts)
endif

EXTRA_DIST += $(test_scripts)

EXTRA_DIST += doc/overview-api.txt doc/behavior-api.txt \
				doc/coding-style.txt doc/wifi-p2p-overview.txt \
				doc/vpn-agent-api.txt doc/peer-api.txt \
				doc/ipconfig-api.txt doc/plugin-api.txt \
				doc/manager-api.txt doc/agent-api.txt \
				doc/service-api.txt doc/technology-api.txt \
				doc/counter-api.txt doc/config-format.txt \
				doc/clock-api.txt doc/session-api.txt \
				doc/session-overview.txt doc/backtrace.txt \
				doc/advanced-configuration.txt \
				doc/vpn-config-format.txt doc/globalproxy-api.txt\
				doc/vpn-connection-api.txt \
				doc/vpn-manager-api.txt doc/vpn-overview.txt \
				doc/session-policy-format.txt \
				doc/connmanctl.1.in doc/connman.conf.5.in \
				doc/connman-service.config.5.in \
				doc/connman-vpn.conf.5.in \
				doc/connman-vpn-provider.config.5.in \
				doc/connman.8.in doc/connman-vpn.8.in \
				doc/firewall-config-format.txt \
				doc/connman-firewall.config.5.in

EXTRA_DIST += src/main.conf \
		src/eduroam.config \
		scripts/connman_resolvconf.conf.in

MANUAL_PAGES += doc/connmanctl.1 doc/connman.conf.5 \
		doc/connman-service.config.5 doc/connman-vpn.conf.5 \
		doc/connman-vpn-provider.config.5 \
		doc/connman.8 doc/connman-vpn.8 \
		doc/connman-firewall.config.5

nodist_man_MANS = $(MANUAL_PAGES)

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = connman.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-datafiles \
				--enable-hh2serial-gps \
				--enable-openconnect \
				--enable-openvpn \
				--enable-vpnc \
				--enable-session-policy-local \
				--enable-nmcompat \
				--enable-polkit

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs test-driver


src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

vpn/builtin.h: src/genbuiltin $(builtin_vpn_sources)
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_vpn_modules) > $@

src/connman.conf: src/connman-dbus.conf src/connman-polkit.conf
if POLKIT
	$(AM_V_GEN)cp $(srcdir)/src/connman-polkit.conf $@
else
	$(AM_V_GEN)cp $(srcdir)/src/connman-dbus.conf $@
endif

if VPN
vpn/connman-vpn-dbus.conf: vpn/vpn-dbus.conf vpn/vpn-polkit.conf
if POLKIT
	$(AM_V_GEN)cp $(srcdir)/vpn/vpn-polkit.conf $@
else
	$(AM_V_GEN)cp $(srcdir)/vpn/vpn-dbus.conf $@
endif
endif

if SELINUX
if VPN
EXTRA_DIST += connman-task.pp
CLEANFILES += connman-task.pp
endif

connman-task.pp: vpn/connman-task.te
	make -f /usr/share/selinux/devel/Makefile
endif

EXTRA_DIST += vpn/connman-task.te

do_subst = $(AM_V_GEN)$(SED) \
		-e 's,[@]prefix[@],$(prefix),g' \
		-e 's,[@]sbindir[@],$(sbindir),g' \
		-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
		-e 's,[@]localstatedir[@],$(localstatedir),g' \
		-e 's,[@]CONNMAN_SERVICE_REQUIRES[@],$(CONNMAN_SERVICE_REQUIRES),g' \
		-e 's,[@]CONNMAN_SERVICE_AFTER[@],$(CONNMAN_SERVICE_AFTER),g' \
		-e 's,[@]runstatedir[@],$(runstatedir),g'

%.1 : %.1.in
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(do_subst) < $< > $@

%.5 : %.5.in
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(do_subst) < $< > $@

%.8 : %.8.in
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(do_subst) < $< > $@

%.service: %.service.in Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(do_subst) < $< > $@

scripts/connman: scripts/connman.in Makefile
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(do_subst) < $< > $@

scripts/connman_resolvconf.conf: scripts/connman_resolvconf.conf.in
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(do_subst) < $< > $@

include/connman/version.h: include/version.h
	$(AM_V_at)$(MKDIR_P) include/connman
	$(AM_V_GEN)$(LN_S) $(abs_top_builddir)/$< $@

include/connman/%.h: $(abs_top_srcdir)/include/%.h
	$(AM_V_at)$(MKDIR_P) include/connman
	$(AM_V_GEN)$(LN_S) $< $@

include/connman/gdbus.h: $(abs_top_srcdir)/gdbus/gdbus.h
	$(AM_V_at)$(MKDIR_P) include/connman
	$(AM_V_GEN)$(LN_S) $< $@

include/connman/vpn/%.h: $(abs_top_srcdir)/vpn/%.h
	$(AM_V_at)$(MKDIR_P) include/connman/vpn
	$(AM_V_GEN)$(LN_S) $< $@

include/connman/vpn/plugins/%.h: $(abs_top_srcdir)/vpn/plugins/%.h
	$(AM_V_at)$(MKDIR_P) include/connman/vpn/plugins
	$(AM_V_GEN)$(LN_S) $< $@

clean-local:
	@$(RM) -rf include/connman $(MANUAL_PAGES)
