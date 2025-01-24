/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2020  Jolla Ltd.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <gdbus.h>
#include <gweb/gweb.h>
#include <gweb/gresolv.h>
#include <gdhcp/gdhcp.h>

#include "connman.h"
#include "iptables_ext.h"

#define CONF_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]) - 1)

#define DEFAULT_INPUT_REQUEST_TIMEOUT (120 * 1000)
#define DEFAULT_BROWSER_LAUNCH_TIMEOUT (300 * 1000)
#define DEFAULT_STOGAGE_ROOT_PERMISSIONS (0755)
#define DEFAULT_STORAGE_DIR_PERMISSIONS (0700)
#define DEFAULT_STORAGE_FILE_PERMISSIONS (0600)
#define DEFAULT_UMASK (0077)
#define DEFAULT_LOCALTIME "/etc/localtime"

/*
 * We set the integer to 1 sec so that we have a chance to get
 * necessary IPv6 router advertisement messages that might have
 * DNS data etc.
 */
#define DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL 1
#define DEFAULT_ONLINE_CHECK_MAX_INTERVAL 12

#define MAINFILE "main.conf"
#define CONFIGMAINFILE CONFIGDIR "/" MAINFILE

static char *default_auto_connect[] = {
	NULL
};

static char *default_favorite_techs[] = {
	"ethernet",
	NULL
};

static char *default_blacklist[] = {
	"vmnet",
	"vboxnet",
	"virbr",
	"ifb",
	"ve-",
	"vb-",
	NULL
};

static struct {
	bool bg_scan;
	char **pref_timeservers;
	unsigned int *auto_connect;
	unsigned int *favorite_techs;
	unsigned int *preferred_techs;
	unsigned int *always_connected_techs;
	char **fallback_nameservers;
	unsigned int timeout_inputreq;
	unsigned int timeout_browserlaunch;
	char **blacklisted_interfaces;
	bool allow_hostname_updates;
	bool allow_domainname_updates;
	bool single_tech;
	char **tethering_technologies;
	bool persistent_tethering_mode;
	char *ipv6_status_url;
	char *ipv4_status_url;
	char *tethering_subnet_block;
	char **dont_bring_down_at_startup;
	char *fs_identity;
	char *storage_root;
	mode_t storage_root_permissions;
	mode_t storage_dir_permissions;
	mode_t storage_file_permissions;
	mode_t umask;
	char *user_storage_dir;
	bool enable_6to4;
	char *vendor_class_id;
	bool enable_online_check;
	bool auto_connect_roaming_services;
	bool acd;
	bool use_gateways_as_timeservers;
	GHashTable *fallback_device_types;
	bool enable_login_manager;
	char *localtime;
	bool regdom_follows_timezone;
	unsigned int online_check_initial_interval;
	unsigned int online_check_max_interval;
} connman_settings  = {
	.bg_scan = true,
	.pref_timeservers = NULL,
	.auto_connect = NULL,
	.favorite_techs = NULL,
	.preferred_techs = NULL,
	.always_connected_techs = NULL,
	.fallback_nameservers = NULL,
	.timeout_inputreq = DEFAULT_INPUT_REQUEST_TIMEOUT,
	.timeout_browserlaunch = DEFAULT_BROWSER_LAUNCH_TIMEOUT,
	.blacklisted_interfaces = NULL,
	.allow_hostname_updates = true,
	.allow_domainname_updates = true,
	.single_tech = false,
	.tethering_technologies = NULL,
	.persistent_tethering_mode = false,
	.storage_root_permissions = DEFAULT_STOGAGE_ROOT_PERMISSIONS,
	.storage_dir_permissions = DEFAULT_STORAGE_DIR_PERMISSIONS,
	.storage_file_permissions = DEFAULT_STORAGE_FILE_PERMISSIONS,
	.umask = DEFAULT_UMASK,
	.enable_6to4 = false,
	.vendor_class_id = NULL,
	.enable_online_check = true,
	.auto_connect_roaming_services = false,
	.acd = false,
	.use_gateways_as_timeservers = false,
	.fallback_device_types = NULL,
	.enable_login_manager = false,
	.localtime = NULL,
	.regdom_follows_timezone = false,
	.online_check_initial_interval = DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL,
	.online_check_max_interval = DEFAULT_ONLINE_CHECK_MAX_INTERVAL,
};

#define CONF_BG_SCAN                    "BackgroundScanning"
#define CONF_PREF_TIMESERVERS           "FallbackTimeservers"
#define CONF_AUTO_CONNECT_TECHS         "DefaultAutoConnectTechnologies"
#define CONF_FAVORITE_TECHS             "DefaultFavoriteTechnologies"
#define CONF_ALWAYS_CONNECTED_TECHS     "AlwaysConnectedTechnologies"
#define CONF_PREFERRED_TECHS            "PreferredTechnologies"
#define CONF_FALLBACK_NAMESERVERS       "FallbackNameservers"
#define CONF_TIMEOUT_INPUTREQ           "InputRequestTimeout"
#define CONF_TIMEOUT_BROWSERLAUNCH      "BrowserLaunchTimeout"
#define CONF_BLACKLISTED_INTERFACES     "NetworkInterfaceBlacklist"
#define CONF_ALLOW_HOSTNAME_UPDATES     "AllowHostnameUpdates"
#define CONF_ALLOW_DOMAINNAME_UPDATES   "AllowDomainnameUpdates"
#define CONF_SINGLE_TECH                "SingleConnectedTechnology"
#define CONF_TETHERING_TECHNOLOGIES      "TetheringTechnologies"
#define CONF_PERSISTENT_TETHERING_MODE  "PersistentTetheringMode"
#define CONF_DONT_BRING_DOWN_AT_STARTUP "DontBringDownAtStartup"
#define CONF_DISABLE_PLUGINS            "DisablePlugins"
#define CONF_FILE_SYSTEM_IDENTITY       "FileSystemIdentity"
#define CONF_STORAGE_ROOT               "StorageRoot"
#define CONF_STORAGE_ROOT_PERMISSIONS   "StorageRootPermissions"
#define CONF_STORAGE_DIR_PERMISSIONS    "StorageDirPermissions"
#define CONF_STORAGE_FILE_PERMISSIONS   "StorageFilePermissions"
#define CONF_USER_STORAGE_DIR           "UserStorage"
#define CONF_UMASK                      "Umask"
#define CONF_ENABLE_6TO4                "Enable6to4"
#define CONF_VENDOR_CLASS_ID            "VendorClassID"
#define CONF_ENABLE_ONLINE_CHECK        "EnableOnlineCheck"
#define CONF_AUTO_CONNECT_ROAMING_SERVICES "AutoConnectRoamingServices"
#define CONF_ACD                        "AddressConflictDetection"
#define CONF_USE_GATEWAYS_AS_TIMESERVERS "UseGatewaysAsTimeservers"
#define CONF_FALLBACK_DEVICE_TYPES      "FallbackDeviceTypes"
#define CONF_ENABLE_LOGIN_MANAGER       "EnableLoginManager"
#define CONF_LOCALTIME                  "Localtime"
#define CONF_REGDOM_FOLLOWS_TIMEZONE    "RegdomFollowsTimezone"

#define CONF_ONLINE_CHECK_INITIAL_INTERVAL "OnlineCheckInitialInterval"
#define CONF_ONLINE_CHECK_MAX_INTERVAL     "OnlineCheckMaxInterval"

static const char *supported_options[] = {
	CONF_BG_SCAN,
	CONF_PREF_TIMESERVERS,
	CONF_AUTO_CONNECT_TECHS,
	CONF_ALWAYS_CONNECTED_TECHS,
	CONF_PREFERRED_TECHS,
	CONF_FALLBACK_NAMESERVERS,
	CONF_TIMEOUT_INPUTREQ,
	CONF_TIMEOUT_BROWSERLAUNCH,
	CONF_BLACKLISTED_INTERFACES,
	CONF_ALLOW_HOSTNAME_UPDATES,
	CONF_ALLOW_DOMAINNAME_UPDATES,
	CONF_SINGLE_TECH,
	CONF_TETHERING_TECHNOLOGIES,
	CONF_PERSISTENT_TETHERING_MODE,
	CONF_FILE_SYSTEM_IDENTITY,
	CONF_STORAGE_ROOT,
	CONF_STORAGE_ROOT_PERMISSIONS,
	CONF_STORAGE_DIR_PERMISSIONS,
	CONF_STORAGE_FILE_PERMISSIONS,
	CONF_USER_STORAGE_DIR,
	CONF_UMASK,
	CONF_STATUS_URL_IPV4,
	CONF_STATUS_URL_IPV6,
	CONF_TETHERING_SUBNET_BLOCK,
	CONF_DONT_BRING_DOWN_AT_STARTUP,
	CONF_DISABLE_PLUGINS,
	CONF_ENABLE_6TO4,
	CONF_VENDOR_CLASS_ID,
	CONF_ENABLE_ONLINE_CHECK,
	CONF_AUTO_CONNECT_ROAMING_SERVICES,
	CONF_ACD,
	CONF_USE_GATEWAYS_AS_TIMESERVERS,
	CONF_FALLBACK_DEVICE_TYPES,
	CONF_ENABLE_LOGIN_MANAGER,
	CONF_LOCALTIME,
	CONF_REGDOM_FOLLOWS_TIMEZONE,
	CONF_ONLINE_CHECK_INITIAL_INTERVAL,
	CONF_ONLINE_CHECK_MAX_INTERVAL,
	NULL
};

/* Default values */
#define CONF_STATUS_URL_IPV4_DEF "http://ipv4.connman.net/online/status.html"
#define CONF_STATUS_URL_IPV6_DEF "http://ipv6.connman.net/online/status.html"
#define CONF_TETHERING_SUBNET_BLOCK_DEF "192.168.0.0"

static void append_noplugin(const char *value);

static GKeyFile *load_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (err->code != G_FILE_ERROR_NOENT) {
			connman_error("Parsing %s failed: %s", file,
								err->message);
		}

		g_error_free(err);
		g_key_file_unref(keyfile);
		return NULL;
	}

	return keyfile;
}

static uint *parse_service_types(char **str_list, gsize len)
{
	unsigned int *type_list;
	int i, j;
	enum connman_service_type type;

	type_list = g_try_new0(unsigned int, len + 1);
	if (!type_list)
		return NULL;

	i = 0;
	j = 0;
	while (str_list[i]) {
		type = __connman_service_string2type(str_list[i]);

		if (type != CONNMAN_SERVICE_TYPE_UNKNOWN) {
			type_list[j] = type;
			j += 1;
		}
		i += 1;
	}

	type_list[j] = CONNMAN_SERVICE_TYPE_UNKNOWN;

	return type_list;
}

static char **parse_fallback_nameservers(char **nameservers, gsize len)
{
	char **servers;
	int i, j;

	servers = g_try_new0(char *, len + 1);
	if (!servers)
		return NULL;

	i = 0;
	j = 0;
	while (nameservers[i]) {
		if (connman_inet_check_ipaddress(nameservers[i]) > 0) {
			servers[j] = g_strdup(nameservers[i]);
			j += 1;
		}
		i += 1;
	}

	return servers;
}

static GHashTable *parse_fallback_device_types(char **devtypes, gsize len)
{
	GHashTable *h;
	gsize i;

	h = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	for (i = 0; i < len; ++i) {
		char **v;

		v = g_strsplit(devtypes[i], ":", 2);
		if (!v)
			continue;

		if (v[0] && v[1])
			g_hash_table_replace(h, g_strdup(v[0]),
					g_strdup(v[1]));

		g_strfreev(v);
	}

	if (g_hash_table_size(h) > 0)
		return h;

	g_hash_table_unref(h);
	return NULL;
}

static void check_config(GKeyFile *config)
{
	char **keys;
	int j;

	if (!config)
		return;

	keys = g_key_file_get_groups(config, NULL);

	for (j = 0; keys && keys[j]; j++) {
		if (g_strcmp0(keys[j], "General") != 0)
			connman_warn("Unknown group %s in %s",
						keys[j], MAINFILE);
	}

	g_strfreev(keys);

	keys = g_key_file_get_keys(config, "General", NULL, NULL);

	for (j = 0; keys && keys[j]; j++) {
		bool found;
		int i;

		found = false;
		for (i = 0; supported_options[i]; i++) {
			if (g_strcmp0(keys[j], supported_options[i]) == 0) {
				found = true;
				break;
			}
		}
		if (!found && !supported_options[i])
			connman_warn("Unknown option %s in %s",
						keys[j], MAINFILE);
	}

	g_strfreev(keys);
}

static gboolean parse_perm(GKeyFile *config, const char *group,
					const char *key, mode_t *perm)
{
	gboolean ok = FALSE;
	char *str = g_key_file_get_string(config, group, key, NULL);
	if (str) {
		/*
		 * Some people are thinking that # is a comment
		 * anywhere on the line, not just at the beginning
		 */
		unsigned long val;
		char *comment = strchr(str, '#');
		if (comment) *comment = 0;
		val = strtoul(g_strstrip(str), NULL, 0);
		if (val > 0 && !(val & ~0777UL)) {
			*perm = (mode_t)val;
			ok = TRUE;
		}
		g_free(str);
	}
	return ok;
}

static void parse_config(GKeyFile *config)
{
	GError *error = NULL;
	bool boolean;
	char **timeservers;
	char **interfaces;
	char **str_list;
	char **tethering;
	char *str;
	const char *group = "General";
	struct in_addr ip;
        char *vendor_class_id;
	gsize len;
	int integer;

	if (!config) {
		connman_settings.auto_connect =
			parse_service_types(default_auto_connect, CONF_ARRAY_SIZE(default_auto_connect));
		connman_settings.favorite_techs =
			parse_service_types(default_favorite_techs, CONF_ARRAY_SIZE(default_favorite_techs));
		connman_settings.blacklisted_interfaces =
			g_strdupv(default_blacklist);
		return;
	}

	DBG("parsing %s", MAINFILE);

	boolean = g_key_file_get_boolean(config, "General",
						CONF_BG_SCAN, &error);
	if (!error)
		connman_settings.bg_scan = boolean;

	g_clear_error(&error);

	timeservers = __connman_config_get_string_list(config, "General",
					CONF_PREF_TIMESERVERS, NULL, &error);
	if (!error)
		connman_settings.pref_timeservers = timeservers;

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_AUTO_CONNECT_TECHS, &len, &error);

	if (!error)
		connman_settings.auto_connect =
			parse_service_types(str_list, len);
	else
		connman_settings.auto_connect =
			parse_service_types(default_auto_connect, CONF_ARRAY_SIZE(default_auto_connect));

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_FAVORITE_TECHS, &len, &error);

	if (!error)
		connman_settings.favorite_techs =
			parse_service_types(str_list, len);
	else
		connman_settings.favorite_techs =
			parse_service_types(default_favorite_techs, CONF_ARRAY_SIZE(default_favorite_techs));

	g_strfreev(str_list);

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_PREFERRED_TECHS, &len, &error);

	if (!error)
		connman_settings.preferred_techs =
			parse_service_types(str_list, len);

	g_strfreev(str_list);

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_ALWAYS_CONNECTED_TECHS, &len, &error);

	if (!error)
		connman_settings.always_connected_techs =
			parse_service_types(str_list, len);

	g_strfreev(str_list);

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_FALLBACK_NAMESERVERS, &len, &error);

	if (!error)
		connman_settings.fallback_nameservers =
			parse_fallback_nameservers(str_list, len);

	g_strfreev(str_list);

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "General",
			CONF_TIMEOUT_INPUTREQ, &error);
	if (!error && integer >= 0)
		connman_settings.timeout_inputreq = integer * 1000;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "General",
			CONF_TIMEOUT_BROWSERLAUNCH, &error);
	if (!error && integer >= 0)
		connman_settings.timeout_browserlaunch = integer * 1000;

	g_clear_error(&error);

	interfaces = __connman_config_get_string_list(config, "General",
			CONF_BLACKLISTED_INTERFACES, &len, &error);

	if (!error)
		connman_settings.blacklisted_interfaces = interfaces;
	else
		connman_settings.blacklisted_interfaces =
			g_strdupv(default_blacklist);

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
					CONF_ALLOW_HOSTNAME_UPDATES,
					&error);
	if (!error)
		connman_settings.allow_hostname_updates = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
					CONF_ALLOW_DOMAINNAME_UPDATES,
					&error);
	if (!error)
		connman_settings.allow_domainname_updates = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
			CONF_SINGLE_TECH, &error);
	if (!error)
		connman_settings.single_tech = boolean;

	g_clear_error(&error);

	tethering = __connman_config_get_string_list(config, "General",
			CONF_TETHERING_TECHNOLOGIES, &len, &error);

	if (!error)
		connman_settings.tethering_technologies = tethering;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
					CONF_PERSISTENT_TETHERING_MODE,
					&error);
	if (!error)
		connman_settings.persistent_tethering_mode = boolean;

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, group,
					CONF_DISABLE_PLUGINS, &len, NULL);
	if (str_list) {
		int i;

		for (i = 0; str_list[i]; i++)
			append_noplugin(str_list[i]);

		g_strfreev(str_list);
	}

	connman_settings.dont_bring_down_at_startup =
		__connman_config_get_string_list(config, group,
			CONF_DONT_BRING_DOWN_AT_STARTUP, &len, NULL);

	connman_settings.storage_root = __connman_config_get_string(config,
				group, CONF_STORAGE_ROOT, &error);
	if (error)
		connman_settings.storage_root = g_strdup(DEFAULT_STORAGE_ROOT);

	g_clear_error(&error);

	connman_settings.user_storage_dir = __connman_config_get_string(config,
				group, CONF_USER_STORAGE_DIR, &error);
	if (error)
		connman_settings.user_storage_dir =
						g_strdup(DEFAULT_USER_STORAGE);

	g_clear_error(&error);

	connman_settings.fs_identity = __connman_config_get_string(config,
				group, CONF_FILE_SYSTEM_IDENTITY, NULL);

	parse_perm(config, group, CONF_STORAGE_ROOT_PERMISSIONS,
				&connman_settings.storage_root_permissions);

	parse_perm(config, group, CONF_STORAGE_DIR_PERMISSIONS,
				&connman_settings.storage_dir_permissions);

	parse_perm(config, group, CONF_STORAGE_FILE_PERMISSIONS,
				&connman_settings.storage_file_permissions);

	parse_perm(config, group, CONF_UMASK, &connman_settings.umask);

	connman_settings.ipv4_status_url = __connman_config_get_string(config,
					group, CONF_STATUS_URL_IPV4, NULL);

	connman_settings.ipv6_status_url = __connman_config_get_string(config,
					group, CONF_STATUS_URL_IPV6, NULL);

	str = __connman_config_get_string(config, group,
					CONF_TETHERING_SUBNET_BLOCK, NULL);
	if (str && inet_pton(AF_INET, str, &ip) == 1 &&
					(ntohl(ip.s_addr) & 0xff) == 0) {
		connman_settings.tethering_subnet_block = str;
	} else {
		g_free(str);
	}

	boolean = __connman_config_get_bool(config, "General",
					CONF_ENABLE_6TO4, &error);
	if (!error)
		connman_settings.enable_6to4 = boolean;

	g_clear_error(&error);

	vendor_class_id = __connman_config_get_string(config, "General",
					CONF_VENDOR_CLASS_ID, &error);
	if (!error)
		connman_settings.vendor_class_id = vendor_class_id;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
					CONF_ENABLE_ONLINE_CHECK, &error);
	if (!error) {
		connman_settings.enable_online_check = boolean;
		if (!boolean)
			connman_info("Online check disabled by main config.");
	}

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
				CONF_AUTO_CONNECT_ROAMING_SERVICES, &error);
	if (!error)
		connman_settings.auto_connect_roaming_services = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General", CONF_ACD, &error);
	if (!error)
		connman_settings.acd = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
				CONF_USE_GATEWAYS_AS_TIMESERVERS, &error);
	if (!error)
		connman_settings.use_gateways_as_timeservers = boolean;

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_FALLBACK_DEVICE_TYPES, &len, &error);

	if (!error)
		connman_settings.fallback_device_types =
				parse_fallback_device_types(str_list, len);

	g_strfreev(str_list);

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, group,
				CONF_ENABLE_LOGIN_MANAGER, &error);
	if (!error)
		connman_settings.enable_login_manager = boolean;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "General",
			CONF_ONLINE_CHECK_INITIAL_INTERVAL, &error);
	if (!error && integer >= 0)
		connman_settings.online_check_initial_interval = integer;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "General",
			CONF_ONLINE_CHECK_MAX_INTERVAL, &error);
	if (!error && integer >= 0)
		connman_settings.online_check_max_interval = integer;

	g_clear_error(&error);

	if (connman_settings.online_check_initial_interval < 1 ||
		connman_settings.online_check_initial_interval >
		connman_settings.online_check_max_interval) {
		connman_warn("Incorrect online check intervals [%u, %u]",
				connman_settings.online_check_initial_interval,
				connman_settings.online_check_max_interval);
		connman_settings.online_check_initial_interval =
			DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL;
		connman_settings.online_check_max_interval =
			DEFAULT_ONLINE_CHECK_MAX_INTERVAL;
	}

	str = __connman_config_get_string(config, group, CONF_LOCALTIME,
				&error);
	if (!error)
		connman_settings.localtime = str;
	else
		g_free(str);

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, group,
				CONF_REGDOM_FOLLOWS_TIMEZONE, &error);
	if (!error)
		connman_settings.regdom_follows_timezone = boolean;

	g_clear_error(&error);
}

static int config_init(const char *file)
{
	GKeyFile *config;

	config = load_config(file);
	check_config(config);
	parse_config(config);
	if (config)
		g_key_file_unref(config);

	return 0;
}

static GMainLoop *main_loop = NULL;

static unsigned int __terminated = 0;

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (__terminated == 0) {
			DBG("Terminating");
			g_main_loop_quit(main_loop);
		}

		__terminated = 1;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	connman_error("D-Bus disconnect");

	g_main_loop_quit(main_loop);
}

static gchar *option_config = NULL;
static gchar *option_debug = NULL;
static gchar *option_device = NULL;
static gchar *option_plugin = NULL;
static gchar *option_nodevice = NULL;
static gchar *option_noplugin = NULL;
static gchar *option_wifi = NULL;
static gboolean option_detach = TRUE;
static gboolean option_dnsproxy = TRUE;
static gboolean option_backtrace = TRUE;
static gboolean option_version = FALSE;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value) {
		if (option_debug) {
			char *prev = option_debug;

			option_debug = g_strconcat(prev, ",", value, NULL);
			g_free(prev);
		} else {
			option_debug = g_strdup(value);
		}
	} else {
		g_free(option_debug);
		option_debug = g_strdup("*");
	}

	return true;
}

static void append_noplugin(const char *value)
{
	if (option_noplugin) {
		char *prev = option_noplugin;

		option_noplugin = g_strconcat(prev, ",", value, NULL);
		g_free(prev);
	} else {
		option_noplugin = g_strdup(value);
	}
}

static bool parse_noplugin(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	append_noplugin(value);
	return true;
}

static GOptionEntry options[] = {
	{ "config", 'c', 0, G_OPTION_ARG_STRING, &option_config,
				"Load the specified configuration file "
				"instead of " CONFIGMAINFILE, "FILE" },
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ "device", 'i', 0, G_OPTION_ARG_STRING, &option_device,
			"Specify networking devices or interfaces", "DEV,..." },
	{ "nodevice", 'I', 0, G_OPTION_ARG_STRING, &option_nodevice,
			"Specify networking interfaces to ignore", "DEV,..." },
	{ "plugin", 'p', 0, G_OPTION_ARG_STRING, &option_plugin,
				"Specify plugins to load", "NAME,..." },
	{ "noplugin", 'P', 0, G_OPTION_ARG_CALLBACK, &parse_noplugin,
				"Specify plugins not to load", "NAME,..." },
	{ "wifi", 'W', 0, G_OPTION_ARG_STRING, &option_wifi,
				"Specify driver for WiFi/Supplicant", "NAME" },
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't fork daemon to background" },
	{ "nodnsproxy", 'r', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_dnsproxy,
				"Don't support DNS resolving" },
	{ "nobacktrace", 0, G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_backtrace,
				"Don't print out backtrace information" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

const char *connman_setting_get_string(const char *key)
{
	if (g_str_equal(key, CONF_VENDOR_CLASS_ID))
		return connman_settings.vendor_class_id;

	if (g_strcmp0(key, "wifi") == 0) {
		if (!option_wifi)
			return "nl80211,wext";
		else
			return option_wifi;
	}

	if (g_str_equal(key, CONF_STATUS_URL_IPV4))
		return connman_settings.ipv4_status_url ?
			connman_settings.ipv4_status_url :
			CONF_STATUS_URL_IPV4_DEF;

	if (g_str_equal(key, CONF_STATUS_URL_IPV6))
		return connman_settings.ipv6_status_url ?
			connman_settings.ipv6_status_url :
			CONF_STATUS_URL_IPV6_DEF;

	if (g_str_equal(key, CONF_TETHERING_SUBNET_BLOCK))
		return connman_settings.tethering_subnet_block ?
			connman_settings.tethering_subnet_block :
			CONF_TETHERING_SUBNET_BLOCK_DEF;

	if (g_str_equal(key, CONF_LOCALTIME))
		return connman_settings.localtime ?
				connman_settings.localtime : DEFAULT_LOCALTIME;

	return NULL;
}

bool connman_setting_get_bool(const char *key)
{
	if (g_str_equal(key, CONF_BG_SCAN))
		return connman_settings.bg_scan;

	if (g_str_equal(key, CONF_ALLOW_HOSTNAME_UPDATES))
		return connman_settings.allow_hostname_updates;

	if (g_str_equal(key, CONF_ALLOW_DOMAINNAME_UPDATES))
		return connman_settings.allow_domainname_updates;

	if (g_str_equal(key, CONF_SINGLE_TECH))
		return connman_settings.single_tech;

	if (g_str_equal(key, CONF_PERSISTENT_TETHERING_MODE))
		return connman_settings.persistent_tethering_mode;

	if (g_str_equal(key, CONF_ENABLE_6TO4))
		return connman_settings.enable_6to4;

	if (g_str_equal(key, CONF_ENABLE_ONLINE_CHECK))
		return connman_settings.enable_online_check;

	if (g_str_equal(key, CONF_AUTO_CONNECT_ROAMING_SERVICES))
		return connman_settings.auto_connect_roaming_services;

	if (g_str_equal(key, CONF_ACD))
		return connman_settings.acd;

	if (g_str_equal(key, CONF_USE_GATEWAYS_AS_TIMESERVERS))
		return connman_settings.use_gateways_as_timeservers;

	if (g_str_equal(key, CONF_ENABLE_LOGIN_MANAGER))
		return connman_settings.enable_login_manager;

	if (g_str_equal(key, CONF_REGDOM_FOLLOWS_TIMEZONE))
		return connman_settings.regdom_follows_timezone;

	return false;
}

unsigned int connman_setting_get_uint(const char *key)
{
	if (g_str_equal(key, CONF_ONLINE_CHECK_INITIAL_INTERVAL))
		return connman_settings.online_check_initial_interval;

	if (g_str_equal(key, CONF_ONLINE_CHECK_MAX_INTERVAL))
		return connman_settings.online_check_max_interval;

	return 0;
}

char **connman_setting_get_string_list(const char *key)
{
	if (g_str_equal(key, CONF_PREF_TIMESERVERS))
		return connman_settings.pref_timeservers;

	if (g_str_equal(key, CONF_FALLBACK_NAMESERVERS))
		return connman_settings.fallback_nameservers;

	if (g_str_equal(key, CONF_BLACKLISTED_INTERFACES))
		return connman_settings.blacklisted_interfaces;

	if (g_str_equal(key, CONF_TETHERING_TECHNOLOGIES))
		return connman_settings.tethering_technologies;

	if (g_str_equal(key, CONF_DONT_BRING_DOWN_AT_STARTUP))
		return connman_settings.dont_bring_down_at_startup;

	return NULL;
}

unsigned int *connman_setting_get_uint_list(const char *key)
{
	if (g_str_equal(key, CONF_AUTO_CONNECT_TECHS))
		return connman_settings.auto_connect;

	if (g_str_equal(key, CONF_FAVORITE_TECHS))
		return connman_settings.favorite_techs;

	if (g_str_equal(key, CONF_PREFERRED_TECHS))
		return connman_settings.preferred_techs;

	if (g_str_equal(key, CONF_ALWAYS_CONNECTED_TECHS))
		return connman_settings.always_connected_techs;

	return NULL;
}

unsigned int connman_timeout_input_request(void)
{
	return connman_settings.timeout_inputreq;
}

unsigned int connman_timeout_browser_launch(void)
{
	return connman_settings.timeout_browserlaunch;
}

const char *__connman_setting_get_fallback_device_type(const char *interface)
{
	if (!connman_settings.fallback_device_types)
		return NULL;

	return g_hash_table_lookup(connman_settings.fallback_device_types,
			interface);
}

static struct connman_storage_callbacks storage_callbacks = {
	.pre =			__connman_technology_disable_all,
	.unload =		__connman_service_unload_services,
	.load =			__connman_service_load_services,
	.post =			__connman_technology_enable_from_config,
	.uid_changed =		__connman_notifier_storage_uid_changed,
	.access_policy_create =	__connman_access_storage_policy_create,
	.access_change_user = 	__connman_access_storage_change_user,
	.access_policy_free = 	__connman_access_storage_policy_free,
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	guint signal;
	int fs_err;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (option_detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	gweb_log_hook = connman_log;
	gresolv_log_hook = connman_log;
	gdhcp_client_log_hook = connman_log;
	gdhcp_server_log_hook = connman_log;

	main_loop = g_main_loop_new(NULL, FALSE);

	signal = setup_signalfd();

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, CONNMAN_SERVICE, &err);
	if (!conn) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	g_dbus_set_disconnect_function(conn, disconnect_callback, NULL, NULL);

	__connman_log_init(argv[0], option_debug, option_detach,
			option_backtrace, "Connection Manager", VERSION);

	__connman_dbus_init(conn);

	if (!option_config)
		config_init(CONFIGMAINFILE);
	else
		config_init(option_config);

	if (connman_settings.fs_identity)
		__connman_set_fsid(connman_settings.fs_identity);

	__connman_inotify_init();
	__connman_storage_init(connman_settings.storage_root,
				connman_settings.user_storage_dir,
				connman_settings.storage_dir_permissions,
				connman_settings.storage_file_permissions);

	fs_err = __connman_storage_create_dir(connman_settings.storage_root,
				connman_settings.storage_root_permissions);
	if (fs_err)
		connman_error("failed to create storage root %s: %s "
					"settings cannot be saved.",
					connman_settings.storage_root,
					strerror(-fs_err));

	fs_err = __connman_storage_create_dir(STORAGEDIR,
				connman_settings.storage_dir_permissions);
	if (fs_err) {
		connman_error("failed to create storage directory %s: %s "
					"settings cannot be saved",
					STORAGEDIR, strerror(-fs_err));
	} else {
		if (__connman_storage_register_dbus(STORAGE_DIR_TYPE_MAIN,
					&storage_callbacks))
			connman_error("failed to register storage D-Bus");
	}

	umask(connman_settings.umask);

	__connman_login_manager_init();
	__connman_util_init();
	__connman_technology_init();
	__connman_notifier_init();
	__connman_agent_init();
	__connman_service_init();
	__connman_peer_service_init();
	__connman_peer_init();
	__connman_provider_init();
	__connman_network_init();
	__connman_config_init();
	__connman_device_init(option_device, option_nodevice);

	__connman_ippool_init();
	__connman_iptables_validate_init();
	__connman_firewall_init();
	__connman_nat_init();
	__connman_tethering_init();
	__connman_counter_init();
	__connman_manager_init();
	__connman_stats_init();
	__connman_clock_init();

	__connman_ipconfig_init();
	__connman_rtnl_init();
	__connman_task_init();
	__connman_proxy_init();
	__connman_detect_init();
	__connman_session_init();
	__connman_timeserver_init();
	__connman_connection_init();

	__connman_plugin_init(option_plugin, option_noplugin);

	__connman_resolver_init(option_dnsproxy);
	__connman_rtnl_start();
	__connman_dhcp_init();
	__connman_dhcpv6_init();
	__connman_wpad_init();
	__connman_wispr_init();
	__connman_rfkill_init();
	__connman_machine_init();

	g_free(option_config);
	g_free(option_device);
	g_free(option_plugin);
	g_free(option_nodevice);
	g_free(option_noplugin);

	g_main_loop_run(main_loop);

	g_source_remove(signal);

	__connman_machine_cleanup();
	__connman_rfkill_cleanup();
	__connman_wispr_cleanup();
	__connman_wpad_cleanup();
	__connman_dhcpv6_cleanup();
	__connman_session_cleanup();
	__connman_plugin_cleanup();
	__connman_provider_cleanup();
	__connman_connection_cleanup();
	__connman_timeserver_cleanup();
	__connman_detect_cleanup();
	__connman_proxy_cleanup();
	__connman_task_cleanup();
	__connman_rtnl_cleanup();
	__connman_resolver_cleanup();

	__connman_firewall_pre_cleanup();
	__connman_iptables_save_all();
	
	__connman_clock_cleanup();
	__connman_stats_cleanup();
	__connman_config_cleanup();
	__connman_manager_cleanup();
	__connman_counter_cleanup();
	__connman_tethering_cleanup();
	__connman_nat_cleanup();
	__connman_firewall_cleanup();
	__connman_iptables_validate_cleanup();
	__connman_peer_service_cleanup();
	__connman_peer_cleanup();
	__connman_ippool_cleanup();
	__connman_device_cleanup();
	__connman_network_cleanup();
	__connman_dhcp_cleanup();
	__connman_service_cleanup();
	__connman_agent_cleanup();
	__connman_ipconfig_cleanup();
	__connman_notifier_cleanup();
	__connman_technology_cleanup();
	__connman_login_manager_cleanup();
	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	__connman_util_cleanup();
	__connman_dbus_cleanup();

	__connman_log_cleanup(option_backtrace);

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	if (connman_settings.pref_timeservers)
		g_strfreev(connman_settings.pref_timeservers);

	g_free(connman_settings.auto_connect);
	g_free(connman_settings.favorite_techs);
	g_free(connman_settings.preferred_techs);
	g_strfreev(connman_settings.fallback_nameservers);
	g_strfreev(connman_settings.blacklisted_interfaces);
	g_strfreev(connman_settings.tethering_technologies);
	g_strfreev(connman_settings.dont_bring_down_at_startup);
	g_free(connman_settings.ipv6_status_url);
	g_free(connman_settings.ipv4_status_url);
	g_free(connman_settings.tethering_subnet_block);
	g_free(connman_settings.storage_root);
	g_free(connman_settings.fs_identity);
	g_free(connman_settings.user_storage_dir);
	g_free(connman_settings.localtime);

	if (connman_settings.fallback_device_types)
		g_hash_table_unref(connman_settings.fallback_device_types);

	g_free(option_debug);
	g_free(option_wifi);

	return 0;
}
