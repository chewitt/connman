/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2014  Intel Corporation. All rights reserved.
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
#include <string.h>
#include <netdb.h>
#include <gdbus.h>
#include <ctype.h>
#include <stdint.h>

#include <connman/storage.h>
#include <connman/setting.h>
#include <connman/agent.h>

#include "src/shared/util.h"

#include "connman.h"

#define CONNECT_TIMEOUT		120

#define VPN_AUTOCONNECT_TIMEOUT_DEFAULT 1
#define VPN_AUTOCONNECT_TIMEOUT_STEP 30
#define VPN_AUTOCONNECT_TIMEOUT_ATTEMPTS_THRESHOLD 270

/*
 * There are many call sites throughout this module for these
 * functions. These are macros to help, during debugging, to acertain
 * where they were called from.
 */

#define DEFAULT_CHANGED() \
	default_changed(__func__)

#define SERVICE_LIST_SORT() \
	service_list_sort(__func__)

typedef guint (*online_check_timeout_compute_t)(unsigned int interval);
typedef bool (*is_counter_threshold_met_predicate_t)(
	const struct connman_service *service,
	const char *counter_description,
	unsigned int counter_threshold);

static DBusConnection *connection = NULL;

static GList *service_list = NULL;
static GHashTable *service_hash = NULL;
static GHashTable *passphrase_requested = NULL;
static GSList *counter_list = NULL;
static unsigned int autoconnect_id = 0;
static unsigned int vpn_autoconnect_id = 0;
/**
 *  A weak reference to the current default service (that is, has the
 *  default route) used to compare against another service when the
 *  default service has potentially changed.
 *
 *  @sa connman_service_get_default
 *  @sa connman_service_is_default
 *  @sa default_changed
 *
 */
static struct connman_service *current_default = NULL;
static bool services_dirty = false;
static unsigned int online_check_connect_timeout_ms = 0;
static unsigned int online_check_initial_interval = 0;
static unsigned int online_check_max_interval = 0;
static const char *online_check_timeout_interval_style = NULL;
static online_check_timeout_compute_t online_check_timeout_compute_func = NULL;

struct connman_stats {
	bool valid;
	bool enabled;
	struct connman_stats_data data_last;
	struct connman_stats_data data;
	GTimer *timer;
};

struct connman_stats_counter {
	bool append_all;
	struct connman_stats stats;
	struct connman_stats stats_roaming;
};

/**
 *  IP configuration type-specific "online" HTTP-based Internet
 *  reachability check state.
 *
 */
struct online_check_state {
	/**
	 *  Indicates whether an online check is active and in-flight.
	 */
	bool active;

	/**
	 *  The current GLib main loop timer identifier.
	 *
	 */
	guint timeout;

	/**
	 *  The current "online" reachability check sequence interval.
	 *
	 */
	unsigned int interval;

	/**
	 *	The number of sustained, back-to-back "online" reachability
	 *	check successes for "continuous" online check mode.
	 */
	unsigned int successes;

	/**
	 *	The number of sustained, back-to-back "online" reachability
	 *	check failures for "continuous" online check mode.
	 */
	unsigned int failures;
};

struct connman_service {
	int refcount;
	char *identifier;
	char *path;
	enum connman_service_type type;
	enum connman_service_security security;
	enum connman_service_state state;
	enum connman_service_state state_ipv4;
	enum connman_service_state state_ipv6;
	enum connman_service_error error;
	enum connman_service_connect_reason connect_reason;
	uint8_t strength;
	bool favorite;
	bool immutable;
	bool hidden;
	bool ignore;
	bool autoconnect;
	struct timeval modified;
	unsigned int order;
	char *name;
	char *passphrase;
	bool roaming;
	struct connman_ipconfig *ipconfig_ipv4;
	struct connman_ipconfig *ipconfig_ipv6;
	struct connman_network *network;
	struct connman_provider *provider;
	char **nameservers;
	char **nameservers_config;
	char **nameservers_auto;
	int nameservers_timeout;
	char **domains;
	bool mdns;
	bool mdns_config;
	char *hostname;
	char *domainname;
	char **timeservers;
	char **timeservers_config;
	/* 802.1x settings from the config files */
	char *eap;
	char *identity;
	char *anonymous_identity;
	char *agent_identity;
	char *ca_cert_file;
	char *subject_match;
	char *altsubject_match;
	char *domain_suffix_match;
	char *domain_match;
	char *client_cert_file;
	char *private_key_file;
	char *private_key_passphrase;
	char *phase2;
	DBusMessage *pending;
	guint timeout;
	struct connman_stats stats;
	struct connman_stats stats_roaming;
	GHashTable *counter_table;
	enum connman_service_proxy_method proxy;
	enum connman_service_proxy_method proxy_config;
	char **proxies;
	char **excludes;
	char *pac;
	bool wps;
	bool wps_advertizing;

    /**
     *  IPv4-specific "online" reachability check state.
     */
	struct online_check_state online_check_state_ipv4;

    /**
     *  IPv6-specific "online" reachability check state.
     */
	struct online_check_state online_check_state_ipv6;

    /**
     *  Tracks whether the service has met the number of sustained,
     *  back-to-back "online" reachability check failures for
     *  "continuous" online check mode.
     */
	bool online_check_failures_met_threshold;
	bool do_split_routing;
	bool new_service;
	bool hidden_service;
	char *config_file;
	char *config_entry;
};

static bool allow_property_changed(struct connman_service *service);

static struct connman_ipconfig *create_ip4config(struct connman_service *service,
		int index, enum connman_ipconfig_method method);
static struct connman_ipconfig *create_ip6config(struct connman_service *service,
		int index);
static void dns_changed(struct connman_service *service);
static void vpn_auto_connect(void);
static void trigger_autoconnect(struct connman_service *service);
static void service_list_sort(const char *function);
static void complete_online_check(struct connman_service *service,
					enum connman_ipconfig_type type,
					bool success,
					int err);
static bool service_downgrade_online_state(struct connman_service *service);
static bool connman_service_is_default(const struct connman_service *service);
static int start_online_check_if_connected(struct connman_service *service);
static void set_error(struct connman_service *service,
					enum connman_service_error error);
static void clear_error(struct connman_service *service);

struct find_data {
	const char *path;
	struct connman_service *service;
};

static void compare_path(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	struct find_data *data = user_data;

	if (data->service)
		return;

	if (g_strcmp0(service->path, data->path) == 0)
		data->service = service;
}

static struct connman_service *find_service(const char *path)
{
	struct find_data data = { .path = path, .service = NULL };

	DBG("path %s", path);

	g_list_foreach(service_list, compare_path, &data);

	return data.service;
}

static const char *reason2string(enum connman_service_connect_reason reason)
{

	switch (reason) {
	case CONNMAN_SERVICE_CONNECT_REASON_NONE:
		return "none";
	case CONNMAN_SERVICE_CONNECT_REASON_USER:
		return "user";
	case CONNMAN_SERVICE_CONNECT_REASON_AUTO:
		return "auto";
	case CONNMAN_SERVICE_CONNECT_REASON_SESSION:
		return "session";
	case CONNMAN_SERVICE_CONNECT_REASON_NATIVE:
		return "native";
	}

	return "unknown";
}

const char *__connman_service_type2string(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return "system";
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "cellular";
	case CONNMAN_SERVICE_TYPE_GPS:
		return "gps";
	case CONNMAN_SERVICE_TYPE_VPN:
		return "vpn";
	case CONNMAN_SERVICE_TYPE_GADGET:
		return "gadget";
	case CONNMAN_SERVICE_TYPE_P2P:
		return "p2p";
	}

	return NULL;
}

enum connman_service_type __connman_service_string2type(const char *str)
{
	if (!str)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	if (strcmp(str, "ethernet") == 0)
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	if (strcmp(str, "gadget") == 0)
		return CONNMAN_SERVICE_TYPE_GADGET;
	if (strcmp(str, "wifi") == 0)
		return CONNMAN_SERVICE_TYPE_WIFI;
	if (strcmp(str, "cellular") == 0)
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	if (strcmp(str, "bluetooth") == 0)
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	if (strcmp(str, "vpn") == 0)
		return CONNMAN_SERVICE_TYPE_VPN;
	if (strcmp(str, "gps") == 0)
		return CONNMAN_SERVICE_TYPE_GPS;
	if (strcmp(str, "system") == 0)
		return CONNMAN_SERVICE_TYPE_SYSTEM;
	if (strcmp(str, "p2p") == 0)
		return CONNMAN_SERVICE_TYPE_P2P;

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

enum connman_service_security __connman_service_string2security(const char *str)
{
	if (!str)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;

	if (!strcmp(str, "psk"))
		return CONNMAN_SERVICE_SECURITY_PSK;
	if (!strcmp(str, "ieee8021x") || !strcmp(str, "8021x"))
		return CONNMAN_SERVICE_SECURITY_8021X;
	if (!strcmp(str, "none") || !strcmp(str, "open"))
		return CONNMAN_SERVICE_SECURITY_NONE;
	if (!strcmp(str, "wep"))
		return CONNMAN_SERVICE_SECURITY_WEP;

	return CONNMAN_SERVICE_SECURITY_UNKNOWN;
}

static const char *security2string(enum connman_service_security security)
{
	switch (security) {
	case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		break;
	case CONNMAN_SERVICE_SECURITY_NONE:
		return "none";
	case CONNMAN_SERVICE_SECURITY_WEP:
		return "wep";
	case CONNMAN_SERVICE_SECURITY_PSK:
	case CONNMAN_SERVICE_SECURITY_WPA:
	case CONNMAN_SERVICE_SECURITY_RSN:
		return "psk";
	case CONNMAN_SERVICE_SECURITY_8021X:
		return "ieee8021x";
	}

	return NULL;
}

static const char *state2string(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_STATE_IDLE:
		return "idle";
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		return "association";
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return "configuration";
	case CONNMAN_SERVICE_STATE_READY:
		return "ready";
	case CONNMAN_SERVICE_STATE_ONLINE:
		return "online";
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		return "disconnect";
	case CONNMAN_SERVICE_STATE_FAILURE:
		return "failure";
	}

	return NULL;
}

static const char *error2string(enum connman_service_error error)
{
	switch (error) {
	case CONNMAN_SERVICE_ERROR_UNKNOWN:
		break;
	case CONNMAN_SERVICE_ERROR_OUT_OF_RANGE:
		return "out-of-range";
	case CONNMAN_SERVICE_ERROR_PIN_MISSING:
		return "pin-missing";
	case CONNMAN_SERVICE_ERROR_DHCP_FAILED:
		return "dhcp-failed";
	case CONNMAN_SERVICE_ERROR_CONNECT_FAILED:
		return "connect-failed";
	case CONNMAN_SERVICE_ERROR_LOGIN_FAILED:
		return "login-failed";
	case CONNMAN_SERVICE_ERROR_AUTH_FAILED:
		return "auth-failed";
	case CONNMAN_SERVICE_ERROR_INVALID_KEY:
		return "invalid-key";
	case CONNMAN_SERVICE_ERROR_BLOCKED:
		return "blocked";
	case CONNMAN_SERVICE_ERROR_ONLINE_CHECK_FAILED:
		return "online-check-failed";
	}

	return NULL;
}

static const char *proxymethod2string(enum connman_service_proxy_method method)
{
	switch (method) {
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		return "direct";
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		return "manual";
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		return "auto";
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		break;
	}

	return NULL;
}

static enum connman_service_proxy_method string2proxymethod(const char *method)
{
	if (g_strcmp0(method, "direct") == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_DIRECT;
	else if (g_strcmp0(method, "auto") == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_AUTO;
	else if (g_strcmp0(method, "manual") == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_MANUAL;
	else
		return CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;
}

void __connman_service_split_routing_changed(struct connman_service *service)
{
	dbus_bool_t split_routing;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	split_routing = service->do_split_routing;
	if (!connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "SplitRouting",
					DBUS_TYPE_BOOLEAN, &split_routing))
		connman_warn("cannot send SplitRouting property change on %s",
					service->identifier);
}

void __connman_service_set_split_routing(struct connman_service *service,
								bool value)
{
	if (service->type != CONNMAN_SERVICE_TYPE_VPN)
		return;

	service->do_split_routing = value;

	if (service->do_split_routing)
		service->order = 0;
	else
		service->order = 10;

	/*
	 * In order to make sure the value is propagated also when loading the
	 * VPN service signal the value regardless of the value change.
	 */
	__connman_service_split_routing_changed(service);
}

int __connman_service_load_modifiable(struct connman_service *service)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	gchar *str;
	bool autoconnect;

	DBG("service %p", service);

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return -EIO;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		__connman_service_set_split_routing(service,
						g_key_file_get_boolean(keyfile,
						service->identifier,
						"SplitRouting", NULL));

		/* fall through */
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		autoconnect = g_key_file_get_boolean(keyfile,
				service->identifier, "AutoConnect", &error);
		if (!error)
			service->autoconnect = autoconnect;
		g_clear_error(&error);
		break;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Modified", NULL);
	if (str) {
		util_iso8601_to_timeval(str, &service->modified);
		g_free(str);
	}

	g_key_file_free(keyfile);

	return 0;
}

static int service_load(struct connman_service *service)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	gsize length;
	gchar *str;
	bool autoconnect;
	unsigned int ssid_len;
	int err = 0;

	DBG("service %p", service);

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile) {
		service->new_service = true;
		return -EIO;
	} else
		service->new_service = false;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		__connman_service_set_split_routing(service,
						g_key_file_get_boolean(keyfile,
						service->identifier,
						"SplitRouting", NULL));

		autoconnect = g_key_file_get_boolean(keyfile,
				service->identifier, "AutoConnect", &error);
		if (!error)
			service->autoconnect = autoconnect;
		g_clear_error(&error);
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		if (!service->name) {
			gchar *name;

			name = g_key_file_get_string(keyfile,
					service->identifier, "Name", NULL);
			if (name) {
				g_free(service->name);
				service->name = name;
			}

			if (service->network)
				connman_network_set_name(service->network,
									name);
		}

		if (service->network &&
				!connman_network_get_blob(service->network,
						"WiFi.SSID", &ssid_len)) {
			gchar *hex_ssid;

			hex_ssid = g_key_file_get_string(keyfile,
							service->identifier,
								"SSID", NULL);

			if (hex_ssid) {
				gchar *ssid;
				unsigned int i, j = 0, hex;
				size_t hex_ssid_len = strlen(hex_ssid);

				ssid = g_try_malloc0(hex_ssid_len / 2);
				if (!ssid) {
					g_free(hex_ssid);
					err = -ENOMEM;
					goto done;
				}

				for (i = 0; i < hex_ssid_len; i += 2) {
					sscanf(hex_ssid + i, "%02x", &hex);
					ssid[j++] = hex;
				}

				connman_network_set_blob(service->network,
					"WiFi.SSID", ssid, hex_ssid_len / 2);

				g_free(ssid);
			}

			g_free(hex_ssid);
		}
		/* fall through */

	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		service->favorite = g_key_file_get_boolean(keyfile,
				service->identifier, "Favorite", NULL);

		/* fall through */

	case CONNMAN_SERVICE_TYPE_ETHERNET:
		autoconnect = g_key_file_get_boolean(keyfile,
				service->identifier, "AutoConnect", &error);
		if (!error)
			service->autoconnect = autoconnect;
		g_clear_error(&error);
		break;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Modified", NULL);
	if (str) {
		util_iso8601_to_timeval(str, &service->modified);
		g_free(str);
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Passphrase", NULL);
	if (str) {
		char *dec = g_strcompress(str);
		g_free(str);
		g_free(service->passphrase);
		service->passphrase = dec;
	}

	if (service->ipconfig_ipv4)
		__connman_ipconfig_load(service->ipconfig_ipv4, keyfile,
					service->identifier, "IPv4.");

	if (service->ipconfig_ipv6)
		__connman_ipconfig_load(service->ipconfig_ipv6, keyfile,
					service->identifier, "IPv6.");

	service->nameservers_config = g_key_file_get_string_list(keyfile,
			service->identifier, "Nameservers", &length, NULL);
	if (service->nameservers_config && length == 0) {
		g_strfreev(service->nameservers_config);
		service->nameservers_config = NULL;
	}

	service->timeservers_config = g_key_file_get_string_list(keyfile,
			service->identifier, "Timeservers", &length, NULL);
	if (service->timeservers_config && length == 0) {
		g_strfreev(service->timeservers_config);
		service->timeservers_config = NULL;
	}

	service->domains = g_key_file_get_string_list(keyfile,
			service->identifier, "Domains", &length, NULL);
	if (service->domains && length == 0) {
		g_strfreev(service->domains);
		service->domains = NULL;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Proxy.Method", NULL);
	if (str)
		service->proxy_config = string2proxymethod(str);

	g_free(str);

	service->proxies = g_key_file_get_string_list(keyfile,
			service->identifier, "Proxy.Servers", &length, NULL);
	if (service->proxies && length == 0) {
		g_strfreev(service->proxies);
		service->proxies = NULL;
	}

	service->excludes = g_key_file_get_string_list(keyfile,
			service->identifier, "Proxy.Excludes", &length, NULL);
	if (service->excludes && length == 0) {
		g_strfreev(service->excludes);
		service->excludes = NULL;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Proxy.URL", NULL);
	if (str) {
		g_free(service->pac);
		service->pac = str;
	}

	service->mdns_config = g_key_file_get_boolean(keyfile,
				service->identifier, "mDNS", NULL);

	service->hidden_service = g_key_file_get_boolean(keyfile,
					service->identifier, "Hidden", NULL);

done:
	g_key_file_free(keyfile);

	return err;
}

static int service_save(struct connman_service *service)
{
	GKeyFile *keyfile;
	gchar *str;
	guint freq;
	const char *cst_str = NULL;
	int err = 0;

	DBG("service %p (%s) new %d",
		service, connman_service_get_identifier(service),
		service->new_service);

	if (service->new_service)
		return -ESRCH;

	keyfile = g_key_file_new();
	if (!keyfile)
		return -EIO;

	if (service->name)
		g_key_file_set_string(keyfile, service->identifier,
						"Name", service->name);

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		g_key_file_set_boolean(keyfile, service->identifier,
				"SplitRouting", service->do_split_routing);
		if (service->favorite)
			g_key_file_set_boolean(keyfile, service->identifier,
					"AutoConnect", service->autoconnect);
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		if (service->network) {
			const unsigned char *ssid;
			unsigned int ssid_len = 0;

			ssid = connman_network_get_blob(service->network,
							"WiFi.SSID", &ssid_len);

			if (ssid && ssid_len > 0 && ssid[0] != '\0') {
				char *identifier = service->identifier;
				GString *ssid_str;
				unsigned int i;

				ssid_str = g_string_sized_new(ssid_len * 2);
				if (!ssid_str) {
					err = -ENOMEM;
					goto done;
				}

				for (i = 0; i < ssid_len; i++)
					g_string_append_printf(ssid_str,
							"%02x", ssid[i]);

				g_key_file_set_string(keyfile, identifier,
							"SSID", ssid_str->str);

				g_string_free(ssid_str, TRUE);
			}

			freq = connman_network_get_frequency(service->network);
			g_key_file_set_integer(keyfile, service->identifier,
						"Frequency", freq);
		}
		/* fall through */

	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		g_key_file_set_boolean(keyfile, service->identifier,
					"Favorite", service->favorite);

		/* fall through */

	case CONNMAN_SERVICE_TYPE_ETHERNET:
		if (service->favorite)
			g_key_file_set_boolean(keyfile, service->identifier,
					"AutoConnect", service->autoconnect);
		break;
	}

	str = util_timeval_to_iso8601(&service->modified);
	if (str) {
		g_key_file_set_string(keyfile, service->identifier,
				"Modified", str);
		g_free(str);
	}

	if (service->passphrase && strlen(service->passphrase) > 0) {
		char *enc = g_strescape(service->passphrase, NULL);
		g_key_file_set_string(keyfile, service->identifier,
				"Passphrase", enc);
		g_free(enc);
	}

	if (service->ipconfig_ipv4)
		__connman_ipconfig_save(service->ipconfig_ipv4, keyfile,
				service->identifier, "IPv4.");

	if (service->ipconfig_ipv6)
		__connman_ipconfig_save(service->ipconfig_ipv6, keyfile,
				service->identifier, "IPv6.");

	if (service->nameservers_config) {
		guint len = g_strv_length(service->nameservers_config);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Nameservers",
				(const gchar **) service->nameservers_config, len);
	}

	if (service->timeservers_config) {
		guint len = g_strv_length(service->timeservers_config);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Timeservers",
				(const gchar **) service->timeservers_config, len);
	}

	if (service->domains) {
		guint len = g_strv_length(service->domains);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Domains",
				(const gchar **) service->domains, len);
	}

	cst_str = proxymethod2string(service->proxy_config);
	if (cst_str)
		g_key_file_set_string(keyfile, service->identifier,
				"Proxy.Method", cst_str);

	if (service->proxies) {
		guint len = g_strv_length(service->proxies);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Proxy.Servers",
				(const gchar **) service->proxies, len);
	}

	if (service->excludes) {
		guint len = g_strv_length(service->excludes);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Proxy.Excludes",
				(const gchar **) service->excludes, len);
	}

	if (service->pac && strlen(service->pac) > 0)
		g_key_file_set_string(keyfile, service->identifier,
				"Proxy.URL", service->pac);

	if (service->mdns_config)
		g_key_file_set_boolean(keyfile, service->identifier,
				"mDNS", TRUE);

	if (service->hidden_service)
		g_key_file_set_boolean(keyfile, service->identifier,
				"Hidden", TRUE);

	if (service->config_file && strlen(service->config_file) > 0)
		g_key_file_set_string(keyfile, service->identifier,
				"Config.file", service->config_file);

	if (service->config_entry && strlen(service->config_entry) > 0)
		g_key_file_set_string(keyfile, service->identifier,
				"Config.ident", service->config_entry);

done:
	__connman_storage_save_service(keyfile, service->identifier);

	g_key_file_free(keyfile);

	return err;
}

void __connman_service_save(struct connman_service *service)
{
	if (!service)
		return;

	service_save(service);
}

static enum connman_service_state combine_state(
					enum connman_service_state state_a,
					enum connman_service_state state_b)
{
	enum connman_service_state result;

	if (state_a == state_b) {
		result = state_a;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_UNKNOWN) {
		result = state_b;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_UNKNOWN) {
		result = state_a;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_IDLE) {
		result = state_b;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_IDLE) {
		result = state_a;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_ONLINE) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_ONLINE) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_READY) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_READY) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_CONFIGURATION) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_CONFIGURATION) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_ASSOCIATION) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_ASSOCIATION) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_DISCONNECT) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_DISCONNECT) {
		result = state_b;
		goto done;
	}

	result = CONNMAN_SERVICE_STATE_FAILURE;

done:
	return result;
}

static bool is_connecting(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return true;
	}

	return false;
}

static bool is_connected(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		break;
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		return true;
	}

	return false;
}

static bool is_online(enum connman_service_state state)
{
	return state == CONNMAN_SERVICE_STATE_ONLINE;
}

static bool is_idle(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		return true;
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	}

	return false;
}

static int nameservers_changed_cb(void *user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	service->nameservers_timeout = 0;
	if ((is_idle(service->state) && !service->nameservers) ||
			is_connected(service->state))
		dns_changed(service);

	return FALSE;
}

static void nameservers_changed(struct connman_service *service)
{
	if (!service->nameservers_timeout)
		service->nameservers_timeout = g_idle_add(nameservers_changed_cb,
							service);
}

static bool nameserver_available(struct connman_service *service,
				enum connman_ipconfig_type type,
				const char *ns)
{
	int family;

	family = connman_inet_check_ipaddress(ns);

	if (family == AF_INET) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
			return false;

		return is_connected(service->state_ipv4);
	}

	if (family == AF_INET6) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			return false;

		return is_connected(service->state_ipv6);
	}

	return false;
}

static int searchdomain_add_all(struct connman_service *service)
{
	int index, i = 0;

	if (!is_connected(service->state))
		return -ENOTCONN;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	if (service->domains) {
		while (service->domains[i]) {
			connman_resolver_append(index, service->domains[i],
						NULL);
			i++;
		}

		return 0;
	}

	if (service->domainname)
		connman_resolver_append(index, service->domainname, NULL);

	return 0;

}

static int searchdomain_remove_all(struct connman_service *service)
{
	int index, i = 0;

	if (!is_connected(service->state))
		return -ENOTCONN;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	while (service->domains && service->domains[i]) {
		connman_resolver_remove(index, service->domains[i], NULL);
		i++;
	}

	if (service->domainname)
		connman_resolver_remove(index, service->domainname, NULL);

	return 0;
}

static int nameserver_add(struct connman_service *service,
			enum connman_ipconfig_type type,
			const char *nameserver)
{
	int index, ret;

	if (!nameserver_available(service, type, nameserver))
		return 0;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	ret = connman_resolver_append(index, NULL, nameserver);
	if (ret >= 0)
		nameservers_changed(service);

	return ret;
}

static int nameserver_add_all(struct connman_service *service,
			enum connman_ipconfig_type type)
{
	int i = 0;

	if (service->nameservers_config) {
		while (service->nameservers_config[i]) {
			nameserver_add(service, type,
				service->nameservers_config[i]);
			i++;
		}
	} else if (service->nameservers) {
		while (service->nameservers[i]) {
			nameserver_add(service, type,
				service->nameservers[i]);
			i++;
		}
	}

	if (!i)
		__connman_resolver_append_fallback_nameservers();

	searchdomain_add_all(service);

	return 0;
}

static int nameserver_remove(struct connman_service *service,
			enum connman_ipconfig_type type,
			const char *nameserver)
{
	int index, ret;

	if (!nameserver_available(service, type, nameserver))
		return 0;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	ret = connman_resolver_remove(index, NULL, nameserver);
	if (ret >= 0)
		nameservers_changed(service);

	return ret;
}

static int nameserver_remove_all(struct connman_service *service,
				enum connman_ipconfig_type type)
{
	int index, i = 0;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	while (service->nameservers_config && service->nameservers_config[i]) {

		nameserver_remove(service, type,
				service->nameservers_config[i]);
		i++;
	}

	i = 0;
	while (service->nameservers && service->nameservers[i]) {
		nameserver_remove(service, type, service->nameservers[i]);
		i++;
	}

	searchdomain_remove_all(service);

	return 0;
}

/*
 * The is_auto variable is set to true when IPv6 autoconf nameservers are
 * inserted to resolver via netlink message (see rtnl.c:rtnl_newnduseropt()
 * for details) and not through service.c
 */
int __connman_service_nameserver_append(struct connman_service *service,
				const char *nameserver, bool is_auto)
{
	char **nameservers;
	int len, i;

	DBG("service %p (%s) nameserver %s auto %d",
		service, connman_service_get_identifier(service),
		nameserver, is_auto);

	if (!nameserver)
		return -EINVAL;

	if (is_auto)
		nameservers = service->nameservers_auto;
	else
		nameservers = service->nameservers;

	if (nameservers) {
		for (i = 0; nameservers[i]; i++) {
			if (g_strcmp0(nameservers[i], nameserver) == 0)
				return -EEXIST;
		}

		len = g_strv_length(nameservers);
		nameservers = g_try_renew(char *, nameservers, len + 2);
	} else {
		len = 0;
		nameservers = g_try_new0(char *, len + 2);
	}

	if (!nameservers)
		return -ENOMEM;

	nameservers[len] = g_strdup(nameserver);
	nameservers[len + 1] = NULL;

	if (is_auto) {
		service->nameservers_auto = nameservers;
	} else {
		service->nameservers = nameservers;
		nameserver_add(service, CONNMAN_IPCONFIG_TYPE_ALL, nameserver);
	}

	nameservers_changed(service);

	searchdomain_add_all(service);

	return 0;
}

int __connman_service_nameserver_remove(struct connman_service *service,
				const char *nameserver, bool is_auto)
{
	char **servers, **nameservers;
	bool found = false;
	int len, i, j;

	DBG("service %p nameserver %s auto %d", service, nameserver, is_auto);

	if (!nameserver)
		return -EINVAL;

	if (is_auto)
		nameservers = service->nameservers_auto;
	else
		nameservers = service->nameservers;

	if (!nameservers)
		return 0;

	for (i = 0; nameservers[i]; i++)
		if (g_strcmp0(nameservers[i], nameserver) == 0) {
			found = true;
			break;
		}

	if (!found)
		return 0;

	len = g_strv_length(nameservers);

	if (len == 1) {
		servers = NULL;
		goto set_servers;
	}

	servers = g_try_new0(char *, len);
	if (!servers)
		return -ENOMEM;

	for (i = 0, j = 0; i < len; i++) {
		if (g_strcmp0(nameservers[i], nameserver)) {
			servers[j] = nameservers[i];
			j++;
		} else
			g_free(nameservers[i]);

		nameservers[i] = NULL;
	}
	servers[len - 1] = NULL;

set_servers:
	g_strfreev(nameservers);
	nameservers = servers;

	if (is_auto) {
		service->nameservers_auto = nameservers;
	} else {
		service->nameservers = nameservers;
		nameserver_remove(service, CONNMAN_IPCONFIG_TYPE_ALL,
				nameserver);
	}

	return 0;
}

void __connman_service_nameserver_clear(struct connman_service *service)
{
	nameserver_remove_all(service, CONNMAN_IPCONFIG_TYPE_ALL);

	g_strfreev(service->nameservers);
	service->nameservers = NULL;

	nameserver_add_all(service, CONNMAN_IPCONFIG_TYPE_ALL);
}

/**
 *  @brief
 *    Add an IPv4 or IPv6 host route for the specified domain name
 *    service (DNS) server.
 *
 *  This attempts to add an IPv4 or IPv6 host route for the specified
 *  domain name service (DNS) server with the specified attributes.
 *
 *  @param[in]  family      The address family describing the
 *                          address pointed to by @a nameserver.
 *  @param[in]  index       The network interface index associated
 *                          with the output network device for
 *                          the route.
 *  @param[in]  nameserver  A pointer to an immutable null-terminated
 *                          C string containing the IPv4 or IPv6
 *                          address, in text form, of the route
 *                          DNS server destination address.
 *  @param[in]  gw          A pointer to an immutable null-terminated
 *                          C string containing the IPv4 or IPv6
 *                          address, in text form, of the route next
 *                          hop gateway address.
 *
 *  @sa del_nameserver_route
 *  @sa nameserver_add_routes
 *
 */
static void add_nameserver_route(int family, int index, const char *nameserver,
				const char *gw)
{
	DBG("family %d index %d nameserver %s gw %s",
		family, index, nameserver, gw);

	switch (family) {
	case AF_INET:
		if (connman_inet_compare_subnet(index, nameserver))
			break;

		if (connman_inet_add_host_route(index, nameserver, gw) < 0)
			/* For P-t-P link the above route add will fail */
			connman_inet_add_host_route(index, nameserver, NULL);
		break;

	case AF_INET6:
		if (connman_inet_add_ipv6_host_route(index, nameserver,
								gw) < 0)
			connman_inet_add_ipv6_host_route(index, nameserver,
							NULL);
		break;
	}
}

/**
 *  @brief
 *    Delete an IPv4 or IPv6 host route for the specified domain name
 *    service (DNS) server.
 *
 *  This attempts to delete an IPv4 or IPv6 host route for the
 *  specified domain name service (DNS) server with the specified
 *  attributes.
 *
 *  @param[in]  family      The address family describing the
 *                          address pointed to by @a nameserver.
 *  @param[in]  index       The network interface index associated
 *                          with the output network device for
 *                          the route.
 *  @param[in]  nameserver  A pointer to an immutable null-terminated
 *                          C string containing the IPv4 or IPv6
 *                          address, in text form, of the route
 *                          DNS server destination address.
 *  @param[in]  gw          A pointer to an immutable null-terminated
 *                          C string containing the IPv4 or IPv6
 *                          address, in text form, of the route next
 *                          hop gateway address.
 *
 *  @sa add_nameserver_route
 *  @sa nameserver_del_routes
 *
 */
static void del_nameserver_route(int family, int index, const char *nameserver,
				const char *gw,
				enum connman_ipconfig_type type)
{
	DBG("family %d index %d nameserver %s gw %s",
		family, index, nameserver, gw);

	switch (family) {
	case AF_INET:
		if (type != CONNMAN_IPCONFIG_TYPE_IPV4 &&
			type != CONNMAN_IPCONFIG_TYPE_ALL)
			break;

		if (connman_inet_compare_subnet(index, nameserver))
			break;

		if (connman_inet_del_host_route(index, nameserver, gw) < 0)
			/* For P-t-P link the above route del will fail */
			connman_inet_del_host_route(index, nameserver, NULL);
		break;

	case AF_INET6:
		if (type != CONNMAN_IPCONFIG_TYPE_IPV6 &&
			type != CONNMAN_IPCONFIG_TYPE_ALL)
			break;

		if (connman_inet_del_ipv6_host_route(index, nameserver,
								gw) < 0)
			connman_inet_del_ipv6_host_route(index, nameserver,
							NULL);
		break;
	}
}

/**
 *  @brief
 *    Add IPv4 or IPv6 host routes for the specified domain name
 *    service (DNS) servers.
 *
 *  This attempts to add IPv4 or IPv6 host routes for the specified
 *  domain name service (DNS) servers with the specified attributes.
 *
 *  @param[in]  index        The network interface index associated
 *                           with the output network device for
 *                           the route.
 *  @param[in]  nameservers  A pointer to a null-terminated array of
 *                           mutable null-terminated C strings
 *                           containing the IPv4 or IPv6 addresses, in
 *                           text form, of the route DNS server
 *                           destination addresses.
 *  @param[in]  gw           A pointer to an immutable null-terminated
 *                           C string containing the IPv4 or IPv6
 *                           address, in text form, of the route next
 *                           hop gateway address.
 *
 *  @sa add_nameserver_route
 *  @sa nameserver_del_routes
 *
 */
static void nameserver_add_routes(int index, char **nameservers,
					const char *gw)
{
	int i, ns_family, gw_family;

	gw_family = connman_inet_check_ipaddress(gw);
	if (gw_family < 0)
		return;

	for (i = 0; nameservers[i]; i++) {
		ns_family = connman_inet_check_ipaddress(nameservers[i]);
		if (ns_family < 0 || ns_family != gw_family)
			continue;

		add_nameserver_route(ns_family, index, nameservers[i], gw);
	}
}

/**
 *  @brief
 *    Delete IPv4 or IPv6 host routes for the specified domain name
 *    service (DNS) servers.
 *
 *  This attempts to delete IPv4 or IPv6 host routes for the specified
 *  domain name service (DNS) servers with the specified attributes.
 *
 *  @param[in]  index        The network interface index associated
 *                           with the output network device for
 *                           the route.
 *  @param[in]  nameservers  A pointer to a null-terminated array of
 *                           mutable null-terminated C strings
 *                           containing the IPv4 or IPv6 addresses, in
 *                           text form, of the route DNS server
 *                           destination addresses.
 *  @param[in]  gw           A pointer to an immutable null-terminated
 *                           C string containing the IPv4 or IPv6
 *                           address, in text form, of the route next
 *                           hop gateway address.
 *
 *  @sa del_nameserver_route
 *  @sa nameserver_add_routes
 *
 */
static void nameserver_del_routes(int index, char **nameservers,
				const char *gw,
				enum connman_ipconfig_type type)
{
	int i, ns_family, gw_family;

	gw_family = connman_inet_check_ipaddress(gw);
	if (gw_family < 0)
		return;

	for (i = 0; nameservers[i]; i++) {
		ns_family = connman_inet_check_ipaddress(nameservers[i]);
		if (ns_family < 0 || ns_family != gw_family)
			continue;

		del_nameserver_route(ns_family, index, nameservers[i],
			gw, type);
	}
}

/**
 *  @brief
 *    Add IPv4 or IPv6 host routes for the domain name service (DNS)
 *    servers associated with the specified service.
 *
 *  This attempts to add IPv4 or IPv6 host routes for both the
 *  automatic and configured domain name service (DNS) servers
 *  associated with the specified network service.
 *
 *  @param[in]  service      A pointer to the immutable network
 *                           service for which to add DNS server host
 *                           routes.
 *  @param[in]  gw           A pointer to an immutable null-terminated
 *                           C string containing the IPv4 or IPv6
 *                           address, in text form, of the route next
 *                           hop gateway address.
 *
 *  @sa __connman_service_nameserver_del_routes
 *  @sa nameserver_add_routes
 *
 */
void __connman_service_nameserver_add_routes(
					const struct connman_service *service,
					const char *gw)
{
	int index;

	if (!service)
		return;

	index = __connman_service_get_index(service);

	if (service->nameservers_config) {
		/*
		 * Configured nameserver takes preference over the
		 * discoverd nameserver gathered from DHCP, VPN, etc.
		 */
		nameserver_add_routes(index, service->nameservers_config, gw);
	} else if (service->nameservers) {
		/*
		 * We add nameservers host routes for nameservers that
		 * are not on our subnet. For those who are, the subnet
		 * route will be installed by the time the dns proxy code
		 * tries to reach them. The subnet route is installed
		 * when setting the interface IP address.
		 */
		nameserver_add_routes(index, service->nameservers, gw);
	}
}

/**
 *  @brief
 *    Delete IPv4 or IPv6 host routes for the domain name service (DNS)
 *    servers associated with the specified service.
 *
 *  This attempts to delete IPv4 or IPv6 host routes for both the
 *  automatic and configured domain name service (DNS) servers
 *  associated with the specified network service.
 *
 *  @param[in]  service      A pointer to the immutable network
 *                           service for which to delete DNS server
 *                           host routes.
 *  @param[in]  gw           A pointer to an immutable null-terminated
 *                           C string containing the IPv4 or IPv6
 *                           address, in text form, of the route next
 *                           hop gateway address.
 *  @param[in]  type         The IP configuration type for which to
 *                           delete DNS server host routes.
 *
 *  @sa __connman_service_nameserver_del_routes
 *  @sa nameserver_add_routes
 *
 */
void __connman_service_nameserver_del_routes(
					const struct connman_service *service,
					const char *gw,
					enum connman_ipconfig_type type)
{
	int index;

	if (!service)
		return;

	index = __connman_service_get_index(service);

	if (service->nameservers_config)
		nameserver_del_routes(index, service->nameservers_config,
					gw, type);
	else if (service->nameservers)
		nameserver_del_routes(index, service->nameservers, gw, type);
}

/**
 *  @brief
 *    Check the proxy setup of the specified network service.
 *
 *  This checks the proxy configuration of the specified network
 *  service. The network service, @a service, may be set to
 *  #CONNMAN_SERVICE_PROXY_METHOD_DIRECT if the current internal
 *  method is empty or if there is no Proxy Auto-configuration (PAC)
 *  URL received from DHCP or if the user proxy configuration is empty
 *  or automatic and the Web Proxy Auto-discovery (WPAD) protocol
 *  fails.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which the proxy setup is to be
 *                           checked and for which the method may be
 *                           updated to
 *                           #CONNMAN_SERVICE_PROXY_METHOD_DIRECT.
 *
 *  @returns
 *    True if the proxy method has been established for the specified
 *    service; otherwise, false.
 *
 *  @sa connman_service_set_proxy_method
 *  @sa __connman_wpad_start
 *
 */
static bool check_proxy_setup(struct connman_service *service)
{
	DBG("service %p (%s)", service, connman_service_get_identifier(service));

	/*
	 * We start WPAD if we haven't got a PAC URL from DHCP and
	 * if our proxy manual configuration is either empty or set
	 * to AUTO with an empty URL.
	 */

	if (service->proxy != CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN)
		return true;

	if (service->proxy_config != CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN &&
		(service->proxy_config != CONNMAN_SERVICE_PROXY_METHOD_AUTO ||
			service->pac))
		return true;

	if (__connman_wpad_start(service) < 0) {
		connman_service_set_proxy_method(service,
			CONNMAN_SERVICE_PROXY_METHOD_DIRECT);
		return true;
	}

	return false;
}

const char *__connman_service_online_check_mode2string(
				enum service_online_check_mode mode)
{
	switch (mode) {
	case CONNMAN_SERVICE_ONLINE_CHECK_MODE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_ONLINE_CHECK_MODE_NONE:
		return "none";
	case CONNMAN_SERVICE_ONLINE_CHECK_MODE_ONE_SHOT:
		return "one-shot";
	case CONNMAN_SERVICE_ONLINE_CHECK_MODE_CONTINUOUS:
		return "continuous";
	default:
		break;
	}

	return NULL;
}

enum service_online_check_mode __connman_service_online_check_string2mode(
				const char *mode)
{
	if (!mode)
		return CONNMAN_SERVICE_ONLINE_CHECK_MODE_UNKNOWN;

	if (g_strcmp0(mode, "none") == 0)
		return CONNMAN_SERVICE_ONLINE_CHECK_MODE_NONE;
	else if (g_strcmp0(mode, "one-shot") == 0)
		return CONNMAN_SERVICE_ONLINE_CHECK_MODE_ONE_SHOT;
	else if (g_strcmp0(mode, "continuous") == 0)
		return CONNMAN_SERVICE_ONLINE_CHECK_MODE_CONTINUOUS;

	return CONNMAN_SERVICE_ONLINE_CHECK_MODE_UNKNOWN;
}

/**
 *  @brief
 *    Return the "online" HTTP-based Internet reachability check mode.
 *
 *  @returns
 *    The "online" HTTP-based Internet reachability check mode.
 *
 */
enum service_online_check_mode __connman_service_get_online_check_mode(void)
{
	return connman_setting_get_uint("OnlineCheckMode");
}

/**
 *  @brief
 *    Return whether the "online" HTTP-based Internet reachability
 *    checks are enabled.
 *
 *  @returns
 *    True if "online" HTTP-based Internet reachability checks are
 *    enabled; otherwise, false.
 *
 *  @sa __connman_service_get_online_check_mode
 *
 */
bool __connman_service_is_online_check_enabled(void)
{
	const enum service_online_check_mode mode =
		__connman_service_get_online_check_mode();

	return mode != CONNMAN_SERVICE_ONLINE_CHECK_MODE_UNKNOWN &&
		mode != CONNMAN_SERVICE_ONLINE_CHECK_MODE_NONE;
}

/**
 *  @brief
 *    Determines whether the "online" HTTP-based Internet reachability
 *    check mode is the specified mode.
 *
 *  @param[in]  mode  The "online" HTTP-based Internet reachability
 *                    check mode to confirm.
 *
 *  @returns
 *    True if the current "online" HTTP-based Internet reachability
 *    check mode is @a mode; otherwise, false.
 *
 *  @sa __connman_service_get_online_check_mode
 *
 */
bool __connman_service_is_online_check_mode(
		enum service_online_check_mode mode)
{
	return __connman_service_get_online_check_mode() == mode;
}

/**
 *  @brief
 *    Determine whether an "online" HTTP-based Internet reachability
 *    check is active.
 *
 *  This determines whether an "online" HTTP-based Internet
 *  reachability check is active for the specified network service IP
 *  configuration type.
 *
 *  @param[in]  service  A pointer to the immutable network service
 *                       for which to determine whether an "online"
 *                       HTTP-based Internet reachability is active.
 *  @param[in]  type     The IP configuration type for which to
 *                       determine whether an "online" HTTP-based
 *                       Internet reachability is active.
 *
 *  @returns
 *    True if an "online" HTTP-based Internet reachability check is
 *    active for the specified network service IP configuration type;
 *    otherwise, false.
 *
 */
static bool online_check_is_active(const struct connman_service *service,
		enum connman_ipconfig_type type)
{
	bool do_ipv4 = false, do_ipv6 = false;
	bool active = false;

	DBG("service %p (%s) type %d (%s)",
		service, connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type));

	if (!service)
		goto done;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_ALL)
		do_ipv4 = do_ipv6 = true;
	else
		goto done;

	active = (do_ipv4 && service->online_check_state_ipv4.active) ||
			 (do_ipv6 && service->online_check_state_ipv6.active);

	DBG("active? %u", active);

 done:
	return active;
}

/**
 *  @brief
 *    Assign the "online" HTTP-based Internet reachability check
 *    active state.
 *
 *  This assigns the "online" HTTP-based Internet reachability check
 *  active state for the specified network service IP configuration
 *  type.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to assign the "online" HTTP-
 *                           based Internet reachability active
 *                           state.
 *  @param[in]      type     The IP configuration type for which to
 *                           assign the "online" HTTP-based Internet
 *                           reachability active state.
 *  @param[in]      active   The "online" HTTP-based Internet
 *                           reachability active state to assign.
 *
 *  @sa online_check_is_active
 *
 */
static void online_check_active_set_value(struct connman_service *service,
		enum connman_ipconfig_type type,
		bool active)
{
	bool do_ipv4 = false, do_ipv6 = false;

	DBG("service %p (%s) type %d (%s) active? %u",
		service, connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		active);

	if (!service)
		return;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_ALL)
		do_ipv4 = do_ipv6 = true;
	else
		return;

	if (do_ipv4)
		service->online_check_state_ipv4.active = active;

	if (do_ipv6)
		service->online_check_state_ipv6.active = active;
}

/**
 *  @brief
 *    Set, or assert, the "online" HTTP-based Internet reachability
 *    check active state.
 *
 *  This sets, or asserts, the "online" HTTP-based Internet
 *  reachability check active state for the specified network service
 *  IP configuration type.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to set the "online" HTTP-
 *                           based Internet reachability active
 *                           state.
 *  @param[in]      type     The IP configuration type for which to
 *                           set the "online" HTTP-based Internet
 *                           reachability active state.
 *
 *  @sa online_check_active_set_value
 *  @sa online_check_is_active
 *
 */
static void online_check_active_set(struct connman_service *service,
		enum connman_ipconfig_type type)
{
	online_check_active_set_value(service, type, true);
}

/**
 *  @brief
 *    Clear, or deassert, the "online" HTTP-based Internet
 *    reachability check active state.
 *
 *  This clears, or deasserts, the "online" HTTP-based Internet
 *  reachability check active state for the specified network service
 *  IP configuration type.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to clear the "online" HTTP-
 *                           based Internet reachability active
 *                           state.
 *  @param[in]      type     The IP configuration type for which to
 *                           clear the "online" HTTP-based Internet
 *                           reachability active state.
 *
 *  @sa online_check_active_set_value
 *  @sa online_check_is_active
 *
 */
static void online_check_active_clear(struct connman_service *service,
		enum connman_ipconfig_type type)
{
	online_check_active_set_value(service, type, false);
}

/**
 *  @brief
 *    Compute a Fibonacci online check timeout based on the specified
 *    interval.
 *
 *  This computes the Fibonacci online check timeout, in seconds,
 *  based on the specified interval in a Fibonacci series. For
 *  example, an interval of 9 yields a timeout of 34 seconds.
 *
 *  @note
 *    As compared to a geometric series, the Fibonacci series is
 *    slightly less aggressive in backing off up to the equivalence
 *    point at interval 12, but far more aggressive past that point,
 *    climbing to past an hour at interval 19 whereas the geometric
 *    series does not reach that point until interval 60.
 *
 *  @param[in]  interval  The interval in the geometric series for
 *                        which to compute the online check timeout.
 *
 *  @returns
 *    The timeout, in seconds, for the online check.
 *
 *  @sa online_check_timeout_compute_fibonacci
 *
 */
static guint online_check_timeout_compute_fibonacci(unsigned int interval)
{
	unsigned int i;
	guint first = 0;
	guint second = 1;
	guint timeout_seconds;

	for (i = 0; i <= interval; i++) {
		timeout_seconds = first;

		first = second;

		second = second + timeout_seconds;
	}

	return timeout_seconds;
}

/**
 *  @brief
 *    Compute a geometric online check timeout based on the specified
 *    interval.
 *
 *  This computes the geometric online check timeout, in seconds,
 *  based on the specified interval in a geometric series, where the
 *  resulting value is interval^2. For example, an interval of 9
 *  yields a timeout of 81 seconds.
 *
 *  @note
 *    As compared to a Fibonacci series, the geometric series is
 *    slightly more aggressive in backing off up to the equivalence
 *    point at interval 12, but far less aggressive past that point,
 *    only reaching an hour at interval 90 compared to interval 19 for
 *    Fibonacci for a similar timeout.
 *
 *  @param[in]  interval  The interval in the geometric series for
 *                        which to compute the online check timeout.
 *
 *  @returns
 *    The timeout, in seconds, for the online check.
 *
 *  @sa online_check_timeout_compute_fibonacci
 *
 */
static guint online_check_timeout_compute_geometric(unsigned int interval)
{
	const guint timeout_seconds = interval * interval;

	return timeout_seconds;
}

/**
 *  @brief
 *    Cancel any "online" HTTP-based Internet reachability checks for
 *    the specified network service IP configuration type.
 *
 *  This cancels any current or pending IPv4 and/or IPv6 "online"
 *  HTTP-based Internet reachability checks for the specified network
 *  service IP configuration type.
 *
 *  @note
 *    Any lingering WISPr portal reachability context will be lazily
 *    released at the start of the next online check for the service
 *    and replaced with new context.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which any current or pending IPv4 or
 *                           IPv6 "online" reachability checks should
 *                           be canceled.
 *  @param[in]      type     The IP configuration type for which the
 *                           "online" reachability check is to be
 *                           canceled.
 *
 *  @sa start_online_check
 *  @sa complete_online_check
 *  @sa __connman_wispr_start
 *  @sa __connman_wispr_stop
 *
 */
static void cancel_online_check(struct connman_service *service,
				enum connman_ipconfig_type type)
{
	bool do_ipv4 = false, do_ipv6 = false;

	DBG("service %p (%s) type %d (%s) "
		"online_timeout_ipv4 %d online_timeout_ipv6 %d",
		service, connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		service->online_check_state_ipv4.timeout,
		service->online_check_state_ipv6.timeout);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_ALL)
		do_ipv4 = do_ipv6 = true;
	else
		return;

	/*
	 * First, ensure that the reachability check(s) is/are cancelled
	 * in the WISPr module. This may fail, however, we ignore any such
	 * failures as we still want to cancel any outstanding check(s)
	 * from this module as well.
	 */

	if (do_ipv4)
		__connman_wispr_cancel(service, CONNMAN_IPCONFIG_TYPE_IPV4);

	if (do_ipv6)
		__connman_wispr_cancel(service, CONNMAN_IPCONFIG_TYPE_IPV6);

	/*
	 * Now that the reachability check(s) has/have been cancelled in
	 * the WISPr module, cancel any outstanding check(s) that may be
	 * scheduled in this module.
	 */
	if (do_ipv4 &&
		service->online_check_state_ipv4.timeout) {
		g_source_remove(service->online_check_state_ipv4.timeout);
		service->online_check_state_ipv4.timeout = 0;

		/*
		 * This balances the retained referece made when
		 * g_timeout_add_seconds was called to schedule this
		 * now-cancelled scheduled online check.
		 */
		connman_service_unref(service);
	}

	if (do_ipv6 &&
		service->online_check_state_ipv6.timeout) {
		g_source_remove(service->online_check_state_ipv6.timeout);
		service->online_check_state_ipv6.timeout = 0;

		/*
		 * This balances the retained referece made when
		 * g_timeout_add_seconds was called to schedule this
		 * now-cancelled scheduled online check.
		 */
		connman_service_unref(service);
	}

    /* Mark the online check state as inactive. */

	online_check_active_clear(service, type);
}

/**
 *  @brief
 *    Check whether an online check is enabled for the specified
 *    service.
 *
 *  This determines whether "online" HTTP-based Internet reachability
 *  checks are enabled for the specified network service. If not, an
 *  information-level message is logged.
 *
 *  @param[in]  service  A pointer to the immutable service for which
 *                       to determine whether "online" HTTP-based
 *                       Internet reachability checks are enabled.
 *
 *  @returns
 *    True if "online" HTTP-based Internet reachability * checks are
 *    enabled for the specified network service; otherwise, false.
 *
 *  @sa start_online_check
 *  @sa start_online_check_if_connected
 *
 */
static bool online_check_is_enabled_check(
		const struct connman_service *service)
{
	g_autofree char *interface = NULL;

	if (!__connman_service_is_online_check_enabled()) {
		interface = connman_service_get_interface(service);

		connman_info("Online check disabled; "
			"interface %s [ %s ] remains in %s state.",
			interface,
			__connman_service_type2string(service->type),
			state2string(CONNMAN_SERVICE_STATE_READY));

		return false;
	}

	return true;
}

/**
 *  @brief
 *    Start an "online" HTTP-based Internet reachability check for the
 *    specified network service IP configuration type.
 *
 *  This attempts to start an "online" HTTP-based Internet
 *  reachability check for the specified network service IP
 *  configuration type.
 *
 *  @note
 *    Any check is skipped, with an informational log message, if @a
 *    OnlineCheckMode is "none".
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to start the "online"
 *                           reachability check.
 *  @param[in]      type     The IP configuration type for which the
 *                           "online" reachability check is to be
 *                           started.
 *
 *  @retval  0          If successful.
 *  @retval  -EINVAL    If @a service is null or @a type is invalid.
 *  @retval  -EPERM     If online checks are disabled via
 *                      configuration.
 *  @retval  -EALREADY  If online checks are already active for @a
 *                      service.
 *
 *  @sa cancel_online_check
 *  @sa complete_online_check
 *  @sa start_online_check_if_connected
 *  @sa __connman_service_wispr_start
 *
 */
static int start_online_check(struct connman_service *service,
				enum connman_ipconfig_type type)
{
	int status = 0;

	DBG("service %p (%s) type %d (%s) maybe start WISPr",
		service,
		connman_service_get_identifier(service),
		type,
		__connman_ipconfig_type2string(type));

	if (!service) {
		status = -EINVAL;
		goto done;
	}

	if (!online_check_is_enabled_check(service)) {
		status = -EPERM;
		goto done;
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 || check_proxy_setup(service)) {
		cancel_online_check(service, type);

		status = __connman_service_wispr_start(service, type);
	}

done:
	DBG("status %d (%s)", status, strerror(-status));

	return status;
}

/**
 *  @brief
 *    Return the online check failures threshold state.
 *
 *  @param[in]  service  A pointer to the immutable service for which
 *                       to return the online check failures threshold
 *                       state.
 *
 *  @returns
 *    True if the online check failures threshold was met; otherwise,
 *    false.
 *
 *  @sa online_check_failures_threshold_was_met_set_value
 *  @sa online_check_failures_threshold_was_met_set
 *  @sa online_check_failures_threshold_was_met_clear
 *
 */
static bool online_check_failures_threshold_was_met(
			const struct connman_service *service)
{
	return service->online_check_failures_met_threshold;
}

/**
 *  @brief
 *    Set the online check failures threshold state to the specified
 *    value.
 *
 *  @param[in,out]  service  A pointer to the mutable service for which
 *                           to set the failures threshold state.
 *  @param[in]      value    The value to set the @a service failures
 *                           threshold state to.
 *
 *  @sa online_check_failures_threshold_was_met_set
 *  @sa online_check_failures_threshold_was_met_clear
 *
 */
static void online_check_failures_threshold_was_met_set_value(
			struct connman_service *service, bool value)
{
	DBG("service %p (%s) failures met threshold %u",
		service, connman_service_get_identifier(service),
		value);

	service->online_check_failures_met_threshold = value;
}

/**
 *  @brief
 *    Set (that is, assert) the online check failures threshold state.
 *
 *  @param[in,out]  service  A pointer to the mutable service for which
 *                           to set the failures threshold state.
 *
 *  @sa online_check_failures_threshold_was_met_set_value
 *  @sa online_check_failures_threshold_was_met_clear
 *
 */
static void online_check_failures_threshold_was_met_set(
			struct connman_service *service)
{
	online_check_failures_threshold_was_met_set_value(service, true);
}

/**
 *  @brief
 *    Clear (that is, deassert) the online check failures threshold
 *    state.
 *
 *  @param[in,out]  service  A pointer to the mutable service for which
 *                           to clear the failures threshold state.
 *
 *  @sa online_check_failures_threshold_was_met_set_value
 *  @sa online_check_failures_threshold_was_met_set
 *
 */
static void online_check_failures_threshold_was_met_clear(
			struct connman_service *service)
{
	online_check_failures_threshold_was_met_set_value(service, false);
}

/**
 *  Reset the specified counter to zero (0).
 *
 *  @param[in,out]  counter  A pointer to the counter to reset by
 *                           setting it to zero (0).
 *
 */
static inline void online_check_counter_reset(
			unsigned int *counter)
{
	if (!counter)
		return;

	*counter = 0;
}

/**
 *  @brief
 *    Reset to zero (0) the IPv4 and IPv6 online check failure
 *    counters for the specified service.
 *
 *  @param[in]   service   A pointer to the mutable service for which
 *                         to reset the IPv4 and IPv6 online check
 *                         failure counters.
 *
 *  @sa online_check_successes_reset
 *
 */
static void online_check_failures_reset(struct connman_service *service)
{
	DBG("service %p (%s)",
		service, connman_service_get_identifier(service));

	online_check_counter_reset(&service->online_check_state_ipv4.failures);
	online_check_counter_reset(&service->online_check_state_ipv6.failures);
}

/**
 *  @brief
 *    Reset to zero (0) the IPv4 and IPv6 online check success
 *    counters for the specified service.
 *
 *  @param[in]   service   A pointer to the mutable service for which
 *                         to reset the IPv4 and IPv6 online check
 *                         success counters.
 *
 *  @sa online_check_failures_reset
 *
 */
static void online_check_successes_reset(struct connman_service *service)
{
	DBG("service %p (%s)",
		service, connman_service_get_identifier(service));

	online_check_counter_reset(&service->online_check_state_ipv4.successes);
	online_check_counter_reset(&service->online_check_state_ipv6.successes);
}

/**
 *  @brief
 *    Reset the online check state for the specified service.
 *
 *  This resets the online check state for the specified service,
 *  including its failure threshold state, failure counters, and
 *  success counters.
 *
 *  @param[in]   service   A pointer to the mutable service for which
 *                         to reset the online check state.
 *
 *  @sa online_check_failures_reset
 *  @sa online_check_successes_reset
 *  @sa online_check_failures_threshold_was_met_clear
 *
 */
static void online_check_state_reset(struct connman_service *service)
{
	online_check_failures_reset(service);

	online_check_successes_reset(service);

	online_check_failures_threshold_was_met_clear(service);

	clear_error(service);
}

/**
 *  @brief
 *    Log the specified IPv4 and IPv6 online check counters for the
 *    specified service.
 *
 *  This logs the specified IPv4 and IPv6 online check counters
 *  described by the provided description for the specified network
 *  service.
 *
 *  @param[in]  service              A pointer to the immutable network
 *                                   service associated with @a
 *                                   ipv4_counter and @a ipv6_counter.
 *  @param[in]  counter_description  A pointer to a null-terminated C
 *                                   string describing @a ipv4_counter
 *                                   and @a ipv6_counter. For example,
 *                                   "failure".
 *  @param[in]  ipv4_counter         The IPv4-specific counter to log.
 *  @param[in]  ipv6_counter         The IPv6-specific counter to log.
 *
 */
static void online_check_counters_log(
			const struct connman_service *service,
			const char *counter_description,
			unsigned int ipv4_counter,
			unsigned int ipv6_counter)
{
	DBG("service %p (%s) "
		"ipv4 state %d (%s) %s(s/es) %u "
		"ipv6 state %d (%s) %s(s/es) %u ",
		service, connman_service_get_identifier(service),
		service->state_ipv4, state2string(service->state_ipv4),
		counter_description,
		ipv4_counter,
		service->state_ipv6, state2string(service->state_ipv6),
		counter_description,
		ipv6_counter);
}

/**
 *  @brief
 *    Determine whether an online check counter has met its threshold.
 *
 *  This determines whether an online check counter associated with
 *  the specified network service has met its threshold, where the
 *  threshold is accessed from the configuration store with the
 *  specified key.
 *
 *  @param[in]  service                A pointer to the immutable
 *                                     network service associated with
 *                                     the counter to check.
 *  @param[in]  counter_threshold_key  A pointer to a null-terminated
 *                                     C string containing the key to
 *                                     use with the configuration
 *                                     store to access the threshold
 *                                     value to check the counter
 *                                     against.
 *  @param[in]  counter_description    A pointer to a null-terminated
 *                                     C string describing the counter
 *                                     to check. For example, "failure".
 *  @param[in]  predicate              A pointer to the predicate
 *                                     function to invoke to make the
 *                                     actual determination of whether
 *                                     the counter has met the
 *                                     threshold accessed by @a
 *                                     counter_threshold_key.
 *
 *  @returns
 *    True if the counter has met the threshold; otherwise, false.
 *
 */
static bool online_check_counter_threshold_is_met(
			const struct connman_service *service,
			const char *counter_threshold_key,
			const char *counter_description,
			is_counter_threshold_met_predicate_t predicate)
{
	unsigned int counter_threshold;
	bool threshold_met = false;

	if (!service ||
		!counter_threshold_key ||
		!counter_description ||
		!predicate)
		goto done;

	counter_threshold = connman_setting_get_uint(counter_threshold_key);

	threshold_met = predicate(service,
						counter_description,
						counter_threshold);

	DBG("service %p (%s) %s threshold %u %s(s) met %u",
		service, connman_service_get_identifier(service),
		counter_description,
		counter_threshold,
		counter_description,
		threshold_met);

done:
	return threshold_met;
}

/**
 *  @brief
 *    Determine whether the service has met the online check failure
 *    threshold.
 *
 *  This predicate determines whether the online check failure
 *  threshold has been met by the specified network service.
 *
 *  @param[in]  service                A pointer to the immutable
 *                                     network service for which to
 *                                     check whether its has met the
 *                                     online check failure threshold.
 *  @param[in]  counter_description    A pointer to a null-terminated
 *                                     C string describing the failure
 *                                     counter. For example,
 *                                     "failure".
 *  @param[in]  counter_threshold      The threshold value to check the
 *                                     failure counter against.
 *
 *  @returns
 *    True if the online check failure counter has met the failure
 *    threshold; otherwise, false.
 *
 *  @sa online_check_failures_threshold_is_met
 *
 */
static bool is_online_check_failure_threshold_met_predicate(
			const struct connman_service *service,
			const char *counter_description,
			unsigned int counter_threshold)
{
	bool ipv4_is_connected;
	bool ipv6_is_connected;
	bool threshold_met = false;

	online_check_counters_log(service,
		counter_description,
		service->online_check_state_ipv4.failures,
		service->online_check_state_ipv6.failures);

	ipv4_is_connected = is_connected(service->state_ipv4);
	ipv6_is_connected = is_connected(service->state_ipv6);

	/*
	 * It is entirely possible that IPv4 reachability is fine and that
	 * IPv6 reachablity is not due to the premises ISP, premises
	 * Internet access equipment (that is, CPE), availability of the
	 * reachability endpoint infrastructure, etc.
	 *
	 * Consequently, we want to see bilateral failures of BOTH IPv4
	 * AND IPv6 in excess of the threshold, to the extent either is
	 * connected (based on the #is_connected predicate).
	 */
	if ((!ipv6_is_connected &&
		 ipv4_is_connected &&
		 service->online_check_state_ipv4.failures >=
		 counter_threshold) ||

		(!ipv4_is_connected &&
		ipv6_is_connected &&
		service->online_check_state_ipv6.failures >=
		counter_threshold) ||

		(ipv4_is_connected &&
		service->online_check_state_ipv4.failures >=
		counter_threshold &&
		ipv6_is_connected &&
		service->online_check_state_ipv6.failures >=
		counter_threshold)) {
		threshold_met = true;
	}

	return threshold_met;
}

/**
 *  @brief
 *    Determine whether the online check failures threshold is met.
 *
 *  This attempts to determine whether the online check failures
 *  threshold is met, comparing the current IPv4 and IPv6 online check
 *  failure counts against the "OnlineCheckFailuresThreshold" settings
 *  value and returning @a true if @b both the IPv4 and IPv6 counts
 *  meet or exceed the threshold.
 *
 *  @param[in]  service  A pointer to the immutable service for which
 *                       to determine whether the online check failure
 *                       threshold is met.
 *
 *  @returns
 *    True if the failure threshold is met; otherwise, false.
 *
 *  @sa online_check_successes_threshold_is_met
 *
 */
static bool online_check_failures_threshold_is_met(
			const struct connman_service *service)
{
	const char * const counter_threshold_key =
		"OnlineCheckFailuresThreshold";
	const char * const counter_description =
		"failure";

	return online_check_counter_threshold_is_met(service,
			counter_threshold_key,
			counter_description,
			is_online_check_failure_threshold_met_predicate);
}

/**
 *  @brief
 *    Determine whether the service has met the online check success
 *    threshold.
 *
 *  This predicate determines whether the online check success
 *  threshold has been met by the specified network service.
 *
 *  @param[in]  service                A pointer to the immutable
 *                                     network service for which to
 *                                     check whether its has met the
 *                                     online check success threshold.
 *  @param[in]  counter_description    A pointer to a null-terminated
 *                                     C string describing the success
 *                                     counter. For example,
 *                                     "success".
 *  @param[in]  counter_threshold      The threshold value to check the
 *                                     success counter against.
 *
 *  @returns
 *    True if the online check success counter has met the success
 *    threshold; otherwise, false.
 *
 *  @sa online_check_successes_threshold_is_met
 *
 */
static bool is_online_check_success_threshold_met_predicate(
			const struct connman_service *service,
			const char *counter_description,
			unsigned int counter_threshold)
{
	bool threshold_met = false;

	online_check_counters_log(service,
		counter_description,
		service->online_check_state_ipv4.successes,
		service->online_check_state_ipv6.successes);

	/*
	 * It is entirely possible that IPv4 reachability is fine and that
	 * IPv6 reachablity is not due to the premises ISP, premises
	 * Internet access equipment (that is, CPE), availability of the
	 * reachability endpoint infrastructure, etc.
	 *
	 * Consequently, we want to see bilateral successes of EITHER IPv4
	 * OR IPv6 (as with #combine_state) in excess of the threshold, to
	 * the extent either is connected (based on the #is_connected
	 * predicate).
	 */

	if ((is_connected(service->state_ipv4) &&
		service->online_check_state_ipv4.successes >=
		counter_threshold) ||
		(is_connected(service->state_ipv6) &&
		service->online_check_state_ipv6.successes >=
		counter_threshold)) {
		threshold_met = true;
	}

	return threshold_met;
}

/**
 *  @brief
 *    Determine whether the online check successes threshold is met.
 *
 *  This attempts to determine whether the online check successes
 *  threshold is met, comparing the current IPv4 and IPv6 online check
 *  success counts against the "OnlineCheckSuccessesThreshold" settings
 *  value and returning @a true if @b either the IPv4 @b or IPv6 counts
 *  meet or exceed the threshold.
 *
 *  @param[in]  service  A pointer to the immutable service for which
 *                       to determine whether the online check success
 *                       threshold is met.
 *
 *  @returns
 *    True if the success threshold is met; otherwise, false.
 *
 *  @sa online_check_failures_threshold_is_met
 *
 */
static bool online_check_successes_threshold_is_met(
			const struct connman_service *service)
{
	const char * const counter_threshold_key =
		"OnlineCheckSuccessesThreshold";
	const char * const counter_description =
		"success";

	return online_check_counter_threshold_is_met(service,
			counter_threshold_key,
			counter_description,
			is_online_check_success_threshold_met_predicate);
}

/**
 *  @brief
 *    Retry an "online" HTTP-based Internet reachability check.
 *
 *  This retries an "online" HTTP-based Internet reachability check
 *  for the specified network service IP configuration type.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which an "online" reachability check
 *                           should be retried.
 *  @param[in]      type     The IP configuration type for which an
 *                           "online" reachability check should be
 *                           retried.
 *
 *  @sa complete_online_check
 *  @sa redo_wispr_ipv4
 *  @sa redo_wispr_ipv6
 *
 */
static void redo_wispr(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	DBG("Retrying service %p (%s) type %d (%s) WISPr",
		service, connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type));

	__connman_wispr_start(service, type,
			online_check_connect_timeout_ms, complete_online_check);

	// Release the reference to the service taken when
	// g_timeout_add_seconds was invoked with the callback
	// that, in turn, invoked this function.

	connman_service_unref(service);
}

/**
 *  @brief
 *    Retry an "online" HTTP-based Internet reachability check
 *    callback.
 *
 *  This callback retries an IPv4 "online" HTTP-based Internet
 *  reachability check for the specified network service.
 *
 *  @param[in,out]  user_data  A pointer to the mutable network
 *                             service for which an IPv4 "online"
 *                             reachability check should be retried.
 *
 *  @returns
 *    FALSE (that is, G_SOURCE_REMOVE) unconditionally, indicating
 *    that the timeout source that triggered this callback should be
 *    removed on callback completion.
 *
 *  @sa complete_online_check
 *  @sa redo_wispr
 *  @sa redo_wispr_ipv6
 *
 */
static gboolean redo_wispr_ipv4(gpointer user_data)
{
	struct connman_service *service = user_data;

	service->online_check_state_ipv4.timeout = 0;

	redo_wispr(service, CONNMAN_IPCONFIG_TYPE_IPV4);

	return FALSE;
}

/**
 *  @brief
 *    Retry an "online" HTTP-based Internet reachability check
 *    callback.
 *
 *  This callback retries an IPv6 "online" HTTP-based Internet
 *  reachability check for the specified network service.
 *
 *  @param[in,out]  user_data  A pointer to the mutable network
 *                             service for which an IPv6 "online"
 *                             reachability check should be retried.
 *
 *  @returns
 *    FALSE (that is, G_SOURCE_REMOVE) unconditionally, indicating
 *    that the timeout source that triggered this callback should be
 *    removed on callback completion.
 *
 *  @sa complete_online_check
 *  @sa redo_wispr
 *  @sa redo_wispr_ipv4
 *
 */
static gboolean redo_wispr_ipv6(gpointer user_data)
{
	struct connman_service *service = user_data;

	service->online_check_state_ipv6.timeout = 0;

	redo_wispr(service, CONNMAN_IPCONFIG_TYPE_IPV6);

	return FALSE;
}

/**
 *  @brief
 *    Reschedule an "online" HTTP-based Internet reachability check
 *    for the specified network service IP configuration type.
 *
 *  This attempts to eschedule an "online" HTTP-based Internet
 *  reachability check for the specified network service IP
 *  configuration type with the provided interval and timeout
 *  identifier.
 *
 *  @param[in,out]  service             A pointer to the mutable
 *                                      network service for which to
 *                                      reschedule the "online"
 *                                      reachability check. On
 *                                      success, the service will have
 *                                      a reference retained that must
 *                                      be elsewhere released.
 *  @param[in]      type                The IP configuration type for
 *                                      which the "online"
 *                                      reachability check is to be
 *                                      rescheduled.
 *  @param[in,out]  online_check_state  A pointer to the mutable IP
 *                                      configuration type-specific
 *                                      "online" reachability check
 *                                      state associated with @a
 *                                      service and @a type. On
 *                                      success, the 'interval' field
 *                                      will be incremented by one (1)
 *                                      if it is less than the value
 *                                      of the @a
 *                                      OnlineCheckMaxInterval
 *                                      configuration setting and the
 *                                      'timeout' field this will be
 *                                      updated with the GLib main
 *                                      loop timer identifier
 *                                      associated with the
 *                                      rescheduled "online"
 *                                      HTTP-based Internet
 *                                      reachability check request.
 *
 *  @sa redo_wispr_ipv4
 *  @sa redo_wispr_ipv6
 *
 */
static void reschedule_online_check(struct connman_service *service,
			enum connman_ipconfig_type type,
			struct online_check_state *online_check_state)
{
	GSourceFunc redo_func;
	guint seconds;

	if (!service || !online_check_state)
		return;

	DBG("service %p (%s) type %d (%s) interval %u timeout %u",
		service,
		connman_service_get_identifier(service),
		type,
		__connman_ipconfig_type2string(type),
		online_check_state->interval,
		online_check_state->timeout);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		redo_func = redo_wispr_ipv4;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		redo_func = redo_wispr_ipv6;
	else
		return;

	DBG("updating online checkout timeout period");

	seconds = online_check_timeout_compute_func(
				online_check_state->interval);

	DBG("service %p (%s) type %d (%s) interval %u style \"%s\" seconds %u",
		service,
		connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		online_check_state->interval,
		online_check_timeout_interval_style,
		seconds);

	online_check_state->timeout = g_timeout_add_seconds(seconds,
				redo_func, connman_service_ref(service));

	/* Increment the interval for the next time, limiting to a maximum
	 * interval of @a online_check_max_interval.
	 */
	if (online_check_state->interval < online_check_max_interval)
		online_check_state->interval++;
}

/**
 *  @brief
 *    Increment and log the specified online check counter.
 *
 *  This increments by one (1) and logs the post-increment value of
 *  the specified online check counter associated with the specified
 *  network service.
 *
 *  @param[in]  service              A pointer to the immutable network
 *                                   service associated with @a
 *                                   counter.
 *  @param[in]  type                 The IP configuration type associated
 *                                   with @a counter.
 *  @param[in]  counter_description  A pointer to a null-terminated C
 *                                   string describing @a counter. For
 *                                   example, "failure".
 *
 */
static void online_check_counter_increment_and_log(
			const struct connman_service *service,
			enum connman_ipconfig_type type,
			const char *counter_description,
			unsigned int *counter)
{
	if (!service || !counter_description || !counter)
		return;

	(*counter)++;

	DBG("service %p (%s) type %d (%s) %s %u",
		service, connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		counter_description, *counter);
}

/**
 *  @brief
 *    Log an online check success.
 *
 *  This logs an online check success for the specified network
 *  service IP configuration type.
 *
 *  @param[in]  service  A pointer to the immutable network
 *                       service for which to log an online
 *                       check success.
 *  @param[in]  type     The IP configuration type for which
 *                       the online check was successful.
 *
 */
static void online_check_log_success(const struct connman_service *service,
			enum connman_ipconfig_type type)
{
	g_autofree char *interface = NULL;

	interface = connman_service_get_interface(service);

	connman_info("Interface %s [ %s ] %s online check to %s succeeded",
		interface,
		__connman_service_type2string(service->type),
		__connman_ipconfig_type2string(type),
		type == CONNMAN_IPCONFIG_TYPE_IPV4 ?
			connman_setting_get_string("OnlineCheckIPv4URL") :
			connman_setting_get_string("OnlineCheckIPv6URL"));
}

/**
 *  @brief
 *    Log that an online check counter has met its threshold.
 *
 *  This logs that an online check counter associated with the
 *  specified network service has met its threshold.
 *
 *  @param[in]  service                A pointer to the immutable
 *                                     network service for which to
 *                                     log that one of its online
 *                                     check counters has met its
 *                                     threshold.
 *  @param[in]  counter_threshold_key  A pointer to a null-terminated
 *                                     C string containing the key to
 *                                     use with the configuration
 *                                     store to access the threshold
 *                                     value for the counter.
 *  @param[in]  counter_description    A pointer to a null-terminated
 *                                     C string describing the counter
 *                                     to check. For example,
 *                                     "failure(s)".
 *
 */
static void continuous_online_check_log_counter_threshold_met(
			const struct connman_service *service,
			const char *counter_threshold_key,
			const char *counter_description)
{
	g_autofree char *interface = NULL;

	interface = connman_service_get_interface(service);

	connman_warn("Interface %s [ %s ] online check had %u back-to-back "
		"%s; %s threshold met",
		interface,
		__connman_service_type2string(service->type),
		connman_setting_get_uint(counter_threshold_key),
				 counter_description,
				 counter_description);
}

/**
 *  @brief
 *    Log that an online check success counter has met its threshold.
 *
 *  This logs that an online check success counter associated with the
 *  specified network service has met its threshold.
 *
 *  @param[in]  service                A pointer to the immutable
 *                                     network service for which to
 *                                     log that its online check
 *                                     success counter has met its
 *                                     threshold.
 *
 */
static void continuous_online_check_log_successes_threshold_met(
			const struct connman_service *service
)
{
	static const char *const counter_threshold_key =
		"OnlineCheckSuccessesThreshold";
	static const char *const counter_description =
		"success(es)";

	continuous_online_check_log_counter_threshold_met(service,
		counter_threshold_key,
		counter_description);
}

/**
 *  @brief
 *    Log that an online check failure counter has met its threshold.
 *
 *  This logs that an online check failure counter associated with the
 *  specified network service has met its threshold.
 *
 *  @param[in]  service                A pointer to the immutable
 *                                     network service for which to
 *                                     log that its online check
 *                                     failure counter has met its
 *                                     threshold.
 *
 */
static void continuous_online_check_log_failures_threshold_met(
			const struct connman_service *service
)
{
	static const char *const counter_threshold_key =
		"OnlineCheckFailuresThreshold";
	static const char *const counter_description =
		"failure(s)";

	continuous_online_check_log_counter_threshold_met(service,
		counter_threshold_key,
		counter_description);
}

/**
 *  @brief
 *    Handle the successful completion of an "online" HTTP-based
 *    Internet reachability check for the specified network service
 *    and IP configuration type for the "one-shot" online check mode.
 *
 *  This handles the completion of a successful "online" HTTP-based
 *  Internet reachability check for the specified network service and
 *  IP configuration type for the "one-shot" online check mode. This
 *  effectively "bookends" an earlier #__connman_service_wispr_start.
 *
 *  @param[in,out]  service             A pointer to the mutable service
 *                                      for which to handle a
 *                                      successful previously-requested
 *                                      online check.
 *  @param[in]      type                The IP configuration type for
 *                                      which to handle a successful
 *                                      previously-requested online
 *                                      check.
 *  @param[in,out]  online_check_state  A pointer to the online check
 *                                      state for @a service
 *                                      associated with @a type.
 *
 *  @returns
 *    False, unconditionally.
 *
 *  @sa handle_oneshot_online_check_failure
 *  @sa handle_online_check_success
 *
 */
static bool handle_oneshot_online_check_success(
			struct connman_service *service,
			enum connman_ipconfig_type type,
			struct online_check_state *online_check_state)
{
	const bool reschedule = true;

	/*
	 * Simply log the success, mark the service IP configuration state
	 * as ONLINE, and return.
	 */
	online_check_log_success(service, type);

	__connman_service_ipconfig_indicate_state(service,
		CONNMAN_SERVICE_STATE_ONLINE,
		type);

	return !reschedule;
}

/**
 *  @brief
 *    Handle the successful completion of an "online" HTTP-based
 *    Internet reachability check for the specified network service
 *    and IP configuration type for the "continuous" online check mode.
 *
 *  This handles the completion of a successful "online" HTTP-based
 *  Internet reachability check for the specified network service and
 *  IP configuration type for the "continuous" online check mode. This
 *  effectively "bookends" an earlier #__connman_service_wispr_start.
 *
 *  @param[in,out]  service             A pointer to the mutable service
 *                                      for which to handle a
 *                                      successful previously-requested
 *                                      online check.
 *  @param[in]      type                The IP configuration type for
 *                                      which to handle a successful
 *                                      previously-requested online
 *                                      check.
 *  @param[in,out]  online_check_state  A pointer to the online check
 *                                      state for @a service
 *                                      associated with @a type.
 *
 *  @returns
 *    True if another online check should be scheduled; otherwise,
 *    false.
 *
 *  @sa handle_continuous_online_check_failure
 *  @sa handle_online_check_success
 *
 */
static bool handle_continuous_online_check_success(
			struct connman_service *service,
			enum connman_ipconfig_type type,
			struct online_check_state *online_check_state)
{
	bool failures_threshold_was_met;
	bool successes_threshold_is_met;
	const bool reschedule = true;

	/* Unconditionally increment and log the success counter. */

	online_check_counter_increment_and_log(service, type,
		"successes", &online_check_state->successes);

	/*
	 * Ultimately, for failures, we are looking for a STRING of
	 * SUSTAINED, BACK-TO-BACK failures to meet the failures
	 * threshold. Consequently, any success should reset the
	 * corresponding failure count back to zero (0).
	 */
	online_check_counter_reset(&online_check_state->failures);

	failures_threshold_was_met =
		online_check_failures_threshold_was_met(service);
	successes_threshold_is_met =
		online_check_successes_threshold_is_met(service);

	DBG("failures threshold was met %u, "
		"successes threshold is met %u, "
		"default %u",
		failures_threshold_was_met,
		successes_threshold_is_met,
		connman_service_is_default(service));

	/*
	 * If the service HAD previously-exceeded the failure threshold
	 * AND if this is the first success, then reset the online check
	 * interval to the initial, minimum value since we want to recover
	 * as quickly as possible with a STRING of SUSTAINED, BACK-TO-BACK
	 * successes, where the length of that string is dictated by the
	 * "OnlineCheckSuccessesThreshold" settings value.
	 *
	 * Otherwise, if the service HAD NOT previously-exceeded the
	 * failure threshold OR if it HAD previously-exceeded the failure
	 * threshold AND the successes threshold was met, then reset the
	 * online check interval to the maximum value.
	 */
	if (failures_threshold_was_met &&
		online_check_state->successes == 1)
		online_check_state->interval = online_check_initial_interval;
	else if (!failures_threshold_was_met ||
		(failures_threshold_was_met && successes_threshold_is_met))
		online_check_state->interval = online_check_max_interval;

	/*
	 * If the service HAD NOT previously-exceeded the failure
	 * threshold, then simply mark the service IP configuration state
	 * as ONLINE.
	 *
	 * Otherwise, if the service HAD previously exceeded the failure
	 * threshold AND successes meet or exceed the configured success
	 * threshold, then re-sort the network services and update the
	 * gateways accordingly.
	 *
	 * The succeeding service will be promoted until such time as it
	 * has a configured number of failures, at which time, we will
	 * resort again.
	 *
	 */
	if (!failures_threshold_was_met) {
		if (online_check_state->successes == 1)
			online_check_log_success(service, type);

		if (connman_service_is_default(service))
			__connman_service_ipconfig_indicate_state(service,
				CONNMAN_SERVICE_STATE_ONLINE,
				type);
	} else if (failures_threshold_was_met &&
			   successes_threshold_is_met) {
		online_check_log_success(service, type);

		continuous_online_check_log_successes_threshold_met(service);

		online_check_state_reset(service);

		/*
		 * The ordering here is considered and intentional. FIRST, now
		 * that this service has cleared / reset the online check
		 * state, re-sort the service list. This may promote this
		 * service back to the default. SECOND, make the READY to
		 * ONLINE promotion, since that promotion is qualified with
		 * this service being the default (that is, has the default
		 * route) service.
		 */
		SERVICE_LIST_SORT();

		if (connman_service_is_default(service)) {
			__connman_service_ipconfig_indicate_state(
				service,
				CONNMAN_SERVICE_STATE_ONLINE,
				type);
		}

		__connman_gateway_update();
	}

	return reschedule;
}

/**
 *  @brief
 *    Handle the successful completion of an "online" HTTP-based
 *    Internet reachability check for the specified network service
 *    and IP configuration type.
 *
 *  This handles the completion of a successful "online" HTTP-based
 *  Internet reachability check for the specified network service and
 *  IP configuration type. This effectively "bookends" an earlier
 *  #__connman_service_wispr_start.
 *
 *  @param[in,out]  service             A pointer to the mutable service
 *                                      for which to handle a
 *                                      successful previously-requested
 *                                      online check.
 *  @param[in]      type                The IP configuration type for
 *                                      which to handle a successful
 *                                      previously-requested online
 *                                      check.
 *  @param[in,out]  online_check_state  A pointer to the online check
 *                                      state for @a service
 *                                      associated with @a type.
 *  @param[in]      oneshot             A Boolean indicating whether the
 *                                      online check mode is
 *                                      "one-shot" (true) or
 *                                      "continuous" (false).
 *
 *  @returns
 *    True if another online check should be scheduled; otherwise,
 *    false.
 *
 *  @sa handle_online_check_failure
 *  @sa handle_oneshot_online_check_success
 *  @sa handle_continuous_online_check_success
 *
 */
static bool handle_online_check_success(struct connman_service *service,
				enum connman_ipconfig_type type,
				struct online_check_state *online_check_state,
				bool oneshot)
{
	bool reschedule;

	DBG("service %p (%s) type %d (%s) "
		"one-shot %u\n",
		service,
		connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		oneshot);

	if (oneshot)
		reschedule = handle_oneshot_online_check_success(service,
						type,
						online_check_state);
	else
		reschedule = handle_continuous_online_check_success(service,
						type,
						online_check_state);

	return reschedule;
}

/**
 *  @brief
 *    Log an online check failure.
 *
 *  This logs an online check failure for the specified network
 *  service IP configuration type.
 *
 *  @param[in]  service  A pointer to the immutable network
 *                       service for which to log an online
 *                       check failure.
 *  @param[in]  type     The IP configuration type for which
 *                       the online check failed.
 *  @param[in]  err      The error status, in the POSIX domain,
 *                       associated with the online check failure.
 *
 */
static void online_check_log_failure(const struct connman_service *service,
			enum connman_ipconfig_type type,
			int err)
{
	g_autofree char *interface = NULL;

	interface = connman_service_get_interface(service);

	connman_warn("Interface %s [ %s ] %s online check to %s failed: %d: %s",
		interface,
		__connman_service_type2string(service->type),
		__connman_ipconfig_type2string(type),
		type == CONNMAN_IPCONFIG_TYPE_IPV4 ?
			connman_setting_get_string("OnlineCheckIPv4URL") :
			connman_setting_get_string("OnlineCheckIPv6URL"),
		err,
		strerror(-err));
}

/**
 *  @brief
 *    Handle the failed completion of an one-shot mode "online"
 *    HTTP-based Internet reachability check for the specified network
 *    service and IP configuration type for the "one-shot" online
 *    check mode.
 *
 *  This handles the completion of a failed one-shot mode "online"
 *  HTTP-based Internet reachability check for the specified network
 *  service and IP configuration type for the "one-shot" online check
 *  mode. This effectively "bookends" an earlier
 *  #__connman_service_wispr_start.
 *
 *  This simply indicates that rescheduling another check is desired.
 *
 *  @param[in,out]  service             A pointer to the mutable service
 *                                      for which to handle a
 *                                      failed previously-requested
 *                                      online check.
 *  @param[in]      type                The IP configuration type for
 *                                      which to handle a failed
 *                                      previously-requested online
 *                                      check.
 *  @param[in]      ipconfig_state      The current @a type IP
 *                                      configuration state for @a
 *                                      service.
 *  @param[in,out]  online_check_state  A pointer to the online check
 *                                      state for @a service
 *                                      associated with @a type.
 *  @param[in]      err                 The error status associated with
 *                                      the failed previously-requested
 *                                      online check. This is expected
 *                                      to be less than zero ('< 0').
 *
 *  @returns
 *    True, unconditionally.
 *
 *  @sa handle_online_check_failure
 *  @sa handle_oneshot_online_check_failure
 *
 */
static bool handle_oneshot_online_check_failure(
			struct connman_service *service,
			enum connman_ipconfig_type type,
			enum connman_service_state ipconfig_state,
			struct online_check_state *online_check_state,
			int err)
{
	const bool reschedule = true;

	/* Simply indicate rescheduling another check is desired. */

	DBG("online check mode is one-shot; requesting another check");

	return reschedule;
}

/**
 *  @brief
 *    Handle the failed completion of an one-shot mode "online"
 *    HTTP-based Internet reachability check for the specified network
 *    service and IP configuration type for the "continuous" online
 *    check mode.
 *
 *  This handles the completion of a failed continuous mode "online"
 *  HTTP-based Internet reachability check for the specified network
 *  service and IP configuration type for the "continuous" online check
 *  mode. This effectively "bookends" an earlier
 *  #__connman_service_wispr_start.
 *
 *  @param[in,out]  service             A pointer to the mutable service
 *                                      for which to handle a
 *                                      failed previously-requested
 *                                      online check.
 *  @param[in]      type                The IP configuration type for
 *                                      which to handle a failed
 *                                      previously-requested online
 *                                      check.
 *  @param[in]      ipconfig_state      The current @a type IP
 *                                      configuration state for @a
 *                                      service.
 *  @param[in,out]  online_check_state  A pointer to the online check
 *                                      state for @a service
 *                                      associated with @a type.
 *  @param[in]      err                 The error status associated with
 *                                      the failed previously-requested
 *                                      online check. This is expected
 *                                      to be less than zero ('< 0').
 *
 *  @returns
 *    True if another online check should be scheduled; otherwise,
 *    false.
 *
 *  @sa handle_online_check_failure
 *  @sa handle_continuous_online_check_failure
 *
 */
static bool handle_continuous_online_check_failure(
			struct connman_service *service,
			enum connman_ipconfig_type type,
			enum connman_service_state ipconfig_state,
			struct online_check_state *online_check_state,
			int err)
{
	bool reschedule = false;

	/* Unconditionally increment and log the failure counter. */

	online_check_counter_increment_and_log(service, type,
		"failures", &online_check_state->failures);

	/*
	 * Ultimately, for successes, we are looking for a STRING of
	 * SUSTAINED, BACK-TO-BACK successes to meet the successes
	 * threshold. Consequently, any failure should reset the
	 * corresponding success count back to zero (0).
	 */
	online_check_counter_reset(&online_check_state->successes);

	/*
	 * If this is the first failure, then reset the online check
	 * interval to the initial, minimum value. Subsequent failures
	 * will increment the interval on reschedule from here until the
	 * maximum interval is hit.
	 */
	if (online_check_state->failures == 1)
		online_check_state->interval = online_check_initial_interval;

	DBG("failures threshold was met %u failures threshold is met %u "
		"default %u",
		online_check_failures_threshold_was_met(service),
		online_check_failures_threshold_is_met(service),
		connman_service_is_default(service));

	/*
	 * If the service HAD NOT previously-exceeded the failure
	 * threshold AND failures meet or exceed the configured failure
	 * threshold, then:
	 *
	 *	  1. Assert the failure threshold state.
	 *	  2. Reset the success counters.
	 *	  3. Attempt to downgrade the service IP configuration state
	 *		 from ONLINE to READY.
	 *	  4. Re-sort the network services.
	 *	  5. Update the gateways accordingly.
	 *
	 * The failing service will be demoted until such time as it has a
	 * configured number of successes, at which time, we will resort
	 * again.
	 *
	 */
	if (!online_check_failures_threshold_was_met(service) &&
		online_check_failures_threshold_is_met(service)) {
		online_check_failures_threshold_was_met_set(service);

		continuous_online_check_log_failures_threshold_met(service);

		online_check_successes_reset(service);

		/*
		 * Attempt to downgrade the service state from ONLINE to
		 * READY.
		 *
		 * We attempt BOTH IPv4 and IPv6 IP configuration states since
		 * the #online_check_failures_threshold_is_met predicate tells
		 * us that both IP configurations have met the failures
		 * threshold.
		 */
		service_downgrade_online_state(service);

		set_error(service, CONNMAN_SERVICE_ERROR_ONLINE_CHECK_FAILED);

		SERVICE_LIST_SORT();

		__connman_gateway_update();
	}

	DBG("failures threshold was met %u, default %u",
		online_check_failures_threshold_was_met(service),
		connman_service_is_default(service));

	/*
	 * We only want to reschedule future online checks for
	 * the default service or those that are in failure.
	 */
	if (connman_service_is_default(service) ||
		online_check_failures_threshold_was_met(service))
		reschedule = true;

	return reschedule;
}

/**
 *  @brief
 *    Handle the failed completion of an "online" HTTP-based
 *    Internet reachability check for the specified network service
 *    and IP configuration type.
 *
 *  This handles the completion of a failed "online" HTTP-based
 *  Internet reachability check for the specified network service and
 *  IP configuration type. This effectively "bookends" an earlier
 *  #__connman_service_wispr_start.
 *
 *  @param[in,out]  service             A pointer to the mutable service
 *                                      for which to handle a
 *                                      failed previously-requested
 *                                      online check.
 *  @param[in]      type                The IP configuration type for
 *                                      which to handle a failed
 *                                      previously-requested online
 *                                      check.
 *  @param[in]      ipconfig_state      The current @a type IP
 *                                      configuration state for @a
 *                                      service.
 *  @param[in,out]  online_check_state  A pointer to the online check
 *                                      state for @a service
 *                                      associated with @a type.
 *  @param[in]      oneshot             A Boolean indicating whether the
 *                                      online check mode is
 *                                      "one-shot" (true) or
 *                                      "continuous" (false).
 *  @param[in]      err                 The error status associated with
 *                                      the failed previously-requested
 *                                      online check. This is expected
 *                                      to be less than zero ('< 0').
 *
 *  @returns
 *    True if another online check should be scheduled; otherwise,
 *    false.
 *
 *  @sa handle_online_check_success
 *  @sa handle_oneshot_online_check_failure
 *  @sa handle_continuous_online_check_failure
 *
 */
static bool handle_online_check_failure(struct connman_service *service,
				enum connman_ipconfig_type type,
				enum connman_service_state ipconfig_state,
				struct online_check_state *online_check_state,
				bool oneshot,
				int err)
{
	bool reschedule = false;

	DBG("service %p (%s) type %d (%s) state %d (%s) "
		"one-shot %u err %d (%s)\n",
		service,
		connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		ipconfig_state, state2string(ipconfig_state),
		oneshot, err, strerror(-err));

	/*
	 * Regardless of online check mode, if this completion closure
	 * was a failure with error status -ECANCELED, then it was canceled
	 * by #__connman_wispr_cancel. Simply ignore it and DO NOT indicate
	 * rescheduling another check is desired.
	 */
	if (err == -ECANCELED) {
		DBG("online check was canceled; no action taken");

		goto done;
	}

	/* Unconditionally log the failure, regardless of online check mode. */

	online_check_log_failure(service, type, err);

	/* Handle the failure according to the online check mode. */

	if (oneshot)
		reschedule = handle_oneshot_online_check_failure(
						service,
						type,
						ipconfig_state,
						online_check_state,
						err);
	else
		reschedule = handle_continuous_online_check_failure(
						service,
						type,
						ipconfig_state,
						online_check_state,
						err);

done:
	return reschedule;
}

/**
 *  @brief
 *    This completes an "online" HTTP-based Internet reachability
 *    check for the specified network service and IP configuration
 *    type.
 *
 *  This completes a failed or successful "online" HTTP-based Internet
 *  reachability check for the specified network service and IP
 *  configuration type. This effectively "bookends" an earlier
 *  #__connman_service_wispr_start.
 *
 *  If "OnlineCheckMode" is "one-shot" and if @a success is asserted,
 *  then the state for the specified IP configuration type is
 *  transitioned to "online" and a future online check is scheduled
 *  based on the current interval and the "OnlineCheckIntervalStyle"
 *  setting.
 *
 *  Otherwise, if "OnlineCheckMode" is "continuous", then counters are
 *  managed for the success or failure and state is managed and
 *  tracked resulting in the potential demotion of the service,
 *  placing it into a temporary failure state until such time as a
 *  series of back-to-back online checks successfully complete. If the
 *  service is a non-default after demotion and it is in failure state
 *  or if it is the default service, then a future online check is
 *  scheduled based on the current interval and the
 *  "OnlineCheckIntervalStyle" setting.
 *
 *  @param[in,out]  service  A pointer to the mutable service for which
 *                           to complete a previously-requested online
 *                           check.
 *  @param[in]      type     The IP configuration type for which to
 *                           complete a previously-requested online
 *                           check.
 *  @param[in]      success  A Boolean indicating whether the previously-
 *                           requested online check was successful.
 *  @param[in]      err      The error status associated with previously-
 *                           requested online check. This is expected
 *                           to be zero ('0') if @a success is @a true
 *                           and less than zero ('< 0') if @a success
 *                           is @a false.
 *
 *  @sa cancel_online_check
 *  @sa start_online_check
 *  @sa start_online_check_if_connected
 *  @sa __connman_service_wispr_start
 *  @sa handle_online_check_success
 *  @sa handle_online_check_failure
 *  @sa reschedule_online_check
 *
 */
static void complete_online_check(struct connman_service *service,
					enum connman_ipconfig_type type,
					bool success,
					int err)
{
	const bool oneshot = __connman_service_is_online_check_mode(
		CONNMAN_SERVICE_ONLINE_CHECK_MODE_ONE_SHOT);
	struct online_check_state *online_check_state;
	enum connman_service_state ipconfig_state;
	bool reschedule = false;

	DBG("service %p (%s) type %d (%s) "
		"success %u err %d (%s)\n",
		service,
		connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		success, err, strerror(-err));

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		online_check_state = &service->online_check_state_ipv4;
		ipconfig_state = service->state_ipv4;
	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		online_check_state = &service->online_check_state_ipv6;
		ipconfig_state = service->state_ipv6;
	} else
		return;

	if (success)
		reschedule = handle_online_check_success(service,
					 type,
					 online_check_state,
					 oneshot);
	else
		reschedule = handle_online_check_failure(service,
					 type,
					 ipconfig_state,
					 online_check_state,
					 oneshot,
					 err);

	DBG("reschedule online check %u", reschedule);

	if (reschedule)
		reschedule_online_check(service, type, online_check_state);
	else
		online_check_active_clear(service, type);
}

/**
 *  @brief
 *    Start HTTP-based Internet reachability probes if the specified
 *    service is connected.
 *
 *  This attempts to start IPv4 or IPv6 HTTP-based Internet
 *  reachability probes if the IPv4 state or IPv6 state is connected
 *  (that is, "ready" or "online") and if the online check state is
 *  not already active for the specified network service IP
 *  configuration type.
 *
 *  @param[in,out]  service  A pointer to a mutable service on which
 *                           to start "online" HTTP-based Internet
 *                           reachability checks if the IP
 *                           configuration state associated with @a
 *                           type is "connected" (that is, "ready" or
 *                           "online").
 *  @param[in]      type     The IP configuration type for which to
 *                           start the "online" HTTP-based Internet
 *                           reachability checks.
 *
 *  @retval  0          If successful.
 *  @retval  -EINVAL    If @a service is null or @a type is invalid.
 *  @retval  -EPERM     If online checks are disabled via
 *                      configuration.
 *  @retval  -ENOTCONN  If @a service is not "connected" (that is,
 *                      "ready" or "online").
 *  @retval  -EALREADY  If online checks are already active for @a
 *                      service.
 *
 *  @sa start_online_check
 *  @sa start_online_check_if_connected_with_type
 *
 */
static int start_online_check_if_connected_with_type(
					struct connman_service *service,
					enum connman_ipconfig_type type)
{
	int status = 0;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		break;
	default:
		return -EINVAL;
	}

	if (!__connman_service_is_connected_state(service, type))
		status = -ENOTCONN;
	else
		status = __connman_service_wispr_start(service, type);

	return status;
}

/**
 *  @brief
 *    Start HTTP-based Internet reachability probes if the specified
 *    service is connected.
 *
 *  This attempts to start IPv4 and/or IPv6 HTTP-based Internet
 *  reachability probes if the IPv4 state or IPv6 state is connected
 *  (that is, "ready" or "online").
 *
 *  @param[in,out]  service  A pointer to a mutable service on which
 *                           to start "online" HTTP-based Internet
 *                           reachability checks if the IPv4 or IPv6
 *                           state is "connected" (that is, "ready" or
 *                           "online").
 *
 *  @retval  0          If successful.
 *  @retval  -EINVAL    If @a service is null or @a type is invalid.
 *  @retval  -EPERM     If online checks are disabled via
 *                      configuration.
 *  @retval  -ENOTCONN  If @a service is not "connected" (that is,
 *                      "ready" or "online").
 *  @retval  -EALEADY   If online checks are already active for @a
 *                      service.
 *
 *  @sa start_online_check
 *  @sa start_online_check_if_connected_with_type
 *
 */
static int start_online_check_if_connected(struct connman_service *service)
{
	int status4 = 0, status6 = 0;

	DBG("service %p (%s) state4 %d (%s) state6 %d (%s) maybe start WISPr",
		service,
		connman_service_get_identifier(service),
		service->state_ipv4, state2string(service->state_ipv4),
		service->state_ipv6, state2string(service->state_ipv6));

	if (!service)
		return -EINVAL;

	if (!online_check_is_enabled_check(service))
		return -EPERM;

	status4 = start_online_check_if_connected_with_type(service,
			CONNMAN_IPCONFIG_TYPE_IPV4);

	status6 = start_online_check_if_connected_with_type(service,
			CONNMAN_IPCONFIG_TYPE_IPV6);

	DBG("status4 %d (%s) status6 %d (%s)",
		status4, strerror(-status4),
		status6, strerror(-status6));

	return (status4 < 0 ? status4 : status6);
}

/**
 *  @brief
 *    Start an "online" HTTP-based Internet reachability check for the
 *    specified network service IP configuration type.
 *
 *  This attempts to start an "online" HTTP-based Internet
 *  reachability check for the specified network service IP
 *  configuration type.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to start the "online"
 *                           reachability check.
 *  @param[in]      type     The IP configuration type for which the
 *                           "online" reachability check is to be
 *                           started.
 *
 *  @retval  0          If successful.
 *  @retval  -EINVAL    If @a service is null or @a type is invalid.
 *  @retval  -EALREADY  If online checks are already active for @a
 *                      service.
 *
 *  @sa cancel_online_check
 *  @sa start_online_check
 *  @sa complete_online_check
 *  @sa start_online_check_if_connected
 *
 */
int __connman_service_wispr_start(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	DBG("service %p (%s) type %d (%s)",
		service,
		connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type));

	if (!service)
		return -EINVAL;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		break;
	default:
		return -EINVAL;
	}

	if (online_check_is_active(service, type))
		return -EALREADY;

	/*
	 * At this particular entry point, we assume to be starting an
	 * "online" HTTP-based Internet reachability check
	 * afresh. Consequently, set the check interval to initial.
	 */
	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		service->online_check_state_ipv4.interval =
					online_check_initial_interval;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		service->online_check_state_ipv6.interval =
					online_check_initial_interval;

	__connman_wispr_start(service, type,
			online_check_connect_timeout_ms, complete_online_check);

	/* Mark the online check state as active. */

	online_check_active_set(service, type);

	return 0;
}

/**
 *  @brief
 *    Handle an update to the address(es) for the specified network
 *    service and IP configuration type.
 *
 *  This attempts to handle an address change or update for the
 *  specified network service and IP configuration type if and only if
 *  it is connected (that is, #is_connected returns true) and it is
 *  the default service (that is, has the default route).
 *
 *  If the service meets those criteria, then nameservers are
 *  refreshed, an "online" HTTP-based Internet reachability check is
 *  initiated, and a time-of-day synchronization is requested.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which there was an address change or
 *                           update.
 *  @param[in]      type     The IP configuration type for @a service
 *                           for which there was an address change or
 *                           update.
 *
 *  @sa nameserver_remove_all
 *  @sa nameserver_add_all
 *  @sa start_online_check
 *  @sa __connman_timeserver_sync
 *
 */
static void address_updated(struct connman_service *service,
			enum connman_ipconfig_type type)
{
	DBG("service %p (%s) type %d (%s)",
		service,
		connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type));

	if (is_connected(service->state) &&
			connman_service_is_default(service)) {
		nameserver_remove_all(service, type);
		nameserver_add_all(service, type);
		start_online_check(service, type);

		__connman_timeserver_sync(service,
				CONNMAN_TIMESERVER_SYNC_REASON_ADDRESS_UPDATE);
	}
}

static struct connman_stats *stats_get(struct connman_service *service)
{
	if (service->roaming)
		return &service->stats_roaming;
	else
		return &service->stats;
}

static bool stats_enabled(struct connman_service *service)
{
	struct connman_stats *stats = stats_get(service);

	return stats->enabled;
}

static void stats_start(struct connman_service *service)
{
	struct connman_stats *stats = stats_get(service);

	DBG("service %p", service);

	if (!stats->timer)
		return;

	stats->enabled = true;
	stats->data_last.time = stats->data.time;

	g_timer_start(stats->timer);
}

static void stats_stop(struct connman_service *service)
{
	struct connman_stats *stats = stats_get(service);
	unsigned int seconds;

	DBG("service %p", service);

	if (!stats->timer)
		return;

	if (!stats->enabled)
		return;

	g_timer_stop(stats->timer);

	seconds = g_timer_elapsed(stats->timer, NULL);
	stats->data.time = stats->data_last.time + seconds;

	stats->enabled = false;
}

static void reset_stats(struct connman_service *service)
{
	DBG("service %p", service);

	/* home */
	service->stats.valid = false;

	service->stats.data.rx_packets = 0;
	service->stats.data.tx_packets = 0;
	service->stats.data.rx_bytes = 0;
	service->stats.data.tx_bytes = 0;
	service->stats.data.rx_errors = 0;
	service->stats.data.tx_errors = 0;
	service->stats.data.rx_dropped = 0;
	service->stats.data.tx_dropped = 0;
	service->stats.data.time = 0;
	service->stats.data_last.time = 0;

	g_timer_reset(service->stats.timer);

	/* roaming */
	service->stats_roaming.valid = false;

	service->stats_roaming.data.rx_packets = 0;
	service->stats_roaming.data.tx_packets = 0;
	service->stats_roaming.data.rx_bytes = 0;
	service->stats_roaming.data.tx_bytes = 0;
	service->stats_roaming.data.rx_errors = 0;
	service->stats_roaming.data.tx_errors = 0;
	service->stats_roaming.data.rx_dropped = 0;
	service->stats_roaming.data.tx_dropped = 0;
	service->stats_roaming.data.time = 0;
	service->stats_roaming.data_last.time = 0;

	g_timer_reset(service->stats_roaming.timer);
}

/**
 *  @brief
 *    Return the default service, if any.
 *
 *  This attempts to return a pointer to the default service (that is,
 *  the service with the default route), if any.
 *
 *  @returns
 *    A pointer to the mutable default service, if one exists;
 *    otherwise, null.
 *
 */
struct connman_service *connman_service_get_default(void)
{
	struct connman_service *service;

	if (!service_list)
		return NULL;

	// Sorting is such that the default service is ALWAYS at the
	// head of the service list, if one exists.

	service = service_list->data;

	if (!is_connected(service->state))
		return NULL;

	return service;
}

/**
 *  @brief
 *    Determine whether the specified service is the default service.
 *
 *  This determines whether the specified service is the default
 *  service (that is, the service with the default route).
 *
 *  @param[in]  service  A pointer to the immutable service for which
 *                       to determine whether it is the default
 *                       network service.
 *  @returns
 *    True if the specified service is the default network service;
 *    otherwise, false.
 *
 *  @sa connman_service_get_default
 *
 */
static bool connman_service_is_default(const struct connman_service *service)
{
	if (!service)
		return false;

	return connman_service_get_default() == service;
}

/**
 *  @brief
 *    Determine whether the specified network interface index belongs
 *    to the default service.
 *
 *  This determines whether or not the specified network interface
 *  index belongs to the default service (that is, the service with
 *  the default route).
 *
 *  @param[in]  index  The network interface to determine whether it
 *                     belongs to the default service.
 *
 *  @returns
 *    True if the specified index belongs to the default service;
 *    otherwise, false.
 *
 *  @sa connman_service_get_default
 *  @sa __connman_service_get_index
 *
 */
bool __connman_service_index_is_default(int index)
{
	struct connman_service *service;

	if (index < 0)
		return false;

	service = connman_service_get_default();

	return __connman_service_get_index(service) == index;
}

static void service_log_default(const struct connman_service *service)
{
	g_autofree char *interface = NULL;

	interface = connman_service_get_interface(service);

	connman_info("Interface %s [ %s ] is the default",
		interface,
		__connman_service_type2string(service->type));
}

static void default_changed(const char *function)
{
	struct connman_service *service = connman_service_get_default();

	DBG("from %s()", function);

	if (service == current_default)
		return;

	DBG("current default %p (%s)", current_default,
		connman_service_get_identifier(current_default));
	DBG("new default %p (%s)", service, connman_service_get_identifier(service));

	__connman_service_timeserver_changed(current_default, NULL);

	/*
	 * If there is a current default service, then it may either have
	 * been temporarily:
	 *
	 *	 1. promoted as a failover from another senior service that
	 *		was temporarily demoted
	 *	 2. demoted as a failover to another junior service that is
	 *		being temporarily promoted
	 *
	 * due to a continuous mode online check failure.
	 *
	 * Regardless, only services in online check failure or the default
	 * service should be running online checks and only the default
	 * service should be online. Consequently, make the appropriate
	 * calls on the current default to ensure that is the case BEFORE
	 * assigning the proposed new default as the current default.
	 */
	if (current_default) {
		if (!online_check_failures_threshold_was_met(current_default) &&
			current_default->error !=
				CONNMAN_SERVICE_ERROR_ONLINE_CHECK_FAILED) {
			cancel_online_check(current_default,
				CONNMAN_IPCONFIG_TYPE_ALL);

			service_downgrade_online_state(current_default);
		}
	}

	current_default = service;

	if (service) {
		service_log_default(service);

		if (service->hostname &&
				connman_setting_get_bool("AllowHostnameUpdates"))
			__connman_utsname_set_hostname(service->hostname);

		if (service->domainname &&
				connman_setting_get_bool("AllowDomainnameUpdates"))
			__connman_utsname_set_domainname(service->domainname);

		start_online_check_if_connected(service);

		/*
		 * Connect VPN automatically when new default service
		 * is set and connected, unless new default is VPN
		 */
		if (is_connected(service->state) &&
				service->type != CONNMAN_SERVICE_TYPE_VPN) {
			DBG("running vpn_auto_connect");
			vpn_auto_connect();
		}
	}

	__connman_notifier_default_changed(service);
}

static void service_log_state(const struct connman_service *service)
{
	g_autofree char *interface = NULL;

	interface = connman_service_get_interface(service);

	connman_info("Interface %s [ %s ] state is %s",
		interface,
		__connman_service_type2string(service->type),
		state2string(service->state));
}

static void state_changed(struct connman_service *service)
{
	const char *str;

	service_log_state(service);

	__connman_notifier_service_state_changed(service, service->state);

	str = state2string(service->state);
	if (!str)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "State",
						DBUS_TYPE_STRING, &str);
}

static void strength_changed(struct connman_service *service)
{
	if (service->strength == 0)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Strength",
					DBUS_TYPE_BYTE, &service->strength);
}

static void favorite_changed(struct connman_service *service)
{
	dbus_bool_t favorite;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	favorite = service->favorite;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Favorite",
					DBUS_TYPE_BOOLEAN, &favorite);
}

static void immutable_changed(struct connman_service *service)
{
	dbus_bool_t immutable;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	immutable = service->immutable;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Immutable",
					DBUS_TYPE_BOOLEAN, &immutable);
}

static void roaming_changed(struct connman_service *service)
{
	dbus_bool_t roaming;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	roaming = service->roaming;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Roaming",
					DBUS_TYPE_BOOLEAN, &roaming);
}

static void autoconnect_changed(struct connman_service *service)
{
	dbus_bool_t autoconnect;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	autoconnect = service->autoconnect;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "AutoConnect",
				DBUS_TYPE_BOOLEAN, &autoconnect);
}

bool connman_service_set_autoconnect(struct connman_service *service,
							bool autoconnect)
{
	if (service->autoconnect == autoconnect)
		return false;

	service->autoconnect = autoconnect;
	autoconnect_changed(service);

	connman_network_set_autoconnect(service->network, autoconnect);

	return true;
}

static void append_security(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	const char *str;

	str = security2string(service->security);
	if (str)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);

	/*
	 * Some access points incorrectly advertise WPS even when they
	 * are configured as open or no security, so filter
	 * appropriately.
	 */
	if (service->wps) {
		switch (service->security) {
		case CONNMAN_SERVICE_SECURITY_PSK:
		case CONNMAN_SERVICE_SECURITY_WPA:
		case CONNMAN_SERVICE_SECURITY_RSN:
			str = "wps";
			dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &str);
			break;
		case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		case CONNMAN_SERVICE_SECURITY_NONE:
		case CONNMAN_SERVICE_SECURITY_WEP:
		case CONNMAN_SERVICE_SECURITY_8021X:
			break;
		}

		if (service->wps_advertizing) {
			str = "wps_advertising";
			dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &str);
		}
	}
}

static void security_changed(struct connman_service *service)
{
	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE, "Security",
				DBUS_TYPE_STRING, append_security, service);
}

static void append_ethernet(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (service->ipconfig_ipv4)
		__connman_ipconfig_append_ethernet(service->ipconfig_ipv4,
									iter);
	else if (service->ipconfig_ipv6)
		__connman_ipconfig_append_ethernet(service->ipconfig_ipv6,
									iter);
}

static void append_ipv4(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state_ipv4))
		return;

	if (service->ipconfig_ipv4)
		__connman_ipconfig_append_ipv4(service->ipconfig_ipv4, iter);
}

static void append_ipv6(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state_ipv6))
		return;

	if (service->ipconfig_ipv6)
		__connman_ipconfig_append_ipv6(service->ipconfig_ipv6, iter,
						service->ipconfig_ipv4);
}

static void append_ipv4config(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (service->ipconfig_ipv4)
		__connman_ipconfig_append_ipv4config(service->ipconfig_ipv4,
							iter);
}

static void append_ipv6config(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (service->ipconfig_ipv6)
		__connman_ipconfig_append_ipv6config(service->ipconfig_ipv6,
							iter);
}

static void append_nameservers(DBusMessageIter *iter,
		struct connman_service *service, char **servers)
{
	int i;
	bool available = true;

	for (i = 0; servers[i]; i++) {
		if (service)
			available = nameserver_available(service,
						CONNMAN_IPCONFIG_TYPE_ALL,
						servers[i]);

		if (available)
			dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &servers[i]);
	}
}

static void append_dns(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state))
		return;

	if (service->nameservers_config) {
		append_nameservers(iter, service, service->nameservers_config);
		return;
	} else {
		if (service->nameservers)
			append_nameservers(iter, service,
					service->nameservers);

		if (service->nameservers_auto)
			append_nameservers(iter, service,
					service->nameservers_auto);

		if (!service->nameservers && !service->nameservers_auto) {
			char **ns;

			DBG("append fallback nameservers");

			ns = connman_setting_get_string_list("FallbackNameservers");
			if (ns)
				append_nameservers(iter, service, ns);
		}
	}
}

static void append_dnsconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!service->nameservers_config)
		return;

	append_nameservers(iter, NULL, service->nameservers_config);
}

static void append_ts(DBusMessageIter *iter, void *user_data)
{
	GSList *list = user_data;

	while (list) {
		char *timeserver = list->data;

		if (timeserver)
			dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
					&timeserver);

		list = g_slist_next(list);
	}
}

static void append_tsconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->timeservers_config)
		return;

	for (i = 0; service->timeservers_config[i]; i++) {
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING,
				&service->timeservers_config[i]);
	}
}

static void append_domainconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->domains)
		return;

	for (i = 0; service->domains[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->domains[i]);
}

static void append_domain(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state) &&
				!is_connecting(service->state))
		return;

	if (service->domains)
		append_domainconfig(iter, user_data);
	else if (service->domainname)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->domainname);
}

static void append_proxies(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->proxies)
		return;

	for (i = 0; service->proxies[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->proxies[i]);
}

static void append_excludes(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->excludes)
		return;

	for (i = 0; service->excludes[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->excludes[i]);
}

static void append_proxy(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	enum connman_service_proxy_method proxy;
	const char *pac = NULL;
	const char *method = proxymethod2string(
		CONNMAN_SERVICE_PROXY_METHOD_DIRECT);

	if (!is_connected(service->state))
		return;

	proxy = connman_service_get_proxy_method(service);

	switch (proxy) {
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		return;
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		goto done;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		connman_dbus_dict_append_array(iter, "Servers",
					DBUS_TYPE_STRING, append_proxies,
					service);

		connman_dbus_dict_append_array(iter, "Excludes",
					DBUS_TYPE_STRING, append_excludes,
					service);
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		/* Maybe DHCP, or WPAD,  has provided an url for a pac file */
		if (service->ipconfig_ipv4)
			pac = __connman_ipconfig_get_proxy_autoconfig(
				service->ipconfig_ipv4);
		else if (service->ipconfig_ipv6)
			pac = __connman_ipconfig_get_proxy_autoconfig(
				service->ipconfig_ipv6);

		if (!service->pac && !pac)
			goto done;

		if (service->pac)
			pac = service->pac;

		connman_dbus_dict_append_basic(iter, "URL",
					DBUS_TYPE_STRING, &pac);
		break;
	}

	method = proxymethod2string(proxy);

done:
	connman_dbus_dict_append_basic(iter, "Method",
					DBUS_TYPE_STRING, &method);
}

static void append_proxyconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	const char *method;

	if (service->proxy_config == CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN)
		return;

	switch (service->proxy_config) {
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		return;
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		if (service->proxies)
			connman_dbus_dict_append_array(iter, "Servers",
						DBUS_TYPE_STRING,
						append_proxies, service);

		if (service->excludes)
			connman_dbus_dict_append_array(iter, "Excludes",
						DBUS_TYPE_STRING,
						append_excludes, service);
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		if (service->pac)
			connman_dbus_dict_append_basic(iter, "URL",
					DBUS_TYPE_STRING, &service->pac);
		break;
	}

	method = proxymethod2string(service->proxy_config);

	connman_dbus_dict_append_basic(iter, "Method",
				DBUS_TYPE_STRING, &method);
}

static void append_provider(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state))
		return;

	if (service->provider)
		__connman_provider_append_properties(service->provider, iter);
}


static void settings_changed(struct connman_service *service,
				struct connman_ipconfig *ipconfig)
{
	enum connman_ipconfig_type type;

	type = __connman_ipconfig_get_config_type(ipconfig);

	__connman_notifier_ipconfig_changed(service, ipconfig);

	if (!allow_property_changed(service))
		return;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "IPv4",
					append_ipv4, service);
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "IPv6",
					append_ipv6, service);
}

static void ipv4_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE,
							"IPv4.Configuration",
							append_ipv4config,
							service);
}

void __connman_service_notify_ipv4_configuration(
					struct connman_service *service)
{
	if (!service)
		return;

	ipv4_configuration_changed(service);
}

static void ipv6_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE,
							"IPv6.Configuration",
							append_ipv6config,
							service);
}

static void dns_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE, "Nameservers",
					DBUS_TYPE_STRING, append_dns, service);
}

static void dns_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE,
				"Nameservers.Configuration",
				DBUS_TYPE_STRING, append_dnsconfig, service);

	dns_changed(service);
}

static void domain_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE, "Domains",
				DBUS_TYPE_STRING, append_domain, service);
}

static void domain_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE,
				"Domains.Configuration",
				DBUS_TYPE_STRING, append_domainconfig, service);
}

static void proxy_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "Proxy",
							append_proxy, service);
}

static void proxy_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
			CONNMAN_SERVICE_INTERFACE, "Proxy.Configuration",
						append_proxyconfig, service);

	proxy_changed(service);
}

static void mdns_changed(struct connman_service *service)
{
	dbus_bool_t mdns = service->mdns;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
			CONNMAN_SERVICE_INTERFACE, "mDNS", DBUS_TYPE_BOOLEAN,
			&mdns);
}

static void mdns_configuration_changed(struct connman_service *service)
{
	dbus_bool_t mdns_config = service->mdns_config;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
			CONNMAN_SERVICE_INTERFACE, "mDNS.Configuration",
			DBUS_TYPE_BOOLEAN, &mdns_config);
}

static int set_mdns(struct connman_service *service,
			bool enabled)
{
	int result;

	result = __connman_resolver_set_mdns(
			__connman_service_get_index(service), enabled);

	if (result == 0) {
		if (service->mdns != enabled) {
			service->mdns = enabled;
			mdns_changed(service);
		}
	}

	return result;
}

static void timeservers_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
			CONNMAN_SERVICE_INTERFACE,
			"Timeservers.Configuration",
			DBUS_TYPE_STRING,
			append_tsconfig, service);
}

static void link_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "Ethernet",
						append_ethernet, service);
}

static void stats_append_counters(DBusMessageIter *dict,
			struct connman_stats_data *stats,
			struct connman_stats_data *counters,
			bool append_all)
{
	if (counters->rx_packets != stats->rx_packets || append_all) {
		counters->rx_packets = stats->rx_packets;
		connman_dbus_dict_append_basic(dict, "RX.Packets",
					DBUS_TYPE_UINT32, &stats->rx_packets);
	}

	if (counters->tx_packets != stats->tx_packets || append_all) {
		counters->tx_packets = stats->tx_packets;
		connman_dbus_dict_append_basic(dict, "TX.Packets",
					DBUS_TYPE_UINT32, &stats->tx_packets);
	}

	if (counters->rx_bytes != stats->rx_bytes || append_all) {
		counters->rx_bytes = stats->rx_bytes;
		connman_dbus_dict_append_basic(dict, "RX.Bytes",
					DBUS_TYPE_UINT32, &stats->rx_bytes);
	}

	if (counters->tx_bytes != stats->tx_bytes || append_all) {
		counters->tx_bytes = stats->tx_bytes;
		connman_dbus_dict_append_basic(dict, "TX.Bytes",
					DBUS_TYPE_UINT32, &stats->tx_bytes);
	}

	if (counters->rx_errors != stats->rx_errors || append_all) {
		counters->rx_errors = stats->rx_errors;
		connman_dbus_dict_append_basic(dict, "RX.Errors",
					DBUS_TYPE_UINT32, &stats->rx_errors);
	}

	if (counters->tx_errors != stats->tx_errors || append_all) {
		counters->tx_errors = stats->tx_errors;
		connman_dbus_dict_append_basic(dict, "TX.Errors",
					DBUS_TYPE_UINT32, &stats->tx_errors);
	}

	if (counters->rx_dropped != stats->rx_dropped || append_all) {
		counters->rx_dropped = stats->rx_dropped;
		connman_dbus_dict_append_basic(dict, "RX.Dropped",
					DBUS_TYPE_UINT32, &stats->rx_dropped);
	}

	if (counters->tx_dropped != stats->tx_dropped || append_all) {
		counters->tx_dropped = stats->tx_dropped;
		connman_dbus_dict_append_basic(dict, "TX.Dropped",
					DBUS_TYPE_UINT32, &stats->tx_dropped);
	}

	if (counters->time != stats->time || append_all) {
		counters->time = stats->time;
		connman_dbus_dict_append_basic(dict, "Time",
					DBUS_TYPE_UINT32, &stats->time);
	}
}

static void stats_append(struct connman_service *service,
				const char *counter,
				struct connman_stats_counter *counters,
				bool append_all)
{
	DBusMessageIter array, dict;
	DBusMessage *msg;

	DBG("service %p counter %s", service, counter);

	msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
	if (!msg)
		return;

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH,
				&service->path, DBUS_TYPE_INVALID);

	dbus_message_iter_init_append(msg, &array);

	/* home counter */
	connman_dbus_dict_open(&array, &dict);

	stats_append_counters(&dict, &service->stats.data,
				&counters->stats.data, append_all);

	connman_dbus_dict_close(&array, &dict);

	/* roaming counter */
	connman_dbus_dict_open(&array, &dict);

	stats_append_counters(&dict, &service->stats_roaming.data,
				&counters->stats_roaming.data, append_all);

	connman_dbus_dict_close(&array, &dict);

	__connman_counter_send_usage(counter, msg);
}

static void stats_update(struct connman_service *service,
				unsigned int rx_packets, unsigned int tx_packets,
				unsigned int rx_bytes, unsigned int tx_bytes,
				unsigned int rx_errors, unsigned int tx_errors,
				unsigned int rx_dropped, unsigned int tx_dropped)
{
	struct connman_stats *stats = stats_get(service);
	struct connman_stats_data *data_last = &stats->data_last;
	struct connman_stats_data *data = &stats->data;
	unsigned int seconds;

	DBG("service %p", service);

	if (stats->valid) {
		data->rx_packets +=
			rx_packets - data_last->rx_packets;
		data->tx_packets +=
			tx_packets - data_last->tx_packets;
		data->rx_bytes +=
			rx_bytes - data_last->rx_bytes;
		data->tx_bytes +=
			tx_bytes - data_last->tx_bytes;
		data->rx_errors +=
			rx_errors - data_last->rx_errors;
		data->tx_errors +=
			tx_errors - data_last->tx_errors;
		data->rx_dropped +=
			rx_dropped - data_last->rx_dropped;
		data->tx_dropped +=
			tx_dropped - data_last->tx_dropped;
	} else {
		stats->valid = true;
	}

	data_last->rx_packets = rx_packets;
	data_last->tx_packets = tx_packets;
	data_last->rx_bytes = rx_bytes;
	data_last->tx_bytes = tx_bytes;
	data_last->rx_errors = rx_errors;
	data_last->tx_errors = tx_errors;
	data_last->rx_dropped = rx_dropped;
	data_last->tx_dropped = tx_dropped;

	seconds = g_timer_elapsed(stats->timer, NULL);
	stats->data.time = stats->data_last.time + seconds;
}

void __connman_service_notify(struct connman_service *service,
			unsigned int rx_packets, unsigned int tx_packets,
			unsigned int rx_bytes, unsigned int tx_bytes,
			unsigned int rx_errors, unsigned int tx_errors,
			unsigned int rx_dropped, unsigned int tx_dropped)
{
	GHashTableIter iter;
	gpointer key, value;
	const char *counter;
	struct connman_stats_counter *counters;
	struct connman_stats_data *data;
	int err;

	if (!service)
		return;

	if (!is_connected(service->state))
		return;

	stats_update(service,
		rx_packets, tx_packets,
		rx_bytes, tx_bytes,
		rx_errors, tx_errors,
		rx_dropped, tx_dropped);

	data = &stats_get(service)->data;
	err = __connman_stats_update(service, service->roaming, data);
	if (err < 0)
		connman_error("Failed to store statistics for %s",
				service->identifier);

	g_hash_table_iter_init(&iter, service->counter_table);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		counter = key;
		counters = value;

		stats_append(service, counter, counters, counters->append_all);
		counters->append_all = false;
	}
}

int __connman_service_counter_register(const char *counter)
{
	struct connman_service *service;
	GList *list;
	struct connman_stats_counter *counters;

	DBG("counter %s", counter);

	counter_list = g_slist_prepend(counter_list, (gpointer)counter);

	for (list = service_list; list; list = list->next) {
		service = list->data;

		counters = g_try_new0(struct connman_stats_counter, 1);
		if (!counters)
			return -ENOMEM;

		counters->append_all = true;

		g_hash_table_replace(service->counter_table, (gpointer)counter,
					counters);
	}

	return 0;
}

void __connman_service_counter_unregister(const char *counter)
{
	struct connman_service *service;
	GList *list;

	DBG("counter %s", counter);

	for (list = service_list; list; list = list->next) {
		service = list->data;

		g_hash_table_remove(service->counter_table, counter);
	}

	counter_list = g_slist_remove(counter_list, counter);
}

int connman_service_iterate_services(connman_service_iterate_cb cb,
							void *user_data)
{
	GList *list;
	int ret = 0;

	for (list = service_list; list && ret == 0; list = list->next)
		ret = cb((struct connman_service *)list->data, user_data);

	return ret;
}

static void append_properties(DBusMessageIter *dict, dbus_bool_t limited,
					struct connman_service *service)
{
	dbus_bool_t val;
	const char *str;
	GSList *list;

	str = __connman_service_type2string(service->type);
	if (str)
		connman_dbus_dict_append_basic(dict, "Type",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_array(dict, "Security",
				DBUS_TYPE_STRING, append_security, service);

	str = state2string(service->state);
	if (str)
		connman_dbus_dict_append_basic(dict, "State",
						DBUS_TYPE_STRING, &str);

	str = error2string(service->error);
	if (str)
		connman_dbus_dict_append_basic(dict, "Error",
						DBUS_TYPE_STRING, &str);

	if (service->strength > 0)
		connman_dbus_dict_append_basic(dict, "Strength",
					DBUS_TYPE_BYTE, &service->strength);

	val = service->favorite;
	connman_dbus_dict_append_basic(dict, "Favorite",
					DBUS_TYPE_BOOLEAN, &val);

	val = service->immutable;
	connman_dbus_dict_append_basic(dict, "Immutable",
					DBUS_TYPE_BOOLEAN, &val);

	if (service->favorite)
		val = service->autoconnect;
	else
		val = service->favorite;

	connman_dbus_dict_append_basic(dict, "AutoConnect",
				DBUS_TYPE_BOOLEAN, &val);

	if (service->name)
		connman_dbus_dict_append_basic(dict, "Name",
					DBUS_TYPE_STRING, &service->name);

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		val = service->roaming;
		connman_dbus_dict_append_basic(dict, "Roaming",
					DBUS_TYPE_BOOLEAN, &val);

		connman_dbus_dict_append_dict(dict, "Ethernet",
						append_ethernet, service);
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_GADGET:
		connman_dbus_dict_append_dict(dict, "Ethernet",
						append_ethernet, service);
		break;
	}

	connman_dbus_dict_append_dict(dict, "IPv4", append_ipv4, service);

	connman_dbus_dict_append_dict(dict, "IPv4.Configuration",
						append_ipv4config, service);

	connman_dbus_dict_append_dict(dict, "IPv6", append_ipv6, service);

	connman_dbus_dict_append_dict(dict, "IPv6.Configuration",
						append_ipv6config, service);

	connman_dbus_dict_append_array(dict, "Nameservers",
				DBUS_TYPE_STRING, append_dns, service);

	connman_dbus_dict_append_array(dict, "Nameservers.Configuration",
				DBUS_TYPE_STRING, append_dnsconfig, service);

	if (is_connected(service->state))
		list = __connman_timeserver_get_all(service);
	else
		list = NULL;

	connman_dbus_dict_append_array(dict, "Timeservers",
				DBUS_TYPE_STRING, append_ts, list);

	g_slist_free_full(list, g_free);

	connman_dbus_dict_append_array(dict, "Timeservers.Configuration",
				DBUS_TYPE_STRING, append_tsconfig, service);

	connman_dbus_dict_append_array(dict, "Domains",
				DBUS_TYPE_STRING, append_domain, service);

	connman_dbus_dict_append_array(dict, "Domains.Configuration",
				DBUS_TYPE_STRING, append_domainconfig, service);

	connman_dbus_dict_append_dict(dict, "Proxy", append_proxy, service);

	connman_dbus_dict_append_dict(dict, "Proxy.Configuration",
						append_proxyconfig, service);

	val = service->mdns;
	connman_dbus_dict_append_basic(dict, "mDNS", DBUS_TYPE_BOOLEAN,
				&val);

	val = service->mdns_config;
	connman_dbus_dict_append_basic(dict, "mDNS.Configuration",
				DBUS_TYPE_BOOLEAN, &val);

	connman_dbus_dict_append_dict(dict, "Provider",
						append_provider, service);

	if (service->network)
		connman_network_append_acddbus(dict, service->network);
}

static void append_struct_service(DBusMessageIter *iter,
		connman_dbus_append_cb_t function,
		struct connman_service *service)
{
	DBusMessageIter entry, dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
							&service->path);

	connman_dbus_dict_open(&entry, &dict);
	if (function)
		function(&dict, service);
	connman_dbus_dict_close(&entry, &dict);

	dbus_message_iter_close_container(iter, &entry);
}

static void append_dict_properties(DBusMessageIter *dict, void *user_data)
{
	struct connman_service *service = user_data;

	append_properties(dict, TRUE, service);
}

static void append_struct(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	DBusMessageIter *iter = user_data;

	if (!service->path)
		return;

	append_struct_service(iter, append_dict_properties, service);
}

void __connman_service_list_struct(DBusMessageIter *iter)
{
	g_list_foreach(service_list, append_struct, iter);
}

bool __connman_service_is_hidden(const struct connman_service *service)
{
	return service->hidden;
}

bool
__connman_service_is_split_routing(const struct connman_service *service)
{
	return service->do_split_routing;
}

bool __connman_service_index_is_split_routing(int index)
{
	struct connman_service *service;

	if (index < 0)
		return false;

	service = __connman_service_lookup_from_index(index);
	if (!service)
		return false;

	return __connman_service_is_split_routing(service);
}

int __connman_service_get_index(const struct connman_service *service)
{
	if (!service)
		return -1;

	if (service->network)
		return connman_network_get_index(service->network);
	else if (service->provider)
		return connman_provider_get_index(service->provider);

	return -1;
}

void __connman_service_set_hidden(struct connman_service *service)
{
	if (!service || service->hidden)
		return;

	service->hidden_service = true;
}

void __connman_service_set_hostname(struct connman_service *service,
						const char *hostname)
{
	if (!service || service->hidden)
		return;

	g_free(service->hostname);
	service->hostname = NULL;

	if (hostname && g_str_is_ascii(hostname))
		service->hostname = g_strdup(hostname);
}

const char *__connman_service_get_hostname(const struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->hostname;
}

void __connman_service_set_domainname(struct connman_service *service,
						const char *domainname)
{
	if (!service || service->hidden)
		return;

	g_free(service->domainname);
	service->domainname = NULL;

	if (domainname && g_str_is_ascii(domainname))
		service->domainname = g_strdup(domainname);

	domain_changed(service);
}

const char *connman_service_get_domainname(const struct connman_service *service)
{
	if (!service)
		return NULL;

	if (service->domains)
		return service->domains[0];
	else
		return service->domainname;
}

const char *connman_service_get_dbuspath(const struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->path;
}

char **connman_service_get_nameservers(const struct connman_service *service)
{
	if (!service)
		return NULL;

	if (service->nameservers_config)
		return g_strdupv(service->nameservers_config);
	else if (service->nameservers ||
					service->nameservers_auto) {
		int len = 0, len_auto = 0, i;
		char **nameservers;

		if (service->nameservers)
			len = g_strv_length(service->nameservers);
		if (service->nameservers_auto)
			len_auto = g_strv_length(service->nameservers_auto);

		nameservers = g_try_new0(char *, len + len_auto + 1);
		if (!nameservers)
			return NULL;

		for (i = 0; i < len; i++)
			nameservers[i] = g_strdup(service->nameservers[i]);

		for (i = 0; i < len_auto; i++)
			nameservers[i + len] =
				g_strdup(service->nameservers_auto[i]);

		return nameservers;
	}

	return g_strdupv(connman_setting_get_string_list("FallbackNameservers"));
}

const char * const *connman_service_get_timeservers_config(const struct connman_service *service)
{
	if (!service)
		return NULL;

	return (const char * const *)service->timeservers_config;
}

const char * const *connman_service_get_timeservers(const struct connman_service *service)
{
	if (!service)
		return NULL;

	return (const char * const *)service->timeservers;
}

/**
 *  @brief
 *    Set the web proxy method of the specified service.
 *
 *  This attempts to set the web proxy method of the specified service
 *  but will fail to do so if @a service is null or is hidden.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to set the web proxy method.
 *  @param[in]      method   The web proxy method to set.
 *
 *  @sa proxy_changed
 *  @sa __connman_notifier_proxy_changed
 *
 */
void connman_service_set_proxy_method(struct connman_service *service,
					enum connman_service_proxy_method method)
{
	DBG("service %p (%s) method %d (%s)",
		service, connman_service_get_identifier(service),
		method, proxymethod2string(method));

	if (!service || service->hidden)
		return;

	service->proxy = method;

	proxy_changed(service);

	if (method != CONNMAN_SERVICE_PROXY_METHOD_AUTO)
		__connman_notifier_proxy_changed(service);
}

enum connman_service_proxy_method connman_service_get_proxy_method(
					const struct connman_service *service)
{
	if (!service)
		return CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;

	if (service->proxy_config != CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN) {
		if (service->proxy_config == CONNMAN_SERVICE_PROXY_METHOD_AUTO &&
				!service->pac)
			return service->proxy;

		return service->proxy_config;
	}

	return service->proxy;
}

char **connman_service_get_proxy_servers(struct connman_service *service)
{
	return g_strdupv(service->proxies);
}

char **connman_service_get_proxy_excludes(struct connman_service *service)
{
	return g_strdupv(service->excludes);
}

const char *connman_service_get_proxy_url(const struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->pac;
}

void __connman_service_set_proxy_autoconfig(struct connman_service *service,
							const char *url)
{
	if (!service || service->hidden)
		return;

	service->proxy = CONNMAN_SERVICE_PROXY_METHOD_AUTO;

	if (service->ipconfig_ipv4) {
		if (__connman_ipconfig_set_proxy_autoconfig(
			    service->ipconfig_ipv4, url) < 0)
			return;
	} else if (service->ipconfig_ipv6) {
		if (__connman_ipconfig_set_proxy_autoconfig(
			    service->ipconfig_ipv6, url) < 0)
			return;
	} else
		return;

	proxy_changed(service);

	__connman_notifier_proxy_changed(service);
}

const char *connman_service_get_proxy_autoconfig(struct connman_service *service)
{
	if (!service)
		return NULL;

	if (service->ipconfig_ipv4)
		return __connman_ipconfig_get_proxy_autoconfig(
						service->ipconfig_ipv4);
	else if (service->ipconfig_ipv6)
		return __connman_ipconfig_get_proxy_autoconfig(
						service->ipconfig_ipv6);
	return NULL;
}

void __connman_service_set_timeservers(struct connman_service *service,
				char **timeservers)
{
	int i;

	if (!service)
		return;

	g_strfreev(service->timeservers);
	service->timeservers = NULL;

	for (i = 0; timeservers && timeservers[i]; i++)
		__connman_service_timeserver_append(service, timeservers[i]);
}

int __connman_service_timeserver_append(struct connman_service *service,
						const char *timeserver)
{
	int len;

	DBG("service %p timeserver %s", service, timeserver);

	if (!timeserver)
		return -EINVAL;

	if (service->timeservers) {
		int i;

		for (i = 0; service->timeservers[i]; i++)
			if (g_strcmp0(service->timeservers[i], timeserver) == 0)
				return -EEXIST;

		len = g_strv_length(service->timeservers);
		service->timeservers = g_try_renew(char *, service->timeservers,
							len + 2);
	} else {
		len = 0;
		service->timeservers = g_try_new0(char *, len + 2);
	}

	if (!service->timeservers)
		return -ENOMEM;

	service->timeservers[len] = g_strdup(timeserver);
	service->timeservers[len + 1] = NULL;

	return 0;
}

int __connman_service_timeserver_remove(struct connman_service *service,
						const char *timeserver)
{
	char **servers;
	int len, i, j, found = 0;

	DBG("service %p timeserver %s", service, timeserver);

	if (!timeserver)
		return -EINVAL;

	if (!service->timeservers)
		return 0;

	for (i = 0; service->timeservers &&
					service->timeservers[i]; i++)
		if (g_strcmp0(service->timeservers[i], timeserver) == 0) {
			found = 1;
			break;
		}

	if (found == 0)
		return 0;

	len = g_strv_length(service->timeservers);

	if (len == 1) {
		g_strfreev(service->timeservers);
		service->timeservers = NULL;

		return 0;
	}

	servers = g_try_new0(char *, len);
	if (!servers)
		return -ENOMEM;

	for (i = 0, j = 0; i < len; i++) {
		if (g_strcmp0(service->timeservers[i], timeserver) != 0) {
			servers[j] = g_strdup(service->timeservers[i]);
			if (!servers[j]) {
				g_strfreev(servers);
				return -ENOMEM;
			}
			j++;
		}
	}
	servers[len - 1] = NULL;

	g_strfreev(service->timeservers);
	service->timeservers = servers;

	return 0;
}

void __connman_service_timeserver_changed(struct connman_service *service,
		GSList *ts_list)
{
	if (!service)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
			CONNMAN_SERVICE_INTERFACE, "Timeservers",
			DBUS_TYPE_STRING, append_ts, ts_list);
}

void __connman_service_set_pac(struct connman_service *service,
					const char *pac)
{
	if (service->hidden)
		return;
	g_free(service->pac);
	service->pac = g_strdup(pac);

	proxy_changed(service);
}

void __connman_service_set_agent_identity(struct connman_service *service,
						const char *agent_identity)
{
	if (service->hidden)
		return;
	g_free(service->agent_identity);
	service->agent_identity = g_strdup(agent_identity);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.AgentIdentity",
					service->agent_identity);
}

int __connman_service_check_passphrase(enum connman_service_security security,
		const char *passphrase)
{
	guint i;
	gsize length;

	if (!passphrase)
		return 0;

	length = strlen(passphrase);

	switch (security) {
	case CONNMAN_SERVICE_SECURITY_UNKNOWN:
	case CONNMAN_SERVICE_SECURITY_NONE:
	case CONNMAN_SERVICE_SECURITY_WPA:
	case CONNMAN_SERVICE_SECURITY_RSN:

		DBG("service security '%s' (%d) not handled",
				security2string(security), security);

		return -EOPNOTSUPP;

	case CONNMAN_SERVICE_SECURITY_PSK:
		/* A raw key is always 64 bytes length,
		 * its content is in hex representation.
		 * A PSK key must be between [8..63].
		 */
		if (length == 64) {
			for (i = 0; i < 64; i++)
				if (!isxdigit((unsigned char)
					      passphrase[i]))
					return -ENOKEY;
		} else if (length < 8 || length > 63)
			return -ENOKEY;
		break;
	case CONNMAN_SERVICE_SECURITY_WEP:
		/* length of WEP key is 10 or 26
		 * length of WEP passphrase is 5 or 13
		 */
		if (length == 10 || length == 26) {
			for (i = 0; i < length; i++)
				if (!isxdigit((unsigned char)
					      passphrase[i]))
					return -ENOKEY;
		} else if (length != 5 && length != 13)
			return -ENOKEY;
		break;

	case CONNMAN_SERVICE_SECURITY_8021X:
		break;
	}

	return 0;
}

int __connman_service_set_passphrase(struct connman_service *service,
					const char *passphrase)
{
	int err;

	if (service->hidden)
		return -EINVAL;

	if (service->immutable &&
			service->security != CONNMAN_SERVICE_SECURITY_8021X)
		return -EINVAL;

	err = __connman_service_check_passphrase(service->security, passphrase);

	if (err < 0)
		return err;

	g_free(service->passphrase);
	service->passphrase = g_strdup(passphrase);

	if (service->network)
		connman_network_set_string(service->network, "WiFi.Passphrase",
				service->passphrase);

	if (service->hidden_service &&
			service->error == CONNMAN_SERVICE_ERROR_INVALID_KEY)
		clear_error(service);

	return 0;
}

const char *__connman_service_get_passphrase(const struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->passphrase;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);
	append_properties(&dict, FALSE, service);
	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static char **remove_empty_strings(char **strv)
{
	int index = 0;
	char **iter = strv;

	while (*iter) {
		if (**iter)
			strv[index++] = *iter;
		else
			g_free(*iter);
		iter++;
	}

	strv[index] = NULL;
	return strv;
}

static int update_proxy_configuration(struct connman_service *service,
				DBusMessageIter *array)
{
	DBusMessageIter dict;
	enum connman_service_proxy_method method;
	GString *servers_str = NULL;
	GString *excludes_str = NULL;
	const char *url = NULL;

	method = CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key;
		int type;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto error;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto error;

		dbus_message_iter_recurse(&entry, &variant);

		type = dbus_message_iter_get_arg_type(&variant);

		if (g_str_equal(key, "Method")) {
			const char *val;

			if (type != DBUS_TYPE_STRING)
				goto error;

			dbus_message_iter_get_basic(&variant, &val);
			method = string2proxymethod(val);
		} else if (g_str_equal(key, "URL")) {
			if (type != DBUS_TYPE_STRING)
				goto error;

			dbus_message_iter_get_basic(&variant, &url);
		} else if (g_str_equal(key, "Servers")) {
			DBusMessageIter str_array;

			if (type != DBUS_TYPE_ARRAY)
				goto error;

			servers_str = g_string_new(NULL);
			if (!servers_str)
				goto error;

			dbus_message_iter_recurse(&variant, &str_array);

			while (dbus_message_iter_get_arg_type(&str_array) ==
							DBUS_TYPE_STRING) {
				char *val = NULL;

				dbus_message_iter_get_basic(&str_array, &val);

				if (servers_str->len > 0)
					g_string_append_printf(servers_str,
							" %s", val);
				else
					g_string_append(servers_str, val);

				dbus_message_iter_next(&str_array);
			}
		} else if (g_str_equal(key, "Excludes")) {
			DBusMessageIter str_array;

			if (type != DBUS_TYPE_ARRAY)
				goto error;

			excludes_str = g_string_new(NULL);
			if (!excludes_str)
				goto error;

			dbus_message_iter_recurse(&variant, &str_array);

			while (dbus_message_iter_get_arg_type(&str_array) ==
							DBUS_TYPE_STRING) {
				char *val = NULL;

				dbus_message_iter_get_basic(&str_array, &val);

				if (excludes_str->len > 0)
					g_string_append_printf(excludes_str,
							" %s", val);
				else
					g_string_append(excludes_str, val);

				dbus_message_iter_next(&str_array);
			}
		}

		dbus_message_iter_next(&dict);
	}

	switch (method) {
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		if (!servers_str && !service->proxies)
			goto error;

		if (servers_str) {
			g_strfreev(service->proxies);

			if (servers_str->len > 0) {
				char **proxies = g_strsplit_set(
					servers_str->str, " ", 0);
				proxies = remove_empty_strings(proxies);
				service->proxies = proxies;
			} else
				service->proxies = NULL;
		}

		if (excludes_str) {
			g_strfreev(service->excludes);

			if (excludes_str->len > 0) {
				char **excludes = g_strsplit_set(
					excludes_str->str, " ", 0);
				excludes = remove_empty_strings(excludes);
				service->excludes = excludes;
			} else
				service->excludes = NULL;
		}

		if (!service->proxies)
			method = CONNMAN_SERVICE_PROXY_METHOD_DIRECT;

		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		g_free(service->pac);

		if (url && strlen(url) > 0)
			service->pac = g_strstrip(g_strdup(url));
		else
			service->pac = NULL;

		/* if we are connected:
		   - if service->pac == NULL
		   - if __connman_ipconfig_get_proxy_autoconfig(
		   service->ipconfig) == NULL
		   --> We should start WPAD */

		break;
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		goto error;
	}

	if (servers_str)
		g_string_free(servers_str, TRUE);

	if (excludes_str)
		g_string_free(excludes_str, TRUE);

	service->proxy_config = method;

	return 0;

error:
	if (servers_str)
		g_string_free(servers_str, TRUE);

	if (excludes_str)
		g_string_free(excludes_str, TRUE);

	return -EINVAL;
}

static void do_auto_connect(struct connman_service *service,
	enum connman_service_connect_reason reason)
{
	/*
	 * CONNMAN_SERVICE_CONNECT_REASON_NONE must be ignored for VPNs. VPNs
	 * always have reason CONNMAN_SERVICE_CONNECT_REASON_USER/AUTO.
	 */
	if (!service || (service->type == CONNMAN_SERVICE_TYPE_VPN &&
				reason == CONNMAN_SERVICE_CONNECT_REASON_NONE))
		return;

	/*
	 * Only user interaction should get VPN or WIFI connected in failure
	 * state.
	 */
	if (service->state == CONNMAN_SERVICE_STATE_FAILURE &&
				reason != CONNMAN_SERVICE_CONNECT_REASON_USER &&
				(service->type == CONNMAN_SERVICE_TYPE_VPN ||
				service->type == CONNMAN_SERVICE_TYPE_WIFI))
		return;

	/*
	 * Do not use the builtin auto connect, instead rely on the
	 * native auto connect feature of the service.
	 */
	if (service->connect_reason == CONNMAN_SERVICE_CONNECT_REASON_NATIVE)
		return;

	/*
	 * Run service auto connect for other than VPN services. Afterwards
	 * start also VPN auto connect process.
	 */
	if (service->type != CONNMAN_SERVICE_TYPE_VPN)
		__connman_service_auto_connect(reason);

	vpn_auto_connect();
}

int __connman_service_reset_ipconfig(struct connman_service *service,
		enum connman_ipconfig_type type, DBusMessageIter *array,
		enum connman_service_state *new_state)
{
	struct connman_ipconfig *ipconfig, *new_ipconfig;
	enum connman_ipconfig_method old_method, new_method;
	enum connman_service_state state;
	int err = 0, index;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		ipconfig = service->ipconfig_ipv4;
		state = service->state_ipv4;
		new_method = CONNMAN_IPCONFIG_METHOD_DHCP;
	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		ipconfig = service->ipconfig_ipv6;
		state = service->state_ipv6;
		new_method = CONNMAN_IPCONFIG_METHOD_AUTO;
	} else
		return -EINVAL;

	if (!ipconfig)
		return -ENXIO;

	old_method = __connman_ipconfig_get_method(ipconfig);
	index = __connman_ipconfig_get_index(ipconfig);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		new_ipconfig = create_ip4config(service, index,
				CONNMAN_IPCONFIG_METHOD_UNKNOWN);
	else
		new_ipconfig = create_ip6config(service, index);

	if (array) {
		err = __connman_ipconfig_set_config(new_ipconfig, array);
		if (err < 0) {
			__connman_ipconfig_unref(new_ipconfig);
			return err;
		}

		new_method = __connman_ipconfig_get_method(new_ipconfig);
	}

	if (is_connecting(state) || is_connected(state))
		__connman_network_clear_ipconfig(service->network, ipconfig);

	__connman_ipconfig_unref(ipconfig);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		service->ipconfig_ipv4 = new_ipconfig;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		service->ipconfig_ipv6 = new_ipconfig;

	if (is_connecting(state) || is_connected(state))
		__connman_ipconfig_enable(new_ipconfig);

	if (new_state && new_method != old_method) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			*new_state = service->state_ipv4;
		else
			*new_state = service->state_ipv6;

		settings_changed(service, new_ipconfig);
		address_updated(service, type);

		do_auto_connect(service, CONNMAN_SERVICE_CONNECT_REASON_AUTO);
	}

	DBG("err %d ipconfig %p type %d method %d state %s", err,
		new_ipconfig, type, new_method,
		!new_state  ? "-" : state2string(*new_state));

	return err;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("service %p", service);

	if (!dbus_message_iter_init(msg, &iter))
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "AutoConnect")) {
		dbus_bool_t autoconnect;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		if (!service->favorite)
			return __connman_error_invalid_service(msg);

		dbus_message_iter_get_basic(&value, &autoconnect);

		if (autoconnect && service->type == CONNMAN_SERVICE_TYPE_VPN) {
			/*
			 * Changing the autoconnect flag on VPN to "on" should
			 * have the same effect as user connecting the VPN =
			 * clear previous error and change state to idle.
			 */
			clear_error(service);

			if (service->state == CONNMAN_SERVICE_STATE_FAILURE) {
				service->state = CONNMAN_SERVICE_STATE_IDLE;
				state_changed(service);
			}
		}

		if (connman_service_set_autoconnect(service, autoconnect)) {
			service_save(service);
			if (autoconnect)
				do_auto_connect(service,
					CONNMAN_SERVICE_CONNECT_REASON_AUTO);
		}
	} else if (g_str_equal(name, "Nameservers.Configuration")) {
		DBusMessageIter entry;
		GString *str;
		int index;
		const char *gw;

		if (__connman_provider_is_immutable(service->provider) ||
				service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (!str)
			return __connman_error_invalid_arguments(msg);

		index = __connman_service_get_index(service);
		gw = __connman_ipconfig_get_gateway_from_index(index,
			CONNMAN_IPCONFIG_TYPE_ALL);

		if (gw && strlen(gw))
			__connman_service_nameserver_del_routes(service,
						gw,
						CONNMAN_IPCONFIG_TYPE_ALL);

		dbus_message_iter_recurse(&value, &entry);

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;
			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);

			if (!val[0])
				continue;

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

		nameserver_remove_all(service, CONNMAN_IPCONFIG_TYPE_ALL);
		g_strfreev(service->nameservers_config);

		if (str->len > 0) {
			char **nameservers, **iter;

			nameservers = g_strsplit_set(str->str, " ", 0);

			for (iter = nameservers; *iter; iter++)
				if (connman_inet_check_ipaddress(*iter) <= 0)
					*iter[0] = '\0';

			nameservers = remove_empty_strings(nameservers);
			service->nameservers_config = nameservers;
		} else {
			service->nameservers_config = NULL;
		}

		g_string_free(str, TRUE);

		if (gw && strlen(gw))
			__connman_service_nameserver_add_routes(service, gw);

		nameserver_add_all(service, CONNMAN_IPCONFIG_TYPE_ALL);
		dns_configuration_changed(service);

		start_online_check_if_connected(service);

		service_save(service);
	} else if (g_str_equal(name, "Timeservers.Configuration")) {
		DBusMessageIter entry;
		GString *str;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (!str)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_recurse(&value, &entry);

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;
			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);

			if (!val[0])
				continue;

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

		g_strfreev(service->timeservers_config);
		service->timeservers_config = NULL;

		if (str->len > 0) {
			char **timeservers = g_strsplit_set(str->str, " ", 0);
			timeservers = remove_empty_strings(timeservers);
			service->timeservers_config = timeservers;
		}

		g_string_free(str, TRUE);

		service_save(service);
		timeservers_configuration_changed(service);
		__connman_timeserver_conf_update(service);

	} else if (g_str_equal(name, "Domains.Configuration")) {
		DBusMessageIter entry;
		GString *str;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (!str)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_recurse(&value, &entry);

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;
			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);

			if (!val[0])
				continue;

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

		searchdomain_remove_all(service);
		g_strfreev(service->domains);

		if (str->len > 0) {
			char **domains = g_strsplit_set(str->str, " ", 0);
			domains = remove_empty_strings(domains);
			service->domains = domains;
		} else
			service->domains = NULL;

		g_string_free(str, TRUE);

		searchdomain_add_all(service);
		domain_configuration_changed(service);
		domain_changed(service);

		service_save(service);
	} else if (g_str_equal(name, "Proxy.Configuration")) {
		int err;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		err = update_proxy_configuration(service, &value);

		if (err < 0)
			return __connman_error_failed(msg, -err);

		proxy_configuration_changed(service);

		__connman_notifier_proxy_changed(service);

		service_save(service);
	} else if (g_str_equal(name, "mDNS.Configuration")) {
		dbus_bool_t val;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &val);
		service->mdns_config = val;

		mdns_configuration_changed(service);

		set_mdns(service, service->mdns_config);

		service_save(service);
	} else if (g_str_equal(name, "IPv4.Configuration") ||
			g_str_equal(name, "IPv6.Configuration")) {

		enum connman_service_state state =
						CONNMAN_SERVICE_STATE_UNKNOWN;
		enum connman_ipconfig_type type =
			CONNMAN_IPCONFIG_TYPE_UNKNOWN;
		int err = 0;

		if (service->type == CONNMAN_SERVICE_TYPE_VPN ||
				service->immutable)
			return __connman_error_not_supported(msg);

		DBG("%s", name);

		if (!service->ipconfig_ipv4 &&
					!service->ipconfig_ipv6)
			return __connman_error_invalid_property(msg);

		if (g_str_equal(name, "IPv4.Configuration"))
			type = CONNMAN_IPCONFIG_TYPE_IPV4;
		else
			type = CONNMAN_IPCONFIG_TYPE_IPV6;

		err = __connman_service_reset_ipconfig(service, type, &value,
								&state);

		if (err < 0) {
			if (is_connected(state) || is_connecting(state)) {
				if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
					__connman_network_enable_ipconfig(service->network,
							service->ipconfig_ipv4);
				else
					__connman_network_enable_ipconfig(service->network,
							service->ipconfig_ipv6);
			}

			return __connman_error_failed(msg, -err);
		}

		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			ipv4_configuration_changed(service);
		else
			ipv6_configuration_changed(service);

		if (is_connecting(service->state) ||
				is_connected(service->state)) {
			if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
				__connman_network_enable_ipconfig(service->network,
								service->ipconfig_ipv4);
			else
				__connman_network_enable_ipconfig(service->network,
								service->ipconfig_ipv6);
		}

		service_save(service);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void service_log_error(const struct connman_service *service,
					enum connman_service_error error)
{
	g_autofree char *interface = NULL;

	interface = connman_service_get_interface(service);

	connman_warn("Interface %s [ %s ] error \"%s\"",
		interface,
		__connman_service_type2string(service->type),
		error2string(error));
}

/**
 *  @brief
 *    Set the specified network service "Error" property.
 *
 *  This sets the specified network service "Error" property to the
 *  provided value.
 *
 *  @note
 *    This function results in a D-Bus property changed signal for the
 *    network service "Error" property.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to set the "Error" property.
 *  @param[in]      error    The error value to set.
 *
 *  @sa clear_error
 *
 */
static void set_error(struct connman_service *service,
					enum connman_service_error error)
{
	const char *str = error2string(error);

	if (!str)
		str = "";

	DBG("service %p (%s) error %d (%s)",
		service, connman_service_get_identifier(service),
		error, str);

	if (service->error == error)
		return;

	service->error = error;

	if (!service->path)
		return;

	if (error != CONNMAN_SERVICE_ERROR_UNKNOWN)
		service_log_error(service, error);

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Error",
				DBUS_TYPE_STRING, &str);
}

/**
 *  @brief
 *    Clear or reset the specified network service "Error" property.
 *
 *  This sets the specified network service "Error" property to the
 *  initialization value of #CONNMAN_SERVICE_ERROR_UNKNOWN,
 *  effectively clearing or resetting the property.
 *
 *  @note
 *    This function results in a D-Bus property changed signal for the
 *    network service "Error" property.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to clear or reset the "Error"
 *                           property.
 *
 *  @sa set_error
 *
 */
static void clear_error(struct connman_service *service)
{
	set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);
}

static void remove_timeout(struct connman_service *service)
{
	if (service->timeout > 0) {
		g_source_remove(service->timeout);
		service->timeout = 0;
	}
}

static void reply_pending(struct connman_service *service, int error)
{
	remove_timeout(service);

	if (service->pending) {
		connman_dbus_reply_pending(service->pending, error, NULL);
		service->pending = NULL;
	}
}

static void service_complete(struct connman_service *service)
{
	reply_pending(service, EIO);

	if (service->connect_reason != CONNMAN_SERVICE_CONNECT_REASON_USER)
		do_auto_connect(service, service->connect_reason);

	gettimeofday(&service->modified, NULL);
	service_save(service);
}

static DBusMessage *clear_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	const char *name;

	DBG("service %p", service);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);

	if (g_str_equal(name, "Error")) {
		clear_error(service);

		__connman_service_clear_error(service);
		service_complete(service);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static bool is_ipconfig_usable(struct connman_service *service)
{
	if (!__connman_ipconfig_is_usable(service->ipconfig_ipv4) &&
			!__connman_ipconfig_is_usable(service->ipconfig_ipv6))
		return false;

	return true;
}

static bool is_ignore(struct connman_service *service)
{
	if (!service->autoconnect)
		return true;

	if (service->roaming &&
		!connman_setting_get_bool("AutoConnectRoamingServices"))
		return true;

	if (service->ignore)
		return true;

	if (service->state == CONNMAN_SERVICE_STATE_FAILURE)
		return true;

	if (!is_ipconfig_usable(service))
		return true;

	return false;
}

static void disconnect_on_last_session(enum connman_service_type type)
{
	GList *list;

	for (list = service_list; list; list = list->next) {
		struct connman_service *service = list->data;

		if (service->type != type)
			continue;

		if (service->connect_reason != CONNMAN_SERVICE_CONNECT_REASON_SESSION)
			 continue;

		__connman_service_disconnect(service);
		return;
	}
}

static int active_sessions[MAX_CONNMAN_SERVICE_TYPES] = {};
static int always_connect[MAX_CONNMAN_SERVICE_TYPES] = {};
static int active_count = 0;

void __connman_service_set_active_session(bool enable, GSList *list)
{
	if (!list)
		return;

	if (enable)
		active_count++;
	else
		active_count--;

	while (list) {
		enum connman_service_type type = GPOINTER_TO_INT(list->data);

		switch (type) {
		case CONNMAN_SERVICE_TYPE_ETHERNET:
		case CONNMAN_SERVICE_TYPE_WIFI:
		case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		case CONNMAN_SERVICE_TYPE_CELLULAR:
		case CONNMAN_SERVICE_TYPE_GADGET:
			if (enable)
				active_sessions[type]++;
			else
				active_sessions[type]--;
			break;

		case CONNMAN_SERVICE_TYPE_UNKNOWN:
		case CONNMAN_SERVICE_TYPE_SYSTEM:
		case CONNMAN_SERVICE_TYPE_GPS:
		case CONNMAN_SERVICE_TYPE_VPN:
		case CONNMAN_SERVICE_TYPE_P2P:
			break;
		}

		if (active_sessions[type] == 0)
			disconnect_on_last_session(type);

		list = g_slist_next(list);
	}

	DBG("eth %d wifi %d bt %d cellular %d gadget %d sessions %d",
			active_sessions[CONNMAN_SERVICE_TYPE_ETHERNET],
			active_sessions[CONNMAN_SERVICE_TYPE_WIFI],
			active_sessions[CONNMAN_SERVICE_TYPE_BLUETOOTH],
			active_sessions[CONNMAN_SERVICE_TYPE_CELLULAR],
			active_sessions[CONNMAN_SERVICE_TYPE_GADGET],
			active_count);
}

struct preferred_tech_data {
	GList *preferred_list;
	enum connman_service_type type;
};

static void preferred_tech_add_by_type(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;
	struct preferred_tech_data *tech_data = user_data;

	if (service->type == tech_data->type) {
		tech_data->preferred_list =
			g_list_append(tech_data->preferred_list, service);

		DBG("type %d service %p %s", tech_data->type, service,
				service->name);
	}
}

static GList *preferred_tech_list_get(void)
{
	unsigned int *tech_array;
	struct preferred_tech_data tech_data = { 0, };
	int i;

	tech_array = connman_setting_get_uint_list("PreferredTechnologies");
	if (!tech_array)
		return NULL;

	if (connman_setting_get_bool("SingleConnectedTechnology")) {
		GList *list;
		for (list = service_list; list; list = list->next) {
			struct connman_service *service = list->data;

			if (!is_connected(service->state))
				break;

			if (service->connect_reason ==
					CONNMAN_SERVICE_CONNECT_REASON_USER) {
				DBG("service %p name %s is user connected",
						service, service->name);
				return NULL;
			}
		}
	}

	for (i = 0; tech_array[i] != 0; i += 1) {
		tech_data.type = tech_array[i];
		g_list_foreach(service_list, preferred_tech_add_by_type,
				&tech_data);
	}

	return tech_data.preferred_list;
}

static void set_always_connecting_technologies()
{
	unsigned int *always_connected_techs =
		connman_setting_get_uint_list("AlwaysConnectedTechnologies");
	int i;
	for (i = 0; always_connected_techs && always_connected_techs[i]; i++)
		always_connect[always_connected_techs[i]] = 1;
}

static bool autoconnect_no_session_active(struct connman_service *service)
{
	/*
	 * Test active_count to see if there are no sessions set up and
	 * stop autoconnecting, but continue connecting if the service
	 * belongs to a technology which should always autoconnect.
	 */
	if (!active_count && !always_connect[service->type])
		return true;

	return false;
}

static bool autoconnect_already_connecting(struct connman_service *service,
					   bool autoconnecting)
{
	/*
	 * If another service is already connecting and this service type has
	 * not been marked as always connecting, stop the connecting procedure.
	 */
	if (autoconnecting &&
			!active_sessions[service->type] &&
			!always_connect[service->type])
		return true;

	return false;
}

static int service_indicate_state(struct connman_service *service);

static bool auto_connect_service(GList *services,
				enum connman_service_connect_reason reason,
				bool preferred)
{
	struct connman_service *service = NULL;
	bool ignore[MAX_CONNMAN_SERVICE_TYPES] = { };
	bool autoconnecting = false;
	GList *list;
	int index;

	DBG("preferred %d sessions %d reason %s", preferred, active_count,
		reason2string(reason));

	ignore[CONNMAN_SERVICE_TYPE_VPN] = true;

	for (list = services; list; list = list->next) {
		service = list->data;

		if (ignore[service->type]) {
			DBG("service %p type %s ignore", service,
				__connman_service_type2string(service->type));
			continue;
		}

		if (service->connect_reason ==
				CONNMAN_SERVICE_CONNECT_REASON_NATIVE) {
			DBG("service %p uses native autonnect, skip", service);
			continue;
		}

		index = __connman_service_get_index(service);
		if (g_hash_table_lookup(passphrase_requested,
					GINT_TO_POINTER(index)))
			return true;

		if (service->pending ||
				is_connecting(service->state) ||
				is_connected(service->state)) {
			if (autoconnect_no_session_active(service))
					return true;

			ignore[service->type] = true;
			autoconnecting = true;

			DBG("service %p type %s busy", service,
				__connman_service_type2string(service->type));

			continue;
		}

		if (!service->favorite) {
			if (preferred)
			       continue;

			return autoconnecting;
		}

		if (is_ignore(service) || service->state !=
				CONNMAN_SERVICE_STATE_IDLE)
			continue;

		if (autoconnect_already_connecting(service, autoconnecting)) {
			DBG("service %p type %s has no users", service,
				__connman_service_type2string(service->type));
			continue;
		}

		DBG("service %p %s %s", service, service->name,
			(preferred) ? "preferred" : reason2string(reason));

		if (__connman_service_connect(service, reason) == 0)
			service_indicate_state(service);

		if (autoconnect_no_session_active(service))
			return true;

		ignore[service->type] = true;
	}

	return autoconnecting;
}

static gboolean run_auto_connect(gpointer data)
{
	enum connman_service_connect_reason reason = GPOINTER_TO_UINT(data);
	bool autoconnecting = false;
	GList *preferred_tech;

	autoconnect_id = 0;

	DBG("");

	preferred_tech = preferred_tech_list_get();
	if (preferred_tech) {
		autoconnecting = auto_connect_service(preferred_tech, reason,
							true);
		g_list_free(preferred_tech);
	}

	if (!autoconnecting || active_count)
		auto_connect_service(service_list, reason, false);

	return FALSE;
}

void __connman_service_auto_connect(enum connman_service_connect_reason reason)
{
	DBG("");

	if (autoconnect_id != 0)
		return;

	if (!__connman_session_policy_autoconnect(reason))
		return;

	autoconnect_id = g_idle_add(run_auto_connect,
						GUINT_TO_POINTER(reason));
}

static gboolean run_vpn_auto_connect(gpointer data) {
	GList *list;
	bool need_split = false;
	bool autoconnectable_vpns = false;
	int attempts = 0;
	int timeout = VPN_AUTOCONNECT_TIMEOUT_DEFAULT;
	struct connman_service *def_service;

	attempts = GPOINTER_TO_INT(data);
	def_service = connman_service_get_default();

	/*
	 * Stop auto connecting VPN if there is no transport service or the
	 * transport service is not connected or if the  current default service
	 * is a connected VPN (in ready state).
	 */
	if (!def_service || !is_connected(def_service->state) ||
		(def_service->type == CONNMAN_SERVICE_TYPE_VPN &&
		is_connected(def_service->state))) {

		DBG("stopped, default service %s connected %d",
			connman_service_get_identifier(def_service),
			def_service ? is_connected(def_service->state) : -1);
		goto out;
	}

	for (list = service_list; list; list = list->next) {
		struct connman_service *service = list->data;
		int res;

		if (service->type != CONNMAN_SERVICE_TYPE_VPN)
			continue;

		if (is_connected(service->state) ||
					is_connecting(service->state)) {
			if (!service->do_split_routing)
				need_split = true;

			/*
			 * If the service is connecting it must be accounted
			 * for to keep the autoconnection in main loop.
			 */
			if (is_connecting(service->state))
				autoconnectable_vpns = true;

			continue;
		}

		if (is_ignore(service) || !service->favorite)
			continue;

		if (need_split && !service->do_split_routing) {
			DBG("service %p no split routing", service);
			continue;
		}

		DBG("service %p %s %s", service, service->name,
				service->do_split_routing ?
				"split routing" : "");

		res = __connman_service_connect(service,
				CONNMAN_SERVICE_CONNECT_REASON_AUTO);

		switch (res) {
		case 0:
			service_indicate_state(service);
			/* fall through */
		case -EINPROGRESS:
			autoconnectable_vpns = true;
			break;
		default:
			continue;
		}

		if (!service->do_split_routing)
			need_split = true;
	}

	/* Stop if there is no VPN to automatically connect.*/
	if (!autoconnectable_vpns) {
		DBG("stopping, no autoconnectable VPNs found");
		goto out;
	}

	/* Increase the attempt count up to the threshold.*/
	if (attempts < VPN_AUTOCONNECT_TIMEOUT_ATTEMPTS_THRESHOLD)
		attempts++;

	/*
	 * Timeout increases with 1s after VPN_AUTOCONNECT_TIMEOUT_STEP amount
	 * of attempts made. After VPN_AUTOCONNECT_TIMEOUT_ATTEMPTS_THRESHOLD is
	 * reached the delay does not increase.
	 */
	timeout = timeout + (int)(attempts / VPN_AUTOCONNECT_TIMEOUT_STEP);

	/* Re add this to main loop */
	vpn_autoconnect_id =
		g_timeout_add_seconds(timeout, run_vpn_auto_connect,
			GINT_TO_POINTER(attempts));

	DBG("re-added to main loop, next VPN autoconnect in %d seconds (#%d)",
		timeout, attempts);

	return G_SOURCE_REMOVE;

out:
	vpn_autoconnect_id = 0;
	return G_SOURCE_REMOVE;
}

static void vpn_auto_connect(void)
{
	/*
	 * Remove existing autoconnect from main loop to reset the attempt
	 * counter in order to get VPN connected when there is a network change.
	 */
	if (vpn_autoconnect_id) {
		if (!g_source_remove(vpn_autoconnect_id))
			return;
	}

	vpn_autoconnect_id =
		g_idle_add(run_vpn_auto_connect, NULL);
}

static void check_pending_msg(struct connman_service *service)
{
	if (!service->pending)
		return;

	DBG("service %p pending msg %p already exists", service,
						service->pending);
	dbus_message_unref(service->pending);
}

void __connman_service_set_hidden_data(struct connman_service *service,
							gpointer user_data)
{
	DBusMessage *pending = user_data;

	DBG("service %p pending %p", service, pending);

	if (!pending)
		return;

	check_pending_msg(service);

	service->pending = pending;
}

void __connman_service_return_error(struct connman_service *service,
				int error, gpointer user_data)
{
	DBG("service %p error %d user_data %p", service, error, user_data);

	__connman_service_set_hidden_data(service, user_data);

	reply_pending(service, error);
}

static gboolean connect_timeout(gpointer user_data)
{
	struct connman_service *service = user_data;
	bool autoconnect = false;

	DBG("service %p", service);

	service->timeout = 0;

	if (service->network)
		__connman_network_disconnect(service->network);
	else if (service->provider) {
		/*
		 * Remove timeout when the VPN is waiting for user input in
		 * association state. By default the VPN agent timeout is
		 * 300s whereas default connection timeout is 120s. Provider
		 * will start connect timeout for the service when it enters
		 * configuration state.
		 */
		const char *statestr = connman_provider_get_string(
					service->provider, "State");
		if (!g_strcmp0(statestr, "association")) {
			DBG("VPN provider %p is waiting for VPN agent, "
						"stop connect timeout",
						service->provider);
			return G_SOURCE_REMOVE;
		}

		connman_provider_disconnect(service->provider);
	}



	__connman_stats_service_unregister(service);

	if (service->pending) {
		DBusMessage *reply;

		reply = __connman_error_operation_timeout(service->pending);
		if (reply)
			g_dbus_send_message(connection, reply);

		dbus_message_unref(service->pending);
		service->pending = NULL;
	} else
		autoconnect = true;

	__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE,
					CONNMAN_IPCONFIG_TYPE_IPV4);
	__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE,
					CONNMAN_IPCONFIG_TYPE_IPV6);

	if (autoconnect &&
			service->connect_reason !=
				CONNMAN_SERVICE_CONNECT_REASON_USER)
		do_auto_connect(service, CONNMAN_SERVICE_CONNECT_REASON_AUTO);

	return G_SOURCE_REMOVE;
}

void __connman_service_start_connect_timeout(struct connman_service *service,
								bool restart)
{
	DBG("");

	if (!service)
		return;

	if (!restart && service->timeout)
		return;

	if (restart && service->timeout) {
		DBG("cancel running connect timeout");
		g_source_remove(service->timeout);
	}

	service->timeout = g_timeout_add_seconds(CONNECT_TIMEOUT,
				connect_timeout, service);
}

static DBusMessage *connect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	int index, err = 0;
	GList *list;

	DBG("service %p", service);

	/* Hidden services do not keep the pending msg, check it from agent */
	if (service->pending || (service->hidden &&
				__connman_agent_is_request_pending(service,
						dbus_message_get_sender(msg))))
		return __connman_error_in_progress(msg);

	index = __connman_service_get_index(service);

	for (list = service_list; list; list = list->next) {
		struct connman_service *temp = list->data;

		if (!is_connecting(temp->state) && !is_connected(temp->state))
			continue;

		if (service == temp)
			continue;

		if (service->type != temp->type)
			continue;

		if (__connman_service_get_index(temp) == index &&
				__connman_service_disconnect(temp) == -EINPROGRESS)
			err = -EINPROGRESS;

	}
	if (err == -EINPROGRESS)
		return __connman_error_operation_timeout(msg);

	service->ignore = false;

	service->pending = dbus_message_ref(msg);

	err = __connman_service_connect(service,
			CONNMAN_SERVICE_CONNECT_REASON_USER);

	if (err != -EINPROGRESS)
		reply_pending(service, -err);

	return NULL;
}

static DBusMessage *disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	int err;

	DBG("service %p", service);

	service->ignore = true;

	err = __connman_service_disconnect(service);
	if (err < 0 && err != -EINPROGRESS)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

bool __connman_service_remove(struct connman_service *service)
{
	if (service->type == CONNMAN_SERVICE_TYPE_ETHERNET ||
			service->type == CONNMAN_SERVICE_TYPE_GADGET)
		return false;

	if (service->immutable || service->hidden ||
			__connman_provider_is_immutable(service->provider))
		return false;

	if (!service->favorite && !is_idle(service->state))
		return false;

	__connman_service_disconnect(service);
	if (service->network)
		__connman_network_forget(service->network);

	g_free(service->passphrase);
	service->passphrase = NULL;

	g_free(service->identity);
	service->identity = NULL;

	g_free(service->anonymous_identity);
	service->anonymous_identity = NULL;

	g_free(service->subject_match);
	service->subject_match = NULL;

	g_free(service->altsubject_match);
	service->altsubject_match = NULL;

	g_free(service->domain_suffix_match);
	service->domain_suffix_match = NULL;

	g_free(service->domain_match);
	service->domain_match = NULL;

	g_free(service->agent_identity);
	service->agent_identity = NULL;

	g_free(service->eap);
	service->eap = NULL;

	service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;

	__connman_service_set_favorite(service, false);

	__connman_ipconfig_ipv6_reset_privacy(service->ipconfig_ipv6);

	service_save(service);

	return true;
}

static DBusMessage *remove_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	if (!__connman_service_remove(service))
		return __connman_error_not_supported(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static bool check_suitable_state(enum connman_service_state a,
					enum connman_service_state b)
{
	/*
	 * Special check so that "ready" service can be moved before
	 * "online" one.
	 */
	if ((a == CONNMAN_SERVICE_STATE_ONLINE &&
			b == CONNMAN_SERVICE_STATE_READY) ||
		(b == CONNMAN_SERVICE_STATE_ONLINE &&
			a == CONNMAN_SERVICE_STATE_READY))
		return true;

	return a == b;
}

/**
 *  @brief
 *    Downgrade the service IP configuration state from "online" to
 *    "ready".
 *
 *  This attempts to downgrade the specified IP configuration state of
 *  the specified service to "ready" if it is "online".
 *
 *  @param[in,out]  service  A pointer to the mutable service whose IP
 *                           configuration state, if
 *                           #CONNMAN_SERVICE_STATE_ONLINE, is to be
 *                           downgraded to
 *                           #CONNMAN_SERVICE_STATE_READY.
 *  @param[in]      state    The current IP configuration state of @a
 *                           service.
 *  @param[in]      type     The IP configuration type of @a service to
 *                           try to downgrade.
 *
 *  @returns
 *    True if the service state was downgraded for the specified IP
 *    configuration type; otherwise, false.
 *
 *  @sa service_downgrade_online_state
 *  @sa service_downgrade_online_state_if_default
 *
 */
static bool service_ipconfig_downgrade_online_state(
					struct connman_service *service,
					enum connman_service_state state,
					enum connman_ipconfig_type type)
{
	if (!service)
		return false;

	DBG("service %p (%s) type %d (%s) state %d (%s)",
		service,
		connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		state, state2string(state));

	if (is_online(state)) {
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						type);

		return true;
	}

	return false;
}

/**
 *  @brief
 *    Downgrade the service IPv4 and IPv6 states from "online" to
 *    "ready".
 *
 *  This attempts to downgrade the IPv4 and IPv6 states of the
 *  specified service to "ready" if they are "online".
 *
 *  @param[in,out]  service  A pointer to the mutable service whose IPv4
 *                           and IPv6 states, if
 *                           #CONNMAN_SERVICE_STATE_ONLINE, are to be
 *                           downgraded to
 *                           #CONNMAN_SERVICE_STATE_READY.
 *
 *  @returns
 *    True if either IPv4 or IPv6 service state was downgraded;
 *    otherwise, false.
 *
 *  @sa service_ipconfig_downgrade_online_state
 *  @sa service_downgrade_online_state_if_default
 *
 */
static bool service_downgrade_online_state(struct connman_service *service)
{
	bool ipv4_downgraded = false;
	bool ipv6_downgraded = false;

	if (!service)
		return false;

	DBG("service %p (%s) state4 %d (%s) state6 %d (%s)",
		service,
		connman_service_get_identifier(service),
		service->state_ipv4, state2string(service->state_ipv4),
		service->state_ipv6, state2string(service->state_ipv6));

	ipv4_downgraded = service_ipconfig_downgrade_online_state(service,
								 service->state_ipv4,
								 CONNMAN_IPCONFIG_TYPE_IPV4);

	ipv6_downgraded = service_ipconfig_downgrade_online_state(service,
								 service->state_ipv6,
								 CONNMAN_IPCONFIG_TYPE_IPV6);

	return ipv4_downgraded || ipv6_downgraded;
}

/**
 *  @brief
 *    Downgrade the service IPv4 and IPv6 states from "online" to
 *    "ready" if and only if the service is the default service and it
 *    is "online".
 *
 *  This attempts to downgrade the IPv4 and IPv6 states of the
 *  specified service to "ready" if and only if the service is the
 *  default service and its combined service state is "online".
 *
 *  @param[in,out]  service  A pointer to the mutable service whose IPv4
 *                           and IPv6 states, if it is the default
 *                           service and its combined service state is
 *                           #CONNMAN_SERVICE_STATE_ONLINE, are to be
 *                           downgraded to
 *                           #CONNMAN_SERVICE_STATE_READY.
 *
 *  @returns
 *    True if either IPv4 or IPv6 service state was downgraded;
 *    otherwise, false.
 *
 *  @sa service_ipconfig_downgrade_online_state
 *  @sa service_downgrade_online_state
 *
 */
static bool service_downgrade_online_state_if_default(struct connman_service *service)
{
	struct connman_service *def_service;

	def_service = connman_service_get_default();
	if (!def_service || def_service != service ||
		!is_online(def_service->state))
		return false;

	return service_downgrade_online_state(def_service);
}

/**
 *  @brief
 *    Switch the order of the two specified services in the network
 *    service list.
 *
 *  This attempts to switch the order of the two specified services in
 *  the ntework service list. This has the side-effect of potentially
 *  downgrading the state of @a demoted_service from "online" to
 *  "ready" if it is "online" and is the default service and
 *  downgrading the state of @a promoted_service from "online" to
 *  "ready".
 *
 *  @note
 *    If the two services have pointer equivalence or are already in
 *    the specified order, there is no state downgrade of @a
 *    promoted_service.
 *
 *  @param[in,out]  demoted_service   A pointer to the mutable service
 *                                    to demote in the network service
 *                                    list to @b after @a
 *                                    promoted_service.
 *  @param[in,out]  promoted_service  A pointer to the mutable service
 *                                    to promote in the network service
 *                                    list to @b before @a
 *                                    demoted_service.
 *
 */
static void switch_service_order(struct connman_service *demoted_service,
		struct connman_service *promoted_service)
{
	struct connman_service *service;
	GList *src, *dst;

	DBG("demoted_service %p (%s) default %u promoted_sevice %p (%s) default %u",
		demoted_service,
		connman_service_get_identifier(demoted_service),
		connman_service_is_default(demoted_service),
		promoted_service,
		connman_service_get_identifier(promoted_service),
		connman_service_is_default(promoted_service));

	service_downgrade_online_state_if_default(demoted_service);

	src = g_list_find(service_list, promoted_service);
	dst = g_list_find(service_list, demoted_service);

	/* Nothing to do */
	if (src == dst || src->next == dst)
		return;

	service = src->data;
	service_list = g_list_delete_link(service_list, src);
	service_list = g_list_insert_before(service_list, dst, service);

	service_downgrade_online_state(promoted_service);
}

static struct _services_notify {
	int id;
	GHashTable *add;
	GHashTable *remove;
} *services_notify;


static void service_append_added_foreach(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;
	DBusMessageIter *iter = user_data;

	if (!service || !service->path) {
		DBG("service %p or path is NULL", service);
		return;
	}

	if (g_hash_table_lookup(services_notify->add, service->path)) {
		DBG("new %s", service->path);

		append_struct(service, iter);
		g_hash_table_remove(services_notify->add, service->path);
	} else {
		DBG("changed %s", service->path);

		append_struct_service(iter, NULL, service);
	}
}

static void service_append_ordered(DBusMessageIter *iter, void *user_data)
{
	g_list_foreach(service_list, service_append_added_foreach, iter);
}

static void append_removed(gpointer key, gpointer value, gpointer user_data)
{
	char *objpath = key;
	DBusMessageIter *iter = user_data;

	DBG("removed %s", objpath);
	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &objpath);
}

static void service_append_removed(DBusMessageIter *iter, void *user_data)
{
	g_hash_table_foreach(services_notify->remove, append_removed, iter);
}

static gboolean service_send_changed(gpointer data)
{
	DBusMessage *signal;

	DBG("");

	services_notify->id = 0;

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "ServicesChanged");
	if (!signal)
		return FALSE;

	__connman_dbus_append_objpath_dict_array(signal,
					service_append_ordered, NULL);
	__connman_dbus_append_objpath_array(signal,
					service_append_removed, NULL);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);

	g_hash_table_remove_all(services_notify->remove);
	g_hash_table_remove_all(services_notify->add);

	return FALSE;
}

/**
 *  @brief
 *    Schedule a D-Bus "ServicesChanged" signal at 100 milliseconds
 *    from now.
 *
 *  @sa service_send_changed
 *  @sa service_list_sort
 *
 */
static void service_schedule_changed(void)
{
	if (services_notify->id != 0)
		return;

	services_notify->id = g_timeout_add(100, service_send_changed, NULL);
}

int __connman_service_move(struct connman_service *service,
				struct connman_service *target, bool before)
{
	enum connman_ipconfig_method target4, target6;
	enum connman_ipconfig_method service4, service6;

	DBG("service %p", service);

	if (!service)
		return -EINVAL;

	if (!service->favorite)
		return -EOPNOTSUPP;

	if (!target || !target->favorite || target == service)
		return -EINVAL;

	if (target->type == CONNMAN_SERVICE_TYPE_VPN) {
		/*
		 * We only allow VPN route splitting if there are
		 * routes defined for a given VPN.
		 */
		if (!__connman_provider_check_routes(target->provider)) {
			connman_info("Cannot move service. "
				"No routes defined for provider %s",
				__connman_provider_get_ident(target->provider));
			return -EINVAL;
		}

		__connman_service_set_split_routing(target, true);
	} else
		__connman_service_set_split_routing(target, false);

	__connman_service_set_split_routing(service, false);

	target4 = __connman_ipconfig_get_method(target->ipconfig_ipv4);
	target6 = __connman_ipconfig_get_method(target->ipconfig_ipv6);
	service4 = __connman_ipconfig_get_method(service->ipconfig_ipv4);
	service6 = __connman_ipconfig_get_method(service->ipconfig_ipv6);

	DBG("target %s method %d/%d state %d/%d split %d", target->identifier,
		target4, target6, target->state_ipv4, target->state_ipv6,
		target->do_split_routing);

	DBG("service %s method %d/%d state %d/%d", service->identifier,
				service4, service6,
				service->state_ipv4, service->state_ipv6);

	/*
	 * If method is OFF, then we do not need to check the corresponding
	 * ipconfig state.
	 */
	if (target4 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (service6 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv6,
							service->state_ipv6))
				return -EINVAL;
		}
	}

	if (target6 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (service4 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv4,
							service->state_ipv4))
				return -EINVAL;
		}
	}

	if (service4 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (target6 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv6,
							service->state_ipv6))
				return -EINVAL;
		}
	}

	if (service6 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (target4 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv4,
							service->state_ipv4))
				return -EINVAL;
		}
	}

	gettimeofday(&service->modified, NULL);
	service_save(service);
	service_save(target);

	/*
	 * If the service which goes down is the default service and is
	 * online, we downgrade directly its state to ready so:
	 * the service which goes up, needs to recompute its state which
	 * is triggered via downgrading it - if relevant - to state ready.
	 */
	if (before)
		switch_service_order(target, service);
	else
		switch_service_order(service, target);

	__connman_gateway_update();

	service_schedule_changed();

	return 0;
}

static DBusMessage *move_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data,
								bool before)
{
	struct connman_service *service = user_data;
	struct connman_service *target;
	const char *path;
	int err;

	DBG("service %p", service);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	target = find_service(path);

	err = __connman_service_move(service, target, before);
	switch (err) {
	case 0:
		break;
	case -EINVAL:
		return __connman_error_invalid_service(msg);
	case -EOPNOTSUPP:
		return __connman_error_not_supported(msg);
	default:
		connman_warn("unsupported error code %d in move_service()",
									err);
		break;
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *move_before(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return move_service(conn, msg, user_data, true);
}

static DBusMessage *move_after(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return move_service(conn, msg, user_data, false);
}

static DBusMessage *reset_counters(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	reset_stats(service);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void service_schedule_added(struct connman_service *service)
{
	DBG("service %p (%s)",
		service, connman_service_get_identifier(service));

	g_hash_table_remove(services_notify->remove, service->path);
	g_hash_table_replace(services_notify->add, service->path, service);

	service_schedule_changed();
}

static void service_schedule_removed(struct connman_service *service)
{
	if (!service || !service->path) {
		DBG("service %p or path is NULL", service);
		return;
	}

	DBG("service %p %s", service, service->path);

	g_hash_table_remove(services_notify->add, service->path);
	g_hash_table_replace(services_notify->remove, g_strdup(service->path),
			NULL);

	service_schedule_changed();
}

static bool allow_property_changed(struct connman_service *service)
{
	if (g_hash_table_lookup_extended(services_notify->add, service->path,
					NULL, NULL))
		return false;

	return true;
}

static const GDBusMethodTable service_methods[] = {
	{ GDBUS_DEPRECATED_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_METHOD("ClearProperty",
			GDBUS_ARGS({ "name", "s" }), NULL,
			clear_property) },
	{ GDBUS_ASYNC_METHOD("Connect", NULL, NULL,
			      connect_service) },
	{ GDBUS_METHOD("Disconnect", NULL, NULL,
			disconnect_service) },
	{ GDBUS_METHOD("Remove", NULL, NULL, remove_service) },
	{ GDBUS_METHOD("MoveBefore",
			GDBUS_ARGS({ "service", "o" }), NULL,
			move_before) },
	{ GDBUS_METHOD("MoveAfter",
			GDBUS_ARGS({ "service", "o" }), NULL,
			move_after) },
	{ GDBUS_METHOD("ResetCounters", NULL, NULL, reset_counters) },
	{ },
};

static const GDBusSignalTable service_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ },
};

static void service_free(gpointer user_data)
{
	struct connman_service *service = user_data;
	char *path = service->path;

	DBG("service %p (%s)", service, connman_service_get_identifier(service));

	reply_pending(service, ENOENT);

	if (service->nameservers_timeout) {
		g_source_remove(service->nameservers_timeout);
		dns_changed(service);
	}

	__connman_notifier_service_remove(service);
	service_schedule_removed(service);

	cancel_online_check(service, CONNMAN_IPCONFIG_TYPE_ALL);

	__connman_wispr_stop(service);

	stats_stop(service);

	service->path = NULL;

	if (path) {
		__connman_gateway_update();

		g_dbus_unregister_interface(connection, path,
						CONNMAN_SERVICE_INTERFACE);
		g_free(path);
	}

	g_hash_table_destroy(service->counter_table);

	if (service->network) {
		__connman_network_disconnect(service->network);
		connman_network_unref(service->network);
		service->network = NULL;
	}

	if (service->provider)
		connman_provider_unref(service->provider);

	if (service->ipconfig_ipv4) {
		__connman_ipconfig_set_ops(service->ipconfig_ipv4, NULL);
		__connman_ipconfig_set_data(service->ipconfig_ipv4, NULL);
		__connman_ipconfig_unref(service->ipconfig_ipv4);
		service->ipconfig_ipv4 = NULL;
	}

	if (service->ipconfig_ipv6) {
		__connman_ipconfig_set_ops(service->ipconfig_ipv6, NULL);
		__connman_ipconfig_set_data(service->ipconfig_ipv6, NULL);
		__connman_ipconfig_unref(service->ipconfig_ipv6);
		service->ipconfig_ipv6 = NULL;
	}

	g_strfreev(service->timeservers);
	g_strfreev(service->timeservers_config);
	g_strfreev(service->nameservers);
	g_strfreev(service->nameservers_config);
	g_strfreev(service->nameservers_auto);
	g_strfreev(service->domains);
	g_strfreev(service->proxies);
	g_strfreev(service->excludes);

	g_free(service->hostname);
	g_free(service->domainname);
	g_free(service->pac);
	g_free(service->name);
	g_free(service->passphrase);
	g_free(service->identifier);
	g_free(service->eap);
	g_free(service->identity);
	g_free(service->anonymous_identity);
	g_free(service->agent_identity);
	g_free(service->ca_cert_file);
	g_free(service->subject_match);
	g_free(service->altsubject_match);
	g_free(service->domain_suffix_match);
	g_free(service->domain_match);
	g_free(service->client_cert_file);
	g_free(service->private_key_file);
	g_free(service->private_key_passphrase);
	g_free(service->phase2);
	g_free(service->config_file);
	g_free(service->config_entry);

	if (service->stats.timer)
		g_timer_destroy(service->stats.timer);
	if (service->stats_roaming.timer)
		g_timer_destroy(service->stats_roaming.timer);

	if (current_default == service)
		current_default = NULL;

	g_free(service);
}

static void stats_init(struct connman_service *service)
{
	/* home */
	service->stats.valid = false;
	service->stats.enabled = false;
	service->stats.timer = g_timer_new();

	/* roaming */
	service->stats_roaming.valid = false;
	service->stats_roaming.enabled = false;
	service->stats_roaming.timer = g_timer_new();
}

static void service_initialize(struct connman_service *service)
{
	DBG("service %p", service);

	service->refcount = 1;

	service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;

	service->type     = CONNMAN_SERVICE_TYPE_UNKNOWN;
	service->security = CONNMAN_SERVICE_SECURITY_UNKNOWN;

	service->state = CONNMAN_SERVICE_STATE_UNKNOWN;
	service->state_ipv4 = CONNMAN_SERVICE_STATE_UNKNOWN;
	service->state_ipv6 = CONNMAN_SERVICE_STATE_UNKNOWN;

	service->favorite  = false;
	service->immutable = false;
	service->hidden = false;

	service->ignore = false;

	service->connect_reason = CONNMAN_SERVICE_CONNECT_REASON_NONE;

	service->order = 0;

	stats_init(service);

	service->provider = NULL;

	service->wps = false;
	service->wps_advertizing = false;
}

/**
 * connman_service_create:
 *
 * Allocate a new service.
 *
 * Returns: a newly-allocated #connman_service structure
 */
struct connman_service *connman_service_create(void)
{
	GSList *list;
	struct connman_stats_counter *counters;
	const char *counter;

	struct connman_service *service;

	service = g_try_new0(struct connman_service, 1);
	if (!service)
		return NULL;

	DBG("service %p", service);

	service->counter_table = g_hash_table_new_full(g_str_hash,
						g_str_equal, NULL, g_free);

	for (list = counter_list; list; list = list->next) {
		counter = list->data;

		counters = g_try_new0(struct connman_stats_counter, 1);
		if (!counters) {
			g_hash_table_destroy(service->counter_table);
			g_free(service);
			return NULL;
		}

		counters->append_all = true;

		g_hash_table_replace(service->counter_table, (gpointer)counter,
				counters);
	}

	service_initialize(service);

	return service;
}

/**
 * connman_service_ref:
 * @service: service structure
 *
 * Increase reference counter of service
 */
struct connman_service *
connman_service_ref_debug(struct connman_service *service,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", service, service->refcount + 1,
		file, line, caller);

	__sync_fetch_and_add(&service->refcount, 1);

	return service;
}

/**
 * connman_service_unref:
 * @service: service structure
 *
 * Decrease reference counter of service and release service if no
 * longer needed.
 */
void connman_service_unref_debug(struct connman_service *service,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", service, service->refcount - 1,
		file, line, caller);

	if (__sync_fetch_and_sub(&service->refcount, 1) != 1)
		return;

	service_list = g_list_remove(service_list, service);

	__connman_service_disconnect(service);

	g_hash_table_remove(service_hash, service->identifier);
}

static gint service_compare(gconstpointer a, gconstpointer b);

static gint service_compare_vpn(const struct connman_service *a,
						const struct connman_service *b)
{
	struct connman_provider *provider;
	const struct connman_service *service;
	struct connman_service *transport;
	const char *ident;
	bool reverse;

	if (a->provider) {
		provider = a->provider;
		service = b;
		reverse = false;
	} else if (b->provider) {
		provider = b->provider;
		service = a;
		reverse = true;
	} else {
		return 0;
	}

	ident = __connman_provider_get_transport_ident(provider);
	transport = connman_service_lookup_from_identifier(ident);
	if (!transport)
		return 0;

	if (reverse)
		return service_compare(service, transport);

	return service_compare(transport, service);
}

/**
 *  @brief
 *    Compare two network services against the @a
 *    PreferredTechnologies priority list.
 *
 *  This compares the two specified network services, by their
 *  technology type, against the @a PreferredTechnologies priority
 *  list.
 *
 *  @param[in]  service_a  A pointer to the first immutable service
 *                         to compare by its technology type with the
 *                         @a PreferredTechnologies priority list.
 *  @param[in]  service_b  A pointer to the second immutable service
 *                         to compare by its technology type with the
 *                         @a PreferredTechnologies priority list.
 *
 *  @retval   0  If the @a PreferredTechnologies configuration is empty
 *               or if neither service type matches a technology type
 *               in the @a PreferredTechnologies list.
 *  @retval  -1  If @a service_a type matches a technology type
 *               in the @a PreferredTechnologies list and should sort
 *               @b before @a service_b.
 *  @retval   1  If @a service_b type matches a technology type
 *               in the @a PreferredTechnologies list and should sort
 *               @b before @a service_a.
 *
 */
static gint service_compare_preferred(const struct connman_service *service_a,
					const struct connman_service *service_b)
{
	unsigned int *tech_array;
	int i;

	tech_array = connman_setting_get_uint_list("PreferredTechnologies");
	if (tech_array) {
		for (i = 0; tech_array[i]; i++) {
			if (tech_array[i] == service_a->type)
				return -1;

			if (tech_array[i] == service_b->type)
				return 1;
		}
	}
	return 0;
}

/**
 *  @brief
 *    Compare two network services against one another.
 *
 *  This compares the two specified network services.
 *
 *  Services are compared with the following sort criteria:
 *
 *    1. State
 *    2. Favorite status
 *    3. Type
 *    4. Strength
 *    5. Name
 *
 *  @param[in]  a  A pointer to the first immutable service
 *                 to compare.
 *  @param[in]  b  A pointer to the second immutable service
 *                 to compare.
 *
 *  @retval    0  If service @a a and @a b are equivalent.
 *  @retval  < 0  If service @a a should sort @b before service @a b.
 *  @retval  > 0  If service @a b should sort @b before service @a a.
 *
 *  @sa service_compare_preferred
 *  @sa __connman_service_compare
 *
 */
static gint service_compare(gconstpointer a, gconstpointer b)
{
	const struct connman_service *service_a = (const void *) a;
	const struct connman_service *service_b = (const void *) b;
	enum connman_service_state state_a, state_b;
	bool a_connected, b_connected;
	gint strength;

	state_a = service_a->state;
	state_b = service_b->state;
	a_connected = is_connected(state_a);
	b_connected = is_connected(state_b);

	/*
	 * If both services are connected (that is, "ready" or "online"),
	 * then further sort by whether the services are VPN type, then
	 * service order if there is VPN equivalence, and then by their
	 * preferred technology status.
	 */
	if (a_connected && b_connected) {
		int rval;

		/*
		 * If at this point the services are still comparing as
		 * equivalent, then use online check failure status, giving
		 * priority to the service that has not met the failure
		 * threshold.
		 */
		if (!online_check_failures_threshold_was_met(service_a) &&
			online_check_failures_threshold_was_met(service_b)) {
			return -1;
		}

		if (online_check_failures_threshold_was_met(service_a) &&
			!online_check_failures_threshold_was_met(service_b)) {
			return 1;
		}

		/* Compare the VPN transport and the service */
		if ((service_a->type == CONNMAN_SERVICE_TYPE_VPN ||
				service_b->type == CONNMAN_SERVICE_TYPE_VPN) &&
				service_b->type != service_a->type) {
			rval = service_compare_vpn(service_a, service_b);
			if (rval)
				return rval;
		}

		if (service_a->order > service_b->order)
			return -1;

		if (service_a->order < service_b->order)
			return 1;

		rval = service_compare_preferred(service_a, service_b);
		if (rval)
			return rval;
	}

	/*
	 * If at this point the services are still comparing as
	 * equilvalent, then check whether their combined states are
	 * different. If they are, then prefer the service that is
	 * "online" to that which is only "ready", then prefer @a a being
	 * connected versus @a b being connected, and, finally, then
	 * prefer @a a being in the process of connecting to @a b being in
	 * the process of connecting.
	 */
	if (state_a != state_b) {
		if (a_connected && b_connected) {
			/* We prefer online over ready state */
			if (is_online(state_a))
				return -1;

			if (is_online(state_b))
				return 1;
		}

		if (a_connected)
			return -1;
		if (b_connected)
			return 1;

		if (is_connecting(state_a))
			return -1;
		if (is_connecting(state_b))
			return 1;
	}

	/*
	 * If at this point the services are still comparing as
	 * equivalent, then use favorite status, giving priority to @a a
	 * as a favorite versus @a b as a favorite.
	 */
	if (service_a->favorite && !service_b->favorite)
		return -1;

	if (!service_a->favorite && service_b->favorite)
		return 1;

	/*
	 * If at this point the services are still comparing as
	 * equivalent, then check whether their types are different. If
	 * they are, then compare their types. First, against the
	 * PreferredTechnologies priority list and then by an internal
	 * prioritization favoring Ethernet over Wi-Fi, Wi-Fi over
	 * Cellular, Cellular over Bluetooth, Bluetooth over VPN, and VPN
	 * over Gadget (that is, USB Ethernet).
	 */
	if (service_a->type != service_b->type) {
		int rval;

		rval = service_compare_preferred(service_a, service_b);
		if (rval)
			return rval;

		if (service_a->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_WIFI)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_WIFI)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_CELLULAR)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_CELLULAR)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_BLUETOOTH)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_BLUETOOTH)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_VPN)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_VPN)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_GADGET)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_GADGET)
			return 1;
	}

	/*
	 * If at this point the services are still comparing as
	 * equivalent, then check their strengths.
	 */
	strength = (gint) service_b->strength - (gint) service_a->strength;
	if (strength)
		return strength;

	/*
	 * Finally, if at this point the services are still comparing as
	 * equivalent, then check their names.
	 */
	return g_strcmp0(service_a->name, service_b->name);
}

/**
 *  @brief
 *    Sort the network services list and schedule a "ServicesChanged"
 *    D-Bus signal.
 *
 *  This attempts to sort, if non-null and has more than one element,
 *  the network services list. On completion of the sort, a D-Bus
 *  "ServicesChanged" signal is scheduled.
 *
 *  @param[in]  function  A pointer to an immutable null-terminated
 *                        C string containing the function name to
 *                        which the call to this function should be
 *                        attributed.
 *
 *  @sa service_compare
 *  @sa service_compare_preferred
 *  @sa service_schedule_changed
 *
 */
static void service_list_sort(const char *function)
{
	DBG("from %s()", function);

	if (service_list && service_list->next) {
		service_list = g_list_sort(service_list, service_compare);
		service_schedule_changed();
	}
}

/**
 *  @brief
 *    Compare two network services against one another.
 *
 *  This compares the two specified network services.
 *
 *  @param[in]  a  A pointer to the first immutable service
 *                 to compare.
 *  @param[in]  b  A pointer to the second immutable service
 *                 to compare.
 *
 *  @retval    0  If service @a a and @a b are equivalent.
 *  @retval  < 0  If service @a a should sort @b before service @a b.
 *  @retval  > 0  If service @a b should sort @b before service @a a.
 *
 *  @sa service_compare
 *  @sa service_compare_preferred
 *  @sa service_list_sort
 *
 */
int __connman_service_compare(const struct connman_service *a,
					const struct connman_service *b)
{
	return service_compare(a, b);
}

/**
 * connman_service_get_type:
 * @service: service structure
 *
 * Get the type of service
 */
enum connman_service_type connman_service_get_type(const struct connman_service *service)
{
	if (!service)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	return service->type;
}

/**
 * connman_service_get_interface:
 * @service: service structure
 *
 * Get network interface of service
 */
char *connman_service_get_interface(const struct connman_service *service)
{
	int index;

	if (!service)
		return NULL;

	index = __connman_service_get_index(service);

	return connman_inet_ifname(index);
}

/**
 * connman_service_get_network:
 * @service: service structure
 *
 * Get the service network
 */
struct connman_network *
__connman_service_get_network(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->network;
}

/**
 *  @brief
 *    Return the current service count.
 *
 *  @returns
 *    The current service count.
 *
 */
static size_t service_get_count(void)
{
	return service_list ? g_list_length(service_list) : 0;
}

/**
 *  @brief
 *    Get the route metric/priority for the specified service.
 *
 *  This attempts to get the route metric/priority for the specified
 *  service based on the current service and services state.
 *
 *  If the service is the default or if it is the only service, then
 *  the metric is zero (0). Otherwise, a low-priority metric (metric >
 *  0) unique to @a service and its underlying network interface is
 *  computed and returned.
 *
 *  @param[in]      service  A pointer to the immutable service for
 *                           which to get the route metric/priority.
 *  @param[in,out]  metric   A pointer to storage for the route
 *                           metric/priority, populated with the route
 *                           metric/priority on success.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If @a service or @a metric are null.
 *  @retval  -ENXIO   If the network interface index associated with
 *                    @a service is invalid.
 *
 *  @sa connman_service_is_default
 *
 */
int __connman_service_get_route_metric(const struct connman_service *service,
				uint32_t *metric)
{
	static const uint32_t metric_base = UINT32_MAX;
	static const uint32_t metric_ceiling = (1 << 20);
	static const uint32_t metric_index_step = (1 << 10);
	int index;

	DBG("");

	if (!service || !metric)
		return -EINVAL;

	DBG("service %p (%s) metric %p",
		service, connman_service_get_identifier(service),
		metric);

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	/*
	 * The algorithm uses the network interface index since it is
	 * assumed to be stable for the uptime of the network interface
	 * and, consequently, the potential maximum lifetime of the route.
	 *
	 * The algorithm establishes UINT32_MAX as the metric base (the
	 * lowest possible priority) and a somewhat-arbitrary 2^20 as the
	 * ceiling (to keep metrics out of a range that might be used by
	 * other applications). The metric is then adjusted in increments
	 * of 1,024 (2^10) from the base, but less than the ceiling, by
	 * multiplying the increment by the network interface index. This
	 * is easy and simple to compute and is invariant on service
	 * order.
	 *
	 * In the fullness of time, the "rule of least astonishment" for
	 * Connection Manager might be that low priority metrics follow
	 * the service order with the default service always having metric
	 * zero (0) and lowest priority metric assigned to the lowest
	 * priority service, etc. Achieving this would require having
	 * access to APIs (such as '__connman_service_get_count()' and
	 * '__connman_service_get_order(service)') that expose a
	 * strictly-in/decreasing service order with no duplicates. Today,
	 * there is no such API nor is there such a durable service order
	 * meeting that mathematical requirement.
	 */

	if (service_get_count() <= 1 || connman_service_is_default(service))
		*metric = 0;
	else
		*metric = MAX(metric_ceiling,
					metric_base -
					(index * metric_index_step));

	DBG("metric %u", *metric);

	return 0;
}

struct connman_ipconfig *
__connman_service_get_ip4config(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->ipconfig_ipv4;
}

struct connman_ipconfig *
__connman_service_get_ip6config(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->ipconfig_ipv6;
}

struct connman_ipconfig *
__connman_service_get_ipconfig(struct connman_service *service, int family)
{
	if (family == AF_INET)
		return __connman_service_get_ip4config(service);
	else if (family == AF_INET6)
		return __connman_service_get_ip6config(service);
	else
		return NULL;

}

bool __connman_service_is_connected_state(const struct connman_service *service,
					enum connman_ipconfig_type type)
{
	if (!service)
		return false;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		return is_connected(service->state_ipv4);
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		return is_connected(service->state_ipv6);
	case CONNMAN_IPCONFIG_TYPE_ALL:
		return is_connected(service->state_ipv4) &&
			is_connected(service->state_ipv6);
	}

	return false;
}
enum connman_service_security __connman_service_get_security(
				const struct connman_service *service)
{
	if (!service)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;

	return service->security;
}

const char *__connman_service_get_phase2(const struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->phase2;
}

bool __connman_service_wps_enabled(const struct connman_service *service)
{
	if (!service)
		return false;

	return service->wps;
}

void __connman_service_mark_dirty(void)
{
	services_dirty = true;
}

/**
 * __connman_service_set_favorite_delayed:
 * @service: service structure
 * @favorite: favorite value
 * @delay_ordering: do not order service sequence
 *
 * Change the favorite setting of service
 */
int __connman_service_set_favorite_delayed(struct connman_service *service,
					bool favorite,
					bool delay_ordering)
{
	if (service->hidden)
		return -EOPNOTSUPP;

	if (service->favorite == favorite)
		return -EALREADY;

	service->favorite = favorite;

	favorite_changed(service);
	/* If native autoconnect is in use, the favorite state may affect the
	 * autoconnect state, so it needs to be rerun. */
	trigger_autoconnect(service);

	if (!delay_ordering) {

		SERVICE_LIST_SORT();

		__connman_gateway_update();
	}

	return 0;
}

/**
 * __connman_service_set_favorite:
 * @service: service structure
 * @favorite: favorite value
 *
 * Change the favorite setting of service
 */
int __connman_service_set_favorite(struct connman_service *service,
						bool favorite)
{
	return __connman_service_set_favorite_delayed(service, favorite,
							false);
}

bool connman_service_get_favorite(const struct connman_service *service)
{
	return service->favorite;
}

bool connman_service_get_autoconnect(const struct connman_service *service)
{
	return service->autoconnect;
}

int __connman_service_set_immutable(struct connman_service *service,
						bool immutable)
{
	if (service->hidden)
		return -EOPNOTSUPP;

	if (service->immutable == immutable)
		return 0;

	service->immutable = immutable;

	immutable_changed(service);

	return 0;
}

int __connman_service_set_ignore(struct connman_service *service,
						bool ignore)
{
	if (!service)
		return -EINVAL;

	service->ignore = ignore;

	return 0;
}

void __connman_service_set_string(struct connman_service *service,
				  const char *key, const char *value)
{
	if (service->hidden)
		return;
	if (g_str_equal(key, "EAP")) {
		g_free(service->eap);
		service->eap = g_strdup(value);
	} else if (g_str_equal(key, "Identity")) {
		g_free(service->identity);
		service->identity = g_strdup(value);
	} else if (g_str_equal(key, "AnonymousIdentity")) {
		g_free(service->anonymous_identity);
		service->anonymous_identity = g_strdup(value);
	} else if (g_str_equal(key, "CACertFile")) {
		g_free(service->ca_cert_file);
		service->ca_cert_file = g_strdup(value);
	} else if (g_str_equal(key, "SubjectMatch")) {
		g_free(service->subject_match);
		service->subject_match = g_strdup(value);
	} else if (g_str_equal(key, "AltSubjectMatch")) {
		g_free(service->altsubject_match);
		service->altsubject_match = g_strdup(value);
	} else if (g_str_equal(key, "DomainSuffixMatch")) {
		g_free(service->domain_suffix_match);
		service->domain_suffix_match = g_strdup(value);
	} else if (g_str_equal(key, "DomainMatch")) {
		g_free(service->domain_match);
		service->domain_match = g_strdup(value);
	} else if (g_str_equal(key, "ClientCertFile")) {
		g_free(service->client_cert_file);
		service->client_cert_file = g_strdup(value);
	} else if (g_str_equal(key, "PrivateKeyFile")) {
		g_free(service->private_key_file);
		service->private_key_file = g_strdup(value);
	} else if (g_str_equal(key, "PrivateKeyPassphrase")) {
		g_free(service->private_key_passphrase);
		service->private_key_passphrase = g_strdup(value);
	} else if (g_str_equal(key, "Phase2")) {
		g_free(service->phase2);
		service->phase2 = g_strdup(value);
	} else if (g_str_equal(key, "Passphrase"))
		__connman_service_set_passphrase(service, value);
}

void __connman_service_set_search_domains(struct connman_service *service,
					char **domains)
{
	searchdomain_remove_all(service);

	if (service->domains)
		g_strfreev(service->domains);

	service->domains = g_strdupv(domains);

	searchdomain_add_all(service);
}

int __connman_service_set_mdns(struct connman_service *service,
			bool enabled)
{
	service->mdns_config = enabled;

	return set_mdns(service, enabled);
}

static void report_error_cb(void *user_context, bool retry,
							void *user_data)
{
	struct connman_service *service = user_context;

	if (retry)
		__connman_service_connect(service,
					CONNMAN_SERVICE_CONNECT_REASON_USER);
	else {
		/* It is not relevant to stay on Failure state
		 * when failing is due to wrong user input */
		__connman_service_clear_error(service);

		service_complete(service);
		SERVICE_LIST_SORT();
		__connman_gateway_update();
	}
}

static int check_wpspin(struct connman_service *service, const char *wpspin)
{
	int length;
	guint i;

	if (!wpspin)
		return 0;

	length = strlen(wpspin);

	/* If 0, it will mean user wants to use PBC method */
	if (length == 0) {
		connman_network_set_string(service->network,
							"WiFi.PinWPS", NULL);
		return 0;
	}

	/* A WPS PIN is always 8 chars length,
	 * its content is in digit representation.
	 */
	if (length != 8)
		return -ENOKEY;

	for (i = 0; i < 8; i++)
		if (!isdigit((unsigned char) wpspin[i]))
			return -ENOKEY;

	connman_network_set_string(service->network, "WiFi.PinWPS", wpspin);

	return 0;
}

static void request_input_cb(struct connman_service *service,
			bool values_received,
			const char *name, int name_len,
			const char *identity, const char *passphrase,
			bool wps, const char *wpspin,
			const char *error, void *user_data)
{
	struct connman_device *device;
	const char *security;
	int err = 0;
	int index;

	DBG("RequestInput return, %p", service);

	if (error) {
		DBG("error: %s", error);

		if (g_strcmp0(error,
				"net.connman.Agent.Error.Canceled") == 0) {
			err = -ECONNABORTED;

			if (service->hidden)
				__connman_service_return_error(service,
							ECONNABORTED,
							user_data);
		} else {
			err = -ETIMEDOUT;

			if (service->hidden)
				__connman_service_return_error(service,
							ETIMEDOUT, user_data);
		}

		goto done;
	}

	if (service->hidden) {
		if (name_len > 0 && name_len <= 32) {
			device = connman_network_get_device(service->network);
			security = connman_network_get_string(service->network,
								"WiFi.Security");
			err = __connman_device_request_hidden_scan(device,
								name, name_len,
								identity, passphrase,
								security, user_data);
		} else {
			err = -EINVAL;
		}
		if (err < 0)
			__connman_service_return_error(service,	-err,
							user_data);
	}

	if (!values_received || service->hidden) {
		err = -EINVAL;
		goto done;
	}

	if (wps && service->network) {
		err = check_wpspin(service, wpspin);
		if (err < 0)
			goto done;

		connman_network_set_bool(service->network, "WiFi.UseWPS", wps);
	}

	if (identity)
		__connman_service_set_agent_identity(service, identity);

	if (passphrase)
		err = __connman_service_set_passphrase(service, passphrase);

 done:
	index = __connman_service_get_index(service);
	g_hash_table_remove(passphrase_requested,
				GINT_TO_POINTER(index));

	if (err >= 0) {
		/* We forget any previous error. */
		clear_error(service);

		__connman_service_connect(service,
					CONNMAN_SERVICE_CONNECT_REASON_USER);

	} else if (err == -ENOKEY) {
		__connman_service_indicate_error(service,
					CONNMAN_SERVICE_ERROR_INVALID_KEY);
	} else {
		/* It is not relevant to stay on Failure state
		 * when failing is due to wrong user input */
		service->state = CONNMAN_SERVICE_STATE_IDLE;

		if (!service->hidden) {
			/*
			 * If there was a real error when requesting
			 * hidden scan, then that error is returned already
			 * to the user somewhere above so do not try to
			 * do this again.
			 */
			__connman_service_return_error(service,	-err,
							user_data);
		}

		service_complete(service);
		__connman_gateway_update();
	}
}

/**
 *  @brief
 *    Downgrade the service IPv4 and IPv6 states from "online" to
 *    "ready" of all connected services.
 *
 *  This attempts to downgrade the IPv4 and IPv6 states of all
 *  @a is_connected services to "ready" if they are "online".
 *
 *  @sa service_ipconfig_downgrade_online_state
 *  @sa service_downgrade_online_state
 *  @sa service_downgrade_online_state_if_default
 *
 */
static void downgrade_connected_services(void)
{
	struct connman_service *up_service;
	GList *list;

	DBG("");

	for (list = service_list; list; list = list->next) {
		up_service = list->data;

		if (!is_connected(up_service->state))
			continue;

		if (is_online(up_service->state))
			return;

		service_downgrade_online_state(up_service);
	}
}

/**
 *  @brief
 *    Potentially change the network service list order of the default
 *    network service and the specified network service.
 *
 *  This attempts to switch the order of the specified services in the
 *  network service list if and only if a) the services are non-null,
 *  b) do not have pointer equivalence, and c) if @a new_service
 *  should sort before @a default_service according to the @a
 *  PreferredTechnologies list.
 *
 *  @param[in,out]  default_service  A pointer to the mutable, default
 *                                   network service to potentially
 *                                   demote in the network service
 *                                   list to @b after @a new_service.
 *  @param[in,out]  new_service      A pointer to the mutable service
 *                                   to potentially promote in the
 *                                   network service list to @b before
 *                                   @a default_service.
 *  @param[in]      new_state        The pending network service state
 *                                   of @a new_service that is
 *                                   precipitating the order update.
 *
 *  @retval  0          If the preferred order was successfully
 *                      changed which includes @a default_service
 *                      being null or @a default_service and @a
 *                      new_service having pointer equivalence.
 *  @retval  -EALREADY  If the preferred order was unchanged.
 *
 */
static int service_update_preferred_order(struct connman_service *default_service,
		struct connman_service *new_service,
		enum connman_service_state new_state)
{
	DBG("default_service %p (%s) new_service %p (%s) new_state %d (%s)",
		default_service, connman_service_get_identifier(default_service),
		new_service, connman_service_get_identifier(new_service),
		new_state, state2string(new_state));

	if (!default_service || default_service == new_service)
		return 0;

	if (service_compare_preferred(default_service, new_service) > 0) {
		switch_service_order(default_service,
				new_service);
		__connman_gateway_update();
		return 0;
	}

	return -EALREADY;
}

static void single_connected_tech(struct connman_service *allowed)
{
	struct connman_service *service;
	GSList *services = NULL, *list;
	GList *iter;

	DBG("keeping %p %s", allowed, allowed->path);

	for (iter = service_list; iter; iter = iter->next) {
		service = iter->data;

		if (!is_connected(service->state))
			break;

		if (service == allowed)
			continue;

		services = g_slist_prepend(services, service);
	}

	for (list = services; list; list = list->next) {
		service = list->data;

		DBG("disconnecting %p %s", service, service->path);
		__connman_service_disconnect(service);
	}

	g_slist_free(services);
}

static const char *get_dbus_sender(struct connman_service *service)
{
	if (!service->pending)
		return NULL;

	return dbus_message_get_sender(service->pending);
}

static int service_indicate_state(struct connman_service *service)
{
	enum connman_service_state old_state, new_state;
	struct connman_service *def_service;
	enum connman_ipconfig_method method;
	int result;

	if (!service)
		return -EINVAL;

	old_state = service->state;
	new_state = combine_state(service->state_ipv4, service->state_ipv6);

	DBG("service %p (%s) old %s - new %s/%s => %s",
					service,
					connman_service_get_identifier(service),
					state2string(old_state),
					state2string(service->state_ipv4),
					state2string(service->state_ipv6),
					state2string(new_state));

	if (old_state == new_state)
		return -EALREADY;

	def_service = connman_service_get_default();

	if (is_online(new_state)) {
		result = service_update_preferred_order(def_service,
				service, new_state);
		if (result == -EALREADY)
			return result;
	}

	if (is_online(old_state))
		__connman_notifier_leave_online(service->type);

	if (is_connected(old_state) && !is_connected(new_state))
		searchdomain_remove_all(service);

	service->state = new_state;
	state_changed(service);

	if (!is_connected(old_state) && is_connected(new_state))
		searchdomain_add_all(service);

	switch(new_state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:

		break;

	case CONNMAN_SERVICE_STATE_IDLE:
		if (old_state == CONNMAN_SERVICE_STATE_FAILURE &&
				service->connect_reason ==
					CONNMAN_SERVICE_CONNECT_REASON_NATIVE &&
				service->error ==
					CONNMAN_SERVICE_ERROR_INVALID_KEY) {
			__connman_service_clear_error(service);
			service_complete(service);
		}

		if (old_state != CONNMAN_SERVICE_STATE_DISCONNECT)
			__connman_service_disconnect(service);

		break;

	case CONNMAN_SERVICE_STATE_ASSOCIATION:

		break;

	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		if (!service->new_service &&
				__connman_stats_service_register(service) == 0) {
			/*
			 * For new services the statistics are updated after
			 * we have successfully connected.
			 */
			__connman_stats_get(service, false,
						&service->stats.data);
			__connman_stats_get(service, true,
						&service->stats_roaming.data);
		}

		break;

	case CONNMAN_SERVICE_STATE_READY:
		clear_error(service);

		if (service->new_service &&
				__connman_stats_service_register(service) == 0) {
			/*
			 * This is normally done after configuring state
			 * but for new service do this after we have connected
			 * successfully.
			 */
			__connman_stats_get(service, false,
						&service->stats.data);
			__connman_stats_get(service, true,
						&service->stats_roaming.data);
		}

		service->new_service = false;

		def_service = connman_service_get_default();

		service_update_preferred_order(def_service, service, new_state);

		DEFAULT_CHANGED();

		__connman_service_set_favorite(service, true);

		reply_pending(service, 0);

		if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
			connman_network_get_bool(service->network,
						"WiFi.UseWPS")) {
			const char *pass;

			pass = connman_network_get_string(service->network,
							"WiFi.Passphrase");

			__connman_service_set_passphrase(service, pass);

			connman_network_set_bool(service->network,
							"WiFi.UseWPS", false);
		}

		gettimeofday(&service->modified, NULL);
		service_save(service);

		domain_changed(service);
		proxy_changed(service);

		if (!is_online(old_state))
			__connman_notifier_connect(service->type);

		method = __connman_ipconfig_get_method(service->ipconfig_ipv6);
		if (method == CONNMAN_IPCONFIG_METHOD_OFF)
			__connman_ipconfig_disable_ipv6(
						service->ipconfig_ipv6);

		if (connman_setting_get_bool("SingleConnectedTechnology"))
			single_connected_tech(service);
		else if (service->type != CONNMAN_SERVICE_TYPE_VPN)
			vpn_auto_connect();

		break;

	case CONNMAN_SERVICE_STATE_ONLINE:

		break;

	case CONNMAN_SERVICE_STATE_DISCONNECT:
		clear_error(service);

		reply_pending(service, ECONNABORTED);

		DEFAULT_CHANGED();

		cancel_online_check(service, CONNMAN_IPCONFIG_TYPE_ALL);

		__connman_wispr_stop(service);

		online_check_state_reset(service);

		__connman_wpad_stop(service);

		domain_changed(service);
		proxy_changed(service);

		/*
		 * Previous services which are connected and which states
		 * are set to online should reset relevantly ipconfig_state
		 * to ready so wispr/portal will be rerun on those
		 */
		downgrade_connected_services();

		do_auto_connect(service, CONNMAN_SERVICE_CONNECT_REASON_AUTO);
		break;

	case CONNMAN_SERVICE_STATE_FAILURE:
		if (service->connect_reason == CONNMAN_SERVICE_CONNECT_REASON_USER ||
			service->connect_reason == CONNMAN_SERVICE_CONNECT_REASON_NATIVE) {
			result = connman_agent_report_error(service,
						service->path,
						error2string(service->error),
						report_error_cb,
						get_dbus_sender(service),
						NULL);
			if (result == -EINPROGRESS)
				goto notifier;
		}
		service_complete(service);
		break;
	}

	SERVICE_LIST_SORT();

	__connman_gateway_update();

notifier:
	if ((old_state == CONNMAN_SERVICE_STATE_ONLINE &&
			new_state != CONNMAN_SERVICE_STATE_READY) ||
		(old_state == CONNMAN_SERVICE_STATE_READY &&
			new_state != CONNMAN_SERVICE_STATE_ONLINE)) {
		__connman_notifier_disconnect(service->type);
	}

	if (is_online(new_state)) {
		__connman_notifier_enter_online(service->type);
		DEFAULT_CHANGED();
	}

	return 0;
}

int __connman_service_indicate_error(struct connman_service *service,
					enum connman_service_error error)
{
	DBG("service %p error %d", service, error);

	if (!service)
		return -EINVAL;

	if (service->state == CONNMAN_SERVICE_STATE_FAILURE)
		return -EALREADY;

	set_error(service, error);

	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	return 0;
}

int __connman_service_clear_error(struct connman_service *service)
{
	DBusMessage *pending;

	DBG("service %p", service);

	if (!service)
		return -EINVAL;

	if (service->state != CONNMAN_SERVICE_STATE_FAILURE)
		return -EINVAL;

	pending = service->pending;
	service->pending = NULL;

	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_IDLE,
						CONNMAN_IPCONFIG_TYPE_IPV6);

	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_IDLE,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	service->pending = pending;

	return 0;
}

int __connman_service_indicate_default(struct connman_service *service)
{
	DBG("service %p (%s) state %d (%s)",
		service, connman_service_get_identifier(service),
		service->state, state2string(service->state));

	if (!is_connected(service->state)) {
		/*
		 * If service is not yet fully connected, then we must not
		 * change the default yet. The default gw will be changed
		 * after the service state is in ready.
		 */
		return -EINPROGRESS;
	}

	DEFAULT_CHANGED();

	return 0;
}

enum connman_service_state __connman_service_ipconfig_get_state(
					struct connman_service *service,
					enum connman_ipconfig_type type)
{
	if (!service)
		return CONNMAN_SERVICE_STATE_UNKNOWN;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		return service->state_ipv4;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		return service->state_ipv6;

	return CONNMAN_SERVICE_STATE_UNKNOWN;
}

/*
 * How many networks are connected at the same time. If more than 1,
 * then set the rp_filter setting properly (loose mode routing) so that network
 * connectivity works ok. This is only done for IPv4 networks as IPv6
 * does not have rp_filter knob.
 */
static int connected_networks_count;
static int original_rp_filter;

static void service_rp_filter(struct connman_service *service,
				bool connected)
{
	enum connman_ipconfig_method method;

	method = __connman_ipconfig_get_method(service->ipconfig_ipv4);

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		return;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		break;
	}

	if (connected) {
		if (connected_networks_count == 1) {
			int filter_value;
			filter_value = __connman_ipconfig_set_rp_filter();
			if (filter_value < 0)
				return;

			original_rp_filter = filter_value;
		}
		connected_networks_count++;

	} else {
		if (connected_networks_count == 2)
			__connman_ipconfig_unset_rp_filter(original_rp_filter);

		connected_networks_count--;
		if (connected_networks_count < 0)
			connected_networks_count = 0;
	}

	DBG("%s %s ipconfig %p method %d count %d filter %d",
		connected ? "connected" : "disconnected", service->identifier,
		service->ipconfig_ipv4, method,
		connected_networks_count, original_rp_filter);
}

int __connman_service_ipconfig_indicate_state(struct connman_service *service,
					enum connman_service_state new_state,
					enum connman_ipconfig_type type)
{
	struct connman_ipconfig *ipconfig = NULL;
	enum connman_service_state old_state;
	enum connman_ipconfig_method method;

	if (!service)
		return -EINVAL;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
	case CONNMAN_IPCONFIG_TYPE_ALL:
		return -EINVAL;

	case CONNMAN_IPCONFIG_TYPE_IPV4:
		old_state = service->state_ipv4;
		ipconfig = service->ipconfig_ipv4;

		break;

	case CONNMAN_IPCONFIG_TYPE_IPV6:
		old_state = service->state_ipv6;
		ipconfig = service->ipconfig_ipv6;

		break;
	}

	if (!ipconfig)
		return -EINVAL;

	method = __connman_ipconfig_get_method(ipconfig);

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		if (new_state != CONNMAN_SERVICE_STATE_IDLE)
			connman_warn("ipconfig state %d ipconfig method %d",
				new_state, method);

		new_state = CONNMAN_SERVICE_STATE_IDLE;
		break;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		break;

	}

	/* Any change? */
	if (old_state == new_state)
		return -EALREADY;

	DBG("service %p (%s) type %d (%s) old state %d (%s) new state %d (%s)",
		service, connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		old_state, state2string(old_state),
		new_state, state2string(new_state));

	switch (new_state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		break;
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		break;
	case CONNMAN_SERVICE_STATE_READY:
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			service_rp_filter(service, true);
		set_mdns(service, service->mdns_config);
		break;
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		if (service->state == CONNMAN_SERVICE_STATE_IDLE)
			return -EINVAL;

		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			service_rp_filter(service, false);

		break;

	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_FAILURE:
		__connman_ipconfig_disable(ipconfig);

		break;
	}

	if (is_connected(old_state) && !is_connected(new_state)) {
		nameserver_remove_all(service, type);
		cancel_online_check(service, type);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		service->state_ipv4 = new_state;
	else
		service->state_ipv6 = new_state;

	if (!is_connected(old_state) && is_connected(new_state)) {
		nameserver_add_all(service, type);

		/*
		 * Care must be taken here in a multi-technology and -service
		 * environment. In such an environment, there may be a senior,
		 * default service that is providing the network service for
		 * time-of-day synchronization.
		 *
		 * Without an appropriate qualifier here, a junior,
		 * non-default service may come in and usurp the senior,
		 * default service and start trying to provide time-of-day
		 * synchronization which is NOT what is desired.
		 *
		 * However, this qualifier should NOT be moved to the next
		 * most outer block. Otherwise, name servers will not be added
		 * to junior, non-default services and they will be unusable
		 * from a DNS perspective.
		 */
		if (connman_service_is_default(service))
			__connman_timeserver_sync(service,
				CONNMAN_TIMESERVER_SYNC_REASON_STATE_UPDATE);
	}

	return service_indicate_state(service);
}

static bool prepare_network(struct connman_service *service)
{
	enum connman_network_type type;
	unsigned int ssid_len;

	type = connman_network_get_type(service->network);

	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		return false;
	case CONNMAN_NETWORK_TYPE_WIFI:
		if (!connman_network_get_blob(service->network, "WiFi.SSID",
						&ssid_len))
			return false;

		if (service->passphrase)
			connman_network_set_string(service->network,
				"WiFi.Passphrase", service->passphrase);
		break;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
	case CONNMAN_NETWORK_TYPE_GADGET:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
	case CONNMAN_NETWORK_TYPE_CELLULAR:
		break;
	}

	return true;
}

static void prepare_8021x(struct connman_service *service)
{
	if (service->eap)
		connman_network_set_string(service->network, "WiFi.EAP",
								service->eap);

	if (service->identity)
		connman_network_set_string(service->network, "WiFi.Identity",
							service->identity);

	if (service->anonymous_identity)
		connman_network_set_string(service->network,
						"WiFi.AnonymousIdentity",
						service->anonymous_identity);

	if (service->ca_cert_file)
		connman_network_set_string(service->network, "WiFi.CACertFile",
							service->ca_cert_file);

	if (service->subject_match)
		connman_network_set_string(service->network, "WiFi.SubjectMatch",
							service->subject_match);

	if (service->altsubject_match)
		connman_network_set_string(service->network, "WiFi.AltSubjectMatch",
							service->altsubject_match);

	if (service->domain_suffix_match)
		connman_network_set_string(service->network, "WiFi.DomainSuffixMatch",
							service->domain_suffix_match);

	if (service->domain_match)
		connman_network_set_string(service->network, "WiFi.DomainMatch",
							service->domain_match);

	if (service->client_cert_file)
		connman_network_set_string(service->network,
						"WiFi.ClientCertFile",
						service->client_cert_file);

	if (service->private_key_file)
		connman_network_set_string(service->network,
						"WiFi.PrivateKeyFile",
						service->private_key_file);

	if (service->private_key_passphrase)
		connman_network_set_string(service->network,
					"WiFi.PrivateKeyPassphrase",
					service->private_key_passphrase);

	if (service->phase2)
		connman_network_set_string(service->network, "WiFi.Phase2",
							service->phase2);
}

static int service_connect(struct connman_service *service)
{
	int err;

	if (service->hidden)
		return -EPERM;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		return -EINVAL;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_VPN:
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		switch (service->security) {
		case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		case CONNMAN_SERVICE_SECURITY_NONE:
			break;
		case CONNMAN_SERVICE_SECURITY_WEP:
		case CONNMAN_SERVICE_SECURITY_PSK:
		case CONNMAN_SERVICE_SECURITY_WPA:
		case CONNMAN_SERVICE_SECURITY_RSN:
			if (service->error == CONNMAN_SERVICE_ERROR_INVALID_KEY)
				return -ENOKEY;

			if (!service->passphrase) {
				if (!service->network)
					return -EOPNOTSUPP;

				if (!service->wps ||
					!connman_network_get_bool(service->network, "WiFi.UseWPS"))
					return -ENOKEY;
			}
			break;

		case CONNMAN_SERVICE_SECURITY_8021X:
			if (!service->eap) {
				connman_warn("EAP type has not been found. "
					"Most likely ConnMan is not able to "
					"find a configuration for given "
					"8021X network. "
					"Check SSID or Name match with the "
					"network name.");
				return -EINVAL;
			}

			/*
			 * never request credentials if using EAP-TLS
			 * (EAP-TLS networks need to be fully provisioned)
			 */
			if (g_str_equal(service->eap, "tls"))
				break;

			/*
			 * Return -ENOKEY if either identity or passphrase is
			 * missing. Agent provided credentials can be used as
			 * fallback if needed.
			 */
			if (((!service->identity &&
					!service->agent_identity) ||
					!service->passphrase) ||
					service->error == CONNMAN_SERVICE_ERROR_INVALID_KEY)
				return -ENOKEY;

			break;
		}
		break;
	}

	if (service->network) {
		if (!prepare_network(service))
			return -EINVAL;

		switch (service->security) {
		case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		case CONNMAN_SERVICE_SECURITY_NONE:
		case CONNMAN_SERVICE_SECURITY_WEP:
		case CONNMAN_SERVICE_SECURITY_PSK:
		case CONNMAN_SERVICE_SECURITY_WPA:
		case CONNMAN_SERVICE_SECURITY_RSN:
			break;
		case CONNMAN_SERVICE_SECURITY_8021X:
			prepare_8021x(service);
			break;
		}

		if (__connman_stats_service_register(service) == 0) {
			__connman_stats_get(service, false,
						&service->stats.data);
			__connman_stats_get(service, true,
						&service->stats_roaming.data);
		}

		err = __connman_network_connect(service->network);
	} else if (service->type == CONNMAN_SERVICE_TYPE_VPN &&
					service->provider)
		err = __connman_provider_connect(service->provider,
						get_dbus_sender(service));
	else
		return -EOPNOTSUPP;

	if (err < 0) {
		if (err != -EINPROGRESS) {
			__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV4);
			__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV6);
			__connman_stats_service_unregister(service);
		}
	}

	return err;
}

int __connman_service_connect(struct connman_service *service,
			enum connman_service_connect_reason reason)
{
	int index;
	int err;

	DBG("service %p state %s connect reason %s -> %s",
		service, state2string(service->state),
		reason2string(service->connect_reason),
		reason2string(reason));

	if (is_connected(service->state))
		return -EISCONN;

	if (is_connecting(service->state))
		return -EALREADY;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		return -EINVAL;

	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_WIFI:
		break;
	}

	if (!is_ipconfig_usable(service))
		return -ENOLINK;

	__connman_service_clear_error(service);

	if (service->network && service->autoconnect &&
			__connman_network_native_autoconnect(service->network)) {
		DBG("service %p switch connecting reason to native", service);
		reason = CONNMAN_SERVICE_CONNECT_REASON_NATIVE;
	}

	err = service_connect(service);

	DBG("service %p err %d", service, err);

	service->connect_reason = reason;

	if (err >= 0)
		return 0;

	if (err == -EINPROGRESS) {
		/*
		 * VPN will start connect timeout when it enters CONFIGURATION
		 * state.
		 */
		if (service->type != CONNMAN_SERVICE_TYPE_VPN)
			__connman_service_start_connect_timeout(service, false);

		return -EINPROGRESS;
	}

	if (service->network)
		__connman_network_disconnect(service->network);
	else if (service->type == CONNMAN_SERVICE_TYPE_VPN &&
				service->provider)
			connman_provider_disconnect(service->provider);

	if (reason == CONNMAN_SERVICE_CONNECT_REASON_USER ||
			reason == CONNMAN_SERVICE_CONNECT_REASON_NATIVE) {
		if (err == -ENOKEY || err == -EPERM) {
			DBusMessage *pending = NULL;
			const char *dbus_sender = get_dbus_sender(service);

			/*
			 * We steal the reply here. The idea is that the
			 * connecting client will see the connection status
			 * after the real hidden network is connected or
			 * connection failed.
			 */
			if (service->hidden) {
				pending = service->pending;
				service->pending = NULL;
			}

			if (service->hidden_service &&
			service->error == CONNMAN_SERVICE_ERROR_INVALID_KEY) {
				__connman_service_indicate_error(service,
					CONNMAN_SERVICE_ERROR_INVALID_KEY);
				return err;
			}

			err = __connman_agent_request_passphrase_input(service,
					request_input_cb,
					dbus_sender,
					pending);
			if (service->hidden && err != -EINPROGRESS)
				service->pending = pending;

			if (err == -EINPROGRESS) {
				index = __connman_service_get_index(service);
				g_hash_table_replace(passphrase_requested,
						GINT_TO_POINTER(index),
						GINT_TO_POINTER(true));
			}

			return err;
		}
	}

	return err;
}

int __connman_service_disconnect(struct connman_service *service)
{
	int err;

	DBG("service %p", service);

	service->connect_reason = CONNMAN_SERVICE_CONNECT_REASON_NONE;
	service->proxy = CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;

	connman_agent_cancel(service);

	__connman_stats_service_unregister(service);

	if (service->network) {
		err = __connman_network_disconnect(service->network);
	} else if (service->type == CONNMAN_SERVICE_TYPE_VPN &&
					service->provider)
		err = connman_provider_disconnect(service->provider);
	else
		return -EOPNOTSUPP;

	if (err < 0 && err != -EINPROGRESS)
		return err;

	__connman_6to4_remove(service->ipconfig_ipv4);

	if (service->ipconfig_ipv4)
		__connman_ipconfig_set_proxy_autoconfig(service->ipconfig_ipv4,
							NULL);
	else
		__connman_ipconfig_set_proxy_autoconfig(service->ipconfig_ipv6,
							NULL);

	__connman_ipconfig_address_remove(service->ipconfig_ipv4);
	settings_changed(service, service->ipconfig_ipv4);

	__connman_ipconfig_address_remove(service->ipconfig_ipv6);
	settings_changed(service, service->ipconfig_ipv6);

	__connman_ipconfig_disable(service->ipconfig_ipv4);
	__connman_ipconfig_disable(service->ipconfig_ipv6);

	return err;
}

/**
 * lookup_by_identifier:
 * @identifier: service identifier
 *
 * Look up a service by identifier (reference count will not be increased)
 */
static struct connman_service *lookup_by_identifier(const char *identifier)
{
	return g_hash_table_lookup(service_hash, identifier);
}

struct connman_service *connman_service_lookup_from_identifier(const char* identifier)
{
	return identifier ? lookup_by_identifier(identifier) : NULL;
}

struct provision_user_data {
	const char *ident;
	int ret;
};

static void provision_changed(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	struct provision_user_data *data = user_data;
	const char *path = data->ident;
	int ret;

	ret = __connman_config_provision_service_ident(service, path,
			service->config_file, service->config_entry);
	if (ret > 0)
		data->ret = ret;
}

int __connman_service_provision_changed(const char *ident)
{
	struct provision_user_data data = {
		.ident = ident,
		.ret = 0
	};

	g_list_foreach(service_list, provision_changed, (void *)&data);

	/*
	 * Because the provision_changed() might have set some services
	 * as favorite, we must sort the sequence now.
	 */
	if (services_dirty) {
		services_dirty = false;

		SERVICE_LIST_SORT();

		__connman_gateway_update();
	}

	return data.ret;
}

void __connman_service_set_config(struct connman_service *service,
				const char *file_id, const char *entry)
{
	if (!service)
		return;

	g_free(service->config_file);
	service->config_file = g_strdup(file_id);

	g_free(service->config_entry);
	service->config_entry = g_strdup(entry);
}

/**
 * __connman_service_get:
 * @identifier: service identifier
 *
 * Look up a service by identifier or create a new one if not found
 */
static struct connman_service *service_get(const char *identifier)
{
	struct connman_service *service;

	service = g_hash_table_lookup(service_hash, identifier);
	if (service) {
		connman_service_ref(service);
		return service;
	}

	service = connman_service_create();
	if (!service)
		return NULL;

	DBG("service %p", service);

	service->identifier = g_strdup(identifier);

	service_list = g_list_insert_sorted(service_list, service,
						service_compare);

	g_hash_table_insert(service_hash, service->identifier, service);

	return service;
}

static int service_register(struct connman_service *service)
{
	DBG("service %p", service);

	if (service->path)
		return -EALREADY;

	service->path = g_strdup_printf("%s/service/%s", CONNMAN_PATH,
						service->identifier);

	DBG("path %s", service->path);

	g_dbus_register_interface(connection, service->path,
					CONNMAN_SERVICE_INTERFACE,
					service_methods, service_signals,
							NULL, service, NULL);

	if (__connman_config_provision_service(service) < 0)
		service_load(service);

	SERVICE_LIST_SORT();

	__connman_gateway_update();

	return 0;
}

static void service_up(struct connman_ipconfig *ipconfig,
		const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s up", ifname);

	link_changed(service);

	service->stats.valid = false;
	service->stats_roaming.valid = false;
}

static void service_down(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	DBG("%s down", ifname);
}

static void service_lower_up(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s lower up", ifname);

	stats_start(service);
}

static void service_lower_down(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s lower down", ifname);

	stats_stop(service);
	service_save(service);
}

static void service_ip_bound(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);
	enum connman_ipconfig_method method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
	enum connman_ipconfig_type type = CONNMAN_IPCONFIG_TYPE_UNKNOWN;

	DBG("%s ip bound", ifname);

	type = __connman_ipconfig_get_config_type(ipconfig);
	method = __connman_ipconfig_get_method(ipconfig);

	DBG("service %p (%s) type %d (%s) ipconfig %p method %d (%s)",
		service, connman_service_get_identifier(service),
		type, __connman_ipconfig_type2string(type),
		ipconfig, method, __connman_ipconfig_method2string(method));

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
			method == CONNMAN_IPCONFIG_METHOD_AUTO)
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV6);

	settings_changed(service, ipconfig);
	address_updated(service, type);
}

static void service_ip_release(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);
	enum connman_ipconfig_method method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
	enum connman_ipconfig_type type = CONNMAN_IPCONFIG_TYPE_UNKNOWN;

	DBG("%s ip release", ifname);

	type = __connman_ipconfig_get_config_type(ipconfig);
	method = __connman_ipconfig_get_method(ipconfig);

	DBG("service %p ipconfig %p type %d method %d", service, ipconfig,
							type, method);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
			method == CONNMAN_IPCONFIG_METHOD_OFF)
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV6);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
			method == CONNMAN_IPCONFIG_METHOD_OFF)
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	settings_changed(service, ipconfig);
}

/**
 *  @brief
 *    Handler for IP configuration routes changes.
 *
 *  This is the IP configuration handler for route set (add) and unset
 *  (delete) operations for the specified IP configuration and its
 *  associated network interface name.
 *
 *  @param[in]  ipconfig  A pointer to the IP configuration associated
 *                        with the network service route change.
 *  @param[in]  ifname    A pointer to an immutable null-terminated
 *                        C string containing the network interface
 *                        name associated with the route change.
 *
 *  @sa __connman_ipconfig_set_data
 *  @sa __connman_ipconfig_set_ops
 *  @sa settings_changed
 *
 */
static void service_route_changed(struct connman_ipconfig *ipconfig,
				const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("service %p (%s) ipconfig %p ifname %s route changed",
		service, connman_service_get_identifier(service),
		ipconfig,
		ifname);

	settings_changed(service, ipconfig);
}

static const struct connman_ipconfig_ops service_ops = {
	.up		= service_up,
	.down		= service_down,
	.lower_up	= service_lower_up,
	.lower_down	= service_lower_down,
	.ip_bound	= service_ip_bound,
	.ip_release	= service_ip_release,
	.route_set	= service_route_changed,
	.route_unset	= service_route_changed,
};

static struct connman_ipconfig *create_ip4config(struct connman_service *service,
		int index, enum connman_ipconfig_method method)
{
	struct connman_ipconfig *ipconfig_ipv4;

	ipconfig_ipv4 = __connman_ipconfig_create(index,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	if (!ipconfig_ipv4)
		return NULL;

	__connman_ipconfig_set_method(ipconfig_ipv4, method);

	__connman_ipconfig_set_data(ipconfig_ipv4, service);

	__connman_ipconfig_set_ops(ipconfig_ipv4, &service_ops);

	return ipconfig_ipv4;
}

static struct connman_ipconfig *create_ip6config(struct connman_service *service,
		int index)
{
	struct connman_ipconfig *ipconfig_ipv6;

	ipconfig_ipv6 = __connman_ipconfig_create(index,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	if (!ipconfig_ipv6)
		return NULL;

	__connman_ipconfig_set_data(ipconfig_ipv6, service);

	__connman_ipconfig_set_ops(ipconfig_ipv6, &service_ops);

	return ipconfig_ipv6;
}

void __connman_service_read_ip4config(struct connman_service *service)
{
	GKeyFile *keyfile;

	if (!service->ipconfig_ipv4)
		return;

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return;

	__connman_ipconfig_load(service->ipconfig_ipv4, keyfile,
				service->identifier, "IPv4.");

	g_key_file_free(keyfile);
}

void connman_service_create_ip4config(struct connman_service *service,
					int index)
{
	DBG("ipv4 %p", service->ipconfig_ipv4);

	if (service->ipconfig_ipv4)
		return;

	service->ipconfig_ipv4 = create_ip4config(service, index,
			CONNMAN_IPCONFIG_METHOD_DHCP);
	__connman_service_read_ip4config(service);
}

void __connman_service_read_ip6config(struct connman_service *service)
{
	GKeyFile *keyfile;

	if (!service->ipconfig_ipv6)
		return;

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return;

	__connman_ipconfig_load(service->ipconfig_ipv6, keyfile,
				service->identifier, "IPv6.");

	g_key_file_free(keyfile);
}

void connman_service_create_ip6config(struct connman_service *service,
								int index)
{
	DBG("ipv6 %p", service->ipconfig_ipv6);

	if (service->ipconfig_ipv6)
		return;

	service->ipconfig_ipv6 = create_ip6config(service, index);

	__connman_service_read_ip6config(service);
}

/**
 * connman_service_lookup_from_network:
 * @network: network structure
 *
 * Look up a service by network (reference count will not be increased)
 */
struct connman_service *connman_service_lookup_from_network(struct connman_network *network)
{
	struct connman_service *service;
	const char *ident, *group;
	char *name;

	if (!network)
		return NULL;

	ident = __connman_network_get_ident(network);
	if (!ident)
		return NULL;

	group = connman_network_get_group(network);
	if (!group)
		return NULL;

	name = g_strdup_printf("%s_%s_%s",
			__connman_network_get_type(network), ident, group);
	service = lookup_by_identifier(name);
	g_free(name);

	return service;
}

struct connman_service *__connman_service_lookup_from_index(int index)
{
	struct connman_service *service;
	GList *list;

	for (list = service_list; list; list = list->next) {
		service = list->data;

		if (__connman_ipconfig_get_index(service->ipconfig_ipv4)
							== index)
			return service;

		if (__connman_ipconfig_get_index(service->ipconfig_ipv6)
							== index)
			return service;
	}

	return NULL;
}

const char *connman_service_get_identifier(const struct connman_service *service)
{
	return service ? service->identifier : "<null>";
}

const char *__connman_service_get_path(const struct connman_service *service)
{
	return service->path;
}

const char *__connman_service_get_name(const struct connman_service *service)
{
	return service->name;
}

enum connman_service_state connman_service_get_state(const struct connman_service *service)
{
	return service ? service->state : CONNMAN_SERVICE_STATE_UNKNOWN;
}

static enum connman_service_type convert_network_type(struct connman_network *network)
{
	enum connman_network_type type = connman_network_get_type(network);

	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		break;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	case CONNMAN_NETWORK_TYPE_WIFI:
		return CONNMAN_SERVICE_TYPE_WIFI;
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	case CONNMAN_NETWORK_TYPE_CELLULAR:
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	case CONNMAN_NETWORK_TYPE_GADGET:
		return CONNMAN_SERVICE_TYPE_GADGET;
	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

static enum connman_service_security convert_wifi_security(const char *security)
{
	if (!security)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;
	else if (g_str_equal(security, "none"))
		return CONNMAN_SERVICE_SECURITY_NONE;
	else if (g_str_equal(security, "wep"))
		return CONNMAN_SERVICE_SECURITY_WEP;
	else if (g_str_equal(security, "psk"))
		return CONNMAN_SERVICE_SECURITY_PSK;
	else if (g_str_equal(security, "ieee8021x"))
		return CONNMAN_SERVICE_SECURITY_8021X;
	else if (g_str_equal(security, "wpa"))
		return CONNMAN_SERVICE_SECURITY_WPA;
	else if (g_str_equal(security, "rsn"))
		return CONNMAN_SERVICE_SECURITY_RSN;
	else
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;
}

static void update_wps_values(struct connman_service *service,
				struct connman_network *network)
{
	bool wps = connman_network_get_bool(network, "WiFi.WPS");
	bool wps_advertising = connman_network_get_bool(network,
							"WiFi.WPSAdvertising");

	if (service->wps != wps ||
			service->wps_advertizing != wps_advertising) {
		service->wps = wps;
		service->wps_advertizing = wps_advertising;
		security_changed(service);
	}
}

static void update_from_network(struct connman_service *service,
					struct connman_network *network)
{
	uint8_t strength = service->strength;
	const char *str;

	DBG("service %p network %p", service, network);

	if (is_connected(service->state))
		return;

	if (is_connecting(service->state))
		return;

	str = connman_network_get_string(network, "Name");
	if (str) {
		g_free(service->name);
		service->name = g_strdup(str);
		service->hidden = false;
	} else {
		g_free(service->name);
		service->name = NULL;
		service->hidden = true;
	}

	service->strength = connman_network_get_strength(network);
	service->roaming = connman_network_get_bool(network, "Roaming");

	if (service->strength == 0) {
		/*
		 * Filter out 0-values; it's unclear what they mean
		 * and they cause anomalous sorting of the priority list.
		 */
		service->strength = strength;
	}

	str = connman_network_get_string(network, "WiFi.Security");
	service->security = convert_wifi_security(str);

	if (service->type == CONNMAN_SERVICE_TYPE_WIFI)
		update_wps_values(service, network);

	if (service->strength > strength && service->network) {
		connman_network_unref(service->network);
		service->network = connman_network_ref(network);

		strength_changed(service);
	}

	if (!service->network)
		service->network = connman_network_ref(network);

	SERVICE_LIST_SORT();
}

static void trigger_autoconnect(struct connman_service *service)
{
	struct connman_device *device;
	bool native;

	if (!service->favorite)
		return;

	native = __connman_network_native_autoconnect(service->network);
	if (native && service->autoconnect) {
		DBG("trigger native autoconnect");
		connman_network_set_autoconnect(service->network, true);
		return;
	}

	device = connman_network_get_device(service->network);
	if (device && connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_UNKNOWN))
		return;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;

	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		if (service->autoconnect) {
			__connman_service_connect(service,
						CONNMAN_SERVICE_CONNECT_REASON_AUTO);
			break;
		}

		/* fall through */
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		do_auto_connect(service, CONNMAN_SERVICE_CONNECT_REASON_AUTO);
		break;
	}
}

/**
 * __connman_service_create_from_network:
 * @network: network structure
 *
 * Look up service by network and if not found, create one
 */
struct connman_service * __connman_service_create_from_network(struct connman_network *network)
{
	struct connman_service *service;
	const char *ident, *group;
	char *name;
	unsigned int *auto_connect_types, *favorite_types;
	int i, index;

	DBG("network %p", network);

	if (!network)
		return NULL;

	ident = __connman_network_get_ident(network);
	if (!ident)
		return NULL;

	group = connman_network_get_group(network);
	if (!group)
		return NULL;

	name = g_strdup_printf("%s_%s_%s",
			__connman_network_get_type(network), ident, group);
	service = service_get(name);
	g_free(name);

	if (!service)
		return NULL;

	if (__connman_network_get_weakness(network))
		return service;

	index = connman_network_get_index(network);

	if (service->path) {
		update_from_network(service, network);

		if (service->ipconfig_ipv4)
			__connman_ipconfig_set_index(service->ipconfig_ipv4,
									index);

		if (service->ipconfig_ipv6)
			__connman_ipconfig_set_index(service->ipconfig_ipv6,
									index);

		__connman_gateway_update();
		return service;
	}

	service->type = convert_network_type(network);

	auto_connect_types = connman_setting_get_uint_list("DefaultAutoConnectTechnologies");
	service->autoconnect = false;
	for (i = 0; auto_connect_types &&
		     auto_connect_types[i] != 0; i++) {
		if (service->type == auto_connect_types[i]) {
			service->autoconnect = true;
			break;
		}
	}

	favorite_types = connman_setting_get_uint_list("DefaultFavoriteTechnologies");
	service->favorite = false;
	for (i = 0; favorite_types && favorite_types[i] != 0; i++) {
		if (service->type == favorite_types[i]) {
			service->favorite = true;
			break;
		}
	}

	service->state_ipv4 = service->state_ipv6 = CONNMAN_SERVICE_STATE_IDLE;
	service->state = combine_state(service->state_ipv4, service->state_ipv6);

	update_from_network(service, network);

	if (!service->ipconfig_ipv4)
		service->ipconfig_ipv4 = create_ip4config(service, index,
				CONNMAN_IPCONFIG_METHOD_DHCP);
	else
		__connman_ipconfig_set_index(service->ipconfig_ipv4, index);

	if (!service->ipconfig_ipv6)
		service->ipconfig_ipv6 = create_ip6config(service, index);
	else
		__connman_ipconfig_set_index(service->ipconfig_ipv6, index);

	service_register(service);
	service_schedule_added(service);

	trigger_autoconnect(service);

	__connman_notifier_service_add(service, service->name);

	return service;
}

void __connman_service_update_from_network(struct connman_network *network)
{
	bool need_sort = false;
	struct connman_service *service;
	uint8_t strength;
	bool roaming;
	const char *name;
	bool stats_enable;

	service = connman_service_lookup_from_network(network);
	if (!service)
		return;

	if (!service->network)
		return;

	name = connman_network_get_string(service->network, "Name");
	if (g_strcmp0(service->name, name) != 0) {
		g_free(service->name);
		service->name = g_strdup(name);

		if (allow_property_changed(service))
			connman_dbus_property_changed_basic(service->path,
					CONNMAN_SERVICE_INTERFACE, "Name",
					DBUS_TYPE_STRING, &service->name);
	}

	if (service->type == CONNMAN_SERVICE_TYPE_WIFI)
		update_wps_values(service, network);

	strength = connman_network_get_strength(service->network);
	if (strength == service->strength)
		goto roaming;

	service->strength = strength;
	need_sort = true;

	strength_changed(service);

roaming:
	roaming = connman_network_get_bool(service->network, "Roaming");
	if (roaming == service->roaming)
		goto sorting;

	stats_enable = stats_enabled(service);
	if (stats_enable)
		stats_stop(service);

	service->roaming = roaming;
	need_sort = true;

	if (stats_enable)
		stats_start(service);

	roaming_changed(service);

sorting:
	if (need_sort) {
		SERVICE_LIST_SORT();
	}
}

void __connman_service_remove_from_network(struct connman_network *network)
{
	struct connman_service *service;

	service = connman_service_lookup_from_network(network);

	DBG("network %p service %p", network, service);

	if (!service)
		return;

	service->ignore = true;

	__connman_gateway_remove(service,
					CONNMAN_IPCONFIG_TYPE_ALL);

	connman_service_unref(service);
}

/**
 * __connman_service_create_from_provider:
 * @provider: provider structure
 *
 * Look up service by provider and if not found, create one
 */
struct connman_service *
__connman_service_create_from_provider(struct connman_provider *provider)
{
	struct connman_service *service;
	const char *ident, *str;
	char *name;
	int index = connman_provider_get_index(provider);

	DBG("provider %p", provider);

	ident = __connman_provider_get_ident(provider);
	if (!ident)
		return NULL;

	name = g_strdup_printf("vpn_%s", ident);
	service = service_get(name);
	g_free(name);

	if (!service)
		return NULL;

	service->type = CONNMAN_SERVICE_TYPE_VPN;
	service->order = service->do_split_routing ? 0 : 10;
	service->provider = connman_provider_ref(provider);
	service->autoconnect = false;
	service->favorite = true;

	service->state_ipv4 = service->state_ipv6 = CONNMAN_SERVICE_STATE_IDLE;
	service->state = combine_state(service->state_ipv4, service->state_ipv6);

	str = connman_provider_get_string(provider, "Name");
	if (str) {
		g_free(service->name);
		service->name = g_strdup(str);
		service->hidden = false;
	} else {
		g_free(service->name);
		service->name = NULL;
		service->hidden = true;
	}

	service->strength = 0;

	if (!service->ipconfig_ipv4)
		service->ipconfig_ipv4 = create_ip4config(service, index,
				CONNMAN_IPCONFIG_METHOD_MANUAL);

	if (!service->ipconfig_ipv6)
		service->ipconfig_ipv6 = create_ip6config(service, index);

	service_register(service);

	__connman_notifier_service_add(service, service->name);
	service_schedule_added(service);

	return service;
}

static void remove_unprovisioned_services(void)
{
	gchar **services;
	GKeyFile *keyfile, *configkeyfile;
	char *file, *section;
	int i = 0;

	services = connman_storage_get_services();
	if (!services)
		return;

	for (; services[i]; i++) {
		file = section = NULL;
		keyfile = configkeyfile = NULL;

		keyfile = connman_storage_load_service(services[i]);
		if (!keyfile)
			continue;

		file = g_key_file_get_string(keyfile, services[i],
					"Config.file", NULL);
		if (!file)
			goto next;

		section = g_key_file_get_string(keyfile, services[i],
					"Config.ident", NULL);
		if (!section)
			goto next;

		configkeyfile = __connman_storage_load_config(file);
		if (!configkeyfile) {
			/*
			 * Config file is missing, remove the provisioned
			 * service.
			 */
			__connman_storage_remove_service(services[i]);
			goto next;
		}

		if (!g_key_file_has_group(configkeyfile, section))
			/*
			 * Config section is missing, remove the provisioned
			 * service.
			 */
			__connman_storage_remove_service(services[i]);

	next:
		if (keyfile)
			g_key_file_free(keyfile);

		if (configkeyfile)
			g_key_file_free(configkeyfile);

		g_free(section);
		g_free(file);
	}

	g_strfreev(services);
}

static int agent_probe(struct connman_agent *agent)
{
	DBG("agent %p", agent);
	return 0;
}

static void agent_remove(struct connman_agent *agent)
{
	DBG("agent %p", agent);
}

static void *agent_context_ref(void *context)
{
	struct connman_service *service = context;

	return (void *)connman_service_ref(service);
}

static void agent_context_unref(void *context)
{
	struct connman_service *service = context;

	connman_service_unref(service);
}

static struct connman_agent_driver agent_driver = {
	.name		= "service",
	.interface      = CONNMAN_AGENT_INTERFACE,
	.probe		= agent_probe,
	.remove		= agent_remove,
	.context_ref	= agent_context_ref,
	.context_unref	= agent_context_unref,
};

int __connman_service_init(void)
{
	int err;

	DBG("");

	err = connman_agent_driver_register(&agent_driver);
	if (err < 0) {
		connman_error("Cannot register agent driver for %s",
						agent_driver.name);
		return err;
	}

	set_always_connecting_technologies();

	connection = connman_dbus_get_connection();

	service_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, service_free);

	passphrase_requested = g_hash_table_new(g_direct_hash, g_direct_equal);

	services_notify = g_new0(struct _services_notify, 1);
	services_notify->remove = g_hash_table_new_full(g_str_hash,
			g_str_equal, g_free, NULL);
	services_notify->add = g_hash_table_new(g_str_hash, g_str_equal);

	remove_unprovisioned_services();

	online_check_timeout_interval_style =
		connman_setting_get_string("OnlineCheckIntervalStyle");
	if (g_strcmp0(online_check_timeout_interval_style, "fibonacci") == 0)
		online_check_timeout_compute_func = online_check_timeout_compute_fibonacci;
	else
		online_check_timeout_compute_func = online_check_timeout_compute_geometric;

	online_check_connect_timeout_ms =
		connman_setting_get_uint("OnlineCheckConnectTimeout");

	online_check_initial_interval =
		connman_setting_get_uint("OnlineCheckInitialInterval");
	online_check_max_interval =
		connman_setting_get_uint("OnlineCheckMaxInterval");

	return 0;
}

void __connman_service_cleanup(void)
{
	DBG("");

	if (vpn_autoconnect_id) {
		g_source_remove(vpn_autoconnect_id);
		vpn_autoconnect_id = 0;
	}

	if (autoconnect_id != 0) {
		g_source_remove(autoconnect_id);
		autoconnect_id = 0;
	}

	connman_agent_driver_unregister(&agent_driver);

	g_list_free(service_list);
	service_list = NULL;

	g_hash_table_destroy(service_hash);
	service_hash = NULL;

	g_hash_table_destroy(passphrase_requested);
	passphrase_requested = NULL;

	g_slist_free(counter_list);
	counter_list = NULL;

	if (services_notify->id != 0) {
		g_source_remove(services_notify->id);
		service_send_changed(NULL);
	}

	g_hash_table_destroy(services_notify->remove);
	g_hash_table_destroy(services_notify->add);
	g_free(services_notify);

	dbus_connection_unref(connection);
}
