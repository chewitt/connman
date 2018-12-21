/*
 *  Connection Manager
 *
 *  Copyright (C) 2018 Jolla Ltd. All rights reserved.
 *  Contact: David Llewellyn-Jones <david.llewellyn-jones@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <sys/inotify.h>
#include <gdbus.h>
#include <glib.h>

#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/storage.h>
#include <connman/inotify.h>
#include <connman/access.h>
#include <dbusaccess_peer.h>
#include <dbusaccess_policy.h>
#include "../src/connman.h"

#include "globalproxy.h"

#define CONNMAN_API_SUBJECT_TO_CHANGE

/*
 * # Examples
 *
 * See doc/globalproxy-api.txt for more detail.
 *
 * ## Get the active status
 *
 * gdbus call --system --dest net.connman --object-path / \
 * 	--method org.sailfishos.connman.GlobalProxy.GetProperty "Active"
 *
 * ## Get the global proxy configuration
 *
 * gdbus call --system --dest net.connman --object-path / \
 * 	--method org.sailfishos.connman.GlobalProxy.GetProperty "Configuration"
 *
 * ## Set the active status
 *
 * gdbus call --system --dest net.connman --object-path / \
 * 	--method org.sailfishos.connman.GlobalProxy.SetProperty \
 * 	"Active" \
 * 	"<false>"
 *
 * ## Set the global proxy configuration
 *
 * gdbus call --system --dest net.connman --object-path / \
 * 	--method org.sailfishos.connman.GlobalProxy.SetProperty \
 * 	"Configuration" \
 * 	"<{'Method':<'manual'>,'Servers': <['https://www.jolla.com:80']>}>"
 *
 * ## Test whether the proxy is being correctly passed to pacrunner
 *
 * gdbus call --system --dest org.pacrunner --object-path /org/pacrunner/client \
 *  --method org.pacrunner.Client.FindProxyForURL \
 *  "https://www.jolla.com" "www.jolla.com"
 *
 * # Configuration file format
 *
 * See doc/globalproxy-config-format.txt for more detail.
 *
 * Stored in <connman config dir>/global_proxy/settings
 * For example: /var/lib/connman/global_proxy/settings
 *
 * [global proxy]
 * Active=<true|false>
 * Proxy.Method=<direct|manual|auto>
 * Proxy.Servers=<url;...>
 * Proxy.Excludes=<domain;...>
 * Proxy.URL=<url>
 *
 */

#define DEFAULT_STORAGE_DIR_PERMISSIONS (0700)

#define GLOBALPROXY_CONFIGDIR "global_proxy"

#define GLOBALPROXY_CONFIGFILE "settings"

#define DBUS_KEY_ACTIVE "Active"
#define DBUS_KEY_CONFIGURATION "Configuration"

#define DBUS_KEY_METHOD "Method"
#define DBUS_KEY_SERVERS "Servers"
#define DBUS_KEY_EXCLUDES "Excludes"
#define DBUS_KEY_URL "URL"

#define DBUS_VALUE_TYPE_DIRECT "direct"
#define DBUS_VALUE_TYPE_MANUAL "manual"
#define DBUS_VALUE_TYPE_AUTO "auto"

#define CONFIG_GROUP_MAIN "global proxy"
#define CONFIG_KEY_ACTIVE DBUS_KEY_ACTIVE
#define CONFIG_KEY_METHOD "Proxy." DBUS_KEY_METHOD
#define CONFIG_KEY_PROXIES "Proxy." DBUS_KEY_SERVERS
#define CONFIG_KEY_EXCLUDES "Proxy." DBUS_KEY_EXCLUDES
#define CONFIG_KEY_URL "Proxy." DBUS_KEY_URL

/* Set properties (Get is always ACCESS_ALLOW for these) */
#define SET_PROXYACTIVE_ACCESS          CONNMAN_ACCESS_DENY
#define SET_PROXYCONFIG_ACCESS          CONNMAN_ACCESS_DENY

#define CONNMAN_BUS DA_BUS_SYSTEM

struct connman_global_proxy {
	dbus_bool_t active;
	enum connman_service_proxy_method config;
	char **proxies;
	char **excludes;
	char *pac;
};

enum globalproxy_access_action {
	GLOBALPROXY_ACCESS_SET_PROPERTY = 1
};

struct access_globalproxy_policy {
	DAPolicy *impl;
};

static DBusConnection *connection = NULL;
struct connman_global_proxy * proxy;
static GSList *notifier_list = NULL;
char *config_dir;
char *config_file;
struct access_globalproxy_policy *policy;

// Internal functions

// Lifecycle functions
int global_proxy_init(void);
void global_proxy_exit(void);
static void read_configuration();
static void write_configuration();
static void notify_handler(struct inotify_event *event,
				const char *filename,
				gpointer user_data);
static void register_handlers();
static void unregister_handlers();
static struct connman_global_proxy *global_proxy_create();
static void global_proxy_delete(struct connman_global_proxy * proxy);
static void global_proxy_reset(struct connman_global_proxy * proxy);
static struct connman_global_proxy *global_proxy_copy(
		struct connman_global_proxy * proxy);
static bool compare_active(
		struct connman_global_proxy * first,
		struct connman_global_proxy * second);
static bool compare_configuration(
		struct connman_global_proxy * first,
		struct connman_global_proxy * second);
static bool is_filename_valid(const char *filename);

// Helper functions
static char **remove_empty_strings(char **strv);
static enum connman_service_proxy_method string2proxymethod(const char *method);
static const char *proxymethod2string(enum connman_service_proxy_method method);
static DBusMessage *error_invalid_arguments(DBusMessage *msg);

// Set property functions
static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data);
static int set_configuration(DBusMessageIter *array);
static bool global_proxy_set_active(bool active);

// Get property functions
static DBusMessage *get_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data);
static DBusMessage *reply_proxy_active(DBusMessage *msg, dbus_bool_t *active);
static DBusMessage *reply_proxy_properties(DBusMessage *msg);
static void append_proxyconfig(DBusMessageIter *iter, void *user_data);
static void append_proxies(DBusMessageIter *iter, void *user_data);
static void append_excludes(DBusMessageIter *iter, void *user_data);

// Property changed functions
static void configuration_changed();
static void active_changed();

// Notification functions
static gint compare_priority(gconstpointer a, gconstpointer b);
static void notifier_active_changed(bool active);
static void notifier_config_changed();
static void notifier_proxy_changed();

// policy functions
static struct access_globalproxy_policy *
		access_globalproxy_policy_create(const char *spec);
static void access_globalproxy_policy_free
			(struct access_globalproxy_policy *p);
static enum connman_access access_globalproxy_set_property
		(const struct access_globalproxy_policy *policy,
			const char *name, const char *sender,
			enum connman_access default_access);
static gboolean check_set_property(const char *name, DBusMessage *msg,
		enum connman_access default_access);
static gboolean can_set_property(const char *name, DBusMessage *msg,
		enum connman_access default_access);




static const GDBusMethodTable global_proxy_methods[] = {
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL,
			set_property) },
	{ GDBUS_METHOD("GetProperty",
			GDBUS_ARGS({ "name", "s" }),
			GDBUS_ARGS({ "value", "v" }),
			get_property) },
	{ },
};

static const GDBusSignalTable global_proxy_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ },
};

static const char *globalproxy_policy_default =
	DA_POLICY_VERSION ";"
	"SetProperty(*)=deny;"
	"group(privileged)=allow";

static const DA_ACTION globalproxy_policy_actions [] = {
	{ "set",         GLOBALPROXY_ACCESS_SET_PROPERTY, 1 },
	{ "SetProperty", GLOBALPROXY_ACCESS_SET_PROPERTY, 1 },
	{ NULL }
};


int global_proxy_init(void)
{
	DBG("Global Proxy initialise");

	connection = connman_dbus_get_connection();

	proxy = global_proxy_create();
	if (!proxy)
		return -1;

	g_dbus_register_interface(connection, GLOBALPROXY_DBUS_PATH,
					GLOBALPROXY_CONNMAN_INTERFACE,
					global_proxy_methods,
					global_proxy_signals, NULL, NULL, NULL);

	config_dir = g_strdup_printf("%s/%s", connman_storage_dir(),
					GLOBALPROXY_CONFIGDIR);
	config_file = g_strdup_printf("%s/%s", config_dir,
					GLOBALPROXY_CONFIGFILE);
	read_configuration();
	register_handlers();

	policy = access_globalproxy_policy_create(NULL);
	DBG("Policy is %p", policy);

	return 0;
}

void global_proxy_exit(void)
{
	DBG("Global Proxy deinitialise");

	unregister_handlers();
	write_configuration();

	global_proxy_delete(proxy);
	proxy = NULL;

	g_free(config_dir);
	config_dir = NULL;
	g_free(config_file);
	config_file = NULL;

	access_globalproxy_policy_free(policy);
	policy = NULL;
}

static void read_configuration()
{
	GKeyFile *keyfile;
	bool result;
	gchar *method;

	if (!config_file)
		return;

	keyfile = g_key_file_new();

	DBG("Loading global proxy config: %s", config_file);
	result = g_key_file_load_from_file(keyfile, config_file, 0, NULL);

	if (result) {
		proxy->active = g_key_file_get_boolean(keyfile,
							CONFIG_GROUP_MAIN,
							CONFIG_KEY_ACTIVE,
							NULL);
		method = g_key_file_get_string(keyfile, CONFIG_GROUP_MAIN,
						CONFIG_KEY_METHOD, NULL);
		if (method) {
			proxy->config = string2proxymethod(method);
			g_free(method);
			method = NULL;
		}

		if (proxy->proxies) {
			g_strfreev(proxy->proxies);
		}
		proxy->proxies = g_key_file_get_string_list(keyfile,
							CONFIG_GROUP_MAIN,
							CONFIG_KEY_PROXIES,
							NULL, NULL);

		if (proxy->excludes) {
			g_strfreev(proxy->excludes);
		}
		proxy->excludes = g_key_file_get_string_list(keyfile,
							CONFIG_GROUP_MAIN,
							CONFIG_KEY_EXCLUDES,
							NULL, NULL);

		if (proxy->pac) {
			g_free(proxy->pac);
		}
		proxy->pac = g_key_file_get_string(keyfile, CONFIG_GROUP_MAIN,
							CONFIG_KEY_URL, NULL);

		g_key_file_unref(keyfile);
	}
}

static void write_configuration()
{
	GKeyFile *keyfile;
	GError *error = NULL;
	bool result;
	const char *method;

	if ((!config_dir) || (!config_file))
		return;

	keyfile = g_key_file_new();

	g_key_file_set_boolean(keyfile, CONFIG_GROUP_MAIN, CONFIG_KEY_ACTIVE,
				proxy->active);

	method = proxymethod2string(proxy->config);
	if (method) {
		g_key_file_set_string(keyfile, CONFIG_GROUP_MAIN,
					CONFIG_KEY_METHOD,
					method);
	}

	if (proxy->proxies) {
		g_key_file_set_string_list(keyfile, CONFIG_GROUP_MAIN,
					CONFIG_KEY_PROXIES,
					(gchar const * const *)proxy->proxies,
					g_strv_length(proxy->proxies));
	}

	if (proxy->excludes) {
		g_key_file_set_string_list(keyfile, CONFIG_GROUP_MAIN,
					CONFIG_KEY_EXCLUDES,
					(gchar const * const *)proxy->excludes,
					g_strv_length(proxy->excludes));
	}

	if (proxy->pac) {
		g_key_file_set_string(keyfile, CONFIG_GROUP_MAIN,
					CONFIG_KEY_URL,
					proxy->pac);
	}

	if (g_mkdir_with_parents(config_dir,
			DEFAULT_STORAGE_DIR_PERMISSIONS) < 0) {
		if (errno != EEXIST)
			DBG("Failed to create global proxy config directory");
	}

	DBG("connman: saving global proxy config: %s", config_file);
	result = g_key_file_save_to_file(keyfile, config_file, &error);

	if (!result && error && error->message) {
		DBG("Failed to save global proxy configuration");
		DBG("Error: %s", error->message);
		g_error_free(error);
		error = NULL;
	}

	g_key_file_unref(keyfile);
}

static void register_handlers()
{
	int err;

	DBG("Registering handler on path; %s", config_dir);
	err = connman_inotify_register(config_dir, notify_handler, NULL, NULL);
	if (err < 0)
		DBG("Failed to register global proxy config file notification handler");
}

static void unregister_handlers()
{
	DBG("Deregistering handler on path; %s", config_dir);
	connman_inotify_unregister(config_dir, notify_handler, NULL);
}

static void notify_handler(struct inotify_event *event,
				const char *filename,
				gpointer user_data)
{
	struct connman_global_proxy *previous;

	DBG("event %x file %s", event->mask, filename);

	if (event->mask & IN_CREATE)
		return;

	if (!is_filename_valid(filename))
		return;

	previous = global_proxy_copy(proxy);

	if (event->mask & (IN_DELETE | IN_MOVED_FROM)) {
		DBG("Configuration removed for '%s'", filename);
		global_proxy_reset(proxy);
	}

	if (event->mask & (IN_MOVED_TO | IN_MODIFY)) {
		DBG("Configuration update for '%s'", filename);
		read_configuration();
	}

	if (!compare_configuration(previous, proxy)) {
		DBG("Configuration changed");
		configuration_changed();
	}

	if (!compare_active(previous, proxy)) {
		DBG("Active changed");
		active_changed();
	}

	global_proxy_delete(previous);
}

static bool is_filename_valid(const char *filename)
{
	if (!filename)
		return false;

	if (filename[0] == '.')
		return false;

	return (g_strcmp0(filename, GLOBALPROXY_CONFIGFILE) == 0);
}

static struct connman_global_proxy *global_proxy_create()
{
	struct connman_global_proxy *proxy;
	proxy = g_try_new0(struct connman_global_proxy, 1);
	global_proxy_reset(proxy);

	return proxy;
}

static void global_proxy_delete(struct connman_global_proxy * proxy)
{
	if (proxy->proxies) {
		g_strfreev(proxy->proxies);
		proxy->proxies = NULL;
	}

	if (proxy->excludes) {
		g_strfreev(proxy->excludes);
		proxy->excludes = NULL;
	}

	if (proxy->pac) {
		g_free(proxy->pac);
		proxy->pac = NULL;
	}

	g_free(proxy);
}

static void global_proxy_reset(struct connman_global_proxy * proxy)
{
	proxy->active = false;
	proxy->config = CONNMAN_SERVICE_PROXY_METHOD_DIRECT;
	proxy->proxies = NULL;
	proxy->excludes = NULL;
	proxy->pac = NULL;
}

static struct connman_global_proxy *global_proxy_copy(
		struct connman_global_proxy * proxy)
{
	struct connman_global_proxy *copy = NULL;

	if (proxy) {
		copy = global_proxy_create();

		copy->active = proxy->active;
		copy->config = proxy->config;
		copy->proxies = g_strdupv(proxy->proxies);
		copy->excludes = g_strdupv(proxy->excludes);
		copy->pac = g_strdup(proxy->pac);
	}

	return copy;
}

static bool compare_active(
		struct connman_global_proxy * first,
		struct connman_global_proxy * second)
{
	bool result;

	if (first && second) {
		result = (first->active == second->active);
	} else {
		result = ((first == NULL) == (second == NULL));
	}

	return result;
}

static bool compare_configuration(
		struct connman_global_proxy * first,
		struct connman_global_proxy * second)
{
	bool result;
	int pos;

	result = true;

	if (result) {
		result = (first->proxies == NULL) == (second->proxies == NULL);
	}

	if (result) {
		if (first->proxies && second->proxies) {
			// Proxy ordering is relevant
			pos = 0;
			while (result && (first->proxies[pos] || second->proxies[pos])) {
				// Note that g_strcmp0 handles NULL strings gracefully
				result = (g_strcmp0(first->proxies[pos],
					second->proxies[pos]) == 0);
				pos++;
			}
		}
	}

	if (result) {
		result = (first->excludes == NULL) == (second->excludes == NULL);
	}

	if (result) {
		if (first->excludes && second->excludes) {
			// Exception ordering is irrelevant
			pos = 0;
			while (result && first->excludes[pos]) {
				result = g_strv_contains(
					(gchar const * const *)second->excludes,
					first->excludes[pos]);
				pos++;
			}
		}
	}

	if (result) {
		// Note that g_strcmp0 handles NULL strings gracefully
		result = (g_strcmp0(first->pac, second->pac) == 0);
	}

	return result;
}

/**
 * global_proxy_get_proxy_method:
 *
 * Returns the current method in use by the global proxy (i.e. direct,
 * manual or auto).
 *
 * This value is independent of the active state of the proxy, so it can be
 * considered as the value that would apply if the proxy were active.
 *
 * Returns: The global proxy's current method
 */
enum connman_service_proxy_method global_proxy_get_proxy_method()
{
	return proxy->config;
}

/**
 * global_proxy_get_proxy_servers:
 *
 * Returns a null-terminated list of pointers to servers that the proxy
 * will query. The list is ordered: if one proxy fails, the next will be
 * tried.
 *
 * The value is only relevant for the manual proxy method.
 *
 * This value is independent of the active state of the proxy, so it can be
 * considered as the value that would apply if the proxy were active.
 *
 * Returns: A list of servers to use as proxies.
 */
char **global_proxy_get_proxy_servers()
{
	return g_strdupv(proxy->proxies);
}

/**
 * global_proxy_get_proxy_excludes:
 *
 * Returns a null-terminated list of pointers to domains that are excluded
 * from using the servers in the proxy list. The list is unordered.
 *
 * The value is only relevant for the manual proxy method.
 *
 * This value is independent of the active state of the proxy, so it can be
 * considered as the value that would apply if the proxy were active.
 *
 * Returns: A list of domains for which the manual proxy shouldn't be used.
 */
char **global_proxy_get_proxy_excludes()
{
	return g_strdupv(proxy->excludes);
}

/**
 * global_proxy_get_proxy_url:
 *
 * Returns the url of the pac file that will be queried to determine
 * the proxy that should be used. This is a single URL.
 *
 * The value is only relevant for the auto proxy method.
 *
 * This value is independent of the active state of the proxy, so it can be
 * considered as the value that would apply if the proxy were active.
 *
 * Returns: The URL of the pac file to use to determine the proxy to use.
 */
const char *global_proxy_get_proxy_url()
{
	return proxy->pac;
}

/**
 * global_proxy_get_proxy_autoconfig:
 *
 * This function always returns NULL. It's the global proxy equivalent of the
 * connman_service_get_proxy_autoconfig() function that applies to servers.
 * However, the global proxy doesn't have an autoconfig value.
 *
 * Returns: NULL, always.
 */
const char *global_proxy_get_proxy_autoconfig()
{
	// Always returns NULL
	return NULL;
}

/**
 * service_or_global_proxy_get_proxy_method:
 * @service: The service to get the value from if the global proxy is inactive
 *
 * Returns the current method in use by the global proxy (i.e. direct,
 * manual or auto).
 *
 * If the global proxy is active it will return the global proxy value,
 * otherwise it will return the value for the service provided.
 *
 * Returns: The currently active proxy's method
 */
enum connman_service_proxy_method service_or_global_proxy_get_proxy_method(
		struct connman_service *service)
{
	return (proxy->active
		? global_proxy_get_proxy_method()
		: connman_service_get_proxy_method(service));
}

/**
 * service_or_global_proxy_get_proxy_servers:
 * @service: The service to get the value from if the global proxy is inactive
 *
 * Returns a null-terminated list of pointers to servers that the proxy
 * will query. The list is ordered: if one proxy fails, the next will be
 * tried.
 *
 * The value is only relevant for the manual proxy method.
 *
 * If the global proxy is active it will return the global proxy value,
 * otherwise it will return the value for the service provided.
 *
 * Returns: The currently active proxy's server list.
 */
char **service_or_global_proxy_get_proxy_servers(
		struct connman_service *service)
{
	return (proxy->active
		? global_proxy_get_proxy_servers()
		: connman_service_get_proxy_servers(service));
}

/**
 * service_or_global_proxy_get_proxy_excludes:
 * @service: The service to get the value from if the global proxy is inactive
 *
 * Returns a null-terminated list of pointers to domains that are excluded
 * from using the servers in the proxy list. The list is unordered.
 *
 * The value is only relevant for the manual proxy method.
 *
 * If the global proxy is active it will return the global proxy value,
 * otherwise it will return the value for the service provided.
 *
 * Returns: The currently active proxy's excludes list.
 */
char **service_or_global_proxy_get_proxy_excludes(
		struct connman_service *service)
{
	return (proxy->active
		? global_proxy_get_proxy_excludes()
		: connman_service_get_proxy_excludes(service));
}

/**
 * service_or_global_proxy_get_proxy_url:
 * @service: The service to get the value from if the global proxy is inactive
 *
 * Returns the url of the pac file that will be queried to determine
 * the proxy that should be used. This is a single URL.
 *
 * The value is only relevant for the auto proxy method.
 *
 * If the global proxy is active it will return the global proxy value,
 * otherwise it will return the value for the service provided.
 *
 * Returns: The URL of the pac file to use to determine the proxy to use
 */
const char *service_or_global_proxy_get_proxy_url(
		struct connman_service *service)
{
	return (proxy->active
		? global_proxy_get_proxy_url()
		: connman_service_get_proxy_url(service));
}

/**
 * service_or_global_proxy_get_proxy_autoconfig:
 * @service: The service to get the value from if the global proxy is inactive
 *
 * Returns the autoconfig for the proxy.
 *
 * If the global proxy is active it will return the global proxy value,
 * otherwise it will return the value for the service provided.
 *
 * Returns: The autoconfig value for the currently active proxy.
 */
const char *service_or_global_proxy_get_proxy_autoconfig(
		struct connman_service *service)
{
	return (proxy->active
		? global_proxy_get_proxy_autoconfig()
		: connman_service_get_proxy_autoconfig(service));
}

/**
 * service_or_global_proxy_get_interface:
 * @service: The service to get the value from if the global proxy is inactive
 *
 * Returns the network interface for the current service, or NULL if the
 * global proxy is active.
 *
 * Returns: The network interface for the specific service, or NULL if the
 *	global proxy is active.
 */
char *service_or_global_proxy_get_interface(struct connman_service *service)
{
	return (proxy->active
		? NULL
		: connman_service_get_interface(service));
}

/**
 * service_or_global_proxy_get_domainname:
 * @service: The service to get the value from if the global proxy is inactive
 *
 * Returns the domain name for the current service, or NULL if the global
 * proxy is active.
 *
 * Returns: The domain name for the specific service, or NULL if the
 *	global proxy is active.
 */
const char *service_or_global_proxy_get_domainname(
		struct connman_service *service)
{
	return (proxy->active
		? NULL
		: connman_service_get_domainname(service));
}

/**
 * service_or_global_get_nameservers:
 * @service: The service to get the value from if the global proxy is inactive
 *
 * Returns the name servers for the current service, or NULL if the global
 * proxy is active.
 *
 * Returns: The name servers for the specific service, or NULL if the
 *	global proxy is active.
 */
char **service_or_global_get_nameservers(struct connman_service *service)
{
	return (proxy->active
		? NULL
		: connman_service_get_nameservers(service));
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

static DBusMessage *error_invalid_arguments(DBusMessage *msg)
{
	return g_dbus_create_error(msg, CONNMAN_ERROR_INTERFACE
				".InvalidArguments", "Invalid arguments");
}

static enum connman_service_proxy_method string2proxymethod(const char *method)
{
	if (g_strcmp0(method, DBUS_VALUE_TYPE_DIRECT) == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_DIRECT;
	else if (g_strcmp0(method, DBUS_VALUE_TYPE_AUTO) == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_AUTO;
	else if (g_strcmp0(method, DBUS_VALUE_TYPE_MANUAL) == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_MANUAL;
	else
		return CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;
}

static const char *proxymethod2string(enum connman_service_proxy_method method)
{
	switch (method) {
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		return DBUS_VALUE_TYPE_DIRECT;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		return DBUS_VALUE_TYPE_MANUAL;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		return DBUS_VALUE_TYPE_AUTO;
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		break;
	}

	return NULL;
}

static struct access_globalproxy_policy *
		access_globalproxy_policy_create(const char *spec)
{
	DAPolicy *impl;

	if (!spec || !spec[0]) {
		/* Empty policy = use default */
		spec = globalproxy_policy_default;
	}

	/* Parse the policy string */
	impl = da_policy_new_full(spec, globalproxy_policy_actions);
	if (impl) {
		/* String is usable */
		struct access_globalproxy_policy *p =
			g_slice_new0(struct access_globalproxy_policy);

		p->impl = impl;
		return p;
	} else {
		DBG("invalid spec \"%s\"", spec);
		return NULL;
	}
}

static void access_globalproxy_policy_free
			(struct access_globalproxy_policy *p)
{
	da_policy_unref(p->impl);
	g_slice_free(struct access_globalproxy_policy, p);
}

static enum connman_access access_globalproxy_set_property
		(const struct access_globalproxy_policy *policy,
			const char *name, const char *sender,
			enum connman_access default_access)
{
	/* Don't unref this one: */
	DAPeer* peer = da_peer_get(CONNMAN_BUS, sender);

	/* Reject the access if the peer is gone */
	return peer ? (enum connman_access)da_policy_check(policy->impl,
		&peer->cred, GLOBALPROXY_ACCESS_SET_PROPERTY, name, (DA_ACCESS)
		default_access) : CONNMAN_ACCESS_DENY;
}

static gboolean check_set_property(const char *name, DBusMessage *msg,
		enum connman_access default_access)
{
    return access_globalproxy_set_property(policy,
	    name,
	    dbus_message_get_sender(msg),
	    default_access) == CONNMAN_ACCESS_ALLOW;
}

static gboolean can_set_property(const char *name, DBusMessage *msg,
		enum connman_access default_access)
{
	if (check_set_property(name, msg, default_access)) {
		return TRUE;
	} else {
		connman_warn("%s is not allowed to set %s for the global proxy",
		    dbus_message_get_sender(msg), name);
		return FALSE;
	}
}

static DBusMessage *set_property(DBusConnection *conn, DBusMessage *msg,
					void *user_data)
{
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("global proxy");

	if (!dbus_message_iter_init(msg, &iter))
		return error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, DBUS_KEY_ACTIVE)) {
		dbus_bool_t active;

		if (!can_set_property(name, msg, SET_PROXYACTIVE_ACCESS))
			return __connman_error_permission_denied(msg);

		if (type != DBUS_TYPE_BOOLEAN)
			return error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &active);

		global_proxy_set_active(active);
		DBG("Global proxy is %s", (active ? "active" : "inactive"));
	} else if (g_str_equal(name, DBUS_KEY_CONFIGURATION)) {
		int err;

		if (!can_set_property(name, msg, SET_PROXYCONFIG_ACCESS))
			return __connman_error_permission_denied(msg);

		if (type != DBUS_TYPE_ARRAY)
			return error_invalid_arguments(msg);

		err = set_configuration(&value);

		if (err < 0) {
			//return __connman_error_failed(msg, -err);
			// Invalid arguments (EINVAL) is currently the only
			// error case supported
			return error_invalid_arguments(msg);
		}

		write_configuration();
		configuration_changed();
	} else {
		DBG("%s requested %s - why?", dbus_message_get_sender(msg),
			name);
		return error_invalid_arguments(msg);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static int set_configuration(DBusMessageIter *array)
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

		if (g_str_equal(key, DBUS_KEY_METHOD)) {
			const char *val;

			if (type != DBUS_TYPE_STRING)
				goto error;

			dbus_message_iter_get_basic(&variant, &val);
			method = string2proxymethod(val);
		} else if (g_str_equal(key, DBUS_KEY_URL)) {
			if (type != DBUS_TYPE_STRING)
				goto error;

			dbus_message_iter_get_basic(&variant, &url);
		} else if (g_str_equal(key, DBUS_KEY_SERVERS)) {
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
		} else if (g_str_equal(key, DBUS_KEY_EXCLUDES)) {
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
		if (!servers_str && !proxy->proxies)
			goto error;

		if (servers_str) {
			g_strfreev(proxy->proxies);

			if (servers_str->len > 0) {
				char **proxies = g_strsplit_set(
					servers_str->str, " ", 0);
				proxies = remove_empty_strings(proxies);
				proxy->proxies = proxies;
			} else
				proxy->proxies = NULL;
		}

		if (excludes_str) {
			g_strfreev(proxy->excludes);

			if (excludes_str->len > 0) {
				char **excludes = g_strsplit_set(
					excludes_str->str, " ", 0);
				excludes = remove_empty_strings(excludes);
				proxy->excludes = excludes;
			} else
				proxy->excludes = NULL;
		}

		if (!proxy->proxies)
			method = CONNMAN_SERVICE_PROXY_METHOD_DIRECT;

		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		g_free(proxy->pac);

		if (url && strlen(url) > 0)
			proxy->pac = g_strstrip(g_strdup(url));
		else
			proxy->pac = NULL;

		/* if we are connected:
		   - if proxy->pac == NULL
		   - if __connman_ipconfig_get_proxy_autoconfig(
		   proxy->ipconfig) == NULL
		   --> We should start WPAD */

		break;
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		goto error;
	}

	if (servers_str)
		g_string_free(servers_str, TRUE);

	if (excludes_str)
		g_string_free(excludes_str, TRUE);

	proxy->config = method;

	return 0;

error:
	if (servers_str)
		g_string_free(servers_str, TRUE);

	if (excludes_str)
		g_string_free(excludes_str, TRUE);

	return -EINVAL;
}

static DBusMessage *get_property(DBusConnection *conn, DBusMessage *msg,
					void *user_data)
{
	const char *name;
	DBusMessageIter iter;

	DBG("global proxy: GetProperty called");

	if (!dbus_message_iter_init(msg, &iter))
		return error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);

	if (!g_strcmp0(name, DBUS_KEY_ACTIVE)) {
		return reply_proxy_active(msg, &proxy->active);
	} else if (!g_strcmp0(name, DBUS_KEY_CONFIGURATION)) {
		return reply_proxy_properties(msg);
	}

	DBG("%s requested %s - why?", dbus_message_get_sender(msg), name);
	return error_invalid_arguments(msg);
}

static DBusMessage *reply_proxy_active(DBusMessage *msg, dbus_bool_t *active)
{
	DBusMessage *reply;
	DBusMessageIter iter, variant;

	DBG("global proxy: boolean");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_BOOLEAN_AS_STRING, &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, active);
	dbus_message_iter_close_container(&iter, &variant);

	return reply;
}


static DBusMessage *reply_proxy_properties(DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter, variant, dict;

	DBG("global proxy: proxy config");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	connman_dbus_dict_open_variant(&iter, &variant);

	connman_dbus_dict_open(&variant, &dict);
	append_proxyconfig(&dict, NULL);
	connman_dbus_dict_close(&variant, &dict);

	connman_dbus_dict_close(&iter, &variant);

	return reply;
}

static void append_proxyconfig(DBusMessageIter *iter, void *user_data)
{
	const char *method;

	if (proxy->config == CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN)
		return;

	switch (proxy->config) {
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		return;
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		if (proxy->proxies)
			connman_dbus_dict_append_array(iter, DBUS_KEY_SERVERS,
					DBUS_TYPE_STRING,
					append_proxies, NULL);

		if (proxy->excludes)
			connman_dbus_dict_append_array(iter, DBUS_KEY_EXCLUDES,
					DBUS_TYPE_STRING,
					append_excludes, NULL);
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		if (proxy->pac)
			connman_dbus_dict_append_basic(iter, DBUS_KEY_URL,
					DBUS_TYPE_STRING, &proxy->pac);
		break;
	}

	method = proxymethod2string(proxy->config);

	connman_dbus_dict_append_basic(iter, DBUS_KEY_METHOD,
					DBUS_TYPE_STRING, &method);
}

static void append_proxies(DBusMessageIter *iter, void *user_data)
{
	int i;

	if (!proxy->proxies)
		return;

	for (i = 0; proxy->proxies[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &proxy->proxies[i]);
}

static void append_excludes(DBusMessageIter *iter, void *user_data)
{
	int i;

	if (!proxy->excludes)
		return;

	for (i = 0; proxy->excludes[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &proxy->excludes[i]);
}

static dbus_bool_t dbus_property_changed_dict_variant(
		const char *path,
		const char *interface, const char *key,
		connman_dbus_append_cb_t function, void *user_data)
{
	DBusMessage *signal;
	DBusMessageIter iter, variant, dict;

	if (!path)
		return FALSE;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");
	if (!signal)
		return FALSE;

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key);

	connman_dbus_dict_open_variant(&iter, &variant);

	connman_dbus_dict_open(&variant, &dict);
	function(&dict, user_data);
	connman_dbus_dict_close(&variant, &dict);

	connman_dbus_dict_close(&iter, &variant);

	g_dbus_send_message(connection, signal);

	return TRUE;
}


static void configuration_changed()
{
	dbus_property_changed_dict_variant(GLOBALPROXY_DBUS_PATH,
		GLOBALPROXY_CONNMAN_INTERFACE, DBUS_KEY_CONFIGURATION,
						append_proxyconfig, NULL);

	notifier_config_changed();
	if (proxy->active) {
		notifier_proxy_changed();
	}
}

/**
 * global_proxy_get_active:
 *
 * Returns the active state of the global proxy.
 *
 * Returns: TRUE if the global proxy is active, FALSE o/w
 */
gboolean global_proxy_get_active()
{
	return proxy->active;
}

static bool global_proxy_set_active(bool active)
{
	if (proxy->active == active)
		return false;

	proxy->active = active;
	write_configuration();
	active_changed();

	return true;
}

static void active_changed()
{
	connman_dbus_property_changed_basic(GLOBALPROXY_DBUS_PATH,
		GLOBALPROXY_CONNMAN_INTERFACE, DBUS_KEY_ACTIVE,
		DBUS_TYPE_BOOLEAN, &proxy->active);

	notifier_active_changed(proxy->active);
	notifier_proxy_changed();
}

/**
 * global_proxy_notifier_register:
 * @notifier: A structure containing details of the notification functions
 *
 * Register a new notifier module. The functions provided in the structure
 * will be called when the global proxy changes its configuration, or changes
 * its active state.
 *
 * Returns: %0 on success
 */
int global_proxy_notifier_register(struct global_proxy_notifier *notifier)
{
	DBG("notifier %p name %s", notifier, notifier->name);

	notifier_list = g_slist_insert_sorted(notifier_list, notifier,
							compare_priority);

	return 0;
}

/**
 * global_proxy_notifier_unregister:
 * @notifier: A structure containing details of the notification functions,
 *	as passed to the global_proxy_notifier_register() function.
 *
 * Remove a previously registered notifier module.
 */
void global_proxy_notifier_unregister(struct global_proxy_notifier *notifier)
{
	DBG("notifier %p name %s", notifier, notifier->name);

	notifier_list = g_slist_remove(notifier_list, notifier);
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct global_proxy_notifier *notifier1 = a;
	const struct global_proxy_notifier *notifier2 = b;

	return notifier2->priority - notifier1->priority;
}

static void notifier_active_changed(bool active)
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		struct global_proxy_notifier *notifier = list->data;

		if (notifier->active_changed)
			notifier->active_changed(active);
	}
}

static void notifier_config_changed()
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		struct global_proxy_notifier *notifier = list->data;

		if (notifier->config_changed)
			notifier->config_changed();
	}
}

static void notifier_proxy_changed()
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		struct global_proxy_notifier *notifier = list->data;

		if (notifier->proxy_changed)
			notifier->proxy_changed();
	}
}

CONNMAN_PLUGIN_DEFINE(globalproxy, "Global proxy configuration", VERSION,
		CONNMAN_PLUGIN_PRIORITY_HIGH - 1,
		global_proxy_init, global_proxy_exit)


/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
