/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2016  BMW Car IT GmbH.
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
#include <string.h>
#include <stdbool.h>
#include <linux/if_ether.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/network.h>
#include <connman/technology.h>
#include <connman/inet.h>
#include <gdbus.h>

static DBusConnection *connection;
static GDBusClient *client;
static GDBusProxy *agent_proxy;
static GHashTable *adapters;
static GHashTable *devices;
static GHashTable *networks;
static GHashTable *known_networks;
static GHashTable *stations;
static GHashTable *access_points;
static bool agent_registered;

#define IWD_SERVICE			"net.connman.iwd"
#define IWD_PATH			"/"
#define IWD_AGENT_MANAGER_INTERFACE	"net.connman.iwd.AgentManager"
#define IWD_ADAPTER_INTERFACE		"net.connman.iwd.Adapter"
#define IWD_DEVICE_INTERFACE		"net.connman.iwd.Device"
#define IWD_NETWORK_INTERFACE		"net.connman.iwd.Network"
#define IWD_KNOWN_NETWORK_INTERFACE	"net.connman.iwd.KnownNetwork"
#define IWD_STATION_INTERFACE		"net.connman.iwd.Station"
#define IWD_AP_INTERFACE		"net.connman.iwd.AccessPoint"

#define IWD_AGENT_INTERFACE		"net.connman.iwd.Agent"
#define IWD_AGENT_ERROR_INTERFACE	"net.connman.iwd.Agent.Error"
#define AGENT_PATH			"/net/connman/iwd_agent"

struct iwd_adapter {
	GDBusProxy *proxy;
	char *path;
	char *vendor;
	char *model;
	bool powered;
	bool ad_hoc;
	bool station;
	bool ap;
};

struct iwd_device {
	GDBusProxy *proxy;
	char *path;
	char *adapter;
	char *name;
	char *address;
	bool powered;
	char *mode;

	struct connman_device *device;
};

struct iwd_network {
	GDBusProxy *proxy;
	char *path;
	char *device;
	char *name;
	char *type;
	bool connected;
	char *known_network;

	struct iwd_device *iwdd;
	struct connman_network *network;
};

struct iwd_known_network {
	GDBusProxy *proxy;
	char *path;
	char *name;
	char *type;
	bool hidden;
	char *last_connected_time;
	bool auto_connect;
};

struct iwd_station {
	GDBusProxy *proxy;
	char *path;
	char *state;
	char *connected_network;
	bool scanning;
};

struct iwd_ap {
	GDBusProxy *proxy;
	char *path;
	bool started;
};

static const char *proxy_get_string(GDBusProxy *proxy, const char *property)
{
	DBusMessageIter iter;
	const char *str;

	if (!g_dbus_proxy_get_property(proxy, property, &iter))
		return NULL;

	dbus_message_iter_get_basic(&iter, &str);

	return str;
}

static GSList *proxy_get_strings(GDBusProxy *proxy, const char *property)
{
	DBusMessageIter array, entry;
	GSList *list = NULL;

	if (!g_dbus_proxy_get_property(proxy, property, &array))
		return NULL;

	dbus_message_iter_recurse(&array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING){
		const char *val;

		dbus_message_iter_get_basic(&entry, &val);
		list = g_slist_prepend(list, g_strdup(val));
		dbus_message_iter_next(&entry);
	}

	return list;
}

static bool proxy_get_bool(GDBusProxy *proxy, const char *property)
{
	DBusMessageIter iter;
	dbus_bool_t value;

	if (!g_dbus_proxy_get_property(proxy, property, &iter))
		return false;

	dbus_message_iter_get_basic(&iter, &value);

	return value;
}

static void address2ident(const char *address, char *ident)
{
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		ident[i * 2] = address[i * 3];
		ident[i * 2 + 1] = address[i * 3 + 1];
	}
	ident[ETH_ALEN * 2] = '\0';
}

static int cm_network_probe(struct connman_network *network)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, networks);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct iwd_network *iwdn = value;

		if (network == iwdn->network)
			return 0;
	}

	return -EOPNOTSUPP;
}

static void update_network_connected(struct iwd_network *iwdn)
{
	struct iwd_device *iwdd;
	int index;

	iwdd = g_hash_table_lookup(devices, iwdn->device);
	if (!iwdd)
		return;

	index = connman_inet_ifindex(iwdd->name);
	if (index < 0)
		return;

	DBG("interface name %s index %d", iwdd->name, index);
	connman_network_set_index(iwdn->network, index);
	connman_network_set_connected(iwdn->network, true);
}

static void update_network_disconnected(struct iwd_network *iwdn)
{
	DBG("interface name %s", iwdn->name);
	connman_network_set_connected(iwdn->network, false);
}

static void cm_network_connect_cb(DBusMessage *message, void *user_data)
{
	const char *path = user_data;
	struct iwd_network *iwdn;

	iwdn = g_hash_table_lookup(networks, path);
	if (!iwdn)
		return;

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *dbus_error = dbus_message_get_error_name(message);

		if (!strcmp(dbus_error, "net.connman.iwd.InProgress"))
			return;

		DBG("%s connect failed: %s", path, dbus_error);
		connman_network_set_error(iwdn->network,
					CONNMAN_NETWORK_ERROR_CONNECT_FAIL);
		return;
	}

	update_network_connected(iwdn);
}

static int cm_network_connect(struct connman_network *network)
{
	struct iwd_network *iwdn = connman_network_get_data(network);

	if (!iwdn)
		return -EINVAL;

	if (!g_dbus_proxy_method_call(iwdn->proxy, "Connect",
			NULL, cm_network_connect_cb,
			g_strdup(iwdn->path), g_free))
		return -EIO;

	connman_network_set_associating(iwdn->network, true);

	return -EINPROGRESS;
}

static void cm_network_disconnect_cb(DBusMessage *message, void *user_data)
{
	const char *path = user_data;
	struct iwd_network *iwdn;

	iwdn = g_hash_table_lookup(networks, path);
	if (!iwdn)
		return;

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *dbus_error = dbus_message_get_error_name(message);

		if (!strcmp(dbus_error, "net.connman.iwd.NotConnected")) {
			/* fall through */
		} else {
			DBG("%s disconnect failed: %s", path, dbus_error);
			return;
		}
	}

	/*
	 * We end up in a tight loop in the error case. That is
	 * when we can't connect, bail out in cm_network_connect_cb() with
	 * an error.
	 */
	if (connman_network_get_connected(iwdn->network))
		update_network_disconnected(iwdn);
}

static int cm_network_disconnect(struct connman_network *network)
{
	struct iwd_network *iwdn = connman_network_get_data(network);
	struct iwd_device *iwdd;

	if (!iwdn)
		return -EINVAL;

	iwdd = g_hash_table_lookup(devices, iwdn->device);
	if (!iwdd)
		return -EIO;

	if (!g_dbus_proxy_method_call(iwdd->proxy, "Disconnect",
			NULL, cm_network_disconnect_cb, g_strdup(iwdn->path), g_free))
		return -EIO;

	return -EINPROGRESS;
}

static struct connman_network_driver network_driver = {
	.name		= "iwd",
	.type           = CONNMAN_NETWORK_TYPE_WIFI,
	.probe          = cm_network_probe,
	.connect        = cm_network_connect,
	.disconnect     = cm_network_disconnect,
};

static int cm_device_probe(struct connman_device *device)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, devices);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct iwd_device *iwdd = value;

		if (device == iwdd->device)
			return 0;
	}

	return -EOPNOTSUPP;
}

static void cm_device_remove(struct connman_device *device)
{
}

struct dev_cb_data {
	char *path;
	bool powered;
};

static void device_powered_cb(const DBusError *error, void *user_data)
{
	struct dev_cb_data *cbd = user_data;
	struct iwd_device *iwdd;

	iwdd = g_hash_table_lookup(devices, cbd->path);
	if (!iwdd)
		goto out;

	if (dbus_error_is_set(error)) {
		connman_warn("WiFi device %s not enabled %s",
				cbd->path, error->message);
		goto out;
	}

	connman_device_set_powered(iwdd->device, cbd->powered);
out:
	g_free(cbd->path);
	g_free(cbd);
}

static int set_device_powered(struct connman_device *device, bool powered)
{
	struct iwd_device *iwdd = connman_device_get_data(device);
	dbus_bool_t device_powered = powered;
	struct dev_cb_data *cbd;

	if (proxy_get_bool(iwdd->proxy, "Powered"))
		return -EALREADY;

	cbd = g_new(struct dev_cb_data, 1);
	cbd->path = g_strdup(iwdd->path);
	cbd->powered = powered;

	g_dbus_proxy_set_property_basic(iwdd->proxy, "Powered",
			DBUS_TYPE_BOOLEAN, &device_powered,
			device_powered_cb, cbd, NULL);

	return -EINPROGRESS;
}

static int cm_device_enable(struct connman_device *device)
{
	return set_device_powered(device, true);
}

static int cm_device_disable(struct connman_device *device)
{
	return set_device_powered(device, false);
}

static struct connman_device_driver device_driver = {
	.name		= "iwd",
	.type		= CONNMAN_DEVICE_TYPE_WIFI,
	.probe          = cm_device_probe,
	.remove         = cm_device_remove,
	.enable         = cm_device_enable,
	.disable        = cm_device_disable,
};

static int cm_tech_probe(struct connman_technology *technology)
{
	return 0;
}

static void cm_tech_remove(struct connman_technology *technology)
{
}

static struct connman_technology_driver tech_driver = {
	.name		= "iwd",
	.type		= CONNMAN_SERVICE_TYPE_WIFI,
	.probe          = cm_tech_probe,
	.remove         = cm_tech_remove,
};

static const char *security_remap(const char *security)
{
	if (!g_strcmp0(security, "open"))
		return "none";
	else if (!g_strcmp0(security, "psk"))
		return "psk";
	else if (!g_strcmp0(security, "8021x"))
		return "ieee8021x";

	return "unknown";
}

static char *create_identifier(const char *path, const char *security)
{
	char *start, *end, *identifier;
	char *_path = g_strdup(path);

	/*
	 * _path is something like
	 *     /0/4/5363686970686f6c5f427573696e6573735f454150_8021x
	 */
	start = strrchr(_path, '/');
	start++;
	end = strchr(start, '_');
	*end = '\0';

	/*
	 * Create an ident which is identical to the corresponding
	 * wpa_supplicant identifier.
	 */
	identifier = g_strdup_printf("%s_managed_%s", start,
				security_remap(security));
	g_free(_path);

	return identifier;
}

static void add_network(const char *path, struct iwd_network *iwdn)
{
	struct iwd_device *iwdd;
	char *identifier;

	iwdd = g_hash_table_lookup(devices, iwdn->device);
	if (!iwdd)
		return;

	identifier = create_identifier(path, iwdn->type);
	iwdn->network = connman_network_create(identifier,
					CONNMAN_NETWORK_TYPE_WIFI);
	connman_network_set_data(iwdn->network, iwdn);

	connman_network_set_name(iwdn->network, iwdn->name);
	connman_network_set_blob(iwdn->network, "WiFi.SSID", iwdn->name,
					strlen(iwdn->name));
	connman_network_set_string(iwdn->network, "WiFi.Security",
					iwdn->type);
	connman_network_set_string(iwdn->network, "WiFi.Mode", "managed");

	if (connman_device_add_network(iwdd->device, iwdn->network) < 0) {
		connman_network_unref(iwdn->network);
		iwdn->network = NULL;
		return;
	}
	iwdn->iwdd = iwdd;

	connman_network_set_available(iwdn->network, true);
	connman_network_set_group(iwdn->network, identifier);

	g_free(identifier);
}

static void remove_network(struct iwd_network *iwdn)
{
	if (!iwdn->network)
		return;

	if (iwdn->iwdd)
		connman_device_remove_network(iwdn->iwdd->device,
						iwdn->network);

	connman_network_unref(iwdn->network);
	iwdn->network = NULL;
}

static void add_device(const char *path, struct iwd_device *iwdd)
{
	char ident[ETH_ALEN * 2 + 1];

	iwdd->device = connman_device_create("wifi", CONNMAN_DEVICE_TYPE_WIFI);
	if (!iwdd->device)
		return;

	connman_device_set_data(iwdd->device, iwdd);

	address2ident(iwdd->address, ident);
	connman_device_set_ident(iwdd->device, ident);

	if (connman_device_register(iwdd->device) < 0) {
		g_hash_table_remove(devices, path);
		return;
	}

	connman_device_set_powered(iwdd->device, iwdd->powered);
}

static void remove_device_networks(struct iwd_device *iwdd)
{
	GHashTableIter iter;
	gpointer key, value;
	struct iwd_network *iwdn;
	GSList *list, *nets = NULL;

	g_hash_table_iter_init(&iter, networks);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		iwdn = value;

		if (!strcmp(iwdd->path, iwdn->device))
			nets = g_slist_prepend(nets, iwdn);
	}

	for (list = nets; list; list = list->next) {
		iwdn = list->data;
		g_hash_table_remove(networks, iwdn->path);
	}

	g_slist_free(nets);
}

static void remove_device(struct iwd_device *iwdd)
{
	if (!iwdd->device)
		return;

	remove_device_networks(iwdd);
	connman_device_unregister(iwdd->device);
	connman_device_unref(iwdd->device);
	iwdd->device = NULL;
}

static void adapter_property_change(GDBusProxy *proxy, const char *name,
		DBusMessageIter *iter, void *user_data)
{
	struct iwd_adapter *adapter;
	const char *path;

	path = g_dbus_proxy_get_path(proxy);
	adapter = g_hash_table_lookup(adapters, path);
	if (!adapter)
		return;

	if (!strcmp(name, "Powered")) {
		dbus_bool_t powered;

		dbus_message_iter_get_basic(iter, &powered);
		adapter->powered = powered;

		DBG("%p powered %d", path, adapter->powered);
	}
}

static void device_property_change(GDBusProxy *proxy, const char *name,
		DBusMessageIter *iter, void *user_data)
{
	struct iwd_device *iwdd;
	const char *path;

	path = g_dbus_proxy_get_path(proxy);
	iwdd = g_hash_table_lookup(devices, path);
	if (!iwdd)
		return;

	if (!strcmp(name, "Name")) {
		const char *name;

		dbus_message_iter_get_basic(iter, &name);
		g_free(iwdd->name);
		iwdd->name = g_strdup(name);

		DBG("%p name %s", path, iwdd->name);
	} else if (!strcmp(name, "Powered")) {
		dbus_bool_t powered;

		dbus_message_iter_get_basic(iter, &powered);
		iwdd->powered = powered;

		DBG("%s powered %d", path, iwdd->powered);
	} else if (!strcmp(name, "Mode")) {
		const char *mode;

		dbus_message_iter_get_basic(iter, &mode);
		g_free(iwdd->mode);
		iwdd->mode = g_strdup(mode);

		DBG("%s mode %s", path, iwdd->mode);
	}
}

static void network_property_change(GDBusProxy *proxy, const char *name,
		DBusMessageIter *iter, void *user_data)
{
	struct iwd_network *iwdn;
	const char *path;

	path = g_dbus_proxy_get_path(proxy);
	iwdn = g_hash_table_lookup(networks, path);
	if (!iwdn)
		return;

	if (!strcmp(name, "Connected")) {
		dbus_bool_t connected;

		dbus_message_iter_get_basic(iter, &connected);
		iwdn->connected = connected;

		DBG("%s connected %d", path, iwdn->connected);

		if (iwdn->connected)
			update_network_connected(iwdn);
		else
			update_network_disconnected(iwdn);
	}
}

static void station_property_change(GDBusProxy *proxy, const char *name,
		DBusMessageIter *iter, void *user_data)
{
	struct iwd_station *iwds;
	const char *path;

	path = g_dbus_proxy_get_path(proxy);
	iwds = g_hash_table_lookup(stations, path);
	if (!iwds)
		return;

	if (!strcmp(name, "State")) {
		const char *state;

		dbus_message_iter_get_basic(iter, &state);
		g_free(iwds->state);
		iwds->state = g_strdup(state);

		DBG("%s state %s", path, iwds->state);
	} else if (!strcmp(name, "ConnectedNetwork")) {
		const char *connected_network;

		g_free(iwds->connected_network);
		if (!g_strcmp0(iwds->state, "disconnecting")) {
			iwds->connected_network = NULL;
		} else {
			dbus_message_iter_get_basic(iter, &connected_network);
			iwds->connected_network = g_strdup(connected_network);
		}

		DBG("%s connected_network %s", path, iwds->connected_network);
	} else if (!strcmp(name, "Scanning")) {
		dbus_bool_t scanning;

		dbus_message_iter_get_basic(iter, &scanning);
		iwds->scanning = scanning;

		DBG("%s scanning %d", path, iwds->scanning);
	}
}

static void ap_property_change(GDBusProxy *proxy, const char *name,
		DBusMessageIter *iter, void *user_data)
{
	struct iwd_ap *iwdap;
	const char *path;

	path = g_dbus_proxy_get_path(proxy);
	iwdap = g_hash_table_lookup(access_points, path);
	if (!iwdap)
		return;

        if (!strcmp(name, "Started")) {
		dbus_bool_t started;

		dbus_message_iter_get_basic(iter, &started);
		iwdap->started = started;

		DBG("%s started %d", path, iwdap->started);
	}
}

static void adapter_free(gpointer data)
{
	struct iwd_adapter *iwda = data;

	if (iwda->proxy) {
		g_dbus_proxy_unref(iwda->proxy);
		iwda->proxy = NULL;
	}

	g_free(iwda->path);
	g_free(iwda->vendor);
	g_free(iwda->model);
	g_free(iwda);
}

static void device_free(gpointer data)
{
	struct iwd_device *iwdd = data;

	if (iwdd->proxy) {
		g_dbus_proxy_unref(iwdd->proxy);
		iwdd->proxy = NULL;
	}

	remove_device(iwdd);

	g_free(iwdd->path);
	g_free(iwdd->adapter);
	g_free(iwdd->name);
	g_free(iwdd->address);
	g_free(iwdd);
}

static void network_free(gpointer data)
{
	struct iwd_network *iwdn = data;

	if (iwdn->proxy) {
		g_dbus_proxy_unref(iwdn->proxy);
		iwdn->proxy = NULL;
	}

	remove_network(iwdn);

	g_free(iwdn->path);
	g_free(iwdn->device);
	g_free(iwdn->name);
	g_free(iwdn->type);
	g_free(iwdn->known_network);
	g_free(iwdn);
}

static void known_network_free(gpointer data)
{
	struct iwd_known_network *iwdkn = data;

	if (iwdkn->proxy) {
		g_dbus_proxy_unref(iwdkn->proxy);
		iwdkn->proxy = NULL;
	}

	g_free(iwdkn->path);
	g_free(iwdkn->name);
	g_free(iwdkn->type);
	g_free(iwdkn->last_connected_time);
	g_free(iwdkn);
}

static void station_free(gpointer data)
{
	struct iwd_station *iwds = data;

	if (iwds->proxy) {
		g_dbus_proxy_unref(iwds->proxy);
		iwds->proxy = NULL;
	}
	g_free(iwds->path);
	g_free(iwds->connected_network);
	g_free(iwds);
}

static void ap_free(gpointer data)
{
	struct iwd_ap *iwdap = data;

	if (iwdap->proxy) {
		g_dbus_proxy_unref(iwdap->proxy);
		iwdap->proxy = NULL;
	}
	g_free(iwdap);
}

static void create_adapter(GDBusProxy *proxy)
{
	const char *path = g_dbus_proxy_get_path(proxy);
	struct iwd_adapter *iwda;
	GSList *modes, *list;

	iwda = g_try_new0(struct iwd_adapter, 1);

	if (!iwda) {
		connman_error("Out of memory creating IWD adapter");
		return;
	}

	iwda->path = g_strdup(path);
	g_hash_table_replace(adapters, iwda->path, iwda);

	iwda->proxy = g_dbus_proxy_ref(proxy);

	if (!iwda->proxy) {
		connman_error("Cannot create IWD adapter watcher %s", path);
		g_hash_table_remove(adapters, path);
		return;
	}

	iwda->vendor = g_strdup(proxy_get_string(proxy, "Vendor"));
	iwda->model = g_strdup(proxy_get_string(proxy, "Model"));
	iwda->powered = proxy_get_bool(proxy, "Powered");

	modes = proxy_get_strings(proxy, "SupportedModes");
	for (list = modes; list; list = list->next) {
		char *m = list->data;

		if (!m)
			continue;

		if (!strcmp(m, "ad-hoc"))
			iwda->ad_hoc = true;
		else if (!strcmp(m, "station"))
			iwda->station = true;
		else if (!strcmp(m, "ap"))
			iwda->ap = true;
	}
	g_slist_free_full(modes, g_free);

	DBG("%s vendor '%s' model '%s' powered %d ad-hoc %d station %d ap %d",
		path, iwda->vendor, iwda->model, iwda->powered,
		iwda->ad_hoc, iwda->station, iwda->ap);

	g_dbus_proxy_set_property_watch(iwda->proxy,
			adapter_property_change, NULL);
}

static void create_device(GDBusProxy *proxy)
{
	const char *path = g_dbus_proxy_get_path(proxy);
	struct iwd_device *iwdd;

	iwdd = g_try_new0(struct iwd_device, 1);

	if (!iwdd) {
		connman_error("Out of memory creating IWD device");
		return;
	}

	iwdd->path = g_strdup(path);
	g_hash_table_replace(devices, iwdd->path, iwdd);

	iwdd->proxy = g_dbus_proxy_ref(proxy);

	if (!iwdd->proxy) {
		connman_error("Cannot create IWD device watcher %s", path);
		g_hash_table_remove(devices, path);
		return;
	}

	iwdd->adapter = g_strdup(proxy_get_string(proxy, "Adapter"));
	iwdd->name = g_strdup(proxy_get_string(proxy, "Name"));
	iwdd->address = g_strdup(proxy_get_string(proxy, "Address"));
	iwdd->powered = proxy_get_bool(proxy, "Powered");
	iwdd->mode = g_strdup(proxy_get_string(proxy, "Mode"));

	DBG("adapter %s name %s address %s powered %d mode %s",
		iwdd->adapter, iwdd->name, iwdd->address,
		iwdd->powered, iwdd->mode);

	g_dbus_proxy_set_property_watch(iwdd->proxy,
			device_property_change, NULL);

	add_device(path, iwdd);
}

static void unregister_agent();

static DBusMessage *agent_release_method(DBusConnection *dbus_conn,
					DBusMessage *message, void *user_data)
{
	unregister_agent();
	return g_dbus_create_reply(message, DBUS_TYPE_INVALID);
}

static DBusMessage *get_reply_on_error(DBusMessage *message, int error)
{
	return g_dbus_create_error(message,
		IWD_AGENT_ERROR_INTERFACE ".Failed", "Invalid parameters");
}

static DBusMessage *agent_request_passphrase(DBusConnection *dbus_conn,
						DBusMessage *message,
						void *user_data)
{
	struct iwd_network *iwdn;
	DBusMessageIter iter;
	const char *path, *passwd;

	DBG("");

	dbus_message_iter_init(message, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return get_reply_on_error(message, EINVAL);

	dbus_message_iter_get_basic(&iter, &path);

	iwdn = g_hash_table_lookup(networks, path);
	if (!iwdn)
		return get_reply_on_error(message, EINVAL);

	passwd = connman_network_get_string(iwdn->network, "WiFi.Passphrase");

	return g_dbus_create_reply(message, DBUS_TYPE_STRING, &passwd,
					DBUS_TYPE_INVALID);
}

static DBusMessage *agent_cancel(DBusConnection *dbus_conn,
					DBusMessage *message, void *user_data)
{
	DBusMessageIter iter;
	const char *reason;

	dbus_message_iter_init(message, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return get_reply_on_error(message, EINVAL);

	dbus_message_iter_get_basic(&iter, &reason);

	DBG("cancel: %s", reason);

	/*
	 * We don't have to do anything here, because we asked the
	 * user upfront for the passphrase. So
	 * agent_request_passphrase() will always send a passphrase
	 * immediately.
	 */

	return g_dbus_create_reply(message, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable agent_methods[] = {
	{ GDBUS_METHOD("Release", NULL, NULL, agent_release_method) },
	{ GDBUS_METHOD("RequestPassphrase",
			GDBUS_ARGS({ "path", "o" }),
			GDBUS_ARGS({ "passphrase", "s" }),
			agent_request_passphrase)},
	{ GDBUS_METHOD("Cancel",
			GDBUS_ARGS({ "reason", "s" }),
			NULL, agent_cancel) },
	{ },
};

static void agent_register_builder(DBusMessageIter *iter, void *user_data)
{
	const char *path = AGENT_PATH;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
				&path);
}

static void register_agent(GDBusProxy *proxy)
{
	if (!g_dbus_proxy_method_call(proxy,
					"RegisterAgent",
					agent_register_builder,
					NULL, NULL, NULL))
		return;

	agent_proxy = g_dbus_proxy_ref(proxy);
}

static void unregister_agent()
{
	if (!agent_proxy)
		return;

	g_dbus_proxy_method_call(agent_proxy,
					"UnregisterAgent",
					agent_register_builder,
					NULL, NULL, NULL);

	g_dbus_proxy_unref(agent_proxy);
	agent_proxy = NULL;
}

static void iwd_is_present(DBusConnection *conn, void *user_data)
{
	if (agent_registered)
		return;

	if (!g_dbus_register_interface(connection, AGENT_PATH,
					IWD_AGENT_INTERFACE, agent_methods,
					NULL, NULL, NULL, NULL))
		return;

	agent_registered = true;
}

static void iwd_is_out(DBusConnection *conn, void *user_data)
{
	if (agent_registered) {
		g_dbus_unregister_interface(connection,
					AGENT_PATH, IWD_AGENT_INTERFACE);
		agent_registered = false;
	}
}

static void create_network(GDBusProxy *proxy)
{
	const char *path = g_dbus_proxy_get_path(proxy);
	struct iwd_network *iwdn;

	iwdn = g_try_new0(struct iwd_network, 1);

	if (!iwdn) {
		connman_error("Out of memory creating IWD network");
		return;
	}

	iwdn->path = g_strdup(path);
	g_hash_table_replace(networks, iwdn->path, iwdn);

	iwdn->proxy = g_dbus_proxy_ref(proxy);

	if (!iwdn->proxy) {
		connman_error("Cannot create IWD network watcher %s", path);
		g_hash_table_remove(networks, path);
		return;
	}

	iwdn->device = g_strdup(proxy_get_string(proxy, "Device"));
	iwdn->name = g_strdup(proxy_get_string(proxy, "Name"));
	iwdn->type = g_strdup(proxy_get_string(proxy, "Type"));
	iwdn->connected = proxy_get_bool(proxy, "Connected");
	iwdn->known_network = g_strdup(proxy_get_string(proxy, "KnownNetwork"));

	DBG("device %s name '%s' type %s connected %d known_network %s",
		iwdn->device, iwdn->name, iwdn->type, iwdn->connected,
		iwdn->known_network);

	g_dbus_proxy_set_property_watch(iwdn->proxy,
			network_property_change, NULL);

	add_network(path, iwdn);
}

static void create_know_network(GDBusProxy *proxy)
{
	const char *path = g_dbus_proxy_get_path(proxy);
	struct iwd_known_network *iwdkn;

	iwdkn = g_try_new0(struct iwd_known_network, 1);
	if (!iwdkn) {
		connman_error("Out of memory creating IWD known network");
		return;
	}

	iwdkn->path = g_strdup(path);
	g_hash_table_replace(known_networks, iwdkn->path, iwdkn);

	iwdkn->proxy = g_dbus_proxy_ref(proxy);

	if (!iwdkn->proxy) {
		connman_error("Cannot create IWD known network watcher %s", path);
		g_hash_table_remove(known_networks, path);
		return;
	}

	iwdkn->name = g_strdup(proxy_get_string(proxy, "Name"));
	iwdkn->type = g_strdup(proxy_get_string(proxy, "Type"));
	iwdkn->hidden = proxy_get_bool(proxy, "Hidden");
	iwdkn->last_connected_time =
		g_strdup(proxy_get_string(proxy, "LastConnectedTime"));
	iwdkn->auto_connect = proxy_get_bool(proxy, "AutoConnec");

	DBG("name '%s' type %s hidden %d, last_connection_time %s auto_connect %d",
		iwdkn->name, iwdkn->type, iwdkn->hidden,
		iwdkn->last_connected_time, iwdkn->auto_connect);
}

static void create_station(GDBusProxy *proxy)
{
	const char *path = g_dbus_proxy_get_path(proxy);
	struct iwd_station *iwds;

	iwds = g_try_new0(struct iwd_station, 1);
	if (!iwds) {
		connman_error("Out of memory creating IWD station");
		return;
	}

	iwds->path = g_strdup(path);
	g_hash_table_replace(stations, iwds->path, iwds);

	iwds->proxy = g_dbus_proxy_ref(proxy);

	if (!iwds->proxy) {
		connman_error("Cannot create IWD station watcher %s", path);
		g_hash_table_remove(stations, path);
		return;
	}

	iwds->state = g_strdup(proxy_get_string(proxy, "State"));
	iwds->connected_network = g_strdup(proxy_get_string(proxy, "ConnectedNetwork"));
	iwds->scanning = proxy_get_bool(proxy, "Scanning");

	DBG("state '%s' connected_network %s scanning %d",
		iwds->state, iwds->connected_network, iwds->scanning);

	g_dbus_proxy_set_property_watch(iwds->proxy,
			station_property_change, NULL);
}

static void create_ap(GDBusProxy *proxy)
{
	const char *path = g_dbus_proxy_get_path(proxy);
	struct iwd_ap *iwdap;

	iwdap = g_try_new0(struct iwd_ap, 1);
	if (!iwdap) {
		connman_error("Out of memory creating IWD access point");
		return;
	}

	iwdap->path = g_strdup(path);
	g_hash_table_replace(access_points, iwdap->path, iwdap);

	iwdap->proxy = g_dbus_proxy_ref(proxy);

	if (!iwdap->proxy) {
		connman_error("Cannot create IWD access point watcher %s", path);
		g_hash_table_remove(access_points, path);
		return;
	}

	iwdap->started = proxy_get_bool(proxy, "Started");

	DBG("started %d", iwdap->started);

	g_dbus_proxy_set_property_watch(iwdap->proxy,
			ap_property_change, NULL);
}

static void object_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);
	if (!interface) {
		connman_warn("Interface or proxy missing when adding "
							"iwd object");
		return;
	}

	DBG("%s %s", interface, g_dbus_proxy_get_path(proxy));

	if (!strcmp(interface, IWD_AGENT_MANAGER_INTERFACE))
		register_agent(proxy);
	else if (!strcmp(interface, IWD_ADAPTER_INTERFACE))
		create_adapter(proxy);
	else if (!strcmp(interface, IWD_DEVICE_INTERFACE))
		create_device(proxy);
	else if (!strcmp(interface, IWD_NETWORK_INTERFACE))
		create_network(proxy);
	else if (!strcmp(interface, IWD_KNOWN_NETWORK_INTERFACE))
		create_know_network(proxy);
	else if (!strcmp(interface, IWD_STATION_INTERFACE))
		create_station(proxy);
	else if (!strcmp(interface, IWD_AP_INTERFACE))
		create_ap(proxy);
}

static void object_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface, *path;

	interface = g_dbus_proxy_get_interface(proxy);
	if (!interface) {
		connman_warn("Interface or proxy missing when removing "
							"iwd object");
		return;
	}

	path = g_dbus_proxy_get_path(proxy);
	DBG("%s %s", interface, path);

	if (!strcmp(interface, IWD_AGENT_MANAGER_INTERFACE))
		unregister_agent();
	if (!strcmp(interface, IWD_ADAPTER_INTERFACE))
		g_hash_table_remove(adapters, path);
	else if (!strcmp(interface, IWD_DEVICE_INTERFACE))
		g_hash_table_remove(devices, path);
	else if (!strcmp(interface, IWD_NETWORK_INTERFACE))
		g_hash_table_remove(networks, path);
	else if (!strcmp(interface, IWD_KNOWN_NETWORK_INTERFACE))
		g_hash_table_remove(known_networks, path);
	else if (!strcmp(interface, IWD_STATION_INTERFACE))
		g_hash_table_remove(stations, path);
	else if (!strcmp(interface, IWD_AP_INTERFACE))
		g_hash_table_remove(access_points, path);
}

static int iwd_init(void)
{
	connection = connman_dbus_get_connection();
	if (!connection)
		goto out;

	adapters = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			adapter_free);

	devices = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			device_free);

	networks = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			network_free);

	known_networks = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			known_network_free);

	stations = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			station_free);

	access_points = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			ap_free);

	if (connman_technology_driver_register(&tech_driver) < 0) {
		connman_warn("Failed to initialize technology for IWD");
		goto out;
	}

	if (connman_device_driver_register(&device_driver) < 0) {
		connman_warn("Failed to initialize device driver for "
				IWD_SERVICE);
		connman_technology_driver_unregister(&tech_driver);
		goto out;
	}

	if (connman_network_driver_register(&network_driver) < 0) {
		connman_technology_driver_unregister(&tech_driver);
		connman_device_driver_unregister(&device_driver);
		goto out;
	}

	client = g_dbus_client_new(connection, IWD_SERVICE, IWD_PATH);
	if (!client) {
		connman_warn("Failed to initialize D-Bus client for "
				IWD_SERVICE);
		goto out;
	}

	g_dbus_client_set_connect_watch(client, iwd_is_present, NULL);
	g_dbus_client_set_disconnect_watch(client, iwd_is_out, NULL);
	g_dbus_client_set_proxy_handlers(client, object_added, object_removed,
			NULL, NULL);

	return 0;

out:
	if (devices)
		g_hash_table_destroy(devices);

	if (networks)
		g_hash_table_destroy(networks);

	if (known_networks)
		g_hash_table_destroy(known_networks);

	if (stations)
		g_hash_table_destroy(stations);

	if (access_points)
		g_hash_table_destroy(access_points);

	if (adapters)
		g_hash_table_destroy(adapters);

	if (connection)
		dbus_connection_unref(connection);

	return -EIO;
}

static void iwd_exit(void)
{
	connman_network_driver_unregister(&network_driver);
	connman_device_driver_unregister(&device_driver);
	connman_technology_driver_unregister(&tech_driver);

	g_dbus_client_unref(client);

	g_hash_table_destroy(access_points);
	g_hash_table_destroy(stations);
	g_hash_table_destroy(known_networks);
	g_hash_table_destroy(networks);
	g_hash_table_destroy(devices);
	g_hash_table_destroy(adapters);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(iwd, "IWD plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, iwd_init, iwd_exit)
