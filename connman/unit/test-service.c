/*
 *
 *  ConnMan VPN daemon settings unit tests
 *
 *  Copyright (C) 2018 Jolla Ltd. All rights reserved.
 *  Contact: jussi.laakkonen@jolla.com
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

#include <glib.h>
#include <glib/gstdio.h>

#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif


#include "src/service.c"

static gint index_counter = 0;
unsigned int *preferred_list = NULL;

/* Dummies */
const char *__connman_setting_get_fallback_device_type(const char *interface)
{
	return NULL;
}

unsigned int *connman_setting_get_uint_list(const char *key)
{ 
	if (g_str_equal(key, "PreferredTechnologies"))
		return preferred_list;

	return 0;
}

bool connman_setting_get_bool(const char *key) { return true; }
unsigned int connman_setting_get_uint(const char *key) { return 0; }
char **connman_setting_get_string_list(const char *key) { return NULL; }
unsigned int connman_timeout_input_request(void) { return 0; }
unsigned int connman_timeout_browser_launch(void) { return 0; }
bool __connman_session_policy_autoconnect(
	enum connman_service_connect_reason reason) { return true; }
int __connman_session_destroy(DBusMessage *msg) { return 0; }
int __connman_session_create(DBusMessage *msg) { return 0; }
const char *connman_setting_get_string(const char *key) { return NULL; }
const char *__connman_tethering_get_bridge(void) { return NULL; }
void __connman_tethering_set_disabled(void) { return; }
int __connman_tethering_set_enabled(void) { return 0; }
int __connman_private_network_release(const char *path) { return 0; }
int __connman_private_network_request(DBusMessage *msg, const char *owner)
{
	return 0;
}

unsigned int ptr = 0x12345678;
GHashTable *dbus_path_data = NULL;

dbus_bool_t dbus_connection_register_object_path(DBusConnection *connection,
			const char *path, const DBusObjectPathVTable *vtable,
			void *user_data)
{
	g_hash_table_replace(dbus_path_data, g_strdup(path), user_data);

	return true;
}

dbus_bool_t dbus_connection_get_object_path_data (DBusConnection *connection,
					const char *path, void **data_p)
{
	void *user_data;

	user_data = g_hash_table_lookup(dbus_path_data, path);
	if (!user_data)
		return false;

	*data_p = user_data;
	return true;
}

DBusConnection* dbus_connection_ref(DBusConnection *connection)
{
	return (DBusConnection*)&ptr;
}

void dbus_connection_unref(DBusConnection *connection) { return; }

dbus_bool_t dbus_connection_send(DBusConnection *connection,
				DBusMessage *message, dbus_uint32_t *serial)
{
	return true;
}

gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy)
{
	return true;
}

gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name)
{
	return true;
}

gboolean g_dbus_send_reply(DBusConnection *connection,
				DBusMessage *message, int type, ...)
{
	return true;
}

gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message)
{
	return true;
}

static const char *__dbus_sender = "1:00";

const char *g_dbus_get_current_sender(void)
{
	return __dbus_sender;
}

static int __gdbusproxyptr = 0x43211234;

GDBusProxy *g_dbus_proxy_new(GDBusClient *client, const char *path,
							const char *interface)
{
	return (GDBusProxy*)&__gdbusproxyptr;
}

DBusMessage *g_dbus_create_error_valist(DBusMessage *message, const char *name,
					const char *format, va_list args)
{
	char str[1024];

	if (format)
		vsnprintf(str, sizeof(str), format, args);
	else
		str[0] = '\0';

	return dbus_message_new_error(message, name, str);
}

DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...)
{
	va_list args;
	DBusMessage *reply;

	g_assert(message);

	DBG("message %p serial %u name %s format %s", message,
				dbus_message_get_serial(message),
				name, format);

	va_start(args, format);

	reply = g_dbus_create_error_valist(message, name, format, args);

	va_end(args);

	DBG("created error %p", reply);

	return reply;
}

DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...)
{
	g_assert(message);

	DBG("message %p", message);

	return dbus_message_new_method_return(message);
}

gboolean g_dbus_send_message_with_reply(DBusConnection *connection,
					DBusMessage *message,
					DBusPendingCall **call, int timeout)
{
	return true;
}

gboolean g_dbus_emit_signal(DBusConnection *connection,
				const char *path, const char *interface,
				const char *name, int type, ...)
{
	return TRUE;
}

guint g_dbus_add_service_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction connect,
				GDBusWatchFunction disconnect,
				void *user_data, GDBusDestroyFunction destroy)
{
	return 1;
}

gboolean g_dbus_remove_watch(DBusConnection *connection, guint id)
{
	return true;
}

void g_dbus_client_unref(GDBusClient *client) { return; }

void __connman_peer_list_struct(DBusMessageIter *array) { return; }

int __connman_peer_service_register(const char *owner, DBusMessage *msg,
					const unsigned char *specification,
					int specification_length,
					const unsigned char *query,
					int query_length, int version,
					bool master)
{
	return 0;
}

int __connman_peer_service_unregister(const char *owner,
					const unsigned char *specification,
					int specification_length,
					const unsigned char *query,
					int query_length, int version)
{
	return 0;
}

struct connman_provider {
	char *name;
	struct connman_service *vpn_service;
	int index;
	char *identifier;
	int family;
	const char *service_ident;
};

int connman_provider_get_index(struct connman_provider *provider)
{
	return provider ? provider->index : -1;
}

int connman_provider_get_family(struct connman_provider *provider)
{
	return provider ? provider->family : PF_UNSPEC;
}

int __connman_provider_create_and_connect(DBusMessage *msg) { return 0; }
int connman_provider_disconnect(struct connman_provider *provider) { return 0; }

void connman_provider_unref_debug(struct connman_provider *provider,
	const char *file, int line, const char *caller)
{
	g_assert(provider);
	g_free(provider->identifier);
	g_free(provider->name);
	g_free(provider);
}

int __connman_provider_remove_by_path(const char *path) { return 0; }

struct connman_provider *
connman_provider_ref_debug(struct connman_provider *provider,
			const char *file, int line, const char *caller)
{
	return provider;
}

bool __connman_provider_is_immutable(struct connman_provider *provider)
{
	return false;
}
int __connman_provider_connect(struct connman_provider *provider,
	const char *dbus_sender) { return 0; }

bool __connman_provider_check_routes(struct connman_provider *provider)
{
	return true;
}
const char *__connman_provider_get_ident(struct connman_provider *provider)
{
	return provider ? provider->identifier : NULL;
}

const char * __connman_provider_get_transport_ident(
					struct connman_provider *provider)
{
	return provider ? provider->service_ident : NULL;
}

void __connman_provider_append_properties(struct connman_provider *provider,
							DBusMessageIter *iter)
{
	return;
}

static struct connman_provider *provider_new(void)
{
	struct connman_provider *provider;

	provider = g_try_new0(struct connman_provider, 1);
	if (!provider) {
		DBG("failed to create provider");
		return NULL;
	}

	provider->index = ++index_counter;
	provider->identifier = NULL;
	provider->family = AF_INET;

	return provider;
}

static int provider_count = 0;

struct connman_provider *connman_provider_get(const char *identifier)
{
	struct connman_provider *provider;

	provider = provider_new();
	if (!provider)
		return NULL;

	DBG("provider %p", provider);

	provider->identifier = g_strdup(identifier);
	provider->name = g_strdup_printf("VPN%d", ++provider_count);

	return provider;
}

const char *connman_provider_get_string(struct connman_provider *provider,
					const char *key)
{
	g_assert(provider);
	g_assert(key);
	g_assert_cmpstr(key, ==, "Name");

	return provider->name;
}

int __connman_provider_set_ipv6_for_connected(
					struct connman_provider *provider,
					bool enable)
{
	return 0;
}

//typedef struct connman_stats;
int ptr2 = 0x87654321;

struct connman_stats *__connman_stats_new(struct connman_service *service,
							gboolean roaming)
{
	g_assert(service);
	return (struct connman_stats*)&ptr2;
}

void __connman_stats_free(struct connman_stats *stats) { return; }
void __connman_stats_reset(struct connman_stats *stats)  { return; }
void __connman_stats_set_index(struct connman_stats *stats, int index)
{
	return;
}

gboolean __connman_stats_update(struct connman_stats *stats,
				const struct connman_stats_data *data)
{
	return TRUE;
}

void __connman_stats_rebase(struct connman_stats *stats,
				const struct connman_stats_data *data)
{
	return;
}

void __connman_stats_get(struct connman_stats *stats,
				struct connman_stats_data *data)
{
	return;
}

void __connman_stats_read(const char *identifier, gboolean roaming,
				struct connman_stats_data *data)
{
	return;
}

void __connman_stats_clear(const char *identifier, gboolean roaming)
{
	return;
}

int __connman_counter_register(const char *owner, const char *path,
						unsigned int interval)
{
	return 0;
}

int __connman_counter_unregister(const char *owner, const char *path)
{
	return 0;
}

void __connman_counter_send_usage(const char *counter, DBusMessage *msg)
{
	return;
}

int connman_agent_driver_register(struct connman_agent_driver *driver)
{
	return 0;
}

void connman_agent_driver_unregister(struct connman_agent_driver *driver)
{
	return;
}

int connman_agent_report_error(void *user_context, const char *path,
				const char *error,
				report_error_cb_t callback,
				const char *dbus_sender, void *user_data)
{
	return 0;
}

int connman_agent_register(const char *sender, const char *path)
{
	return 0;
}

int connman_agent_unregister(const char *sender, const char *path)
{
	return 0;
}

void connman_agent_cancel(void *user_context) { return; }

int __connman_agent_report_peer_error(struct connman_peer *peer,
					const char *path, const char *error,
					report_error_cb_t callback,
					const char *dbus_sender,
					void *user_data)
{
	return 0;
}

int __connman_agent_request_peer_authorization(struct connman_peer *peer,
						peer_wps_cb_t callback,
						bool wps_requested,
						const char *dbus_sender,
						void *user_data)
{
	return 0;
}

int __connman_agent_request_passphrase_input(struct connman_service *service,
				authentication_cb_t callback,
				const char *dbus_sender, void *user_data)
{
	return 0;
}

int __connman_machine_init(void) { return 0; }
void __connman_machine_cleanup(void) { return; }

enum wispr_status {
	WISPR_STATUS_IDLE = 0,
	WISPR_STATUS_START,
	WISPR_STATUS_RESOLVE,
	WISPR_STATUS_ONLINE_CHECK,
	WISPR_STATUS_STOP,
};

enum wispr_status __wispr_status = WISPR_STATUS_IDLE;

static void do_wispr(struct connman_service *service, const char *gw)
{
	g_assert(service);

	switch (__wispr_status) {
	case WISPR_STATUS_IDLE:
		DBG("not setup");
		return;
	case WISPR_STATUS_START:
		DBG("start -> resolve");
		__connman_service_nameserver_add_routes(service, gw);
		__wispr_status++;
		break;
	case WISPR_STATUS_RESOLVE:
		DBG("resolve -> online check");
		__connman_service_nameserver_del_routes(service,
					CONNMAN_IPCONFIG_TYPE_IPV4);
		__wispr_status++;
		break;
	case WISPR_STATUS_ONLINE_CHECK:
		DBG("online check -> stop");
		connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_ONLINE,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
		__wispr_status++;
		break;
	case WISPR_STATUS_STOP:
		DBG("wispr stop");
		__wispr_status = WISPR_STATUS_IDLE;
		break;
	default:
		DBG("invalid state");
		break;
	}
}

int __connman_wispr_start(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	DBG("");

	g_assert(service);
	g_assert_cmpint(type, ==, CONNMAN_IPCONFIG_TYPE_IPV4);

	if (__wispr_status != WISPR_STATUS_IDLE)
		DBG("Restarting");

	/*
	 * gweb.c would be cancelled as the wp_context in wispr is unref'd,
	 * when restarting wispr, which will in turn result in gweb.c removing
	 * the nameserver routes if added at cancel process.
	 */
	if (__wispr_status == WISPR_STATUS_RESOLVE)
		__connman_service_nameserver_del_routes(service,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	__wispr_status = WISPR_STATUS_START;

	return 0;
}

void __connman_wispr_stop(struct connman_service *service)
{
	DBG("");

	g_assert(service);
	__wispr_status = WISPR_STATUS_IDLE;
	return;
}

static GHashTable *phy_vpn_table = NULL;

int __connman_connection_get_vpn_index(int phy_index)
{
	GHashTableIter iter;
	gpointer value, key;

	DBG("%d", phy_index);

	g_hash_table_iter_init(&iter, phy_vpn_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct connman_service *service = key;
		struct connman_service *transport = value;

		if (__connman_service_get_index(transport) != phy_index)
			continue;

		return __connman_service_get_index(service);
	}

	return -1;
}

int __connman_connection_get_vpn_phy_index(int vpn_index)
{
	GHashTableIter iter;
	gpointer value, key;

	DBG("%d", vpn_index);

	g_hash_table_iter_init(&iter, phy_vpn_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct connman_service *service = key;
		struct connman_service *transport = value;

		if (__connman_service_get_index(service) != vpn_index)
			continue;

		return __connman_service_get_index(transport);
	}

	return -1;
}

bool __connman_connection_update_gateway(void)
{
	return true;
}

int __connman_connection_gateway_add(struct connman_service *service,
					const char *gateway,
					enum connman_ipconfig_type type,
					const char *peer)
{
	g_assert(service);
	__connman_service_nameserver_add_routes(service, gateway);
	return 0;
}

void __connman_connection_gateway_remove(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	g_assert(service);
	__connman_service_nameserver_del_routes(service, type);
	return;
}

int __connman_config_provision_service(struct connman_service *service)
{
	g_assert(service);
	return 0;
}

int __connman_config_provision_service_ident(struct connman_service *service,
		const char *ident, const char *file, const char *entry)
{
	return 0;
}

bool __connman_config_address_provisioned(const char *address,
					const char *netmask)
{
	return false;
}

struct connman_device {
	int index;
	char *name;
	char *ident;
	struct connman_network *network;
	bool keep_network;
	bool scanning;
};

struct connman_device wifi_device = {
	.index = -1,
	.name = "wifi",
	.ident = "deadbeefbaad",
	.network = NULL,
	.keep_network = false,
	.scanning = false,
};

int __connman_device_request_scan(enum connman_service_type type)
{
	g_assert_cmpint(type, ==, CONNMAN_SERVICE_TYPE_WIFI);
	return 0;
}

int __connman_device_request_hidden_scan(struct connman_device *device,
				const char *ssid, unsigned int ssid_len,
				const char *identity, const char *passphrase,
				const char *security, void *user_data)
{
	g_assert(device);
	return -EINPROGRESS;
}

void __connman_device_keep_network(struct connman_network *network)
{
	g_assert(network);
	g_assert(wifi_device.network == network);
	wifi_device.keep_network = true;
}

void __connman_device_set_network(struct connman_device *device,
					struct connman_network *network)
{
	g_assert(device);
	g_assert(device == &wifi_device);

	device->network = network;
}

int __connman_device_disable(struct connman_device *device)
{
	g_assert(device);
	return 0;
}

int __connman_device_disconnect(struct connman_device *device)
{
	g_assert(device);
	return 0;
}

int __connman_device_enable(struct connman_device *device)
{
	g_assert(device);
	return 0;
}

struct connman_device *__connman_device_find_device(
						enum connman_service_type type)
{
	if (type == CONNMAN_SERVICE_TYPE_WIFI)
		return &wifi_device;

	return NULL;
}

enum connman_service_type __connman_device_get_service_type(
						struct connman_device *device)
{
	g_assert(device);
	g_assert(device == &wifi_device);
	return CONNMAN_SERVICE_TYPE_WIFI;
}

bool __connman_device_isfiltered(const char *devname)
{
	g_assert(devname);
	g_assert_cmpstr(devname, ==, wifi_device.name);

	return false;
}

struct connman_device *connman_device_create_from_index(int index)
{
	g_assert_cmpint(index, ==, index_counter);
	return &wifi_device;
}

const char *connman_device_get_ident(struct connman_device *device)
{
	g_assert(device);
	g_assert(device == &wifi_device);
	return device->ident;
}

int connman_device_get_index(struct connman_device *device)
{
	g_assert(device);
	g_assert(device == &wifi_device);
	return device->index;
}

bool connman_device_get_powered(struct connman_device *device)
{
	g_assert(device);
	if (device == &wifi_device)
		return true;

	return false;
}

bool connman_device_get_scanning(struct connman_device *device,
						enum connman_service_type type)
{
	g_assert(device);
	g_assert(device == &wifi_device);
	return device->scanning;
}

int connman_device_register(struct connman_device *device)
{
	g_assert(device);
	g_assert(device == &wifi_device);
	return 0;
}

int connman_device_set_regdom(struct connman_device *device,
						const char *alpha2)
{
	g_assert(device);
	g_assert(alpha2);
	g_assert(device == &wifi_device);
	return 0;
}

int connman_device_set_scanning(struct connman_device *device,
				enum connman_service_type type, bool scanning)
{
	g_assert(device);
	g_assert(device == &wifi_device);
	g_assert(type == CONNMAN_SERVICE_TYPE_WIFI);
	if (device->scanning == scanning)
		return -EALREADY;

	device->scanning = scanning;

	return 0;
}

void __connman_device_stop_scan(enum connman_service_type type)
{
	return;
}


struct connman_device *connman_device_ref_debug(struct connman_device *device,
				const char *file, int line, const char *caller)
{
	return device;
}
void connman_device_unref_debug(struct connman_device *device,
				const char *file, int line, const char *caller)
{
	return;
}

void connman_device_unregister(struct connman_device *device)
{
	g_assert(device);
	g_assert(device == &wifi_device);
}

char *__connman_dhcp_get_server_address(struct connman_ipconfig *ipconfig)
{
	g_assert(ipconfig);
	return g_strdup("192.168.1.1");
}

int __connman_dhcp_start(struct connman_ipconfig *ipconfig,
			struct connman_network *network, dhcp_cb callback,
			gpointer user_data)
{
	g_assert(ipconfig);
	g_assert(network);

	return 0;
}

void __connman_dhcp_stop(struct connman_ipconfig *ipconfig)
{
	g_assert(ipconfig);
}

int __connman_inet_get_interface_address(int index, int family, void *address)
{
	g_assert_cmpint(index, ==, index_counter);
	g_assert_cmpint(family, ==, AF_INET);

	return 0;
}

int __connman_inet_get_interface_mac_address(int index, uint8_t *mac_address)
{
	g_assert_cmpint(index, ==, index_counter);
	return 0;
}

int __connman_inet_ipv6_do_dad(int index, int timeout_ms,
				struct in6_addr *addr,
				connman_inet_ns_cb_t callback,
				void *user_data)
{
	return 0;
}

GSList *__connman_inet_ipv6_get_prefixes(struct nd_router_advert *hdr,
					unsigned int length)
{
	return NULL;
}

int __connman_inet_ipv6_send_ra(int index, struct in6_addr *src_addr,
				GSList *prefixes, int router_lifetime)
{
	return 0;
}

int __connman_inet_ipv6_send_rs(int index, int timeout,
			__connman_inet_rs_cb_t callback, void *user_data)
{
	return 0;
}

int __connman_inet_ipv6_start_recv_rs(int index,
					__connman_inet_recv_rs_cb_t callback,
					void *user_data,
					void **context)
{
	return 0;
}

void __connman_inet_ipv6_stop_recv_rs(void *context) { return; }

int __connman_inet_modify_address(int cmd, int flags,
				int index, int family,
				const char *address,
				const char *peer,
				unsigned char prefixlen,
				const char *broadcast,
				bool is_p2p)
{
	return 0;
}

int __connman_inet_rtnl_addattr32(struct nlmsghdr *n, size_t maxlen, int type,
				__u32 data)
{
	return 0;
}

int __connman_inet_rtnl_addattr_l(struct nlmsghdr *n, size_t max_length,
				int type, const void *data, size_t data_length)
{
	return 0;
}

void __connman_inet_rtnl_close(struct __connman_inet_rtnl_handle *rth)
{
	return;
}

int __connman_inet_rtnl_open(struct __connman_inet_rtnl_handle *rth)
{
	return 0;
}

int __connman_inet_rtnl_talk(struct __connman_inet_rtnl_handle *rtnl,
			struct nlmsghdr *n, int timeout,
			__connman_inet_rtnl_cb_t callback, void *user_data)
{
	return 0;
}

static GList *__inet_route_list = NULL;

struct inet_route_item {
	int index;
	char *host;
	char *gateway;
};

static struct inet_route_item *inet_route_item_new(int index,
							const char *host,
							const char *gateway)
{
	struct inet_route_item *item;

	item = g_try_new0(struct inet_route_item, 1);
	g_assert(item);
	item->index = index;
	item->host = g_strdup(host);
	item->gateway = g_strdup(gateway);

	return item;
}

static void inet_route_item_del(struct inet_route_item *item)
{
	g_assert(item);
	g_free(item->host);
	g_free(item->gateway);
	g_free(item);
}

static void inet_route_item_remove(gpointer data, gpointer user_data)
{
	struct inet_route_item *item = data;
	inet_route_item_del(item);
}

static gint route_item_compare(gconstpointer a, gconstpointer b)
{
	const struct inet_route_item *item_a = a;
	const struct inet_route_item *item_b = b;

	if ((item_a->index == item_b->index) &&
				!g_strcmp0(item_a->host, item_b->host) &&
				!g_strcmp0(item_a->gateway, item_b->gateway))
		return 0;

	return 1;
}

static gint route_item_compare_no_gw(gconstpointer a, gconstpointer b)
{
	const struct inet_route_item *item_a = a;
	const struct inet_route_item *item_b = b;

	if ((item_a->index == item_b->index) &&
				!g_strcmp0(item_a->host, item_b->host))
		return 0;

	return 1;
}

int connman_inet_add_host_route(int index, const char *host,
							const char *gateway)
{
	struct inet_route_item *item;

	g_assert_cmpint(index, ==, index_counter);
	g_assert(host);
	g_assert(gateway);

	DBG("index %d host %s gateway %s", index, host, gateway);

	item = inet_route_item_new(index, host, gateway);
	g_assert(item);

	g_assert_null(g_list_find_custom(__inet_route_list, item,
							route_item_compare));

	__inet_route_list = g_list_append(__inet_route_list, item);

	return 0;
}

int connman_inet_del_host_route(int index, const char *host)
{
	GList *list_item;
	struct inet_route_item item = {
		.index = index,
		.host = (char*)host,
		.gateway = NULL,
	};

	DBG("index %d host %s", index, host);

	list_item = g_list_find_custom(__inet_route_list, &item,
						route_item_compare_no_gw);
	g_assert(list_item);

	__inet_route_list  = g_list_remove_link(__inet_route_list, list_item);
	inet_route_item_del(list_item->data);
	g_list_free(list_item);

	return 0;
}

int connman_inet_add_ipv6_host_route(int index, const char *host,
					const char *gateway)
{
	return 0;
}

int connman_inet_del_ipv6_host_route(int index, const char *host)
{
	return 0;
}

int connman_inet_check_ipaddress(const char *host)
{
	g_assert(host);
	return AF_INET;
}
int connman_inet_clear_address(int index, struct connman_ipaddress *ipaddress)
{
	g_assert_cmpint(index, ==, index_counter);
	g_assert(ipaddress);
	return 0;
}

int connman_inet_clear_ipv6_address(int index,
					struct connman_ipaddress *ipaddress)
{
	return 0;
}

bool connman_inet_compare_subnet(int index, const char *host)
{
	g_assert_cmpint(index, ==, index_counter);
	g_assert(host);
	return false;
}

int connman_inet_ifindex(const char *name)
{
	g_assert(name);
	g_assert_cmpstr(name, ==, "wlan0");
	return index_counter;
}

char *connman_inet_ifname(int index)
{
	g_assert_cmpint(index, ==, index_counter);
	return g_strdup("wlan0");
}

bool connman_inet_is_ipv6_supported() { return false; }

int connman_inet_set_address(int index, struct connman_ipaddress *ipaddress)
{
	g_assert_cmpint(index, ==, index_counter);
	g_assert(ipaddress);
	return 0;
}

int connman_inet_set_ipv6_address(int index,
		struct connman_ipaddress *ipaddress)
{
	return 0;
}

int connman_inet_setup_tunnel(char *tunnel, int mtu) { return 0; }


void __connman_resolver_append_fallback_nameservers(void) { return; }
int __connman_resolvfile_append(int index, const char *domain,
							const char *server)
{
	return 0;
}

int __connman_resolvfile_remove(int index, const char *domain,
							const char *server)
{
	return 0;
}

int __connman_resolver_redo_servers(int index)
{
	return 0;
}


int connman_resolver_append(int index, const char *domain,
							const char *server)
{
	return 0;
}

int connman_resolver_append_lifetime(int index, const char *domain,
				const char *server, unsigned int lifetime)
{
	return 0;
}

int connman_resolver_remove(int index, const char *domain,
							const char *server)
{
	return 0;
}

int __connman_resolver_set_mdns(int index, bool enabled)
{
	return 0;
}

/* EOD - end of dummies */

/* Prevent fs access with these */

FILE *fopen(const char *pathname, const char *mode)
{
	DBG("pathname %s mode %s", pathname, mode);
	return NULL;
}

int fclose(FILE *stream)
{
	DBG("");
	return 0;
}

int fprintf(FILE *stream, const char *format, ...)
{
	DBG("");
	return 0;
}

int fscanf(FILE *stream, const char *format, ...)
{
	DBG("");
	return 0;
}

int rmdir(const char *pathname)
{
	DBG("pathname %s", pathname);
	return 0;
}

DIR *opendir(const char *name)
{
	DBG("name %p", name);
	return NULL;
}

struct dirent *readdir(DIR *dirp)
{
	DBG("DIR %p", dirp);
	return NULL;
}

int closedir(DIR *dirp)
{
	DBG("DIR %p", dirp);
	return 0;
}

gboolean g_file_set_contents(const gchar* filename, const gchar* contents,
						gssize length, GError** error)
{
	DBG("filename %s", filename);

	return TRUE;
}

gboolean g_key_file_load_from_file(GKeyFile *keyfile, const gchar *filename,
					GKeyFileFlags flags, GError** error)
{
	DBG("filename %s", filename);

	*error = g_error_new_literal(1, G_FILE_ERROR_NOENT, "no file in test");

	return FALSE;
}

gboolean g_mkdir_with_parents(const char *pathname, gint mode)
{
	DBG("pathname %s", pathname);

	return TRUE;
}

char *realpath(const char *path, char *resolved_path)
{
	char *ptr;
	size_t len;

	g_assert(path);
	g_assert(resolved_path);

	DBG("path %s", path);

	errno = 0;
	len = strlen(path);
	ptr = stpncpy(resolved_path, path, len);
	g_assert(ptr);

	return ptr;
}

/* EOFS */

static void set_vpn_phy(struct connman_service *service)
{
	struct connman_service *transport;

	transport = get_connected_default_service();
	if (!transport) {
		return; // May be unset, not connected
	}

	DBG("VPN %p -> %p", service, transport);

	g_assert(phy_vpn_table);

	g_hash_table_replace(phy_vpn_table, service, transport);

	if (service->provider)
		service->provider->service_ident = transport->identifier;
}

static struct connman_service *get_vpn_transport(
					struct connman_service *service)
{
	if (!phy_vpn_table)
		return NULL;

	return g_hash_table_lookup(phy_vpn_table, service);
}

static gint ident_counter = 0;

static char *create_ident(enum connman_service_type type)
{
	int pos = 0;
	char *ident = NULL;
	const char *prefix[] = {
		"unknown",
		"system",
		"ethernet",
		"wifi",
		"bluetooth",
		"cellular",
		"gps",
		"vpn",
		"gadget",
		"p2p",
		NULL,
	};
	const char *postfix[] = {
		"unknown",
		"system1",
		"cable1",
		"managed_psk",
		"dun1",
		"context1",
		"pos1",
		"domain_org",
		"gadget1",
		"network1",
		NULL,
	};

	if (type > CONNMAN_SERVICE_TYPE_P2P)
		pos = 0;
	else
		pos = (int)type;

	ident_counter++;

	ident = g_strdup_printf("%s_%d_%s", prefix[pos], ident_counter,
		postfix[pos]);

	return ident;
}

static void setup_network_or_provider(struct connman_service *service)
{
	enum connman_network_type type = CONNMAN_NETWORK_TYPE_UNKNOWN;
	int prefix_pos = 0;
	char *ident = NULL;
	const char* prefixes[] = {
		"network",
		"provider",
		NULL,
	};

	switch(service->type) {
	case CONNMAN_SERVICE_TYPE_WIFI:
		type = CONNMAN_NETWORK_TYPE_WIFI;
		break;
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		type = CONNMAN_NETWORK_TYPE_CELLULAR;
		break;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		type = CONNMAN_NETWORK_TYPE_ETHERNET;
		break;
	case CONNMAN_SERVICE_TYPE_GADGET:
		type = CONNMAN_NETWORK_TYPE_GADGET;
		break;
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		type = CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN;
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		prefix_pos = 1;
		break;
	default:
		break;
	}

	ident = g_strdup_printf("%s_%s", prefixes[prefix_pos],
			service->identifier);
	++index_counter;

	if (service->state == CONNMAN_SERVICE_STATE_ONLINE ||
				service->state == CONNMAN_SERVICE_STATE_READY) {
		if (type != CONNMAN_NETWORK_TYPE_UNKNOWN) {
			service->network = connman_network_create(ident, type);
			connman_network_set_index(service->network, index_counter);
		}

		if (service->type == CONNMAN_SERVICE_TYPE_VPN) {
			service->provider = connman_provider_get(ident);
			service->provider->vpn_service = service;
		}
	}

	connman_service_create_ip4config(service, index_counter);
	connman_service_create_ip6config(service, index_counter);

	g_free(ident);
}

static struct connman_service *add_service_type(enum connman_service_type type,
			enum connman_service_state state, bool split_routing,
			uint8_t signal_str)
{
	char *ident = NULL;
	struct connman_service *service = NULL;

	ident = create_ident(type);
	service = service_new(type, ident);

	service->state = state;
	service->strength = signal_str;
	
	setup_network_or_provider(service);
	
	if (type == CONNMAN_SERVICE_TYPE_VPN) {
		if (state == CONNMAN_SERVICE_STATE_READY)
			set_vpn_phy(service);
			/*service->vpn_transport =
					get_connected_default_service();*/

		__connman_service_set_split_routing(service, split_routing);
	}

	service_list = g_list_insert_sorted(service_list, service,
							service_compare);
	g_hash_table_replace(service_hash, service->identifier, service);

	g_free(ident);

	return service;
}

static void add_services()
{
	enum connman_service_state state = 1;
	enum connman_service_type type = 1;
	uint8_t strength = 0;

	for (type = 1; type <= CONNMAN_SERVICE_TYPE_P2P; type++) {
		for (state = 1; state <= CONNMAN_SERVICE_STATE_FAILURE;
								state++) {

			/*
			 * Apparently P2P, GPS, SYSTEM nor VPN do not have
			 * online check. TODO check this.
			 */
			if ((type == CONNMAN_SERVICE_TYPE_VPN ||
					type == CONNMAN_SERVICE_TYPE_P2P ||
					type == CONNMAN_SERVICE_TYPE_GPS ||
					type == CONNMAN_SERVICE_TYPE_SYSTEM) &&
					state == CONNMAN_SERVICE_STATE_ONLINE)
				continue;

			if (type == CONNMAN_SERVICE_TYPE_WIFI &&
					(state == CONNMAN_SERVICE_STATE_READY ||
					state == CONNMAN_SERVICE_STATE_ONLINE))
				strength = (int)state + 70;
			else
				strength = 0;

			add_service_type(type, state, false, strength);
		}
	}
}

static void print_test_service(struct connman_service *service, void *user_data)
{
	if (!service)
		return;

	printf("%p %2d %-56s %-3d %-6s %-10s %-16s %-12s %u\n",
			service, __connman_service_get_index(service),
			service->identifier, service->order,
			is_connected(service->state) ? "true" : "false",
			is_available(service) ? "available" : "non-avail",
			state2string(service->state),
			__connman_service_is_split_routing(service) ?
					"split routed" : "default",
			service->strength);
}

static void print_services()
{
	static struct connman_debug_desc debug_desc CONNMAN_DEBUG_ATTR = {
		.file = __FILE__,
		.flags = CONNMAN_DEBUG_FLAG_DEFAULT
	};

	if (debug_desc.flags && CONNMAN_DEBUG_FLAG_PRINT) {
		__connman_service_foreach(print_test_service, NULL);
	}
}


static bool check_preferred_type_order(struct connman_service *a,
	struct connman_service *b)
{
	unsigned int a_pref_order = G_MAXUINT;
	unsigned int b_pref_order = G_MAXUINT;
	int i;

	DBG("%p vs %p", a, b);

	if (is_connected(a->state) && is_connected(b->state)) {
		if (a->type == CONNMAN_SERVICE_TYPE_VPN &&
							is_connected(a->state))
			return true;

		if (b->type == CONNMAN_SERVICE_TYPE_VPN &&
							is_connected(b->state))
			return true;

		for (i = 0 ; preferred_list[i] != 0; i++) {
			if (preferred_list[i] == a->type)
				a_pref_order = i;

			if (preferred_list[i] == b->type)
				b_pref_order = i;
		}

		return a_pref_order <= b_pref_order;
	}

	return true;
}

static int get_type_order(enum connman_service_type type)
{
	/* Ranking order based on service.c:service_compare() */
	switch (type) {
	case CONNMAN_SERVICE_TYPE_VPN:
		return 6;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return 5;
	case CONNMAN_SERVICE_TYPE_WIFI:
		return 4;
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return 3;
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return 2;
	case CONNMAN_SERVICE_TYPE_GADGET:
		return 1;
	default:
		return 0;
	}
}

static bool check_type_order(struct connman_service *a,
	struct connman_service *b)
{
	int a_type_order = 0, b_type_order = 0;
	
	a_type_order = get_type_order(a->type);
	b_type_order = get_type_order(b->type);
	
	return a_type_order >= b_type_order;
}

static void service_order_check(bool(*order_cb)(struct connman_service *a,
						struct connman_service *b))
{
	GList *iter;
	GList *iter_next;
	struct connman_service *a;
	struct connman_service *b;

	for (iter = service_list ; iter ; iter = iter->next) {
		iter_next = iter->next;

		/* iter is the last item */
		if (!iter_next)
			continue;

		a = iter->data;
		b = iter_next->data;

		DBG("T: %s vs. %s", a->identifier, b->identifier);

		if (a->type == CONNMAN_SERVICE_TYPE_VPN &&
				a->state == CONNMAN_SERVICE_STATE_READY) {
			/* VPN as default should be on top */
			if (!__connman_service_is_split_routing(a))
				g_assert(a == service_list->data);
			else
				g_assert(a != service_list->data);

			/*
			 * State of the transport service of VPN has to be
			 * equal or greater than the service below, both of
			 * which need to be connected for state comparison to
			 * to work.
			 */
			if(is_connected(a->state) && is_connected(b->state)) {
				/* Both are VPNs */
				if (b->type == CONNMAN_SERVICE_TYPE_VPN) {
					struct connman_service* a_transport;
					struct connman_service* b_transport;

					a_transport = get_vpn_transport(a);
					b_transport = get_vpn_transport(b);

					g_assert_cmpint(a_transport->state, >=,
							b_transport->state);
				/* Check order only if b is transport */
				} else {
					g_assert_true(order_cb(a,b));
				}
			}

			continue;
		}

		if (b->type == CONNMAN_SERVICE_TYPE_VPN &&
				b->state == CONNMAN_SERVICE_STATE_READY) {
			g_assert(a->state >= b->state);
			continue;
		}

		/* For Wifi, check strength */
		if (a->type == CONNMAN_SERVICE_TYPE_WIFI &&
				b->type ==
				CONNMAN_SERVICE_TYPE_WIFI)
			g_assert(a->strength >= b->strength);

		if (a->state == b->state) {
			g_assert(a->order >= b->order);
			g_assert_true(order_cb(a,b));
			continue;
		}

		/*
		 * If a is connected and b is connected or not, a
		 * should be on top.
		 */
		if (is_connected(a->state)) {
			if (is_connected(b->state) ||
						(is_connecting(b->state)))
				g_assert(a->state >= b->state);
			else
				g_assert(is_available(a) && !is_available(b));

			continue;
		}

		/* Non-conn. must not be on top of connected.*/
		g_assert_false(is_connected(b->state));

		/* configuration & association */
		if (is_connecting(a->state) && is_connecting(b->state)) {
			g_assert(a->state >= b->state);
			continue;
		}

		/* Connected or connecting should not be on top of
		 * not-connected or not connecting.
		 */
		g_assert_false(is_connecting(b->state));

		/*
		 * If both are not connected the state should be
		 * orderd.
		 */
		if (!is_connecting(a->state))
			g_assert(a->state >= b->state);
	}
}

static void service_free_wrapper(void *data, void *user_data)
{
	g_assert(data);
	service_free(data);
}

static void clean_service_list()
{
	g_list_foreach(service_list, service_free_wrapper, NULL);
	g_list_free(service_list);
	service_list = NULL;
}

static void test_init()
{
	__connman_dbus_init(connection);
	__connman_ipconfig_init();

	service_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, NULL);
	service_type_hash = g_new0(GHashTable*, MAX_CONNMAN_SERVICE_TYPES);
	services_notify = g_new0(struct _services_notify, 1);
	services_notify->remove = g_hash_table_new_full(g_str_hash,
			g_str_equal, g_free, NULL);
	services_notify->add = g_hash_table_new(g_str_hash, g_str_equal);
	services_notify->update = g_hash_table_new(g_str_hash, g_str_equal);

	ident_counter = index_counter = 0;
	phy_vpn_table = g_hash_table_new(g_direct_hash, g_direct_equal);
	g_assert(phy_vpn_table);
}

static void test_cleanup()
{
	DBG("");

	clean_service_list();

	g_hash_table_destroy(service_hash);
	service_hash = NULL;

	for (int i = 0; i < MAX_CONNMAN_SERVICE_TYPES; i++) {
		if (!service_type_hash[i])
			continue;

		g_hash_table_destroy(service_type_hash[i]);
		service_type_hash[i] = NULL;
	}

	g_free(service_type_hash);
	service_type_hash = NULL;

	if (services_notify->id != 0) {
		g_source_remove(services_notify->id);
		service_send_changed(NULL);
	}

	g_hash_table_destroy(services_notify->remove);
	g_hash_table_destroy(services_notify->add);
	g_hash_table_destroy(services_notify->update);
	g_free(services_notify);

	g_hash_table_destroy(phy_vpn_table);

	g_list_foreach(__inet_route_list, inet_route_item_remove, NULL);
	g_list_free(__inet_route_list);
	__inet_route_list = NULL;

	__connman_ipconfig_cleanup();
	__connman_dbus_cleanup();
}

static void test_service_sort_full_positive()
{
	test_init();

	add_services();

	service_list = g_list_sort(service_list, service_compare);

	print_services();
	service_order_check(check_type_order);

	test_cleanup();
}

void test_service_sort_with_preferred_list1()
{
	unsigned int list[] = {
		CONNMAN_SERVICE_TYPE_BLUETOOTH,
		CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_TYPE_CELLULAR,
		CONNMAN_SERVICE_TYPE_UNKNOWN,
	};

	test_init();

	preferred_list = list;

	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_STATE_ONLINE, false, 85);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_READY, false, 60);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_ONLINE, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_READY, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	add_service_type(CONNMAN_SERVICE_TYPE_BLUETOOTH,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	service_list = g_list_sort(service_list, service_compare);

	print_services();
	service_order_check(check_preferred_type_order);

	clean_service_list();
}

void test_service_sort_with_preferred_list2()
{
	/* By default eth > wifi > cellular, reverse order */
	unsigned int list[] = {
		CONNMAN_SERVICE_TYPE_BLUETOOTH,
		CONNMAN_SERVICE_TYPE_CELLULAR,
		CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_TYPE_ETHERNET,
		CONNMAN_SERVICE_TYPE_UNKNOWN,
	};

	test_init();

	preferred_list = list;

	add_services();

	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_STATE_ONLINE, false,50);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_READY, false, 45);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_ONLINE, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_READY, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	add_service_type(CONNMAN_SERVICE_TYPE_BLUETOOTH,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	service_list = g_list_sort(service_list, service_compare);

	print_services();
	service_order_check(check_preferred_type_order);

	test_cleanup();
}

void test_service_sort_without_preferred_list()
{
	test_init();

	add_services();

	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_ONLINE, false,50);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_READY, false, 45);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_ONLINE, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_READY, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	add_service_type(CONNMAN_SERVICE_TYPE_BLUETOOTH,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	service_list = g_list_sort(service_list, service_compare);

	print_services();
	service_order_check(check_type_order);

	test_cleanup();
}

void test_service_sort_vpn_default()
{
	test_init();

	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_ONLINE, false,50);
	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_ONLINE, false, 0);

	/* Add both non-split routed (default) and split routed */
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_READY, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_READY, true, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_FAILURE, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_DISCONNECT, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	service_list = g_list_sort(service_list, service_compare);

	print_services();
	service_order_check(check_type_order);

	test_cleanup();
}

void test_service_sort_vpn_default_preferred_list()
{
	unsigned int list[] = {
		CONNMAN_SERVICE_TYPE_BLUETOOTH,
		CONNMAN_SERVICE_TYPE_CELLULAR,
		CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_TYPE_ETHERNET,
		CONNMAN_SERVICE_TYPE_UNKNOWN,
	};

	test_init();

	preferred_list = list;

	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_ONLINE, false, 50);
	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_ONLINE, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_READY, false, 45);

	/* Add both non-split routed (default) and split routed */
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_READY, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_READY, true, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_FAILURE, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_DISCONNECT, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_IDLE, false, 0);

	service_list = g_list_sort(service_list, service_compare);

	print_services();
	service_order_check(check_preferred_type_order);

	test_cleanup();
}

void test_service_sort_vpn_split()
{
	test_init();

	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_ONLINE, false, 0);

	add_service_type(CONNMAN_SERVICE_TYPE_VPN, CONNMAN_SERVICE_STATE_READY,
				true, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_FAILURE, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_DISCONNECT,
				false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN, CONNMAN_SERVICE_STATE_IDLE,
				false, 0);

	service_list = g_list_sort(service_list, service_compare);

	print_services();
	service_order_check(check_type_order);

	test_cleanup();
}

void test_service_sort_vpn_split_preferred_list()
{
	unsigned int list[] = {
		CONNMAN_SERVICE_TYPE_BLUETOOTH,
		CONNMAN_SERVICE_TYPE_CELLULAR,
		CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_TYPE_ETHERNET,
		CONNMAN_SERVICE_TYPE_UNKNOWN,
	};

	test_init();

	preferred_list = list;

	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_ONLINE, false, 50);
	add_service_type(CONNMAN_SERVICE_TYPE_CELLULAR,
				CONNMAN_SERVICE_STATE_ONLINE, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
				CONNMAN_SERVICE_STATE_READY, false, 45);

	add_service_type(CONNMAN_SERVICE_TYPE_VPN, CONNMAN_SERVICE_STATE_READY,
				true, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_FAILURE, false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN,
				CONNMAN_SERVICE_STATE_DISCONNECT,
				false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_VPN, CONNMAN_SERVICE_STATE_IDLE,
				false, 0);

	service_list = g_list_sort(service_list, service_compare);

	print_services();
	service_order_check(check_preferred_type_order);

	test_cleanup();
}


void test_service_sort_single_tech_types()
{
	enum connman_service_type type;
	enum connman_service_state state;

	test_init();

	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN;
				type < MAX_CONNMAN_SERVICE_TYPES; type++) {
		for (state = CONNMAN_SERVICE_STATE_UNKNOWN + 1;
					state <= CONNMAN_SERVICE_STATE_FAILURE;
					state++) {
			if (type == CONNMAN_SERVICE_TYPE_VPN &&
					state == CONNMAN_SERVICE_STATE_ONLINE)
				continue;

			add_service_type(type, state, false, 0);
		}

		service_list = g_list_sort(service_list, service_compare);

		print_services();
		service_order_check(check_type_order);

		clean_service_list();
	}

	test_cleanup();
}

static int wlan_probe(struct connman_network *network) { return 0; }
static void wlan_remove(struct connman_network *network) { return; }
static int wlan_connect(struct connman_network *network) { return 0; }
static int wlan_disconnect(struct connman_network *network) { return 0; }


struct connman_network_driver driver = {
	.name = "wifi",
	.type = CONNMAN_NETWORK_TYPE_WIFI,
	.priority = 1,
	.probe = wlan_probe,
	.remove = wlan_remove,
	.connect = wlan_connect,
	.disconnect = wlan_disconnect,
	.autoconnect_changed = NULL,
};

static struct connman_service *test_setup_service(void)
{
	struct connman_service *service;
	struct connman_network *network;

	g_assert_cmpint(connman_network_driver_register(&driver), ==, 0);
	network = connman_network_create("1234567890",
						CONNMAN_NETWORK_TYPE_WIFI);
	g_assert(network);

	__connman_network_set_device(network, &wifi_device);
	connman_network_set_name(network, "TestWiFi");
	connman_network_set_group(network, "managed_psk");
	connman_network_set_index(network, ++index_counter);

	g_assert_true(__connman_service_create_from_network(network));
	service = connman_service_lookup_from_network(network);

	g_assert(service);
	g_assert(service->ipconfig_ipv4);

	return service;
}

/* Only IPv4 */
static void test_service_nameserver_route_refcount1()
{
	struct connman_service *service;

	test_init();

	service = test_setup_service();

	print_services();

	/* Associate the service network */
	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_ASSOCIATION,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service->strength = 90;
	service_list = g_list_sort(service_list, service_compare);
	print_services();

	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);

	/* Configure IP  as fixed */
	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_CONFIGURATION,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	print_services();

	__connman_ipconfig_set_config_from_address(service->ipconfig_ipv4,
					CONNMAN_IPCONFIG_METHOD_FIXED,
					"192.168.1.2",
					"255.0.0.0",
					"255.255.255.0",
					24);
	__connman_service_nameserver_append(service, "1.1.1.1", false);
	__connman_service_nameserver_append(service, "2.2.2.2", false);
	__connman_ipconfig_set_gateway(service->ipconfig_ipv4, "192.168.1.1");
	g_assert_cmpint(__connman_network_connect(service->network), ==, 0);

	/* Complete connection to ready - gateway gets added */
	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_READY,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	g_assert_cmpint(__connman_ipconfig_gateway_add(service->ipconfig_ipv4),
							==, 0);

	/* Calling __connman_connection_gateway_add() adds DNS routes */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);
	print_services();

	/* Online check transitions normally to ONLINE, simulate that */
	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_ONLINE,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);
	print_services();

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 0);
	print_services();

	/* This has no effect, i.e., counters do not go to negative. */
	__connman_service_nameserver_del_routes(service,
						CONNMAN_IPCONFIG_TYPE_ALL);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 0);

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_IDLE,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	print_services();

	test_cleanup();
}

/* Only IPv4 */
static void test_service_nameserver_route_refcount2()
{
	struct connman_service *service;
	const char *gw = "192.168.1.1";

	test_init();

	service = test_setup_service();

	print_services();

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_ASSOCIATION,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service->strength = 90;
	service_list = g_list_sort(service_list, service_compare);
	print_services();

	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_CONFIGURATION,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	print_services();

	__connman_ipconfig_set_config_from_address(service->ipconfig_ipv4,
					CONNMAN_IPCONFIG_METHOD_FIXED,
					"192.168.1.2",
					"255.0.0.0",
					"255.255.255.0",
					24);
	__connman_service_nameserver_append(service, "1.1.1.1", false);
	__connman_service_nameserver_append(service, "2.2.2.2", false);
	__connman_ipconfig_set_gateway(service->ipconfig_ipv4, gw);
	g_assert_cmpint(__connman_network_connect(service->network), ==, 0);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 0);

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_READY,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	g_assert_cmpint(__connman_ipconfig_gateway_add(service->ipconfig_ipv4),
							==, 0);
	/* Nameserver routes are added */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);
	print_services();

	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_START);

	/* Does resolve and tries to add  nameserver routes */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_RESOLVE);

	/* Refcount increases but no new routes */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 2);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);

	/* Removes nameserver routes and sets service to do online check */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_ONLINE_CHECK);

	/* Routes are not removed but request is done */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);

	/* Sets service to online as online check completes */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_STOP);

	/* No update is done to refs/routes as service goes online */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);
	g_assert_cmpint(service->state, ==, CONNMAN_SERVICE_STATE_ONLINE);

	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);
	print_services();

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 0);
	print_services();

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_IDLE,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	print_services();

	test_cleanup();
}

static void add_test_dnsconfig(DBusMessageIter *iter, void *user_data)
{
	char **servers = user_data;
	int i;

	if (!servers)
		return;

	for (i = 0; servers[i]; i++)
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
								&servers[i]);
}

static void add_test_ipconfig_value(DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, user_data);
}

static void add_test_ipconfig(DBusMessageIter *iter, void *user_data)
{
	const char *method = user_data;

	if (!g_strcmp0(method, "dhcp")) {
		connman_dbus_property_append_dict(iter, "Method",
					add_test_ipconfig_value, user_data);
	} else if (!g_strcmp0(method, "manual")) {
		connman_dbus_property_append_dict(iter, "Method",
					add_test_ipconfig_value, user_data);
		connman_dbus_property_append_dict(iter, "Address",
					add_test_ipconfig_value, "192.168.2.2");
		connman_dbus_property_append_dict(iter, "Gateway",
					add_test_ipconfig_value, "192.168.2.1");
		connman_dbus_property_append_dict(iter, "Netmask",
					add_test_ipconfig_value,
					"255.255.255.0");
	}
}

static int dbus_serial = 0;

static void test_call_set_property(struct connman_service *service,
					const char *key, char **nameservers,
					const char *method)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter iter;

	g_assert(service);
	g_assert(key);

	msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
	g_assert(msg);

	dbus_message_set_serial(msg, ++dbus_serial);
	dbus_message_iter_init_append(msg, &iter);

	if (!g_strcmp0(key, "Nameservers.Configuration"))
		connman_dbus_property_append_array(&iter, key,
					DBUS_TYPE_STRING, add_test_dnsconfig,
					nameservers);
	else if (!g_strcmp0(key, "IPv4.Configuration"))
		connman_dbus_property_append_array(&iter, key,
					DBUS_TYPE_VARIANT, add_test_ipconfig,
					(char*)method);
	else
		goto out;

	/* This replaces the routes but leaves the refcount as is */
	reply = set_property(connection, msg, service);
	g_assert(reply);

	g_assert_false(dbus_message_is_error(reply, "Invalid arguments"));
	g_assert_false(dbus_message_is_error(reply, "Not supported"));

out:
	dbus_message_unref(msg);
}

/* Only IPv4, manual change during resolve */
static void test_service_nameserver_route_refcount3()
{
	struct connman_service *service;
	const char *gw = "192.168.1.1";
	char **nameservers;
	struct rtnl_link_stats64 stats = { 0 };

	test_init();

	service = test_setup_service();

	print_services();

	__connman_ipconfig_newlink(index_counter, 1, IFF_UP,
						"aabbccddeeff", 1500, &stats);
	__connman_ipconfig_newlink(index_counter, 1,
						(IFF_RUNNING | IFF_LOWER_UP),
						"aabbccddeeff", 1500, &stats);

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_ASSOCIATION,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service->strength = 90;
	service_list = g_list_sort(service_list, service_compare);
	print_services();

	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_CONFIGURATION,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	print_services();

	__connman_ipconfig_set_config_from_address(service->ipconfig_ipv4,
					CONNMAN_IPCONFIG_METHOD_FIXED,
					"192.168.1.2",
					"255.0.0.0",
					"255.255.255.0",
					24);
	__connman_service_nameserver_append(service, "1.1.1.1", false);
	__connman_service_nameserver_append(service, "2.2.2.2", false);
	__connman_ipconfig_set_gateway(service->ipconfig_ipv4, gw);
	g_assert_cmpint(__connman_network_connect(service->network), ==, 0);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 0);

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_READY,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	g_assert_cmpint(__connman_ipconfig_gateway_add(service->ipconfig_ipv4),
							==, 0);
	/* Nameserver routes are added */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);
	print_services();

	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_START);

	/* Does resolve and tries to add  nameserver routes */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_RESOLVE);

	/* Refcount increases but no new routes */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 2);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);

	/* Manual change to nameservers via D-Bus */
	nameservers = g_try_new0(char *, 4);
	nameservers[0] = g_strdup("3.3.3.3");
	nameservers[1] = g_strdup("4.4.4.4");
	nameservers[2] = g_strdup("5.5.5.5");

	test_call_set_property(service, "Nameservers.Configuration",
							nameservers, NULL);

	g_strfreev(nameservers);

	/* Since the gweb.c request has been restarted it has removed the ref */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 3);

	/* Since setting user nameservers restarts wispr */
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_START);

	/* Do resolve and try to add  nameserver routes */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_RESOLVE);

	/* Refcount increases but no new routes */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 2);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 3);

	/* Removes nameserver routes and sets service to do online check */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_ONLINE_CHECK);

	/* Routes are not removed but request is done */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 3);

	/* Sets service to online as online check completes */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_STOP);

	/* No update is done to refs/routes as service goes online */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 3);
	g_assert_cmpint(service->state, ==, CONNMAN_SERVICE_STATE_ONLINE);

	/* New nameservers set by user */
	nameservers = g_try_new0(char *, 3);
	nameservers[0] = g_strdup("6.6.6.6");
	nameservers[1] = g_strdup("7.7.7.7");

	test_call_set_property(service, "Nameservers.Configuration",
							nameservers, NULL);

	g_strfreev(nameservers);

	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);
	print_services();

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 0);
	print_services();

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_IDLE,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	print_services();

	test_cleanup();
}

/*
 * Only IPv4, manual change during resolve and reset ipconf after online check
 * is done to use DHCP.
 */
static void test_service_nameserver_route_refcount4()
{
	struct connman_service *service;
	const char *gw = "192.168.1.1";
	char **nameservers;
	struct rtnl_link_stats64 stats = { 0 };

	test_init();

	service = test_setup_service();

	print_services();

	__connman_ipconfig_newlink(index_counter, 1, IFF_UP,
						"aabbccddeeff", 1500, &stats);
	__connman_ipconfig_newlink(index_counter, 1,
						(IFF_RUNNING | IFF_LOWER_UP),
						"aabbccddeeff", 1500, &stats);

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_ASSOCIATION,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service->strength = 90;
	service_list = g_list_sort(service_list, service_compare);
	print_services();

	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_CONFIGURATION,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	print_services();

	__connman_ipconfig_set_config_from_address(service->ipconfig_ipv4,
					CONNMAN_IPCONFIG_METHOD_FIXED,
					"192.168.1.2",
					"255.0.0.0",
					"255.255.255.0",
					24);
	__connman_service_nameserver_append(service, "1.1.1.1", false);
	__connman_service_nameserver_append(service, "2.2.2.2", false);
	__connman_ipconfig_set_gateway(service->ipconfig_ipv4, gw);
	g_assert_cmpint(__connman_network_connect(service->network), ==, 0);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 0);

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_READY,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	g_assert_cmpint(__connman_ipconfig_gateway_add(service->ipconfig_ipv4),
							==, 0);

	/* Nameserver routes are added */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);
	print_services();

	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_START);

	/* Does resolve and tries to add nameserver routes */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_RESOLVE);

	/* Refcount increases but no new routes */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 2);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);

	/* Manual change to nameservers via D-Bus */
	nameservers = g_try_new0(char *, 4);
	nameservers[0] = g_strdup("3.3.3.3");
	nameservers[1] = g_strdup("4.4.4.4");
	nameservers[2] = g_strdup("5.5.5.5");

	test_call_set_property(service, "Nameservers.Configuration",
							nameservers, NULL);

	g_strfreev(nameservers);

	/* Since the gweb.c request has been restarted it has removed the ref */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 3);

	/* Since setting user nameservers restarts wispr */
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_START);

	/* Do resolve and try to add  nameserver routes */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_RESOLVE);

	/* Refcount increases but no new routes */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 2);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 3);

	/* Removes nameserver routes and sets service to do online check */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_ONLINE_CHECK);

	/* Routes are not removed but request is done */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 3);

	/* Sets service to online as online check completes */
	do_wispr(service, gw);
	g_assert_cmpint(__wispr_status, ==, WISPR_STATUS_STOP);

	/* No update is done to refs/routes as service goes online */
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 3);
	g_assert_cmpint(service->state, ==, CONNMAN_SERVICE_STATE_ONLINE);

	/*
	 * Reset IPv4 configuration manually to use dhcp -> nameservers changed
	 * to empty before this (also domains but no need to use here)
	 */
	test_call_set_property(service, "Nameservers.Configuration", NULL,
									NULL);
	test_call_set_property(service, "IPv4.Configuration", NULL, "dhcp");

	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 1);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 2);
	print_services();

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	g_assert_cmpint(g_list_length(__inet_route_list), ==, 0);
	print_services();

	connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_IDLE,
					CONNMAN_IPCONFIG_TYPE_IPV4,
					false);
	service_list = g_list_sort(service_list, service_compare);
	g_assert_cmpint(service->nameservers_ipv4_refcount, ==, 0);
	print_services();

	test_cleanup();
}

int rmdir_r(const gchar* path)
{
	DIR *d = opendir(path);

	if (d) {
		const struct dirent *p;
		int r = 0;

		while (!r && (p = readdir(d))) {
			char *buf;
			struct stat st;

			if (!strcmp(p->d_name, ".") ||
						!strcmp(p->d_name, "..")) {
				continue;
			}

			buf = g_strdup_printf("%s/%s", path, p->d_name);
			if (!stat(buf, &st)) {
				r =  S_ISDIR(st.st_mode) ? rmdir_r(buf) :
								unlink(buf);
			}
			g_free(buf);
		}
		closedir(d);
		return r ? r : rmdir(path);
	} else {
		return -1;
	}
}

static void cleanup_test_directory(gchar *test_path)
{
	gint access_mode = R_OK|W_OK|X_OK;

	if (g_file_test(test_path, G_FILE_TEST_IS_DIR)) {
		g_assert(!access(test_path, access_mode));
		rmdir_r(test_path);
	}
}

static gchar *option_debug = NULL;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return true;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ NULL },
};

int main(int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	int ret;
	char* test_dir = g_dir_make_tmp("connman_test_service_XXXXXX", NULL);

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else {
			g_printerr("An unknown error occurred\n");
		}

		return 1;
	}

	g_option_context_free(context);

	g_test_init(&argc, &argv, NULL);

	__connman_log_init(argv[0], option_debug, false, false,
				"Unit Tests Connection Manager",
				CONNMAN_VERSION);

	g_assert_cmpint(__connman_storage_init(test_dir, ".local", 0755,
								0644), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(VPN_STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_cmpint(__connman_notifier_init(), ==, 0);
	g_assert_cmpint(__connman_ipconfig_init(), ==, 0);

	connection = (DBusConnection*)&ptr;
	dbus_path_data = g_hash_table_new(g_str_hash, g_str_equal);

	g_test_add_func("/service/service_sort_full_positive",
				test_service_sort_full_positive);
	g_test_add_func("/service/service_sort_with_preferred1",
			test_service_sort_with_preferred_list1);
	g_test_add_func("/service/service_sort_with_preferred2",
				test_service_sort_with_preferred_list2);
	g_test_add_func("/service/service_sort_without_preferred",
				test_service_sort_without_preferred_list);
	g_test_add_func("/service/service_sort_vpn_default",
				test_service_sort_vpn_default);
	g_test_add_func("/service/service_sort_vpn_default_preferred_list",
				test_service_sort_vpn_default_preferred_list);
	g_test_add_func("/service/service_sort_vpn_split",
				test_service_sort_vpn_split);
	g_test_add_func("/service/service_sort_vpn_split_preferred_list",
				test_service_sort_vpn_split_preferred_list);
	g_test_add_func("/service/service_sort_single_tech_types",
				test_service_sort_single_tech_types);
	g_test_add_func("/service/service_nameserver_route_refcount1",
				test_service_nameserver_route_refcount1);
	g_test_add_func("/service/service_nameserver_route_refcount2",
				test_service_nameserver_route_refcount2);
	g_test_add_func("/service/service_nameserver_route_refcount3",
				test_service_nameserver_route_refcount3);
	g_test_add_func("/service/service_nameserver_route_refcount4",
				test_service_nameserver_route_refcount4);


	ret = g_test_run();

	__connman_notifier_cleanup();
	__connman_storage_cleanup();
	cleanup_test_directory(test_dir);
	g_free(test_dir);
	__connman_log_cleanup(FALSE);

	return ret;
}
