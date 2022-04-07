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

#include "src/service.c"

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
void __connman_tethering_set_enabled(void) { return; }
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

static gint index_counter = 0;

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

int __connman_wispr_start(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	return 0;
}

void __connman_wispr_stop(struct connman_service *service) { return; }

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
	return 0;
}

void __connman_connection_gateway_remove(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	return;
}

/* EOD - end of dummies */

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

	if (service->state != CONNMAN_SERVICE_STATE_ONLINE &&
		service->state != CONNMAN_SERVICE_STATE_READY) {
		return;
	}
	
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

	if (type != CONNMAN_NETWORK_TYPE_UNKNOWN) {
		service->network = connman_network_create(ident, type);
		connman_network_set_index(service->network, ++index_counter);
	}

	if (service->type == CONNMAN_SERVICE_TYPE_VPN) {
		service->provider = connman_provider_get(ident);
		service->provider->vpn_service = service;
	}

	connman_service_create_ip4config(service, index_counter);
	connman_service_create_ip6config(service, index_counter);

	g_free(ident);
}

static void add_service_type(enum connman_service_type type,
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
			is_connected(service) ? "true" : "false",
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

	if (is_connected(a) && is_connected(b)) {
		if (a->type == CONNMAN_SERVICE_TYPE_VPN && is_connected(a))
			return true;

		if (b->type == CONNMAN_SERVICE_TYPE_VPN && is_connected(b))
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
			if(is_connected(a) && is_connected(b)) {
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
		if (is_connected(a)) {
			if (is_connected(b) || (is_connecting(b)))
				g_assert(a->state >= b->state);
			else
				g_assert(is_available(a) && !is_available(b));

			continue;
		}

		/* Non-conn. must not be on top of connected.*/
		g_assert_false(is_connected(b));

		/* configuration & association */
		if (is_connecting(a) && is_connecting(b)) {
			g_assert(a->state >= b->state);
			continue;
		}

		/* Connected or connecting should not be on top of
		 * not-connected or not connecting.
		 */
		g_assert_false(is_connecting(b));

		/*
		 * If both are not connected the state should be
		 * orderd.
		 */
		if (!is_connecting(a))
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
	service_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, NULL);
	ident_counter = index_counter = 0;
	phy_vpn_table = g_hash_table_new(g_direct_hash, g_direct_equal);
	g_assert(phy_vpn_table);
}

static void test_cleanup()
{
	g_hash_table_destroy(service_hash);
	g_hash_table_destroy(phy_vpn_table);
	clean_service_list();
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

	__connman_storage_init(test_dir, 0755, 0644);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(VPN_STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_cmpint(__connman_notifier_init(), ==, 0);
	g_assert_cmpint(__connman_ipconfig_init(), ==, 0);

	connection = (DBusConnection*)&ptr;
	dbus_path_data = g_hash_table_new(g_str_hash, g_str_equal);
	services_notify = g_new0(struct _services_notify, 1);
	services_notify->add = g_hash_table_new(g_str_hash, g_str_equal);

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

	ret = g_test_run();

	g_hash_table_destroy(services_notify->add);
	if (dbus_path_data)
		g_hash_table_destroy(dbus_path_data);

	__connman_notifier_cleanup();
	__connman_storage_cleanup();
	cleanup_test_directory(test_dir);
	g_free(test_dir);
	__connman_log_cleanup(FALSE);

	return ret;
}
