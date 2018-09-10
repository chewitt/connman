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

#include "src/service.c"

unsigned int *preferred_list = NULL;

/* Dummies */
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
const char *connman_option_get_string(const char *key) { return NULL; }
const char *__connman_tethering_get_bridge(void) { return NULL; }
void __connman_tethering_set_disabled(void) { return; }
void __connman_tethering_set_enabled(void) { return; }
int __connman_private_network_release(const char *path) { return 0; }
int __connman_private_network_request(DBusMessage *msg, const char *owner)
{
	return 0;
}

void dbus_connection_unref(DBusConnection *connection) { return; }

struct connman_provider {
	int refcount;
	bool immutable;
	struct connman_service *vpn_service;
	int index;
	char *identifier;
	int family;
	struct connman_provider_driver *driver;
	void *driver_data;
};

int connman_provider_get_index(struct connman_provider *provider) { return -1; }
int __connman_provider_create_and_connect(DBusMessage *msg) { return 0; }
int connman_provider_disconnect(struct connman_provider *provider) { return 0; }
void connman_provider_unref_debug(struct connman_provider *provider,
	const char *file, int line, const char *caller) { return; }
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

void __connman_provider_append_properties(struct connman_provider *provider,
							DBusMessageIter *iter)
{
	return;
}

static struct connman_provider *provider_new(void)
{
	struct connman_provider *provider;

	provider = g_try_new0(struct connman_provider, 1);
	if (!provider)
		return NULL;

	provider->index = 0;
	provider->identifier = NULL;

	return provider;
}

struct connman_provider *connman_provider_get(const char *identifier)
{
	struct connman_provider *provider;

	provider = provider_new();
	if (!provider)
		return NULL;

	DBG("provider %p", provider);

	provider->identifier = g_strdup(identifier);

	return provider;
}

GList *non_default_providers = NULL;
const char *false_string = "false";

int connman_provider_set_string(struct connman_provider *provider,
					const char *key, const char *value)
{
	if (g_str_equal("DefaultRoute", key) &&
		g_str_equal("false", value)) {
		non_default_providers = g_list_append(non_default_providers,
						provider);
	}

	return 0;
}

const char *connman_provider_get_string(struct connman_provider *provider,
					const char *key)
{
	GList *iter = NULL;
	struct connman_provider *found = NULL;

	for (iter = non_default_providers ; iter ; iter = iter->next) {
		found = iter->data;

		if (found == provider)
			return false_string;
	}

	return NULL;
}

bool __connman_provider_is_default_route(struct connman_provider *provider)
{
	return connman_provider_get_string(provider, NULL) ? false : true;
}

/* EOD - end of dummies */

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
	gchar *random_string = g_uuid_string_random();

	if (type > CONNMAN_SERVICE_TYPE_P2P)
		pos = 0;
	else
		pos = (int)type;

	ident = g_strdup_printf("%s_%s_%s", prefix[pos], random_string,
		postfix[pos]);

	g_free(random_string);

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

	if (type != CONNMAN_NETWORK_TYPE_UNKNOWN)
		service->network = connman_network_create(ident, type);

	if (service->type == CONNMAN_SERVICE_TYPE_VPN)
		service->provider = connman_provider_get(ident);

	g_free(ident);
}

static void add_service_type(enum connman_service_type type,
	enum connman_service_state state, bool default_route,
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
		if (state == CONNMAN_SERVICE_STATE_READY) {
			service->depends_on =
				get_connected_default_route_service();
		}
		service->order = 10;
	
		if (!default_route && service->provider) {
			connman_provider_set_string(service->provider,
				"DefaultRoute", "false");
		}
	}
	
	service_list = g_list_insert_sorted(service_list, service,
		service_compare);
	
	g_free(ident);
}

static void add_services()
{
	enum connman_service_state state = 1;
	enum connman_service_type type = 1;
	uint8_t strength = 0;

	for (type = 1; type <= CONNMAN_SERVICE_TYPE_P2P; type++) {
		for (state = 1; state <= CONNMAN_SERVICE_STATE_FAILURE; state++) {

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

			add_service_type(type, state, true, strength);
		}
	}
}

static void print_test_service(struct connman_service *service, void *user_data)
{
	if (!service)
		return;

	printf("%p %-56s %-3d %-6s %-10s %-16s %-12s %u\n",
		service,
		service->identifier,
		service->order,
		is_connected(service) ? "true" : "false",
		is_available(service) ? "available" : "non-avail",
		state2string(service->state),
		__connman_service_is_default_route(service) ?
			"default" : "non-default",
		service->strength);
}

static void print_services()
{
	static struct connman_debug_desc debug_desc CONNMAN_DEBUG_ATTR = {
		.file = __FILE__,
		.flags = CONNMAN_DEBUG_FLAG_PRINT
	};

	if (debug_desc.flags && CONNMAN_DEBUG_FLAG_PRINT) {
		__connman_service_foreach(print_test_service, NULL);
	}
}


static bool check_preferred_type_order(struct connman_service *a,
	struct connman_service *b)
{
	// TODO use order in preferred list
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

static void test_service_sort_full_positive()
{
	GList *iter = NULL, *iter_next = NULL;
	struct connman_service *a = NULL, *b = NULL;

	add_services();

	add_service_type(CONNMAN_SERVICE_TYPE_VPN, CONNMAN_SERVICE_STATE_READY,
		false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_STATE_ONLINE, true, 60);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_STATE_ONLINE, true, 85);

	service_list = g_list_sort(service_list, service_compare);

	print_services();

	for (iter = service_list ; iter ; iter = iter->next) {
		iter_next = iter->next;

		/* iter is the last item */
		if (!iter_next)
			continue;

		a = iter->data;
		b = iter_next->data;

		/* For debugging */
		DBG("T: %s vs. %s", a->identifier, b->identifier);

		if (a->type == CONNMAN_SERVICE_TYPE_VPN &&
			a->state == CONNMAN_SERVICE_STATE_READY) {

			/* VPN as default should be on top */
			if (__connman_service_is_default_route(a))
				g_assert(a == service_list->data);
			else
				g_assert(a != service_list->data);

			/*
			 * State of the transport service of VPN has to be
			 * equal or greater than the service below
			 */
			if(a->depends_on)
				g_assert(a->depends_on->state >= b->state);

		} else if (b->type == CONNMAN_SERVICE_TYPE_VPN &&
			b->state == CONNMAN_SERVICE_STATE_READY) {

			g_assert(a->state >= b->state);

		} else {
			if (a->type != b->type) {
				if (a->state == b->state) {
					g_assert(a->order >= b->order);
					g_assert(check_type_order(a,b));
				} else {
					/*
					 * TODO: some items are not sorted
					 * properly, this will fail with gps
					 * in configuration state put too low
					 */
					//g_assert(a->state >= b->state);
				}
			} else {
				/* For Wifi, check strength */
				if (a->type == CONNMAN_SERVICE_TYPE_WIFI &&
					b->type == CONNMAN_SERVICE_TYPE_WIFI)
					g_assert(a->strength >= b->strength);

				g_assert(a->state >= b->state);
			}
		}
	}

	g_list_free(service_list);
	service_list = NULL;
}

void test_service_sort_with_preferred_list()
{
	unsigned int list[] = {
		CONNMAN_SERVICE_TYPE_BLUETOOTH,
		CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_TYPE_CELLULAR,
		CONNMAN_SERVICE_TYPE_UNKNOWN,
	};
	GList *iter = NULL, *iter_next = NULL;
	struct connman_service *a = NULL, *b = NULL;
	
	if (preferred_list)
		g_free(preferred_list);
	
	preferred_list = list;

	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_STATE_ONLINE, true, 85);

	add_service_type(CONNMAN_SERVICE_TYPE_VPN, CONNMAN_SERVICE_STATE_READY,
		false, 0);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_STATE_READY, true, 60);
	add_service_type(CONNMAN_SERVICE_TYPE_WIFI,
		CONNMAN_SERVICE_STATE_IDLE, true, 0);

	service_list = g_list_sort(service_list, service_compare);

	print_services();
	
	for (iter = service_list ; iter ; iter = iter->next) {
		iter_next = iter->next;

		/* iter is the last item */
		if (!iter_next)
			continue;

		a = iter->data;
		b = iter_next->data;
		
		if (a->state == b->state) {
			g_assert(check_preferred_type_order(a,b));
		} else {
			g_assert(check_preferred_type_order(a,b));
		}
	}
}

/* TODO */
void test_service_sort_without_preferred_list()
{
	return;
}

/* TODO */
void test_service_sort_vpn_default()
{
	return;
}

/* TODO */
void test_service_sort_vpn_non_default()
{
	return;
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/service/service_sort_full_positive",
		test_service_sort_full_positive);
	g_test_add_func("/service/service_sort_with_preferred",
		test_service_sort_with_preferred_list);
	g_test_add_func("/service/service_sort_without_preferred",
		test_service_sort_without_preferred_list);
	g_test_add_func("/service/service_sort_vpn_default",
		test_service_sort_vpn_default);
	g_test_add_func("/service/service_sort_vpn_non_default",
		test_service_sort_vpn_non_default);

	return g_test_run();
}
