/*
 *  ConnMan blacklist monitor plugin unit tests
 *
 *  Copyright (C) 2022 Jolla Ltd. All rights reserved..
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

#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "plugin.h"

#include "src/connman.h"

#define SERVICES_MAX (20)

extern struct connman_plugin_desc __connman_builtin_blacklist_monitor;

struct connman_rtnl *rtnl;
struct connman_notifier *notifier;

struct connman_ipconfig {
	enum connman_ipconfig_type type;
	enum connman_ipconfig_method method;
};

struct connman_network {
	struct connman_ipconfig *ipconfig;
	int index;
	bool connected;
};

struct connman_service {
	struct connman_network *network;
};

static struct connman_service *services[SERVICES_MAX];

bool connman_device_isfiltered(const char *ifname)
{
	g_assert(ifname);
	return !strncmp(ifname, "filtered", 8);
}

struct inet_route {
	int index;
	char *host;
	char *gw;
	unsigned char prefix_len;
	short metric;
};

struct inet_route *new_inet_route(int index, const char *host, const char* gw,
					unsigned char prefix_len, short metric)
{
	struct inet_route *route;

	route = g_try_new0(struct inet_route, 1);
	if (!route)
		return NULL;

	route->index = index;
	route->host = g_strdup(host);
	route->gw = g_strdup(gw);
	route->prefix_len = prefix_len;
	route->metric = metric;

	return route;
}

void free_inet_route(gpointer data)
{
	struct inet_route *route = data;
	
	g_free(route->host);
	g_free(route->gw);
	g_free(route);
}

static GSList *inet_added_routes = NULL;

int connman_inet_add_ipv6_network_route_with_metric(int index, const char *host,
						const char *gateway,
						unsigned char prefix_len,
						short metric)
{
	struct inet_route *route = new_inet_route(index, host, gateway,
					prefix_len, metric);
	if (route)
		inet_added_routes = g_slist_prepend(inet_added_routes, route);

	return 0;
}

static GSList *inet_removed_routes = NULL;

int connman_inet_del_ipv6_network_route_with_metric(int index, const char *host,
						unsigned char prefix_len,
						short metric)
{
	struct inet_route *route = new_inet_route(index, host, NULL,
					prefix_len, metric);
	if (route)
		inet_removed_routes = g_slist_prepend(inet_removed_routes,
							route);
	
	return 0;
}

char *connman_inet_ifname(int index)
{
	if (index >= 0 && index < 10)
		return g_strdup("filtered");

	if (index >= 10 && index < SERVICES_MAX)
		return g_strdup("managed");

	return NULL;
}

bool connman_inet_is_any_addr(const char *dst, int family)
{
	g_assert_cmpint(family, ==, AF_INET6);
	return !g_strcmp0(dst, "::");
}

enum connman_ipconfig_type connman_ipconfig_get_config_type(
					struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return CONNMAN_IPCONFIG_TYPE_UNKNOWN;

	return ipconfig->type;
}

/* Network stubs */

bool connman_network_get_connected(struct connman_network *network)
{
	g_assert(network);
	return network->connected;;
}

int connman_network_get_index(struct connman_network *network)
{
	g_assert(network);
	return network->index;
}

bool connman_network_is_configured(struct connman_network *network,
						enum connman_ipconfig_type type)
{
	if (!network || !network->ipconfig)
		return false;

	return network->ipconfig->type == type;
}


/* Notifier stubs */ 

int connman_notifier_register(struct connman_notifier *n)
{
	notifier = n;
	g_assert(notifier);
	return 0;
}

void connman_notifier_unregister(struct connman_notifier *n)
{
	g_assert(n);

	if (notifier && !g_strcmp0(n->name, notifier->name))
		notifier = NULL;
}


/* Service stubs */

static struct connman_service *default_service = NULL;

struct connman_service *connman_service_get_default()
{
	return default_service;
}

enum connman_ipconfig_method connman_service_get_ipconfig_method(
						struct connman_service *service,
						enum connman_ipconfig_type type)
{
	if (service && service->network && service->network->ipconfig)
		return service->network->ipconfig->method;

	return CONNMAN_IPCONFIG_METHOD_UNKNOWN;
}

struct connman_network *connman_service_get_network(
						struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->network;
}

struct connman_service *connman_service_lookup_from_index(int index)
{
	int i;

	if (index > SERVICES_MAX)
		return NULL;

	for (i = 0; i <= SERVICES_MAX; i++) {
		if (services[i] && services[i]->network &&
					services[i]->network->index == index)
			return services[i];
	}

	return NULL;
}

/* rtnl stubs */

int connman_rtnl_register(struct connman_rtnl *r)
{
	rtnl = r;
	g_assert(rtnl);
	return 0;
}

void connman_rtnl_unregister(struct connman_rtnl *r)
{
	g_assert(r);

	if (rtnl && !g_strcmp0(r->name, rtnl->name))
		rtnl = NULL;
}

void connman_rtnl_handle_rtprot_ra(bool value)
{
	return;
}

static bool update_requested = false;

int connman_rtnl_request_route_update(int family)
{
	if (family == AF_INET6)
		update_requested = true;

	return 0;
}

/* EOF stubs */

static void create_data_structures()
{
	struct connman_service *service;
	struct connman_network *network;
	struct connman_ipconfig *ipconfig;
	int i;

	/* Filtered services IPv6*/
	for (i = 0; i < 6; i++) {
		service = g_try_new0(struct connman_service, 1);
		g_assert(service);

		network = g_try_new0(struct connman_network, 1);
		g_assert(network);

		ipconfig = g_try_new0(struct connman_ipconfig, 1);
		g_assert(ipconfig);

		ipconfig->type = CONNMAN_IPCONFIG_TYPE_IPV6;
		ipconfig->method = i; /* UNKNOWN ... AUTO */
		
		network->ipconfig = ipconfig;
		network->index = i;
		network->connected = (i > 1 ? true : false);
		
		service->network = network;
		services[i] = service;
	}

	/* Filtered services IPv4 */
	for (i = 6; i < 10; i++) {
		service = g_try_new0(struct connman_service, 1);
		g_assert(service);

		network = g_try_new0(struct connman_network, 1);
		g_assert(network);

		ipconfig = g_try_new0(struct connman_ipconfig, 1);
		g_assert(ipconfig);

		ipconfig->type = CONNMAN_IPCONFIG_TYPE_IPV4;
		ipconfig->method = i - 5; /* OFF ... DHCP */
		
		network->ipconfig = ipconfig;
		network->index = i;
		network->connected = ((i - 5) > 1 ? true : false);
		
		service->network = network;
		services[i] = service;
	}

	/* Managed services IPv6*/
	for (i = 10; i < 16; i++) {
		service = g_try_new0(struct connman_service, 1);
		g_assert(service);

		network = g_try_new0(struct connman_network, 1);
		g_assert(network);

		ipconfig = g_try_new0(struct connman_ipconfig, 1);
		g_assert(ipconfig);

		ipconfig->type = CONNMAN_IPCONFIG_TYPE_IPV6;
		ipconfig->method = i - 10; /* UNKNOWN ... AUTO */
		
		network->ipconfig = ipconfig;
		network->index = i;
		network->connected = ((i - 10) > 1 ? true : false);
		
		service->network = network;
		services[i] = service;
	}

	/* Managed services IPv4 */
	for (i = 16; i < SERVICES_MAX; i++) {
		service = g_try_new0(struct connman_service, 1);
		g_assert(service);

		network = g_try_new0(struct connman_network, 1);
		g_assert(network);

		ipconfig = g_try_new0(struct connman_ipconfig, 1);
		g_assert(ipconfig);

		ipconfig->type = CONNMAN_IPCONFIG_TYPE_IPV4;
		ipconfig->method = i - 15; /* OFF ... DHCP */
		
		network->ipconfig = ipconfig;
		network->index = i;
		network->connected = ((i - 15) > 1 ? true : false);
		
		service->network = network;
		services[i] = service;
	}
}

static void free_data_structures()
{
	int i;

	for (i = 0; i < SERVICES_MAX; i++) {
		if (services[i]) {
			if (services[i]->network) {
				if (services[i]->network->ipconfig)
					g_free(services[i]->network->ipconfig);

				g_free(services[i]->network);
			}
			g_free(services[i]);
		}
	}
}

static unsigned char current_rtm_protocol = RTPROT_RA;

static void set_rtm_prot(unsigned char rtm_protocol)
{
	current_rtm_protocol = rtm_protocol;
}

static void update_newgateway(int index, const char *dst, const char *gateway,
								int metric)
{
	g_assert(rtnl);
	g_assert(rtnl->newgateway6);
	rtnl->newgateway6(index, dst, gateway, metric, current_rtm_protocol);
	update_requested = false;
}

static void update_delgateway(int index, const char *dst, const char *gateway,
								int metric)
{
	g_assert(rtnl);
	g_assert(rtnl->delgateway6);
	rtnl->delgateway6(index, dst, gateway, metric, current_rtm_protocol);
}

static void change_default_service(struct connman_service *service)
{
	default_service = service;
	g_assert(notifier);
	g_assert(notifier->default_changed);
	notifier->default_changed(default_service);
}

static void change_service_state(int index, enum connman_service_state state)
{
	struct connman_service *service;

	service = connman_service_lookup_from_index(index);
	g_assert(service);

	g_assert(notifier);
	g_assert(notifier->service_state_changed);
	notifier->service_state_changed(service, state);
}

static void init_test()
{
	update_requested = false;
	set_rtm_prot(RTPROT_RA);
}

static void clear_test()
{
	g_slist_free_full(inet_added_routes, free_inet_route);
	inet_added_routes = NULL;

	g_slist_free_full(inet_removed_routes, free_inet_route);
	inet_removed_routes = NULL;

	default_service = NULL;
	notifier = NULL;
	rtnl = NULL;
}

/* No default service, add and remove */
static void blacklist_monitor_plugin_test1()
{
	int i;
	int j;

	init_test();

	g_assert(__connman_builtin_blacklist_monitor.init() == 0);

	g_assert(notifier);
	g_assert(rtnl);
	g_assert_true(update_requested);

	/* Add and remove */
	for (i = 0; i < SERVICES_MAX; i++) {
		for (j = RTPROT_UNSPEC; j <= RTPROT_STATIC; j++) {
			set_rtm_prot(j);
			update_newgateway(i, "::", "fe80::dead:beef", 1024 - i);
			update_delgateway(i, "::", "fe80::dead:beef", 1024 - i);
		}

		set_rtm_prot(RTPROT_RA);
		update_newgateway(i, "::", "fe80::dead:beef", 1024 - i);
		update_delgateway(i, "::", "fe80::dead:beef", 1024 - i);
	}

	g_assert_null(inet_added_routes);
	g_assert_null(inet_removed_routes);

	/* Add non-default and remove non-existing */
	for (i = 0; i < SERVICES_MAX; i++) {
		for (j = RTPROT_UNSPEC; j <= RTPROT_STATIC; j++) {
			set_rtm_prot(j);
			update_newgateway(i, "feed::abba::beef",
						"fe80::dead:beef", 1024 - i);
			update_delgateway(i, "::", "fe80::dead:beef",
						1024 - i);
		}

		set_rtm_prot(RTPROT_RA);
		update_newgateway(i, "feed::abba::beef", "fe80::dead:beef",
								1024 - i);
			update_delgateway(i, "::", "fe80::dead:beef",
								1024 - i);
	}

	g_assert_null(inet_added_routes);
	g_assert_null(inet_removed_routes);

	__connman_builtin_blacklist_monitor.exit();
	g_assert_null(notifier);
	g_assert_null(rtnl);

	clear_test();
}

/* Blacklisted default service add/remove */
static void blacklist_monitor_plugin_test2()
{
	int i;

	init_test();

	g_assert(__connman_builtin_blacklist_monitor.init() == 0);

	g_assert(notifier);
	g_assert(rtnl);
	g_assert_true(update_requested);

	default_service = services[5]; // Connected IPv6 AUTO method filtered

	/* Add and remove with default service set*/
	for (i = 0; i < SERVICES_MAX; i++) {
		update_newgateway(i, "::", "fe80::dead:beef", 1024 - i);
		update_delgateway(i, "::", "fe80::dead:beef", 1024 - i);
	}

	g_assert_null(inet_added_routes);
	/* All blacklisted interface routes except one that is default now */
	g_assert_cmpint(g_slist_length(inet_removed_routes), ==, 9);

	__connman_builtin_blacklist_monitor.exit();
	g_assert_null(notifier);
	g_assert_null(rtnl);

	clear_test();
}

/* Managed default service add/remove */
static void blacklist_monitor_plugin_test3()
{
	int i;

	init_test();

	g_assert(__connman_builtin_blacklist_monitor.init() == 0);

	g_assert(notifier);
	g_assert(rtnl);
	g_assert_true(update_requested);

	default_service = services[15]; // Connected IPv6 AUTO method managed

	/* Add with default service set*/
	for (i = 0; i < SERVICES_MAX; i++) {
		update_newgateway(i, "::", "fe80::dead:beef", 1024 - i);
		update_delgateway(i, "::", "fe80::dead:beef", 1024 - i);
	}

	g_assert_null(inet_added_routes);
	/* All blacklisted interface routes */
	g_assert_cmpint(g_slist_length(inet_removed_routes), ==, 10);

	__connman_builtin_blacklist_monitor.exit();
	g_assert_null(notifier);
	g_assert_null(rtnl);

	clear_test();
}

/* Blacklisted default service add/remove with different protocol types */
static void blacklist_monitor_plugin_test4()
{
	int i;
	int j;

	init_test();

	g_assert(__connman_builtin_blacklist_monitor.init() == 0);

	g_assert(notifier);
	g_assert(rtnl);
	g_assert_true(update_requested);

	default_service = services[5]; // Connected IPv6 AUTO method filtered

	/* Add and remove with default service set*/
	for (i = 0; i < SERVICES_MAX; i++) {
		/* Run through all the RTPROT_ types (not all have defines) */
		for (j = RTPROT_UNSPEC; j <= RTPROT_MROUTED; j++) {
			set_rtm_prot(j);
			update_newgateway(i, "::", "fe80::dead:beef",
								1024 - i - j);
			update_delgateway(i, "::", "fe80::dead:beef",
								1024 - i - j);
		}
	}

	g_assert_null(inet_added_routes);
	/* All blacklisted interface routes except one that is default now */
	g_assert_cmpint(g_slist_length(inet_removed_routes), ==, 27);

	__connman_builtin_blacklist_monitor.exit();
	g_assert_null(notifier);
	g_assert_null(rtnl);

	clear_test();
}

/* Blacklisted default service changes to managed and back */
static void blacklist_monitor_plugin_test_defchange1()
{
	int i;

	init_test();

	g_assert(__connman_builtin_blacklist_monitor.init() == 0);

	g_assert(notifier);
	g_assert(rtnl);
	g_assert_true(update_requested);

	default_service = services[5]; // Connected IPv6 AUTO method filtered

	/* Add and remove with default service set*/
	for (i = 0; i < SERVICES_MAX; i++)
		update_newgateway(i, "::", "fe80::dead:beef", 1024 - i);

	/* Changing to NULL does not indicate new update */
	change_default_service(NULL);
	g_assert_false(update_requested);
	update_newgateway(15, "::", "feed::dead::abba", 1000);

	// Connected IPv6 AUTO method managed, updates previous route
	change_default_service(services[15]);
	g_assert_true(update_requested);
	update_newgateway(15, "::", "feed::dead::baad", 1000);

	change_default_service(services[5]);
	g_assert_true(update_requested);

	for (i = 0; i < SERVICES_MAX; i++)
		update_delgateway(i, "::", "fe80::dead:beef", 1024 - i);

	g_assert_null(inet_added_routes);
	/* All blacklisted interface routes except one that was as  default. */
	g_assert_cmpint(g_slist_length(inet_removed_routes), ==, 9);

	__connman_builtin_blacklist_monitor.exit();
	g_assert_null(notifier);
	g_assert_null(rtnl);


	clear_test();
}

/* Managed default service changes to blacklist and back */
static void blacklist_monitor_plugin_test_defchange2()
{
	int i;

	init_test();

	g_assert(__connman_builtin_blacklist_monitor.init() == 0);

	g_assert(notifier);
	g_assert(rtnl);
	g_assert_true(update_requested);

	default_service = services[15]; // Connected IPv6 AUTO method managed

	/* Add with default service set*/
	for (i = 0; i < SERVICES_MAX; i++)
		update_newgateway(i, "::", "fe80::dead:beef", 1024 - i);

	change_default_service(services[5]);
	update_newgateway(5, "::", "feed::dead::abdc", 1001);

	change_default_service(services[15]);

	/* Add with default service set*/
	for (i = 0; i < SERVICES_MAX; i++)
		update_delgateway(i, "::", "fe80::dead:beef", 1024 - i);

	g_assert_null(inet_added_routes);
	/* All blacklisted interface routes */
	g_assert_cmpint(g_slist_length(inet_removed_routes), ==, 10);

	__connman_builtin_blacklist_monitor.exit();
	g_assert_null(notifier);
	g_assert_null(rtnl);

	clear_test();
}

/*
 * Filtered manual/fixed as default, change to managed -> requests update ->
 * update gives routes for both, filtered goes to restore list ->
 * managed are ignored -> change to same filtered->
 * inet function is called to add the route.
 */

static void blacklist_monitor_plugin_test_process1()
{
	init_test();

	g_assert(__connman_builtin_blacklist_monitor.init() == 0);

	change_default_service(services[3]);
	g_assert_true(update_requested);

	/* Add few gateways that are ignored */
	update_newgateway(3, "::", "beef::0000::dead", 1024);
	update_newgateway(3, "::", "feed::0000::dead", 1023);

	/* Ignored and not called to be added/removed */
	g_assert_null(inet_added_routes);
	g_assert_null(inet_removed_routes);

	/* Managed auto */
	change_default_service(services[15]);
	g_assert_true(update_requested);

	/* These are deleted and saved */
	update_newgateway(3, "::", "beef::0000::dead", 1024);
	update_newgateway(3, "::", "feed::0000::dead", 1023);

	/* These are ignored */
	update_newgateway(15, "::", "beef::0000::deed", 1024);
	update_newgateway(15, "::", "feed::0000::deed", 1023);

	/* Routes from index 3 are deleted */
	g_assert_null(inet_added_routes);
	g_assert_cmpint(g_slist_length(inet_removed_routes), ==, 2);

	change_default_service(services[3]);
	g_assert_true(update_requested);

	/* Restore list is used to add the saved routes */
	g_assert_cmpint(g_slist_length(inet_added_routes), ==, 2);
	g_assert_cmpint(g_slist_length(inet_removed_routes), ==, 2);

	__connman_builtin_blacklist_monitor.exit();
	g_assert_null(notifier);
	g_assert_null(rtnl);

	clear_test();
}

/*
 * Same as before but filtered service disappears and when re-appears no
 * routes are added.
 */
static void blacklist_monitor_plugin_test_process2()
{
	init_test();

	g_assert(__connman_builtin_blacklist_monitor.init() == 0);

	change_default_service(services[3]);
	g_assert_true(update_requested);

	/* Add few gateways that are ignored */
	update_newgateway(3, "::", "beef::0000::dead", 1024);
	update_newgateway(3, "::", "feed::0000::dead", 1023);

	/* Ignored and not called to be added/removed */
	g_assert_null(inet_added_routes);
	g_assert_null(inet_removed_routes);

	/* Managed auto */
	change_default_service(services[15]);
	g_assert_true(update_requested);

	/* These are deleted and saved */
	update_newgateway(3, "::", "beef::0000::dead", 1024);
	update_newgateway(3, "::", "feed::0000::dead", 1023);

	/* These are ignored */
	update_newgateway(15, "::", "beef::0000::deed", 1024);
	update_newgateway(15, "::", "feed::0000::deed", 1023);

	/* Routes from index 3 are deleted */
	g_assert_null(inet_added_routes);
	g_assert_cmpint(g_slist_length(inet_removed_routes), ==, 2);

	/* Index 3 goes idle and its routes are removed from restore list */
	change_service_state(3, CONNMAN_SERVICE_STATE_DISCONNECT);
	change_service_state(3, CONNMAN_SERVICE_STATE_IDLE);

	change_default_service(services[3]);
	g_assert_true(update_requested);

	/* Restore list is used to add the saved routes */
	g_assert_null(inet_added_routes);
	g_assert_cmpint(g_slist_length(inet_removed_routes), ==, 2);

	__connman_builtin_blacklist_monitor.exit();
	g_assert_null(notifier);
	g_assert_null(rtnl);

	clear_test();
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

#define TEST_PREFIX "/blacklist_monitor/"


int main (int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	int err;

	g_test_init(&argc, &argv, NULL);

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		return 1;
	}

	g_option_context_free(context);

	__connman_log_init(argv[0], option_debug, false, false,
			"Unit Tests Connection Manager", VERSION);

	create_data_structures();

	g_test_add_func(TEST_PREFIX "test1", blacklist_monitor_plugin_test1);
	g_test_add_func(TEST_PREFIX "test2", blacklist_monitor_plugin_test2);
	g_test_add_func(TEST_PREFIX "test3", blacklist_monitor_plugin_test3);
	g_test_add_func(TEST_PREFIX "test4", blacklist_monitor_plugin_test4);

	g_test_add_func(TEST_PREFIX "test_default_change1",
				blacklist_monitor_plugin_test_defchange1);
	g_test_add_func(TEST_PREFIX "test_default_change2",
				blacklist_monitor_plugin_test_defchange2);

	g_test_add_func(TEST_PREFIX "test_process1",
				blacklist_monitor_plugin_test_process1);
	g_test_add_func(TEST_PREFIX "test_process2",
				blacklist_monitor_plugin_test_process2);

	err = g_test_run();

	free_data_structures();
	return err;
}
