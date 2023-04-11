/*
 *  ConnMan device unit tests
 *
 *  Copyright (C) 2019 Jolla Ltd. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "plugin.h"

#include "src/connman.h"

extern struct connman_plugin_desc __connman_builtin_ethernet;

// network dummies
struct connman_service *connman_service_lookup_from_network(
			struct connman_network *network)
{
	return NULL;
}

bool connman_network_get_connected(struct connman_network *network)
{
	return true;
}

int connman_network_set_connected(struct connman_network *network, bool on)
{
	return 0;
}

bool connman_network_get_connecting(struct connman_network *network)
{
	return true;
}

int connman_network_set_available(struct connman_network *network, bool on)
{
	return 0;
}

bool connman_network_get_available(struct connman_network *network)
{
	return true;
}

const char *connman_network_get_identifier(struct connman_network *network)
{
	return NULL;
}

void __connman_network_set_device(struct connman_network *network,
			struct connman_device *device)
{
	return;
}

const char *connman_network_get_string(struct connman_network *network,
				const char *string)
{
	return NULL;
}

int __connman_network_disconnect(struct connman_network *network)
{
	return 0;
}

/**
 * connman_network_ref:
 * @network: network structure
 *
 * Increase reference counter of  network
 */
struct connman_network *
connman_network_ref_debug(struct connman_network *network,
			const char *file, int line, const char *caller)
{
	/*DBG("%p name %s ref %d by %s:%d:%s()", network, network->name,
		network->refcount + 1, file, line, caller);*/

	/*__sync_fetch_and_add(&network->refcount, 1);*/

	return network;
}

/**
 * connman_network_unref:
 * @network: network structure
 *
 * Decrease reference counter of network
 */
void connman_network_unref_debug(struct connman_network *network,
				const char *file, int line, const char *caller)
{
	/*DBG("%p name %s ref %d by %s:%d:%s()", network, network->name,
		network->refcount - 1, file, line, caller);

	if (__sync_fetch_and_sub(&network->refcount, 1) != 1)
		return;

	network_list = g_slist_remove(network_list, network);

	network_destruct(network);*/
}

int connman_network_driver_register(struct connman_network_driver *driver)
{
	return 0;
}

void connman_network_driver_unregister(struct connman_network_driver *driver)
{
	return;
}

void connman_network_set_index(struct connman_network *network, int index)
{
	return;
}

int connman_network_set_name(struct connman_network *network, const char *name)
{
	return 0;
}

void connman_network_set_group(struct connman_network *network,
						const char *group)
{
	return;
}

struct connman_network *connman_network_create(const char *identifier,
						enum connman_network_type type)
{
	return NULL;
}

// service dummies
int __connman_service_disconnect(struct connman_service *service)
{
	return 0;
}

void __connman_service_auto_connect(enum connman_service_connect_reason r)
{
	return;
}

// tech dummies
int __connman_technology_add_device(struct connman_device *device)
{
	return 0;
}

int __connman_technology_remove_device(struct connman_device *device)
{
	return 0;
}

int __connman_technology_disabled(enum connman_service_type type)
{
	return 0;
}

void __connman_technology_scan_started(struct connman_device *device)
{
	return;
}

void __connman_technology_scan_stopped(struct connman_device *device,
			enum connman_service_type type)
{
	return;
}

void __connman_technology_notify_regdom_by_device(struct connman_device *device,
					int result, const char *alpha2)
{
	return;
}

struct connman_technology_driver *eth_tech_driver = NULL;

int connman_technology_driver_register(struct connman_technology_driver *driver)
{
	g_assert(driver);
	g_assert(driver->name);
	g_assert(!g_strcmp0(driver->name, "ethernet"));

	eth_tech_driver = driver;

	return 0;
}

void connman_technology_driver_unregister(
				struct connman_technology_driver *driver)
{
	g_assert(driver);
	g_assert(driver->name);
	g_assert(!g_strcmp0(driver->name, "ethernet"));

	eth_tech_driver = NULL;
}

bool connman_technology_is_tethering_allowed(enum connman_service_type type)
{
	return type == CONNMAN_SERVICE_TYPE_ETHERNET ? true : false;
}

void connman_technology_tethering_notify(struct connman_technology *technology,
							bool enabled)
{
	return;
}

int __connman_technology_enabled(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return 0;
	default:
		return -1;
	}
}

const char *__connman_technology_get_regdom(enum connman_service_type type)
{
	return NULL;
}

// rtnl dummies

static unsigned int watch_id = 42;

unsigned int connman_rtnl_add_newlink_watch(int index,
			connman_rtnl_link_cb_t callback, void *user_data)
{
	return watch_id;
}

void connman_rtnl_remove_watch(unsigned int id)
{
	g_assert_cmpint(id, ==, watch_id);
}

enum connman_device_type __connman_rtnl_get_device_type(int index)
{
	return CONNMAN_DEVICE_TYPE_UNKNOWN;
}

// inet dummies

#define DEVICE_UNKNOWN_INDEX 100
#define DEVICE_UNKNOWN_IFNAME "rndis0"
#define DEVICE_ETHERNET_INDEX 101
#define DEVICE_ETHERNET_IFNAME "eth0"

char *connman_inet_ifname(int index)
{
	return NULL;
}

int connman_inet_ifindex(const char *ifname)
{
	if (!g_strcmp0(ifname, DEVICE_UNKNOWN_IFNAME))
		return DEVICE_UNKNOWN_INDEX;

	if (!g_strcmp0(ifname, DEVICE_ETHERNET_IFNAME))
		return DEVICE_ETHERNET_INDEX;

	return -1;
}

int __connman_inet_get_address_netmask(int ifindex,
					struct sockaddr_in *address,
					struct sockaddr_in *netmask)
{
	return 0;
}

static bool allow_ifdown = true;
static int interfaces[2] = { -1, -1};

int connman_inet_ifup(int index)
{
	/* Also device.c connman_device_enable() calls this */
	switch (index) {
	case DEVICE_UNKNOWN_INDEX:
	case DEVICE_ETHERNET_INDEX:
		interfaces[0] = index;
		return 0;
	default:
		return -EINVAL;
	}
}

int connman_inet_ifdown(int index)
{
	/*
	 * If set to anything else than true then interface down operations
	 * are not allowed.
	 */
	g_assert_true(allow_ifdown);
	interfaces[1] = index;

	return 0;
}

int connman_inet_add_to_bridge(int index, const char *bridge)
{
	return 0;
}

int connman_inet_remove_from_bridge(int index, const char *bridge)
{
	return 0;
}

char **__connman_inet_get_running_interfaces(void)
{
	return NULL;
}

// setting dummies
char **connman_setting_get_string_list(const char *string)
{
	return NULL;
}

// config dummies
bool __connman_config_address_provisioned(const char *address,
					const char *netmask)
{
	return TRUE;
}

enum notify_type {
	NOTIFY_TYPE_UNSET = 0,
	NOTIFY_TYPE_STATUS,
	NOTIFY_TYPE_MANAGED
};

static enum notify_type notify = NOTIFY_TYPE_UNSET;

// notifier dummies

struct connman_notifier* ethernet_notifier = NULL;

int connman_notifier_register(struct connman_notifier *notifier)
{
	g_assert(!g_strcmp0(notifier->name, "ethernet_plugin"));
	ethernet_notifier = notifier;
	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
	g_assert(!g_strcmp0(notifier->name, "ethernet_plugin"));
	ethernet_notifier = NULL;
}

void __connman_notifier_device_status_changed(struct connman_device *device,
								bool on)
{
	DBG("device %p on:%d", device, on);

	if (!connman_device_has_status_changed_to(device, on)) {
		DBG("no status change, managed notify");
		notify = NOTIFY_TYPE_MANAGED;
	} else {
		DBG("status change");
		notify = NOTIFY_TYPE_STATUS;
	}

	if (ethernet_notifier) {
		g_assert(ethernet_notifier->device_status_changed);
		ethernet_notifier->device_status_changed(device, on);
	}
}

void reset_notify()
{
	notify = NOTIFY_TYPE_UNSET;
}

void reset_test()
{
	reset_notify();
	allow_ifdown = true;
	interfaces[0] = interfaces[1] = -1;
	ethernet_notifier = NULL;
	eth_tech_driver = NULL;
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

/* Basic test to check notifications, toggle managed and on/off status */
static void device_notify_test0()
{
	struct connman_device *device;

	reset_test();

	device = connman_device_create("test1", CONNMAN_DEVICE_TYPE_UNKNOWN);
	connman_device_set_index(device, DEVICE_UNKNOWN_INDEX);
	connman_device_set_interface(device, DEVICE_UNKNOWN_IFNAME);

	/* No notify if in unset status and managed changes */
	connman_device_set_managed(device, false);
	g_assert_false(connman_device_get_managed(device));
	g_assert(notify == NOTIFY_TYPE_UNSET);

	/* Status notify */
	connman_device_status_notify(device, true);
	g_assert(notify == NOTIFY_TYPE_STATUS);
	g_assert_false(connman_device_get_managed(device));

	/* Notify managed status */
	connman_device_set_managed(device, true);
	g_assert(notify == NOTIFY_TYPE_MANAGED);
	g_assert_true(connman_device_get_managed(device));

	/* Notify off */
	connman_device_status_notify(device, false);
	g_assert(notify == NOTIFY_TYPE_STATUS);

	connman_device_unref(device);
}

/* Test double notifications - they should be blocked */
static void device_notify_test1()
{
	struct connman_device *device;

	reset_test();

	device = connman_device_create("test1", CONNMAN_DEVICE_TYPE_UNKNOWN);
	connman_device_set_index(device, DEVICE_UNKNOWN_INDEX);
	connman_device_set_interface(device, DEVICE_UNKNOWN_IFNAME);

	/* Status notify */
	connman_device_status_notify(device, true);
	g_assert(notify == NOTIFY_TYPE_STATUS);
	reset_notify();

	/* Second does not send notify */
	connman_device_status_notify(device, true);
	g_assert(notify == NOTIFY_TYPE_UNSET);

	/* Notifying same managed status creates no notify */
	connman_device_set_managed(device, true);
	g_assert(notify == NOTIFY_TYPE_UNSET);
	g_assert_true(connman_device_get_managed(device));

	/* Notify off */
	connman_device_status_notify(device, false);
	g_assert(notify == NOTIFY_TYPE_STATUS);
	reset_notify();

	/* Notify on to check status */
	connman_device_status_notify(device, true);
	g_assert(notify == NOTIFY_TYPE_STATUS);

	connman_device_unref(device);
}

/*
 * Register a device to use ethernet plugin, add its interface to get index into
 * the plugins' list, set device to managed and enable it -> ethernet plugin
 * should not call ifdown for a non-managed device.
 */
void device_test_ethernet_plugin0()
{
	struct connman_device *device;

	reset_test();

	g_assert(__connman_builtin_ethernet.init() == 0);

	device = connman_device_create("eth1", CONNMAN_DEVICE_TYPE_ETHERNET);
	connman_device_set_index(device, DEVICE_ETHERNET_INDEX);
	connman_device_set_interface(device, DEVICE_ETHERNET_IFNAME);
	g_assert(connman_device_register(device) == 0);

	/* Add a new interface */
	g_assert(eth_tech_driver);
	g_assert(eth_tech_driver->add_interface);

	/* Ethernet plugin does not utilize struct connman_technology */
	eth_tech_driver->add_interface(NULL, DEVICE_ETHERNET_INDEX,
				DEVICE_ETHERNET_IFNAME, "eth1");

	/* Notify that this is not managed */
	connman_device_set_managed(device, false);
	g_assert(notify == NOTIFY_TYPE_UNSET);

	/* Set non-managed device on */
	connman_device_status_notify(device, true);
	g_assert(notify == NOTIFY_TYPE_STATUS);
	allow_ifdown = false;

	/* Another on and managed notify, no reaction */
	connman_device_status_notify(device, true);
	connman_device_set_managed(device, false);

	/* Enable device */
	__connman_device_enable(device);
	g_assert_cmpint(interfaces[0], ==, DEVICE_ETHERNET_INDEX);

	/* Disable device, ethernet plugin should not try to set it down */
	__connman_device_disable(device);
	connman_device_unregister(device);
	g_assert_cmpint(interfaces[1], ==, -1);

	__connman_builtin_ethernet.exit();

	connman_device_unref(device);
}

/*
 * Register a device to use ethernet plugin, add its interface to get index into
 * the plugins' list, set device to managed and enable it then disable it ->
 * ethernet plugin should not call ifdown for a non-managed device.
 */
void device_test_ethernet_plugin1()
{
	struct connman_device *device;

	reset_test();

	g_assert(__connman_builtin_ethernet.init() == 0);

	device = connman_device_create("eth1", CONNMAN_DEVICE_TYPE_ETHERNET);
	connman_device_set_index(device, DEVICE_ETHERNET_INDEX);
	connman_device_set_interface(device, DEVICE_ETHERNET_IFNAME);
	g_assert(connman_device_register(device) == 0);

	/* Add a new interface */
	g_assert(eth_tech_driver);
	g_assert(eth_tech_driver->add_interface);

	/* Ethernet plugin does not utilize struct connman_technology */
	eth_tech_driver->add_interface(NULL, DEVICE_ETHERNET_INDEX,
				DEVICE_ETHERNET_IFNAME, "eth1");

	/* Enable device */
	__connman_device_enable(device);
	g_assert_cmpint(interfaces[0], ==, DEVICE_ETHERNET_INDEX);

	/* Notify that this is not managed */
	connman_device_set_managed(device, false);
	g_assert(notify == NOTIFY_TYPE_UNSET);

	/* Set non-managed device on */
	connman_device_status_notify(device, true);
	g_assert(notify == NOTIFY_TYPE_STATUS);
	allow_ifdown = false;

	/* Set non-managed device off */
	connman_device_status_notify(device, false);
	g_assert(notify == NOTIFY_TYPE_STATUS);
	g_assert_cmpint(interfaces[1], ==, -1);
	allow_ifdown = true;

	/* Disable device, ethernet plugin should be able to set it down */
	__connman_device_disable(device);
	connman_device_unregister(device);
	g_assert_cmpint(interfaces[1], ==, DEVICE_ETHERNET_INDEX);

	__connman_builtin_ethernet.exit();

	connman_device_unref(device);
}

/*
 * Register a device to use ethernet plugin, add its interface to get index into
 * the plugins' list, set device to managed and enable it and set the device
 * back to managed to allow ethernet plugin to set it down.
 */
void device_test_ethernet_plugin2()
{
	struct connman_device *device;

	reset_test();

	g_assert(__connman_builtin_ethernet.init() == 0);

	device = connman_device_create("eth1", CONNMAN_DEVICE_TYPE_ETHERNET);
	connman_device_set_index(device, DEVICE_ETHERNET_INDEX);
	connman_device_set_interface(device, DEVICE_ETHERNET_IFNAME);
	g_assert(connman_device_register(device) == 0);

	/* Add a new interface */
	g_assert(eth_tech_driver);
	g_assert(eth_tech_driver->add_interface);

	/* Ethernet plugin does not utilize struct connman_technology */
	eth_tech_driver->add_interface(NULL, DEVICE_ETHERNET_INDEX,
				DEVICE_ETHERNET_IFNAME, "eth1");

	/* Enable device */
	__connman_device_enable(device);
	g_assert_cmpint(interfaces[0], ==, DEVICE_ETHERNET_INDEX);

	/* Notify that this is not managed */
	connman_device_set_managed(device, false);
	g_assert(notify == NOTIFY_TYPE_UNSET);

	/* Set non-managed device on */
	connman_device_status_notify(device, true);
	g_assert(notify == NOTIFY_TYPE_STATUS);
	allow_ifdown = false;

	/* Set back to managed */
	connman_device_set_managed(device, true);
	g_assert(notify == NOTIFY_TYPE_MANAGED);
	allow_ifdown = true;

	/* Disable, ethernet plugin should set interface down */
	__connman_device_disable(device);
	g_assert_cmpint(interfaces[1], ==, DEVICE_ETHERNET_INDEX);
	connman_device_unregister(device);

	__connman_builtin_ethernet.exit();

	connman_device_unref(device);
}

void device_test_error0()
{
	reset_test();
	g_assert(__connman_builtin_ethernet.init() == 0);

	connman_device_set_managed(NULL, true);
	g_assert(notify == NOTIFY_TYPE_UNSET);

	g_assert_true(connman_device_get_managed(NULL));
	g_assert_false(connman_device_has_status_changed_to(NULL, false));

	connman_device_status_notify(NULL, true);
	g_assert(notify == NOTIFY_TYPE_UNSET);

	__connman_builtin_ethernet.exit();
}

int main (int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;

	g_test_init(&argc, &argv, NULL);

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

	__connman_log_init(argv[0], option_debug, false, false,
			"Unit Tests Connection Manager", VERSION);
	g_test_add_func("/device/notify_test0", device_notify_test0);
	g_test_add_func("/device/notify_test1", device_notify_test1);
	g_test_add_func("/device/ethernet_plugin0",
						device_test_ethernet_plugin0);
	g_test_add_func("/device/ethernet_plugin1",
						device_test_ethernet_plugin1);
	g_test_add_func("/device/ethernet_plugin2",
						device_test_ethernet_plugin2);
	g_test_add_func("/device/test_error0", device_test_error0);

	return g_test_run();
}
