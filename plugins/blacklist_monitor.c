/*
 *  Connection Manager
 *
 *  Copyright (C) 2022 Jolla Ltd. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/device.h>
#include <connman/ipconfig.h>
#include <connman/inet.h>
#include <connman/log.h>
#include <connman/network.h>
#include <connman/plugin.h>
#include <connman/service.h>

#include "src/connman.h"

#include <linux/rtnetlink.h>

#define IPV6_ANY "::"

struct rtnl_gw {
	int index;
	char *gw;
	int metric;
};

static GSList *rtnl_gw_list = NULL;
static GSList *rtnl_gw_restore_list = NULL;

static struct rtnl_gw *new_rtnl_gw(int index, const char *gw, int metric)
{
	struct rtnl_gw *item;

	item = g_new0(struct rtnl_gw, 1);
	item->index = index;
	item->gw = g_strdup(gw);
	item->metric = metric;

	return item;
}

static struct rtnl_gw *copy_rtnl_gw(struct rtnl_gw* item)
{
	if (!item)
		return NULL;

	return new_rtnl_gw(item->index, item->gw, item->metric);
}

static void free_rtnl_gw(gpointer data)
{
	struct rtnl_gw *item = data;

	if (!item)
		return;

	g_free(item->gw);
	g_free(item);
}

static gint compare_route(gconstpointer a, gconstpointer b)
{
	const struct rtnl_gw *route_a = a;
	const struct rtnl_gw *route_b = b;

	if (route_a->index == route_b->index) {
		if (!g_strcmp0(route_a->gw, route_b->gw))
			return route_b->metric - route_a->metric;

		return g_strcmp0(route_a->gw, route_b->gw);
	}

	return route_b->index - route_a->index;
}

static gint compare_route_by_index(gconstpointer a, gconstpointer b)
{
	const struct rtnl_gw *route_a = a;
	const struct rtnl_gw *route_b = b;

	return route_b->index - route_a->index;
}

static gint compare_route_by_index_and_metric(gconstpointer a, gconstpointer b)
{
	const struct rtnl_gw *route_a = a;
	const struct rtnl_gw *route_b = b;

	if (route_a->index == route_b->index)
		return route_b->metric - route_a->metric;

	return route_b->index - route_a->index;
}

static GSList *add_gateway_to_list(GSList *list, struct rtnl_gw *item, int *err)
{
	GSList *list_item;
	*err = 0;

	if (!item) {
		*err = -EINVAL;
		return list;
	}

	DBG("index %d dst %s gw %s metric %d", item->index, IPV6_ANY, item->gw,
								item->metric);

	if (list) {
		/* There should be only one route for index metric pair */
		list_item = g_slist_find_custom(list, item,
					compare_route_by_index_and_metric);
		if (list_item) {
			/* Exact match */
			if (!compare_route(list_item->data, item)) {
				DBG("already in list %p", list);
				*err = -EALREADY;
				return list;
			}

			/* Assign the new item as data */
			free_rtnl_gw(list_item->data);
			list_item->data = item;
			return list;
		}
	}

	return g_slist_prepend(list, item);
}

static int add_gateway_to_rtnl_list(struct rtnl_gw *item)
{
	int err;

	rtnl_gw_list = add_gateway_to_list(rtnl_gw_list, item, &err);
	if (!err)
		DBG("added to list");

	return err;
}

static int add_gateway_to_rtnl_restore_list(struct rtnl_gw *item)
{
	int err;

	rtnl_gw_restore_list = add_gateway_to_list(rtnl_gw_restore_list, item,
									&err);
	if (!err)
		DBG("added to list");

	return err;
}

static GSList *del_gateway_from_list(GSList *list, struct rtnl_gw *item,
								int *err)
{
	struct rtnl_gw *route;
	GSList *iter;

	if (!item) {
		*err = -EINVAL;
		return list;
	}

	DBG("index %d dst %s gw %s metric %d", item->index, IPV6_ANY, item->gw,
								item->metric);

	if (!list) {
		*err = 0;
		return list;
	}

	*err = -ENOENT;

	for (iter = list; iter; iter = iter->next) {
		route = iter->data;

		if(!compare_route(route, item)) {
			list = g_slist_delete_link(list, iter);
			free_rtnl_gw(route);
			*err = 0;

			break;
		}
	}

	return list;
}

static int del_gateway_from_rtnl_list(struct rtnl_gw *item)
{
	int err;
	rtnl_gw_list = del_gateway_from_list(rtnl_gw_list, item, &err);
	if (!err)
		DBG("deleted from list");

	return err;
}

static int del_gateway_from_rtnl_restore_list(struct rtnl_gw *item)
{
	int err;
	rtnl_gw_restore_list = del_gateway_from_list(rtnl_gw_restore_list,
								item, &err);
	if (!err)
		DBG("deleted from list");

	return err;
}

static bool is_ipconfig_fixed_or_manual(struct connman_service *service)
{
	
	enum connman_ipconfig_method method;

	method = connman_service_get_ipconfig_method(service,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		DBG("fixed/manual configured service %p", service);
		break;
	default:
		return false;
	}

	return true;
}

static void remove_route(gpointer data, gpointer user_data)
{
	struct connman_service *service;
	struct connman_network *network;
	struct rtnl_gw *item = data;
	struct rtnl_gw *item_copy;
	int index = GPOINTER_TO_INT(user_data);
	int err;

	/* Delete all gateways that are not for the current interface */
	if (item->index == index) {
		DBG("Not handling index %d, is the current interface", index);
		return;
	}

	DBG("deleting index %d dst %s gw %s metric %d", item->index, IPV6_ANY,
							item->gw, item->metric);

	/* Interested only in default gw routes that have no prefix */
	err = connman_inet_del_ipv6_network_route_with_metric(item->index,
							IPV6_ANY, 0,
							item->metric);
	if (err) {
		connman_warn("Cannot delete IPv6 network (%d %s %s %d)",
							item->index, IPV6_ANY,
							item->gw, item->metric);
	} else {
		/* 
		 * When removed check if there is a service and connected
		 * network for the index. In such case a route for an existing
		 * service was removed that should be restored when the
		 * address is set by manual method.
		 */
		service = connman_service_lookup_from_index(item->index);
		if (!service)
			return;

		if (!is_ipconfig_fixed_or_manual(service))
			return;

		network = connman_service_get_network(service);
		if (!network || !connman_network_get_connected(network))
			return;

		/*
		 * Copy as caller may delete the item. Also the content
		 * ownership is transferred to the list when added.
		 */
		item_copy = copy_rtnl_gw(item);
		err = add_gateway_to_rtnl_restore_list(item_copy);
		if (err) {
			DBG("cannot add to restore list: %s", strerror(-err));
			free_rtnl_gw(item_copy);
		}
	}
}

static void handle_gateway_rtnl_list(int index)
{
	DBG("handle all but index %d", index);

	g_slist_foreach(rtnl_gw_list, remove_route, GINT_TO_POINTER(index));
	g_slist_free_full(rtnl_gw_list, free_rtnl_gw);
	rtnl_gw_list = NULL;
}

static bool check_rtm_protocol(unsigned char rtm_protocol)
{
	switch (rtm_protocol) {
	case RTPROT_BOOT:
	case RTPROT_KERNEL:
	case RTPROT_RA:
	/* TODO: case RTPROT_DHCP: might be needed. */
		return true;
	default:
		return false;
	}
}

static void monitor_new_rtnl_gateway(int index, const char *dst,
						const char *gateway, int metric,
						unsigned char rtm_protocol)
{
	struct connman_service *service;
	struct connman_network *network;
	struct rtnl_gw *item = NULL;
	char *ifname;
	int service_index;

	DBG("");

	if (!check_rtm_protocol(rtm_protocol))
		return;

	if (!connman_inet_is_any_addr(dst, AF_INET6)) {
		DBG("dst %s != IPv6 ANY: %s", dst, IPV6_ANY);
		return;
	}

	ifname = connman_inet_ifname(index);
	if (!ifname || !connman_device_isfiltered(ifname)) {
		DBG("%s is not a filtered interface ", ifname);
		goto out;
	}

	DBG("%d/%s dst %s gateway %s metric %d", index, ifname, dst, gateway,
									metric);

	item = new_rtnl_gw(index, gateway, metric);
	if (!item)
		goto out;

	service = connman_service_get_default();
	if (!service) {
		DBG("no default service -> add to list");
		goto add;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected -> add to list", network);
		goto add;
	}

	service_index = connman_network_get_index(network);
	if (service_index != index)
		remove_route(item, GINT_TO_POINTER(service_index));
	else /* do nothing for connected gw */
		DBG("index %d is the default service -> not adding", index);

	goto out;

add:
	if (!add_gateway_to_rtnl_list(item))
		item = NULL;

out:
	free_rtnl_gw(item);

	g_free(ifname);
}

static void monitor_del_rtnl_gateway(int index, const char *dst,
						const char *gateway, int metric,
						unsigned char rtm_protocol)
{
	struct rtnl_gw *item;
	char *ifname;

	if (!check_rtm_protocol(rtm_protocol))
		return;

	if (!connman_inet_is_any_addr(dst, AF_INET6))
		return;

	ifname = connman_inet_ifname(index);

	DBG("%d/%s dst %s gateway %s metric %d", index, ifname, dst, gateway,
									metric);

	if (ifname && connman_device_isfiltered(ifname)) {
		item = new_rtnl_gw(index, gateway, metric);
		if (del_gateway_from_rtnl_list(item))
			DBG("cannot remove from list");
		free_rtnl_gw(item);
	}

	g_free(ifname);
}

static struct connman_rtnl monitor_rtnl = {
	.name			= "blacklist_monitor",
	.newgateway6		= monitor_new_rtnl_gateway,
	.delgateway6		= monitor_del_rtnl_gateway,
};

static void handle_restore_rtnl_gateway(int index, bool add_route,
					struct connman_service *service)
{
	GSList *iter;
	struct rtnl_gw *item;
	struct rtnl_gw match = { .index = index };
	int err;

	if (index < 0 || !service || !rtnl_gw_restore_list)
		return;

	/* Check method only when adding */
	if (add_route && !is_ipconfig_fixed_or_manual(service))
		return;

	iter = rtnl_gw_restore_list;
	while (iter) {
		item = iter->data;

		if (compare_route_by_index(item, &match)) {
			iter = iter->next;
			continue;
		}

		if (add_route) {
			err = connman_inet_add_ipv6_network_route_with_metric(
					item->index, IPV6_ANY, item->gw, 0,
					item->metric);
			DBG("%s route index %d dst %s gw %s metric %d",
					!err ? "Restored" : "Failed to restore",
					item->index, IPV6_ANY, item->gw,
					item->metric);
		}

		iter = iter->next;
		del_gateway_from_rtnl_restore_list(item);
	}
}

static void handle_network_rtnl_gateway(struct connman_network *network)
{
	int index = connman_network_get_index(network);
	if (index < 0) {
		DBG("index not set (%d)", index);
		return;
	}

	handle_gateway_rtnl_list(index);
}

static void monitor_ipconfig_changed(struct connman_service *service,
					struct connman_ipconfig *ipconfig)
{
	struct connman_service *def_service;
	struct connman_network *network;

	DBG("service %p ipconfig %p", service, ipconfig);

	if (connman_ipconfig_get_config_type(ipconfig) !=
						CONNMAN_IPCONFIG_TYPE_IPV6) {
		DBG("Ignore non-IPv6 ipconfig");
		return;
	}

	def_service = connman_service_get_default();
	if (service != def_service) {
		DBG("service %p != default service %p", service, def_service);
		return;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected", network);
		return;
	}

	handle_network_rtnl_gateway(network);
}

static void monitor_default_changed(struct connman_service *service)
{
	struct connman_network *network;

	DBG("service %p", service);

	if (!service)
		return;

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected", network);
		return;
	}

	if (!connman_network_is_configured(network,
						CONNMAN_IPCONFIG_TYPE_IPV6)) {
		DBG("IPv6 is not configured on network %p", network);
		return;
	}

	/* Removes all other IPv6 routes */
	handle_network_rtnl_gateway(network);

	/* Restores previously removed fixed/manual IPv6 routes */
	handle_restore_rtnl_gateway(connman_network_get_index(network), true,
						service);

	/* Calls for an update to re-check routes when default changes */
	connman_rtnl_request_route_update(AF_INET6);
}

static void monitor_service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	struct connman_network *network;
	int index;

	if (!service)
		return;

	switch (state) {
	/* Not connected, remove restore route */
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		break;
	/* Connecting or connected */
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		return;
	}

	network = connman_service_get_network(service);
	if (!network)
		return;

	index = connman_network_get_index(network);
	if (index < 0)
		return;

	DBG("Remove stale routes of index %d service %p", index, service);

	handle_restore_rtnl_gateway(index, false, service);
}

static struct connman_notifier monitor_notifier = {
	.name			= "blacklist_monitor",
	.ipconfig_changed	= monitor_ipconfig_changed,
	.default_changed	= monitor_default_changed,
	.service_state_changed	= monitor_service_state_changed
};

static int blacklist_monitor_init(void)
{
	int err;

	DBG("");

	err = connman_rtnl_register(&monitor_rtnl);
	if (err) {
		connman_error("Blacklist monitor: RTLN listener failed");
		return err;
	}

	err = connman_notifier_register(&monitor_notifier);
	if (err) {
		connman_error("Blacklist monitor: notifier register failed");
		return err;
	}

	connman_rtnl_handle_rtprot_ra(true);
	connman_rtnl_request_route_update(AF_INET);
	connman_rtnl_request_route_update(AF_INET6);

	return 0;
}

static void blacklist_monitor_exit(void)
{
	DBG("");

	connman_notifier_unregister(&monitor_notifier);
	connman_rtnl_unregister(&monitor_rtnl);

	g_slist_free_full(rtnl_gw_list, free_rtnl_gw);
	rtnl_gw_list = NULL;

	g_slist_free_full(rtnl_gw_restore_list, free_rtnl_gw);
	rtnl_gw_restore_list = NULL;
}

CONNMAN_PLUGIN_DEFINE(blacklist_monitor,
			"Blacklist interface monitoring plugin",
			VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
			blacklist_monitor_init, blacklist_monitor_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
