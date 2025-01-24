/*
 *  Connection Manager
 *
 *  Copyright (C) 2019-2020 Jolla Ltd. All rights reserved.
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

#include "vpn.h"
#include <connman/log.h>
#include <connman/vpn-dbus.h>

#include <errno.h>
#include <string.h>

static GSList *access_plugins;

static const char * vpn_access_method_names[VPN_ACCESS_METHOD_COUNT] = {
	/* Connection */
	"GetProperties",
	"SetProperty",
	"ClearProperty",
	"Connect",
	"Disconnect",

	/* Manager */
	"Create",
	"Remove",
	"GetConnections",
	"RegisterAgent",
	"UnregisterAgent",

	/* Storage */
	"ChangeUser"
};

const char *vpn_access_intf_name(enum vpn_access_intf intf)
{
	switch (intf) {
	case VPN_ACCESS_INTF_CONNECTION:
		return VPN_CONNECTION_INTERFACE;
	case VPN_ACCESS_INTF_MANAGER:
		return VPN_MANAGER_INTERFACE;
	case VPN_ACCESS_INTF_STORAGE:
		return VPN_STORAGE_INTERFACE;
	default:
		return NULL;
	}
}

const char *vpn_access_method_name(enum vpn_access_method method)
{
	if ((method >= 0) && (method < VPN_ACCESS_METHOD_COUNT))
		return vpn_access_method_names[method];

	return NULL;
}

enum vpn_access_intf vpn_access_intf_from_method(enum vpn_access_method method)
{
	enum vpn_access_intf intf = VPN_ACCESS_INTF_STORAGE;

	if (method < VPN_ACCESS_CONNECTION_COUNT)
		intf = VPN_ACCESS_INTF_CONNECTION;
	else if (method < VPN_ACCESS_MANAGER_COUNT)
		intf = VPN_ACCESS_INTF_MANAGER;

	return intf;
}

/**
 * Returns 0 if both are equal;
 * <0 if a comes before b;
 * >0 if a comes after b.
 */
static gint vpn_access_plugin_compare(gconstpointer a, gconstpointer b)
{
	const struct vpn_access_plugin *a_plugin = a;
	const struct vpn_access_plugin *b_plugin = b;
	int difference = b_plugin->priority - a_plugin->priority;

	/* return < 0 if a has higher priority,
		  > 0 if b has higher priority,
		  alphabetical if they're the same priority */
	if (difference != 0)
		return difference;

	return strcmp(a_plugin->name, b_plugin->name);
}

int vpn_access_plugin_register(const struct vpn_access_plugin *plugin)
{
	if (!plugin || !plugin->name)
		return -EINVAL;

	if (g_slist_find(access_plugins, plugin))
		return -EALREADY;

	DBG("\"%s\"", plugin->name);
	access_plugins = g_slist_insert_sorted(access_plugins, (void*)plugin,
					       vpn_access_plugin_compare);
	return 0;
}

void vpn_access_plugin_unregister(const struct vpn_access_plugin *plugin)
{
	if (g_slist_find(access_plugins, plugin)) {
		DBG("\"%s\"", plugin->name);
		access_plugins = g_slist_remove(access_plugins, plugin);
	}
}

bool __vpn_access_policy_check(const char *sender,
					  enum vpn_access_method method,
					  const char *arg,
					  bool default_access)
{
	GSList *l = access_plugins;
	enum vpn_access access;

	while (l) {
		GSList *next = l->next;
		const struct vpn_access_plugin *plugin = l->data;

		access = plugin->vpn_policy_check(sender, method, arg);
		if (access != VPN_ACCESS_DONT_CARE)
			return access == VPN_ACCESS_ALLOW;

		l = next;
	}

	return default_access;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
