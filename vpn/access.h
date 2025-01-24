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

#ifndef __VPN_ACCESS_H
#define __VPN_ACCESS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum vpn_access {
	VPN_ACCESS_DENY,
	VPN_ACCESS_ALLOW,
	VPN_ACCESS_DONT_CARE
};

enum vpn_access_intf {
	VPN_ACCESS_INTF_CONNECTION,
	VPN_ACCESS_INTF_MANAGER,
	VPN_ACCESS_INTF_STORAGE,

	VPN_ACCESS_INTF_COUNT
};

enum vpn_access_method {
	/* Connection */
	VPN_ACCESS_CONNECTION_GET_PROPERTIES,
	VPN_ACCESS_CONNECTION_SET_PROPERTY,
	VPN_ACCESS_CONNECTION_CLEAR_PROPERTY,
	VPN_ACCESS_CONNECTION_CONNECT,
	VPN_ACCESS_CONNECTION_DISCONNECT,
	VPN_ACCESS_CONNECTION_COUNT,

	/* Manager */
	VPN_ACCESS_MANAGER_CREATE = VPN_ACCESS_CONNECTION_COUNT,
	VPN_ACCESS_MANAGER_REMOVE,
	VPN_ACCESS_MANAGER_GET_CONNECTIONS,
	VPN_ACCESS_MANAGER_REGISTER_AGENT,
	VPN_ACCESS_MANAGER_UNREGISTER_AGENT,
	VPN_ACCESS_MANAGER_COUNT,

	/* Storage */
	VPN_ACCESS_STORAGE_CHANGE_USER = VPN_ACCESS_MANAGER_COUNT,
	VPN_ACCESS_STORAGE_COUNT,

	VPN_ACCESS_METHOD_COUNT = VPN_ACCESS_STORAGE_COUNT
};

#define VPN_ACCESS_PRIORITY_LOW     (-100)
#define VPN_ACCESS_PRIORITY_DEFAULT (0)
#define VPN_ACCESS_PRIORITY_HIGH    (100)

struct vpn_access_plugin {
	const char *name;
	int priority;

	enum vpn_access (*vpn_policy_check)
		(const char *sender,
		 enum vpn_access_method method,
		 const char *arg);

	void (*_reserved[10])(void);

	/* api_level will remain zero (and ignored) until we run out of
	 * the above placeholders. */
	int api_level;
};

int vpn_access_plugin_register(const struct vpn_access_plugin *plugin);
void vpn_access_plugin_unregister(const struct vpn_access_plugin *plugin);

const char *vpn_access_intf_name(enum vpn_access_intf intf);
const char *vpn_access_method_name(enum vpn_access_method method);
enum vpn_access_intf vpn_access_intf_from_method(enum vpn_access_method method);

#ifdef __cplusplus
}
#endif

#endif /* __VPN_ACCESS_H */

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
