/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2011-2014  BMW Car IT GmbH.
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

/**
 *  @file
 *    This implements non-client-facing functionality for managing
 *    network service gateways and routes. It also serves as a Linux
 *    Routing Netlink (rtnl) listener for routing table additions and
 *    deletions in the Linux kernel.
 *
 *    Gateway lifecycle is generally top-down, from user space to
 *    kernel. That is, Connection Manager manages and adds/sets or
 *    gateway routes and then uses notifications from the kernel
 *    Routing Netlink (rtnl) to confirm and "activate" those
 *    routes. Likewise, Connection Manager removes/clears/deletes
 *    gateway routes and then uses notifications from the kernel
 *    Routing Netlink (rtnl) to confirm and "inactivate" those
 *    routes. The following is the state machine for that lifecycle:
 *
 *                              .----------.    SIOCADDRT /
 *                              |          |    RTM_NEWROUTE
 *           .------------------| Inactive |--------------------.
 *           |                  |          |                    |
 *           |                  '----------'                    |
 *           | connman_rtnl                                     |
 *           | .delgateway                                      |
 *           |                                                  V
 *      .---------.         SIOCADDRT / RTM_NEWROUTE        .-------.
 *      |         |---------------------------------------->|       |
 *      | Removed |                                         | Added |
 *      |         |<----------------------------------------|       |
 *      '---------'         SIOCDELRT / RTM_DELROUTE        '-------'
 *           ^                                                  |
 *           | SIOCDELRT /                                      |
 *           | RTM_DELROUTE                                     |
 *           |                   .--------.     connman_rtnl    |
 *           |                   |        |     .newgateway     |
 *           '-------------------| Active |<--------------------'
 *                               |        |
 *                               '--------'
 *
 *    Gateways, and their associated routes, are generally of two types:
 *
 *      1. High-priority (that is, metric 0) default route.
 *
 *         This is used by the default service and its underlying
 *         network interface.
 *
 *      2. Low-priority (that is, metric > 0) default route.
 *
 *         This is used by non-default services and their underlying
 *         network interface.
 *
 *         For IPv6, these are handled and managed automatically by
 *         the kernel as part of Router Discovery (RD) Router
 *         Advertisements (RAs) and because link-local addresses and
 *         multi-homing are a natural part of IPv6, nothing needs to
 *         be done here. These routes show up in 'ip -6 route show'
 *         as:
 *
 *             default via fe80::f29f:c2ff:fe10:271e dev eth0
 *                 proto ra metric 1024 expires 1622sec hoplimit 64
 *                 pref medium
 *             default via fe80::f29f:c2ff:fe10:271e dev wlan0
 *                 proto ra metric 1024 expires 1354sec hoplimit 64
 *                 pref medium
 *
 *         For IPv4, largely invented before the advent of link-local
 *         addresses and multi-homing hosts, these need to be
 *         fully-managed here and, with such management, show up in
 *         'ip -4 route show' as low-priority (that is, high metric
 *         value) default routes:
 *
 *             default via 192.168.2.1 dev wlan0 metric 4294967295
 *
 *         The other alternative to low-priority routes would be to
 *         use "def1" default routes commonly used by VPNs that have a
 *         prefix length of 1 (hence the "def1" name). These would
 *         show up as:
 *
 *             0.0.0.0/1 via 192.168.2.1 dev wlan0
 *             128.0.0.0/1 via 192.168.2.1 dev wlan0
 *
 *         However, since these require twice the number of routing
 *         table entries and seem no more effective than the
 *         low-priority route approach, this alternative is not used
 *         here at present.
 *
 *    VPNs and point-to-point (P2P) links get special treatment but
 *    otherwise utilize the same states and types as described above.
 *
 *    Operationally, down calls from outside this module generally
 *    come from the following three functions:
 *
 *      1. __connman_gateway_add
 *      2. __connman_gateway_remove
 *      3. __connman_gateway_update
 *
 *    and up calls generally come from the following two functions:
 *
 *      1. gateway_rtnl_new
 *      2. gateway_rtnl_del
 *
 *    From these five functions above, we are then attempting to do
 *    the following for a gateway associated with a network service
 *    and its underlying network interface:
 *
 *      1. Set, or add, the high- or low-priority default route(s).
 *      2. Unset, or remove, the high- or low-priority default route(s).
 *      3. Promote the default route from low- to high-priority.
 *      4. Demote the default route from high- to low-priority.
 *
 *    The call trees for these operations amount to:
 *
 *      set_default_gateway (1)
 *        |
 *        '-mutate_default_gateway
 *            |
 *            |-set_ipv4_high_priority_default_gateway
 *            |   |
 *            |   '-set_default_gateway_route_common
 *            |       |
 *            |       '-set_ipv4_high_priority_default_gateway_route_cb
 *            |
 *            '-set_ipv6_high_priority_default_gateway
 *                |
 *                '-set_default_gateway_route_common
 *                    |
 *                    '-set_ipv6_high_priority_default_gateway_route_cb
 *
 *      set_low_priority_default_gateway (1)
 *        |
 *        '-mutate_default_gateway
 *            |
 *            '-set_ipv4_low_priority_default_gateway
 *                |
 *                '-set_default_gateway_route_common
 *                    |
 *                    '-set_ipv4_low_priority_default_gateway_route_cb
 *                        |
 *                        '-compute_low_priority_metric
 *
 *      unset_default_gateway (2)
 *        |
 *        '-mutate_default_gateway
 *            |
 *            |-unset_ipv4_high_priority_default_gateway
 *            |   |
 *            |   '-unset_default_gateway_route_common
 *            |       |
 *            |       '-unset_ipv4_high_priority_default_gateway_route_cb
 *            |
 *            '-unset_ipv6_high_priority_default_gateway
 *                |
 *                '-unset_default_gateway_route_common
 *                    |
 *                    '-unset_ipv6_high_priority_default_gateway_route_cb
 *
 *      unset_low_priority_default_gateway (2)
 *        |
 *        '-mutate_default_gateway
 *            |
 *            '-unset_ipv4_low_priority_default_gateway
 *                |
 *                '-unset_default_gateway_route_common
 *                    |
 *                    '-unset_ipv4_low_priority_default_gateway_route_cb
 *                        |
 *                        '-compute_low_priority_metric
 *
 *      promote_default_gateway (3)
 *        |
 *        |-unset_low_priority_default_gateway (2)
 *        |
 *        '-set_default_gateway (1)
 *
 *      demote_default_gateway (4)
 *        |
 *        |-unset_default_gateway (2)
 *        |
 *        '-set_low_priority_default_gateway (1)
 *
 *    where:
 *
 *      * 'mutate_default_gateway' and
 *        '{un,}set_default_gateway_route_common' are abstract,
 *        generalized handlers that manage the broad error conditions
 *        and gateway data and configuration lifecycle management.
 *
 *      * '*_route_cb' callbacks handle the actual routing table
 *        manipulation as appropriate for the IP configuration and
 *        gateway type, largely through the use of gateway
 *        configuration "ops" to help neutralize differences between
 *        IPv4 and IPv6.
 *
 *        In the fullness of time, the use of the gateway
 *        configuration "ops" should allow further collapsing the IPv4
 *        and IPv6 cases and simplifying the IP type-specific branches
 *        of the above call trees.
 *
 *        The low-priority metric is determined on a per-network
 *        interface basis and is computed by
 *        'compute_low_priority_metric'.
 *
 *    There is one exception to the above. When the Linux kernel
 *    recognizes that the next hop for a route becomes unreachable, it
 *    is automatically purged from the routing table with no
 *    RTM_DELROUTE RTNL notification.
 *
 *    Historically, this file started life as "connection.c". However,
 *    it was renamed to "gateway.c" since its primary focus is gateway
 *    routes and gateway route management.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <net/if.h>

#include <gdbus.h>

#include "connman.h"

/*
 * There are many call sites throughout this module for these
 * functions. These are macros to help, during debugging, to acertain
 * where they were called from.
 */

#define SET_DEFAULT_GATEWAY(data, type) \
	set_default_gateway(data, type, __func__)

#define UNSET_DEFAULT_GATEWAY(data, type) \
	unset_default_gateway(data, type, __func__)

#define SET_LOW_PRIORITY_DEFAULT_GATEWAY(data, type) \
	set_low_priority_default_gateway(data, type, __func__)

#define UNSET_LOW_PRIORITY_DEFAULT_GATEWAY(data, type) \
	unset_low_priority_default_gateway(data, type, __func__)

#define PROMOTE_DEFAULT_GATEWAY(data, type) \
	promote_default_gateway(data, type, __func__)

#define DEMOTE_DEFAULT_GATEWAY(data, type) \
	demote_default_gateway(data, type, __func__)

#define GATEWAY_CONFIG_DBG(description, config) \
	gateway_config_debug(__func__, description, config)

#define GATEWAY_DATA_DBG(description, data) \
	gateway_data_debug(__func__, description, data)

/**
 *  Flags governing the state and use of a gateway configuration.
 */
enum gateway_config_flags {
	/**
	 *	Indicates there are no gateway configuration flags asserted.
	 */
	CONNMAN_GATEWAY_CONFIG_FLAG_NONE = 0,

	/**
	 *	Indicates whether the gateway configuration is part of a VPN.
	 */
	CONNMAN_GATEWAY_CONFIG_FLAG_VPN	 = 1U << 0
};

/**
 *	@brief
 *    Indicates the current lifecycle state of the gateway
 *    configuration.
 *
 *  Gateway lifecycle is generally top-down, from user space to
 *  kernel. That is, Connection Manager manages and adds/sets or
 *  gateway routes and then uses notifications from the kernel Routing
 *  Netlink (rtnl) to confirm and "activate" those routes. Likewise,
 *  Connection Manager removes/clears/deletes gateway routes an then
 *  uses notifications from the kernel Routing Netlink (rtnl) to
 *  confirm and "inactivate" those routes. The following is the state
 *  machine for that lifecycle:
 *
 *                              .----------.    SIOCADDRT /
 *                              |          |    RTM_NEWROUTE
 *           .------------------| Inactive |--------------------.
 *           |                  |          |                    |
 *           |                  '----------'                    |
 *           | connman_rtnl                                     |
 *           | .delgateway                                      |
 *           |                                                  V
 *      .---------.         SIOCADDRT / RTM_NEWROUTE        .-------.
 *      |         |---------------------------------------->|       |
 *      | Removed |                                         | Added |
 *      |         |<----------------------------------------|       |
 *      '---------'         SIOCDELRT / RTM_DELROUTE        '-------'
 *           ^                                                  |
 *           | SIOCDELRT /                                      |
 *           | RTM_DELROUTE                                     |
 *           |                   .--------.     connman_rtnl    |
 *           |                   |        |     .newgateway     |
 *           '-------------------| Active |<--------------------'
 *                               |        |
 *                               '--------'
 *
 */
enum gateway_config_state {
	/**
	 *	Indicates whether the gateway, or default router, is inactive.
	 */
	CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE = 0,

	/**
	 *	Indicates whether the gateway has been added, or set, to the
	 *	kernel but not acknowledged round-trip.
	 */
	CONNMAN_GATEWAY_CONFIG_STATE_ADDED	  = 1,

	/**
	 *	Indicates whether the gateway, or default router, is added and
	 *	acknowledged by the kernel through a Routing Netlink (rtnl)
	 *	notification and, consequently, is active (that is, in use).
	 */
	CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE	  = 2,

	/**
	 *	Indicates whether the gateway has been removed, or cleared,
	 *	from the kernel but not acknowledged round-trip.
	 */
	CONNMAN_GATEWAY_CONFIG_STATE_REMOVED  = 3
};

/**
 *	Indicates the current type or use of the gateway configuration.
 */
enum gateway_config_type {
	/**
	 *	Indicates the gateway, or default router, is not used for any
	 *	route.
	 */
	CONNMAN_GATEWAY_CONFIG_TYPE_NONE				  = 0,

	/**
	 *	Indicates the gateway, or default router, is a high-priority
	 *	(that is, metric 0) default route.
	 */
	CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT = 1,

	/**
	 *	Indicates the gateway, or default router, is a low-priority
	 *	(that is, metric > 0) default route.
	 */
	CONNMAN_GATEWAY_CONFIG_TYPE_LOW_PRIORITY_DEFAULT  = 2
};

/**
 *  Gateway configuration function pointers for IP configuration
 *  type-specific route set/clear/add/delete operations.
 */
struct gateway_config_ops {
	bool (*compare_subnet)(int index,
		const char *address);

	int (*get_dest_addr)(int index,
		char **dest);

	int (*add_interface_route)(int index);
	int (*del_interface_route)(int index);

	int (*add_default_route)(uint32_t table,
		int index,
		const char *gateway);
	int (*del_default_route)(uint32_t table,
		int index,
		const char *gateway);

	int (*add_default_route_with_metric)(uint32_t table,
		int index,
		const char *gateway,
		uint32_t metric);
	int (*del_default_route_with_metric)(uint32_t table,
		int index,
		const char *gateway,
		uint32_t metric);

	int (*add_host_route)(int index,
		const char *host,
		const char *gateway);
	int (*del_host_route)(int index,
		const char *host,
		const char *gateway);
};

/**
 *	An IP configuration type-specific data structure used to maintain
 *	gateway-specific configuration information about a gateway, or
 *	default router, and, for VPNs, the VPN peer.
 */
struct gateway_config {
	/**
	 *	A 32-bit flag bitfield governing the state and use of the
	 *	configuration. See #gateway_config_flags.
	 */
	uint32_t flags;

	/**
	 *	Indicates the current state of the gateway configuration. See
	 *	#gateway_config_state.
	 */
	enum gateway_config_state state;

	/**
	 *	Indicates the current type or use of the gateway configuration.
	 *	See #gateway_config_type.
	 */
	enum gateway_config_type type;

	/**
	 *  A pointer to immutable function pointers for route
	 *  set/clear/add/delete operations.
	 */
	const struct gateway_config_ops *ops;

	/**
	 *	A pointer to a mutable, dynamically-allocated null-terminated
	 *	C string containing the text-formatted address of the gateway,
	 *	or default router.
	 */
	char *gateway;

	/* VPN extra data */
	char *vpn_ip;
	int vpn_phy_index;
	char *vpn_phy_ip;
};

/**
 *	The key data structure used to associate a network service with a
 *	gateway, or default router.
 */
struct gateway_data {
	/**
	 *	The network interface index associated with the underlying
	 *	network interface for the assigned @a service field.
	 */
	int index;

	/**
	 *	A strong (that is, uses #connman_service_{ref,unref})
	 *	reference to the network service associated with this gateway.
	 */
	struct connman_service *service;

	/**
	 *	An optional weak reference to dynamically-allocated storage
	 *	for the gateway-specific configuration, if the gateway is IPv4.
	 */
	struct gateway_config *ipv4_config;

	/**
	 *	An optional weak reference to dynamically-allocated storage
	 *	for the gateway-specific configuration, if the gateway is IPv6.
	 */
	struct gateway_config *ipv6_config;

	/**
	 *	A Boolean indicating whether this gateway / network interface
	 *	index tuple has been handled by the #connman_rtnl @a
	 *	newgateway Linux Routing Netlink (rtnl) new gateway listener
	 *	method and, specifically, whether that method has checked a
	 *	new, incoming gateway against the current gateway / default
	 *	router.
	 */
	bool default_checked;
};

/**
 *	Function pointers to mutating (including, but not limited to,
 *	adding/setting or clearing/deleting/removing routes) IPv4 and/or
 *	IPv6 default gateways.
 */
struct mutate_default_gateway_ops {
	/**
	 *  An optional pointer to a function for mutating (including, but
	 *  not limited to, adding/setting or clearing/deleting/removing
	 *  routes) an IPv4 default gateway.
	 *
	 *  @param[in,out]  data    A pointer to the mutable IPv4 gateway
	 *                          data to mutate.
	 *  @param[in,out]  config  A pointer to the mutable IPv4 gateway
	 *                          configuration to mutate.
	 *
	 *  @returns
	 *    0 if successful; otherwise, < 0 on error.
	 *
	 */
	int (*mutate_ipv4)(struct gateway_data *data,
				struct gateway_config *config);

	/**
	 *  An optional pointer to a function for mutating (including, but
	 *  not limited to, adding/setting or clearing/deleting/removing
	 *  routes) an IPv6 default gateway.
	 *
	 *  @param[in,out]  data    A pointer to the mutable IPv6 gateway
	 *                          data to mutate.
	 *  @param[in,out]  config  A pointer to the mutable IPv6 gateway
	 *                          configuration to mutate.
	 *
	 *  @returns
	 *    0 if successful; otherwise, < 0 on error.
	 *
	 */
	int (*mutate_ipv6)(struct gateway_data *data,
				struct gateway_config *config);
};

/**
 *  Prototype for a function callback to mutate (that is, add/set or
 *  clear/delete/remove) a default route for a gateway using a function
 *  utilizing a SIOCADDRT / SIOCDELRT socket ioctl or a RTM_NEWROUTE /
 *  RTM_DELROUTE Linux Routing Netlink (rtnl) command to modify the Linux
 *  routing table.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          use to mutate the default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to use to mutate the
 *                          default route.
 *
 *  @returns
 *    0 if successful; otherwise, < 0 on error.
 *
 */
typedef int (*mutate_default_gateway_route_cb_t)(struct gateway_data *data,
				struct gateway_config *config);

static int unset_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type,
				const char *function);
static int unset_low_priority_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type,
				const char *function);

static const struct gateway_config_ops ipv4_gateway_config_ops = {
	.compare_subnet				   =
		connman_inet_compare_subnet,

	.get_dest_addr				   =
		connman_inet_get_dest_addr,

	.add_interface_route		   =
		connman_inet_set_gateway_interface,
	.del_interface_route		   =
		connman_inet_clear_gateway_interface,

	.add_default_route			   =
		__connman_inet_add_default_to_table,
	.del_default_route			   =
		__connman_inet_del_default_from_table,

	.add_default_route_with_metric =
		__connman_inet_add_default_to_table_with_metric,
	.del_default_route_with_metric =
		__connman_inet_del_default_from_table_with_metric,

	.add_host_route				   =
		connman_inet_add_host_route,
	.del_host_route				   =
		connman_inet_del_host_route
};

static const struct gateway_config_ops ipv6_gateway_config_ops = {
	.compare_subnet				   =
		connman_inet_compare_ipv6_subnet,

	.get_dest_addr				   =
		connman_inet_ipv6_get_dest_addr,

	.add_interface_route		   =
		connman_inet_set_ipv6_gateway_interface,
	.del_interface_route		   =
		connman_inet_clear_ipv6_gateway_interface,

	.add_default_route			   =
		__connman_inet_add_default_to_table,
	.del_default_route			   =
		__connman_inet_del_default_from_table,

	.add_default_route_with_metric =
		__connman_inet_add_default_to_table_with_metric,
	.del_default_route_with_metric =
		__connman_inet_del_default_from_table_with_metric,

	.add_host_route				   =
		connman_inet_add_ipv6_host_route,
	.del_host_route				   =
		connman_inet_del_ipv6_host_route
};

/*
 * These are declared as 'const char *const' to effect an immutable
 * pointer to an immutable null-terminated character string such that
 * they end up in .text, not .data (which would otherwise be the case
 * for a 'const char *' declaration), and with the 'static'
 * storage/scope qualifier, the compiler can optimize their use within
 * this file as it sees fit.
 */
static const char *const ipv4_addr_any_str = "0.0.0.0";
static const char *const ipv6_addr_any_str = "::";

/**
 *	A dictionary / hash table of network services to gateway, or
 *	default router, data.
 *
 */
static GHashTable *gateway_hash = NULL;

/**
 *  @brief
 *    Return the specified pointer if non-null; otherwise, the
 *    immutable "<null>" string.
 *
 *  @param[in]  pointer  The pointer to be returned if non-null.
 *
 *  @returns
 *     @a pointer if non-null; otherwise the "<null>" immutable
 *     null-terminated C string.
 *
 */
static const char *maybe_null(const void *pointer)
{
	return pointer ? pointer : "<null>";
}

static bool is_gateway_config_flags_set(const struct gateway_config *config,
		uint32_t flags)
{
	return config && ((config->flags & flags) == flags);
}

static void gateway_config_flags_clear(struct gateway_config *config,
		uint32_t flags)
{
	config->flags &= ~flags;
}

static void gateway_config_flags_set(struct gateway_config *config,
	uint32_t flags)
{
	config->flags |= flags;
}

static bool is_gateway_config_vpn(const struct gateway_config *config)
{
	static const uint32_t flags =
		CONNMAN_GATEWAY_CONFIG_FLAG_VPN;

	return is_gateway_config_flags_set(config, flags);
}

static void gateway_config_set_vpn(struct gateway_config *config)
{
	static const uint32_t flags =
		CONNMAN_GATEWAY_CONFIG_FLAG_VPN;

	return gateway_config_flags_set(config, flags);
}

static void gateway_config_clear_vpn(struct gateway_config *config)
{
	static const uint32_t flags =
		CONNMAN_GATEWAY_CONFIG_FLAG_VPN;

	return gateway_config_flags_clear(config, flags);
}

static const char *gateway_config_state2string(enum gateway_config_state state)
{
	switch (state) {
	case CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE:
		return "inactive";
	case CONNMAN_GATEWAY_CONFIG_STATE_ADDED:
		return "added";
	case CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE:
		return "active";
	case CONNMAN_GATEWAY_CONFIG_STATE_REMOVED:
		return "removed";
	}

	return NULL;
}

static const char *gateway_config_type2string(enum gateway_config_type type)
{
	switch (type) {
	case CONNMAN_GATEWAY_CONFIG_TYPE_NONE:
		return "none";
	case CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT:
		return "high-priority default";
	case CONNMAN_GATEWAY_CONFIG_TYPE_LOW_PRIORITY_DEFAULT:
		return "low-priority default";
	}

	return NULL;
}

static void gateway_config_state_set(struct gateway_config *config,
				enum gateway_config_state state)
{
	DBG("config %p old state %d (%s) => new state %d (%s)",
		config,
		config->state, gateway_config_state2string(config->state),
		state, gateway_config_state2string(state));

	config->state = state;
}

static bool is_gateway_config_state(const struct gateway_config *config,
				enum gateway_config_state state)
{
	return config->state == state;
}

static bool is_gateway_config_state_inactive(
				const struct gateway_config *config)
{
	return is_gateway_config_state(config,
				CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE);
}

static bool is_gateway_config_state_added(const struct gateway_config *config)
{
	return is_gateway_config_state(config,
				CONNMAN_GATEWAY_CONFIG_STATE_ADDED);
}

static bool is_gateway_config_state_removed(
				const struct gateway_config *config)
{
	return is_gateway_config_state(config,
				CONNMAN_GATEWAY_CONFIG_STATE_REMOVED);
}

static bool is_gateway_config_state_active(const struct gateway_config *config)
{
	return is_gateway_config_state(config,
				CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE);
}

static void gateway_config_type_set(struct gateway_config *config,
				enum gateway_config_type type)
{
	DBG("config %p old type %d (%s) => new type %d (%s)",
		config,
		config->type, gateway_config_type2string(config->type),
		type, gateway_config_type2string(type));

	config->type = type;
}

static bool is_gateway_config_type(const struct gateway_config *config,
				enum gateway_config_type type)
{
	return config->type == type;
}

static void gateway_config_set_active(struct gateway_config *config)
{
	gateway_config_state_set(config, CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE);
}

static void gateway_config_set_inactive(struct gateway_config *config)
{
	gateway_config_state_set(config,
		CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE);

	gateway_config_type_set(config,
		CONNMAN_GATEWAY_CONFIG_TYPE_NONE);
}

/**
 *  @brief
 *    Conditionally log the specified gateway configuration.
 *
 *  This conditionally logs at the debug level the specified
 *  #gateway_config gateway configuration, @a config, with the
 *  provided description, @a description, attributed to the provided
 *  function name, @a function.
 *
 *  @param[in]  function     A pointer to an immutable null-terminated
 *                           C string containing the function name to
 *                           which the call to this function should be
 *                           attributed.
 *  @param[in]  description  A pointer to an immutable null-terminated
 *                           C string briefly describing @a
 *                           config. For example, "ipv4_config".
 *  @param[in]  config       A pointer to the immutable gateway
 *                           configuration to conditionally log.
 *
 *  @sa DBG
 *
 */
static void gateway_config_debug(const char *function,
				const char *description,
				const struct gateway_config *config)
{
	g_autofree char *vpn_phy_interface = NULL;

	if (!function || !description)
		return;

	if (!config)
		DBG("from %s() %s %p", function, description, config);
	else {
		if (config->vpn_phy_index >= 0)
			vpn_phy_interface =
				connman_inet_ifname(config->vpn_phy_index);

		DBG("from %s() "
			"%s %p: { state: %d (%s), type %d (%s), "
			"flags: 0x%x (%s), "
			"ops: %p, "
			"gateway: %p (%s), "
			"vpn_ip: %p (%s), vpn_phy_index: %d (%s), "
			"vpn_phy_ip: %p (%s) }",
			function,
			description,
			config,
			config->state,
			maybe_null(gateway_config_state2string(config->state)),
			config->type,
			maybe_null(gateway_config_type2string(config->type)),
			config->flags,
			is_gateway_config_vpn(config) ? "VPN" : "",
			config->ops,
			config->gateway, maybe_null(config->gateway),
			config->vpn_ip, maybe_null(config->vpn_ip),
			config->vpn_phy_index, maybe_null(vpn_phy_interface),
			config->vpn_phy_ip, maybe_null(config->vpn_phy_ip));
	}
}

/**
 *  @brief
 *    Conditionally log the specified gateway data.
 *
 *  This conditionally logs at the debug level the specified
 *  #gateway_data gateway data, @a data, with the provided
 *  description, @a description, attributed to the provided function
 *  name, @a function.
 *
 *  @param[in]  function     A pointer to an immutable null-terminated
 *                           C string containing the function name to
 *                           which the call to this function should be
 *                           attributed.
 *  @param[in]  description  A pointer to an immutable null-terminated
 *                           C string briefly describing @a
 *                           data. For example, "default_gateway".
 *  @param[in]  data         A pointer to the immutable gateway
 *                           data to conditionally log.
 *
 *  @sa DBG
 *  @sa gateway_config_debug
 *
 */
static void gateway_data_debug(const char *function,
				const char *description,
				const struct gateway_data *data)
{
	g_autofree char *interface = NULL;

	if (!function || !description)
		return;

	if (!data)
		DBG("from %s() %s %p", function, description, data);
	else {
		interface = connman_inet_ifname(data->index);

		DBG("from %s() %s %p: { index: %d (%s), service: %p (%s), "
			"ipv4_config: %p, ipv6_config: %p, default_checked: %u }",
			function,
			description,
			data,
			data->index,
			maybe_null(interface),
			data->service,
			connman_service_get_identifier(data->service),
			data->ipv4_config,
			data->ipv6_config,
			data->default_checked);

		if (data->ipv4_config)
			gateway_config_debug(function, "ipv4_config",
				data->ipv4_config);

		if (data->ipv6_config)
			gateway_config_debug(function, "ipv6_config",
				data->ipv6_config);
	}
}

/**
 *  @brief
 *    Return the IP-specific gateway configuration for the specified
 *    gateway data.
 *
 *  @param[in]  data  A pointer to the mutable gateway data for which
 *                    the gateway configuration is to be returned,
 *                    specific to @a type.
 *  @param[in]  type  The IP configuration type for which the gateway
 *                    configuration is to be returned.
 *
 *  @returns
 *    The IP-specific gateway configuration for the specified gateway
 *    data on success; otherwise, null.
 *
 */
static struct gateway_config *gateway_data_config_get(struct gateway_data *data,
				enum connman_ipconfig_type type)
{
	struct gateway_config *config = NULL;

	if (!data)
		return config;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		config = data->ipv4_config;
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		config = data->ipv6_config;
		break;
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
	case CONNMAN_IPCONFIG_TYPE_ALL:
	default:
		break;
	}

	return config;
}

/**
 *  @brief
 *    Determine whether the specified text-formatted IPv4 address is
 *    the "any" or "unspecified" address.
 *
 *  This determines whether the specified text-formatted IPv4 address
 *  is the "any" or "unspecified" address, that is "0.0.0.0".
 *
 *  @param[in]  address  A pointer to an immutable null-terminated C
 *                       string containing the text-formatted address
 *                       to determine whether it is the IPv4 "any" or
 *                       "unspecified address.
 *
 *  @returns
 *    True if @a address is the "any" or "unspecified" IPv4 address;
 *    otherwise, false.
 *
 *  @sa is_ipv6_addr_any_str
 *
 */
static bool is_ipv4_addr_any_str(const char *address)
{
	return g_strcmp0(ipv4_addr_any_str, address) == 0;
}

/**
 *  @brief
 *    Determine whether the specified text-formatted IPv6 address is
 *    the "any" or "unspecified" address.
 *
 *  This determines whether the specified text-formatted IPv6 address
 *  is the "any" or "unspecified" address, that is "::".
 *
 *  @param[in]  address  A pointer to an immutable null-terminated C
 *                       string containing the text-formatted address
 *                       to determine whether it is the IPv6 "any" or
 *                       "unspecified address.
 *
 *  @returns
 *    True if @a address is the "any" or "unspecified" IPv6 address;
 *    otherwise, false.
 *
 *  @sa is_ipv4_addr_any_str
 *
 */
static bool is_ipv6_addr_any_str(const char *address)
{
	return g_strcmp0(ipv6_addr_any_str, address) == 0;
}

/**
 *  @brief
 *    Determine whether the specified text-formatted IP address is
 *    the "any" or "unspecified" address.
 *
 *  This determines whether the specified text-formatted IP address
 *  is the "any" or "unspecified" address.
 *
 *  @param[in]  address  A pointer to an immutable null-terminated C
 *                       string containing the text-formatted address
 *                       to determine whether it is the IP "any" or
 *                       "unspecified address.
 *
 *  @returns
 *    True if @a address is the "any" or "unspecified" IP address;
 *    otherwise, false.
 *
 *  @sa is_ipv4_addr_any_str
 *  @sa is_ipv6_addr_any_str
 *
 */
static bool is_addr_any_str(const char *address)
{
	if (!address)
		return false;

	return (!strchr(address, ':') && is_ipv4_addr_any_str(address)) ||
				is_ipv6_addr_any_str(address);
}

/**
 *  @brief
 *    Find the gateway, or default router, configuration associated
 *    with a network interface index.
 *
 *  This attempts to find a gateway, or default router, configuration
 *  associated with the specified network interface index.
 *
 *  It is possible that there is both an IPv4 and IPv6 gateway, or
 *  default router, configuration exist for an index. The IP address
 *  family associated with @a gateway will uniqueify and select among
 *  them.
 *
 *  @param[in]  index    The network interface index for which to find
 *                       gateway, or default router, configuration.
 *  @param[in]  gateway  A pointer to an immutable null-
 *                       terminated C string containing the
 *                       text-formatted address of the gateway, or
 *                       default router, for which to find its
 *                       associated configuration.
 *
 *  @returns
 *    A pointer to the gateway, or default router, configuration
 *    associated with the provided network interface index on success;
 *    otherwise, null.
 *
 *  @sa find_gateway_data
 *
 */
static struct gateway_config *find_gateway_config(int index,
				const char *gateway)
{
	GHashTableIter iter;
	gpointer value, key;

	if (!gateway)
		return NULL;

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *data = value;

		if (data->ipv4_config && data->index == index &&
				g_str_equal(data->ipv4_config->gateway,
					gateway))
			return data->ipv4_config;

		if (data->ipv6_config && data->index == index &&
				g_str_equal(data->ipv6_config->gateway,
					gateway))
			return data->ipv6_config;
	}

	return NULL;
}

/**
 *  @brief
 *    Find the gateway, or default router, data associated
 *    with the configuration.
 *
 *  This attempts to find a gateway, or default router, data
 *  associated with the specified configuration.
 *
 *  @param[in]  config   A pointer to an immutable gateway, or
 *                       default router, configuration for which to
 *                       find the associated gateway data.
 *
 *  @returns
 *    A pointer to the gateway, or default router, data associated
 *    with the provided configuration on success; otherwise, null.
 *
 *  @sa find_gateway_config
 *
 */
static struct gateway_data *find_gateway_data(
				const struct gateway_config *config)
{
	GHashTableIter iter;
	gpointer value, key;

	if (!config)
		return NULL;

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *data = value;

		if (data->ipv4_config &&
				data->ipv4_config == config)
			return data;

		if (data->ipv6_config &&
				data->ipv6_config == config)
			return data;
	}

	return NULL;
}

/**
 *  @brief
 *    Find the first, or any, gateway data marked active.
 *
 *  This attempts to find the first, or any, gateway data marked
 *  active.
 *
 *  @returns
 *    A pointer to the first, or any, gateway data marked active on
 *    success; otherwise, null.
 *
 *  @sa find_default_gateway_data
 *  @sa find_gateway_data
 *
 */
static struct gateway_data *find_any_active_gateway_data(void)
{
	GHashTableIter iter;
	gpointer value, key;

	DBG("");

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *data = value;

		if (data->ipv4_config &&
				is_gateway_config_state_active(
					data->ipv4_config))
			return data;

		if (data->ipv6_config &&
				is_gateway_config_state_active(
					data->ipv6_config))
			return data;
	}

	return NULL;
}

/**
 *  @brief
 *    Find the gateway, or default router, data associated with the
 *    default service.
 *
 *  This attempts to find the gateway, or default router, data
 *  associated with default network service (that is, has the
 *  high-priority default route).
 *
 *  @returns
 *    A pointer to the gateway, or default router, data associated
 *    with the default network service (that is, has the high-priority
 *    default route) on success; otherwise, null.
 *
 *  @sa find_any_active_gateway_data
 *  @sa find_gateway_data
 *
 */
static struct gateway_data *find_default_gateway_data(void)
{
	struct connman_service *service;

	service = connman_service_get_default();
	if (!service)
		return NULL;

	return g_hash_table_lookup(gateway_hash, service);
}

static struct gateway_data *find_vpn_gateway_data(int index,
				const char *gateway)
{
	GHashTableIter iter;
	gpointer value, key;

	if (!gateway)
		return NULL;

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *data = value;

		if (data->ipv4_config && data->index == index &&
				g_str_equal(data->ipv4_config->gateway,
					gateway))
			return data;

		if (data->ipv6_config && data->index == index &&
				g_str_equal(data->ipv6_config->gateway,
					gateway))
			return data;
	}

	return NULL;
}

struct get_gateway_params {
	char *vpn_gateway;
	int vpn_index;
};

static void get_gateway_cb(const char *gateway, int index, void *user_data)
{
	struct gateway_config *config;
	struct gateway_data *data;
	struct get_gateway_params *params = user_data;
	int family;

	if (index < 0)
		goto out;

	DBG("phy index %d phy gw %s vpn index %d vpn gw %s", index, gateway,
		params->vpn_index, params->vpn_gateway);

	data = find_vpn_gateway_data(params->vpn_index, params->vpn_gateway);
	if (!data) {
		DBG("Cannot find VPN link route, index %d addr %s",
			params->vpn_index, params->vpn_gateway);
		goto out;
	}

	family = connman_inet_check_ipaddress(params->vpn_gateway);

	if (family == AF_INET)
		config = data->ipv4_config;
	else if (family == AF_INET6)
		config = data->ipv6_config;
	else
		goto out;

	config->vpn_phy_index = index;

	DBG("vpn %s phy index %d", config->vpn_ip, config->vpn_phy_index);

out:
	g_free(params->vpn_gateway);
	g_free(params);
}

static void set_vpn_routes(struct gateway_data *new_gateway,
			struct connman_service *service,
			const char *gateway,
			enum connman_ipconfig_type type,
			const char *peer,
			struct gateway_data *active_gateway)
{
	struct gateway_config *config;
	struct connman_ipconfig *ipconfig;
	char *dest;

	DBG("new %p service %p gw %s type %d peer %s active %p",
		new_gateway, service, gateway, type, peer, active_gateway);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		ipconfig = __connman_service_get_ip4config(service);
		config = new_gateway->ipv4_config;
	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		ipconfig = __connman_service_get_ip6config(service);
		config = new_gateway->ipv6_config;
	} else
		return;

	if (config) {
		int index = __connman_ipconfig_get_index(ipconfig);
		struct get_gateway_params *params;

		gateway_config_set_vpn(config);

		if (peer)
			config->vpn_ip = g_strdup(peer);
		else if (gateway)
			config->vpn_ip = g_strdup(gateway);

		params = g_try_malloc(sizeof(struct get_gateway_params));
		if (!params)
			return;

		params->vpn_index = index;
		params->vpn_gateway = g_strdup(gateway);

		/*
		 * Find the gateway that is serving the VPN link
		 */
		__connman_inet_get_route(gateway, get_gateway_cb, params);
	}

	if (!active_gateway)
		return;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		/*
		 * Special route to VPN server via gateway. This
		 * is needed so that we can access hosts behind
		 * the VPN. The route might already exist depending
		 * on network topology.
		 */
		if (!active_gateway->ipv4_config)
			return;


		/*
		 * If VPN server is on same subnet as we are, skip adding
		 * route.
		 */
		if (config->ops->compare_subnet(active_gateway->index,
								gateway))
			return;

		DBG("active gw %s", active_gateway->ipv4_config->gateway);

		if (!is_addr_any_str(active_gateway->ipv4_config->gateway))
			dest = active_gateway->ipv4_config->gateway;
		else
			dest = NULL;

		active_gateway->ipv4_config->ops->add_host_route(
							active_gateway->index,
							gateway,
							dest);

	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {

		if (!active_gateway->ipv6_config)
			return;

		if (config->ops->compare_subnet(active_gateway->index,
								gateway))
			return;

		DBG("active gw %s", active_gateway->ipv6_config->gateway);

		if (!is_addr_any_str(active_gateway->ipv6_config->gateway))
			dest = active_gateway->ipv6_config->gateway;
		else
			dest = NULL;

		active_gateway->ipv6_config->ops->add_host_route(
							active_gateway->index,
							gateway,
							dest);
	}
}

/**
 *  @brief
 *    Delete all gateway, or default router, default or host routes
 *    for the gateway data.
 *
 *  This attempts to delete, or remove, all gateway, or default
 *  router, default or host routes associated with the specified
 *  gateway data.
 *
 *  @note
 *    Deletions or removals are restricted to the network * interface
 *    associated with the network interface index specified by * the
 *    @a data @a index field.
 *
 *  @param[in]  data  A pointer to the mutable gateway data for which
 *                    to delete or remove all gateway, or default
 *                    router, default or host routes.
 *  @param[in]  type  The IP configuration type for which the gateway,
 *                    or default router, default or host routes are to
 *                    be deleted or removed.
 *
 *  @retval  0        If successful.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to delete routes.
 *  @retval  -EINVAL  If the routing information to be deleted was
 *                    invalid.
 *  @retval  -EFAULT  If the address to the routing information to be
 *                    deleted was invalid.
 *  @retval  -ESRCH   A request was made to delete a non-existing
 *                    routing entry.
 *
 *  @sa connman_inet_clear_gateway_address
 *  @sa connman_inet_clear_gateway_interface
 *  @sa connman_inet_clear_ipv6_gateway_address
 *  @sa connman_inet_clear_ipv6_gateway_interface
 *  @sa connman_inet_del_host_route
 *  @sa connman_inet_del_ipv6_host_route
 *  @sa del_gateway_routes_if_active
 *
 */
static int del_gateway_routes(struct gateway_data *data,
			enum connman_ipconfig_type type)
{
	int status4 = 0, status6 = 0;
	bool do_ipv4 = false, do_ipv6 = false;

	DBG("data %p type %d (%s)", data,
		type, __connman_ipconfig_type2string(type));

	GATEWAY_DATA_DBG("data", data);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_ALL)
		do_ipv4 = do_ipv6 = true;
	else
		return -EINVAL;

	if (do_ipv4 && data->ipv4_config) {
		if (is_gateway_config_vpn(data->ipv4_config)) {
			status4 = connman_inet_clear_gateway_address(
						data->index,
						data->ipv4_config->vpn_ip);

		} else {
			data->ipv4_config->ops->del_host_route(
						data->index,
						data->ipv4_config->gateway,
						NULL);

			status4 = UNSET_DEFAULT_GATEWAY(data, type);

			UNSET_LOW_PRIORITY_DEFAULT_GATEWAY(data, type);
		}
	}

	if (do_ipv6 && data->ipv6_config) {
		if (is_gateway_config_vpn(data->ipv6_config)) {
			status6 = connman_inet_clear_ipv6_gateway_address(
						data->index,
						data->ipv6_config->vpn_ip);

		} else {
			data->ipv6_config->ops->del_host_route(
						data->index,
						data->ipv6_config->gateway,
						NULL);

			status6 = UNSET_DEFAULT_GATEWAY(data, type);

			UNSET_LOW_PRIORITY_DEFAULT_GATEWAY(data, type);
		}
	}

	DBG("status4 %d (%s) status6 %d (%s)",
		status4, strerror(-status4),
		status6, strerror(-status6));

	return (status4 < 0 ? status4 : status6);
}

/**
 *  @brief
 *    Delete all gateway, or default router, default or host routes
 *    for the gateway data, if they are active.
 *
 *  This attempts to delete, or remove, all gateway, or default
 *  router, default or host routes associated with the specified
 *  gateway data, if the corresponding gateway configuration for the
 *  specified type, @a type, is marked as active.
 *
 *  @note
 *    Deletions or removals are restricted to the network interface
 *    associated with the network interface index specified by the
 *    @a data @a index field.
 *
 *  @param[in]  data  A pointer to the mutable gateway data for which
 *                    to delete or remove all gateway, or default
 *                    router, default or host routes, if they are
 *                    active.
 *  @param[in]  type  The IP configuration type for which the gateway,
 *                    or default router, default or host routes are to
 *                    be deleted or removed.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If data is null, if type is
 *                    #CONNMAN_IPCONFIG_TYPE_UNKNOWN, if the routing
 *                    information to be deleted was invalid.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to delete routes.
 *  @retval  -EFAULT  If the address to the routing information to be
 *                    deleted was invalid.
 *  @retval  -ESRCH   A request was made to delete a non-existing
 *                    routing entry.
 *
 *  @sa del_gateway_routes
 *
 */
static int del_gateway_routes_if_active(struct gateway_data *data,
			enum connman_ipconfig_type type)
{
	bool active = false;

	DBG("data %p type %d (%s)", data,
		type, __connman_ipconfig_type2string(type));

	if (!data || type == CONNMAN_IPCONFIG_TYPE_UNKNOWN)
		return -EINVAL;

	GATEWAY_DATA_DBG("data", data);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		if (data->ipv4_config)
			active = is_gateway_config_state_active(
						data->ipv4_config);
	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		if (data->ipv6_config)
			active = is_gateway_config_state_active(
						data->ipv6_config);
	} else if (type == CONNMAN_IPCONFIG_TYPE_ALL)
		active = true;

	DBG("active %u", active);

	if (active)
		return del_gateway_routes(data, type);

	return 0;
}

/**
 *  @brief
 *    Associate, or add, a new gateway, or default router, with a
 *    network service.
 *
 *  This attempts to associate, or add, a new gateway, or default
 *  router, with a network service. On success, a strong (that is,
 *  uses #connman_service_{ref,unref}) reference to @a service is
 *  retained in the service-to-gateway data hash.
 *
 *  @note
 *    The caller is responsible for deallocating the memory assigned
 *    to @a *data on success.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           object with which to associate @a
 *                           gateway. On success, a strong (that is,
 *                           uses #connman_service_{ref,unref})
 *                           reference to this service is retained
 *                           in the service-to-gateway data hash.
 *  @param[in]      index    The network interface index for the
 *                           network interface backing @a service.
 *  @param[in]      gateway  A pointer to an immutable null-
 *                           terminated C string containing the
 *                           text-formatted address of the gateway, or
 *                           default router, with which to associated
 *                           with @a service.
 *  @param[in]      type     The IP configuration type for the gateway,
 *                           or default router.
 *  @param[in,out]  data     A pointer to mutable storage for a mutable
 *                           pointer to a #gateway_data structure. On
 *                           success, this is assigned a newly-
 *                           allocated and added structure that
 *                           associates the @a gateway with @a service
 *                           and @a type. The caller is responsible
 *                           for deallocating the memory assigned to
 *                           @a *data on success.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If service is null, if the network interface @a
 *                    index is invalid, if @a gateway is null or zero
 *                    in length, if type is not
 *                    #CONNMAN_IPCONFIG_TYPE_IPV4 or
 *                    #CONNMAN_IPCONFIG_TYPE_IPV6, or if @a data is
 *                    null.
 *  @retval  -ENOMEM  If memory could not be allocated for the
 *                    #gateway_data structure and its associated
 *                    #gateway_config.
 *
 *  @sa __connman_gateway_add
 *  @sa del_gateway_routes_if_active
 *
 */
static int add_gateway(struct connman_service *service,
					int index, const char *gateway,
					enum connman_ipconfig_type type,
					struct gateway_data **data)
{
	g_autofree struct gateway_data *temp_data = NULL;
	struct gateway_config *config = NULL;
	struct gateway_data *old;
	int err = 0;

	if (!service || index < 0 || !gateway || strlen(gateway) == 0 || !data)
		return -EINVAL;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		break;
	default:
		return -EINVAL;
	}

	temp_data = g_try_new0(struct gateway_data, 1);
	if (!temp_data)
		return -ENOMEM;

	temp_data->index = index;

	config = g_try_new0(struct gateway_config, 1);
	if (!config)
		return -ENOMEM;

	config->state = CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE;
	config->type = CONNMAN_GATEWAY_CONFIG_TYPE_NONE;
	config->flags = CONNMAN_GATEWAY_CONFIG_FLAG_NONE;
	config->gateway = g_strdup(gateway);
	config->vpn_ip = NULL;
	config->vpn_phy_ip = NULL;
	config->vpn_phy_index = -1;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		temp_data->ipv4_config = config;
		temp_data->ipv4_config->ops = &ipv4_gateway_config_ops;
	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		temp_data->ipv6_config = config;
		temp_data->ipv6_config->ops = &ipv6_gateway_config_ops;
	}

	temp_data->service = service;

	/*
	 * If the service is already in the hash, then we
	 * must not replace it blindly but disable the gateway
	 * of the type we are replacing and take the other type
	 * from old gateway settings.
	 */
	old = g_hash_table_lookup(gateway_hash, service);
	if (old) {
		DBG("Replacing gw %p ipv4 %p ipv6 %p", old,
			old->ipv4_config, old->ipv6_config);

		del_gateway_routes_if_active(old, type);

		if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
			temp_data->ipv6_config = old->ipv6_config;
			old->ipv6_config = NULL;
		} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
			temp_data->ipv4_config = old->ipv4_config;
			old->ipv4_config = NULL;
		}
	}

	connman_service_ref(temp_data->service);
	g_hash_table_replace(gateway_hash, service, temp_data);

	*data = g_steal_pointer(&temp_data);

	return err;
}

/**
 *  @brief
 *    Mutate the gateway for the specified IP configuration type for
 *    the provided gateway data.
 *
 *  This attempts to mutate (including, but not limited to, adding/
 *  setting or clearing/deleting/removing routes) the gateway for the
 *  specified IP configuration type for the provided gateway data.
 *
 *  @param[in,out]  data      A pointer to the mutable gateway data
 *                            to mutate.
 *  @param[in]      type      The IP configuration type for which the
 *                            gateway configuration will be selected
 *                            from @a data and used for mutation.
 *  @param[in]      ops       A pointer to the default gateway mutation
 *                            operations to use for the mutation.
 *  @param[in]      function  A pointer to an immutable null-terminated
 *                            C string containing the function name to
 *                            which the call to this function should
 *                            be attributed.
 *
 *  @returns
 *    0 if successful; otherwise, < 0 on error.
 *
 */
static int mutate_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type,
				const struct mutate_default_gateway_ops *ops,
				const char *function)
{
	int status4 = 0, status6 = 0;
	bool do_ipv4 = false, do_ipv6 = false;

	DBG("data %p type %d (%s) ops %p from %s()", data,
		type, __connman_ipconfig_type2string(type),
		ops,
		function);

	if (!data || !ops || !function)
		return -EINVAL;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_ALL)
		do_ipv4 = do_ipv6 = true;
	else
		return -EINVAL;

	GATEWAY_DATA_DBG("data", data);

	if (do_ipv4 && ops->mutate_ipv4 && data->ipv4_config)
		status4 = ops->mutate_ipv4(data, data->ipv4_config);

	if (do_ipv6 && ops->mutate_ipv6 && data->ipv6_config)
		status6 = ops->mutate_ipv6(data, data->ipv6_config);

	DBG("status4 %d (%s) status6 %d (%s)",
		status4, strerror(-status4),
		status6, strerror(-status6));

	return (status4 < 0 ? status4 : status6);
}

/**
 *  @brief
 *    Set, or add, the default route, for the specified gateway data
 *    and configuration using the provided gateway configuration type
 *    and callback function.
 *
 *  This attempts to set, or add, the default route for the specified
 *  gateway data and configuration using the provided gateway
 *  configuration type and callback function.
 *
 *  On success, the gateway configuration type will be set to @a type
 *  and its state to #CONNMAN_GATEWAY_CONFIG_STATE_ADDED.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          set, or add, as the default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to set, or add, as the
 *                          default route.
 *  @param[in]      type    The gateway configuration type that will
 *                          be assigned to @a config on success.
 *  @param[in]      cb      The callback function used to set, or
 *                          add, the default route.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data, @a config, or @a cb are
 *                          null; if the gateway configuration type is
 *                          not #CONNMAN_GATEWAY_CONFIG_TYPE_NONE or
 *                          @a type; or if the routing information to
 *                          be set, or added, was invalid.
 *  @retval  -EINPROGRESS   If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ADDED.
 *  @retval  -EALREADY      If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be set, or added, was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to set, or
 *                          add, routes.
 *  @retval  -EEXIST        A request was made to add an existing
 *                          routing entry.
 *
 *  @sa gateway_config_state_set
 *  @sa gateway_config_type_set
 *  @sa is_gateway_config_state
 *  @sa is_gateway_config_type
 *  @sa unset_default_gateway_route_common
 *
 */
static int set_default_gateway_route_common(struct gateway_data *data,
				struct gateway_config *config,
				enum gateway_config_type type,
				mutate_default_gateway_route_cb_t cb)
{
	int err = 0;

	if (!data || !config || !cb)
		return -EINVAL;

	if ((is_gateway_config_state_added(config) ||
		is_gateway_config_state_active(config)) &&
		!is_gateway_config_type(config, type))
		return -EINVAL;

	if (is_gateway_config_state_added(config))
		return -EINPROGRESS;

	if (is_gateway_config_state_active(config))
		return -EALREADY;

	err = cb(data, config);
	if (err < 0)
		goto done;

	gateway_config_state_set(config,
		CONNMAN_GATEWAY_CONFIG_STATE_ADDED);

	gateway_config_type_set(config, type);

done:
	return err;
}

/**
 *  @brief
 *    Unset, or remove, the default route, for the specified gateway
 *    data and configuration using the provided gateway configuration
 *    type and callback function.
 *
 *  This attempts to unset, or remove, the default route for the
 *  specified gateway data and configuration using the provided
 *  gateway configuration type and callback function.
 *
 *  On success, the gateway configuration state will be set to
 *  #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          unset, or remove, as the default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to unset, or remove, as the
 *                          default route.
 *  @param[in]      type    The gateway configuration type that @a
 *                          config is expected to be.
 *  @param[in]      cb      The callback function used to unset, or
 *                          remove, the default route.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data, @a config, or @a cb are
 *                          null; if the gateway configuration type is
 *                          not @a type; or if the routing information
 *                          to be unset, or cleared, was invalid.
 *  @retval  -EINPROGRESS   If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *  @retval  -EALREADY      If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be unset, or cleared, was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to unset, or
 *                          clear, routes.
 *
 *  @sa gateway_config_state_set
 *  @sa is_gateway_config_state
 *  @sa is_gateway_config_type
 *  @sa set_default_gateway_route_common
 *
 */
static int unset_default_gateway_route_common(struct gateway_data *data,
				struct gateway_config *config,
				enum gateway_config_type type,
				mutate_default_gateway_route_cb_t cb)
{
	int err = 0;

	if (!data || !config || !cb)
		return -EINVAL;

	if (!is_gateway_config_state_inactive(config) &&
		!is_gateway_config_type(config, type))
		return -EINVAL;

	if (is_gateway_config_state_removed(config))
		return -EINPROGRESS;

	if (is_gateway_config_state_inactive(config))
		return -EALREADY;

	/*
	 * Generally, we mandate that gateway routes follow the documented
	 * lifecycle and state machine, using events and down- and upcalls
	 * to drive the lifecycle.
	 *
	 * There is one exception, however. When the Linux kernel
	 * recognizes that the next hop (that is, the "via" or RTA_GATEWAY
	 * part of the route) for a route becomes unreachable, it is
	 * automatically purged from the routing table with no
	 * RTM_DELROUTE RTNL notification. Consequently, routes so purged
	 * will return -ESRCH when we attempt to delete them here in the
	 * mistaken belief they are still there.
	 *
	 * Map -ESRCH to success such that gateway configuration for such
	 * routes is not indefinitely stuck in the "active" or "added"
	 * states.
	 */
	err = cb(data, config);
	if (err == -ESRCH)
		err = 0;
	else if (err < 0)
		goto done;

	gateway_config_state_set(config,
		CONNMAN_GATEWAY_CONFIG_STATE_REMOVED);

done:
	return err;
}

/**
 *  @brief
 *    Set, or add, the IPv4 high-priority default route for the
 *    specified gateway data and configuration using a function
 *    utilizing a SIOCADDRT socket ioctl or a RTM_NEWROUTE Linux
 *    Routing Netlink (rtnl) command.
 *
 *  This attempts to set, or add, the IPv4 high-priority (that is,
 *  metric 0) default route for the specified gateway data and
 *  configuration using a function utilizing a SIOCADDRT socket ioctl
 *  or a RTM_NEWROUTE Linux Routing Netlink (rtnl) command to modify
 *  the Linux routing table.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          use to set, or add, the IPv4 high-priority
 *                          default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to use to set, or add,
 *                          the IPv4 high-priority default route.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If @a data or @a config are null; or if
 *                    the routing information to be set, or
 *                    added, was invalid.
 *  @retval  -EFAULT  If the address to the routing information
 *                    to be set, or added, was invalid.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to set, or
 *                    add, routes.
 *  @retval  -EEXIST  A request was made to add an existing
 *                    routing entry.
 *
 *  @sa connman_inet_set_gateway_interface
 *  @sa __connman_inet_add_default_to_table
 *
 */
static int set_ipv4_high_priority_default_gateway_route_cb(
				struct gateway_data *data,
				struct gateway_config *config)
{
	int err = 0;

	if (is_gateway_config_vpn(config)) {
		err = config->ops->add_interface_route(data->index);
		if (err < 0)
			goto done;

		DBG("set %p index %d vpn %s index %d phy %s",
			data, data->index, config->vpn_ip,
			config->vpn_phy_index,
			config->vpn_phy_ip);
	} else if (is_addr_any_str(config->gateway)) {
		err = config->ops->add_interface_route(data->index);
		if (err < 0)
			goto done;

		DBG("set %p index %d",
			data, data->index);
	} else {
		err = config->ops->add_default_route(
					RT_TABLE_MAIN,
					data->index,
					config->gateway);
		if (err < 0)
			goto done;

		DBG("set %p index %d gateway %s",
			data, data->index, config->gateway);
	}

done:
	return err;
}

/**
 *  @brief
 *    Set, or add, the IPv6 high-priority default route for the
 *    specified gateway data and configuration using a function
 *    utilizing a SIOCADDRT socket ioctl or a RTM_NEWROUTE Linux
 *    Routing Netlink (rtnl) command.
 *
 *  This attempts to set, or add, the IPv6 high-priority (that is,
 *  metric 0) default route for the specified gateway data and
 *  configuration using a function utilizing a SIOCADDRT socket ioctl
 *  or a RTM_NEWROUTE Linux Routing Netlink (rtnl) command to modify
 *  the Linux routing table.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          use to set, or add, the IPv6 high-priority
 *                          default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to use to set, or add,
 *                          the IPv6 high-priority default route.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If @a data or @a config are null; or if
 *                    the routing information to be set, or
 *                    added, was invalid.
 *  @retval  -EFAULT  If the address to the routing information
 *                    to be set, or added, was invalid.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to set, or
 *                    add, routes.
 *  @retval  -EEXIST  A request was made to add an existing
 *                    routing entry.
 *
 *  @sa connman_inet_set_ipv6_gateway_interface
 *  @sa __connman_inet_add_default_to_table
 *
 */
static int set_ipv6_high_priority_default_gateway_route_cb(
				struct gateway_data *data,
				struct gateway_config *config)
{
	int err = 0;

	if (is_gateway_config_vpn(config)) {
		err = config->ops->add_interface_route(data->index);
		if (err < 0)
			goto done;

		DBG("set %p index %d vpn %s index %d phy %s",
			data, data->index, config->vpn_ip,
			config->vpn_phy_index,
			config->vpn_phy_ip);
	} else if (is_addr_any_str(config->gateway)) {
		err = config->ops->add_interface_route(data->index);
		if (err < 0)
			goto done;

		DBG("set %p index %d",
			data, data->index);
	} else {
		err = config->ops->add_default_route(
					RT_TABLE_MAIN,
					data->index,
					config->gateway);
		if (err < 0)
			goto done;

		DBG("set %p index %d gateway %s",
			data, data->index, config->gateway);
	}

done:
	return err;
}

/**
 *  @brief
 *    Set, or add, the IPv4 high-priority default route for the
 *    specified gateway data and configuration.
 *
 *  This attempts to set, or add, the IPv4 high-priority (that is,
 *  metric 0) default route for the specified gateway data and
 *  configuration.
 *
 *  On success, the gateway configuration type will be set to
 *  #CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT and its state
 *  to #CONNMAN_GATEWAY_CONFIG_STATE_ADDED.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          assign as the IPv4 high-priority default
 *                          route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to assign as the IPv4
 *                          high-priority default route.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data or @a config are
 *                          null; if the gateway configuration type is
 *                          not #CONNMAN_GATEWAY_CONFIG_TYPE_NONE or
 *                          #CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT;
 *                          or if the routing information to be set,
 *                          or added, was invalid.
 *  @retval  -EINPROGRESS   If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ADDED.
 *  @retval  -EALREADY      If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be added was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to add, or
 *                          set, routes.
 *  @retval  -EEXIST        A request was made to add an existing
 *                          routing entry.
 *
 *  @sa set_default_gateway_route_common
 *  @sa set_ipv4_high_priority_default_gateway_func
 *
 */
static int set_ipv4_high_priority_default_gateway(struct gateway_data *data,
				struct gateway_config *config)
{
	static const enum gateway_config_type type =
			CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT;
	static const mutate_default_gateway_route_cb_t cb =
			set_ipv4_high_priority_default_gateway_route_cb;

	return set_default_gateway_route_common(data, config, type, cb);
}

/**
 *  @brief
 *    Set, or add, the IPv6 high-priority default route for the
 *    specified gateway data and configuration.
 *
 *  This attempts to set, or add, the IPv6 high-priority (that is,
 *  metric 0) default route for the specified gateway data and
 *  configuration.
 *
 *  On success, the gateway configuration type will be set to
 *  #CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT and its state
 *  to #CONNMAN_GATEWAY_CONFIG_STATE_ADDED.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          assign as the IPv6 high-priority default
 *                          route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to assign as the IPv6
 *                          high-priority default route.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data or @a config are
 *                          null; if the gateway configuration type is
 *                          not #CONNMAN_GATEWAY_CONFIG_TYPE_NONE or
 *                          #CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT;
 *                          or if the routing information to be set,
 *                          or added, was invalid.
 *  @retval  -EINPROGRESS   If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ADDED.
 *  @retval  -EALREADY      If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be added was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to add, or
 *                          set, routes.
 *  @retval  -EEXIST        A request was made to add an existing
 *                          routing entry.
 *
 *  @sa set_default_gateway_route_common
 *  @sa set_ipv6_high_priority_default_gateway_route_cb
 *
 */
static int set_ipv6_high_priority_default_gateway(struct gateway_data *data,
				struct gateway_config *config)
{
	static const enum gateway_config_type type =
			CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT;
	static const mutate_default_gateway_route_cb_t cb =
			set_ipv6_high_priority_default_gateway_route_cb;

	return set_default_gateway_route_common(data, config, type, cb);
}

/**
 *  @brief
 *    Set, or add, the gateway high-priority default route for the
 *    specified IP configuration type from the provided gateway data.
 *
 *  This attempts to set, or add, the high-priority (that is,
 *  metric 0) default route for the specified IP configuration type
 *  from the provided gateway data. The network interface and, by
 *  extension, the network service with which the gateway is
 *  associated is determined by the @a index field of @a data.
 *
 *  On success, the gateway configuration state and type specific to
 *  @a type will be set to #CONNMAN_GATEWAY_CONFIG_STATE_ADDED and
 *  #CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT, respectively,
 *  and the gateway data network service @a service will be signaled
 *  as the default via #__connman_service_indicate_default.
 *
 *  @param[in,out]  data      A pointer to the mutable gateway data
 *                            to assign as the high-priority default
 *                            route.
 *  @param[in]      type      The IP configuration type for which the
 *                            gateway, or default router,
 *                            configuration will be selected from @a
 *                            data and used to set the high-priority
 *                            default route.
 *  @param[in]      function  A pointer to an immutable null-terminated
 *                            C string containing the function name to
 *                            which the call to this function should
 *                            be attributed.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data or @a config are
 *                          null; if the gateway configuration type is
 *                          not #CONNMAN_GATEWAY_CONFIG_TYPE_NONE or
 *                          #CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT;
 *                          or if the routing information to be set,
 *                          or added, was invalid.
 *  @retval  -EINPROGRESS   If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ADDED.
 *  @retval  -EALREADY      If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be added was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to add, or
 *                          set, routes.
 *  @retval  -EEXIST        A request was made to add an existing
 *                          routing entry.
 *
 *  @sa mutate_default_gateway
 *  @sa set_ipv4_high_priority_default_gateway
 *  @sa set_ipv6_high_priority_default_gateway
 *
 */
static int set_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type,
				const char *function)
{
	static const struct mutate_default_gateway_ops ops = {
		set_ipv4_high_priority_default_gateway,
		set_ipv6_high_priority_default_gateway
	};
	int status = 0;

	DBG("from %s()", function);

	status = mutate_default_gateway(data, type, &ops, __func__);
	if (status < 0)
		goto done;

	__connman_service_indicate_default(data->service);

done:
	return status;
}

/**
 *  @brief
 *    Unset, or remove, the IPv4 high-priority default route for the
 *    specified gateway data and configuration using a function
 *    utilizing a SIOCDELRT socket ioctl or a RTM_DELROUTE Linux
 *    Routing Netlink (rtnl) command.
 *
 *  This attempts to unset, or remove, the IPv4 high-priority (that
 *  is, metric 0) default route for the specified gateway data and
 *  configuration using a function utilizing a SIOCDELRT socket ioctl
 *  or a RTM_DELROUTE Linux Routing Netlink (rtnl) command to modify
 *  the Linux routing table.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          use to unset, or remove, the IPv4
 *                          high-priority default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to use to unset, or remove,
 *                          the IPv4 high-priority default route.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If @a data or @a config are null; or if
 *                    the routing information to be unset, or
 *                    removed, was invalid.
 *  @retval  -EFAULT  If the address to the routing information
 *                    to be set, or added, was invalid.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to set, or
 *                    add, routes.
 *  @retval  -ESRCH   A request was made to delete a non-existing
 *                    routing entry.
 *
 *  @sa connman_inet_clear_gateway_interface
 *  @sa connman_inet_clear_gateway_address
 *
 */
static int unset_ipv4_high_priority_default_gateway_route_cb(
				struct gateway_data *data,
				struct gateway_config *config)
{
	int err = 0;

	if (is_gateway_config_vpn(config)) {
		err = config->ops->del_interface_route(data->index);
		if (err < 0)
			goto done;

		DBG("unset %p index %d vpn %s index %d phy %s",
			data, data->index, config->vpn_ip,
			config->vpn_phy_index,
			config->vpn_phy_ip);
	} else if (is_addr_any_str(config->gateway)) {
		err = config->ops->del_interface_route(data->index);
		if (err < 0)
			goto done;

		DBG("unset %p index %d",
			data, data->index);
	} else {
		err = config->ops->del_default_route(
					RT_TABLE_MAIN,
					data->index,
					config->gateway);
		if (err < 0)
			goto done;

		DBG("unset %p index %d gateway %s",
			data, data->index, config->gateway);
	}

done:
	return err;
}

/**
 *  @brief
 *    Unset, or remove, the IPv6 high-priority default route for the
 *    specified gateway data and configuration using a function
 *    utilizing a SIOCDELRT socket ioctl or a RTM_DELROUTE Linux
 *    Routing Netlink (rtnl) command.
 *
 *  This attempts to unset, or remove, the IPv6 high-priority (that
 *  is, metric 0) default route for the specified gateway data and
 *  configuration using a function utilizing a SIOCDELRT socket ioctl
 *  or a RTM_DELROUTE Linux Routing Netlink (rtnl) command to modify
 *  the Linux routing table.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          use to unset, or remove, the IPv6
 *                          high-priority default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to use to unset, or remove,
 *                          the IPv6 high-priority default route.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If @a data or @a config are null; or if
 *                    the routing information to be unset, or
 *                    removed, was invalid.
 *  @retval  -EFAULT  If the address to the routing information
 *                    to be set, or added, was invalid.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to set, or
 *                    add, routes.
 *  @retval  -ESRCH   A request was made to delete a non-existing
 *                    routing entry.
 *
 *  @sa connman_inet_clear_ipv6_gateway_interface
 *  @sa connman_inet_clear_ipv6_gateway_address
 *
 */
static int unset_ipv6_high_priority_default_gateway_route_cb(
				struct gateway_data *data,
				struct gateway_config *config)
{
	int err = 0;

	if (is_gateway_config_vpn(config)) {
		err = config->ops->del_interface_route(data->index);
		if (err < 0)
			goto done;

		DBG("unset %p index %d vpn %s index %d phy %s",
			data, data->index, config->vpn_ip,
			config->vpn_phy_index,
			config->vpn_phy_ip);
	} else if (is_addr_any_str(config->gateway)) {
		err = config->ops->del_interface_route(data->index);
		if (err < 0)
			goto done;

		DBG("unset %p index %d",
			data, data->index);
	} else {
		err = config->ops->del_default_route(
					RT_TABLE_MAIN,
					data->index,
					config->gateway);
		if (err < 0)
			goto done;

		DBG("unset %p index %d gateway %s",
			data, data->index, config->gateway);
	}

done:
	return err;
}

/**
 *  @brief
 *    Unset, or clear, the IPv4 high-priority default route for the
 *    specified gateway data and configuration.
 *
 *  This attempts to unset, or clear, the IPv4 high-priority (that is,
 *  metric 0) default route from the provided gateway data and
 *  configuration.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          use to unset, or remove, the IPv4
 *                          high-priority default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to use to unset, or remove,
 *                          the IPv4 high-priority default route.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If @a data or @a config are null; or if
 *                    the routing information to be unset, or
 *                    removed, was invalid.
 *  @retval  -EFAULT  If the address to the routing information
 *                    to be unset, or cleared, was invalid.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to unset, or
 *                    clear, routes.
 *  @retval  -ESRCH   A request was made to unset, or clear a
 *                    non-existing routing entry.
 *
 *  @sa unset_default_gateway_route_common
 *  @sa unset_ipv4_high_priority_default_gateway_route_cb
 *
 */
static int unset_ipv4_high_priority_default_gateway(
				struct gateway_data *data,
				struct gateway_config *config)
{
	static const enum gateway_config_type type =
			CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT;
	static const mutate_default_gateway_route_cb_t cb =
			unset_ipv4_high_priority_default_gateway_route_cb;

	return unset_default_gateway_route_common(data, config, type, cb);
}

/**
 *  @brief
 *    Unset, or clear, the IPv6 high-priority default route for the
 *    specified gateway data and configuration.
 *
 *  This attempts to unset, or clear, the IPv6 high-priority (that is,
 *  metric 0) default route from the provided gateway data and
 *  configuration.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          use to unset, or remove, the IPv6
 *                          high-priority default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to use to unset, or remove,
 *                          the IPv6 high-priority default route.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If @a data or @a config are null; or if
 *                    the routing information to be unset, or
 *                    removed, was invalid.
 *  @retval  -EFAULT  If the address to the routing information
 *                    to be unset, or cleared, was invalid.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to unset, or
 *                    clear, routes.
 *  @retval  -ESRCH   A request was made to unset, or clear a
 *                    non-existing routing entry.
 *
 *  @sa unset_default_gateway_route_common
 *  @sa unset_ipv6_high_priority_default_gateway_route_cb
 *
 */
static int unset_ipv6_high_priority_default_gateway(
				struct gateway_data *data,
				struct gateway_config *config)
{
	static const enum gateway_config_type type =
			CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT;
	static const mutate_default_gateway_route_cb_t cb =
			unset_ipv6_high_priority_default_gateway_route_cb;

	return unset_default_gateway_route_common(data, config, type, cb);
}

/**
 *  @brief
 *    Unset the high-priority default route for the specified IP
 *    configuration type from the provided gateway data.
 *
 *  This attempts to unset, or clear, the high-priority (that is,
 *  metric 0) default route for the specified IP configuration type
 *  from the provided gateway data. The network interface and, by
 *  extension, the network service with which the gateway is
 *  associated is determined by the @a index field of @a data.
 *
 *  On success, the gateway configuration state specific to @a type
 *  will be set to #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *
 *  @param[in,out]  data      A pointer to the mutable gateway data
 *                            to clear as the high-priority default
 *                            route.
 *  @param[in]      type      The IP configuration type for which
 *                            the gateway, or default router,
 *                            configuration will be selected from @a
 *                            data and used to unset the high-priority
 *                            default route.
 *  @param[in]      function  A pointer to an immutable null-terminated
 *                            C string containing the function name to
 *                            which the call to this function should
 *                            be attributed.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data is null, if @a type is invalid,
 *                          if the gateway configuration type is not
 *                          type
 *                          #CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT,
 *                          or if the routing information to be unset,
 *                          or cleared, was invalid.
 *  @retval  -EINPROGRESS   If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *  @retval  -EALREADY      If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be unset, or cleared, was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to unset, or
 *                          clear, routes.
 *  @retval  -ESRCH         A request was made to unset, or clear a
 *                          non-existing routing entry.
 *
 *  @sa mutate_default_gateway
 *  @sa unset_ipv4_default_gateway
 *  @sa unset_ipv6_default_gateway
 *
 */
static int unset_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type,
				const char *function)
{
	static const struct mutate_default_gateway_ops ops = {
		unset_ipv4_high_priority_default_gateway,
		unset_ipv6_high_priority_default_gateway
	};

	DBG("from %s()", function);

	return mutate_default_gateway(data, type, &ops, __func__);
}

/**
 *  @brief
 *    Compute and return a low-priority gateway default route metric
 *    unique to the specified gateway data.
 *
 *  This computes and returns a low-priority gateway default route
 *  metric unique to the specified gateway data, @a data.
 *
 *  @param[in]  data  A pointer to the immutable gateway data with
 *                    which to compute the low-priority default route
 *                    metric.
 *
 *  @returns
 *    The low-priority default route metric/priority.
 *
 */
static uint32_t compute_low_priority_metric(const struct gateway_data *data)
{
	static const uint32_t metric_base = UINT32_MAX;
	static const uint32_t metric_ceiling = (1 << 20);
	static const uint32_t metric_index_step = (1 << 10);

	/*
	 * The algorithm uses the network interface index since it is
	 * assumed to be stable for the uptime of the network interface
	 * and, consequently, the potential maximum lifetime of the route.
	 *
	 * The algorithm establishes UINT32_MAX as the metric base (the
	 * lowest possible priority) and a somewhat-arbitrary 2^20 as the
	 * ceiling (to keep metrics out of a range that might be used by
	 * other applications). The metric is then adjusted in increments
	 * of 1,024 (2^10) from the base, but less than the ceiling, by
	 * multiplying the increment by the network interface index. This
	 * is easy and simple to compute and is invariant on service
	 * order.
	 *
	 * In the fullness of time, the "rule of least astonishment" for
	 * Connection Manager might be that low priority metrics follow
	 * the service order with the default service always having metric
	 * zero (0) and lowest priority metric assigned to the lowest
	 * priority service, etc. Achieving this would require 1) caching
	 * the computed metric in the gateway data since services may
	 * re-sort by the time we are asked to recompute high- and
	 * low-priority routes and we need a stable and matching metric to
	 * successfully delete a previously-created route and 2) having
	 * access to an API (such as
	 * '__connman_service_get_order(data->service)') that exposes a
	 * strictly-in/decreasing service order with no duplicates. Today,
	 * there is no such API nor is there such a durable service order
	 * meeting that mathematical requirement.
	 */
	return MAX(metric_ceiling,
				metric_base -
				(data->index * metric_index_step));
}

/**
 *  @brief
 *    Set, or add, the IPv4 low-priority default route for the
 *    specified gateway data and configuration using a function
 *    utilizing a SIOCADDRT socket ioctl or a RTM_NEWROUTE Linux
 *    Routing Netlink (rtnl) command.
 *
 *  This attempts to set, or add, the IPv4 low-priority (that is,
 *  metric > 0) default route for the specified gateway data and
 *  configuration using a function utilizing a SIOCADDRT socket ioctl
 *  or a RTM_NEWROUTE Linux Routing Netlink (rtnl) command to modify
 *  the Linux routing table.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          use to set, or add, the IPv4 low-priority
 *                          default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to use to set, or add, the
 *                          IPv4 low-priority default route.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If @a data or @a config are null; or if
 *                    the routing information to be set, or
 *                    added, was invalid.
 *  @retval  -EFAULT  If the address to the routing information
 *                    to be set, or added, was invalid.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to set, or
 *                    add, routes.
 *  @retval  -EEXIST  A request was made to add an existing
 *                    routing entry.
 *
 *  @sa connman_inet_set_gateway_interface
 *  @sa __connman_inet_add_default_to_table
 *
 */
static int set_ipv4_low_priority_default_gateway_route_cb(
				struct gateway_data *data,
				struct gateway_config *config)
{
	const uint32_t metric = compute_low_priority_metric(data);

	DBG("using metric %u for index %d", metric, data->index);

	return config->ops->add_default_route_with_metric(
				RT_TABLE_MAIN,
				data->index,
				config->gateway,
				metric);
}

/**
 *  @brief
 *    Set, or add, the IPv4 low-priority default route for the
 *    specified gateway data and configuration.
 *
 *  This attempts to set, or add, the IPv4 low-priority (that is,
 *  metric > 0) default route for the specified gateway data and
 *  configuration.
 *
 *  On success, the gateway configuration type will be set to
 *  #CONNMAN_GATEWAY_CONFIG_TYPE_LOW_PRIORITY_DEFAULT and its state
 *  to #CONNMAN_GATEWAY_CONFIG_STATE_ADDED.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          assign as the IPv4 low-priority default
 *                          route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to assign as the IPv4
 *                          low-priority default route.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data or @a config are
 *                          null; if the gateway configuration type is
 *                          not #CONNMAN_GATEWAY_CONFIG_TYPE_NONE or
 *                          #CONNMAN_GATEWAY_CONFIG_TYPE_LOW_PRIORITY_DEFAULT;
 *                          or if the routing information to be set,
 *                          or added, was invalid.
 *  @retval  -EINPROGRESS   If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ADDED.
 *  @retval  -EALREADY      If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be added was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to add, or
 *                          set, routes.
 *  @retval  -EEXIST        A request was made to add an existing
 *                          routing entry.
 *
 *  @sa set_default_gateway_route_common
 *  @sa set_ipv4_low_priority_default_gateway_route_cb
 *
 */
static int set_ipv4_low_priority_default_gateway(
				struct gateway_data *data,
				struct gateway_config *config)
{
	static const enum gateway_config_type type =
			CONNMAN_GATEWAY_CONFIG_TYPE_LOW_PRIORITY_DEFAULT;
	static const mutate_default_gateway_route_cb_t cb =
			set_ipv4_low_priority_default_gateway_route_cb;

	return set_default_gateway_route_common(data, config, type, cb);
}

/**
 *  @brief
 *    Set, or add, the gateway low-priority default route for the
 *    specified IP configuration type from the provided gateway data.
 *
 *  This attempts to set, or add, the low-priority (that is, metric
 *  > 0) default route for the specified IP configuration type from
 *  the provided gateway data. The network interface and, by
 *  extension, the network service with which the gateway is
 *  associated is determined by the @a index field of @a data.
 *
 *  On success, the gateway configuration state and type specific to
 *  @a type will be set to #CONNMAN_GATEWAY_CONFIG_STATE_ADDED and
 *  #CONNMAN_GATEWAY_CONFIG_TYPE_LOW_PRIORITY_DEFAULT, respectively.
 *
 *  @param[in,out]  data      A pointer to the mutable gateway data
 *                            to assign as the low-priority default
 *                            route.
 *  @param[in]      type      The IP configuration type for which the
 *                            gateway, or default router,
 *                            configuration will be selected from @a
 *                            data and used to set the low-priority
 *                            default route.
 *  @param[in]      function  A pointer to an immutable null-terminated
 *                            C string containing the function name to
 *                            which the call to this function should
 *                            be attributed.
 *
 *  @sa mutate_default_gateway
 *  @sa set_ipv4_low_priority_default_gateway
 *
 */
static int set_low_priority_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type,
				const char *function)
{
	static const struct mutate_default_gateway_ops ops = {
		set_ipv4_low_priority_default_gateway,
		NULL
	};

	DBG("from %s()", function);

	return mutate_default_gateway(data, type, &ops, __func__);
}

/**
 *  @brief
 *    Unset, or remove, the IPv4 low-priority default route for the
 *    specified gateway data and configuration using a function
 *    utilizing a SIOCDELRT socket ioctl or a RTM_DELROUTE Linux
 *    Routing Netlink (rtnl) command.
 *
 *  This attempts to unset, or remove, the IPv4 low-priority (that
 *  is, metric > 0) default route for the specified gateway data and
 *  configuration using a function utilizing a SIOCDELRT socket ioctl
 *  or a RTM_DELROUTE Linux Routing Netlink (rtnl) command to modify
 *  the Linux routing table.
 *
 *  @param[in,out]  data    A pointer to the mutable gateway data to
 *                          use to unset, or remove, the IPv4
 *                          low-priority default route.
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                          configuration to use to unset, or remove,
 *                          the IPv4 low-priority default route.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If @a data or @a config are null; or if
 *                    the routing information to be set, or
 *                    added, was invalid.
 *  @retval  -EFAULT  If the address to the routing information
 *                    to be set, or added, was invalid.
 *  @retval  -EPERM   If the current process does not have the
 *                    credentials or capabilities to set, or
 *                    add, routes.
 *  @retval  -ESRCH   A request was made to delete a non-existing
 *                    routing entry.
 *
 *  @sa __connman_inet_del_default_from_table_with_metric;
 *
 */
static int unset_ipv4_low_priority_default_gateway_route_cb(
				struct gateway_data *data,
				struct gateway_config *config)
{
	const uint32_t metric = compute_low_priority_metric(data);

	DBG("using metric %u for index %d", metric, data->index);

	return config->ops->del_default_route_with_metric(
				RT_TABLE_MAIN,
				data->index,
				config->gateway,
				metric);
}

/**
 *  @brief
 *    Unset the IPv4 low-priority default route for the specified IP
 *    configuration type from the provided gateway data.
 *
 *  This attempts to unset, or clear, the IPv4 low-priority (that is,
 *  metric > 0) default route for the specified IP configuration type
 *  from the provided gateway data. The network interface and, by
 *  extension, the network service with which the gateway is
 *  associated is determined by the @a index field of @a data.
 *
 *  On success, the gateway configuration state will be set to
 *  #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *
 *  @param[in,out]  data  A pointer to the mutable gateway data to
 *                        clear as the IPv4 low-priority default
 *                        route.
 *  @param[in]      type  The IP configuration type for which the
 *                        gateway, or default router, configuration
 *                        will be selected from @a data and used to
 *                        unset the IPv4 low-priority default route.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data or @a config are null, if the
 *                          gateway configuration type is not
 *                          #CONNMAN_GATEWAY_CONFIG_TYPE_LOW_PRIORITY_DEFAULT,
 *                          or if the routing information to be unset,
 *                          or cleared, was invalid.
 *  @retval  -EINPROGRESS   If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *  @retval  -EALREADY      If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be unset, or cleared, was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to unset, or
 *                          clear, routes.
 *  @retval  -ESRCH         A request was made to unset, or clear a
 *                          non-existing routing entry.
 *
 *  @sa unset_default_gateway_route_common
 *  @sa unset_ipv4_low_priority_default_gateway_route_cb
 *
 */
static int unset_ipv4_low_priority_default_gateway(struct gateway_data *data,
				struct gateway_config *config)
{
	static const enum gateway_config_type type =
			CONNMAN_GATEWAY_CONFIG_TYPE_LOW_PRIORITY_DEFAULT;
	static const mutate_default_gateway_route_cb_t cb =
			unset_ipv4_low_priority_default_gateway_route_cb;

	return unset_default_gateway_route_common(data, config, type, cb);
}

/**
 *  @brief
 *    Unset the low-priority default route for the specified IP
 *    configuration type from the provided gateway data.
 *
 *  This attempts to unset, or clear, the low-priority (that is,
 *  metric > 0) default route for the specified IP configuration type
 *  from the provided gateway data. The network interface and, by
 *  extension, the network service with which the gateway is
 *  associated is determined by the @a index field of @a data.
 *
 *  On success, the gateway configuration state specific to @a type
 *  will be set to #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *
 *  @param[in,out]  data  A pointer to the mutable gateway data to
 *                        clear as the low-priority default route.
 *  @param[in]      type  The IP configuration type for which the
 *                        gateway, or default router, configuration
 *                        will be selected from @a data and used to
 *                        unset the low-priority default route.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data is null, if @a type is invalid,
 *                          if the gateway configuration type is not
 *                          type
 *                          #CONNMAN_GATEWAY_CONFIG_TYPE_LOW_PRIORITY_DEFAULT,
 *                          or if the routing information to be unset,
 *                          or cleared, was invalid.
 *  @retval  -EINPROGRESS   If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *  @retval  -EALREADY      If the state of @a config is
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be unset, or cleared, was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to unset, or
 *                          clear, routes.
 *  @retval  -ESRCH         A request was made to unset, or clear a
 *                          non-existing routing entry.
 *
 *  @sa mutatate_default_gateway
 *  @sa unset_ipv4_low_priority_default_gateway
 *
 */
static int unset_low_priority_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type,
				const char *function)
{
	static const struct mutate_default_gateway_ops ops = {
		unset_ipv4_low_priority_default_gateway,
		NULL
	};

	DBG("from %s()", function);

	return mutate_default_gateway(data, type, &ops, __func__);
}

/**
 *  @brief
 *    Demote, from high- to low-priority, the default route associated
 *    with the specified gateway data and IP configuration type.
 *
 *  This attempts to demote, from high- (that is, metric 0) to low-
 *  (that is, metric > 0) priority, the default route associated with
 *  the specified gateway data and IP configuration type.
 *
 *  @param[in,out]  data      The gateway data associated with the
 *                            default route for which the priority is
 *                            to be demoted.
 *  @param[in]      type      The IP configuration type for which
 *                            the gateway, or default router, is to be
 *                            demoted.
 *  @param[in]      function  A pointer to an immutable null-terminated
 *                            C string containing the function name to
 *                            which the call to this function should be
 *                            attributed.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data is null, if @a type is
 *                          #CONNMAN_IPCONFIG_TYPE_UNKNOWN, if the
 *                          gateway configuration type is invalid; or
 *                          if the routing information to be added or
 *                          deleted was invalid.
 *  @retval  -EINPROGRESS   If the state of the gateway configuration
 *                          for @a data is already
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ADDED or
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *  @retval  -EALREADY      If the state of the gateway configuration
 *                          for @a data is already
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE or
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be added or deleted was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to add or
 *                          delete routes.
 *  @retval  -EEXIST        A request was made to add an existing
 *                          routing entry.
 *  @retval  -ESRCH         A request was made to delete a non-
 *                          existing routing entry.
 *
 *  @sa unset_default_gateway
 *  @sa set_low_priority_default_gateway
 *  @sa promote_default_gateway
 *
 */
static int demote_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type,
				const char *function)
{
	int unset_status = 0, set_status = 0;

	DBG("from %s() data %p type %d (%s)",
		function,
		data,
		type, __connman_ipconfig_type2string(type));

	unset_status = UNSET_DEFAULT_GATEWAY(data, type);

	set_status = SET_LOW_PRIORITY_DEFAULT_GATEWAY(data, type);

	DBG("unset_status %d (%s) set_status %d (%s)",
		unset_status, strerror(-unset_status),
		set_status, strerror(-set_status));

	/*
	 * Prefer unset status to set status since unsetting is what effects
	 * the priority demotion.
	 */
	return (unset_status == 0 ? unset_status : set_status);
}

/**
 *  @brief
 *    Promote, from low- to high-priority, the default route
 *    associated with the specified gateway data and IP configuration
 *    type.
 *
 *  This attempts to promote, from low- (that is, metric > 0) to high-
 *  (that is, metric 0) priority, the default route associated with
 *  the specified gateway data and IP configuration type.
 *
 *  @param[in,out]  data      The gateway data associated with the
 *                            default route for which the priority is
 *                            to be promoted.
 *  @param[in]      type      The IP configuration type for which
 *                            the gateway, or default router, is to be
 *                            promoted.
 *  @param[in]      function  A pointer to an immutable null-terminated
 *                            C string containing the function name to
 *                            which the call to this function should be
 *                            attributed.
 *
 *  @retval  0              If successful.
 *  @retval  -EINVAL        If @a data is null, if @a type is
 *                          #CONNMAN_IPCONFIG_TYPE_UNKNOWN, if the
 *                          gateway configuration type is invalid; or
 *                          if the routing information to be added or
 *                          deleted was invalid.
 *  @retval  -EINPROGRESS   If the state of the gateway configuration
 *                          for @a data is already
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ADDED or
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_REMOVED.
 *  @retval  -EALREADY      If the state of the gateway configuration
 *                          for @a data is already
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_ACTIVE or
 *                          #CONNMAN_GATEWAY_CONFIG_STATE_INACTIVE.
 *  @retval  -EFAULT        If the address to the routing information
 *                          to be added or deleted was invalid.
 *  @retval  -EPERM         If the current process does not have the
 *                          credentials or capabilities to add or
 *                          delete routes.
 *  @retval  -EEXIST        A request was made to add an existing
 *                          routing entry.
 *  @retval  -ESRCH         A request was made to delete a non-
 *                          existing routing entry.
 *
 *  @sa set_default_gateway
 *  @sa unset_low_priority_default_gateway
 *  @sa demote_default_gateway
 *
 */
static int promote_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type,
				const char *function)
{
	int unset_status = 0, set_status = 0;

	DBG("from %s() data %p type %d (%s)",
		function,
		data,
		type, __connman_ipconfig_type2string(type));

	unset_status = UNSET_LOW_PRIORITY_DEFAULT_GATEWAY(data, type);

	set_status = SET_DEFAULT_GATEWAY(data, type);

	DBG("unset_status %d (%s) set_status %d (%s)",
		unset_status, strerror(-unset_status),
		set_status, strerror(-set_status));

	/*
	 * Prefer set status to unset status since setting is what effects
	 * the priority promotion.
	 */
	return (set_status == 0 ? set_status : unset_status);
}

/**
 *  @brief
 *    Decide whether either of the specified gateways should yield the
 *    default gateway route.
 *
 *  This determines whether either of the specified gateway data
 *  should yield the IP-specific default gateway route via
 *  #unset_default_gateway. @a activated is a newly-activated gateway
 *  from a Routing Netlink (rtnl) notification. @a existing is an
 *  existing gateway from the services-to-gateway data hash.
 *
 *  @param[in,out]  activated  A pointer to a mutable newly-activated
 *                             gateway from a Routing Netlink (rtnl)
 *                             notification.
 *  @param[in,out]  existing   A pointer to a mutable existing
 *                             gateway from the services-to-gateway
 *                             hash.
 *  @param[in]      type       The IP configuration type for which
 *                             gateway, or default router, is to be
 *                             yielded.
 *
 *  @returns
 *    True if @a activated yielded the IP-specific default gateway;
 *    otherwise, false.
 *
 *  @sa __connman_service_compare
 *  @sa unset_default_gateway
 *  @sa yield_default_gateway
 *
 */
static bool yield_default_gateway_for_type(struct gateway_data *activated,
					struct gateway_data *existing,
					enum connman_ipconfig_type type)
{
	static const enum gateway_config_type config_type =
		CONNMAN_GATEWAY_CONFIG_TYPE_HIGH_PRIORITY_DEFAULT;
	const struct gateway_config *const activated_config =
		gateway_data_config_get(activated, type);
	const struct gateway_config *const existing_config =
		gateway_data_config_get(existing, type);
	bool yield_activated = false;

	DBG("activated data %p config %p "
		"existing data %p config %p "
		"type %d (%s)",
		activated, activated_config,
		existing, existing_config,
		type, __connman_ipconfig_type2string(type));

	/*
	 * There is only an default gateway yield decision to be
	 * considered if there is an gateway configuration for BOTH the
	 * activated and existing gateway data.
	 */
	if (!activated_config || !existing_config)
		goto done;

	/*
	 * If the existing gateway data IS NOT active (that is, HAS
	 * NOT made it to the RTNL notification phase of its
	 * lifecycle), then it yields the default gateway to the
	 * activated gateway data.
	 */
	if (!is_gateway_config_state_active(existing_config)) {
		DBG("%s existing %p yielding %s",
			__connman_ipconfig_type2string(type),
			existing,
			maybe_null(gateway_config_type2string(
				config_type)));

		DEMOTE_DEFAULT_GATEWAY(existing, type);
	}

	/*
	 * If the existing gateway data IS active (that is, HAS made
	 * it to the RTNL notification phase of its lifecycle) and if
	 * its associated service is more "senior" in the service sort
	 * order, then the activated gateway data yields the default
	 * gateway to the existing gateway data.
	 */
	if (is_gateway_config_state_active(existing_config) &&
		__connman_service_compare(existing->service,
				activated->service) < 0) {
		DBG("%s activated %p yielding %s",
			__connman_ipconfig_type2string(type),
			activated,
			maybe_null(gateway_config_type2string(
				config_type)));

		DEMOTE_DEFAULT_GATEWAY(activated, type);

		yield_activated = true;
	}

	DBG("yield_activated %u", yield_activated);

done:
	return yield_activated;
}

/**
 *  @brief
 *    Decide whether either of the specified gateways should yield the
 *    default gateway route.
 *
 *  This determines whether either of the specified gateway data
 *  should yield the default gateway route via
 *  #unset_default_gateway. @a activated is a newly-activated gateway
 *  from a Routing Netlink (rtnl) notification. @a existing is an
 *  existing gateway from the services-to-gateway data hash.
 *
 *  @param[in,out]  activated  A pointer to a mutable newly-activated
 *                             gateway from a Routing Netlink (rtnl)
 *                             notification.
 *  @param[in,out]  existing   A pointer to a mutable existing
 *                             gateway from the services-to-gateway
 *                             hash.
 *
 *  @returns
 *    True if @a activated yielded the default gateway; otherwise,
 *    false.
 *
 *  @sa check_default_gateway
 *  @sa __connman_service_compare
 *  @sa unset_default_gateway
 *  @sa yield_default_gateway_for_type
 *
 */
static bool yield_default_gateway(struct gateway_data *activated,
					struct gateway_data *existing)
{
	bool yield_ipv4_activated = false, yield_ipv6_activated = false;

	GATEWAY_DATA_DBG("activated", activated);
	GATEWAY_DATA_DBG("existing", existing);

	yield_ipv4_activated = yield_default_gateway_for_type(
						activated,
						existing,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	yield_ipv6_activated = yield_default_gateway_for_type(
						activated,
						existing,
						CONNMAN_IPCONFIG_TYPE_IPV6);

	DBG("yield_ipv4_activated %u yield_ipv6_activated %u",
		yield_ipv4_activated,
		yield_ipv6_activated);

	return yield_ipv4_activated || yield_ipv6_activated;
}

/**
 *  @brief
 *    Check whether the specified gateway should yield or become the
 *    default.
 *
 *  This compares the specified, ostenisbly new, gateway data against
 *  all, known existing gateway data in the service-to-gateway hash
 *  and determines whether or not the default should be ceded from an
 *  existing gateway and given to the new, incoming gateway or vice
 *  versa.
 *
 *  @param[in,out]  activated  A pointer to the mutable gateway data
 *                             associated with a newly-activated
 *                             gateway route which is to be checked
 *                             against existing gateway data.
 *
 *  @sa yield_default_gateway
 *  @sa gateway_rtnl_new
 *
 */
static void check_default_gateway(struct gateway_data *activated)
{
	GHashTableIter iter;
	gpointer value, key;
	bool yield_activated = false;

	DBG("activated %p", activated);

	GATEWAY_DATA_DBG("activated", activated);

	/*
	 * If we have already handled a Routing Netlink (rtnl)
	 * notification and checked the newly-activated gateway against
	 * the existing gateway / default routers, simply return.
	 *
	 * Otherwise, failure to use this 'default_checked' sentinel could
	 * lead into an infinite Routing Netlink (rntl) loop as changing
	 * the default gateway pushes a new route into the kernel and ends
	 * up back here again (via the .newgateway method).
	 */
	if (activated->default_checked)
		return;

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *existing = value;

		if (existing == activated)
			continue;

		yield_activated = yield_default_gateway(activated, existing);
		if (yield_activated)
			break;
	}

	DBG("yield_activated %u", yield_activated);

	if (!yield_activated) {
		if (activated->ipv4_config)
			PROMOTE_DEFAULT_GATEWAY(activated,
				CONNMAN_IPCONFIG_TYPE_IPV4);

		if (activated->ipv6_config)
			PROMOTE_DEFAULT_GATEWAY(activated,
				CONNMAN_IPCONFIG_TYPE_IPV6);
	}

	activated->default_checked = true;
}

/**
 *  @brief
 *    Handler for gateway, or default route, -specific routes newly
 *    added to the Linux kernel routing tables.
 *
 *  This is the Linux Routing Netlink (rtnl) handler for gateway, or
 *  default route, -specific routes newly-added to the Linux kernel
 *  routing tables. Its primary role and goal is to serve as a
 *  round-trip acknowledgement that gateway-, or default route,
 *  related routes added or set to the kernel are now active and in
 *  use.
 *
 *  @param[in]  index    The network interface index associated with
 *                       the newly-added gateway, or default router.
 *  @param[in]  gateway  A pointer to an immutable null-terminated
 *                       C string containing the text-
 *                       formatted address of the gateway, or default
 *                       router, that was added.
 *
 *  @sa check_default_gateway
 *  @sa set_default_gateway
 *  @sa gateway_rtnl_del
 *
 */
static void gateway_rtnl_new(int index, const char *gateway)
{
	g_autofree char *interface = NULL;
	struct gateway_config *config;
	struct gateway_data *data;

	interface = connman_inet_ifname(index);

	DBG("index %d (%s) gateway %s", index, maybe_null(interface),
		gateway);

	/*
	 * If there is no gateway configuration, then this is not a
	 * gateway, or default router, route we added or
	 * set. Consequently, ignore it and return.
	 */
	config = find_gateway_config(index, gateway);
	if (!config)
		return;

	GATEWAY_CONFIG_DBG("config", config);

    /*
     * If the state is removed, then we may have gone a full
     * added/removed cycle before the added gateway route was even
     * activated. In this case, it is now a stale added
     * activation; simply ignore it.
     */
	if (is_gateway_config_state_removed(config)) {
		DBG("ignoring gateway stale added activation; "
			"probably removed before added activation completed");

		return;
	}

	if (is_gateway_config_state_inactive(config)) {
		DBG("ignoring inactive gateway activation");

		return;
	}

	/*
	 * Otherwise, this is a gateway default route we added, or set,
	 * and it is now acknowledged by the kernel. Consequently, mark it
	 * as active.
	 */
	gateway_config_set_active(config);

	/*
	 * It is possible that we have two default routes atm
	 * if there are two gateways waiting rtnl activation at the
	 * same time.
	 */
	data = find_gateway_data(config);
	if (!data)
		return;

	GATEWAY_DATA_DBG("data", data);

	/*
	 * Check whether this newly-activated gateway should yield or
	 * become the default.
	 */
	check_default_gateway(data);
}

/**
 *  @brief
 *    Deallocate gateway configuration resources.
 *
 *  This attempts to deallocate resources associated with the
 *  specified gateway configuration.
 *
 *  @param[in,out]  config  A pointer to the mutable gateway
 *                  configuration to deallocate.
 *
 */
static void gateway_config_free(struct gateway_config *config)
{
	DBG("config %p", config);

	if (config) {
		g_free(config->gateway);
		g_free(config->vpn_ip);
		g_free(config->vpn_phy_ip);
		g_free(config);
	}
}

static void remove_gateway(gpointer user_data)
{
	struct gateway_data *data = user_data;

	GATEWAY_DATA_DBG("data", data);

	gateway_config_free(data->ipv4_config);

	gateway_config_free(data->ipv6_config);

	/*
	 * Release, and balance, the strong reference to the service
	 * retained in #add_gateway.
	 */
	connman_service_unref(data->service);

	g_free(data);
}

/**
 *  @brief
 *    Handler for gateway, or default route, -specific routes newly
 *    removed from the Linux kernel routing tables.
 *
 *  This is the Linux Routing Netlink (rtnl) handler for gateway, or
 *  default route, -specific routes newly-removed from the Linux
 *  kernel routing tables. Its primary role and goal is to serve as
 *  a round-trip acknowledgement that gateway-, or default route,
 *  related routes removed or cleared from the kernel are now inactive
 *  and are no longer in use.
 *
 *  @param[in]  index    The network interface index associated with
 *                       the newly-removed gateway, or default router.
 *  @param[in]  gateway  A pointer to an immutable null-terminated
 *                       C string containing the text-
 *                       formatted address of the gateway, or default
 *                       router, that was removed.
 *
 *  @sa gateway_rtnl_new
 *  @sa set_default_gateway
 *
 */
static void gateway_rtnl_del(int index, const char *gateway)
{
	g_autofree char *interface = NULL;
	struct gateway_config *config;
	struct gateway_data *data;

	interface = connman_inet_ifname(index);

	DBG("index %d (%s) gateway %s", index, maybe_null(interface),
		gateway);

	/*
	 * This ends the lifecycle of the gateway associated with the
	 * newly-removed route; mark it as no longer active.
	 */
	config = find_gateway_config(index, gateway);
	if (config) {
		GATEWAY_CONFIG_DBG("config", config);

		if (is_gateway_config_state_removed(config))
			gateway_config_set_inactive(config);
		else {
			DBG("ignoring gateway stale removed activation; "
			"probably added before removed activation completed");

			return;
		}
	} else
		DBG("no matching gateway config");

	/*
	 * Due to the newly-removed gateway route, there may have been a
	 * concomitant change in service order that has resulted in a new,
	 * default service, if any. If so, ensure that service acquires
	 * the high priority default route.
	 */
	data = find_default_gateway_data();
	if (data) {
		GATEWAY_DATA_DBG("data", data);

		PROMOTE_DEFAULT_GATEWAY(data, CONNMAN_IPCONFIG_TYPE_ALL);
	} else
		DBG("no default gateway data");
}

static struct connman_rtnl gateway_rtnl = {
	.name		= "gateway",
	.newgateway	= gateway_rtnl_new,
	.delgateway	= gateway_rtnl_del,
};

/**
 *  @brief
 *    Add, or set, a host route for the specified IP configuration
 *    type for the provided gateway data.
 *
 *  This attempts to add, or set, a host route (that is, the RTF_HOST
 *  flag is asserted on the route) for the specified IP configuration
 *  type for the provided gateway data.
 *
 *  @param[in]  data           A pointer to the mutable gateway data
 *                             for which to add a host route.
 *  @param[in]  ipconfig_type  The IP configuration type for which the
 *                             gateway host route(s) are to be added.
 *  @param[in]  service_type   The service type for the network service
 *                             associated with @a index for which the
 *                             host route is being added.
 *
 *  @sa connman_inet_add_host_route
 *  @sa connman_inet_add_ipv6_host_route
 *  @sa connman_inet_get_dest_addr
 *  @sa connman_inet_ipv6_get_dest_addr
 *
 */
static void add_host_route(struct gateway_data *data,
			enum connman_ipconfig_type ipconfig_type,
			enum connman_service_type service_type)
{
	const struct gateway_config *const config =
		gateway_data_config_get(data, ipconfig_type);

	if (!config)
		return;

	if (!is_addr_any_str(config->gateway)) {
		/*
		 * We must not set route to the phy dev gateway in
		 * VPN link. The packets to VPN link might be routed
		 * back to itself and not routed into phy link gateway.
		 */
		if (service_type != CONNMAN_SERVICE_TYPE_VPN)
			config->ops->add_host_route(data->index,
								config->gateway,
								NULL);
	} else {
		/*
		 * Add host route to P-t-P link so that services can
		 * be moved around and we can have some link to P-t-P
		 * network (although those P-t-P links have limited
		 * usage if default route is not directed to them)
		 */
		char *dest;

		if (config->ops->get_dest_addr(data->index, &dest) == 0) {
			config->ops->add_host_route(data->index, dest, NULL);
			g_free(dest);
		}
	}
}

/**
 *  @brief
 *    Add, or set, the gateway, or default router, for a network
 *    service.
 *
 *  This attempts to add, or set, the gateway, or default router, for
 *  a network service using the specified IP configuration gateway
 *  address and network interface index as the lookup key for the
 *  network service.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to add a gateway, or default
 *                           router.
 *  @param[in]      gateway  An optional pointer to an immutable null-
 *                           terminated C string containing the
 *                           text-formatted address of the gateway, or
 *                           default router, to add to or associate
 *                           with @a service.
 *  @param[in]      type     The IP configuration type for which
 *                           gateway, or default router, is to be
 *                           added.
 *  @param[in]      peer     An optional pointer to an immutable null-
 *                           terminated C string containing the
 *                           text-formatted address of the network
 *                           peer, for point-to-point links,
 *                           associated with the gateway.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If service is null or if network interface
 *                    index associated with @a service is invalid.
 *
 *  @sa __connman_gateway_remove
 *  @sa __connman_gateway_update
 *
 */
int __connman_gateway_add(struct connman_service *service,
					const char *gateway,
					enum connman_ipconfig_type type,
					const char *peer)
{
	struct gateway_data *any_active_gateway = NULL;
	struct gateway_data *default_gateway = NULL;
	struct gateway_data *new_gateway = NULL;
	enum connman_service_type service_type;
	int index;
	g_autofree char *interface = NULL;
	bool do_ipv4 = false, do_ipv6 = false;
	bool is_vpn4 = false, is_vpn6 = false;
	int err = 0;

	DBG("service %p (%s) gateway %p (%s) type %d (%s) peer %p (%s)",
		service, maybe_null(connman_service_get_identifier(service)),
		gateway, maybe_null(gateway),
		type, __connman_ipconfig_type2string(type),
		peer, maybe_null(peer));

	if (!service)
		return -EINVAL;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = true;
	else
		return -EINVAL;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -EINVAL;

	interface = connman_inet_ifname(index);

	DBG("index %d (%s)", index, maybe_null(interface));

	service_type = connman_service_get_type(service);

	/*
	 * If gateway is NULL, it's a point to point link and the default
	 * gateway for ipv4 is 0.0.0.0 and for ipv6 is ::, meaning the
	 * interface
	 */
	if (!gateway && do_ipv4)
		gateway = ipv4_addr_any_str;

	if (!gateway && do_ipv6)
		gateway = ipv6_addr_any_str;

	err = add_gateway(service, index, gateway, type, &new_gateway);
	if (err < 0)
		return err;

	GATEWAY_DATA_DBG("new_gateway", new_gateway);

	any_active_gateway = find_any_active_gateway_data();

	GATEWAY_DATA_DBG("any_active_gateway", any_active_gateway);

	default_gateway = find_default_gateway_data();

	GATEWAY_DATA_DBG("default_gateway", default_gateway);

	if (do_ipv4 && new_gateway->ipv4_config) {
		add_host_route(new_gateway, type, service_type);

		__connman_service_nameserver_add_routes(service,
					new_gateway->ipv4_config->gateway);
	}

	if (do_ipv6 && new_gateway->ipv6_config) {
		add_host_route(new_gateway, type, service_type);

		__connman_service_nameserver_add_routes(service,
					new_gateway->ipv6_config->gateway);
	}

	if (service_type == CONNMAN_SERVICE_TYPE_VPN) {

		set_vpn_routes(new_gateway, service, gateway, type, peer,
							any_active_gateway);

		is_vpn4 = do_ipv4 &&
					new_gateway->ipv4_config &&
					is_gateway_config_vpn(
						new_gateway->ipv4_config);

		is_vpn6 = do_ipv6 &&
					new_gateway->ipv6_config &&
					is_gateway_config_vpn(
						new_gateway->ipv6_config);

	} else {
		if (do_ipv4 && new_gateway->ipv4_config)
			gateway_config_clear_vpn(new_gateway->ipv4_config);

		if (do_ipv6 && new_gateway->ipv6_config)
			gateway_config_clear_vpn(new_gateway->ipv6_config);
	}

	/*
	 * If there is no active gateway, then this is the first and only
	 * gateway. Set the high-priority default route for the gateway
	 * and service/network interface tuple.
	 *
	 * Otherwise, if there is no default gateway either, then set the
	 * low-priority default route for the gateway and service/network
	 * interface tuple.
	 *
	 * NOTE: Beyond historical momentum, it is not clear that
	 * '!any_active_gateway' and 'find_any_active_gateway_data' are
	 * the best fit here. This should likely be '!default_gateway'
	 * from 'find_default_gateway_data'.
	 */
	if (!any_active_gateway) {
		SET_DEFAULT_GATEWAY(new_gateway, type);
		goto done;
	} else if (default_gateway && !is_vpn4 && !is_vpn6) {
		SET_LOW_PRIORITY_DEFAULT_GATEWAY(new_gateway, type);
		goto done;
	}

	if (is_vpn4) {
		if (!__connman_service_is_split_routing(new_gateway->service))
			connman_inet_clear_gateway_address(
				any_active_gateway->index,
				any_active_gateway->ipv4_config->gateway);
	}

	if (is_vpn6) {
		if (!__connman_service_is_split_routing(new_gateway->service))
			connman_inet_clear_ipv6_gateway_address(
				any_active_gateway->index,
				any_active_gateway->ipv6_config->gateway);
	}

done:
	if (do_ipv4)
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	if (do_ipv6)
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV6);

	return err;
}

/**
 *  @brief
 *    Remove, or clear, the gateway, or default router, for a network
 *    service.
 *
 *  This attempts to remove, or clear, the gateway, or default router,
 *  for a network service using the specified network service and IP
 *  configuration type.
 *
 *  @param[in,out]  service  A pointer to the mutable network service
 *                           for which to remove, or clear, a gateway,
 *                           or default router.
 *  @param[in]      type     The IP configuration type for which
 *                           gateway, or default router, is to be
 *                           removed.
 *
 *  @retval  0        If successful.
 *  @retval  -EINVAL  If service is null or if network interface
 *                    index associated with @a service is invalid.
 *
 *  @sa __connman_gateway_add
 *  @sa __connman_gateway_update
 *
 */
void __connman_gateway_remove(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	struct gateway_data *data = NULL;
	bool is_vpn4 = false, is_vpn6 = false;
	bool do_ipv4 = false, do_ipv6 = false;
	int err;

	DBG("service %p (%s) type %d (%s)",
		service, maybe_null(connman_service_get_identifier(service)),
		type, __connman_ipconfig_type2string(type));

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = true;
	else if (type == CONNMAN_IPCONFIG_TYPE_ALL)
		do_ipv4 = do_ipv6 = true;
	else
		return;

	/*
	 * If there is no hash table / map entry for this service, then
	 * there are no gateways associated with it; simply return.
	 */
	data = g_hash_table_lookup(gateway_hash, service);
	if (!data)
		return;

	GATEWAY_DATA_DBG("service_data", data);

	/* Delete any routes associated with this service's nameservers. */

	if (do_ipv4 && data->ipv4_config)
		__connman_service_nameserver_del_routes(service,
			data->ipv4_config->gateway,
			type);

	if (do_ipv6 && data->ipv6_config)
		__connman_service_nameserver_del_routes(service,
			data->ipv6_config->gateway,
			type);

	if (do_ipv4 && data->ipv4_config)
		is_vpn4 = is_gateway_config_vpn(data->ipv4_config);

	if (do_ipv6 && data->ipv6_config)
		is_vpn6 = is_gateway_config_vpn(data->ipv6_config);

	DBG("ipv4 gateway %s ipv6 gateway %s vpn %d/%d",
		data->ipv4_config ? data->ipv4_config->gateway : "<null>",
		data->ipv6_config ? data->ipv6_config->gateway : "<null>",
		is_vpn4, is_vpn6);

    /* If necessary, delete any VPN-related host routes. */

	if (is_vpn4 && data->index >= 0)
		data->ipv4_config->ops->del_host_route(
					data->ipv4_config->vpn_phy_index,
					data->ipv4_config->gateway,
					NULL);

	if (is_vpn6 && data->index >= 0)
		data->ipv6_config->ops->del_host_route(
					data->ipv6_config->vpn_phy_index,
					data->ipv6_config->gateway,
					NULL);

	/* Remove all active routes associated with this gateway data. */

	err = del_gateway_routes_if_active(data, type);

	/*
	 * We remove the service from the service/gateway map only if ALL
	 * of the gateway settings are to be removed.
	 */
	if (do_ipv4 == do_ipv6 ||
		(data->ipv4_config && !data->ipv6_config
			&& do_ipv4) ||
		(data->ipv6_config && !data->ipv4_config
			&& do_ipv6)) {
		g_hash_table_remove(gateway_hash, service);
	} else
		DBG("Not yet removing gw ipv4 %p/%d ipv6 %p/%d",
			data->ipv4_config, do_ipv4,
			data->ipv6_config, do_ipv6);

	/* with vpn this will be called after the network was deleted,
	 * we need to call set_default here because we will not receive any
	 * gateway delete notification.
	 * We hit the same issue if remove_gateway() fails.
	 */
	if (is_vpn4 || is_vpn6 || err < 0) {
		data = find_default_gateway_data();

		GATEWAY_DATA_DBG("default_data", data);

		if (data)
			PROMOTE_DEFAULT_GATEWAY(data, type);
	}
}

/**
 *  @brief
 *    Handle a potential change in gateways.
 *
 *  This may be invoked by other modules in the event of service and
 *  technology changes to reexamine and, if necessary, update active
 *  network interface gateways and their associated routing table
 *  entries.
 *
 *  @returns
 *    True if an active gateway was updated; otherwise, false.
 *
 *  @sa __connman_gateway_add
 *  @sa __connman_gateway_remove
 *  @sa set_default_gateway
 *  @sa unset_default_gateway
 *
 */
bool __connman_gateway_update(void)
{
	struct gateway_data *default_gateway;
	GHashTableIter iter;
	gpointer value, key;
	enum connman_ipconfig_type type;
	int status = 0;
	bool updated4 = false, updated6 = false;

	DBG("");

	/*
	 * If there is no service-to-gateway data hash, then there is
	 * nothing to update and do; simply return.
	 */
	if (!gateway_hash)
		goto done;

	default_gateway = find_default_gateway_data();

	GATEWAY_DATA_DBG("default_gateway", default_gateway);

	/*
	 * There can be multiple active gateways so we need to
	 * check them all.
	 */
	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *current_gateway = value;
		struct gateway_config *current_config;

		GATEWAY_DATA_DBG("current_gateway", current_gateway);

		if (current_gateway == default_gateway)
			continue;

		type = CONNMAN_IPCONFIG_TYPE_IPV4;
		current_config = gateway_data_config_get(current_gateway, type);

		if (current_config &&
				is_gateway_config_state_active(
					current_config)) {
			status = DEMOTE_DEFAULT_GATEWAY(current_gateway,
						type);

			updated4 = status == 0;
		}

		type = CONNMAN_IPCONFIG_TYPE_IPV6;
		current_config = gateway_data_config_get(current_gateway, type);

		if (current_config &&
				is_gateway_config_state_active(
					current_config)) {
			status = DEMOTE_DEFAULT_GATEWAY(current_gateway,
						type);

			updated6 = status == 0;
		}
	}

	DBG("updated4 %u updated6 %u", updated4, updated6);

	/*
	 * Set default gateway if it has been updated or if it has not been
	 * set as active yet.
	 */
	if (default_gateway) {
		const struct gateway_config *default_config;

		type = CONNMAN_IPCONFIG_TYPE_IPV4;
		default_config = gateway_data_config_get(default_gateway, type);

		if (default_config &&
			(updated4 ||
			!is_gateway_config_state_active(default_config)))
			PROMOTE_DEFAULT_GATEWAY(default_gateway, type);

		type = CONNMAN_IPCONFIG_TYPE_IPV6;
		default_config = gateway_data_config_get(default_gateway, type);

		if (default_config &&
			(updated6 ||
			!is_gateway_config_state_active(default_config)))
			PROMOTE_DEFAULT_GATEWAY(default_gateway, type);
	}

done:
	return updated4 || updated6;
}

int __connman_gateway_get_vpn_index(int phy_index)
{
	GHashTableIter iter;
	gpointer value, key;

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *data = value;

		if (data->ipv4_config &&
				data->ipv4_config->vpn_phy_index == phy_index)
			return data->index;

		if (data->ipv6_config &&
				data->ipv6_config->vpn_phy_index == phy_index)
			return data->index;
	}

	return -1;
}

int __connman_gateway_get_vpn_phy_index(int vpn_index)
{
	GHashTableIter iter;
	gpointer value, key;

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *data = value;

		if (data->index != vpn_index)
			continue;

		if (data->ipv4_config)
			return data->ipv4_config->vpn_phy_index;

		if (data->ipv6_config)
			return data->ipv6_config->vpn_phy_index;
	}

	return -1;
}

int __connman_gateway_init(void)
{
	int err;

	DBG("");

	gateway_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, remove_gateway);

	err = connman_rtnl_register(&gateway_rtnl);
	if (err < 0)
		connman_error("Failed to setup RTNL gateway driver");

	return err;
}

void __connman_gateway_cleanup(void)
{
	GHashTableIter iter;
	gpointer value, key;

	DBG("");

	connman_rtnl_unregister(&gateway_rtnl);

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *data = value;

		del_gateway_routes_if_active(data, CONNMAN_IPCONFIG_TYPE_ALL);
	}

	g_hash_table_destroy(gateway_hash);
	gateway_hash = NULL;
}
