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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <net/if.h>

#include <gdbus.h>

#include "connman.h"

#define GATEWAY_CONFIG_DBG(description, config) \
	gateway_config_debug(__func__, description, config)

#define GATEWAY_DATA_DBG(description, data) \
	gateway_data_debug(__func__, description, data)

struct gateway_config {
	bool active;
	char *gateway;

	/* VPN extra data */
	bool vpn;
	char *vpn_ip;
	int vpn_phy_index;
	char *vpn_phy_ip;
};

struct gateway_data {
	int index;
	struct connman_service *service;
	struct gateway_config *ipv4_config;
	struct gateway_config *ipv6_config;
	bool default_checked;
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
		DBG("from %s %s %p", function, description, config);
	else {
		if (config->vpn_phy_index >= 0)
			vpn_phy_interface =
				connman_inet_ifname(config->vpn_phy_index);

		DBG("from %s %s %p: { active: %u, gateway: %p (%s), "
			"vpn: %u, vpn_ip: %p (%s), vpn_phy_index: %d (%s), "
			"vpn_phy_ip: %p (%s) }",
			function,
			description,
			config,
			config->active,
			config->gateway, maybe_null(config->gateway),
			config->vpn,
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
		DBG("from %s %s %p", function, description, data);
	else {
		interface = connman_inet_ifname(data->index);

		DBG("from %s %s %p: { index: %d (%s), service: %p (%s), "
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

static struct gateway_data *find_active_gateway_data(void)
{
	GHashTableIter iter;
	gpointer value, key;

	DBG("");

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *data = value;

		if (data->ipv4_config &&
				data->ipv4_config->active)
			return data;

		if (data->ipv6_config &&
				data->ipv6_config->active)
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
 *  associated with default network service (that is, has the default
 *  route).
 *
 *  @returns
 *    A pointer to the gateway, or default router, data associated
 *    with the default network service (that is, has the default
 *    route) on success; otherwise, null.
 *
 *  @sa find_active_gateway_data
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

		config->vpn = true;
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
		if (connman_inet_compare_subnet(active_gateway->index,
								gateway))
			return;

		DBG("active gw %s", active_gateway->ipv4_config->gateway);

		if (!is_ipv4_addr_any_str(active_gateway->ipv4_config->gateway))
			dest = active_gateway->ipv4_config->gateway;
		else
			dest = NULL;

		connman_inet_add_host_route(active_gateway->index, gateway,
									dest);

	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {

		if (!active_gateway->ipv6_config)
			return;

		if (connman_inet_compare_ipv6_subnet(active_gateway->index,
								gateway))
			return;

		DBG("active gw %s", active_gateway->ipv6_config->gateway);

		if (!is_ipv6_addr_any_str(active_gateway->ipv6_config->gateway))
			dest = active_gateway->ipv6_config->gateway;
		else
			dest = NULL;

		connman_inet_add_ipv6_host_route(active_gateway->index,
								gateway, dest);
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
		if (data->ipv4_config->vpn) {
			status4 = connman_inet_clear_gateway_address(
						data->index,
						data->ipv4_config->vpn_ip);

		} else if (is_ipv4_addr_any_str(data->ipv4_config->gateway)) {
			status4 = connman_inet_clear_gateway_interface(
								data->index);
		} else {
			connman_inet_del_host_route(data->index,
						data->ipv4_config->gateway);
			status4 = connman_inet_clear_gateway_address(
						data->index,
						data->ipv4_config->gateway);
		}
	}

	if (do_ipv6 && data->ipv6_config) {
		if (data->ipv6_config->vpn) {
			status6 = connman_inet_clear_ipv6_gateway_address(
						data->index,
						data->ipv6_config->vpn_ip);

		} else if (is_ipv6_addr_any_str(data->ipv6_config->gateway)) {
			status6 = connman_inet_clear_ipv6_gateway_interface(
								data->index);
		} else {
			connman_inet_del_ipv6_host_route(data->index,
						data->ipv6_config->gateway);
			status6 = connman_inet_clear_ipv6_gateway_address(
						data->index,
						data->ipv6_config->gateway);
		}
	}

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
			active = data->ipv4_config->active;
	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		if (data->ipv6_config)
			active = data->ipv6_config->active;
	} else if (type == CONNMAN_IPCONFIG_TYPE_ALL)
		active = true;

	DBG("type %d active %d", type, active);

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
 *  @sa __connman_connection_gateway_add
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

	config->gateway = g_strdup(gateway);
	config->vpn_ip = NULL;
	config->vpn_phy_ip = NULL;
	config->vpn = false;
	config->vpn_phy_index = -1;
	config->active = false;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		temp_data->ipv4_config = config;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		temp_data->ipv6_config = config;

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

static void set_default_gateway(struct gateway_data *data,
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
		return;

	if (do_ipv4 && data->ipv4_config) {
		if (data->ipv4_config->vpn) {
			connman_inet_set_gateway_interface(data->index);

			data->ipv4_config->active = true;

			DBG("set %p index %d vpn %s index %d phy %s",
				data, data->index, data->ipv4_config->vpn_ip,
				data->ipv4_config->vpn_phy_index,
				data->ipv4_config->vpn_phy_ip);
		} else if (is_ipv4_addr_any_str(data->ipv4_config->gateway)) {
			if (connman_inet_set_gateway_interface(
						data->index) < 0)
				return;

			data->ipv4_config->active = true;
		} else {
			status4 = __connman_inet_add_default_to_table(
						RT_TABLE_MAIN,
						data->index,
						data->ipv4_config->gateway);
		}
	}

	if (do_ipv6 && data->ipv6_config) {
		if (data->ipv6_config->vpn) {
			connman_inet_set_ipv6_gateway_interface(data->index);

			data->ipv6_config->active = true;

			DBG("set %p index %d vpn %s index %d phy %s",
				data, data->index, data->ipv6_config->vpn_ip,
				data->ipv6_config->vpn_phy_index,
				data->ipv6_config->vpn_phy_ip);
		} else if (is_ipv6_addr_any_str(data->ipv6_config->gateway)) {
			if (connman_inet_set_ipv6_gateway_interface(
						data->index) < 0)
				return;

			data->ipv6_config->active = true;
		} else {
			status6 = __connman_inet_add_default_to_table(
						RT_TABLE_MAIN,
						data->index,
						data->ipv6_config->gateway);
		}
	}

	if (status4 < 0 || status6 < 0)
		return;

	__connman_service_indicate_default(data->service);
}

static void unset_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type)
{
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
		return;

	if (do_ipv4 && data->ipv4_config &&
					data->ipv4_config->vpn) {
		connman_inet_clear_gateway_interface(data->index);
		data->ipv4_config->active = false;

		DBG("unset %p index %d vpn %s index %d phy %s",
			data, data->index, data->ipv4_config->vpn_ip,
			data->ipv4_config->vpn_phy_index,
			data->ipv4_config->vpn_phy_ip);

		return;
	}

	if (do_ipv6 && data->ipv6_config &&
					data->ipv6_config->vpn) {
		connman_inet_clear_ipv6_gateway_interface(data->index);
		data->ipv6_config->active = false;

		DBG("unset %p index %d vpn %s index %d phy %s",
			data, data->index, data->ipv6_config->vpn_ip,
			data->ipv6_config->vpn_phy_index,
			data->ipv6_config->vpn_phy_ip);

		return;
	}

	if (do_ipv4 && data->ipv4_config &&
			is_ipv4_addr_any_str(data->ipv4_config->gateway)) {
		connman_inet_clear_gateway_interface(data->index);
		data->ipv4_config->active = false;
		return;
	}

	if (do_ipv6 && data->ipv6_config &&
			is_ipv6_addr_any_str(data->ipv6_config->gateway)) {
		connman_inet_clear_ipv6_gateway_interface(data->index);
		data->ipv6_config->active = false;
		return;
	}

	if (do_ipv6 && data->ipv6_config)
		connman_inet_clear_ipv6_gateway_address(data->index,
						data->ipv6_config->gateway);

	if (do_ipv4 && data->ipv4_config)
		connman_inet_clear_gateway_address(data->index,
						data->ipv4_config->gateway);
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
 *                             gateway.
 *  @param[in,out]  existing   A pointer to a mutable existing
 *                             gateway.
 *
 *  @returns
 *    True of @a activated yielded the default gateway; otherwise,
 *    false.
 *
 *  @sa check_default_gateway
 *  @sa __connman_service_compare
 *  @sa unset_default_gateway
 *
 */
static bool yield_default_gateway(struct gateway_data *activated,
					struct gateway_data *existing)
{
	enum connman_ipconfig_type type;
	bool yield_activated = false;

	DBG("activated %p existing %p", activated, existing);

	GATEWAY_DATA_DBG("activated", activated);
	GATEWAY_DATA_DBG("existing", existing);

	/*
	 * There is only an IPv4 default gateway yield decision to be
	 * considered if there is an IPv4 gateway configuration for BOTH
	 * the activated and existing gateway data.
	 */
	if (activated->ipv4_config && existing->ipv4_config) {
		type = CONNMAN_IPCONFIG_TYPE_IPV4;

		/*
		 * If the existing IPv4 gateway data IS NOT active (that is,
		 * HAS NOT made it to the RTNL notification phase of its
		 * lifecycle), then it yields the default gateway to the
		 * activated gateway data.
		 */
		if (!existing->ipv4_config->active) {
			DBG("ipv4 existing %p yielding default", existing);

			unset_default_gateway(existing, type);
		}

		/*
		 * If the existing IPv4 gateway data IS active (that is, HAS
		 * made it to the RTNL notification phase of its lifecycle)
		 * and if its associated service is more "senior" in the
		 * service sort order, then the activated gateway data yields
		 * the default gateway to the existing gateway data.
		 */
		if (existing->ipv4_config->active &&
				__connman_service_compare(existing->service,
						activated->service) < 0) {
			DBG("ipv4 activated %p yielding default", activated);

			unset_default_gateway(activated, type);

			yield_activated = true;
		}
	}

	/*
	 * There is only an IPv6 default gateway yield decision to be
	 * considered if there is an IPv6 gateway configuration for BOTH
	 * the activated and existing gateway data.
	 */
	if (activated->ipv6_config && existing->ipv6_config) {
		type = CONNMAN_IPCONFIG_TYPE_IPV6;

		/*
		 * If the existing IPv6 gateway data IS NOT active (that is,
		 * HAS NOT made it to the RTNL notification phase of its
		 * lifecycle), then it yields the default gateway to the
		 * activated gateway data.
		 */
		if (!existing->ipv6_config->active) {
			DBG("ipv6 existing %p yielding default", existing);

			unset_default_gateway(existing, type);
		}

		/*
		 * If the existing IPv6 gateway data IS active (that is, HAS
		 * made it to the RTNL notification phase of its lifecycle)
		 * and if its associated service is more "senior" in the
		 * service sort order, then the activated gateway data yields
		 * the default gateway to the existing gateway data.
		 */
		if (existing->ipv6_config->active &&
			__connman_service_compare(existing->service,
					activated->service) < 0) {
			DBG("ipv6 activated %p yielding default", activated);

			unset_default_gateway(activated, type);

			yield_activated = true;
		}
	}

	return yield_activated;
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
 *  @sa connection_newgateway
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
			set_default_gateway(activated,
				CONNMAN_IPCONFIG_TYPE_IPV4);

		if (activated->ipv6_config)
			set_default_gateway(activated,
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
 *  @param[in]  gateway  An pointer to an immutable null-terminated
 *                       C string containing the text-
 *                       formatted address of the gateway, or default
 *                       router, that was added.
 *
 *  @sa check_default_gateway
 *  @sa set_default_gateway
 *  @sa connection_delgateway
 *
 */
static void connection_newgateway(int index, const char *gateway)
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
	 * Otherwise, this is a gateway, or default router, route we added
	 * or set and it is now acknowledged by the kernel. Consequently,
	 * prospectively mark it as active; however, this may be
	 * subsequently modified as default route determinations are made.
	 */
	config->active = true;

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

static void remove_gateway(gpointer user_data)
{
	struct gateway_data *data = user_data;

	DBG("data %p", data);

	GATEWAY_DATA_DBG("data", data);

	if (data->ipv4_config) {
		g_free(data->ipv4_config->gateway);
		g_free(data->ipv4_config->vpn_ip);
		g_free(data->ipv4_config->vpn_phy_ip);
		g_free(data->ipv4_config);
	}

	if (data->ipv6_config) {
		g_free(data->ipv6_config->gateway);
		g_free(data->ipv6_config->vpn_ip);
		g_free(data->ipv6_config->vpn_phy_ip);
		g_free(data->ipv6_config);
	}

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
 *  @param[in]  gateway  An pointer to an immutable null-terminated
 *                       C string containing the text-
 *                       formatted address of the gateway, or default
 *                       router, that was removed.
 *
 *  @sa connection_newgateway
 *  @sa set_default_gateway
 *
 */
static void connection_delgateway(int index, const char *gateway)
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

		config->active = false;
	}

	/*
	 * Due to the newly-removed gateway route, there may have been a
	 * concomitant change in service order that has resulted in a new,
	 * default service, if any. If so, ensure that service acquires
	 * the high priority default route.
	 */
	data = find_default_gateway_data();
	if (data) {
		GATEWAY_DATA_DBG("data", data);

		set_default_gateway(data, CONNMAN_IPCONFIG_TYPE_ALL);
	}
}

static struct connman_rtnl connection_rtnl = {
	.name		= "connection",
	.newgateway	= connection_newgateway,
	.delgateway	= connection_delgateway,
};

static void add_host_route(int family, int index, const char *gateway,
			enum connman_service_type service_type)
{
	switch (family) {
	case AF_INET:
		if (!is_ipv4_addr_any_str(gateway)) {
			/*
			 * We must not set route to the phy dev gateway in
			 * VPN link. The packets to VPN link might be routed
			 * back to itself and not routed into phy link gateway.
			 */
			if (service_type != CONNMAN_SERVICE_TYPE_VPN)
				connman_inet_add_host_route(index, gateway,
									NULL);
		} else {
			/*
			 * Add host route to P-t-P link so that services can
			 * be moved around and we can have some link to P-t-P
			 * network (although those P-t-P links have limited
			 * usage if default route is not directed to them)
			 */
			char *dest;
			if (connman_inet_get_dest_addr(index, &dest) == 0) {
				connman_inet_add_host_route(index, dest, NULL);
				g_free(dest);
			}
		}
		break;

	case AF_INET6:
		if (!is_ipv6_addr_any_str(gateway)) {
			if (service_type != CONNMAN_SERVICE_TYPE_VPN)
				connman_inet_add_ipv6_host_route(index,
								gateway, NULL);
		} else {
			/* P-t-P link, add route to destination */
			char *dest;
			if (connman_inet_ipv6_get_dest_addr(index,
								&dest) == 0) {
				connman_inet_add_ipv6_host_route(index, dest,
								NULL);
				g_free(dest);
			}
		}
		break;
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
 *  @sa __connman_connection_gateway_remove
 *  @sa __connman_connection_update_gateway
 *
 */
int __connman_connection_gateway_add(struct connman_service *service,
					const char *gateway,
					enum connman_ipconfig_type type,
					const char *peer)
{
	struct gateway_data *active_gateway = NULL;
	struct gateway_data *new_gateway = NULL;
	enum connman_ipconfig_type type4 = CONNMAN_IPCONFIG_TYPE_UNKNOWN,
		type6 = CONNMAN_IPCONFIG_TYPE_UNKNOWN;
	enum connman_service_type service_type =
					connman_service_get_type(service);
	int index;
	g_autofree char *interface = NULL;
	int err = 0;

	DBG("service %p (%s) gateway %p (%s) type %d (%s) peer %p (%s)",
		service, maybe_null(connman_service_get_identifier(service)),
		gateway, maybe_null(gateway),
		type, __connman_ipconfig_type2string(type),
		peer, maybe_null(peer));

	index = __connman_service_get_index(service);

	interface = connman_inet_ifname(index);

	DBG("index %d (%s)", index, maybe_null(interface));

	/*
	 * If gateway is NULL, it's a point to point link and the default
	 * gateway for ipv4 is 0.0.0.0 and for ipv6 is ::, meaning the
	 * interface
	 */
	if (!gateway && type == CONNMAN_IPCONFIG_TYPE_IPV4)
		gateway = ipv4_addr_any_str;

	if (!gateway && type == CONNMAN_IPCONFIG_TYPE_IPV6)
		gateway = ipv6_addr_any_str;

	DBG("service %p index %d gateway %s vpn ip %s type %d",
		service, index, gateway, peer, type);

	err = add_gateway(service, index, gateway, type, &new_gateway);
	if (err < 0)
		return err;

	GATEWAY_DATA_DBG("new_gateway", new_gateway);

	active_gateway = find_active_gateway_data();

	DBG("active %p index %d new %p", active_gateway,
		active_gateway ? active_gateway->index : -1, new_gateway);

	GATEWAY_DATA_DBG("active_gateway", active_gateway);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
				new_gateway->ipv4_config) {
		add_host_route(AF_INET, index, gateway, service_type);
		__connman_service_nameserver_add_routes(service,
					new_gateway->ipv4_config->gateway);
		type4 = CONNMAN_IPCONFIG_TYPE_IPV4;
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
				new_gateway->ipv6_config) {
		add_host_route(AF_INET6, index, gateway, service_type);
		__connman_service_nameserver_add_routes(service,
					new_gateway->ipv6_config->gateway);
		type6 = CONNMAN_IPCONFIG_TYPE_IPV6;
	}

	if (service_type == CONNMAN_SERVICE_TYPE_VPN) {

		set_vpn_routes(new_gateway, service, gateway, type, peer,
							active_gateway);

	} else {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
					new_gateway->ipv4_config)
			new_gateway->ipv4_config->vpn = false;

		if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
					new_gateway->ipv6_config)
			new_gateway->ipv6_config->vpn = false;
	}

	if (!active_gateway) {
		set_default_gateway(new_gateway, type);
		goto done;
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
				new_gateway->ipv4_config &&
				new_gateway->ipv4_config->vpn) {
		if (!__connman_service_is_split_routing(new_gateway->service))
			connman_inet_clear_gateway_address(
					active_gateway->index,
					active_gateway->ipv4_config->gateway);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
				new_gateway->ipv6_config &&
				new_gateway->ipv6_config->vpn) {
		if (!__connman_service_is_split_routing(new_gateway->service))
			connman_inet_clear_ipv6_gateway_address(
					active_gateway->index,
					active_gateway->ipv6_config->gateway);
	}

done:
	if (type4 == CONNMAN_IPCONFIG_TYPE_IPV4)
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	if (type6 == CONNMAN_IPCONFIG_TYPE_IPV6)
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
 *  @sa __connman_connection_gateway_add
 *  @sa __connman_connection_update_gateway
 *
 */
void __connman_connection_gateway_remove(struct connman_service *service,
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

    /* Delete any routes associated with this service's nameservers. */

	__connman_service_nameserver_del_routes(service, type);

	/*
	 * If there is no hash table / map entry for this service, then
	 * there are no gateways associated with it; simply return.
	 */
	data = g_hash_table_lookup(gateway_hash, service);
	if (!data)
		return;

	GATEWAY_DATA_DBG("service_data", data);

	if (do_ipv4 && data->ipv4_config)
		is_vpn4 = data->ipv4_config->vpn;

	if (do_ipv6 && data->ipv6_config)
		is_vpn6 = data->ipv6_config->vpn;

	DBG("ipv4 gateway %s ipv6 gateway %s vpn %d/%d",
		data->ipv4_config ? data->ipv4_config->gateway : "<null>",
		data->ipv6_config ? data->ipv6_config->gateway : "<null>",
		is_vpn4, is_vpn6);

    /* If necessary, delete any VPN-related host routes. */

	if (is_vpn4 && data->index >= 0)
		connman_inet_del_host_route(data->ipv4_config->vpn_phy_index,
						data->ipv4_config->gateway);

	if (is_vpn6 && data->index >= 0)
		connman_inet_del_ipv6_host_route(
					data->ipv6_config->vpn_phy_index,
						data->ipv6_config->gateway);

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
			set_default_gateway(data, type);
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
 *  @sa __connman_connection_gateway_add
 *  @sa __connman_connection_gateway_remove
 *  @sa set_default_gateway
 *  @sa unset_default_gateway
 *
 */
bool __connman_connection_update_gateway(void)
{
	struct gateway_data *default_gateway;
	bool updated = false;
	GHashTableIter iter;
	gpointer value, key;

	DBG("");

	/*
	 * If there is no service-to-gateway data hash, then there is
	 * nothing to update and do; simply return.
	 */
	if (!gateway_hash)
		return updated;

	default_gateway = find_default_gateway_data();

	DBG("default_gateway %p", default_gateway);

	GATEWAY_DATA_DBG("default_gateway", default_gateway);

	/*
	 * There can be multiple active gateways so we need to
	 * check them all.
	 */
	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *active_gateway = value;

		GATEWAY_DATA_DBG("active_gateway", active_gateway);

		if (active_gateway == default_gateway)
			continue;

		if (active_gateway->ipv4_config &&
				active_gateway->ipv4_config->active) {

			unset_default_gateway(active_gateway,
						CONNMAN_IPCONFIG_TYPE_IPV4);
			updated = true;
		}

		if (active_gateway->ipv6_config &&
				active_gateway->ipv6_config->active) {

			unset_default_gateway(active_gateway,
						CONNMAN_IPCONFIG_TYPE_IPV6);
			updated = true;
		}
	}

	/*
	 * Set default gateway if it has been updated or if it has not been
	 * set as active yet.
	 */
	if (default_gateway) {
		if (default_gateway->ipv4_config &&
			(updated || !default_gateway->ipv4_config->active))
			set_default_gateway(default_gateway,
					CONNMAN_IPCONFIG_TYPE_IPV4);

		if (default_gateway->ipv6_config &&
			(updated || !default_gateway->ipv6_config->active))
			set_default_gateway(default_gateway,
					CONNMAN_IPCONFIG_TYPE_IPV6);
	}

	return updated;
}

int __connman_connection_get_vpn_index(int phy_index)
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

int __connman_connection_get_vpn_phy_index(int vpn_index)
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

int __connman_connection_init(void)
{
	int err;

	DBG("");

	gateway_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, remove_gateway);

	err = connman_rtnl_register(&connection_rtnl);
	if (err < 0)
		connman_error("Failed to setup RTNL gateway driver");

	return err;
}

void __connman_connection_cleanup(void)
{
	GHashTableIter iter;
	gpointer value, key;

	DBG("");

	connman_rtnl_unregister(&connection_rtnl);

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct gateway_data *data = value;

		del_gateway_routes_if_active(data, CONNMAN_IPCONFIG_TYPE_ALL);
	}

	g_hash_table_destroy(gateway_hash);
	gateway_hash = NULL;
}
