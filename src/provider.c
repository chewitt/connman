/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gdbus.h>
#include <gweb/gresolv.h>

#include "connman.h"
#include "src/shared/util.h"

static DBusConnection *connection = NULL;

static GHashTable *provider_hash = NULL;

static GSList *driver_list = NULL;

struct connman_provider {
	int refcount;
	bool immutable;
	struct connman_service *vpn_service;
	int index;
	char *identifier;
	bool family[AF_ARRAY_LENGTH];
	struct connman_provider_driver *driver;
	void *driver_data;
	bool ipv6_data_leak_prevention;
};

static void provider_set_family(struct connman_provider *provider, int family)
{
	if (!provider)
		return;

	util_set_afs(provider->family, family);
}

static bool provider_get_family(struct connman_provider *provider, int family)
{
	if (!provider)
		return false;

	return util_get_afs(provider->family, family);
}

static void provider_reset_family(struct connman_provider *provider)
{
	if (!provider)
		return;

	util_reset_afs(provider->family);
}

void __connman_provider_append_properties(struct connman_provider *provider,
							DBusMessageIter *iter)
{
	const char *host, *domain, *type;
	dbus_bool_t split_routing;

	if (!provider->driver || !provider->driver->get_property)
		return;

	host = provider->driver->get_property(provider, "Host");
	domain = provider->driver->get_property(provider, "Domain");
	type = provider->driver->get_property(provider, "Type");

	if (host)
		connman_dbus_dict_append_basic(iter, "Host",
					DBUS_TYPE_STRING, &host);

	if (domain)
		connman_dbus_dict_append_basic(iter, "Domain",
					DBUS_TYPE_STRING, &domain);

	if (type)
		connman_dbus_dict_append_basic(iter, "Type", DBUS_TYPE_STRING,
						 &type);

	if (provider->vpn_service) {
		split_routing = connman_provider_is_split_routing(provider);
		connman_dbus_dict_append_basic(iter, "SplitRouting",
					DBUS_TYPE_BOOLEAN, &split_routing);
	}
}

struct connman_provider *
connman_provider_ref_debug(struct connman_provider *provider,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", provider, provider->refcount + 1,
		file, line, caller);

	__sync_fetch_and_add(&provider->refcount, 1);

	return provider;
}

static void provider_remove(struct connman_provider *provider)
{
	if (provider->driver) {
		provider->driver->remove(provider);
		provider->driver = NULL;
	}
}

static void provider_destruct(struct connman_provider *provider)
{
	DBG("provider %p", provider);

	g_free(provider->identifier);
	g_free(provider);
}

void connman_provider_unref_debug(struct connman_provider *provider,
				const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", provider, provider->refcount - 1,
		file, line, caller);

	if (__sync_fetch_and_sub(&provider->refcount, 1) != 1)
		return;

	provider_destruct(provider);
}

static bool ipv6_change_running = false;

int __connman_provider_set_ipv6_for_connected(
				struct connman_provider *provider, bool enable)
{
	struct connman_service *service;
	struct connman_service *transport;
	struct connman_ipconfig *ipconfig;
	struct connman_ipconfig *tp_ipconfig;
	enum connman_service_state state;
	const char *transport_ident;
	bool single_connected_tech;
	int index4;
	int index6;

	if (ipv6_change_running)
		return -EALREADY;

	if (!provider)
		return -EINVAL;

	/* Feature is explicitly disabled for the provider */
	if (!provider->ipv6_data_leak_prevention)
		return 0;

	DBG("provider %p %s", provider, enable ? "enable" : "disable");

	service = provider->vpn_service;
	if (!service)
		return -EINVAL;

	/*
	 * Allow only when the VPN service is in ready state, service state
	 * is changed to ready before provider when connecting and changed
	 * away from ready after provider state is changed.
	 */
	state = connman_service_get_state(service);
	if (state != CONNMAN_SERVICE_STATE_READY)
		return 0;

	/*
	 * If a VPN changes from non-split routed to split routed then IPv6 on
	 * the transport must be re-enabled.
	 */
	if (__connman_service_is_split_routing(service) && !enable)
		return 0;

	/*
	 * IPv6 should be disabled when ipconfig method is OFF or disabled
	 * otherwise for the VPN.
	 */
	ipconfig = __connman_service_get_ip6config(service);
	if (__connman_ipconfig_ipv6_is_enabled(ipconfig))
		return 0;

	transport_ident = __connman_provider_get_transport_ident(provider);
	transport = connman_service_lookup_from_identifier(transport_ident);

	switch (connman_service_get_type(transport)) {
	/*
	 * Do not disable IPv6 for a VPN that has a VPN as transport with
	 * IPv6 enabled.
	 */
	case CONNMAN_SERVICE_TYPE_VPN:
		tp_ipconfig = __connman_service_get_ip6config(transport);
		if (__connman_ipconfig_ipv6_is_enabled(tp_ipconfig))
			return 0;
		
		break;
	/*
	 * Or for a transport that does not have IPv4 address set. This may
	 * be the case that a DNS64 is in use with the help of a plugin and
	 * data will be tunneled over IPv6 in which case it must stay on.
	 * Similarly in dual index (interface) support IPv6 is the tunnel.
	 */
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		tp_ipconfig = __connman_service_get_ip4config(transport);
		if (!tp_ipconfig)
			return 0;

		if (!connman_ipconfig_has_ipaddress_set(tp_ipconfig)) {
			DBG("transport %p has no IPv4 set, not disabling IPv6",
								transport);
			return 0;
		}

		index4 = __connman_ipconfig_get_index(tp_ipconfig);

		tp_ipconfig = __connman_service_get_ip6config(transport);
		index6 = __connman_ipconfig_get_index(tp_ipconfig);

		if (index4 != -1 && index6 != -1 && index4 != index6) {
			DBG("transport %p has two interfaces: IPv4 %d IPv6 %d. "
						"Not disabling IPv6", transport,
						index4, index6);
			return 0;
		}

		break;
	default:
		break;
	}

	single_connected_tech =
			connman_setting_get_bool("SingleConnectedTechnology");

	/* If re-enabling IPv6 set the internal status prior to enabling IPv6
	 * for connected servises to allow the IPv6 ipconfig enabled check to
	 * return correct value.
	 */
	if (enable && !single_connected_tech)
		__connman_ipconfig_set_ipv6_support(enable);

	/* In case a sevice of same type that the current transport is changed
	 * to use another, e.g., WiFi AP, then the service is first
	 * disconnected which in turn calls provider_indicate_state() when
	 * provider is being disconnected and this function gets called. In
	 * such case another call to provider_indicate_state() can be made
	 * while traversing through the services list with
	 * __connman_service_set_ipv6_for_connected() to disconnect this
	 * provider. Therefore, using this boolean can prevent a loop within
	 * loop from being executed.
	 */
	ipv6_change_running = true;
	
	/* Set IPv6 for connected, excluding VPN and include transport. */
	__connman_service_set_ipv6_for_connected(service, transport, enable);

	/*
	 * Disable internal IPv6 use after disabling IPv6 for the connected
	 * services to allow IPv6 enabled check to work.
	 */
	if (!enable && !single_connected_tech)
		__connman_ipconfig_set_ipv6_support(enable);

	ipv6_change_running = false;

	return 0;
}

static int provider_indicate_state(struct connman_provider *provider,
					enum connman_service_state state)
{
	int err;

	DBG("state %d", state);

	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		break;
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		__connman_service_start_connect_timeout(provider->vpn_service,
								true);
		break;
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		err = __connman_provider_set_ipv6_for_connected(provider,
									false);
		if (err && err != -EALREADY)
			DBG("cannot disable IPv6 on provider %p transport",
								provider);
		break;
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		err = __connman_provider_set_ipv6_for_connected(provider,
									true);
		if (err && err != -EALREADY)
			DBG("cannot enable IPv6 on provider %p transport",
								provider);

		break;
	}

	__connman_service_ipconfig_indicate_state(provider->vpn_service, state,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	return __connman_service_ipconfig_indicate_state(provider->vpn_service,
					state, CONNMAN_IPCONFIG_TYPE_IPV6);
}

int connman_provider_disconnect(struct connman_provider *provider)
{
	int err;

	DBG("provider %p", provider);

	if (provider->driver && provider->driver->disconnect)
		err = provider->driver->disconnect(provider);
	else
		return -EOPNOTSUPP;

	if (provider->vpn_service)
		provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_DISCONNECT);

	if (err < 0)
		return err;

	if (provider->vpn_service)
		provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_IDLE);

	provider_reset_family(provider);

	return 0;
}

int connman_provider_remove(struct connman_provider *provider)
{
	DBG("Removing VPN %s", provider->identifier);

	provider_remove(provider);

	connman_provider_set_state(provider, CONNMAN_PROVIDER_STATE_IDLE);

	g_hash_table_remove(provider_hash, provider->identifier);

	return 0;
}

int __connman_provider_connect(struct connman_provider *provider,
					const char *dbus_sender)
{
	int err;

	DBG("provider %p", provider);

	if (provider->driver && provider->driver->connect)
		err = provider->driver->connect(provider, dbus_sender);
	else
		return -EOPNOTSUPP;

	switch (err) {
	case 0:
	case -EALREADY:
		break;
	case -EINPROGRESS:
		provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_ASSOCIATION);
		return -EINPROGRESS;
	}

	return err;
}

int __connman_provider_remove_by_path(const char *path)
{
	struct connman_provider *provider;
	GHashTableIter iter;
	gpointer value, key;

	DBG("path %s", path);

	g_hash_table_iter_init(&iter, provider_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		const char *srv_path;
		provider = value;

		if (!provider->vpn_service)
			continue;

		srv_path = __connman_service_get_path(provider->vpn_service);

		if (g_strcmp0(srv_path, path) == 0) {
			DBG("Removing VPN %s", provider->identifier);

			provider_remove(provider);

			connman_provider_set_state(provider,
						CONNMAN_PROVIDER_STATE_IDLE);

			g_hash_table_remove(provider_hash,
						provider->identifier);
			return 0;
		}
	}

	return -ENXIO;
}

static int set_connected(struct connman_provider *provider,
					bool connected)
{
	struct connman_service *service = provider->vpn_service;
	struct connman_ipconfig *ipconfig_ipv4 = NULL;
	struct connman_ipconfig *ipconfig_ipv6 = NULL;

	DBG("provider %p", provider);

	if (!service)
		return -ENODEV;

	if (provider_get_family(provider, AF_INET))
		ipconfig_ipv4 = __connman_service_get_ipconfig(service,
								AF_INET);

	if (provider_get_family(provider, AF_INET6))
		ipconfig_ipv6 = __connman_service_get_ipconfig(service,
								AF_INET6);

	if (connected) {
		if (!ipconfig_ipv4 && !ipconfig_ipv6) {
			provider_indicate_state(provider,
						CONNMAN_SERVICE_STATE_FAILURE);
			return -EIO;
		}

		if (ipconfig_ipv4) {
			__connman_ipconfig_address_add(ipconfig_ipv4);
			__connman_ipconfig_gateway_add(ipconfig_ipv4);
		}

		if (ipconfig_ipv6) {
			__connman_ipconfig_address_add(ipconfig_ipv6);
			__connman_ipconfig_gateway_add(ipconfig_ipv6);
		}

		provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_READY);

		if (provider->driver && provider->driver->set_routes)
			provider->driver->set_routes(provider,
						CONNMAN_PROVIDER_ROUTE_ALL);

	} else {
		if (ipconfig_ipv4) {
			provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_DISCONNECT);
			__connman_ipconfig_gateway_remove(ipconfig_ipv4);
		}

		if (ipconfig_ipv6) {
			provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_DISCONNECT);
			__connman_ipconfig_gateway_remove(ipconfig_ipv6);
		}

		provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_IDLE);
	}

	return 0;
}

int connman_provider_set_state(struct connman_provider *provider,
					enum connman_provider_state state)
{
	if (!provider || !provider->vpn_service)
		return -EINVAL;

	switch (state) {
	case CONNMAN_PROVIDER_STATE_UNKNOWN:
		return -EINVAL;
	case CONNMAN_PROVIDER_STATE_IDLE:
		return set_connected(provider, false);
	case CONNMAN_PROVIDER_STATE_ASSOCIATION:
		/* Connect timeout is not effective for VPNs in this state */
		return provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_ASSOCIATION);
	case CONNMAN_PROVIDER_STATE_CONNECT:
		return provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_CONFIGURATION);
	case CONNMAN_PROVIDER_STATE_READY:
		return set_connected(provider, true);
	case CONNMAN_PROVIDER_STATE_DISCONNECT:
		return provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_DISCONNECT);
	case CONNMAN_PROVIDER_STATE_FAILURE:
		return provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_FAILURE);
	}

	return -EINVAL;
}

int connman_provider_indicate_error(struct connman_provider *provider,
					enum connman_provider_error error)
{
	enum connman_service_error service_error;

	switch (error) {
	case CONNMAN_PROVIDER_ERROR_LOGIN_FAILED:
		service_error = CONNMAN_SERVICE_ERROR_LOGIN_FAILED;
		break;
	case CONNMAN_PROVIDER_ERROR_AUTH_FAILED:
		service_error = CONNMAN_SERVICE_ERROR_AUTH_FAILED;
		break;
	case CONNMAN_PROVIDER_ERROR_CONNECT_FAILED:
		service_error = CONNMAN_SERVICE_ERROR_CONNECT_FAILED;
		break;
	default:
		service_error = CONNMAN_SERVICE_ERROR_UNKNOWN;
		break;
	}

	return __connman_service_indicate_error(provider->vpn_service,
							service_error);
}

int connman_provider_create_service(struct connman_provider *provider)
{
	if (provider->vpn_service) {
		bool connected;

		connected = __connman_service_is_connected_state(
			provider->vpn_service, CONNMAN_IPCONFIG_TYPE_IPV4);
		if (connected)
			return -EALREADY;

		connected = __connman_service_is_connected_state(
			provider->vpn_service, CONNMAN_IPCONFIG_TYPE_IPV6);
		if (connected)
			return -EALREADY;

		return 0;
	}

	provider->vpn_service =
		__connman_service_create_from_provider(provider);

	if (!provider->vpn_service) {
		connman_warn("service creation failed for provider %s",
			provider->identifier);

		g_hash_table_remove(provider_hash, provider->identifier);
		return -EOPNOTSUPP;
	}

	return 0;
}

bool __connman_provider_is_immutable(struct connman_provider *provider)

{
	if (provider)
		return provider->immutable;

	return false;
}

int connman_provider_set_immutable(struct connman_provider *provider,
						bool immutable)
{
	if (!provider)
		return -EINVAL;

	provider->immutable = immutable;

	return 0;
}

static struct connman_provider *provider_lookup(const char *identifier)
{
	return g_hash_table_lookup(provider_hash, identifier);
}

static void connection_ready(DBusMessage *msg, int error_code, void *user_data)
{
	DBusMessage *reply;
	const char *identifier = user_data;

	DBG("msg %p error %d", msg, error_code);

	if (error_code != 0) {
		reply = __connman_error_failed(msg, -error_code);
		if (!g_dbus_send_message(connection, reply))
			DBG("reply %p send failed", reply);
	} else {
		const char *path;
		struct connman_provider *provider;

		provider = provider_lookup(identifier);
		if (!provider) {
			reply = __connman_error_failed(msg, EINVAL);
			g_dbus_send_message(connection, reply);
			return;
		}

		path = __connman_service_get_path(provider->vpn_service);

		g_dbus_send_reply(connection, msg,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);
	}
}

int __connman_provider_create_and_connect(DBusMessage *msg)
{
	struct connman_provider_driver *driver;

	if (!driver_list)
		return -EINVAL;

	driver = driver_list->data;
	if (!driver || !driver->create)
		return -EINVAL;

	DBG("msg %p", msg);

	return driver->create(msg, connection_ready);
}

const char *__connman_provider_get_ident(struct connman_provider *provider)
{
	if (!provider)
		return NULL;

	return provider->identifier;
}

const char * __connman_provider_get_transport_ident(
					struct connman_provider *provider)
{
	if (!provider)
		return NULL;

	if (provider->driver && provider->driver->get_property)
		return provider->driver->get_property(provider, "Transport");

	return NULL;
}

int connman_provider_set_string(struct connman_provider *provider,
					const char *key, const char *value)
{
	if (provider->driver && provider->driver->set_property)
		return provider->driver->set_property(provider, key, value);

	return 0;
}

const char *connman_provider_get_string(struct connman_provider *provider,
							const char *key)
{
	if (provider->driver && provider->driver->get_property)
		return provider->driver->get_property(provider, key);

	return NULL;
}

bool
__connman_provider_check_routes(struct connman_provider *provider)
{
	if (!provider)
		return false;

	if (provider->driver && provider->driver->check_routes)
		return provider->driver->check_routes(provider);

	return false;
}

void *connman_provider_get_data(struct connman_provider *provider)
{
	return provider->driver_data;
}

void connman_provider_set_data(struct connman_provider *provider, void *data)
{
	provider->driver_data = data;
}

void connman_provider_set_index(struct connman_provider *provider, int index)
{
	struct connman_service *service = provider->vpn_service;
	struct connman_ipconfig *ipconfig;

	DBG("");

	if (!service)
		return;

	ipconfig = __connman_service_get_ip4config(service);

	if (!ipconfig) {
		connman_service_create_ip4config(service, index);

		ipconfig = __connman_service_get_ip4config(service);
		if (!ipconfig) {
			DBG("Couldn't create ipconfig");
			goto done;
		}
	}

	__connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_OFF);
	__connman_ipconfig_set_index(ipconfig, index);

	ipconfig = __connman_service_get_ip6config(service);

	if (!ipconfig) {
		connman_service_create_ip6config(service, index);

		ipconfig = __connman_service_get_ip6config(service);
		if (!ipconfig) {
			DBG("Couldn't create ipconfig for IPv6");
			goto done;
		}
	}

	__connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_OFF);
	__connman_ipconfig_set_index(ipconfig, index);

done:
	provider->index = index;
}

int connman_provider_get_index(struct connman_provider *provider)
{
	return provider->index;
}

int connman_provider_set_ipaddress(struct connman_provider *provider,
					struct connman_ipaddress *ipaddress)
{
	struct connman_ipconfig *ipconfig = NULL;

	ipconfig = __connman_service_get_ipconfig(provider->vpn_service,
							ipaddress->family);
	if (!ipconfig)
		return -EINVAL;

	provider_set_family(provider, ipaddress->family);

	__connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_FIXED);

	__connman_ipconfig_set_local(ipconfig, ipaddress->local);
	__connman_ipconfig_set_peer(ipconfig, ipaddress->peer);
	__connman_ipconfig_set_broadcast(ipconfig, ipaddress->broadcast);
	__connman_ipconfig_set_gateway(ipconfig, ipaddress->gateway);
	__connman_ipconfig_set_prefixlen(ipconfig, ipaddress->prefixlen);

	return 0;
}

int connman_provider_set_pac(struct connman_provider *provider, const char *pac)
{
	DBG("provider %p pac %s", provider, pac);

	__connman_service_set_pac(provider->vpn_service, pac);

	return 0;
}


int connman_provider_set_domain(struct connman_provider *provider,
					const char *domain)
{
	DBG("provider %p domain %s", provider, domain);

	__connman_service_set_domainname(provider->vpn_service, domain);

	return 0;
}

int connman_provider_set_nameservers(struct connman_provider *provider,
					char * const *nameservers)
{
	int i;

	DBG("provider %p nameservers %p", provider, nameservers);

	__connman_service_nameserver_clear(provider->vpn_service);

	if (!nameservers)
		return 0;

	for (i = 0; nameservers[i]; i++)
		__connman_service_nameserver_append(provider->vpn_service,
						nameservers[i], false);

	return 0;
}

bool connman_provider_get_autoconnect(struct connman_provider *provider)
{
	DBG("");

	if (!provider || !provider->vpn_service)
		return false;

	return connman_service_get_autoconnect(provider->vpn_service);
}

void connman_provider_set_autoconnect(struct connman_provider *provider,
								bool flag)
{
	if (!provider || !provider->vpn_service)
		return;

	/* Save VPN service if autoconnect value changes */
	if (connman_service_set_autoconnect(provider->vpn_service, flag))
		__connman_service_save(provider->vpn_service);
}

bool connman_provider_is_split_routing(struct connman_provider *provider)
{
	if (!provider || !provider->vpn_service)
		return false;

	return __connman_service_is_split_routing(provider->vpn_service);
}

int connman_provider_set_split_routing(struct connman_provider *provider,
							bool split_routing)
{
	struct connman_service *service;
	enum connman_ipconfig_type type;
	int service_index;
	int vpn_index;
	bool service_split_routing;
	int err = 0;

	DBG("");

	if (!provider || !provider->vpn_service)
		return -EINVAL;

	service_split_routing = __connman_service_is_split_routing(
				provider->vpn_service);

	if (service_split_routing == split_routing) {
		DBG("split_routing already set %s",
					split_routing ? "true" : "false");
		return -EALREADY;
	}

	if (provider_get_family(provider, AF_INET) &&
				provider_get_family(provider, AF_INET6))
		type = CONNMAN_IPCONFIG_TYPE_ALL;
	else if (provider_get_family(provider, AF_INET))
		type = CONNMAN_IPCONFIG_TYPE_IPV4;
	else if (provider_get_family(provider, AF_INET6))
		type = CONNMAN_IPCONFIG_TYPE_IPV6;
	else
		type = CONNMAN_IPCONFIG_TYPE_UNKNOWN;

	if (!__connman_service_is_connected_state(provider->vpn_service,
								type)) {
		DBG("%p VPN not connected", provider->vpn_service);
		goto save;
	}

	vpn_index = __connman_service_get_index(provider->vpn_service);
	service_index = __connman_connection_get_vpn_phy_index(vpn_index);
	service = __connman_service_lookup_from_index(service_index);
	if (!service)
		goto save;

	if (split_routing)
		err = __connman_service_move(service, provider->vpn_service,
					true);
	else
		err = __connman_service_move(provider->vpn_service, service,
					true);

	if (err) {
		connman_warn("cannot move service %p and VPN %p error %d",
					service, provider->vpn_service, err);

		/*
		 * In case of error notify vpnd about the current split routing
		 * state.
		 */
		__connman_service_split_routing_changed(provider->vpn_service);
		goto out;
	}

save:
	__connman_service_set_split_routing(provider->vpn_service,
								split_routing);
	__connman_service_save(provider->vpn_service);

out:
	return err;
}

bool connman_provider_get_family(struct connman_provider *provider, int family)
{
	return provider_get_family(provider, family);
}

void connman_provider_set_ipv6_data_leak_prevention(
				struct connman_provider *provider, bool enable)
{
	if (!provider)
		return;

	provider->ipv6_data_leak_prevention = enable;
}

static void unregister_provider(gpointer data)
{
	struct connman_provider *provider = data;

	DBG("provider %p service %p", provider, provider->vpn_service);

	if (provider->vpn_service) {
		connman_service_unref(provider->vpn_service);
		__connman_service_remove(provider->vpn_service);
		provider->vpn_service = NULL;
	}

	connman_provider_unref(provider);
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	return 0;
}

int connman_provider_driver_register(struct connman_provider_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);
	return 0;
}

void connman_provider_driver_unregister(struct connman_provider_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

void connman_provider_set_driver(struct connman_provider *provider,
				struct connman_provider_driver *driver)
{
	provider->driver = driver;
}

static void provider_disconnect_all(gpointer key, gpointer value,
						gpointer user_data)
{
	struct connman_provider *provider = value;

	connman_provider_disconnect(provider);
}

static void provider_offline_mode(bool enabled)
{
	DBG("enabled %d", enabled);

	if (enabled)
		g_hash_table_foreach(provider_hash, provider_disconnect_all,
									NULL);

}

static void provider_initialize(struct connman_provider *provider)
{
	DBG("provider %p", provider);

	provider->index = 0;
	provider->identifier = NULL;
	provider->ipv6_data_leak_prevention = false;
}

static struct connman_provider *provider_new(void)
{
	struct connman_provider *provider;

	provider = g_try_new0(struct connman_provider, 1);
	if (!provider)
		return NULL;

	provider->refcount = 1;

	DBG("provider %p", provider);
	provider_initialize(provider);

	return provider;
}

struct connman_provider *connman_provider_get(const char *identifier)
{
	struct connman_provider *provider;

	provider = g_hash_table_lookup(provider_hash, identifier);
	if (provider)
		return provider;

	provider = provider_new();
	if (!provider)
		return NULL;

	DBG("provider %p", provider);

	provider->identifier = g_strdup(identifier);

	g_hash_table_insert(provider_hash, provider->identifier, provider);

	return provider;
}

void connman_provider_put(struct connman_provider *provider)
{
	g_hash_table_remove(provider_hash, provider->identifier);
}

static struct connman_provider *provider_get(int index)
{
	GHashTableIter iter;
	gpointer value, key;

	g_hash_table_iter_init(&iter, provider_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct connman_provider *provider = value;

		if (provider->index == index)
			return provider;
	}

	return NULL;
}

static void provider_service_changed(struct connman_service *service,
				enum connman_service_state state)
{
	struct connman_provider *provider;
	struct connman_ipconfig *ipconfig;
	int vpn_index, service_index;

	if (!service)
		return;

	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		return;
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		break;
	}

	/* Try IPv4 first since service may have IP set from two interfaces */
	ipconfig = __connman_service_get_ip4config(service);
	service_index = __connman_ipconfig_get_index(ipconfig);

	vpn_index = __connman_connection_get_vpn_index(service_index);

	DBG("service %p %s state %d index %d/%d", service,
		connman_service_get_identifier(service),
		state, service_index, vpn_index);

	if (vpn_index < 0) {
		/* Then try with IPv6 */
		ipconfig = __connman_service_get_ip6config(service);
		service_index = __connman_ipconfig_get_index(ipconfig);

		vpn_index = __connman_connection_get_vpn_index(service_index);
	}

	if (vpn_index < 0)
		return;

	provider = provider_get(vpn_index);
	if (!provider)
		return;

	DBG("disconnect %p index %d", provider, vpn_index);

	connman_provider_disconnect(provider);
}

static const struct connman_notifier provider_notifier = {
	.name			= "provider",
	.offline_mode		= provider_offline_mode,
	.service_state_changed	= provider_service_changed,
};

int __connman_provider_init(void)
{
	int err;

	DBG("");

	connection = connman_dbus_get_connection();

	provider_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, unregister_provider);

	err = connman_notifier_register(&provider_notifier);
	if (err < 0) {
		g_hash_table_destroy(provider_hash);
		dbus_connection_unref(connection);
	}

	return err;
}

void __connman_provider_cleanup(void)
{
	DBG("");

	connman_notifier_unregister(&provider_notifier);

	g_hash_table_destroy(provider_hash);
	provider_hash = NULL;

	dbus_connection_unref(connection);
}
