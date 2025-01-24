/*
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2019  Daniel Wagner. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/ipconfig.h>
#include <connman/inet.h>
#include <connman/dbus.h>
#include <connman/setting.h>
#include <connman/vpn-dbus.h>

#include <gweb/gresolv.h>

#include "../vpn-provider.h"
#include "../vpn.h"

#include "vpn.h"
#include "wireguard.h"

#define DNS_RERESOLVE_TIMEOUT 20
#define DNS_RERESOLVE_ERROR_LIMIT 5
#define ROUTE_SETUP_TIMEOUT 200 // ms
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

struct wireguard_info {
	struct vpn_provider *provider;
	struct wg_device device;
	struct wg_peer peer;
	char *endpoint_fqdn;
	char *port;
	guint reresolve_id;
	GResolv *resolv;
	guint resolv_id;
	guint remove_resolv_id;
	guint dying_id;
	guint route_setup_id;
};

struct sockaddr_u {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	};
};

struct {
	const char	*opt;
	bool		save;
} wg_options[] = {
	{"WireGuard.Address", true},
	{"WireGuard.ListenPort", true},
	{"WireGuard.DNS", true},
	{"WireGuard.PrivateKey", true}, // TODO set false after agent support
	{"WireGuard.PresharedKey", true}, // TODO set false after agent support
	{"WireGuard.PublicKey", true},
	{"WireGuard.AllowedIPs", true},
	{"WireGuard.EndpointPort", true},
	{"WireGuard.PersistentKeepalive", true},
	{"WireGuard.DisableIPv6", true}
};

static struct wireguard_info *create_private_data(struct vpn_provider *provider)
{
	struct wireguard_info *info;

	info = g_malloc0(sizeof(struct wireguard_info));
	info->peer.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;
	info->device.flags = WGDEVICE_HAS_PRIVATE_KEY;
	info->device.first_peer = &info->peer;
	info->device.last_peer = &info->peer;
	info->provider = vpn_provider_ref(provider);

	return info;
}

static void free_private_data(struct wireguard_info *info)
{
	if (vpn_provider_get_plugin_data(info->provider) == info)
		vpn_provider_set_plugin_data(info->provider, NULL);

	vpn_provider_unref(info->provider);
	g_free(info->endpoint_fqdn);
	g_free(info->port);
	g_free(info);
}

static int parse_key(const char *str, wg_key key)
{
	unsigned char *buf;
	size_t len;

	buf = g_base64_decode(str, &len);

	if (len != 32) {
		g_free(buf);
		return -EINVAL;
	}

	memcpy(key, buf, 32);

	g_free(buf);
	return 0;
}

static int parse_allowed_ips(const char *allowed_ips, wg_peer *peer,
							bool *do_split_routing)
{
	struct wg_allowedip *curaip, *allowedip;
	char buf[INET6_ADDRSTRLEN];
	char **tokens, **toks;
	char *send;
	int i;

	*do_split_routing = true;
	curaip = NULL;
	tokens = g_strsplit(allowed_ips, ", ", -1);
	for (i = 0; tokens[i]; i++) {
		toks = g_strsplit(tokens[i], "/", -1);
		if (g_strv_length(toks) != 2) {
			DBG("Ignore AllowedIPs value %s", tokens[i]);
			g_strfreev(toks);
			continue;
		}

		allowedip = g_malloc0(sizeof(*allowedip));

		if (inet_pton(AF_INET, toks[0], buf) == 1) {
			allowedip->family = AF_INET;
			memcpy(&allowedip->ip4, buf, sizeof(allowedip->ip4));
		} else if (inet_pton(AF_INET6, toks[0], buf) == 1) {
			allowedip->family = AF_INET6;
			memcpy(&allowedip->ip6, buf, sizeof(allowedip->ip6));
		} else {
			DBG("Ignore AllowedIPs value %s", tokens[i]);
			g_free(allowedip);
			g_strfreev(toks);
			continue;
		}

		allowedip->cidr = g_ascii_strtoull(toks[1], &send, 10);

		/*
		 * Force split routing off if any address is detected as using
		 * these as allowed IPs indicates that WireGuard is to be used
		 * to route all traffic.
		 */
		if (connman_inet_is_any_addr(toks[0], allowedip->family))
			*do_split_routing = false;

		g_strfreev(toks);

		if (!curaip)
			peer->first_allowedip = allowedip;
		else
			curaip->next_allowedip = allowedip;

		curaip = allowedip;
	}

	peer->last_allowedip = curaip;
	g_strfreev(tokens);

	return 0;
}

static int parse_endpoint(const char *host, const char *port, struct sockaddr_u *addr)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	char **tokens;
	int sk;
	int err;
	unsigned int len;

	/*
	 * getaddrinfo() relies on inet_pton() that suggests using addresses
	 * without CIDR notation. Host should contain the address in CIDR
	 * notation to be able to pass the prefix length to ConnMan via D-Bus.
	 */
	tokens = g_strsplit(host, "/", -1);
	len = g_strv_length(tokens);
	if (len > 2 || len < 1) {
		DBG("Failure tokenizing host %s", host);
		g_strfreev(tokens);
		return -EINVAL;
	}

	DBG("using host %s", tokens[0]);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	err = getaddrinfo(tokens[0], port, &hints, &result);
	g_strfreev(tokens);

	if (err < 0) {
		DBG("Failed to resolve host address: %s", gai_strerror(err));
		return -EINVAL;
	}

	for (rp = result; rp; rp = rp->ai_next) {
		sk = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sk < 0)
			continue;
		if (connect(sk, rp->ai_addr, rp->ai_addrlen) != -1) {
			/* success */
			close(sk);
			break;
		}

		close(sk);
	}

	if (!rp) {
		freeaddrinfo(result);
		return -EINVAL;
	}

	memcpy(addr, rp->ai_addr, rp->ai_addrlen);
	freeaddrinfo(result);

	return 0;
}

struct wg_ipaddresses {
	struct connman_ipaddress *ipaddress_ipv4;
	struct connman_ipaddress *ipaddress_ipv6;
};

static char *cidr_to_netmask(int family, unsigned char cidr)
{
	switch (family) {
	case AF_INET:
		return g_strdup_printf("%d.%d.%d.%d",
				((0xffffffff << (32 - cidr)) >> 24) & 0xff,
				((0xffffffff << (32 - cidr)) >> 16) & 0xff,
				((0xffffffff << (32 - cidr)) >> 8) & 0xff,
				((0xffffffff << (32 - cidr)) >> 0) & 0xff);

	case AF_INET6:
		return g_strdup_printf("%u", cidr);
	default:
		break;
	}

	return NULL;
}

static int parse_addresses(const char *address, const char *gateway,
		struct wg_ipaddresses *ipaddresses)
{
	char buf[INET6_ADDRSTRLEN];
	unsigned char prefixlen;
	char **addresses;
	char **tokens;
	char *end, *netmask;
	int err;
	int i;

	addresses = g_strsplit(address, ", ", -1);
	if (!g_strv_length(addresses)) {
		g_strfreev(addresses);
		return -EINVAL;
	}

	for (i = 0; addresses[i]; i++) {
		struct connman_ipaddress *ipaddress = NULL;
		int family = 0;

		tokens = g_strsplit(addresses[i], "/", -1);
		if (g_strv_length(tokens) != 2) {
			g_strfreev(tokens);
			DBG("Invalid Wireguard.Address value %s", addresses[i]);
			continue;
		}

		DBG("address %s", addresses[i]);

		prefixlen = g_ascii_strtoull(tokens[1], &end, 10);

		if (inet_pton(AF_INET, tokens[0], buf) == 1) {
			if (ipaddresses->ipaddress_ipv4) {
				g_strfreev(tokens);
				DBG("IPv4 address already set");
				err = -EALREADY;
				continue;
			}

			family = AF_INET;
			netmask = cidr_to_netmask(family, prefixlen);
			ipaddress = connman_ipaddress_alloc(family);
			err = connman_ipaddress_set_ipv4(ipaddress, tokens[0],
							netmask, gateway);
			g_free(netmask);
		} else if (inet_pton(AF_INET6, tokens[0], buf) == 1) {
			if (ipaddresses->ipaddress_ipv6) {
				g_strfreev(tokens);
				DBG("IPv6 address already set");
				err = -EALREADY;
				continue;
			}

			family = AF_INET6;
			ipaddress = connman_ipaddress_alloc(family);
			err = connman_ipaddress_set_ipv6(ipaddress, tokens[0],
							prefixlen, gateway);
		} else {
			DBG("Invalid Wireguard.Address value");
			err = -EINVAL;
		}

		g_strfreev(tokens);
		if (err) {
			connman_ipaddress_free(ipaddress);
			continue;
		}

		connman_ipaddress_set_p2p(ipaddress, true);

		if (family == AF_INET)
			ipaddresses->ipaddress_ipv4 = ipaddress;
		else if (family == AF_INET6)
			ipaddresses->ipaddress_ipv6 = ipaddress;
	}

	g_strfreev(addresses);

	return (ipaddresses->ipaddress_ipv4 || ipaddresses->ipaddress_ipv6) ?
				0 : -EINVAL;
}

struct ifname_data {
	char *ifname;
	bool found;
};

static void ifname_check_cb(int index, void *user_data)
{
	struct ifname_data *data = (struct ifname_data *)user_data;
	char *ifname;

	ifname = connman_inet_ifname(index);

	if (!g_strcmp0(ifname, data->ifname))
		data->found = true;
}

static char *get_ifname(void)
{
	struct ifname_data data;
	int i;

	for (i = 0; i < 256; i++) {
		data.ifname = g_strdup_printf("wg%d", i);
		data.found = false;
		vpn_ipconfig_foreach(ifname_check_cb, &data);

		if (!data.found)
			return data.ifname;

		g_free(data.ifname);
	}

	return NULL;
}

static bool sockaddr_cmp_addr(struct sockaddr_u *a, struct sockaddr_u *b)
{
	if (a->sa.sa_family != b->sa.sa_family)
		return false;

	if (a->sa.sa_family == AF_INET)
		return !memcmp(&a->sin, &b->sin, sizeof(struct sockaddr_in));
	else if (a->sa.sa_family == AF_INET6)
		return !memcmp(a->sin6.sin6_addr.s6_addr,
				b->sin6.sin6_addr.s6_addr,
				sizeof(a->sin6.sin6_addr.s6_addr));

	return false;
}

static void run_dns_reresolve(struct wireguard_info *info);
static void run_route_setup(struct wireguard_info *info, guint timeout);

static void remove_resolv(struct wireguard_info *info)
{
	DBG("");

	if (info->remove_resolv_id)
		g_source_remove(info->remove_resolv_id);

	if (info->resolv && info->resolv_id) {
		DBG("cancel resolv lookup");
		vpn_util_cancel_resolve(info->resolv, info->resolv_id);
	}

	info->resolv_id = 0;
	info->remove_resolv_id = 0;

	vpn_util_resolve_unref(info->resolv);
	info->resolv = NULL;
}

static gboolean remove_resolv_cb(gpointer user_data)
{
	struct wireguard_info *info = user_data;

	remove_resolv(info);

	return G_SOURCE_REMOVE;
}

static void resolve_endpoint_cb(GResolvResultStatus status,
					char **results, gpointer user_data)
{
	struct wireguard_info *info = user_data;
	struct sockaddr_u addr;
	int err;

	DBG("");

	if (!info->resolv && info->resolv_id) {
		DBG("resolv already removed");
		return;
	}

	/*
	 * We cannot unref the resolver here as resolv struct is manipulated
	 * by gresolv.c after we return from this callback. By clearing the
	 * resolv_id no attempt to cancel the lookup that has been executed
	 * here is done.
	 */
	info->remove_resolv_id = g_timeout_add(0, remove_resolv_cb, info);
	info->resolv_id = 0;

	switch (status) {
	case G_RESOLV_RESULT_STATUS_SUCCESS:
		if (!results || !g_strv_length(results)) {
			DBG("no resolved results");
			if (info->provider)
				vpn_provider_add_error(info->provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);

			return;
		}

		DBG("resolv success, parse endpoint");
		break;
	/* request timeouts or an server issue is not an error, try again */
	case G_RESOLV_RESULT_STATUS_NO_RESPONSE:
	case G_RESOLV_RESULT_STATUS_SERVER_FAILURE:
		DBG("retry DNS reresolve");
		if (info->provider)
			vpn_provider_add_error(info->provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);

		run_dns_reresolve(info);
		return;
	/* Consider these as non-continuable errors */
	case G_RESOLV_RESULT_STATUS_ERROR:
	case G_RESOLV_RESULT_STATUS_FORMAT_ERROR:
	case G_RESOLV_RESULT_STATUS_NAME_ERROR:
	case G_RESOLV_RESULT_STATUS_NOT_IMPLEMENTED:
	case G_RESOLV_RESULT_STATUS_REFUSED:
	case G_RESOLV_RESULT_STATUS_NO_ANSWER:
		DBG("stop DNS reresolve");
		if (info->provider)
			vpn_provider_add_error(info->provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);

		return;
	}

	/*
	 * If this fails after being connected it means configuration error
	 * that results in connection errors.
	 */
	err = parse_endpoint(info->endpoint_fqdn, info->port, &addr);
	if (err) {
		if (info->provider)
			vpn_provider_add_error(info->provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);
		run_dns_reresolve(info);
		return;
	}

	if (sockaddr_cmp_addr(&addr,
			(struct sockaddr_u *)&info->peer.endpoint.addr)) {
		run_dns_reresolve(info);
		return;
	}

	if (addr.sa.sa_family == AF_INET)
		memcpy(&info->peer.endpoint.addr, &addr.sin,
					sizeof(info->peer.endpoint.addr4));
	else
		memcpy(&info->peer.endpoint.addr, &addr.sin6,
					sizeof(info->peer.endpoint.addr6));

	DBG("Endpoint address has changed, udpate WireGuard device");
	err = wg_set_device(&info->device);
	if (err)
		DBG("Failed to update Endpoint address for WireGuard device %s",
			info->device.name);

	run_dns_reresolve(info);

	/*
	 * Endpoint has changed and only one peer is used -> all old routes
	 * are invalid. Redo them without delay.
	 */
	vpn_provider_delete_all_routes(info->provider);
	run_route_setup(info, 0);
}

static int disconnect(struct vpn_provider *provider, int error);

static gboolean wg_dns_reresolve_cb(gpointer user_data)
{
	struct wireguard_info *info = user_data;
	int err;

	DBG("");

	info->reresolve_id = 0;

	if (info->resolv_id > 0) {
		DBG("previous query was running, abort it");
		remove_resolv(info);
	}

	info->resolv = vpn_util_resolve_new(0);
	if (!info->resolv) {
		connman_error("cannot create GResolv");
		return G_SOURCE_REMOVE;
	}

	info->resolv_id = vpn_util_resolve_hostname(info->resolv,
						info->endpoint_fqdn,
						resolve_endpoint_cb, info);

	err = vpn_util_get_resolve_error(info->resolv);
	if (!info->resolv_id && err) {
		connman_error("failed to start hostname lookup for %s, err %d",
						info->endpoint_fqdn, err);
		disconnect(info->provider, err);
	}

	return G_SOURCE_REMOVE;
}

static const char *endpoint_to_str(struct wg_peer *peer, char *buf,
							socklen_t len)
{
	struct sockaddr_u *addr;
	int family;

	addr = (struct sockaddr_u *)&peer->endpoint.addr;
	family = peer->endpoint.addr.sa_family;

	switch (family) {
	case AF_INET:
		return inet_ntop(family, &addr->sin.sin_addr, buf, len);
	case AF_INET6:
		return inet_ntop(family, &addr->sin6.sin6_addr, buf, len);
	default:
		break;
	}

	return NULL;
}

static gboolean wg_route_setup_cb(gpointer user_data)
{
	struct wireguard_info *info = user_data;
	struct wg_allowedip *allowedip;
	char addr[INET6_ADDRSTRLEN] = { 0 };
	char endpoint[INET6_ADDRSTRLEN] = { 0 };
	char *netmask;
	int family;
	unsigned long idx = 0;

	info->route_setup_id = 0;

	family = info->peer.endpoint.addr.sa_family;

	if (!endpoint_to_str(&info->peer, endpoint, INET6_ADDRSTRLEN)) {
		DBG("Faulty endpoint set, use endpoint_fqdn");
		memcpy(&endpoint, info->endpoint_fqdn, INET6_ADDRSTRLEN);
		family = connman_inet_check_ipaddress(info->endpoint_fqdn);
	}

	wg_for_each_allowedip(&info->peer, allowedip) {
		// TODO: search peers when multiple peers are supported
		if (allowedip->family != family) {
			DBG("Ignoring AllowedIP with different family as host");
			continue;
		}

		memset(&addr, 0, INET6_ADDRSTRLEN);

		switch (allowedip->family) {
		case AF_INET:
			if (!inet_ntop(allowedip->family, &allowedip->ip4, addr,
							INET6_ADDRSTRLEN)) {
				DBG("ignore invalid IPv4 address");
				continue;
			}

			break;
		case AF_INET6:
			if (!inet_ntop(allowedip->family, &allowedip->ip6, addr,
							INET6_ADDRSTRLEN)) {
				DBG("ignore invalid IPv6 address");
				continue;
			}

			break;
		default:
			DBG("ignore invalid IP family");
			continue;
		}

		if (connman_inet_is_any_addr(addr, allowedip->family)) {
			DBG("ignore any addr %s", addr);
			continue;
		}

		netmask = cidr_to_netmask(allowedip->family, allowedip->cidr);

		vpn_provider_append_route_complete(info->provider, idx,
						allowedip->family, addr,
						netmask, endpoint);

		g_free(netmask);
		++idx;
	}

	return G_SOURCE_REMOVE;
}

static void run_dns_reresolve(struct wireguard_info *info)
{
	if (info->reresolve_id)
		g_source_remove(info->reresolve_id);

	info->reresolve_id = 0;

	if (vpn_provider_get_connection_errors(info->provider) >=
						DNS_RERESOLVE_ERROR_LIMIT) {
		connman_warn("reresolve error limit reached");
		disconnect(info->provider, -ENONET);
		return;
	}

	info->reresolve_id = g_timeout_add_seconds(DNS_RERESOLVE_TIMEOUT,
						wg_dns_reresolve_cb, info);
}

static void run_route_setup(struct wireguard_info *info, guint timeout)
{
	if (info->route_setup_id)
		g_source_remove(info->route_setup_id);

	info->route_setup_id = g_timeout_add(timeout, wg_route_setup_cb, info);
}

static int wg_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb,
			const char *dbus_sender, void *user_data)
{
	struct wg_ipaddresses ipaddresses = { 0 };
	struct wireguard_info *info;
	const char *option, *gateway;
	char *ifname;
	bool do_split_routing = true;
	bool disable_ipv6 = false;
	int err = -EINVAL;

	info = create_private_data(provider);

	DBG("");

	vpn_provider_set_plugin_data(provider, info);
	vpn_provider_set_auth_error_limit(provider, 1);

	option = vpn_provider_get_string(provider, "WireGuard.ListenPort");
	if (option) {
		char *end;
		info->device.listen_port = g_ascii_strtoull(option, &end, 10);
		info->device.flags |= WGDEVICE_HAS_LISTEN_PORT;
	}

	option = vpn_provider_get_string(provider, "WireGuard.DNS");
	if (option) {
		err = vpn_provider_set_nameservers(provider, option);
		if (err) {
			DBG("Cannot set nameservers %s", option);
			goto error;
		}
	}

	option = vpn_provider_get_string(provider, "WireGuard.PrivateKey");
	if (!option) {
		DBG("WireGuard.PrivateKey is missing");
		goto error;
	}
	err = parse_key(option, info->device.private_key);
	if (err) {
		DBG("Failed to parse private key");
		goto error;
	}

	option = vpn_provider_get_string(provider, "WireGuard.PublicKey");
	if (!option) {
		DBG("WireGuard.PublicKey is missing");
		goto error;
	}
	err = parse_key(option, info->peer.public_key);
	if (err) {
		DBG("Failed to parse public key");
		goto error;
	}

	option = vpn_provider_get_string(provider, "WireGuard.PresharedKey");
	if (option) {
		info->peer.flags |= WGPEER_HAS_PRESHARED_KEY;
		err = parse_key(option, info->peer.preshared_key);
		if (err) {
			DBG("Failed to parse pre-shared key");
			goto error;
		}
	}

	option = vpn_provider_get_string(provider, "WireGuard.AllowedIPs");
	if (!option) {
		DBG("WireGuard.AllowedIPs is missing");
		goto error;
	}
	err = parse_allowed_ips(option, &info->peer, &do_split_routing);
	if (err) {
		DBG("Failed to parse allowed IPs %s", option);
		goto error;
	}

	vpn_provider_set_boolean(provider, "SplitRouting", do_split_routing,
							false);


	option = vpn_provider_get_string(provider,
					"WireGuard.PersistentKeepalive");
	if (option) {
		char *end;
		info->peer.persistent_keepalive_interval =
			g_ascii_strtoull(option, &end, 10);
		info->peer.flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
	}

	option = vpn_provider_get_string(provider, "WireGuard.EndpointPort");
	if (!option)
		option = "51820";

	gateway = vpn_provider_get_string(provider, "Host");
	/*
	 * Use the resolve timeout only with re-resolve. Here the network
	 * is setup as the transport is used. In succeeding attempts resolving
	 * is needed as it is done over potentially misconfigured WireGuard
	 * connection that may end up blocking vpnd with getaddrinfo().
	 */
	err = parse_endpoint(gateway, option,
			(struct sockaddr_u *)&info->peer.endpoint.addr);
	if (err) {
		DBG("Failed to parse endpoint %s:%s", gateway, option);
		goto error;
	}

	info->endpoint_fqdn = g_strdup(gateway);
	info->port = g_strdup(option);

	option = vpn_provider_get_string(provider, "WireGuard.Address");
	if (!option) {
		DBG("Missing WireGuard.Address configuration");
		goto error;
	}
	err = parse_addresses(option, gateway, &ipaddresses);
	if (err) {
		DBG("Failed to parse addresses %s gateway %s", option, gateway);
		goto error;
	}

	ifname = get_ifname();
	if (!ifname) {
		DBG("Failed to find an usable device name");
		err = -ENOENT;
		goto done;
	}
	stpncpy(info->device.name, ifname, sizeof(info->device.name) - 1);
	g_free(ifname);

	err = wg_add_device(info->device.name);
	if (err) {
		DBG("Failed to creating WireGuard device %s", info->device.name);
		goto done;
	}

	err = wg_set_device(&info->device);
	if (err) {
		DBG("Failed to configure WireGuard device %s", info->device.name);
		wg_del_device(info->device.name);
	}

	vpn_set_ifname(provider, info->device.name);

	if (ipaddresses.ipaddress_ipv4)
		vpn_provider_set_ipaddress(provider,
						ipaddresses.ipaddress_ipv4);

	if (ipaddresses.ipaddress_ipv6)
		vpn_provider_set_ipaddress(provider,
						ipaddresses.ipaddress_ipv6);
	else
		/*
		 * No IPv6 address when using as default route with IPv6
		 * prevention enabled = do not tunnel IPv6.
		 */
		disable_ipv6 = vpn_provider_get_boolean(provider,
					"WireGuard.DisableIPv6", false) &&
					!do_split_routing;

	vpn_provider_set_supported_ip_networks(provider, true, !disable_ipv6);

done:
	if (cb)
		cb(provider, user_data, -err);

	connman_ipaddress_free(ipaddresses.ipaddress_ipv4);
	connman_ipaddress_free(ipaddresses.ipaddress_ipv6);

	if (!err) {
		run_dns_reresolve(info);
		run_route_setup(info, ROUTE_SETUP_TIMEOUT);
	}

	return err;

error:
	/* 
	 * TODO: add own category for parameter errors. This is to avoid
	 * looping when parameters are incorrect and VPN stays in failed
	 * state.
	 */
	vpn_provider_add_error(provider, VPN_PROVIDER_ERROR_LOGIN_FAILED);
	err = -ECONNABORTED;
	goto done;
}

struct wireguard_exit_data {
	struct vpn_provider *provider;
	int err;
};

static gboolean wg_died(gpointer user_data)
{
	struct wireguard_exit_data *data = user_data;
	struct wireguard_info *info;

	DBG("");

	/* No task for no daemon VPN - use vpn_died() with no task. */
	vpn_died(NULL, data->err, data->provider);

	info = vpn_provider_get_plugin_data(data->provider);
	if (info)
		free_private_data(info);

	g_free(data);

	return G_SOURCE_REMOVE;
}

/* Allow to overrule the exit code for vpn_died */
static int disconnect(struct vpn_provider *provider, int err)
{
	struct wireguard_exit_data *data;
	struct wireguard_info *info;
	int exit_code;

	DBG("");

	info = vpn_provider_get_plugin_data(provider);
	if (!info)
		return -ENODATA;

	if (info->dying_id)
		return -EALREADY;

	if (info->reresolve_id)
		g_source_remove(info->reresolve_id);

	if (info->route_setup_id)
		g_source_remove(info->route_setup_id);

	if (info->resolv || info->resolv_id)
		remove_resolv(info);

	vpn_provider_set_state(provider, VPN_PROVIDER_STATE_DISCONNECT);

	exit_code = wg_del_device(info->device.name);

	/* Simulate a task-running VPN to issue vpn_died after exiting this */
	data = g_malloc0(sizeof(struct wireguard_exit_data));
	data->provider = provider;
	data->err = err ? err : exit_code;

	info->dying_id = g_timeout_add(1, wg_died, data);

	return exit_code;
}

static void wg_disconnect(struct vpn_provider *provider)
{
	int exit_code;

	DBG("");

	exit_code = disconnect(provider, 0);

	DBG("exited with %d", exit_code);
}

static int wg_error_code(struct vpn_provider *provider, int exit_code)
{
	DBG("exit_code %d", exit_code);

	switch (exit_code) {
	/* Failed to parse configuration -> wg_del_device() has no to delete */
	case -ENODEV:
		return 0;
	default:
		return exit_code;
	}
}

static int wg_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(wg_options); i++) {
		if (!wg_options[i].save)
			continue;

		option = vpn_provider_get_string(provider, wg_options[i].opt);
		if (!option)
			continue;

		g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					wg_options[i].opt, option);
	}

	return 0;
}

bool wg_uses_vpn_agent(struct vpn_provider *provider)
{
	return false;
}

static struct vpn_driver vpn_driver = {
	.flags		= VPN_FLAG_NO_TUN | VPN_FLAG_NO_DAEMON,
	.connect	= wg_connect,
	.disconnect	= wg_disconnect,
	.save		= wg_save,
	.error_code	= wg_error_code,
	.uses_vpn_agent	= wg_uses_vpn_agent
};

static int wg_init(void)
{
	return vpn_register("wireguard", &vpn_driver, NULL);
}

static void wg_exit(void)
{
	vpn_unregister("wireguard");
}

CONNMAN_PLUGIN_DEFINE(wireguard, "WireGuard VPN plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, wg_init, wg_exit)
