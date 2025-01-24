/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2014  Intel Corporation. All rights reserved.
 *  Copyright (C) 2013-2020  Jolla Ltd. All rights reserved.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
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

#include <stdbool.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE

#include <connman/dbus.h>

dbus_bool_t __connman_dbus_append_objpath_dict_array(DBusMessage *msg,
			connman_dbus_append_cb_t function, void *user_data);
dbus_bool_t __connman_dbus_append_objpath_array(DBusMessage *msg,
			connman_dbus_append_cb_t function, void *user_data);
int __connman_dbus_init(DBusConnection *conn);
void __connman_dbus_cleanup(void);

DBusMessage *__connman_error_failed(DBusMessage *msg, int errnum);
DBusMessage *__connman_error_invalid_arguments(DBusMessage *msg);
DBusMessage *__connman_error_permission_denied(DBusMessage *msg);
DBusMessage *__connman_error_passphrase_required(DBusMessage *msg);
DBusMessage *__connman_error_not_registered(DBusMessage *msg);
DBusMessage *__connman_error_not_unique(DBusMessage *msg);
DBusMessage *__connman_error_not_supported(DBusMessage *msg);
DBusMessage *__connman_error_not_implemented(DBusMessage *msg);
DBusMessage *__connman_error_not_found(DBusMessage *msg);
DBusMessage *__connman_error_no_carrier(DBusMessage *msg);
DBusMessage *__connman_error_in_progress(DBusMessage *msg);
DBusMessage *__connman_error_already_exists(DBusMessage *msg);
DBusMessage *__connman_error_already_enabled(DBusMessage *msg);
DBusMessage *__connman_error_already_disabled(DBusMessage *msg);
DBusMessage *__connman_error_already_connected(DBusMessage *msg);
DBusMessage *__connman_error_not_connected(DBusMessage *msg);
DBusMessage *__connman_error_operation_aborted(DBusMessage *msg);
DBusMessage *__connman_error_operation_timeout(DBusMessage *msg);
DBusMessage *__connman_error_invalid_service(DBusMessage *msg);
DBusMessage *__connman_error_invalid_property(DBusMessage *msg);
DBusMessage *__connman_error_operation_canceled(DBusMessage *msg);

int __connman_manager_init(void);
void __connman_manager_cleanup(void);

enum time_updates {
	TIME_UPDATES_UNKNOWN = 0,
	TIME_UPDATES_MANUAL  = 1,
	TIME_UPDATES_AUTO    = 2,
};

enum time_updates __connman_clock_timeupdates(void);
int __connman_clock_init(void);
void __connman_clock_cleanup(void);

void __connman_clock_update_timezone(void);

int __connman_timezone_init(void);
void __connman_timezone_cleanup(void);

char *__connman_timezone_lookup(void);
int __connman_timezone_change(const char *zone);

int __connman_agent_init(void);
void __connman_agent_cleanup(void);

void __connman_counter_send_usage(const char *path,
					DBusMessage *message);
int __connman_counter_register(const char *owner, const char *path,
						unsigned int interval);
int __connman_counter_unregister(const char *owner, const char *path);

int __connman_counter_init(void);
void __connman_counter_cleanup(void);

#include <connman/agent.h>

struct connman_service;
struct connman_peer;

void __connman_agent_cancel(struct connman_service *service);

typedef void (* authentication_cb_t) (struct connman_service *service,
				bool values_received,
				const char *name, int name_len,
				const char *identifier, const char *secret,
				bool wps, const char *wpspin,
				const char *error, void *user_data);
typedef void (* browser_authentication_cb_t) (struct connman_service *service,
				bool authentication_done,
				const char *error, void *user_data);
typedef void (* peer_wps_cb_t) (struct connman_peer *peer, bool choice_done,
				const char *wpspin, const char *error,
				void *user_data);
int __connman_agent_request_passphrase_input(struct connman_service *service,
				authentication_cb_t callback,
				const char *dbus_sender, void *user_data);
int __connman_agent_request_login_input(struct connman_service *service,
				authentication_cb_t callback, void *user_data);
int __connman_agent_request_browser(struct connman_service *service,
				browser_authentication_cb_t callback,
				const char *url, void *user_data);
int __connman_agent_report_peer_error(struct connman_peer *peer,
					const char *path, const char *error,
					report_error_cb_t callback,
					const char *dbus_sender,
					void *user_data);
int __connman_agent_request_peer_authorization(struct connman_peer *peer,
						peer_wps_cb_t callback,
						bool wps_requested,
						const char *dbus_sender,
						void *user_data);
bool __connman_agent_is_request_pending(struct connman_service *service,
						const char *dbus_sender);

#include <connman/log.h>

int __connman_log_init(const char *program, const char *debug,
		gboolean detach, gboolean backtrace,
		const char *program_name, const char *program_version);
void __connman_log_cleanup(gboolean backtrace);
void __connman_log_enable(struct connman_debug_desc *start,
					struct connman_debug_desc *stop);

#include <connman/backtrace.h>

#include <connman/setting.h>

const char *__connman_setting_get_fallback_device_type(const char *interface);

#include <connman/plugin.h>

int __connman_plugin_init(const char *pattern, const char *exclude);
void __connman_plugin_cleanup(void);

bool __connman_plugin_enabled(const char *plugin);
void __connman_plugin_foreach(void (*fn) (struct connman_plugin_desc *desc,
			int flags, void *user_data), void *user_data);

#define CONNMAN_PLUGIN_FLAG_BUILTIN (0x01)
#define CONNMAN_PLUGIN_FLAG_ACTIVE  (0x02)

#include <connman/task.h>

int __connman_task_init(void);
void __connman_task_cleanup(void);

#include <connman/inet.h>

char **__connman_inet_get_running_interfaces(void);
int __connman_inet_modify_address(int cmd, int flags, int index, int family,
				const char *address,
				const char *peer,
				unsigned char prefixlen,
				const char *broadcast,
				bool is_p2p);
int __connman_inet_get_interface_address(int index, int family, void *address);
int __connman_inet_get_interface_ll_address(int index, int family, void *address);
int __connman_inet_get_interface_mac_address(int index, uint8_t *mac_address);

bool __connman_inet_is_any_addr(const char *address, int family);

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

typedef void (*__connman_inet_rs_cb_t) (struct nd_router_advert *reply,
					unsigned int length, void *user_data);

int __connman_inet_ipv6_send_rs(int index, int timeout,
			__connman_inet_rs_cb_t callback, void *user_data);
int __connman_inet_ipv6_send_ra(int index, struct in6_addr *src_addr,
				GSList *prefixes, int router_lifetime);

int __connman_inet_ipv6_do_dad(int index, int timeout_ms,
			struct in6_addr *addr,
			connman_inet_ns_cb_t callback, void *user_data);

typedef void (*__connman_inet_recv_rs_cb_t) (struct nd_router_solicit *reply,
					unsigned int length, void *user_data);
int __connman_inet_ipv6_start_recv_rs(int index,
				__connman_inet_recv_rs_cb_t callback,
				void *user_data, void **context);
void __connman_inet_ipv6_stop_recv_rs(void *context);

int __connman_network_refresh_rs_ipv6(struct connman_network *network, int index);

GSList *__connman_inet_ipv6_get_prefixes(struct nd_router_advert *hdr,
					unsigned int length);
typedef void (*connman_inet_addr_cb_t) (const char *src_address, int index,
					void *user_data);
int __connman_inet_get_route(const char *dst_address,
			connman_inet_addr_cb_t callback, void *user_data);

struct __connman_inet_rtnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;

	struct {
		struct nlmsghdr n;
		union {
			struct {
				struct rtmsg rt;
			} r;
			struct {
				struct ifaddrmsg ifa;
			} i;
		} u;
		char buf[1024];
	} req;
};

int __connman_inet_rtnl_open(struct __connman_inet_rtnl_handle *rth);
typedef void (*__connman_inet_rtnl_cb_t) (struct nlmsghdr *answer,
					void *user_data);
int __connman_inet_rtnl_talk(struct __connman_inet_rtnl_handle *rtnl,
			struct nlmsghdr *n, int timeout,
			__connman_inet_rtnl_cb_t callback, void *user_data);
static inline
int __connman_inet_rtnl_send(struct __connman_inet_rtnl_handle *rtnl,
						struct nlmsghdr *n)
{
	return __connman_inet_rtnl_talk(rtnl, n, 0, NULL, NULL);
}

void __connman_inet_rtnl_close(struct __connman_inet_rtnl_handle *rth);
int __connman_inet_rtnl_addattr_l(struct nlmsghdr *n, size_t max_length,
			int type, const void *data, size_t data_length);
int __connman_inet_rtnl_addattr32(struct nlmsghdr *n, size_t maxlen,
			int type, __u32 data);

int __connman_inet_add_fwmark_rule(uint32_t table_id, int family, uint32_t fwmark);
int __connman_inet_del_fwmark_rule(uint32_t table_id, int family, uint32_t fwmark);
int __connman_inet_add_default_to_table(uint32_t table_id, int ifindex, const char *gateway);
int __connman_inet_add_subnet_to_table(uint32_t table_id, int ifindex,
			const char *gateway, unsigned char prefixlen);
int __connman_inet_del_default_from_table(uint32_t table_id, int ifindex, const char *gateway);
int __connman_inet_del_subnet_from_table(uint32_t table_id, int ifindex,
			const char *gateway, unsigned char prefixlen);
int __connman_inet_get_address_netmask(int ifindex,
		struct sockaddr_in *address, struct sockaddr_in *netmask);

int __connman_inet_add_ipv6_neigbour_proxy(int index, const char *ipv6_address,
						unsigned char ipv6_prefixlen);
int __connman_inet_del_ipv6_neigbour_proxy(int index, const char *ipv6_address,
						unsigned char ipv6_prefixlen);

bool __connman_inet_isrootnfs_device(const char *devname);
char **__connman_inet_get_pnp_nameservers(const char *pnp_file);

#include <connman/resolver.h>

int __connman_resolver_init(gboolean dnsproxy);
void __connman_resolver_cleanup(void);
void __connman_resolver_append_fallback_nameservers(void);
int __connman_resolvfile_append(int index, const char *domain, const char *server);
int __connman_resolvfile_remove(int index, const char *domain, const char *server);
int __connman_resolver_redo_servers(int index);
int __connman_resolver_set_mdns(int index, bool enabled);

#include <connman/storage.h>

#define STORAGEDIR connman_storage_dir()
#define VPN_STORAGEDIR connman_storage_vpn_dir()
#define USER_STORAGEDIR connman_storage_user_dir()
#define USER_VPN_STORAGEDIR connman_storage_user_vpn_dir()
#define STORAGE_DIR_MODE __connman_storage_dir_mode()
#define STORAGE_FILE_MODE __connman_storage_file_mode()

enum connman_storage_dir_type {
	STORAGE_DIR_TYPE_MAIN	= 0x0001,
	STORAGE_DIR_TYPE_VPN	= 0x0002,
	STORAGE_DIR_TYPE_USER	= 0x0004,
	STORAGE_DIR_TYPE_STATE	= 0x0008,
};

/*
 * Callbacks to be use in user change process. Callbacks are executed in the
 * defined order.
 */
struct connman_storage_callbacks {
	/* Prepare is called to remove all used technologies from use */
	bool (*pre) (void);

	/* Unload is called to remove all used services/providers from use. */
	void (*unload) (char **items, int len);

	/* Load is called to load all the new services/providers. */
	void (*load) (void);

	/* Post callback is to initialize technologies from new settings. */
	bool (*post) (void);

	/* Finalize callback is to do additional actions after setup. */
	void (*finalize) (uid_t uid, void *user_data);

	/* Additional data to be passed on finalize callback */
	void *finalize_user_data;

	/* Callback for notifying about user change. */
	void (*uid_changed) (uid_t uid);

	/* Callback to create access policy for connmand storage.*/
	struct connman_access_storage_policy* (*access_policy_create)
				(const char *spec);

	/* Callback to check if connmand storage user change is allowed */
	enum connman_access (*access_change_user)
				(const struct connman_access_storage_policy *p,
				const char *user, const char *sender,
				enum connman_access default_access);

	/* Callback to free the created connmand storage access policy. */
	void (*access_policy_free) (struct connman_access_storage_policy *p);

	/* Callback to check if connman-vpnd storage user change is allowed */
	bool (*vpn_access_change_user) (const char *sender, const char *arg,
				bool default_access);

	/* Callback to return the dbus name of the peer (e.g., connman/vpnd) */
	const char* (*get_peer_dbus_name) (void);
};

typedef void (*connman_storage_change_user_result_cb_t)(uid_t uid, int err,
			void *user_data);

mode_t __connman_storage_dir_mode(void);
mode_t __connman_storage_file_mode(void);
int __connman_storage_init(const char *root, const char *user_dir,
				mode_t dir_mode, mode_t file_mode);
int __connman_storage_create_dir(const char *dir, mode_t permissions);
int __connman_storage_register_dbus(enum connman_storage_dir_type type,
				struct connman_storage_callbacks *callbacks);
int __connman_storage_change_user(uid_t uid,
			connman_storage_change_user_result_cb_t cb,
			void *user_cb_data, bool prepare_only);
void __connman_storage_cleanup(void);
GKeyFile *__connman_storage_open_global(void);
GKeyFile *__connman_storage_load_global(void);
int __connman_storage_save_global(GKeyFile *keyfile);
void __connman_storage_delete_global(void);

GKeyFile *__connman_storage_load_config(const char *ident);
GKeyFile *__connman_storage_load_provider_config(const char *ident);

int __connman_storage_save_service(GKeyFile *keyfile, const char *ident);
GKeyFile *__connman_storage_load_provider(const char *identifier);
int __connman_storage_save_provider(GKeyFile *keyfile, const char *identifier);
bool __connman_storage_remove_provider(const char *identifier);
char **__connman_storage_get_providers(void);
bool __connman_storage_remove_service(const char *service_id);

int __connman_detect_init(void);
void __connman_detect_cleanup(void);

#include <connman/inotify.h>

int __connman_inotify_init(void);
void __connman_inotify_cleanup(void);

#include <connman/proxy.h>

int __connman_proxy_init(void);
void __connman_proxy_cleanup(void);

#include <connman/ipconfig.h>

struct connman_ipaddress {
	int family;
	unsigned char prefixlen;
	char *local;
	char *peer;
	char *broadcast;
	char *gateway;
	bool is_p2p; /* P2P connection or VPN, broadcast is excluded. */
};

struct connman_ipconfig_ops {
	void (*up) (struct connman_ipconfig *ipconfig, const char *ifname);
	void (*down) (struct connman_ipconfig *ipconfig, const char *ifname);
	void (*lower_up) (struct connman_ipconfig *ipconfig, const char *ifname);
	void (*lower_down) (struct connman_ipconfig *ipconfig, const char *ifname);
	void (*ip_bound) (struct connman_ipconfig *ipconfig, const char *ifname);
	void (*ip_release) (struct connman_ipconfig *ipconfig, const char *ifname);
	void (*route_set) (struct connman_ipconfig *ipconfig, const char *ifname);
	void (*route_unset) (struct connman_ipconfig *ipconfig, const char *ifname);
};

struct connman_stats_data {
	uint64_t rx_packets;
	uint64_t tx_packets;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t rx_errors;
	uint64_t tx_errors;
	uint64_t rx_dropped;
	uint64_t tx_dropped;
};

struct connman_ipconfig *__connman_ipconfig_create(int index,
					enum connman_ipconfig_type type);

#define __connman_ipconfig_ref(ipconfig) \
	__connman_ipconfig_ref_debug(ipconfig, __FILE__, __LINE__, __func__)
#define __connman_ipconfig_unref(ipconfig) \
	__connman_ipconfig_unref_debug(ipconfig, __FILE__, __LINE__, __func__)

struct connman_ipconfig *
__connman_ipconfig_ref_debug(struct connman_ipconfig *ipconfig,
			const char *file, int line, const char *caller);
void __connman_ipconfig_unref_debug(struct connman_ipconfig *ipconfig,
			const char *file, int line, const char *caller);

void __connman_ipconfig_clear_address(struct connman_ipconfig *ipconfig);
void *__connman_ipconfig_get_data(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_data(struct connman_ipconfig *ipconfig, void *data);

int __connman_ipconfig_get_index(struct connman_ipconfig *ipconfig);
gboolean __connman_ipconfig_get_stats(struct connman_ipconfig *ipconfig,
				struct connman_stats_data *stats);

void __connman_ipconfig_set_ops(struct connman_ipconfig *ipconfig,
				const struct connman_ipconfig_ops *ops);
int __connman_ipconfig_set_method(struct connman_ipconfig *ipconfig,
					enum connman_ipconfig_method method);
void __connman_ipconfig_disable_ipv6(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_enable_ipv6(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_set_ipv6_support(bool enable);
bool __connman_ipconfig_get_ipv6_support();

int __connman_ipconfig_init(void);
void __connman_ipconfig_cleanup(void);

struct rtnl_link_stats64;

void __connman_ipconfig_newlink(int index, unsigned short type,
				unsigned int flags, const char *address,
							unsigned short mtu,
						struct rtnl_link_stats64 *stats);
void __connman_ipconfig_dellink(int index, struct rtnl_link_stats64 *stats);
int __connman_ipconfig_newaddr(int index, int family, const char *label,
				unsigned char prefixlen, const char *address);
void __connman_ipconfig_deladdr(int index, int family, const char *label,
				unsigned char prefixlen, const char *address);
void __connman_ipconfig_newroute(int index, int family, unsigned char scope,
					const char *dst, const char *gateway);
void __connman_ipconfig_delroute(int index, int family, unsigned char scope,
					const char *dst, const char *gateway);

void __connman_ipconfig_foreach(void (*function) (int index, void *user_data),
							void *user_data);
enum connman_ipconfig_type __connman_ipconfig_get_config_type(
					struct connman_ipconfig *ipconfig);
unsigned short __connman_ipconfig_get_type_from_index(int index);
unsigned int __connman_ipconfig_get_flags_from_index(int index);
const char *__connman_ipconfig_get_gateway_from_index(int index,
	enum connman_ipconfig_type type);
void __connman_ipconfig_set_index(struct connman_ipconfig *ipconfig, int index);

const char *__connman_ipconfig_get_local(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_local(struct connman_ipconfig *ipconfig, const char *address);
const char *__connman_ipconfig_get_peer(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_peer(struct connman_ipconfig *ipconfig, const char *address);
const char *__connman_ipconfig_get_broadcast(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_broadcast(struct connman_ipconfig *ipconfig, const char *broadcast);
const char *__connman_ipconfig_get_gateway(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_gateway(struct connman_ipconfig *ipconfig, const char *gateway);
unsigned char __connman_ipconfig_get_prefixlen(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_prefixlen(struct connman_ipconfig *ipconfig, unsigned char prefixlen);

int __connman_ipconfig_enable(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_disable(struct connman_ipconfig *ipconfig);
bool __connman_ipconfig_is_usable(struct connman_ipconfig *ipconfig);
bool __connman_ipconfig_is_configured(struct connman_ipconfig *ipconfig);

const char *__connman_ipconfig_method2string(enum connman_ipconfig_method method);
const char *__connman_ipconfig_type2string(enum connman_ipconfig_type type);
enum connman_ipconfig_method __connman_ipconfig_string2method(const char *method);

void __connman_ipconfig_append_ipv4(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
void __connman_ipconfig_append_ipv4config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
void __connman_ipconfig_append_ipv6(struct connman_ipconfig *ipconfig,
					DBusMessageIter *iter,
					struct connman_ipconfig *ip4config);
void __connman_ipconfig_append_ipv6config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
int __connman_ipconfig_set_config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *array);
int __connman_ipconfig_set_config_from_address(
					struct connman_ipconfig *ipconfig,
					enum connman_ipconfig_method method,
					const char *address,
					const char *netmask,
					const char *gateway,
					unsigned char prefix_length);
void __connman_ipconfig_append_ethernet(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
enum connman_ipconfig_method __connman_ipconfig_get_method(
				struct connman_ipconfig *ipconfig);

int __connman_ipconfig_address_add(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_address_remove(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_address_unset(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_gateway_add(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_gateway_remove(struct connman_ipconfig *ipconfig);

int __connman_ipconfig_set_proxy_autoconfig(struct connman_ipconfig *ipconfig,
							const char *url);
const char *__connman_ipconfig_get_proxy_autoconfig(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_dhcp_address(struct connman_ipconfig *ipconfig,
					const char *address);
char *__connman_ipconfig_get_dhcp_address(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_dhcpv6_prefixes(struct connman_ipconfig *ipconfig,
					char **prefixes);
char **__connman_ipconfig_get_dhcpv6_prefixes(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_dhcpv6_duid(struct connman_ipconfig *ipconfig,
					const char *dhcpv6_duid);
char *__connman_ipconfig_get_dhcpv6_duid(struct connman_ipconfig *ipconfig);

void __connman_ipconfig_load(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix);
void __connman_ipconfig_save(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix);
bool __connman_ipconfig_ipv6_privacy_enabled(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_ipv6_reset_privacy(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_ipv6_set_privacy(struct connman_ipconfig *ipconfig,
					const char *value);
bool __connman_ipconfig_ipv6_is_enabled(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_ipv6_method_save(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_ipv6_method_restore(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_ipv6_set_force_disabled(
					struct connman_ipconfig *ipconfig,
					bool force_disabled);
bool __connman_ipconfig_ipv6_get_force_disabled(
					struct connman_ipconfig *ipconfig);
int __connman_ipconfig_ipv6_get_accept_ra(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_ipv6_set_accept_ra(struct connman_ipconfig *ipconfig,
					int value);
bool __connman_ipconfig_ipv6_get_ndproxy(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_ipv6_set_ndproxy(struct connman_ipconfig *ipconfig,
					bool enable);

int __connman_ipconfig_set_rp_filter();
void __connman_ipconfig_unset_rp_filter(int old_value);

#include <connman/utsname.h>

int __connman_utsname_set_hostname(const char *hostname);
int __connman_utsname_set_domainname(const char *domainname);

#include <connman/timeserver.h>

int __connman_timeserver_init(void);
void __connman_timeserver_cleanup(void);

char **__connman_timeserver_system_get();

GSList *__connman_timeserver_add_list(GSList *server_list,
		const char *timeserver);
GSList *__connman_timeserver_get_all(struct connman_service *service);
int __connman_timeserver_sync(struct connman_service *service);

enum __connman_dhcpv6_status {
	CONNMAN_DHCPV6_STATUS_FAIL     = 0,
	CONNMAN_DHCPV6_STATUS_SUCCEED  = 1,
	CONNMAN_DHCPV6_STATUS_RESTART  = 2,
};

typedef void (* dhcpv6_cb) (struct connman_network *network,
			enum __connman_dhcpv6_status status, gpointer data);

typedef void (* dhcp_cb) (struct connman_ipconfig *ipconfig,
			struct connman_network *opt_network,
			bool success, gpointer data);
char *__connman_dhcp_get_server_address(struct connman_ipconfig *ipconfig);
int __connman_dhcp_start(struct connman_ipconfig *ipconfig,
			struct connman_network *network, dhcp_cb callback,
			gpointer user_data);
void __connman_dhcp_stop(struct connman_ipconfig *ipconfig);
void __connman_dhcp_decline(struct connman_ipconfig *ipconfig);
int __connman_dhcp_init(void);
void __connman_dhcp_cleanup(void);
int __connman_dhcpv6_init(void);
void __connman_dhcpv6_cleanup(void);
int __connman_dhcpv6_start_info(struct connman_network *network,
				dhcpv6_cb callback);
void __connman_dhcpv6_stop(struct connman_network *network);
int __connman_dhcpv6_start(struct connman_network *network,
				GSList *prefixes, dhcpv6_cb callback);
int __connman_dhcpv6_start_renew(struct connman_network *network,
				dhcpv6_cb callback);
int __connman_dhcpv6_start_release(struct connman_network *network,
				dhcpv6_cb callback);
int __connman_dhcpv6_start_pd(int index, GSList *prefixes, dhcpv6_cb callback);
void __connman_dhcpv6_stop_pd(int index);
int __connman_dhcpv6_start_pd_renew(struct connman_network *network,
							dhcpv6_cb callback);
int __connman_dhcpv6_start_pd_release(struct connman_network *network,
				dhcpv6_cb callback);

int __connman_ipv4_init(void);
void __connman_ipv4_cleanup(void);

int __connman_connection_init(void);
void __connman_connection_cleanup(void);

int __connman_connection_gateway_add(struct connman_service *service,
					const char *gateway,
					enum connman_ipconfig_type type,
					const char *peer);
void __connman_connection_gateway_remove(struct connman_service *service,
					enum connman_ipconfig_type type);
int __connman_connection_get_vpn_index(int phy_index);
int __connman_connection_get_vpn_phy_index(int vpn_index);

bool __connman_connection_update_gateway(void);

typedef void (*__connman_ntp_cb_t) (bool success, void *user_data);
int __connman_ntp_start(char *server, __connman_ntp_cb_t callback,
			void *user_data);
void __connman_ntp_stop();

int __connman_wpad_init(void);
void __connman_wpad_cleanup(void);
int __connman_wpad_start(struct connman_service *service);
void __connman_wpad_stop(struct connman_service *service);

int __connman_wispr_init(void);
void __connman_wispr_cleanup(void);
int __connman_wispr_start(struct connman_service *service,
					enum connman_ipconfig_type type);
void __connman_wispr_stop(struct connman_service *service);

#include <connman/technology.h>

void __connman_technology_list_struct(DBusMessageIter *array);

int __connman_technology_add_device(struct connman_device *device);
int __connman_technology_remove_device(struct connman_device *device);
int __connman_technology_enabled(enum connman_service_type type);
int __connman_technology_disabled(enum connman_service_type type);
int __connman_technology_set_offlinemode(bool offlinemode);
bool __connman_technology_get_offlinemode(void);
void __connman_technology_set_connected(enum connman_service_type type,
					bool connected);
bool __connman_technology_disable_all(void);
bool __connman_technology_enable_from_config(void);

int __connman_technology_add_rfkill(unsigned int index,
					enum connman_service_type type,
						bool softblock,
						bool hardblock);
int __connman_technology_update_rfkill(unsigned int index,
					enum connman_service_type type,
						bool softblock,
						bool hardblock);
int __connman_technology_remove_rfkill(unsigned int index,
					enum connman_service_type type);

void __connman_technology_scan_started(struct connman_device *device);
void __connman_technology_scan_stopped(struct connman_device *device,
					enum connman_service_type type);
void __connman_technology_add_interface(enum connman_service_type type,
				int index, const char *ident);
void __connman_technology_remove_interface(enum connman_service_type type,
				int index, const char *ident);
void __connman_technology_notify_regdom_by_device(struct connman_device *device,
						int result, const char *alpha2);
const char *__connman_technology_get_regdom(enum connman_service_type type);
const char *__connman_technology_get_tethering_ident(
					struct connman_technology *tech);
enum connman_service_type __connman_technology_get_type(
					struct connman_technology *tech);

#include <connman/device.h>

int __connman_device_init(const char *device, const char *nodevice);
void __connman_device_cleanup(void);

void __connman_device_list(DBusMessageIter *iter, void *user_data);

enum connman_service_type __connman_device_get_service_type(struct connman_device *device);
struct connman_device *__connman_device_find_device(enum connman_service_type type);
int __connman_device_request_scan(enum connman_service_type type);
int __connman_device_request_scan_full(enum connman_service_type type);
int __connman_device_request_hidden_scan(struct connman_device *device,
				const char *ssid, unsigned int ssid_len,
				const char *identity, const char *passphrase,
				const char *security, void *user_data);
void __connman_device_stop_scan(enum connman_service_type type);

bool __connman_device_isfiltered(const char *devname);

void __connman_device_keep_network(struct connman_network *network);
void __connman_device_set_network(struct connman_device *device,
					struct connman_network *network);
void __connman_device_cleanup_networks(struct connman_device *device);

int __connman_device_enable(struct connman_device *device);
int __connman_device_disable(struct connman_device *device);
int __connman_device_disconnect(struct connman_device *device);

bool __connman_device_has_driver(struct connman_device *device);

const char *__connman_device_get_type(struct connman_device *device);

int __connman_rfkill_init(void);
void __connman_rfkill_cleanup(void);
int __connman_rfkill_block(enum connman_service_type type, bool block);

#include <connman/network.h>

int __connman_network_init(void);
void __connman_network_cleanup(void);

void __connman_network_set_device(struct connman_network *network,
					struct connman_device *device);

int __connman_network_connect(struct connman_network *network);
int __connman_network_disconnect(struct connman_network *network);
int __connman_network_clear_ipconfig(struct connman_network *network,
					struct connman_ipconfig *ipconfig);
int __connman_network_enable_ipconfig(struct connman_network *network,
				struct connman_ipconfig *ipconfig);

const char *__connman_network_get_type(struct connman_network *network);
const char *__connman_network_get_group(struct connman_network *network);
const char *__connman_network_get_ident(struct connman_network *network);
bool __connman_network_get_weakness(struct connman_network *network);

int __connman_config_init();
void __connman_config_cleanup(void);

void __connman_service_foreach(void (*fn) (struct connman_service *service,
					void *user_data), void *user_data);
void __connman_service_list_struct(DBusMessageIter *iter);
void __connman_service_set_disabled(struct connman_service *service,
						gboolean disabled);

int __connman_config_load_service(GKeyFile *keyfile, const char *group,
				  bool persistent);
int __connman_config_provision_service(struct connman_service *service);
int __connman_config_provision_service_ident(struct connman_service *service,
		const char *ident, const char *file, const char *entry);

char *__connman_config_get_string(GKeyFile *key_file,
	const char *group_name, const char *key, GError **error);

char **__connman_config_get_string_list(GKeyFile *key_file,
	const char *group_name, const char *key, gsize *length, GError **error);

bool __connman_config_get_bool(GKeyFile *key_file,
	const char *group_name, const char *key, GError **error);
bool __connman_config_address_provisioned(const char *address,
					const char *netmask);

#include <connman/tethering.h>

int __connman_tethering_init(void);
void __connman_tethering_cleanup(void);

const char *__connman_tethering_get_bridge(void);
int __connman_tethering_set_enabled(void);
void __connman_tethering_set_disabled(void);
void __connman_tethering_list_clients(DBusMessageIter *array);

int __connman_private_network_request(DBusMessage *msg, const char *owner);
int __connman_private_network_release(const char *path);

int __connman_ipv6pd_setup(const char *bridge);
void __connman_ipv6pd_cleanup(void);

#include <connman/provider.h>

bool __connman_provider_check_routes(struct connman_provider *provider);
int __connman_provider_append_user_route(struct connman_provider *provider,
			int family, const char *network, const char *netmask);
void __connman_provider_append_properties(struct connman_provider *provider, DBusMessageIter *iter);
void __connman_provider_list(DBusMessageIter *iter, void *user_data);
bool __connman_provider_is_immutable(struct connman_provider *provider);
int __connman_provider_create_and_connect(DBusMessage *msg);
const char * __connman_provider_get_ident(struct connman_provider *provider);
const char * __connman_provider_get_transport_ident(
					struct connman_provider *provider);
int __connman_provider_indicate_state(struct connman_provider *provider,
					enum connman_provider_state state);
int __connman_provider_indicate_error(struct connman_provider *provider,
					enum connman_provider_error error);
int __connman_provider_connect(struct connman_provider *provider,
					const char *dbus_sender);
int __connman_provider_remove_by_path(const char *path);
int __connman_provider_set_ipv6_for_connected(
					struct connman_provider *provider,
					bool enable);
void __connman_provider_cleanup(void);
int __connman_provider_init(void);

#include <connman/service.h>

int __connman_service_init(void);
void __connman_service_cleanup(void);
void __connman_service_unload_services(gchar **services, int len);
void __connman_service_load_services(void);
int __connman_service_move(struct connman_service *service,
				struct connman_service *target, bool before);
int __connman_service_load_modifiable(struct connman_service *service);

void __connman_service_list_struct(DBusMessageIter *iter);

int __connman_service_compare(const struct connman_service *a,
					const struct connman_service *b);
const char *__connman_service_create(enum connman_service_type type,
				const char *ident, GKeyFile *settings);

struct connman_service *__connman_service_lookup_from_index(int index);
void __connman_service_set_ipv6_for_connected(struct connman_service *vpn,
				struct connman_service *transport, bool enable);
bool __connman_service_create_from_network(struct connman_network *network);
struct connman_service *__connman_service_create_from_provider(struct connman_provider *provider);
bool __connman_service_index_is_default(int index);
void __connman_service_update_from_network(struct connman_network *network);
void __connman_service_remove_from_network(struct connman_network *network);
void __connman_service_read_ip4config(struct connman_service *service);
void __connman_service_read_ip6config(struct connman_service *service);

struct connman_ipconfig *__connman_service_get_ip4config(
				struct connman_service *service);
struct connman_ipconfig *__connman_service_get_ip6config(
				struct connman_service *service);
struct connman_ipconfig *__connman_service_get_ipconfig(
				struct connman_service *service, int family);
void __connman_service_notify_ipv4_configuration(
				struct connman_service *service);
void __connman_service_wispr_start(struct connman_service *service,
                                enum connman_ipconfig_type type);
bool __connman_service_is_connected_state(struct connman_service *service,
					enum connman_ipconfig_type type);
const char *__connman_service_get_path(struct connman_service *service);
const char *__connman_service_get_name(struct connman_service *service);
struct connman_network *__connman_service_get_network(struct connman_service *service);
enum connman_service_security __connman_service_get_security(struct connman_service *service);
const char *__connman_service_get_phase2(struct connman_service *service);
bool __connman_service_wps_enabled(struct connman_service *service);
int __connman_service_set_favorite(struct connman_service *service,
						bool favorite);
int __connman_service_set_favorite_delayed(struct connman_service *service,
					bool favorite,
					bool delay_ordering);
int __connman_service_set_immutable(struct connman_service *service,
						bool immutable);
int __connman_service_set_ignore(struct connman_service *service,
						bool ignore);
void __connman_service_set_search_domains(struct connman_service *service,
					char **domains);
int __connman_service_set_mdns(struct connman_service *service,
					bool enabled);

void __connman_service_set_string(struct connman_service *service,
					const char *key, const char *value);
int __connman_service_online_check_failed(struct connman_service *service,
					enum connman_ipconfig_type type);
int __connman_service_ipconfig_indicate_state(struct connman_service *service,
					enum connman_service_state new_state,
					enum connman_ipconfig_type type);
enum connman_service_state __connman_service_ipconfig_get_state(
					struct connman_service *service,
					enum connman_ipconfig_type type);

int __connman_service_indicate_error(struct connman_service *service,
					enum connman_service_error error);
int __connman_service_clear_error(struct connman_service *service);
int __connman_service_indicate_default(struct connman_service *service);

int __connman_service_connect(struct connman_service *service,
			enum connman_service_connect_reason reason);
int __connman_service_disconnect(struct connman_service *service);
int __connman_service_disconnect_all(void);
void __connman_service_set_active_session(bool enable, GSList *list);
void __connman_service_auto_connect(enum connman_service_connect_reason reason);
void __connman_service_start_connect_timeout(struct connman_service *service,
				bool restart);
bool __connman_service_remove(struct connman_service *service);
bool __connman_service_is_provider_pending(struct connman_service *service);
void __connman_service_set_provider_pending(struct connman_service *service,
							DBusMessage *msg);
void __connman_service_set_hidden_data(struct connman_service *service,
				gpointer user_data);
void __connman_service_return_error(struct connman_service *service,
				int error, gpointer user_data);

int __connman_service_provision_changed(const char *ident);
void __connman_service_set_config(struct connman_service *service,
				const char *file_id, const char *section);
enum connman_service_connect_reason
	__connman_service_get_connect_reason(struct connman_service *service);
bool __connman_service_is_really_hidden(struct connman_service *service);
GBytes *__connman_service_get_ssid(struct connman_service *service);
gboolean __connman_service_update_value_from_network(
			struct connman_service *service,
			struct connman_network *network, const char *key);
int __connman_service_network_property_changed(struct connman_service *service,
							const char *name);

const char *__connman_service_type2string(enum connman_service_type type);
enum connman_service_type __connman_service_string2type(const char *str);
enum connman_service_security __connman_service_string2security(const char *str);
const char *__connman_service_security2string(enum connman_service_security security);

int __connman_service_nameserver_append(struct connman_service *service,
				const char *nameserver, bool is_auto);
int __connman_service_nameserver_remove(struct connman_service *service,
				const char *nameserver, bool is_auto);
void __connman_service_nameserver_clear(struct connman_service *service);
void __connman_service_nameserver_add_routes(struct connman_service *service,
						const char *gw);
void __connman_service_nameserver_del_routes(struct connman_service *service,
					enum connman_ipconfig_type type);
void __connman_service_set_timeservers(struct connman_service *service,
						char **timeservers);
int __connman_service_timeserver_append(struct connman_service *service,
						const char *timeserver);
int __connman_service_timeserver_remove(struct connman_service *service,
						const char *timeserver);
void __connman_service_timeserver_changed(struct connman_service *service,
		GSList *ts_list);
void __connman_service_set_pac(struct connman_service *service,
					const char *pac);
bool __connman_service_is_hidden(struct connman_service *service);
bool __connman_service_is_split_routing(struct connman_service *service);
bool __connman_service_index_is_split_routing(int index);
void __connman_service_set_split_routing(struct connman_service *service,
						bool split_routing);
void __connman_service_split_routing_changed(struct connman_service *service);
int __connman_service_get_index(struct connman_service *service);
GSList *__connman_service_get_depending_vpn_index(
		struct connman_service *service);
void __connman_service_set_hidden(struct connman_service *service);
void __connman_service_set_hostname(struct connman_service *service,
						const char *hostname);
const char *__connman_service_get_hostname(struct connman_service *service);
void __connman_service_set_domainname(struct connman_service *service,
						const char *domainname);
const char *__connman_service_get_nameserver(struct connman_service *service);
void __connman_service_set_proxy_autoconfig(struct connman_service *service,
							const char *url);

void __connman_service_set_identity(struct connman_service *service,
					const char *identity);
void __connman_service_set_anonymous_identity(struct connman_service *service,
					const char *anonymous_identity);
void __connman_service_set_subject_match(struct connman_service *service,
					const char *subject_match);
void __connman_service_set_altsubject_match(struct connman_service *service,
					const char *altsubject_match);
void __connman_service_set_domain_suffix_match(struct connman_service *service,
					const char *domain_suffix_match);
void __connman_service_set_domain_match(struct connman_service *service,
					const char *domain_match);
void __connman_service_set_agent_identity(struct connman_service *service,
						const char *agent_identity);
int __connman_service_set_passphrase(struct connman_service *service,
					const char *passphrase);
const char *__connman_service_get_passphrase(struct connman_service *service);
int __connman_service_check_passphrase(enum connman_service_security security,
					const char *passphrase);
int __connman_service_reset_ipconfig(struct connman_service *service,
		enum connman_ipconfig_type type, DBusMessageIter *array,
		enum connman_service_state *new_state);

void __connman_service_notify(struct connman_service *service,
			const struct connman_stats_data *data);

int __connman_service_counter_register(const char *counter);
void __connman_service_counter_unregister(const char *counter);
void __connman_service_counter_reset_all(const char *type);

#include <connman/peer.h>

int __connman_peer_init(void);
void __connman_peer_cleanup(void);

void __connman_peer_list_struct(DBusMessageIter *array);
const char *__connman_peer_get_path(struct connman_peer *peer);
void __connman_peer_disconnect_all(void);

int __connman_peer_service_init(void);
void __connman_peer_service_cleanup(void);

void __connman_peer_service_set_driver(struct connman_peer_driver *driver);
int __connman_peer_service_register(const char *owner, DBusMessage *msg,
					const unsigned char *specification,
					int specification_length,
					const unsigned char *query,
					int query_length, int version,
					bool master);
int __connman_peer_service_unregister(const char *owner,
					const unsigned char *specification,
					int specification_length,
					const unsigned char *query,
					int query_length, int version);

#include <connman/session.h>

void __connman_service_mark_dirty();
void __connman_service_save(struct connman_service *service);

#include <connman/notifier.h>

int __connman_technology_init(void);
void __connman_technology_cleanup(void);

int __connman_notifier_init(void);
void __connman_notifier_cleanup(void);

void __connman_notifier_service_add(struct connman_service *service,
					const char *name);
void __connman_notifier_service_remove(struct connman_service *service);
void __connman_notifier_enter_online(enum connman_service_type type);
void __connman_notifier_leave_online(enum connman_service_type type);
void __connman_notifier_connect(enum connman_service_type type);
void __connman_notifier_disconnect(enum connman_service_type type);
void __connman_notifier_offlinemode(bool enabled);
void __connman_notifier_default_changed(struct connman_service *service);
void __connman_notifier_proxy_changed(struct connman_service *service);
void __connman_notifier_service_state_changed(struct connman_service *service,
					enum connman_service_state state);
void __connman_notifier_ipconfig_changed(struct connman_service *service,
					struct connman_ipconfig *ipconfig);
void __connman_notifier_tethering_changed(struct connman_technology* tech,
								bool on);
void __connman_notifier_device_status_changed(struct connman_device *device,
								bool on);
void __connman_notifier_storage_uid_changed(uid_t uid);

bool __connman_notifier_is_connected(void);
const char *__connman_notifier_get_state(void);

#include <connman/rtnl.h>

int __connman_rtnl_init(void);
void __connman_rtnl_start(void);
void __connman_rtnl_cleanup(void);

enum connman_device_type __connman_rtnl_get_device_type(int index);
unsigned int __connman_rtnl_update_interval_add(unsigned int interval);
unsigned int __connman_rtnl_update_interval_remove(unsigned int interval);
int __connman_rtnl_request_update(int family);
int __connman_rtnl_send(const void *buf, size_t len);

bool __connman_session_policy_autoconnect(enum connman_service_connect_reason reason);

int __connman_session_create(DBusMessage *msg);
int __connman_session_destroy(DBusMessage *msg);

int __connman_session_init(void);
void __connman_session_cleanup(void);

int __connman_stats_init(void);
void __connman_stats_cleanup(void);

struct connman_stats *__connman_stats_new(struct connman_service *service,
							gboolean roaming);
struct connman_stats *__connman_stats_new_existing(
			struct connman_service *service, gboolean roaming);
void __connman_stats_free(struct connman_stats *stats);
void __connman_stats_reset(struct connman_stats *stats);
void __connman_stats_set_index(struct connman_stats *stats, int index);
gboolean __connman_stats_update(struct connman_stats *stats,
				const struct connman_stats_data *data);
void __connman_stats_rebase(struct connman_stats *stats,
				const struct connman_stats_data *data);
void __connman_stats_get(struct connman_stats *stats,
				struct connman_stats_data *data);
void __connman_stats_read(const char *identifier, gboolean roaming,
				struct connman_stats_data *data);
void __connman_stats_clear(const char *identifier, gboolean roaming);

int __connman_iptables_dump(int type,
				const char *table_name);
int __connman_iptables_new_chain(int type,
				const char *table_name,
				const char *chain);
int __connman_iptables_delete_chain(int type,
				const char *table_name,
				const char *chain);
int __connman_iptables_flush_chain(int type,
				const char *table_name,
				const char *chain);
int __connman_iptables_find_chain(int type,
				const char *table_name,
				const char *chain);
int __connman_iptables_change_policy(int type,
				const char *table_name,
				const char *chain,
				const char *policy);
int __connman_iptables_append(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec);
int __connman_iptables_insert(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec);
int __connman_iptables_delete(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec);
int __connman_iptables_restore_all();
int __connman_iptables_save_all();

void __connman_iptables_validate_init(void);
void __connman_iptables_validate_cleanup(void);
bool __connman_iptables_validate_rule(int type, bool allow_dynamic,
			const char *rule_spec);


typedef int (*connman_iptables_manage_cb_t)(int type, const char *table_name,
				const char *chain, const char *rule_spec);

typedef void (*connman_iptables_iterate_chains_cb_t) (const char *chain_name,
							void *user_data);
int __connman_iptables_iterate_chains(int type,
				const char *table_name,
				connman_iptables_iterate_chains_cb_t cb,
				void *user_data);

int __connman_iptables_init(void);
void __connman_iptables_cleanup(void);
int __connman_iptables_commit(int type, const char *table_name);

int __connman_dnsproxy_init(void);
void __connman_dnsproxy_cleanup(void);
int __connman_dnsproxy_add_listener(int index);
void __connman_dnsproxy_remove_listener(int index);
int __connman_dnsproxy_append(int index, const char *domain, const char *server);
int __connman_dnsproxy_remove(int index, const char *domain, const char *server);
int __connman_dnsproxy_set_mdns(int index, bool enabled);

int __connman_6to4_probe(struct connman_service *service);
void __connman_6to4_remove(struct connman_ipconfig *ipconfig);
int __connman_6to4_check(struct connman_ipconfig *ipconfig);

struct connman_ippool;

typedef void (*ippool_collision_cb_t) (struct connman_ippool *pool,
					void *user_data);

int __connman_ippool_init(void);
void __connman_ippool_cleanup(void);

void __connman_ippool_free(struct connman_ippool *pool);

struct connman_ippool *__connman_ippool_create(int index,
					unsigned int start,
					unsigned int range,
					ippool_collision_cb_t collision_cb,
					void *user_data);

const char *__connman_ippool_get_gateway(struct connman_ippool *pool);
const char *__connman_ippool_get_broadcast(struct connman_ippool *pool);
const char *__connman_ippool_get_subnet_mask(struct connman_ippool *pool);
const char *__connman_ippool_get_start_ip(struct connman_ippool *pool);
const char *__connman_ippool_get_end_ip(struct connman_ippool *pool);

void __connman_ippool_newaddr(int index, const char *address,
				unsigned char prefixlen);
void __connman_ippool_deladdr(int index, const char *address,
				unsigned char prefixlen);

int __connman_bridge_create(const char *name);
int __connman_bridge_remove(const char *name);
int __connman_bridge_enable(const char *name, const char *ip_address,
			int prefix_len, const char *broadcast);
int __connman_bridge_disable(const char *name);

int __connman_nat_init(void);
void __connman_nat_cleanup(void);

int __connman_nat_enable(const char *name, const char *address,
				unsigned char prefixlen);
void __connman_nat_disable(const char *name);

struct firewall_context;

struct firewall_context *__connman_firewall_create(void);
void __connman_firewall_destroy(struct firewall_context *ctx);
int __connman_firewall_enable_nat(struct firewall_context *ctx,
				char *address, unsigned char prefixlen,
				char *dst_address, unsigned char dst_prefixlen,
				char *interface);
int __connman_firewall_disable_nat(struct firewall_context *ctx);
int __connman_firewall_enable_snat(struct firewall_context *ctx,
				int index, const char *ifname,
				const char *addr);
int __connman_firewall_disable_snat(struct firewall_context *ctx);
int __connman_firewall_enable_forward(struct firewall_context *ctx, int family,
				const char *interface_in,
				const char *interface_out);
int __connman_firewall_disable_forward(struct firewall_context *ctx,
				int family);
int __connman_firewall_enable_marking(struct firewall_context *ctx,
					enum connman_session_id_type id_type,
					char *id, const char *src_ip,
					uint32_t mark);
int __connman_firewall_disable_marking(struct firewall_context *ctx);

bool __connman_firewall_is_up(void);

int __connman_firewall_init(void);
void __connman_firewall_cleanup(void);
void __connman_firewall_pre_cleanup(void);

typedef int (* connman_nfacct_flush_cb_t) (unsigned int error, void *user_data);

int __connman_nfacct_flush(connman_nfacct_flush_cb_t cb, void *user_data);

struct nfacct_context;

typedef void (* connman_nfacct_enable_cb_t) (unsigned int error,
						struct nfacct_context *ctx,
						void *user_data);
typedef void (* connman_nfacct_disable_cb_t) (unsigned int error,
						struct nfacct_context *ctx,
						void *user_data);
typedef void (* connman_nfacct_stats_cb_t) (struct nfacct_context *ctx,
						uint64_t packets,
						uint64_t bytes,
						void *user_data);

struct nfacct_context *__connman_nfacct_create_context(void);
void __connman_nfacct_destroy_context(struct nfacct_context *ctx);

int __connman_nfacct_add(struct nfacct_context *ctx, const char *name,
				connman_nfacct_stats_cb_t cb,
				void *user_data);
int __connman_nfacct_enable(struct nfacct_context *ctx,
				connman_nfacct_enable_cb_t cb,
				void *user_data);
int __connman_nfacct_disable(struct nfacct_context *ctx,
				connman_nfacct_disable_cb_t cb,
				void *user_data);

void __connman_nfacct_cleanup(void);

#include <connman/machine.h>

int __connman_machine_init(void);
void __connman_machine_cleanup(void);

#include <connman/access.h>

/* Service */
const char *__connman_access_default_service_policy_str(void);
bool __connman_access_is_default_service_policy
		(struct connman_access_service_policy *policy);

struct connman_access_service_policy *__connman_access_service_policy_create
		(const char *spec);
void __connman_access_service_policy_free
		(struct connman_access_service_policy *policy);
bool __connman_access_service_policy_equal
		(const struct connman_access_service_policy *p1,
			const struct connman_access_service_policy *p2);
enum connman_access __connman_access_service_policy_check
		(const struct connman_access_service_policy *policy,
			enum connman_access_service_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access);

/* Manager */
struct connman_access_manager_policy *__connman_access_manager_policy_create
		(const char *spec);
void __connman_access_manager_policy_free
		(struct connman_access_manager_policy *policy);
enum connman_access __connman_access_manager_policy_check
		(const struct connman_access_manager_policy *policy,
			enum connman_access_manager_methods method,
			const char *arg, const char *sender,
			enum connman_access default_access);

/* Technology */
struct connman_access_tech_policy *__connman_access_tech_policy_create
		(const char *spec);
void __connman_access_tech_policy_free
		(struct connman_access_tech_policy *policy);
enum connman_access __connman_access_tech_set_property
		(const struct connman_access_tech_policy *policy,
			const char *name, const char *sender,
			enum connman_access default_access);

/* Firewall */
struct connman_access_firewall_policy *__connman_access_firewall_policy_create
		(const char *spec);
void __connman_access_firewall_policy_free
		(struct connman_access_firewall_policy *policy);
enum connman_access __connman_access_firewall_manage
		(const struct connman_access_firewall_policy *policy,
			const char *name, const char *sender,
			enum connman_access default_access);

/* Storage */
struct connman_access_storage_policy *__connman_access_storage_policy_create
		(const char *spec);
void __connman_access_storage_policy_free
		(struct connman_access_storage_policy *policy);
enum connman_access __connman_access_storage_change_user
		(const struct connman_access_storage_policy *policy,
			const char *user, const char *sender,
			enum connman_access default_access);

int __connman_util_get_random(uint64_t *val);
unsigned int __connman_util_random_delay_ms(unsigned int secs);
int __connman_util_init(void);
void __connman_util_cleanup(void);

void __connman_set_fsid(const char *fs_identity);

int __connman_login_manager_init();
void __connman_login_manager_cleanup();

#ifdef SYSTEMD
int __systemd_login_init();
void __systemd_login_cleanup();
#endif
