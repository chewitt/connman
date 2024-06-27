/*
 *  ConnMan clat plugin unit tests
 *
 *  Copyright (C) 2023 Jolla Ltd. All rights reserved..
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
#include <gweb/gresolv.h>

#include "plugins/clat.c"

#define CLAT_DEV_INDEX 1
#define CLAT_DEV_NAME "clat"
#define SERVICE_DEV_INDEX 2
#define SERVICE_DEV_NAME "if"

extern struct connman_plugin_desc __connman_builtin_clat;

/* Dummies */

static bool __test_use_keyfile = false;
static bool __clat_dev_set = false;
static bool __clat_dev_up = false;
static int __service_dev_index = SERVICE_DEV_INDEX;

int connman_inet_ifup(int index)
{
	g_assert_cmpint(index, >, 0);

	if (index == CLAT_DEV_INDEX && __clat_dev_set) {
		if (__clat_dev_up)
			return -EALREADY;

		__clat_dev_up = true;
		return 0;
	}

	return -ENODEV;
}

int connman_inet_ifdown(int index)
{
	g_assert_cmpint(index, >, 0);

	if (index == CLAT_DEV_INDEX && __clat_dev_set) {
		if (!__clat_dev_up)
			return -EALREADY;

		__clat_dev_up = false;
		return 0;
	}

	return -ENODEV;
}

int connman_inet_rmtun(const char *ifname, int flags)
{
	g_assert_cmpstr(ifname, ==, CLAT_DEV_NAME);
	g_assert_false(__clat_dev_up);
	g_assert_true(__clat_dev_set);
	__clat_dev_set = false;

	return 0;
}

int connman_inet_mktun(const char *ifname, int flags)
{
	g_assert_cmpstr(ifname, ==, CLAT_DEV_NAME);
	return 0;
}

#define SERVICE_DEV_INDEX_VPN 10

int connman_inet_ifindex(const char *name)
{
	g_assert(name);

	if (!g_strcmp0(name, CLAT_DEV_NAME) && __clat_dev_set)
		return CLAT_DEV_INDEX;

	if (g_str_has_prefix(name, SERVICE_DEV_NAME)) {
		if (g_str_has_suffix(name, "2"))
			return 2;
		if (g_str_has_suffix(name, "3"))
			return 3;
	}

	if (g_str_has_prefix(name, "vpn")) {
		int index = name[strlen(name) - 1] + 10;

		DBG("vpn \"%s\" index %d", name, index);

		return index;
	}

	return -1;
}

char *connman_inet_ifname(int index)
{
	g_assert_cmpint(index, >, 0);

	if (index == CLAT_DEV_INDEX && __clat_dev_set)
		return g_strdup(CLAT_DEV_NAME);

	if (index == __service_dev_index || index == __service_dev_index + 1)
		return g_strdup_printf("%s%d", SERVICE_DEV_NAME, index);

	return NULL;
}

int connman_inet_add_ipv6_network_route_with_metric(int index, const char *host,
					const char *gateway,
					unsigned char prefix_len, short metric)
{
	g_assert(index == CLAT_DEV_INDEX || index == __service_dev_index);
	g_assert(host);

	DBG("index %d host %s gateway %s prefix_len %u metric %d", index, host,
						gateway, prefix_len, metric);
	return 0;
}

int connman_inet_add_ipv6_network_route(int index, const char *host,
					const char *gateway,
					unsigned char prefix_len)
{
	return connman_inet_add_ipv6_network_route_with_metric(index, host,
						gateway, prefix_len, 1);
}

int connman_inet_del_ipv6_network_route_with_metric(int index, const char *host,
					unsigned char prefix_len, short metric)
{
	g_assert(index == CLAT_DEV_INDEX || index == __service_dev_index);
	g_assert(host);

	DBG("index %d host %s prefix_len %u metric %d", index, host,
						prefix_len, metric);
	return 0;
}

int connman_inet_add_ipv6_host_route(int index, const char *host,
							const char *gateway)
{
	g_assert_cmpint(index, ==, __service_dev_index);
	g_assert(host);
	g_assert(gateway);

	DBG("index %d host %s gw %s", index, host, gateway);

	return 0;
}

int connman_inet_del_ipv6_host_route(int index, const char *host)
{
	g_assert_cmpint(index, ==, __service_dev_index);
	g_assert(host);

	DBG("index %d host %s", index, host);

	return 0;
}

int connman_inet_del_ipv6_network_route(int index, const char *host,
						unsigned char prefix_len)
{
	return connman_inet_del_ipv6_network_route_with_metric(index, host,
						prefix_len, 1);
}

int connman_inet_set_address(int index, struct connman_ipaddress *ipaddress)
{
	g_assert_cmpint(index, ==, CLAT_DEV_INDEX);
	g_assert(ipaddress);
	return 0;
}

bool connman_inet_is_any_addr(const char *address, int family)
{
	g_assert(address);

	if (family == AF_INET)
		return !g_strcmp0(address, "0.0.0.0");

	if (family == AF_INET6)
		return !g_strcmp0(address, "::");

	return false;
}

struct route_entry {
	int index;
	char *host;
	char *gateway;
	char *netmask;
	short metric;
	unsigned long mtu;
};

static struct route_entry *__route_entry_vpn = NULL;

int connman_inet_add_host_route(int index, const char *host,
						const char *gateway)
{
	DBG("index %d host %s gateway %s", index, host, gateway);

	g_assert_cmpint(index, ==, CLAT_DEV_INDEX);
	g_assert(host);

	g_assert_null(__route_entry_vpn); /* CLAT should set only one IPv4 route */

	__route_entry_vpn = g_new0(struct route_entry, 1);
	__route_entry_vpn->index = index;
	__route_entry_vpn->host = g_strdup(host);
	__route_entry_vpn->gateway = g_strdup(gateway);

	return 0;
}

int connman_inet_del_host_route(int index, const char *host)
{
	DBG("index %d host %s", index ,host);

	g_assert_cmpint(index, ==, CLAT_DEV_INDEX);
	g_assert(host);

	g_assert(__route_entry_vpn);
	g_assert_cmpint(__route_entry_vpn->index, ==, index);
	g_assert_cmpstr(__route_entry_vpn->host, ==, host);

	g_free(__route_entry_vpn->host);
	g_free(__route_entry_vpn->gateway);

	g_free(__route_entry_vpn);
	__route_entry_vpn = NULL;

	return 0;
}

struct dual_nat {
	char *ifname;
	char *ipaddr_range;
	unsigned char ipaddr_netmask;
};

static struct dual_nat *__dual_nat = NULL;

static struct route_entry *__route_entry = NULL;

int connman_inet_add_network_route_with_metric(int index, const char *host,
					const char *gateway,
					const char *netmask, short metric,
					unsigned long mtu)
{
	DBG("index %d host %s gateway %s netmask %s metric %d mtu %ld", index,
					host, gateway, netmask, metric, mtu);
	
	g_assert_cmpint(index, ==, CLAT_DEV_INDEX);
	g_assert(host);

	g_assert_null(__route_entry); /* CLAT should set only one IPv4 route */

	__route_entry = g_new0(struct route_entry, 1);
	__route_entry->index = index;
	__route_entry->host = g_strdup(host);
	__route_entry->gateway = g_strdup(gateway);
	__route_entry->netmask = g_strdup(netmask);
	__route_entry->metric = metric;
	__route_entry->mtu = mtu;

	return 0;
}

int connman_inet_del_network_route_with_metric(int index, const char *host,
					short metric)
{
	DBG("index %d host %s metric %d", index, host, metric);

	g_assert_cmpint(index, ==, CLAT_DEV_INDEX);
	g_assert(host);

	g_assert(__route_entry);
	g_assert_cmpint(__route_entry->index, ==, index);
	g_assert_cmpstr(__route_entry->host, ==, host);
	g_assert_cmpint(__route_entry->metric, ==, metric);

	g_free(__route_entry->host);
	g_free(__route_entry->gateway);
	g_free(__route_entry->netmask);
	g_free(__route_entry);
	__route_entry = NULL;

	return 0;
}

int connman_inet_clear_address(int index, struct connman_ipaddress *ipaddress)
{
	g_assert_cmpint(index, ==, CLAT_DEV_INDEX);
	g_assert(ipaddress);
	return 0;
}

int connman_inet_clear_ipv6_gateway_address(int index, const char *gateway)
{
	g_assert_cmpint(index, ==, __service_dev_index);
	g_assert(gateway);
	return 0;
}

int connman_inet_set_ipv6_gateway_interface(int index)
{
	g_assert_cmpint(index, ==, __service_dev_index);
	return 0;
}

int connman_inet_clear_ipv6_gateway_interface(int index)
{
	g_assert_cmpint(index, ==, __service_dev_index);
	return 0;
}

int connman_inet_check_ipaddress(const char *host)
{
	g_assert(host);
	return 0;
}

static int dad_reply_ptr = 0x87654321;
static connman_inet_ns_cb_t __dad_callback = NULL;
static struct in6_addr dad_addr = { 0 };
static void *__dad_user_data = NULL;

int connman_inet_ipv6_do_dad(int index, int timeout_ms, struct in6_addr *addr,
				connman_inet_ns_cb_t callback, void *user_data)
{
	g_assert_cmpint(index, ==, __service_dev_index);
	g_assert(addr);
	g_assert(callback);

	__dad_callback = callback;
	memcpy(&dad_addr, addr, sizeof(struct in6_addr));
	__dad_user_data = user_data;

	return 0;
}

static bool __dad_succeeds = true;

static bool call_dad_callback()
{
	struct nd_neighbor_advert *na = NULL;
	unsigned int length = 0;

	if (!__dad_callback)
		return false;

	if (!__dad_succeeds) {
		na = (struct nd_neighbor_advert*)&dad_reply_ptr;
		length = 1;
	}

	__dad_callback(na, length, &dad_addr, __dad_user_data);

	__dad_callback = NULL;
	__dad_user_data = NULL;

	return true;
}

struct connman_task {
	char *path;
	GPtrArray *argv;
	connman_task_exit_t exit_func;
	void *exit_data;
	bool running;
};

static struct connman_task *__task = NULL;
static int __task_exit_value = 0;
static int __task_run_count = 0;
static char *__last_set_contents_write = NULL;
static char *__last_set_contents = NULL;


static void free_pointer(gpointer data, gpointer user_data)
{
	g_free(data);
}

static void free_task()
{
	g_free(__task->path);

	if (__task->argv) {
		g_ptr_array_foreach(__task->argv, free_pointer, NULL);
		g_ptr_array_free(__task->argv, TRUE);
	}

	g_free(__task);
	__task = NULL;
}

struct connman_task *connman_task_create(const char *program,
					connman_task_setup_t custom_task_setup,
					void *setup_data)
{
	DBG("");

	g_assert(program);
	g_assert_null(custom_task_setup);
	g_assert_null(setup_data);

	g_assert_true(g_str_has_suffix(program, "tayga"));

	if (__task)
		free_task();

	__task = g_new0(struct connman_task, 1);
	g_assert(__task);
	
	__task->path = g_strdup(program);
	__task->argv = g_ptr_array_new();
	__task->running = false;

	return __task;
}

int connman_task_add_argument(struct connman_task *task,
					const char *name,
					const char *format, ...)
{
	g_assert(task);
	g_assert(task == __task);
	g_assert(name);

	va_list ap;
	char *str;

	DBG("task %p arg %s", task, name);

	str = g_strdup(name);
	g_ptr_array_add(task->argv, str);

	va_start(ap, format);

	if (format) {
		str = g_strdup_vprintf(format, ap);
		g_ptr_array_add(task->argv, str);
	}

	va_end(ap);

	return 0;
}

#define TASK_STDOUT 1
#define TASK_STDERR 2

int connman_task_run(struct connman_task *task,
			connman_task_exit_t function, void *user_data,
			int *stdin_fd, int *stdout_fd, int *stderr_fd)
{
	DBG("task %p function %p user_data %p", task, function, user_data);

	g_assert(task);
	g_assert(task == __task);
	g_assert_false(__task->running);

	g_assert(function);
	__task->exit_func = function;
	__task->exit_data = user_data;
	__task->running = true;
	__task_run_count++;

	if (stdout_fd)
		*stdout_fd = TASK_STDOUT;

	if (stderr_fd)
		*stderr_fd = TASK_STDERR;

	DBG("stdin %d stdout %d stderr %d", stdin_fd ? *stdin_fd : -1,
					stdout_fd ? *stdout_fd : -1,
					stderr_fd ? *stderr_fd : -1);

	return 0;
}

int connman_task_stop(struct connman_task *task)
{
	connman_task_exit_t exit_func;
	DBG("task %p", task);

	g_assert(task);
	g_assert(task == __task);

	if (task->running) {
		DBG("task running");
		task->running = false;

		/* Allow to run exit only once from a process */
		exit_func = task->exit_func;
		task->exit_func = NULL;

		if (exit_func) {
			DBG("calling exit func");
			exit_func(task, __task_exit_value, task->exit_data);
		}
	} else {
		DBG("task not running");
	}

	return 0;
}

void connman_task_destroy(struct connman_task *task)
{
	DBG("task %p", task);

	g_assert(task);
	g_assert(task == __task);

	if (task->running)
		connman_task_stop(task);

	g_free(task->path);
	task->path = NULL;

	g_ptr_array_foreach(task->argv, free_pointer, NULL);
	g_ptr_array_free(task->argv, TRUE);
	task->argv = NULL;

	g_free(__task);
	__task = NULL;

	return;
}

enum task_setup {
	TASK_SETUP_UNKNOWN = 0,
	TASK_SETUP_PRE,
	TASK_SETUP_CONF,
	TASK_SETUP_POST,
	TASK_SETUP_STOPPED,
};

static enum task_setup get_task_setup()
{
	g_assert(__task->path);

	g_assert_true(g_ptr_array_find_with_equal_func(__task->argv, "--config",
						g_str_equal, NULL));

	if (g_ptr_array_find_with_equal_func(__task->argv, "--mktun",
							g_str_equal, NULL)) {
		__clat_dev_set = true;
		return TASK_SETUP_PRE;
	}

	if (g_ptr_array_find_with_equal_func(__task->argv, "--rmtun",
							g_str_equal, NULL)) {
		__clat_dev_set = false;
		return TASK_SETUP_POST;
	}

	if (g_ptr_array_find_with_equal_func(__task->argv, "--nodetach",
							g_str_equal, NULL))
		return TASK_SETUP_CONF;

	return TASK_SETUP_UNKNOWN;
}

static void call_task_exit(int exit_code)
{
	DBG("exit_code %d", exit_code);

	g_assert(__task->exit_func);
	if (__task->running) {
		__task->running = false;
		__task->exit_func(__task, exit_code, __task->exit_data);
	}
}

static bool __vpn_mode = false;

static gboolean task_running(enum task_setup setup, int add_run_count)
{
	if (!__task)
		return false;

	switch (setup) {
	case TASK_SETUP_PRE:
		g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_PRE);
		g_assert_true(__clat_dev_set);
		g_assert_false(__clat_dev_up);
		g_assert_cmpint(__task_run_count, ==, 1 + add_run_count);
		g_assert(__last_set_contents_write);
		g_assert_true(g_str_has_suffix(__last_set_contents_write,
								"tayga.conf"));
		g_assert_null(__route_entry);

		g_assert_null(__dual_nat);
		g_free(__last_set_contents_write);
		__last_set_contents_write = NULL;
		break;
	case TASK_SETUP_CONF:
		g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_CONF);
		g_assert_true(__clat_dev_set);
		g_assert_true(__clat_dev_up);
		g_assert_cmpint(__task_run_count, ==, 2 + add_run_count);
		g_assert_null(__last_set_contents_write);
		if (__vpn_mode) {
			g_assert_null(__route_entry);
		} else {
			if (__test_use_keyfile)
				g_assert(__route_entry);
		}
		break;
	case TASK_SETUP_POST:
		g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_POST);
		g_assert_false(__clat_dev_set);
		g_assert_false(__clat_dev_up);
		g_assert_cmpint(__task_run_count, ==, 3 + add_run_count);
		g_assert_null(__last_set_contents_write);
		g_assert_null(__route_entry);
		g_assert_null(__dual_nat);
		break;
	case TASK_SETUP_STOPPED:
		g_assert_cmpint(__task_run_count, ==, 3 + add_run_count);
		g_assert_false(__clat_dev_set);
		g_assert_false(__clat_dev_up);
		g_assert_null(__last_set_contents_write);
		return __task->running;
	case TASK_SETUP_UNKNOWN:
		/* No assert checks */
		break;
	}

	return __task->path && __task->running;
}

static gboolean check_task_running(enum task_setup setup, int restarts)
{
	int add_run_count = restarts * 3;

	DBG("setup %d restarts %d", setup, restarts);

	return task_running(setup, add_run_count);
}

static gboolean check_task_running_added_rounds(enum task_setup setup,
							int add_run_count)
{
	DBG("setup %d add %d rounds", setup, add_run_count);

	return task_running(setup, add_run_count);
}

struct connman_ipconfig {
	struct connman_ipaddress *ipaddress;
	enum connman_ipconfig_type type;
	enum connman_ipconfig_method method;
	int index;
};

int connman_ipconfig_get_index(struct connman_ipconfig * ipconfig)
{
	DBG("ipconfig %p", ipconfig);

	g_assert(ipconfig);

	return ipconfig->index;
}

enum connman_ipconfig_type connman_ipconfig_get_config_type(
					struct connman_ipconfig *ipconfig)
{
	DBG("ipconfig %p", ipconfig);

	g_assert(ipconfig);

	return ipconfig->type;
}

struct connman_ipaddress *connman_ipconfig_get_ipaddress(
					struct connman_ipconfig *ipconfig)
{
	DBG("ipconfig %p", ipconfig);

	if (!ipconfig)
		return NULL;

	return ipconfig->ipaddress;
}

bool connman_ipconfig_has_ipaddress_set(struct connman_ipconfig *ipconfig)
{
	struct connman_ipaddress *ipaddress;
	const char *address;
	unsigned char prefixlen;
	int err;

	DBG("ipconfig %p", ipconfig);

	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	err = connman_ipaddress_get_ip(ipaddress, &address, &prefixlen);
	if (err)
		return false;

	if (!address)
		return false;

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		return false;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		break;
	}

	DBG("IP address %s set", address);

	return true;
}

const char *connman_ipconfig_get_gateway_from_index(int index,
					enum connman_ipconfig_type type)
{
	g_assert_cmpint(index, >, 0);
	g_assert_cmpint(type, ==, CONNMAN_IPCONFIG_TYPE_IPV4);

	return "10.10.0.0";
}

enum connman_ipconfig_method get_method(struct connman_ipconfig *ipconfig)
{
	DBG("ipconfig %p", ipconfig);

	g_assert(ipconfig);
	return ipconfig->method;
}

static void init_ipaddress(struct connman_ipconfig *ipconfig)
{
	g_assert(ipconfig);

	if (ipconfig->ipaddress)
		return;

	switch (ipconfig->type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		ipconfig->ipaddress = connman_ipaddress_alloc(AF_INET);
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		ipconfig->ipaddress = connman_ipaddress_alloc(AF_INET6);
		break;
	default:
		return;
	}

	g_assert(ipconfig->ipaddress);
}

static void assign_ipaddress(struct connman_ipconfig *ipconfig)
{
	init_ipaddress(ipconfig);

	switch (ipconfig->type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		connman_ipaddress_set_ipv4(ipconfig->ipaddress, "10.10.10.2",
					"255.255.255.0", "10.10.10.1");
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		connman_ipaddress_set_ipv6(ipconfig->ipaddress,
					"dead:beef:feed:abba:caba:daba::1234",
					64, NULL);
		break;
	default:
		return;
	}

	g_assert(ipconfig->ipaddress);
}

int connman_nat_enable_double_nat_override(const char *ifname,
						const char *ipaddr_range,
						unsigned char ipaddr_netmask)
{
	DBG("interface %s ipaddr_range %s ipaddr_netmask %u", ifname,
						ipaddr_range, ipaddr_netmask);
	g_assert(ifname);
	g_assert_null(__dual_nat);

	__dual_nat = g_new0(struct dual_nat, 1);
	__dual_nat->ifname = g_strdup(ifname);
	__dual_nat->ipaddr_range = g_strdup(ipaddr_range);
	__dual_nat->ipaddr_netmask = ipaddr_netmask;

	return 0;
}

void connman_nat_disable_double_nat_override(const char *ifname)
{
	DBG("interface %s", ifname);

	g_assert(ifname);
	g_assert(__dual_nat);
	g_assert_cmpstr(__dual_nat->ifname, ==, ifname);

	g_free(__dual_nat->ifname);
	g_free(__dual_nat->ipaddr_range);
	g_free(__dual_nat);
	__dual_nat = NULL;
}

int connman_nat6_prepare(struct connman_ipconfig *ipconfig,
						const char *ipv6address,
						unsigned char ipv6prefixlen,
						const char *ifname_in,
						bool ndproxy)
{
	g_assert(ipconfig);
	return 0;
}

void connman_nat6_restore(struct connman_ipconfig *ipconfig)
{
	g_assert(ipconfig);
}

static const struct connman_notifier *n;

int connman_notifier_register(const struct connman_notifier *notifier)
{
	g_assert(notifier);
	g_assert_null(n);
	n = notifier;
	return 0;
}

void connman_notifier_unregister(const struct connman_notifier *notifier)
{
	g_assert(notifier);
	g_assert(notifier == n);
	n = NULL;
}

struct connman_network {
	int index;
	bool connected;
	bool ipv4_configured;
	bool ipv6_configured;
};

int connman_network_get_index(struct connman_network *network)
{
	DBG("network %p", network);

	g_assert(network);
	DBG("index %d", network->index);
	return network->index;
}

bool connman_network_get_connected(struct connman_network *network)
{
	DBG("network %p", network);

	g_assert(network);
	return network->connected;
}

bool connman_network_is_configured(struct connman_network *network,
					enum connman_ipconfig_type type)
{
	DBG("network %p type %d", network, type);

	g_assert(network);

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		break;
	case CONNMAN_IPCONFIG_TYPE_ALL:
		return network->ipv4_configured && network->ipv6_configured;
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		return network->ipv4_configured;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		return network->ipv6_configured;
	default:
		break;
	}

	return false;
}

struct connman_service {
	char *identifier;
	char *path;
	enum connman_service_state state;
	enum connman_service_type type;
	char *name;
	struct connman_ipconfig *ipconfig_ipv4;
	struct connman_ipconfig *ipconfig_ipv6;
	struct connman_network *network;
	
};

static struct connman_service *__def_service = NULL;
static struct connman_service *__vpn_transport = NULL;

struct connman_ipconfig *connman_service_get_ipconfig(
					struct connman_service *service,
					int family)
{
	DBG("service %p family %d", service, family);

	g_assert(service);

	if (family == AF_INET) {
		DBG("IPv4 config %p", service->ipconfig_ipv4);
		return service->ipconfig_ipv4;
	}

	if (family == AF_INET6)
		return service->ipconfig_ipv6;

	return NULL;
}

enum connman_ipconfig_method connman_service_get_ipconfig_method(
					struct connman_service *service,
					enum connman_ipconfig_type type)
{
	DBG("service %p type %d", service, type);

	g_assert(service);

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		return get_method(service->ipconfig_ipv4);
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		return get_method(service->ipconfig_ipv6);
	case CONNMAN_IPCONFIG_TYPE_ALL:
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		break;
	}

	return CONNMAN_IPCONFIG_TYPE_UNKNOWN;
}

int connman_service_ipconfig_indicate_state(struct connman_service *service,
					enum connman_service_state new_state,
					enum connman_ipconfig_type type,
					bool notify_settings_change)
{
	if (!service)
		return -EINVAL;

	return 0;
}

struct connman_service *connman_service_get_default(void)
{
	DBG("default %p", __def_service);

	return __def_service;
}

const char *connman_service_get_identifier(struct connman_service *service)
{
	DBG("service %p", service);

	g_assert(service);
	return service->identifier;
}

enum connman_service_type connman_service_get_type(
					struct connman_service *service)
{
	DBG("service %p", service);

	g_assert(service);
	return service->type;
}

enum connman_service_state connman_service_get_state(
					struct connman_service *service)
{
	DBG("service %p", service);

	/* Mimic the real function */
	if (!service)
		return CONNMAN_SERVICE_STATE_UNKNOWN;

	return service->state;
}

struct connman_network *connman_service_get_network(
					struct connman_service *service)
{
	DBG("service %p", service);

	g_assert(service);
	return service->network;
}

const char *connman_service_get_vpn_transport_identifier(
						struct connman_service *service)
{
	g_assert(service);

	if (!__vpn_transport)
		return NULL;

	return __vpn_transport->identifier;
}

static bool __ipconfig_address_change_notified = false;

int connman_service_reset_ipconfig_to_address(struct connman_service *service,
					enum connman_service_state *new_state,
					enum connman_ipconfig_type type,
					enum connman_ipconfig_method new_method,
					int index,
					const char *address,
					const char *netmask,
					const char *gateway,
					const unsigned char prefix_length)
{
	struct connman_ipconfig *ipconfig;

	g_assert(service);
	g_assert(new_state);
	g_assert_cmpint(index, >, 0);
	g_assert_cmpint(type, ==, CONNMAN_IPCONFIG_TYPE_IPV4);
	g_assert(new_method == CONNMAN_IPCONFIG_METHOD_MANUAL ||
				new_method == CONNMAN_IPCONFIG_METHOD_OFF);
	g_assert_cmpint(prefix_length, ==, 0);

	if (new_method == CONNMAN_IPCONFIG_METHOD_MANUAL)
		g_assert(address);

	ipconfig = connman_service_get_ipconfig(service, AF_INET);
	g_assert(ipconfig);

	if (!ipconfig->ipaddress)
		ipconfig->ipaddress = connman_ipaddress_alloc(AF_INET);

	g_assert(ipconfig->ipaddress);

	connman_ipaddress_set_ipv4(ipconfig->ipaddress, address, netmask,
								gateway);

	if (new_state && ipconfig->method != new_method) {
		*new_state = service->state;
		__ipconfig_address_change_notified = true;
	}

	ipconfig->method = new_method;

	return 0;
}

struct connman_service *
connman_service_ref_debug(struct connman_service *service,
			const char *file, int line, const char *caller)
{
	g_assert(service);
	return service;
}

void connman_service_unref_debug(struct connman_service *service,
			const char *file, int line, const char *caller)
{
	g_assert(service);
	return;
}

struct connman_provider {
	const char *hostip;
};

static struct connman_provider __provider = { "1.2.3.4" };

struct connman_provider *connman_service_get_vpn_provider(
						struct connman_service *service)
{
	if (!service)
		return NULL;

	return &__provider;
}

struct connman_service *connman_service_lookup_from_identifier(
						const char *identifier)
{
	if (!identifier)
		return NULL;

	if (__vpn_transport)
		g_assert_cmpstr(identifier, ==, __vpn_transport->identifier);

	return __vpn_transport;
}

int connman_provider_disconnect(struct connman_provider *provider)
{
	g_assert(provider == &__provider);

	return 0;
}

static bool __service_nameservers_set = true;

char **connman_service_get_nameservers(struct connman_service *service)
{
	char **nss;

	if (!__service_nameservers_set)
		return NULL;

	nss = g_new0(char*, 3);
	nss[0] = g_strdup("4.4.4.4");
	nss[1] = g_strdup("8.8.8.8");
	nss[2] = NULL;

	return nss;
}

struct _GResolv {
	int index;
	GResolvResultFunc result_func;
	gpointer result_data;
	char *hostname;
};

static struct _GResolv *__resolv = NULL;

GResolv *g_resolv_new(int index)
{
	DBG("index %d", index);
	g_assert_cmpint(index, >= , 0);

	g_assert_null(__resolv);
	__resolv = g_new0(struct _GResolv, 1);
	g_assert(__resolv);

	__resolv->index = index;

	return __resolv;
}

void g_resolv_unref(GResolv *resolv)
{
	DBG("resolv %p", resolv);

	g_assert(resolv);
	g_assert(resolv == __resolv);

	g_free(__resolv->hostname);
	g_free(__resolv);
	__resolv = NULL;
}

static guint resolv_id = 0;

guint g_resolv_lookup_hostname(GResolv *resolv, const char *hostname,
				GResolvResultFunc func, gpointer user_data)
{
	DBG("resolv %p hostname %s func %p user_data %p", resolv, hostname,
							func, user_data);

	g_assert(resolv);
	g_assert(resolv == __resolv);
	g_assert(hostname);
	g_assert(func);

	g_assert_cmpstr(hostname, ==, "ipv4only.arpa");
	__resolv->hostname = g_strdup(hostname);
	__resolv->result_func = func;
	__resolv->result_data = user_data;

	return ++resolv_id;
}

bool g_resolv_cancel_lookup(GResolv *resolv, guint id)
{
	DBG("resolv %p id %d", resolv, id);
	g_assert(resolv);
	g_assert(resolv == __resolv);

	g_assert_cmpint(id, ==, resolv_id);

	g_free(__resolv->hostname);
	__resolv->hostname = NULL;

	return true;
}

bool g_resolv_set_address_family(GResolv *resolv, int family)
{
	DBG("resolv %p family %d", resolv, family);

	g_assert(resolv);
	g_assert(resolv == __resolv);
	g_assert_cmpint(family, ==, AF_INET6);

	return true;
}

enum resolv_result_type {
	RESOLV_RESULT_GLOBAL = 0,
	RESOLV_RESULT_ONE_64,
	RESOLV_RESULT_ONE_96,
	RESOLV_RESULT_SORT
};

static enum resolv_result_type __resolv_result_type = RESOLV_RESULT_GLOBAL;

static void call_resolv_result(GResolvResultStatus status)
{
	/* TODO add more and make configurable */
	char **r = g_new0(char*, 5);

	switch (__resolv_result_type) {
	case RESOLV_RESULT_GLOBAL:
		r[0] = g_strdup("64:ff9b::c000:aa");
		r[1] = g_strdup("64:ff9b::c000:ab");
		r[2] = g_strdup("64:ff9b::/96");
		r[3] = g_strdup("dead:beef:0000:feed:abba:cabb:1234:");
		r[4] = NULL;
		break;
	case RESOLV_RESULT_ONE_64:
		r[0] = g_strdup("66:ff9b::c000:aa");
		r[1] = g_strdup("65:ff9b::c000:ab");
		r[2] = g_strdup("63:ff9b::/96");
		r[3] = g_strdup("dead:beef:0000:feed:abba:cabb:1234:5555/64");
		break;
	case RESOLV_RESULT_ONE_96:
		r[0] = g_strdup("66:ff9b:c000:aa:aba:abab:baaa:aaaa");
		r[1] = g_strdup("65:ff9b:c000:ab:1:2:3:4");
		r[2] = g_strdup("63:ff9b::/64");
		r[3] = g_strdup("dead:beef:0000:feed:abba:cabb:1234:5555/96");
		break;
	case RESOLV_RESULT_SORT:
		r[0] = g_strdup("dead:beef:0000:feed:abba:cabb:1234:5556/64");
		r[1] = g_strdup("dead:beef:0000:feed:abba:cabb:1234:5557/96");
		r[2] = g_strdup("dead:beef:0000:feed:abba:cabb:1234:5558/72");
		r[3] = g_strdup("dead:beef:0000:feed:abba:cabb:1234:5559/128");
		break;
	default:
		break;
	}
	r[4] = NULL;

	g_assert(__resolv);
	g_assert(__resolv->hostname);
	g_assert(__resolv->result_func);
	g_assert(__resolv->result_data);

	__resolv->result_func(status, r, __resolv->result_data);

	g_strfreev(r);
}

static gboolean check_set_prefix()
{
	char **tokens;
	char *addr;
	bool result = true;
	int i;

	if (!__last_set_contents)
		return false;

	tokens = g_strsplit(__last_set_contents, "\n", 7);
	if (!tokens)
		return false;

	for (i = 0; tokens[i]; i++) {
		if (g_str_has_prefix(tokens[i], "prefix"))
			break;
	}

	/* TODO make this better */
	switch (__resolv_result_type) {
	case RESOLV_RESULT_GLOBAL:
		addr = g_strdup("prefix 64:ff9b::/96");
		break;
	case RESOLV_RESULT_ONE_64:
		addr = g_strdup("prefix 63:ff9b::/96");
		break;
	case RESOLV_RESULT_ONE_96:
		addr = g_strdup(
			"prefix dead:beef:0000:feed:abba:cabb:1234:5555/96");
		break;
	case RESOLV_RESULT_SORT:
		addr = g_strdup(
			"prefix dead:beef:0000:feed:abba:cabb:1234:5557/96");
		break;
	default:
		addr = NULL;
	}

	if (g_strcmp0(tokens[i], addr)) {
		DBG("prefix %s is not expected %s", tokens[i], addr);
		result = false;
	}

	g_strfreev(tokens);
	g_free(addr);

	return result;
}

gboolean g_file_set_contents(const gchar* filename, const gchar* contents,
						gssize length, GError** error)
{
	DBG("filename %s", filename);

	g_assert(filename);
	g_assert(contents);

	g_free(__last_set_contents_write);
	__last_set_contents_write = g_strdup(filename);

	g_free(__last_set_contents);
	__last_set_contents = g_strdup(contents);

	return TRUE;
}

// TODO config loading tests
gboolean g_key_file_load_from_file(GKeyFile *keyfile, const gchar *file,
					GKeyFileFlags flags, GError** error)
{
	g_assert(keyfile);
	g_assert(file);

	if (!__test_use_keyfile)
		*error = g_error_new_literal(1, G_FILE_ERROR_NOENT,
							"no file in test");

	return __test_use_keyfile;
}

static int stdout_fd_ch_ptr = 0x12345678;
static int stderr_fd_ch_ptr = 0x12344321;

static GIOFunc stdout_func = NULL;
static GIOFunc stderr_func = NULL;
static gpointer stdout_data = NULL;
static gpointer stderr_data = NULL;

struct timeout_function {
	guint id; /* Only for debugs */
	guint interval;
	GSourceFunc function;
	gpointer data;
	bool removed;
	bool called;
};

static GHashTable *__timeouts = NULL;

static guint __timeout_id = 0;

GIOChannel* g_io_channel_unix_new(int fd)
{
	//DBG("fd %d", fd);

	g_assert_cmpint(fd, >, 0);

	if (fd == TASK_STDOUT) {
		stdout_fd_ch_ptr++;
		return (GIOChannel *)&stdout_fd_ch_ptr;
	}

	if (fd == TASK_STDERR) {
		stderr_fd_ch_ptr++;
		return (GIOChannel *)&stderr_fd_ch_ptr;
	}

	return NULL;
}

/* Keep all source id's in the same place */
static guint add_timeout(guint interval, GSourceFunc function, gpointer data)
{	struct timeout_function *tf;

	tf = g_new0(struct timeout_function, 1);
	g_assert(tf);

	tf->interval = interval;
	tf->function = function;
	tf->data = data;

	if (!__timeouts) {
		/* Uses guints to ptr */
		__timeouts = g_hash_table_new_full(g_direct_hash,
						g_direct_equal, NULL, g_free);
		__timeout_id = 0;
	}

	__timeout_id++;
	tf->id = __timeout_id;

	g_hash_table_replace(__timeouts, GUINT_TO_POINTER(__timeout_id), tf);

	return __timeout_id;

}

guint g_io_add_watch(GIOChannel* channel, GIOCondition condition, GIOFunc func,
							gpointer user_data)
{
	//DBG("channel %p func %p user_data %p", channel, func, user_data);

	g_assert(channel);
	g_assert(func);

	if (channel == (GIOChannel *)&stdout_fd_ch_ptr) {
		stdout_func = func;
		stdout_data = user_data;
	}

	if (channel == (GIOChannel *)&stderr_fd_ch_ptr) {
		stderr_func = func;
		stderr_data = user_data;
	}

	return add_timeout(0, NULL, user_data);
}

GIOStatus g_io_channel_shutdown(GIOChannel* channel, gboolean flush,
								GError** error)
{
	//DBG("channel %p", channel);

	if (channel == (GIOChannel *)&stdout_fd_ch_ptr ||
				channel == (GIOChannel *)&stderr_fd_ch_ptr)
		return G_IO_STATUS_NORMAL;

	return G_IO_STATUS_ERROR;
}

static GIOStatus __io_status = G_IO_STATUS_NORMAL;
static char *__io_str = NULL;

GIOStatus g_io_channel_read_line(GIOChannel* channel, gchar** str_return,
					gsize* length, gsize* terminator_pos,
					GError** error)
{
	DBG("channel %p str %s", channel, __io_str);

	g_assert(channel);
	g_assert(str_return);

	if (!__io_str)
		return G_IO_STATUS_ERROR;

	*str_return = g_strdup(__io_str);
	*length = strlen(__io_str); /* These are terminated  with \n */

	return __io_status;
}

void g_io_channel_unref(GIOChannel* channel)
{
	//DBG("channel %p", channel);

	if (channel == (GIOChannel *)&stdout_fd_ch_ptr) {
		stdout_func = NULL;
		stdout_data = NULL;
	}

	if (channel == (GIOChannel *)&stderr_fd_ch_ptr) {
		stderr_func = NULL;
		stderr_data = NULL;
	}
}

void g_io_channel_set_close_on_unref(GIOChannel* channel, gboolean do_close)
{
	g_assert(channel == (GIOChannel *)&stdout_fd_ch_ptr ||
				channel == (GIOChannel *)&stderr_fd_ch_ptr);
}

static bool call_g_io_stderr(GIOCondition cond, const char *str)
{
	gboolean ret;

	g_assert(stderr_func);

	__io_str = g_strdup(str);
	ret = stderr_func((GIOChannel *)&stderr_fd_ch_ptr, cond, stderr_data);

	g_free(__io_str);
	__io_str = NULL;

	return ret;
}

gboolean g_source_remove(guint id)
{
	gpointer value;

	DBG("id %u", id);

	if (!__timeouts)
		return false;

	value = g_hash_table_lookup(__timeouts, GUINT_TO_POINTER(id));
	if (value) {
		struct timeout_function *tf = value;

		DBG("found, marked as removed");
		tf->removed = true;

		return TRUE;
	}

	return FALSE;
}

guint g_timeout_add(guint interval, GSourceFunc function, gpointer data)
{
	guint id;

	g_assert(function);
	g_assert(data);

	id = add_timeout(interval, function, data);

	DBG("added id %d", id);

	return id;
}

guint connman_wakeup_timer_add(guint interval, GSourceFunc function,
								gpointer data)
{
	return g_timeout_add(interval, function, data);
}

static bool call_timeout(gpointer key, gpointer value)
{
	struct timeout_function *tf;
	guint id;

	tf = value;
	id = GPOINTER_TO_UINT(key);
	if (!id)
		id = tf->id;

	if (tf->removed) {
		DBG("id %u already removed, not calling callback", id);
		return false;
	}

	if (tf->called) {
		DBG("id %u already called", id);
		return false;
	}

	g_assert(tf);

	if (!tf->function) {
		DBG("id %u does not have function (GIO)", id);
		return false;
	}

	DBG("call id %u (interval %u)", id, tf->interval);

	if (tf->function(tf->data) == G_SOURCE_REMOVE)
		tf->removed = true;

	tf->called = true;

	return true;
}

static gint compare_uint(gconstpointer a, gconstpointer b)
{
	guint int_a = GPOINTER_TO_UINT(a);
	guint int_b = GPOINTER_TO_UINT(b);

	if (int_a < int_b)
		return -1;

	if (int_a > int_b)
		return 1;

	return 0;
}

static guint call_all_timeouts(void)
{
	GList *keys;
	GList *iter;
	guint count = 0;

	DBG("%p", __timeouts);

	if (!__timeouts || !g_hash_table_size(__timeouts))
		return 0;

	/*
	 * Get the keys at the time we're about to call the callbacks. New
	 * timeout functions may be added when callback is called and, thus
	 * the hash table is altered. This way it is safe to call only those
	 * that are now scheduled. Use sorted list as the keys increase at
	 * each new timeout and the last would be normally returned as first.
	 */
	keys = g_list_sort(g_hash_table_get_keys(__timeouts), compare_uint);
	DBG("%d keys", g_list_length(keys));

	for (iter = keys; iter; iter = g_list_next(iter)) {
		gpointer key;
		gpointer value;

		key = iter->data;

		value = g_hash_table_lookup(__timeouts, key);
		g_assert(value);

		if (call_timeout(key, value))
			count++;
	}

	g_list_free(keys);

	DBG("called %u timeout functions", count);

	return count;
}

static gint compare_timeout_function(gconstpointer a, gconstpointer b)
{
	const struct timeout_function *tf_a = a;
	const struct timeout_function *tf_b = b;

	if (tf_a->interval < tf_b->interval)
		return -1;

	if (tf_a->interval > tf_b->interval)
		return 1;

	return 0;
}

static guint call_all_timeouts_timed(void)
{
	GList *timeouts_sorted = NULL;
	GList *keys;
	GList *iter;
	guint count = 0;

	DBG("%p", __timeouts);

	if (!__timeouts || !g_hash_table_size(__timeouts))
		return 0;

	/*
	 * Get the keys at the time we're about to call the callbacks. New
	 * timeout functions may be added when callback is called and, thus
	 * the hash table is altered. This way it is safe to call only those
	 * that are now scheduled.
	 */
	keys = g_hash_table_get_keys(__timeouts);
	DBG("%d keys", g_list_length(keys));

	for (iter = keys; iter; iter = g_list_next(iter)) {
		gpointer key;
		gpointer value;

		key = iter->data;

		value = g_hash_table_lookup(__timeouts, key);
		g_assert(value);

		/* Sort using the timeout */
		timeouts_sorted = g_list_insert_sorted(timeouts_sorted, value,
					compare_timeout_function);
	}

	for (iter = timeouts_sorted; iter; iter = g_list_next(iter))
	{
		if (call_timeout(0, iter->data))
			count++;
	}

	g_list_free(keys);
	g_list_free(timeouts_sorted);

	DBG("called %u timeout functions", count);

	return count;
}

static guint pending_timeouts(void)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	guint count = 0;

	if (!__timeouts)
		return count;

	g_hash_table_iter_init(&iter, __timeouts);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct timeout_function *tf;

		tf = value;

		if (tf->function && !tf->called && !tf->removed)
			count++;
	}

	return count;
}

static struct connman_rtnl *r = NULL;

int connman_rtnl_register(struct connman_rtnl *rtnl)
{
	g_assert(rtnl);
	g_assert_null(r);
	r = rtnl;
	return 0;
}

void connman_rtnl_unregister(struct connman_rtnl *rtnl)
{
	g_assert(rtnl);
	g_assert(rtnl == r);
	r = NULL;
}

static bool rtprot_ra = false;

void connman_rtnl_handle_rtprot_ra(bool value)
{
	rtprot_ra = value;
	return;
}

/* Just use static info as of now */
static void call_rntl_new_gateway(const char *gw)
{
	g_assert(gw);
	g_assert(r);
	g_assert(r->newgateway6);
	r->newgateway6(SERVICE_DEV_INDEX, "::", gw, 1024, RTPROT_RA);
}

const char *connman_setting_get_string(const char *key)
{
	return NULL;
}

static void test_reset(void) {
	__task_run_count = 0;
	__task_exit_value = 0;
	if (__task)
		free_task();

	__def_service = NULL;

	g_free(__last_set_contents_write);
	__last_set_contents_write = NULL;

	g_free(__last_set_contents);
	__last_set_contents = NULL;

	rtprot_ra = false;
	resolv_id = 0;

	__dad_callback = NULL;
	__dad_user_data = NULL;

	if (__resolv)
		g_resolv_unref(__resolv);

	if (__timeouts)
		g_hash_table_destroy(__timeouts);
	__timeouts = NULL;

	__resolv_result_type = RESOLV_RESULT_GLOBAL;

	__clat_dev_up = false;
	__clat_dev_set = false;

	__io_status = G_IO_STATUS_NORMAL;
	g_free(__io_str);
	__io_str = NULL;

	__service_nameservers_set = true;

	__vpn_transport = NULL;

	__ipconfig_address_change_notified = false;

	__test_use_keyfile = false;
	__service_dev_index = SERVICE_DEV_INDEX;
}

#define TEST_PREFIX "/clat/"

/* No default service bug state goes up to failure */
static void clat_plugin_test1()
{
	struct connman_network network = { 0 };
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	/* There is no default service, nothing will get done */
	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_FAILURE;
					state++) {
		service.state = state;
		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	/* No timeouts have been called */
	g_assert_null(__timeouts);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* Service goes to ready state and then becomes default */
static void clat_plugin_test2()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Mobile data goes first to ready, then comes default and comes online during
 * pre conf.
 */
static void clat_plugin_test3()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* This has no effect during pre-conf */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_PRE);
	g_assert_cmpint(__task_run_count, ==, 1);
	g_assert_null(__last_set_contents_write);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Mobile data goes first to ready, then comes default and comes online while
 * running.
 */
static void clat_plugin_test4()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* This has no effect while running */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Mobile data goes first to ready, then comes default and comes online
 * during post-configure.
 */
static void clat_plugin_test5()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* This has no effect during post-configure */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* service goes ready -> not default -> online -> default */
static void clat_plugin_test6()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* service goes ready when set already as default */
static void clat_plugin_test7()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	/* Service is default before becoming ready */
	__def_service = &service;
	n->default_changed(&service);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state < CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	g_assert_cmpint(__task_run_count, ==, 0);

	state = CONNMAN_SERVICE_STATE_READY;
	service.state = state;
	network.connected = true;
	n->service_state_changed(&service, state);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* Service has not nameservers set yet when trying to connect -> retry */
static void clat_plugin_test8()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	DBG("Cellular as default but no nameservers set");
	__service_nameservers_set = false;
	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is not made but there is a timeout task */
	DBG("Redo query");
	g_assert_null(__resolv);
	g_assert_null(__last_set_contents_write);
	g_assert_cmpint(call_all_timeouts_timed(), ==, 1);

	/* Which does not yet trigger a resolv as no nameservers are set */
	DBG("No resolv triggered");
	g_assert_null(__resolv);
	g_assert_null(__last_set_contents_write);
	g_assert_cmpint(pending_timeouts(), ==, 1);
	g_assert_cmpint(__task_run_count, ==, 0);

	/*
	 * After enabling the nameservers the query is made and returing with
	 * a success CLAT starts.
	 */
	DBG("Nameservers set, query will be done");
	__service_nameservers_set = true;
	g_assert_cmpint(call_all_timeouts_timed(), ==, 1);

	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added in addition to query, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts_timed(), ==, 2);
	g_assert(__resolv); /* New is set */
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts_timed(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* Service changes index after each connection */
static void clat_plugin_test9()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;
	int count = 0;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (network.index = SERVICE_DEV_INDEX;
					network.index < SERVICE_DEV_INDEX + 5;
					network.index++, count++) {
		DBG("#%d service network index %d", count, network.index);
		__service_dev_index = network.index;

		for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
			service.state = state;
			if (state == CONNMAN_SERVICE_STATE_READY)
				network.connected = true;

			n->service_state_changed(&service, state);
			g_assert_null(__task);
			g_assert_null(__resolv);
		}

		DBG("setting new index as default");

		__def_service = &service;
		n->default_changed(&service);
		g_assert_cmpint(__task_run_count, ==, count * 3); /* 3 / run */

		/* Query is made -> call with success */
		g_assert(__resolv);
		g_assert_null(__last_set_contents_write);
		call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

		/* This transitions state to pre-configure */
		g_assert_true(check_task_running(TASK_SETUP_PRE, count));

		/* GResolv removal is added, call it */
		g_assert(__timeouts);
		g_assert_cmpint(call_all_timeouts(), ==, 1);
		g_assert_null(__resolv);
		g_assert_null(__dad_callback);

		/* State transition to running */
		DBG("PRE CONFIGURE stops");
		call_task_exit(0);
		g_assert_true(check_task_running(TASK_SETUP_CONF, count));

		/* Callbacks are added, called and then re-added */
		g_assert_cmpint(call_all_timeouts(), ==, 2);

		g_assert(__resolv);
		g_assert(__dad_callback);
		g_assert_true(call_dad_callback());

		/* There should be always 2 callbacks, prefix query and DAD */
		g_assert_cmpint(pending_timeouts(), ==, 2);

		g_assert_cmpint(get_data()->ifindex, ==, network.index);

		/* State transition to post-configure */
		DBG("RUNNING STOPS");
		call_task_exit(0);

		g_assert_true(check_task_running(TASK_SETUP_POST, count));

		/* Timeouts are removed */
		g_assert_cmpint(pending_timeouts(), ==, 0);
		g_assert_null(__resolv);
		g_assert_null(__dad_callback);

		/* Task is ended */
		DBG("POST CONFIGURE stops");
		//call_task_exit(0);
		n->service_state_changed(&service,
					CONNMAN_SERVICE_STATE_DISCONNECT);
		network.connected = false;

		g_assert_false(check_task_running(TASK_SETUP_STOPPED, count));
		g_assert_cmpint(pending_timeouts(), ==, 0);
		g_assert_null(__resolv);
		g_assert_null(__dad_callback);

		__def_service = NULL;
		n->default_changed(NULL);

		g_assert_false(check_task_running(TASK_SETUP_STOPPED, count));
		g_assert_cmpint(pending_timeouts(), ==, 0);
		g_assert_null(__resolv);
		g_assert_null(__dad_callback);

		n->service_state_changed(&service, CONNMAN_SERVICE_STATE_IDLE);

		g_assert_false(check_task_running(TASK_SETUP_STOPPED, count));
		g_assert_cmpint(pending_timeouts(), ==, 0);
		g_assert_null(__resolv);
		g_assert_null(__dad_callback);
	}

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);

	test_reset();
}

// service goes online -> failure when online
static void clat_plugin_test_failure1()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Downgraded to ready, no change */
	state = CONNMAN_SERVICE_STATE_READY;
	service.state = state;
	n->service_state_changed(&service, state);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Goes to failure -> stops throug post-conf */
	DBG("RUNNING STOPS by state FAILURE");
	state = CONNMAN_SERVICE_STATE_FAILURE;
	service.state = state;
	n->service_state_changed(&service, state);

	/* State transition to post-configure */
	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* pre-config shuts down with error */
static void clat_plugin_test_failure2()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* Error in pre-configure */
	DBG("PRE CONFIGURE stops");
	call_task_exit(1);

	/* Goes to cleanup */
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_POST);
	g_assert_cmpint(__task_run_count, ==, 2);
	g_assert_null(__last_set_contents_write);
	g_assert_true(check_task_running(TASK_SETUP_UNKNOWN, 0));

	/* Goes to failure -> stops throug post-conf */
	DBG("RUNNING STOPS by FAILURE");
	call_task_exit(1);

	g_assert_cmpint(__task_run_count, ==, 2);
	g_assert_null(__last_set_contents_write);
	g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* When running state process returns with 1 -> restart case */
static void clat_plugin_test_failure3()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* State transition to post-configure */
	DBG("RUNNING STOPS with SEGFAULT");
	call_task_exit(1);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Task is ended -> does restart*/
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	/* Back to pre-conf */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 1));

	/* pre-conf ends and process starts */
	DBG("PRE CONFIGURE stops (restart)");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 1));

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 1));

	/* Task is ended -> does restart*/
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 1));

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* post conf segfaults */
static void clat_plugin_test_failure4()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Task is ended with segfault */
	DBG("POST CONFIGURE stops");
	call_task_exit(1);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

// resolv returns error (first ok, then ok, then error)
static void clat_plugin_test_failure5()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;
	int i;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* This has no effect during pre-conf */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_PRE);
	g_assert_cmpint(__task_run_count, ==, 1);
	g_assert_null(__last_set_contents_write);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	for (i = 0; i < 10 ; i++) {
		/* No change */
		call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

		g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

		/* Callbacks are added + remove resolv */
		g_assert_cmpint(call_all_timeouts_timed(), ==, 3);

		g_assert(__resolv);
		g_assert(__dad_callback);
		g_assert_true(call_dad_callback());

		/* There should be always 2 callbacks, prefix query and DAD */
		g_assert_cmpint(pending_timeouts(), ==, 2);
	}

	/* Error with resolv, process is stopped */
	DBG("Resolv error NO_ANSWER");
	call_resolv_result(G_RESOLV_RESULT_STATUS_SERVER_FAILURE);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* remove resolv exists */
	g_assert_cmpint(call_all_timeouts(), ==, 1);

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

#define TIMEOUTS_MAX 6

static GResolvResultStatus get_status(GResolvResultStatus status, int to)
{
	if (status == G_RESOLV_RESULT_STATUS_NO_RESPONSE && to < TIMEOUTS_MAX)
		return G_RESOLV_RESULT_STATUS_NO_RESPONSE;

	if (status == G_RESOLV_RESULT_STATUS_NO_ANSWER && to < TIMEOUTS_MAX)
		return G_RESOLV_RESULT_STATUS_NO_ANSWER;

	return ++status;
}

// loop over all resolv returns
static void clat_plugin_test_failure6()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_network network2 = {
			.index = SERVICE_DEV_INDEX + 1,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_ipconfig ipv4config2 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config2 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	struct connman_service service2 = {
			.type = CONNMAN_SERVICE_TYPE_WIFI,
			.state = CONNMAN_SERVICE_STATE_ONLINE,
	};
	enum connman_service_state state;
	GResolvResultStatus status;
	bool expect_resolv = false;
	int timeout_count = 0;
	int gresolv_timeouts = 0;


	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	service2.network = &network2;
	service2.ipconfig_ipv4 = &ipv4config2;
	service2.ipconfig_ipv6 = &ipv6config2;
	network2.ipv6_configured = true;
	assign_ipaddress(&ipv6config2);
	init_ipaddress(&ipv4config2);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state < CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	/*
	 * Do each status individually by first going online, then default,
	 * then report status, then leave as default and go ready as in normal
	 * use.
	 */
	for (status = G_RESOLV_RESULT_STATUS_ERROR;
			status <= G_RESOLV_RESULT_STATUS_NO_ANSWER;
			status = get_status(status, gresolv_timeouts)) {
		DBG("test resolv result status %d", status);

		if (status == G_RESOLV_RESULT_STATUS_NO_RESPONSE + 1) {
			g_assert_cmpint(gresolv_timeouts, ==, TIMEOUTS_MAX);
			gresolv_timeouts = 0;
		}

		/* Nothing done as not being the default */
		service.state = CONNMAN_SERVICE_STATE_ONLINE;
		n->service_state_changed(&service, service.state);

		g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));
		g_assert_cmpint(__task_run_count, ==, 0);

		if (expect_resolv)
			g_assert(__resolv);
		else
			g_assert_null(__resolv);

		g_assert_null(__dad_callback);
		g_assert_cmpint(pending_timeouts(), ==, timeout_count);

		/* Default service and is online */
		__def_service = &service;
		n->default_changed(&service);
		g_assert_cmpint(__task_run_count, ==, 0);

		/* Query is made -> call with error */
		g_assert(__resolv);
		g_assert_null(__last_set_contents_write);
		call_resolv_result(status);

		g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));
		g_assert_cmpint(__task_run_count, ==, 0);

		if (status == G_RESOLV_RESULT_STATUS_NO_RESPONSE ||
				status == G_RESOLV_RESULT_STATUS_NO_ANSWER) {
			gresolv_timeouts++;

			DBG("retry case (timeout) #%d", gresolv_timeouts);

			/* This adds timeouts for retry remove resolv */
			g_assert_cmpint(call_all_timeouts_timed(), ==, 2);
			g_assert(__resolv);
			g_assert_null(__dad_callback);
			g_assert_cmpint(pending_timeouts(), ==, 1);

			g_assert_false(check_task_running(TASK_SETUP_STOPPED,
									0));
			expect_resolv = true;
			timeout_count = 1;
		} else {
			DBG("failure case");

			/* This calls only the remove resolv timeout */
			g_assert_cmpint(call_all_timeouts_timed(), ==, 1);
			g_assert_null(__resolv);
			g_assert_null(__dad_callback);
			g_assert_cmpint(pending_timeouts(), ==, 0);

			g_assert_false(check_task_running(TASK_SETUP_STOPPED,
									0));

			expect_resolv = false;
			timeout_count = 0;

			/* Default service changes and cellular goes to READY */
			__def_service = &service2;
			n->default_changed(&service2);
		}

		g_assert_cmpint(__task_run_count, ==, 0);

		if (expect_resolv)
			g_assert(__resolv); /* Retry in place */
		else
			g_assert_null(__resolv); /* Stopped */

		g_assert_null(__dad_callback);
		g_assert_cmpint(pending_timeouts(), ==, timeout_count);

		/* To next timeout */
		if (expect_resolv)
			continue;

		/* Going back to ready changes nothing as not being default */
		service.state = CONNMAN_SERVICE_STATE_READY;
		n->service_state_changed(&service, service.state);

		g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));
		g_assert_cmpint(__task_run_count, ==, 0);

		g_assert_null(__resolv);
		g_assert_null(__dad_callback);
		g_assert_cmpint(pending_timeouts(), ==, timeout_count);
	}

	/* NO_ANSWER should be repeated as well in initial state */
	g_assert_cmpint(gresolv_timeouts, ==, TIMEOUTS_MAX);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv6config2.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);
	connman_ipaddress_free(ipv4config2.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Resolv returns timeout during initial query, then ok and then loops 7 times
 * with timeout resulting in error
 */
static void clat_plugin_test_failure7(gconstpointer data)
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;
	GResolvResultStatus status = GPOINTER_TO_INT(data);
	int i;

	DBG("status %d", status);

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with no response = timeout */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_NO_RESPONSE);

	/* This transitions state to pre-configure */
	g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));

	/* GResolv removal and prefix query is restarted are added*/
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 2);
	g_assert(__resolv);
	g_assert_null(__dad_callback);

	/* Second resolv is a success */
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* This has no effect during pre-conf */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_PRE);
	g_assert_cmpint(__task_run_count, ==, 1);
	g_assert_null(__last_set_contents_write);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added + remove resolv */
	g_assert_cmpint(call_all_timeouts_timed(), ==, 3);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* 6 timeouts is ok */
	for (i = 0; i < TIMEOUTS_MAX ; i++) {
		DBG("timeout %d", i);

		/* Timeout that adds new query with shorter interval */
		call_resolv_result(status);

		/* Does not yet go off */ 
		g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

		/* Callbacks are added + remove resolv */
		g_assert_cmpint(call_all_timeouts_timed(), ==, 3);

		g_assert(__resolv);
		g_assert(__dad_callback);
		g_assert_true(call_dad_callback());

		/* There should be always 2 callbacks, prefix query and DAD */
		g_assert_cmpint(pending_timeouts(), ==, 2);
	}

	/* TIMEOUTS_MAX + 1 makes process to stop */
	DBG("Resolv error %d", status);
	call_resolv_result(status);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* remove resolv exists */
	g_assert_cmpint(call_all_timeouts(), ==, 1);

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Resolv returns timeout during initial query, then ok and then loops 4 times
 * with timeout resulting in error
 */
static void clat_plugin_test_failure8(gconstpointer data)
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;
	GResolvResultStatus status = GPOINTER_TO_INT(data);
	int i;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with no response = timeout */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_NO_RESPONSE);

	/* This transitions state to pre-configure */
	g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));

	/* GResolv removal and prefix query is restarted are added*/
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 2);
	g_assert(__resolv);
	g_assert_null(__dad_callback);

	/* Second resolv is a success */
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* This has no effect during pre-conf */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_PRE);
	g_assert_cmpint(__task_run_count, ==, 1);
	g_assert_null(__last_set_contents_write);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added + remove resolv */
	g_assert_cmpint(call_all_timeouts_timed(), ==, 3);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* 4 timeouts/errors */
	for (i = 0; i < 4 ; i++) {
		DBG("timeout %d", i);

		/* Timeout/error that adds new query with shorter interval */
		call_resolv_result(status);

		/* Does not yet go off */ 
		g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

		/* Callbacks are added + remove resolv */
		g_assert_cmpint(call_all_timeouts_timed(), ==, 3);

		g_assert(__resolv);
		g_assert(__dad_callback);
		g_assert_true(call_dad_callback());

		/* There should be always 2 callbacks, prefix query and DAD */
		g_assert_cmpint(pending_timeouts(), ==, 2);
	}

	/* And continue as normal */
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added + remove resolv */
	g_assert_cmpint(call_all_timeouts_timed(), ==, 3);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* resolv returns different prefix_len -> restart case */
static void clat_plugin_test_restart1()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure as a result of changed prefix */
	DBG("RUNNING STOPS different prefix");
	__resolv_result_type = RESOLV_RESULT_ONE_64;
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Resolv query is the one that remains */
	g_assert(__resolv);
	g_assert_cmpint(pending_timeouts(), ==, 1);
	g_assert_null(__dad_callback);

	/* Task is ended -> does restart*/
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	/* Back to pre-conf */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 1));

	/* resolv is re-added, call it */
	g_assert(__resolv);
	g_assert_cmpint(pending_timeouts(), ==, 1);
	g_assert_null(__dad_callback);

	/* pre-conf ends and process starts */
	DBG("PRE CONFIGURE stops (restart)");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 1));

	/* Callbacks are added, called and then re-added, the callback for
	 * resolv also exists */
	g_assert_cmpint(call_all_timeouts(), ==, 3);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(call_all_timeouts(), ==, 2);
	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* When called they re-add themselves */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS (after restart)");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 1));

	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops (after restart)");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 1));

	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* stdout/err have newline tailing */
static const char *tayga_errors[] = {
	"received error when reading from tun device: File descriptor in bad state\n",
	"Unable to attach tun device clat, aborting: Device or resource busy\n",
	"Unable to attach tun device clat, aborting: Invalid argument\n",
	NULL
};

/* CLAT device is removed -> restart case */
static void clat_plugin_test_restart2()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure as a result of changed prefix */
	DBG("RUNNING STOPS clat device lost");
	call_g_io_stderr(G_IO_IN, tayga_errors[0]);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* No resolv query is done, this restart is mainly tayga reload */
	g_assert_null(__resolv);
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__dad_callback);

	/* Task is ended -> does restart*/
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	/* Back to pre-conf */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 1));

	/* resolv is not re-added */
	g_assert_null(__resolv);
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__dad_callback);

	/* pre-conf ends and process starts */
	DBG("PRE CONFIGURE stops (restart)");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 1));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(call_all_timeouts(), ==, 2);
	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* When called they re-add themselves */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 1));

	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 1));

	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

// test different prefixes
static void clat_plugin_test_prefix(gconstpointer data)
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	__resolv_result_type = GPOINTER_TO_INT(data);

	DBG("resolv type %d", __resolv_result_type);

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* TODO check correct prefix from config */

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_set_prefix());

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* This has no effect while running */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Each service type, except cellular goes through all states, in online state
 * service pops as a default service.
 */
static void clat_plugin_test_service1()
{
	struct connman_network network = { 0 };
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_UNKNOWN,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};

	DBG("");

	service.network = &network;

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	__def_service = NULL;
	n->default_changed(NULL);

	for (service.type = CONNMAN_SERVICE_TYPE_UNKNOWN;
				service.type < MAX_CONNMAN_SERVICE_TYPES;
				service.type++)
	{
		/* Ignore cellular in this test */
		if (service.type == CONNMAN_SERVICE_TYPE_CELLULAR)
			continue;

		/* There is no default service, nothing will get done */
		for (service.state = CONNMAN_SERVICE_STATE_UNKNOWN;
				service.state <= CONNMAN_SERVICE_STATE_FAILURE;
				service.state++) {

			/* Set default service to NULL after online change */
			if (service.state ==
					(CONNMAN_SERVICE_STATE_ONLINE + 1)) {
				__def_service = NULL;
				n->default_changed(NULL);
			}

			if (service.state == CONNMAN_SERVICE_STATE_READY)
				network.connected = true;

			n->service_state_changed(&service, service.state);

			g_assert_null(__task);
			g_assert_null(__resolv);

			/* No timeouts have been called */
			g_assert_null(__timeouts);
			g_assert_null(__dad_callback);

			/* Try default with online state sarvice */
			if (service.state == CONNMAN_SERVICE_STATE_ONLINE) {
				__def_service = &service;
				n->default_changed(&service);

				g_assert_null(__task);
				g_assert_null(__resolv);

				/* No timeouts have been called */
				g_assert_null(__timeouts);
				g_assert_null(__dad_callback);
			}
		}
	}

	__connman_builtin_clat.exit();

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Mobile data goes first to ready, then comes default and comes online while
 * running. Then another service becomes online and default -> mobile data
 * goes to ready.
 */
static void clat_plugin_test_service2()
{
	struct connman_network network1 = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_network network2 = {
			.index = SERVICE_DEV_INDEX + 1,
	};
	struct connman_ipconfig ipv4config1 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config1 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_ipconfig ipv4config2 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config2 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service1 = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	/* In service_sort() WIFI > CELLULAR */
	struct connman_service service2 = {
			.type = CONNMAN_SERVICE_TYPE_WIFI,
			.state = CONNMAN_SERVICE_STATE_ONLINE,
	};
	enum connman_service_state state;

	DBG("");

	service1.network = &network1;
	service1.ipconfig_ipv4 = &ipv4config1;
	service1.ipconfig_ipv6 = &ipv6config1;
	network1.ipv6_configured = true;
	assign_ipaddress(&ipv6config1);
	init_ipaddress(&ipv4config1);

	service2.network = &network2;
	service2.ipconfig_ipv4 = &ipv4config2;
	service2.ipconfig_ipv6 = &ipv6config2;
	network2.ipv6_configured = true;
	assign_ipaddress(&ipv6config2);
	init_ipaddress(&ipv4config2);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service1.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network1.connected = true;

		n->service_state_changed(&service1, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service1;
	n->default_changed(&service1);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);
	g_assert_cmpint(__task_run_count, ==, 1);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);
	g_assert_cmpint(__task_run_count, ==, 2);

	/* This has no effect while running */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service1.state = state;
	n->service_state_changed(&service1, state);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);
	g_assert_cmpint(__task_run_count, ==, 2);

	/* Another service befomes default */
	__def_service = &service2;
	n->default_changed(&service2);

	/* CLAT stops, state transition to post-configure */
	DBG("RUNNING STOPS");
	g_assert_true(check_task_running(TASK_SETUP_POST, 0));
	g_assert_cmpint(__task_run_count, ==, 3);

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Cellular is downgraded to ready -> no change */
	service1.state = CONNMAN_SERVICE_STATE_READY;
	n->service_state_changed(&service1, state);

	/* No timeouts are added */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(__task_run_count, ==, 3);
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config1.ipaddress);
	connman_ipaddress_free(ipv4config1.ipaddress);
	connman_ipaddress_free(ipv6config2.ipaddress);
	connman_ipaddress_free(ipv4config2.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Another service is default and then mobile data goes to ready, then comes
 * default and comes online while running. Then another service becomes default
 * -> mobile data goes to ready.
 */
static void clat_plugin_test_service3()
{
	struct connman_network network1 = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_network network2 = {
			.index = SERVICE_DEV_INDEX + 1,
	};
	struct connman_ipconfig ipv4config1 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config1 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_ipconfig ipv4config2 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config2 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service1 = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	/* In service_sort() WIFI > CELLULAR */
	struct connman_service service2 = {
			.type = CONNMAN_SERVICE_TYPE_WIFI,
			.state = CONNMAN_SERVICE_STATE_ONLINE,
	};
	enum connman_service_state state;

	DBG("");

	service1.network = &network1;
	service1.ipconfig_ipv4 = &ipv4config1;
	service1.ipconfig_ipv6 = &ipv6config1;
	network1.ipv6_configured = true;
	assign_ipaddress(&ipv6config1);
	init_ipaddress(&ipv4config1);

	service2.network = &network2;
	service2.ipconfig_ipv4 = &ipv4config2;
	service2.ipconfig_ipv6 = &ipv6config2;
	network2.ipv6_configured = true;
	assign_ipaddress(&ipv6config2);
	init_ipaddress(&ipv4config2);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service1.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network1.connected = true;

		n->service_state_changed(&service1, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service2;
	n->default_changed(&service2);

	/* Nothing is done */
	g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_cmpint(__task_run_count, ==, 0);
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* This has no effect while not being default yet */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service1.state = state;
	n->service_state_changed(&service1, state);

	/* Nothing is still done */
	g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_cmpint(__task_run_count, ==, 0);
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Cellular service befomes default */
	__def_service = &service1;
	n->default_changed(&service1);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);
	g_assert_cmpint(__task_run_count, ==, 1);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);
	g_assert_cmpint(__task_run_count, ==, 2);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);
	g_assert_cmpint(__task_run_count, ==, 2);

	/* Another service befomes default again */
	__def_service = &service2;
	n->default_changed(&service2);

	/* CLAT stops, state transition to post-configure */
	DBG("RUNNING STOPS");
	g_assert_true(check_task_running(TASK_SETUP_POST, 0));
	g_assert_cmpint(__task_run_count, ==, 3);

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Cellular is downgraded to ready -> no change */
	service1.state = CONNMAN_SERVICE_STATE_READY;
	n->service_state_changed(&service1, state);

	/* No timeouts are added */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(__task_run_count, ==, 3);
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config1.ipaddress);
	connman_ipaddress_free(ipv4config1.ipaddress);
	connman_ipaddress_free(ipv6config2.ipaddress);
	connman_ipaddress_free(ipv4config2.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* Stop with null service as default */
/*
 * Mobile data goes first to ready, then comes default and comes online while
 * running. Then another service becomes online and default -> mobile data
 * goes to ready.
 */
static void clat_plugin_test_service4()
{
	struct connman_network network1 = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config1 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config1 = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service1 = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	struct connman_service service2 = {
			.type = CONNMAN_SERVICE_TYPE_WIFI,
			.state = CONNMAN_SERVICE_STATE_ONLINE,
	};

	enum connman_service_state state;

	DBG("");

	service1.network = &network1;
	service1.ipconfig_ipv4 = &ipv4config1;
	service1.ipconfig_ipv6 = &ipv6config1;
	network1.ipv6_configured = true;
	assign_ipaddress(&ipv6config1);
	init_ipaddress(&ipv4config1);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service1.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network1.connected = true;

		n->service_state_changed(&service1, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service1;
	n->default_changed(&service1);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);
	g_assert_cmpint(__task_run_count, ==, 1);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);
	g_assert_cmpint(__task_run_count, ==, 2);

	/* This has no effect while running */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service1.state = state;
	n->service_state_changed(&service1, state);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);
	g_assert_cmpint(__task_run_count, ==, 2);

	/*
	 * NULL service befomes default but the tracked service is online
	 * so no effect.
	 */
	__def_service = NULL;
	n->default_changed(NULL);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);
	g_assert_cmpint(__task_run_count, ==, 2);

	/* When service changes to another CLAT does stop */
	__def_service = &service2;
	n->default_changed(&service2);

	/* CLAT stops, state transition to post-configure */
	DBG("RUNNING STOPS");
	g_assert_true(check_task_running(TASK_SETUP_POST, 0));
	g_assert_cmpint(__task_run_count, ==, 3);

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Cellular is downgraded to ready -> no change */
	service1.state = CONNMAN_SERVICE_STATE_READY;
	n->service_state_changed(&service1, state);

	/* No timeouts are added */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(__task_run_count, ==, 3);
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config1.ipaddress);
	connman_ipaddress_free(ipv4config1.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* Clat device error during pre-configure */
static void clat_plugin_test_if_error1(gconstpointer data)
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;
	unsigned int index = GPOINTER_TO_UINT(data);

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	/* Service is default before becoming ready */
	__def_service = &service;
	n->default_changed(&service);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state < CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	g_assert_cmpint(__task_run_count, ==, 0);

	state = CONNMAN_SERVICE_STATE_READY;
	service.state = state;
	network.connected = true;
	n->service_state_changed(&service, state);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);
	g_assert_cmpint(__task_run_count, ==, 1);

	/* Pre-configure reports error */
	DBG("PRE CONFIGURE io error: \"%s\"", tayga_errors[index]);

	g_assert_cmpint(__task_run_count, ==, 1);

	/* Call with tayga error */
	call_g_io_stderr(G_IO_IN, tayga_errors[index]);

	g_assert_false(__clat_dev_set);
	g_assert_false(__clat_dev_up);

	/* Back to pre-conf without callbacks */
	g_assert_true(check_task_running_added_rounds(TASK_SETUP_PRE, 1));
	g_assert_cmpint(call_all_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running_added_rounds(TASK_SETUP_CONF, 1));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running_added_rounds(TASK_SETUP_POST, 1));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running_added_rounds(TASK_SETUP_STOPPED, 1));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

static void clat_plugin_test_if_error2(gconstpointer data)
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_OFF,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;
	unsigned int index = GPOINTER_TO_UINT(data);

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended by device error */
	DBG("POST CONFIGURE to error %s", tayga_errors[index]);

	/*
	 * Normally the device would be up and the --rmtun wasn't executed.
	 * But the test check_task_running() with TASK_SETUP_POST sets the
	 * __clat_dev_set to false then undo it for the sake of testing here.
	 */
	__clat_dev_set = true;

	call_g_io_stderr(G_IO_IN, tayga_errors[index]);

	g_assert_false(__clat_dev_set);
	g_assert_false(__clat_dev_up);

	/*
	 * In post config case the removal is done prior / at the same time
	 * the process dies.
	 */
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* Different service reports something -> nothing done */
static void clat_plugin_test_ipconfig1()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_network network_wifi = {
			.index = SERVICE_DEV_INDEX + 1,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_OFF,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_ipconfig ipv6config_wifi = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_ipconfig ipv4config_wifi = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	struct connman_service service_wifi = {
			.type = CONNMAN_SERVICE_TYPE_WIFI,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	struct connman_ipconfig *wifi_confs[] = {
						NULL,
						&ipv4config_wifi,
						&ipv6config_wifi
	};
	enum connman_service_state state;
	int i;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	service.ipconfig_ipv6->index = service.network->index;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	service_wifi.network = &network_wifi;
	service_wifi.ipconfig_ipv4 = &ipv4config_wifi;
	service_wifi.ipconfig_ipv4->index = service_wifi.network->index;
	service_wifi.ipconfig_ipv6 = &ipv6config_wifi;
	service_wifi.ipconfig_ipv6->index = service_wifi.network->index;
	network_wifi.ipv6_configured = true;
	network_wifi.ipv4_configured = true;
	assign_ipaddress(&ipv4config_wifi);
	assign_ipaddress(&ipv6config_wifi);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(call_all_timeouts_timed(), ==, 2);
	g_assert_cmpint(__task_run_count, ==, 2);

	/* Ignored: null ipconf, different service */
	for (i = 0; i < 3; i++) {
		DBG("wifi conf id %d", i);

		n->ipconfig_changed(&service_wifi, wifi_confs[i]);

		g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
		g_assert(__resolv);
		g_assert(__dad_callback);

		/* Simulate time */
		g_assert_true(call_dad_callback());
		g_assert_cmpint(call_all_timeouts_timed(), ==, 2);
		g_assert_cmpint(__task_run_count, ==, 2);
	}

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);
	connman_ipaddress_free(ipv4config_wifi.ipaddress);
	connman_ipaddress_free(ipv6config_wifi.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* Cellular is not default or network is not connected */

/* Running: IPv4 address is added and clat stops */
/* Running: IPv6 address is removed and clat stops */
static void clat_plugin_test_ipconfig_type(gconstpointer data)
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_OFF,
	};
	struct connman_ipconfig ipv6config = { 
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;
	int type = GPOINTER_TO_INT(data);

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	service.ipconfig_ipv6->index = service.network->index;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(call_all_timeouts_timed(), ==, 2);
	g_assert_cmpint(__task_run_count, ==, 2);

	/* State transition to post-configure because of ipconfig change */
	DBG("RUNNING STOPS, ipconfig changed");

	/* Setup ipconfig */
	if (type == AF_INET) {
		/* IPv4 address is present -> stop */
		service.ipconfig_ipv4->index = service.network->index;
		assign_ipaddress(&ipv4config);
		n->ipconfig_changed(&service, &ipv4config);
	} else if (type == AF_INET6) {
		/* IPv6 address is lost -> stop */
		connman_ipaddress_clear(ipv6config.ipaddress);
		n->ipconfig_changed(&service, &ipv6config);
	}

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv4config.ipaddress);
	connman_ipaddress_free(ipv6config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Mobile data goes first to ready, then comes default and comes online during
 * pre conf. When running tethering is enabled.
 */
static void clat_plugin_test_tether1()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_OFF,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* This has no effect during pre-conf */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_PRE);
	g_assert_cmpint(__task_run_count, ==, 1);
	g_assert_null(__last_set_contents_write);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* No service changes but tethering is enabled -> dual nat is set */
	n->tethering_changed(NULL, true);
	g_assert(__dual_nat);

	/* Tethering goes off, so does dual nat */
	n->tethering_changed(NULL, false);
	g_assert_null(__dual_nat);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * Tethering is enabled before CLAT is running.
 */
static void clat_plugin_test_tether2()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_OFF,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	n->tethering_changed(NULL, true);
	g_assert_null(__dual_nat);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* No dual nat yet */
	g_assert_null(__dual_nat);

	/* This has no effect during pre-conf */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_PRE);
	g_assert_cmpint(__task_run_count, ==, 1);
	g_assert_null(__last_set_contents_write);

	/* No dual nat yet */
	g_assert_null(__dual_nat);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* Tethering was enabled -> dual nat is set */
	g_assert(__dual_nat);

	/* Tethering goes off, so does dual nat */
	n->tethering_changed(NULL, false);
	g_assert_null(__dual_nat);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/*
 * CLAT stops before tethering is disabled -> dual nat is removed
 */
static void clat_plugin_test_tether3()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_OFF,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	n->tethering_changed(NULL, true);
	g_assert_null(__dual_nat);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* No dual nat yet */
	g_assert_null(__dual_nat);

	/* This has no effect during pre-conf */
	state = CONNMAN_SERVICE_STATE_ONLINE;
	service.state = state;
	n->service_state_changed(&service, state);

	g_assert_true(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_PRE);
	g_assert_cmpint(__task_run_count, ==, 1);
	g_assert_null(__last_set_contents_write);

	/* No dual nat yet */
	g_assert_null(__dual_nat);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* Tethering was enabled -> dual nat is set */
	g_assert(__dual_nat);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);
	g_assert_null(__dual_nat);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);
	g_assert_null(__dual_nat);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

static void set_vpn_mode(bool enable)
{
	__vpn_mode = enable;
}

enum vpn_test_tether {
	VPN_TEST_TETHER_OFF = 0,
	VPN_TEST_TETHER_PRE,
	VPN_TEST_TETHER_ON
};

/*
 * CLAT running and IPv4 VPN goes on in CLAT running state  First CLAT
 * goes online, then it goes ready and default service is changed to VPN. VPN
 * does get to be set as default route and CLAT drops default route. This can
 * be parametrized to have pre-VPN or during VPN tethering tested.
 */
void clat_plugin_test_vpn1(gconstpointer data)
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_OFF,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_ipconfig vpn_ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
			.index = SERVICE_DEV_INDEX_VPN,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
			.identifier = "cellular123",
	};
	struct connman_service vpn_service = {
			.type = CONNMAN_SERVICE_TYPE_VPN,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;
	enum vpn_test_tether test_tether = GPOINTER_TO_UINT(data);

	DBG("");

	service.network = &network;
	network.ipv6_configured = true;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	service.ipconfig_ipv6->index = service.network->index;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	vpn_service.ipconfig_ipv4 = &vpn_ipv4config;
	assign_ipaddress(&vpn_ipv4config);

	__vpn_transport = &service;

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	call_rntl_new_gateway("feed::dead:beef:baaa:aaac");

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* Tethering is enabled before VPN is connected */
	if (test_tether == VPN_TEST_TETHER_PRE) {
		n->tethering_changed(NULL, true);
		g_assert(__dual_nat);
	}

	/* VPN goes on by first dropping cellular to READY */
	service.state = CONNMAN_SERVICE_STATE_READY;
	n->service_state_changed(&service, CONNMAN_SERVICE_STATE_READY);

	/* Nothing is done */
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
	g_assert(__resolv);
	g_assert_null(__dad_callback); /* Timeout is not called yet */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* VPN goes to state transition */
	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		vpn_service.state = state;
		n->service_state_changed(&vpn_service, state);

		/* Nothing is done */
		g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
		g_assert(__resolv);
		g_assert_null(__dad_callback); /* Timeout is not called yet */
		g_assert_cmpint(pending_timeouts(), ==, 2);
	}

	/* Notify VPN IPv4 ipconf */
	if (state == CONNMAN_SERVICE_STATE_READY) {
		n->ipconfig_changed(&vpn_service,
					vpn_service.ipconfig_ipv4);
		
		/* Nothing is done */
		g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
		g_assert(__resolv);
		g_assert_null(__dad_callback); /* Timeout is not called yet */
		g_assert_cmpint(pending_timeouts(), ==, 2);
	}

	/* Next VPN is set as default and CLAT drops default route */
	set_vpn_mode(true);
	__def_service = &vpn_service;
	n->default_changed(&vpn_service);

	/* We keep on running without default route and resolv */
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
	g_assert_null(__resolv);
	g_assert_null(__dad_callback); /* Timeout is not called yet */
	g_assert_cmpint(pending_timeouts(), ==, 1); /* Only dad */

	/* If tethering is enabled -> dual nat will not get set with IPv4 VPN */
	if (test_tether == VPN_TEST_TETHER_ON)
		n->tethering_changed(NULL, true);

	/* Tethering was enabled before or after VPN -> dual nat is dropped */
	if (test_tether != VPN_TEST_TETHER_OFF)
		g_assert_null(__dual_nat);

	/* CLAT becomes online - nothing is done yet */
	service.state = CONNMAN_SERVICE_STATE_ONLINE;
	n->service_state_changed(&service, CONNMAN_SERVICE_STATE_ONLINE);
	
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
	g_assert_null(__resolv);
	g_assert_null(__dad_callback); /* Timeout is not called yet */
	g_assert_cmpint(pending_timeouts(), ==, 1); /* Only dad to is added */

	/* And then VPN disconnects and mobile data is the default */
	vpn_service.state = CONNMAN_SERVICE_STATE_DISCONNECT;
	n->service_state_changed(&vpn_service, vpn_service.state);

	/* Nothing is done yet */
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
	g_assert_null(__resolv);
	g_assert_null(__dad_callback); /* Timeout is not called yet */
	g_assert_cmpint(pending_timeouts(), ==, 1); /* Only dad to is added */

	/* Until the default is changed.. */
	set_vpn_mode(false);
	__def_service = &service;
	n->default_changed(&service);

	/* First the resolv is not initiated but is added ...*/
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
	g_assert_null(__resolv);	/* Resolv is not executed */
	g_assert_null(__dad_callback);	/* Timeout is not called yet */

	/* ... and can be called after which ...*/
	g_assert_cmpint(call_all_timeouts_timed(), ==, 2);

	/* .. the resolv and dad callback exist */
	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback()); /* Sets __dad_callback to NULL */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/*
	 * Tethering is dropped after VPN disconnects. Nat restarts itself
	 * when the default interface changes so it cannot nor should not be
	 * tested here.
	 */
	if (test_tether != VPN_TEST_TETHER_OFF) {
		n->tethering_changed(NULL, false);
		g_assert_null(__dual_nat);
	}

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);
	connman_ipaddress_free(vpn_ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* IPv6 VPN does cause CLAT to stop and start again when it disconnects */
void clat_plugin_test_vpn2()
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_OFF,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_ipconfig vpn_ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
			.index = SERVICE_DEV_INDEX_VPN,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
			.identifier = "cellular123",
	};
	struct connman_service vpn_service = {
			.type = CONNMAN_SERVICE_TYPE_VPN,
			.state = CONNMAN_SERVICE_STATE_READY,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv4 = &ipv4config;
	service.ipconfig_ipv6 = &ipv6config;
	network.ipv6_configured = true;
	assign_ipaddress(&ipv6config);
	init_ipaddress(&ipv4config);

	vpn_service.ipconfig_ipv6 = &vpn_ipv6config;
	assign_ipaddress(&vpn_ipv6config);

	__vpn_transport = &service;

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 0));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));

	call_rntl_new_gateway("feed::dead:beef:baaa:aaac");

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* VPN goes on by first dropping cellular to READY */
	service.state = CONNMAN_SERVICE_STATE_READY;
	n->service_state_changed(&service, CONNMAN_SERVICE_STATE_READY);

	/* Nothing is done */
	g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
	g_assert(__resolv);
	g_assert_null(__dad_callback); /* Timeout is not called yet */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* VPN goes to state transition */
	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		vpn_service.state = state;

		n->service_state_changed(&vpn_service, state);

		/* Nothing is done */
		g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
		g_assert(__resolv);
		g_assert_null(__dad_callback); /* Timeout is not called yet */
		g_assert_cmpint(pending_timeouts(), ==, 2);
	}

	/* Notify VPN IPv6 ipconf */
	if (state == CONNMAN_SERVICE_STATE_READY) {
		n->ipconfig_changed(&vpn_service,
					vpn_service.ipconfig_ipv6);
		
		/* Nothing is done */
		g_assert_true(check_task_running(TASK_SETUP_CONF, 0));
		g_assert(__resolv);
		g_assert_null(__dad_callback); /* Timeout is not called yet */
		g_assert_cmpint(pending_timeouts(), ==, 2);
	}

	/* Next IPv6 VPN is set as default and CLAT stops */
	__def_service = &vpn_service;
	n->default_changed(&vpn_service);

	/* State transition to post-configure */
	DBG("CLAT STOPS");
	g_assert_true(check_task_running(TASK_SETUP_POST, 0));

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);

	/* CLAT becomes online - nothing is done yet */
	service.state = CONNMAN_SERVICE_STATE_ONLINE;
	n->service_state_changed(&service, CONNMAN_SERVICE_STATE_ONLINE);

	g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_null(__resolv);
	g_assert_cmpint(pending_timeouts(), ==, 0);

	/* And then VPN disconnects and mobile data is the default */
	vpn_service.state = CONNMAN_SERVICE_STATE_DISCONNECT;
	n->service_state_changed(&vpn_service, vpn_service.state);

	/* Nothing is done */
	g_assert_false(check_task_running(TASK_SETUP_UNKNOWN, 0));
	g_assert_null(__resolv);
	g_assert_cmpint(pending_timeouts(), ==, 0);

	/* Until cellular is default again */
	__def_service = &service;
	n->default_changed(&service);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_set_contents_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running(TASK_SETUP_PRE, 1));

	/* GResolv removal is added, call it */
	g_assert(__timeouts);
	g_assert_cmpint(call_all_timeouts(), ==, 1);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);
	g_assert_true(check_task_running(TASK_SETUP_CONF, 1));

	/* Callbacks are added, called and then re-added */
	g_assert_cmpint(call_all_timeouts(), ==, 2);

	g_assert(__resolv);
	g_assert(__dad_callback);
	g_assert_true(call_dad_callback());

	/* There should be always 2 callbacks, prefix query and DAD */
	g_assert_cmpint(pending_timeouts(), ==, 2);

	/* State transition to post-configure by disconnect */
	DBG("RUNNING STOPS");
	service.state = CONNMAN_SERVICE_STATE_DISCONNECT;
	n->service_state_changed(&service, service.state);

	/* Timeouts are removed */
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	g_assert_true(check_task_running(TASK_SETUP_POST, 1));

	/* Setting default to NULL has no effect */
	__def_service = NULL;
	n->default_changed(NULL);

	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	g_assert_true(check_task_running(TASK_SETUP_POST, 1));

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 1));
	g_assert_cmpint(pending_timeouts(), ==, 0);
	g_assert_null(__resolv);
	g_assert_null(__dad_callback);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);
	connman_ipaddress_free(vpn_ipv6config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

/* CLAT is not started when VPN is enabled over any service with IPv4 */
void clat_plugin_test_vpn_type(gconstpointer data)
{
	struct connman_network network = {
			.index = SERVICE_DEV_INDEX,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_ipconfig ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
	};
	struct connman_ipconfig vpn_ipv4config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV4,
			.method = CONNMAN_IPCONFIG_METHOD_DHCP,
			.index = SERVICE_DEV_INDEX_VPN,
	};
	struct connman_service service = {
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	struct connman_service vpn_service = {
			.type = CONNMAN_SERVICE_TYPE_VPN,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.type = GPOINTER_TO_INT(data);
	service.network = &network;
	service.ipconfig_ipv6 = &ipv6config;
	service.ipconfig_ipv4 = &ipv4config;
	network.ipv6_configured = true;
	network.ipv4_configured = true;
	assign_ipaddress(&ipv6config);
	assign_ipaddress(&ipv4config);

	vpn_service.ipconfig_ipv4 = &vpn_ipv4config;
	assign_ipaddress(&vpn_ipv4config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_ONLINE;
					state++) {
		service.state = state;
		if (state == CONNMAN_SERVICE_STATE_READY)
			network.connected = true;

		n->service_state_changed(&service, state);
		g_assert_null(__task);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);
	g_assert_cmpint(__task_run_count, ==, 0);

	/* Query is not made*/
	g_assert_null(__resolv);
	g_assert_null(__last_set_contents_write);
	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_null(__timeouts);
	g_assert_cmpint(pending_timeouts(), == , 0);

	/* VPN goes on by first dropping cellular to READY */
	service.state = CONNMAN_SERVICE_STATE_READY;
	n->service_state_changed(&service, CONNMAN_SERVICE_STATE_READY);

	/* Nothing is done */
	g_assert_null(__resolv);
	g_assert_null(__last_set_contents_write);
	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_null(__timeouts);
	g_assert_cmpint(pending_timeouts(), == , 0);

	/* VPN goes to state transition */
	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		vpn_service.state = state;
		n->service_state_changed(&vpn_service, state);

		/* Nothing is done */
		g_assert_null(__resolv);
		g_assert_null(__last_set_contents_write);
		g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
		g_assert_null(__timeouts);
		g_assert_cmpint(pending_timeouts(), == , 0);
	}

	/* Notify VPN IPv4 ipconf */
	if (state == CONNMAN_SERVICE_STATE_READY) {
		n->ipconfig_changed(&vpn_service,
					vpn_service.ipconfig_ipv4);
		
		/* Nothing is done */
		g_assert_null(__resolv);
		g_assert_null(__last_set_contents_write);
		g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
		g_assert_null(__timeouts);
		g_assert_cmpint(pending_timeouts(), == , 0);
	}

	/* Next VPN is set as default and CLAT drops default route */
	set_vpn_mode(true);
	__def_service = &vpn_service;
	n->default_changed(&vpn_service);

	g_assert_null(__resolv);
	g_assert_null(__last_set_contents_write);
	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_null(__timeouts);
	g_assert_cmpint(pending_timeouts(), == , 0);

	/* Mobile data becomes online */
	service.state = CONNMAN_SERVICE_STATE_ONLINE;
	n->service_state_changed(&service, CONNMAN_SERVICE_STATE_ONLINE);

	g_assert_null(__resolv);
	g_assert_null(__last_set_contents_write);
	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_null(__timeouts);
	g_assert_cmpint(pending_timeouts(), == , 0);

	/* And then VPN disconnects and mobile data is the default */
	vpn_service.state = CONNMAN_SERVICE_STATE_DISCONNECT;
	n->service_state_changed(&vpn_service, vpn_service.state);

	/* Nothing is done */
	g_assert_null(__resolv);
	g_assert_null(__last_set_contents_write);
	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_null(__timeouts);
	g_assert_cmpint(pending_timeouts(), == , 0);

	/* Even when the default is changed.. */
	set_vpn_mode(false);
	__def_service = &service;
	n->default_changed(&service);

	g_assert_null(__resolv);
	g_assert_null(__last_set_contents_write);
	g_assert_false(check_task_running(TASK_SETUP_STOPPED, 0));
	g_assert_null(__timeouts);
	g_assert_cmpint(pending_timeouts(), == , 0);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);
	connman_ipaddress_free(ipv4config.ipaddress);
	connman_ipaddress_free(vpn_ipv4config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
	test_reset();
}

struct ipv6_test_address {
	const char *addr;
	const char *rslt;
	unsigned char prefixlen;
};

static void clat_unit_test_derive1()
{
	const struct ipv6_test_address test_addrs[] =
	{
		{
			"a:b:c:d:1:2:3:4",
			"a:b:c",
			48,
		},
		{
			"aa:bb:cc:dd:1:2:3:4",
			"aa:bb:cc",
			48,
		},
		{
			"aaa:bbb:ccc:ddd:1:2:3:4",
			"aaa:bbb:ccc",
			48,
		},
		{
			"aaaa:bbbb:cccc:dddd:1:2:3:4",
			"aaaa:bbbb:cccc",
			48,
		},
		{
			"a:b:c:d:1:2:3:4",
			"a:b:c:d",
			64,
		},
		{
			"aa:bb:cc:dd:1:2:3:4",
			"aa:bb:cc:dd",
			64,
		},
		{
			"aaa:bbb:ccc:ddd:1:2:3:4",
			"aaa:bbb:ccc:ddd",
			64,
		},
		{
			"aaaa:bbbb:cccc:dddd:1:2:3:4",
			"aaaa:bbbb:cccc:dddd",
			64,
		},
		{
			"a:b:c:d:1:2:3:4",
			"a:b:c:d:1",
			80,
		},
		{
			"aa:bb:cc:dd:1:2:3:4",
			"aa:bb:cc:dd:1",
			80,
		},
		{
			"aaa:bbb:ccc:ddd:1:2:3:4",
			"aaa:bbb:ccc:ddd:1",
			80,
		},
		{
			"aaaa:bbbb:cccc:dddd:1:2:3:4",
			"aaaa:bbbb:cccc:dddd:1",
			80,
		},
		{
			"a:b:c:d:1:2:3:4",
			"a:b:c:d:1:2",
			96,
		},
		{
			"aa:bb:cc:dd:1:2:3:4",
			"aa:bb:cc:dd:1:2",
			96,
		},
		{
			"aaa:bbb:ccc:ddd:1:2:3:4",
			"aaa:bbb:ccc:ddd:1:2",
			96,
		},
		{
			"aaaa:bbbb:cccc:dddd:1:2:3:4",
			"aaaa:bbbb:cccc:dddd:1:2",
			96,
		},
		/* Most likely this kind of addresses are not passed to func */
		{
			"a:b:c:d::666",
			"a:b:c:d",
			64,
		},
		{
			"aa:bb:cc:dd::666",
			"aa:bb:cc:dd",
			64,
		},
		{
			"aaa:bbb:ccc:ddd::666",
			"aaa:bbb:ccc:ddd",
			64,
		},
		{
			"aaaa:bbbb:cccc:dddd::666",
			"aaaa:bbbb:cccc:dddd",
			64,
		},
		{
			NULL,
			NULL,
			0
		},
	};
	struct clat_data *data = clat_data_init();
	int err;
	int i;

	err = derive_ipv6_address(data, NULL, 0);
	g_assert_cmpint(err, ==, -EINVAL);
	g_assert_null(data->address);

	for (i = 0; test_addrs[i].addr; i++) {
		char *result;

		err = derive_ipv6_address(data, test_addrs[i].addr,
						test_addrs[i].prefixlen);
		g_assert_cmpint(err, ==, 0);

		result = g_strconcat(test_addrs[i].rslt, "::",
							CLAT_IPv6_SUFFIX, NULL);
		g_assert_cmpstr(data->address, ==, result);
		DBG("result %s", data->address);
		g_assert_cmpint(data->addr_prefixlen, ==, 128);
		g_free(result);
	}

	clat_data_free(data);
}

static void clat_unit_test_prefix1()
{
	struct prefix_entry *entry;
	const char *addresses_gp[] = { "64:ff9b::1/96",
				"64:ff9b::2/96",
				"64:ff9b::1",
				"64:ff9b::2",
				NULL };
	const char address[] = "abc:dbe:123:456:789:1234:5678:beef";
	const char *addresses_fail[] = { "abc:dbe:123:456:789:1234:5678:beef",
				"abc:dbe:123:456:789:1234:5678:beef/128",
				"abc:dbe:123:456:789:1234:5678:beef/8",
				/* global prefix is defined with :: */
				"64:ff9b:ffff:aaaa:bbbb:cccc:dddd:1234",
				NULL };
	unsigned int i;

	g_assert_null(new_prefix_entry(NULL));

	for (i = 0; addresses_gp[i]; i++) {
		entry = new_prefix_entry(addresses_gp[i]);
		g_assert(entry);

		g_assert_cmpstr(entry->prefix, ==, GLOBAL_PREFIX);
		g_assert(entry->prefixlen == GLOBAL_PREFIXLEN);

		free_prefix_entry(entry);
	}

	for (i = 32; i < 128; i += 16) {
		char *addr = g_strdup_printf("%s/%d", address, i);

		entry = new_prefix_entry(addr);
		g_assert(entry);

		g_assert_cmpstr(entry->prefix, ==, address);
		g_assert(entry->prefixlen == (unsigned char)i);

		free_prefix_entry(entry);
		g_free(addr);
	}

	for (i = 0; addresses_fail[i]; i++)
		g_assert_null(new_prefix_entry(addresses_fail[i]));
}

static void clat_unit_test_prefix2()
{
	struct clat_data *data;
	char **results;

	data = clat_data_init();

	results = g_new0(char*, 3);
	results[0] = g_strdup("64:ff9b::1");
	results[1] = g_strdup("64:ff9b::2");

	g_assert_cmpint(assign_clat_prefix(data, NULL), ==, -ENOENT);

	g_assert_cmpint(assign_clat_prefix(data, results), ==, 0);
	g_assert_cmpint(assign_clat_prefix(data, results), ==, -EALREADY);

	g_strfreev(results);

	/* Changed -> restart */
	results = g_new0(char*, 3);
	results[0] = g_strdup("64:ff9c::1/96");
	results[1] = g_strdup("64:ff9c::2/96");
	g_assert_cmpint(assign_clat_prefix(data, results), ==, -ERESTART);

	g_strfreev(results);

	/* Invalid, fallback to global prefix = restart */
	results = g_new0(char*, 3);
	results[0] = g_strdup("aba:daba:caba::1");
	results[1] = g_strdup("a:b:c:d::2");

	g_assert_cmpint(assign_clat_prefix(data, results), ==, -ERESTART);

	clat_data_free(data);

	/* Cleanup and try with invalid = global prefix */
	data = clat_data_init();
	g_assert_cmpint(assign_clat_prefix(data, results), ==, 0);
	g_strfreev(results);
	clat_data_free(data);
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
		} else
			g_printerr("An unknown error occurred\n");
		return 1;
	}

	g_option_context_free(context);

	__connman_log_init(argv[0], option_debug, false, false,
			"Unit Tests Connection Manager", VERSION);

	g_test_add_func(TEST_PREFIX "test1", clat_plugin_test1);
	g_test_add_func(TEST_PREFIX "test2", clat_plugin_test2);
	g_test_add_func(TEST_PREFIX "test3", clat_plugin_test3);
	g_test_add_func(TEST_PREFIX "test4", clat_plugin_test4);
	g_test_add_func(TEST_PREFIX "test5", clat_plugin_test5);
	g_test_add_func(TEST_PREFIX "test6", clat_plugin_test6);
	g_test_add_func(TEST_PREFIX "test7", clat_plugin_test7);
	g_test_add_func(TEST_PREFIX "test8", clat_plugin_test8);
	g_test_add_func(TEST_PREFIX "test9", clat_plugin_test9);

	g_test_add_func(TEST_PREFIX "test_failure1", clat_plugin_test_failure1);
	g_test_add_func(TEST_PREFIX "test_failure2", clat_plugin_test_failure2);
	g_test_add_func(TEST_PREFIX "test_failure3", clat_plugin_test_failure3);
	g_test_add_func(TEST_PREFIX "test_failure4", clat_plugin_test_failure4);
	g_test_add_func(TEST_PREFIX "test_failure5", clat_plugin_test_failure5);
	g_test_add_func(TEST_PREFIX "test_failure6", clat_plugin_test_failure6);
	g_test_add_data_func(TEST_PREFIX "test_failure7_no_answer",
				GINT_TO_POINTER(
					G_RESOLV_RESULT_STATUS_NO_ANSWER),
				clat_plugin_test_failure7);
	g_test_add_data_func(TEST_PREFIX "test_failure7_no_response",
				GINT_TO_POINTER(
					G_RESOLV_RESULT_STATUS_NO_RESPONSE),
				clat_plugin_test_failure7);
	g_test_add_data_func(TEST_PREFIX "test_failure8_no_answer",
				GINT_TO_POINTER(
					G_RESOLV_RESULT_STATUS_NO_ANSWER),
				clat_plugin_test_failure8);
	g_test_add_data_func(TEST_PREFIX "test_failure8_no_response",
				GINT_TO_POINTER(
					G_RESOLV_RESULT_STATUS_NO_RESPONSE),
				clat_plugin_test_failure8);

	g_test_add_func(TEST_PREFIX "test_restart1", clat_plugin_test_restart1);
	g_test_add_func(TEST_PREFIX "test_restart2", clat_plugin_test_restart2);

	g_test_add_data_func(TEST_PREFIX "test_prefix1",
					GINT_TO_POINTER(RESOLV_RESULT_ONE_64),
					clat_plugin_test_prefix);
	g_test_add_data_func(TEST_PREFIX "test_prefix2",
					GINT_TO_POINTER(RESOLV_RESULT_ONE_96),
					clat_plugin_test_prefix);
	g_test_add_data_func(TEST_PREFIX "test_prefix3",
					GINT_TO_POINTER(RESOLV_RESULT_SORT),
					clat_plugin_test_prefix);

	g_test_add_func(TEST_PREFIX "test_service1", clat_plugin_test_service1);
	g_test_add_func(TEST_PREFIX "test_service2", clat_plugin_test_service2);
	g_test_add_func(TEST_PREFIX "test_service3", clat_plugin_test_service3);
	g_test_add_func(TEST_PREFIX "test_service4", clat_plugin_test_service4);

	g_test_add_func(TEST_PREFIX "test_tether1", clat_plugin_test_tether1);
	g_test_add_func(TEST_PREFIX "test_tether2", clat_plugin_test_tether2);
	g_test_add_func(TEST_PREFIX "test_tether3", clat_plugin_test_tether3);

	g_test_add_data_func(TEST_PREFIX "test_vpn1_no_tether",
						GINT_TO_POINTER(
							VPN_TEST_TETHER_OFF),
						clat_plugin_test_vpn1);
	g_test_add_data_func(TEST_PREFIX "test_vpn1_tether_pre_vpn",
						GINT_TO_POINTER(
							VPN_TEST_TETHER_PRE),
						clat_plugin_test_vpn1);
	g_test_add_data_func(TEST_PREFIX "test_vpn1_tether_during_vpn",
						GINT_TO_POINTER(
							VPN_TEST_TETHER_ON),
						clat_plugin_test_vpn1);
	g_test_add_func(TEST_PREFIX "test_vpn2", clat_plugin_test_vpn2);

	g_test_add_data_func(TEST_PREFIX "test_vpn_type_cellular_v4_transport",
						GINT_TO_POINTER(
						CONNMAN_SERVICE_TYPE_CELLULAR),
						clat_plugin_test_vpn_type);
	g_test_add_data_func(TEST_PREFIX "test_vpn_type_wifi_transport",
						GINT_TO_POINTER(
						CONNMAN_SERVICE_TYPE_WIFI),
						clat_plugin_test_vpn_type);
	g_test_add_data_func(TEST_PREFIX "test_vpn_type_ethernet_transport",
						GINT_TO_POINTER(
						CONNMAN_SERVICE_TYPE_ETHERNET),
						clat_plugin_test_vpn_type);

	g_test_add_func(TEST_PREFIX "test_ipconfig1",
						clat_plugin_test_ipconfig1);
	g_test_add_data_func(TEST_PREFIX "test_ipconfig_ipv6_lost",
						GINT_TO_POINTER(AF_INET6),
						clat_plugin_test_ipconfig_type);
	g_test_add_data_func(TEST_PREFIX "test_ipconfig_ipv4_added",
						GINT_TO_POINTER(AF_INET),
						clat_plugin_test_ipconfig_type);

	g_test_add_data_func(TEST_PREFIX "test_if_error1.1",
						GUINT_TO_POINTER(1),
						clat_plugin_test_if_error1);
	g_test_add_data_func(TEST_PREFIX "test_if_error1.2",
						GUINT_TO_POINTER(2),
						clat_plugin_test_if_error1);
	g_test_add_data_func(TEST_PREFIX "test_if_error2.1",
						GUINT_TO_POINTER(1),
						clat_plugin_test_if_error2);
	g_test_add_data_func(TEST_PREFIX "test_if_error2.2",
						GUINT_TO_POINTER(2),
						clat_plugin_test_if_error2);

	g_test_add_func(TEST_PREFIX "unit_derive1", clat_unit_test_derive1);
	g_test_add_func(TEST_PREFIX "unit_prefix1", clat_unit_test_prefix1);
	g_test_add_func(TEST_PREFIX "unit_prefix2", clat_unit_test_prefix2);

	return g_test_run();
}
