/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013-2014  BMW Car IT GmbH.
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

#include <glib.h>
#include <errno.h>
#include <unistd.h>
#include <glib/gstdio.h>

#include "../src/connman.h"

struct connman_service {
	char *dummy;
	char *name;
	char *identifier;
	enum connman_service_type type;
	enum connman_service_state state;
};

struct connman_service test_service = {
	.dummy = "dummy",
	.name = "Ethernet1",
	.identifier = "eth_123",
	.type = CONNMAN_SERVICE_TYPE_ETHERNET,
	.state = CONNMAN_SERVICE_STATE_IDLE,
};

struct connman_service test_service2 = {
	.dummy = "dummy2",
	.name = "cellular1",
	.identifier = "rmnet_123",
	.type = CONNMAN_SERVICE_TYPE_CELLULAR,
	.state = CONNMAN_SERVICE_STATE_IDLE,
};

enum connman_service_type connman_service_get_type(
						struct connman_service *service)
{
	return service->type;
}

const char *__connman_service_get_name(struct connman_service *service)
{
	return service->identifier;
}

const char *connman_service_get_identifier(struct connman_service *service)
{
	return service->name;
}

const char *__connman_service_type2string(enum connman_service_type type)
{
	if (type == CONNMAN_SERVICE_TYPE_ETHERNET)
		return "ethernet";

	if (type == CONNMAN_SERVICE_TYPE_CELLULAR)
		return "cellular";

	return NULL;
}

enum connman_service_type __connman_service_string2type(const char *str)
{
	if (!g_strcmp0(str, "ethernet"))
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	
	if (!g_strcmp0(str, "cellular"))
		return CONNMAN_SERVICE_TYPE_CELLULAR;

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

char *__connman_config_get_string(GKeyFile *key_file,
	const char *group_name, const char *key, GError **error)
{
	char *str = g_key_file_get_string(key_file, group_name, key, error);
	if (!str)
		return NULL;

	return g_strchomp(str);
}

char **__connman_config_get_string_list(GKeyFile *key_file,
	const char *group_name, const char *key, gsize *length, GError **error)
{
	char **p;
	char **strlist = g_key_file_get_string_list(key_file, group_name, key,
		length, error);
	if (!strlist)
		return NULL;

	p = strlist;
	while (*p) {
		*p = g_strstrip(*p);
		p++;
	}

	return strlist;
}

struct connman_service *connman_service_lookup_from_identifier(
						const char* identifier)
{
	if (!g_strcmp0(identifier, "eth_123"))
		return &test_service;

	if (!g_strcmp0(identifier, "rmnet_123"))
		return &test_service2;

	return NULL;
}

const char *__connman_technology_get_tethering_ident(
				struct connman_technology *tech)
{
	return NULL;
}

const char *__connman_tethering_get_bridge(void)
{
	return "tether";
}

enum connman_service_type __connman_technology_get_type(
					struct connman_technology *tech)
{
	return 0;
}

void connman_technology_tethering_notify(struct connman_technology *technology,
							bool enabled)
{
	return;
}

DBusMessage *__connman_error_invalid_arguments(DBusMessage *msg)
{
	return NULL;
}

DBusMessage *__connman_error_permission_denied(DBusMessage *msg)
{
	return NULL;
}

DBusMessage *__connman_error_failed(DBusMessage *msg, int errnum)
{
	return NULL;
}

DBusConnection *connman_dbus_get_connection(void)
{
	return NULL;
}

struct connman_access_firewall_policy *__connman_access_firewall_policy_create
		(const char *spec)
{
	return NULL;
}

void __connman_access_firewall_policy_free
		(struct connman_access_firewall_policy *policy)
{
	return;
}

enum connman_access __connman_access_firewall_manage
		(const struct connman_access_firewall_policy *policy,
			const char *name, const char *sender,
			enum connman_access default_access)
{
	return 0;
}

int connman_service_iterate_services(connman_service_iterate_cb cb,
							void *user_data)
{
	return 0;
}

enum connman_service_state connman_service_get_state(
						struct connman_service *service)
{
	return 0;
}


static bool assert_rule(int type, const char *table_name, const char *rule)
{
	char *cmd, *output, **lines;
	GError **error = NULL;
	int i;
	bool ret = true;

	switch (type) {
	case AF_INET:
		cmd = g_strdup_printf(IPTABLES_SAVE " -t %s", table_name);
		break;
	case AF_INET6:
		cmd = g_strdup_printf(IP6TABLES_SAVE " -t %s", table_name);
		break;
	default:
		return false;
	}

	g_spawn_command_line_sync(cmd, &output, NULL, NULL, error);
	g_free(cmd);

	lines = g_strsplit(output, "\n", 0);
	g_free(output);
	if (!lines)
		return false;

	for (i = 0; lines[i]; i++) {
		DBG("lines[%02d]: %s\n", i, lines[i]);
		if (g_strcmp0(lines[i], rule) == 0)
			break;
	}

	if (!lines[i])
		ret = false;

	g_strfreev(lines);
	return ret;
}

static void assert_rule_exists(int type, const char *table_name,
							const char *rule)
{
	if (type == AF_INET) {
		if (g_strcmp0(IPTABLES_SAVE, "") == 0) {
			DBG("iptables-save is missing, no assertion possible");
			return;
		}
	}

	if (type == AF_INET6) {
		if (g_strcmp0(IP6TABLES_SAVE, "") == 0) {
			DBG("ip6tables-save is missing, no assertion possible");
			return;
		}
	}

	g_assert(assert_rule(type, table_name, rule));
}

static void assert_rule_not_exists(int type, const char *table_name,
							const char *rule)
{
	if (type == AF_INET) {
		if (g_strcmp0(IPTABLES_SAVE, "") == 0) {
			DBG("iptables-save is missing, no assertion possible");
			return;
		}
	}

	if (type == AF_INET6) {
		if (g_strcmp0(IP6TABLES_SAVE, "") == 0) {
			DBG("ip6tables-save is missing, no assertion possible");
			return;
		}
	}

	g_assert(!assert_rule(type, table_name, rule));
}

static void test_iptables_chain0(void)
{
	int err;

	err = __connman_iptables_new_chain(AF_INET, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter", ":foo - [0:0]");

	err = __connman_iptables_delete_chain(AF_INET, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET, "filter", ":foo - [0:0]");
}

static void test_iptables_chain1(void)
{
	int err;

	err = __connman_iptables_new_chain(AF_INET, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	err = __connman_iptables_flush_chain(AF_INET, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	err = __connman_iptables_delete_chain(AF_INET, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);
}

static void test_iptables_chain2(void)
{
	int err;

	err = __connman_iptables_change_policy(AF_INET, "filter", "INPUT", "DROP");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	err = __connman_iptables_change_policy(AF_INET, "filter", "INPUT", "ACCEPT");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);
}

static void test_iptables_chain3(void)
{
	int err;

	err = __connman_iptables_new_chain(AF_INET, "filter", "user-chain-0");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter", ":user-chain-0 - [0:0]");

	err = __connman_iptables_new_chain(AF_INET, "filter", "user-chain-1");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter", ":user-chain-0 - [0:0]");
	assert_rule_exists(AF_INET, "filter", ":user-chain-1 - [0:0]");

	err = __connman_iptables_delete_chain(AF_INET, "filter", "user-chain-1");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter", ":user-chain-0 - [0:0]");
	assert_rule_not_exists(AF_INET, "filter", ":user-chain-1 - [0:0]");

	err = __connman_iptables_delete_chain(AF_INET, "filter", "user-chain-0");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET, "filter", ":user-chain-0 - [0:0]");
}

static void test_iptables_rule0(void)
{
	int err;

	/* Test simple appending and removing a rule */

	err = __connman_iptables_append(AF_INET, "filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");

	err = __connman_iptables_delete(AF_INET, "filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
}

static void test_iptables_rule1(void)
{
	int err;

	/* Test if we can do NAT stuff */

	err = __connman_iptables_append(AF_INET, "nat", "POSTROUTING",
				"-s 10.10.1.0/24 -o eth0 -j MASQUERADE");

	err = __connman_iptables_commit(AF_INET, "nat");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "nat",
		"-A POSTROUTING -s 10.10.1.0/24 -o eth0 -j MASQUERADE");

	err = __connman_iptables_delete(AF_INET, "nat", "POSTROUTING",
				"-s 10.10.1.0/24 -o eth0 -j MASQUERADE");

	err = __connman_iptables_commit(AF_INET, "nat");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET, "nat",
		"-A POSTROUTING -s 10.10.1.0/24 -o eth0 -j MASQUERADE");
}

static void test_iptables_rule2(void)
{
	int err;

	/* Test if the right rule is removed */

	err = __connman_iptables_append(AF_INET, "filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");

	err = __connman_iptables_append(AF_INET, "filter", "INPUT",
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
	assert_rule_exists(AF_INET, "filter",
				"-A INPUT -m mark --mark 0x2 -j LOG");

	err = __connman_iptables_delete(AF_INET, "filter", "INPUT",
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
	assert_rule_not_exists(AF_INET, "filter",
				"-A INPUT -m mark --mark 0x2 -j LOG");

	err = __connman_iptables_delete(AF_INET, "filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
}

static void test_iptables_target0(void)
{
	int err;

	/* Test if 'fallthrough' targets work */

	err = __connman_iptables_append(AF_INET, "filter", "INPUT",
					"-m mark --mark 1");
	g_assert(err == 0);

	err = __connman_iptables_append(AF_INET, "filter", "INPUT",
					"-m mark --mark 2");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter", "-A INPUT -m mark --mark 0x1");
	assert_rule_exists(AF_INET, "filter", "-A INPUT -m mark --mark 0x2");

	err = __connman_iptables_delete(AF_INET, "filter", "INPUT",
					"-m mark --mark 1");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	err = __connman_iptables_delete(AF_INET, "filter", "INPUT",
					"-m mark --mark 2");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET, "filter",
					"-A INPUT -m mark --mark 0x1");
	assert_rule_not_exists(AF_INET, "filter",
					"-A INPUT -m mark --mark 0x2");
}

struct connman_notifier *nat_notifier;
struct connman_notifier *firewall_notifier;

char *connman_service_get_interface(struct connman_service *service)
{
	if (!g_strcmp0(service->identifier, "eth_123"))
		return g_strdup("eth0");

	if (!g_strcmp0(service->identifier, "rmnet_123"))
		return g_strdup("rmnet0");

	return g_strdup("eth0");
}

int connman_notifier_register(struct connman_notifier *notifier)
{
	if (!g_strcmp0(notifier->name, "nat"))
		nat_notifier = notifier;

	if (!g_strcmp0(notifier->name, "firewall"))
		firewall_notifier = notifier;

	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
	nat_notifier = NULL;
	firewall_notifier = NULL;
}

static void test_nat_basic0(void)
{
	int err;

	err = __connman_nat_enable("bridge", "192.168.2.1", 24);
	g_assert(err == 0);

	/* test that table is empty */
	err = __connman_iptables_append(AF_INET, "nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 "
					"-j MASQUERADE");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "nat");
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "nat",
		"-A POSTROUTING -s 192.168.2.0/24 -o eth0 -j MASQUERADE");

	err = __connman_iptables_delete(AF_INET, "nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 "
					"-j MASQUERADE");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "nat");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET, "nat",
		"-A POSTROUTING -s 192.168.2.0/24 -o eth0 -j MASQUERADE");

	__connman_nat_disable("bridge");
}

static void test_nat_basic1(void)
{
	struct connman_service *service;
	int err;

	service = g_try_new0(struct connman_service, 1);
	g_assert(service);

	nat_notifier->default_changed(service);

	err = __connman_nat_enable("bridge", "192.168.2.1", 24);
	g_assert(err == 0);

	/* test that table is not empty */
	err = __connman_iptables_append(AF_INET, "nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 "
					"-j MASQUERADE");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "nat");
	g_assert(err == 0);

	__connman_nat_disable("bridge");

	/* test that table is empty again */
	err = __connman_iptables_delete(AF_INET, "nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 "
					"-j MASQUERADE");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET, "nat");
	g_assert(err == 0);

	g_free(service);
}

static void test_firewall_basic0(void)
{
	struct firewall_context *ctx;
	int err;

	ctx = __connman_firewall_create();
	g_assert(ctx);

	err = __connman_firewall_add_rule(ctx, NULL, "filter", "INPUT",
					"-m mark --mark 999 -j LOG");
	g_assert(err >= 0);

	err = __connman_firewall_enable(ctx);
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter", ":connman-INPUT - [0:0]");
	assert_rule_exists(AF_INET, "filter", "-A INPUT -j connman-INPUT");
	assert_rule_exists(AF_INET, "filter", "-A connman-INPUT "
					"-m mark --mark 0x3e7 -j LOG");

	err = __connman_firewall_disable(ctx);
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET, "filter", ":connman-INPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter", "-A INPUT -j connman-INPUT");
	assert_rule_not_exists(AF_INET, "filter", "-A connman-INPUT "
					"-m mark --mark 0x3e7 -j LOG");

	__connman_firewall_destroy(ctx);
}

static void test_firewall_basic1(void)
{
	struct firewall_context *ctx;
	int err;

	ctx = __connman_firewall_create();
	g_assert(ctx);

	err = __connman_firewall_add_rule(ctx, NULL, "filter", "INPUT",
					"-m mark --mark 999 -j LOG");
	g_assert(err >= 0);

	err = __connman_firewall_add_rule(ctx, NULL, "filter", "OUTPUT",
					"-m mark --mark 999 -j LOG");
	g_assert(err >= 0);

	err = __connman_firewall_enable(ctx);
	g_assert(err == 0);

	err = __connman_firewall_disable(ctx);
	g_assert(err == 0);

	__connman_firewall_destroy(ctx);
}

static void test_firewall_basic2(void)
{
	struct firewall_context *ctx;
	int err;

	ctx = __connman_firewall_create();
	g_assert(ctx);

	err = __connman_firewall_add_rule(ctx, NULL, "mangle", "INPUT",
					"-j CONNMARK --restore-mark");
	g_assert(err >= 0);

	err = __connman_firewall_add_rule(ctx, NULL, "mangle", "POSTROUTING",
					"-j CONNMARK --save-mark");
	g_assert(err >= 0);

	err = __connman_firewall_enable(ctx);
	g_assert(err == 0);

	err = __connman_firewall_disable(ctx);
	g_assert(err == 0);

	__connman_firewall_destroy(ctx);
}

static void test_firewall_basic3(void)
{
	struct firewall_context *ctx;
	int err, id;

	ctx = __connman_firewall_create();
	g_assert(ctx);

	id = __connman_firewall_add_rule(ctx, NULL, "mangle", "INPUT",
					"-j CONNMARK --restore-mark");
	g_assert(id >= 0);

	err = __connman_firewall_enable_rule(ctx, id);
	g_assert(err == 0);

	err = __connman_firewall_disable_rule(ctx, id);
	g_assert(err == 0);

	err = __connman_firewall_remove_rule(ctx, id);
	g_assert(err == 0);

	err = __connman_firewall_disable(ctx);
	g_assert(err == -ENOENT);

	__connman_firewall_destroy(ctx);
}

static void test_ip6tables_chain0(void)
{
	int err;

	err = __connman_iptables_new_chain(AF_INET6, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter", ":foo - [0:0]");

	err = __connman_iptables_delete_chain(AF_INET6, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET6, "filter", ":foo - [0:0]");
}

static void test_ip6tables_chain1(void)
{
	int err;

	err = __connman_iptables_new_chain(AF_INET6, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	err = __connman_iptables_flush_chain(AF_INET6, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	err = __connman_iptables_delete_chain(AF_INET6, "filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);
}

static void test_ip6tables_chain2(void)
{
	int err;

	err = __connman_iptables_change_policy(AF_INET6, "filter", "INPUT",
						"DROP");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	err = __connman_iptables_change_policy(AF_INET6, "filter", "INPUT",
						"ACCEPT");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);
}

static void test_ip6tables_chain3(void)
{
	int err;

	err = __connman_iptables_new_chain(AF_INET6, "filter", "user-chain-0");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter", ":user-chain-0 - [0:0]");

	err = __connman_iptables_new_chain(AF_INET6, "filter", "user-chain-1");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter", ":user-chain-0 - [0:0]");
	assert_rule_exists(AF_INET6, "filter", ":user-chain-1 - [0:0]");

	err = __connman_iptables_delete_chain(AF_INET6, "filter",
						"user-chain-1");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter", ":user-chain-0 - [0:0]");
	assert_rule_not_exists(AF_INET6, "filter", ":user-chain-1 - [0:0]");

	err = __connman_iptables_delete_chain(AF_INET6, "filter",
						"user-chain-0");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET6, "filter", ":user-chain-0 - [0:0]");
}

static void test_ip6tables_rule0(void)
{
	int err;

	/* Test simple appending and removing a rule */

	err = __connman_iptables_append(AF_INET6, "filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");

	err = __connman_iptables_delete(AF_INET6, "filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET6, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
}

static void test_ip6tables_rule1(void)
{
	int err;

	/* Test if the right rule is removed */

	err = __connman_iptables_append(AF_INET6, "filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");

	err = __connman_iptables_append(AF_INET6, "filter", "INPUT",
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
	assert_rule_exists(AF_INET6, "filter",
				"-A INPUT -m mark --mark 0x2 -j LOG");

	err = __connman_iptables_delete(AF_INET6, "filter", "INPUT",
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
	assert_rule_not_exists(AF_INET6, "filter",
				"-A INPUT -m mark --mark 0x2 -j LOG");

	err = __connman_iptables_delete(AF_INET6, "filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET6, "filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
}

static void test_ip6tables_rule2(void)
{
	int err;

	err = __connman_iptables_append(AF_INET6, "filter", "INPUT",
					"-p icmpv6 -m icmpv6 "
					"--icmpv6-type 128/0 -j DROP");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");

	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter", "-A INPUT -p ipv6-icmp "
					"-m icmp6 --icmpv6-type 128/0 -j DROP");

	err = __connman_iptables_append(AF_INET6, "filter", "OUTPUT",
					"-p icmpv6 -m icmpv6 "
					"--icmpv6-type 129/0 -j DROP");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");

	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter", "-A OUTPUT -p ipv6-icmp "
					"-m icmp6 --icmpv6-type 129/0 -j DROP");

	err = __connman_iptables_delete(AF_INET6, "filter", "INPUT",
					"-p icmpv6 -m icmpv6 "
					"--icmpv6-type 128/0 -j DROP");

	g_assert(err == 0);

	err = __connman_iptables_delete(AF_INET6, "filter", "OUTPUT",
					"-p icmpv6 -m icmpv6 "
					"--icmpv6-type 129/0 -j DROP");

	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");

	g_assert(err == 0);

}

static void test_ip6tables_target0(void)
{
	int err;

	/* Test if 'fallthrough' targets work */

	err = __connman_iptables_append(AF_INET6, "filter", "INPUT",
					"-m mark --mark 1");
	g_assert(err == 0);

	err = __connman_iptables_append(AF_INET6, "filter", "INPUT",
					"-m mark --mark 2");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter", "-A INPUT -m mark --mark 0x1");
	assert_rule_exists(AF_INET6, "filter", "-A INPUT -m mark --mark 0x2");

	err = __connman_iptables_delete(AF_INET6, "filter", "INPUT",
					"-m mark --mark 1");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	err = __connman_iptables_delete(AF_INET6, "filter", "INPUT",
					"-m mark --mark 2");
	g_assert(err == 0);

	err = __connman_iptables_commit(AF_INET6, "filter");
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET6, "filter", "-A INPUT "
					"-m mark --mark 0x1");
	assert_rule_not_exists(AF_INET6, "filter", "-A INPUT "
					"-m mark --mark 0x2");
}

static void test_firewall6_basic0(void)
{
	struct firewall_context *ctx;
	int err;

	ctx = __connman_firewall_create();
	g_assert(ctx);

	err = __connman_firewall_add_ipv6_rule(ctx, NULL, "filter", "INPUT",
					"-m mark --mark 999 -j LOG");
	g_assert(err >= 0);

	err = __connman_firewall_enable(ctx);
	g_assert(err == 0);

	assert_rule_exists(AF_INET6, "filter", ":connman-INPUT - [0:0]");
	assert_rule_exists(AF_INET6, "filter", "-A INPUT -j connman-INPUT");
	assert_rule_exists(AF_INET6, "filter",
				"-A connman-INPUT -m mark --mark 0x3e7 -j LOG");

	err = __connman_firewall_disable(ctx);
	g_assert(err == 0);

	assert_rule_not_exists(AF_INET6, "filter", ":connman-INPUT - [0:0]");
	assert_rule_not_exists(AF_INET6, "filter", "-A INPUT -j connman-INPUT");
	assert_rule_not_exists(AF_INET6, "filter",
				"-A connman-INPUT -m mark --mark 0x3e7 -j LOG");

	__connman_firewall_destroy(ctx);
}

static void test_firewall6_basic1(void)
{
	struct firewall_context *ctx;
	int err;

	ctx = __connman_firewall_create();
	g_assert(ctx);

	err = __connman_firewall_add_ipv6_rule(ctx, NULL, "filter", "INPUT",
					"-m mark --mark 999 -j LOG");
	g_assert(err >= 0);

	err = __connman_firewall_add_rule(ctx, NULL, "filter", "OUTPUT",
					"-m mark --mark 999 -j LOG");
	g_assert(err >= 0);

	err = __connman_firewall_enable(ctx);
	g_assert(err == 0);

	err = __connman_firewall_disable(ctx);
	g_assert(err == 0);

	__connman_firewall_destroy(ctx);
}

static void test_firewall6_basic2(void)
{
	struct firewall_context *ctx;
	int err;

	ctx = __connman_firewall_create();
	g_assert(ctx);

	err = __connman_firewall_add_ipv6_rule(ctx, NULL, "mangle", "INPUT",
					"-j CONNMARK --restore-mark");
	g_assert(err >= 0);

	err = __connman_firewall_add_ipv6_rule(ctx, NULL, "mangle", "POSTROUTING",
					"-j CONNMARK --save-mark");
	g_assert(err >= 0);

	err = __connman_firewall_enable(ctx);
	g_assert(err == 0);

	err = __connman_firewall_disable(ctx);
	g_assert(err == 0);

	__connman_firewall_destroy(ctx);
}

static void test_firewall6_basic3(void)
{
	struct firewall_context *ctx;
	int err, id;

	ctx = __connman_firewall_create();
	g_assert(ctx);

	id = __connman_firewall_add_rule(ctx, NULL, "mangle", "INPUT",
					"-j CONNMARK --restore-mark");
	g_assert(id >= 0);

	err = __connman_firewall_enable_rule(ctx, id);
	g_assert(err == 0);

	err = __connman_firewall_disable_rule(ctx, id);
	g_assert(err == 0);

	err = __connman_firewall_remove_rule(ctx, id);
	g_assert(err == 0);

	err = __connman_firewall_disable(ctx);
	g_assert(err == -ENOENT);

	__connman_firewall_destroy(ctx);
}

static void test_firewall_4and6_basic0(void)
{
	struct firewall_context *ctx;
	int err;

	ctx = __connman_firewall_create();

	g_assert(ctx);

	err = __connman_firewall_add_rule(ctx, NULL, "filter", "INPUT",
			"-p icmp -m icmp "
			"--icmp-type 8/0 -j DROP");

	g_assert(err >= 0);

	err = __connman_firewall_add_rule(ctx, NULL, "filter", "OUTPUT",
				"-p icmp -m icmp "
				"--icmp-type 0/0 -j DROP");

	g_assert(err >= 0);

	err = __connman_firewall_add_ipv6_rule(ctx, NULL, "filter", "INPUT",
					"-p icmpv6 -m icmpv6 "
					"--icmpv6-type 128/0 -j DROP");
	g_assert(err >= 0);

	err = __connman_firewall_add_ipv6_rule(ctx, NULL, "filter", "OUTPUT",
					"-p icmpv6 -m icmpv6 "
					"--icmpv6-type 129/0 -j DROP");
	g_assert(err >= 0);

	err = __connman_firewall_enable(ctx);
	g_assert(err == 0);

	assert_rule_exists(AF_INET, "filter", ":connman-INPUT - [0:0]");
	assert_rule_exists(AF_INET, "filter", "-A INPUT -j connman-INPUT");
	assert_rule_exists(AF_INET, "filter", "-A connman-INPUT "
						"-p icmp -m icmp "
						"--icmp-type 8/0 -j DROP");

	assert_rule_exists(AF_INET, "filter", ":connman-OUTPUT - [0:0]");
	assert_rule_exists(AF_INET, "filter", "-A OUTPUT -j connman-OUTPUT");
	assert_rule_exists(AF_INET, "filter", "-A connman-OUTPUT "
						"-p icmp -m icmp "
						"--icmp-type 0/0 -j DROP");

	assert_rule_exists(AF_INET6, "filter", ":connman-INPUT - [0:0]");
	assert_rule_exists(AF_INET6, "filter", "-A INPUT -j connman-INPUT");
	assert_rule_exists(AF_INET6, "filter", "-A connman-INPUT "
						"-p ipv6-icmp -m icmp6 "
						"--icmpv6-type 128/0 -j DROP");

	assert_rule_exists(AF_INET6, "filter", ":connman-OUTPUT - [0:0]");
	assert_rule_exists(AF_INET6, "filter", "-A OUTPUT -j connman-OUTPUT");
	assert_rule_exists(AF_INET6, "filter", "-A connman-OUTPUT "
						"-p ipv6-icmp -m icmp6 "
						"--icmpv6-type 129/0 -j DROP");

	err = __connman_firewall_disable(ctx);
	g_assert(err == 0);

	__connman_firewall_destroy(ctx);
}


static const char *general_input[] = {
		"-p tcp -m tcp --dport 80 -j ACCEPT",
		"-p udp -m udp --dport 81 -j DROP",
		"-p all -m conntrack --ctstate RELATED -j ACCEPT",
		"#-p sctp --dport 69 -j REJECT",
		NULL
};
static const char *general_output[] = {
		"-p tcp -m tcp --sport 80 -j ACCEPT",
		"-p udp -m udp --sport 81 -j DROP",
		"#-p sctp --sport 123 -j REJECT",
		NULL
};
static const char *general_forward[] = {
		"-p tcp -m tcp -j ACCEPT",
		"-p udp -m udp -j DROP",
		NULL
};
static const char *eth_input[] = {
		"-p tcp -m tcp --dport 80 -j ACCEPT",
		"-p udp -m udp --dport 81 -j DROP",
		"-p all -m conntrack --ctstate RELATED -j ACCEPT",
		"#-p sctp --dport 69 -j REJECT",
		NULL
};
static const char *eth_output[] = {
		"-p tcp -m tcp --sport 80 -j ACCEPT",
		"-p udp -m udp --sport 81 -j DROP",
		"#-p sctp --sport 123 -j REJECT",
		NULL
};
static const char *cellular_input[] = {
		"-p tcp -m tcp --dport 80 -j ACCEPT",
		"-p udp -m udp --dport 81 -j DROP",
		"-p all -m conntrack --ctstate RELATED -j ACCEPT",
		NULL
};
static const char *cellular_output[] = {
		"-p tcp -m tcp --sport 80 -j ACCEPT",
		"-p udp -m udp --sport 81 -j DROP",
		NULL
};

/* Invalid rules */
static const char *invalid_general_input[] = {
		"-p tcp -m tcp --dport 80 -j ACCEPT -j DROP",
		"udp -m udp --dport 81 -j DROP",
		"-p tcp -p all -m conntrack --ctstate RELATED -j ACCEPT",
		NULL
};
static const char *invalid_general_output[] = {
		"-p tcp -m tcp --sport 80 -j ACCEPT -j ACCEPT -j DROP",
		"-p udp -m udp --sport 81 --dport 50 --dport 40 -j DROP",
		"DROP",
		NULL
};
static const char *invalid_general_forward[] = {
		"-j ACCEPT -j DROP",
		"-p udp -m udp -m multiport --dport 654 -j DROP",
		NULL
};
static const char *invalid_eth_input[] = {
		"-p tcp -m tcp --dport 80 -j ACCEPT -j DROP",
		"udp -m udp --dport 81 -j DROP",
		"-p tcp -p all -m conntrack --ctstate RELATED -j ACCEPT",
		NULL
};
static const char *invalid_eth_output[] = {
		"-p tcp -m tcp --sport 80 -j ACCEPT -j ACCEPT -j DROP",
		"-p udp -m udp --sport 81 --dport 50 --dport 40 -j DROP",
		"DROP",
		NULL
};

static bool init_firewall_config(bool use_valid_rules)
{
	GKeyFile *config;
	GError *error = NULL;
	char *filename;
	bool ret = false;
	int err;

	config = g_key_file_new();

	g_assert(config);

	if (use_valid_rules) {
		g_key_file_set_string_list(config, "General", "INPUT",
					general_input,
					g_strv_length((char**)general_input));

		g_key_file_set_string_list(config, "General", "OUTPUT",
					general_output,
					g_strv_length((char**)general_output));

		g_key_file_set_string_list(config, "General", "FORWARD",
					general_forward,
					g_strv_length((char**)general_forward));

		g_key_file_set_string_list(config, "ethernet", "INPUT",
					eth_input,
					g_strv_length((char**)eth_input));

		g_key_file_set_string_list(config, "ethernet", "OUTPUT",
					eth_output,
					g_strv_length((char**)eth_output));

		g_key_file_set_string_list(config, "cellular", "INPUT",
					cellular_input,
					g_strv_length((char**)cellular_input));

		g_key_file_set_string_list(config, "cellular", "OUTPUT",
					cellular_output,
					g_strv_length((char**)cellular_output));
	} else {
		g_key_file_set_string_list(config, "General", "INPUT",
					invalid_general_input,
					g_strv_length(
					(char**)invalid_general_input));

		g_key_file_set_string_list(config, "General", "OUTPUT",
					invalid_general_output,
					g_strv_length(
					(char**)invalid_general_output));

		g_key_file_set_string_list(config, "General", "FORWARD",
					invalid_general_forward,
					g_strv_length(
					(char**)invalid_general_forward));

		g_key_file_set_string_list(config, "ethernet", "INPUT",
					invalid_eth_input,
					g_strv_length(
					(char**)invalid_eth_input));

		g_key_file_set_string_list(config, "ethernet", "OUTPUT",
					invalid_eth_output,
					g_strv_length(
					(char**)invalid_eth_output));
	}

	filename = g_strconcat(CONFIGDIR,"/","firewall.conf", NULL);

	if (!g_file_test(CONFIGDIR, G_FILE_TEST_IS_DIR)) {
		err = g_mkdir_with_parents(CONFIGDIR, R_OK|W_OK|X_OK);

		if (err) {
			g_printerr("Error creating %s\n", CONFIGDIR);
			goto out;
		}
	}

	ret = g_key_file_save_to_file(config, filename, &error);

	if (error)
		g_printerr("Error saving %s, %s\n", filename, error->message);

	g_clear_error(&error);

out:
	g_free(filename);

	g_key_file_free(config);

	return ret;
}

static bool clean_firewall_config()
{
	char *filename;
	int err = 0;
	bool ret = false;

	filename = g_strconcat(CONFIGDIR,"/","firewall.conf", NULL);

	if (g_file_test(filename,
				G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		err = g_remove(filename);

		if (err && errno)
			g_printerr("Error removing %s, %s\n", filename,
						strerror(errno));
	}

	g_free(filename);

	if (err)
		goto out;

	if (g_file_test(CONFIGDIR, G_FILE_TEST_IS_DIR)) {
		err = g_rmdir(CONFIGDIR);

		if (err && errno)
			g_printerr("Error removing dir %s, %s\n", CONFIGDIR,
						strerror(errno));
	}

	ret = !err;
out:
	return ret;
}

static void test_managed_rule_exists(int type, const char *chain,
					const char *dev, const char *rule)
{
	char *test_rule;
	char *rule_dev = NULL;
	bool rule_exists = true;

	if (!g_strcmp0(chain, "INPUT") && dev)
		rule_dev = g_strdup_printf(" -i %s ", dev);
	else if (!g_strcmp0(chain, "OUTPUT") && dev)
		rule_dev = g_strdup_printf(" -o %s ", dev);
	else
		rule_dev = g_strdup(" ");

	/* Commented out rule, should not exist */
	if (rule[0] == '#') {
		test_rule = g_strconcat("-A connman-", chain, rule_dev,
					&(rule[1]), NULL);
		rule_exists = false;
	} else if (g_str_has_prefix(rule, "-p all"))
		/* -p all is omitted in iptables-save output, skip it */
		test_rule = g_strconcat("-A connman-", chain, rule_dev,
					&(rule[7]), NULL);
	else
		test_rule = g_strconcat("-A connman-", chain, rule_dev,
					rule, NULL);

	if (rule_exists)
		assert_rule_exists(type, "filter", test_rule);
	else
		assert_rule_not_exists(type, "filter", test_rule);

	g_free(test_rule);
	g_free(rule_dev);
}

static void test_managed_rule_not_exists(int type, const char *chain,
					const char *dev, const char *rule)
{
	char *test_rule;
	char *rule_dev;

	if (rule[0] == '#')
		return;

	if (!g_strcmp0(chain, "INPUT") && dev)
		rule_dev = g_strdup_printf(" -i %s ", dev);
	else if (!g_strcmp0(chain, "OUTPUT") && dev)
		rule_dev = g_strdup_printf(" -o %s ", dev);
	else
		rule_dev = g_strdup(" ");

	test_rule = g_strconcat("-A connman-", chain, rule_dev, rule,
				NULL);

	assert_rule_not_exists(type, "filter", test_rule);

	g_free(test_rule);
	g_free(rule_dev);
}

static void test_firewall_managed_prep(void)
{
	/* It is required to have iptables and firewall empty before setting
	 * new content for testing
	 */
	__connman_firewall_cleanup();
	__connman_iptables_cleanup();

	g_assert(init_firewall_config(true));
}

static void test_firewall_managed_rules0(void)
{
	int i;

	__connman_iptables_init();
	__connman_firewall_init();

	for (i = 0; general_input[i]; i++)
		test_managed_rule_exists(AF_INET, "INPUT", NULL,
					general_input[i]);

	for (i = 0; general_output[i]; i++)
		test_managed_rule_exists(AF_INET, "OUTPUT", NULL,
					general_output[i]);

	for (i = 0; general_forward[i]; i++)
		test_managed_rule_exists(AF_INET, "FORWARD",  NULL,
					general_forward[i]);

	__connman_firewall_cleanup();
	__connman_iptables_cleanup();

	/* Check that iptables is clean */
	for (i = 0; general_input[i]; i++)
		test_managed_rule_not_exists(AF_INET, "INPUT", NULL,
					general_input[i]);

	for (i = 0; general_output[i]; i++)
		test_managed_rule_not_exists(AF_INET, "OUTPUT", NULL,
					general_output[i]);

	for (i = 0; general_forward[i]; i++) 
		test_managed_rule_not_exists(AF_INET, "FORWARD", NULL,
					general_forward[i]);

	/* Check that iptables is clean */
	assert_rule_not_exists(AF_INET, "filter",
				"-A INPUT -j connman-INPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A OUTPUT -j connman-OUTPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A FORWARD -j connman-FORWARD");

	assert_rule_not_exists(AF_INET, "filter",
				":connman-INPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-OUTPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-FORWARD - [0:0]");
}

static void test_firewall_managed_rules1(void)
{
	int i;

	__connman_iptables_init();
	__connman_firewall_init();

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	firewall_notifier->service_state_changed(&test_service,
				CONNMAN_SERVICE_STATE_READY);

	for (i = 0; eth_input[i]; i++)
		test_managed_rule_exists(AF_INET, "INPUT", "eth0",
					eth_input[i]);

	for (i = 0; eth_output[i]; i++)
		test_managed_rule_exists(AF_INET, "OUTPUT", "eth0",
					eth_output[i]);

	test_service.state = CONNMAN_SERVICE_STATE_DISCONNECT;

	firewall_notifier->service_state_changed(&test_service,
				CONNMAN_SERVICE_STATE_DISCONNECT);

	for (i = 0; eth_input[i]; i++)
		test_managed_rule_not_exists(AF_INET, "INPUT", "eth0",
					eth_input[i]);

	for (i = 0; eth_output[i]; i++)
		test_managed_rule_not_exists(AF_INET, "OUTPUT", "eth0",
					eth_output[i]);

	__connman_firewall_cleanup();
	__connman_iptables_cleanup();

	/* Check that iptables is clean */
	assert_rule_not_exists(AF_INET, "filter",
				"-A INPUT -j connman-INPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A OUTPUT -j connman-OUTPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A FORWARD -j connman-FORWARD");

	assert_rule_not_exists(AF_INET, "filter",
				":connman-INPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-OUTPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-FORWARD - [0:0]");

}

static void test_firewall_managed_rules2(void)
{
	int i;

	__connman_iptables_init();
	__connman_firewall_init();

	/* Test service 1 ethernet */
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	firewall_notifier->service_state_changed(&test_service,
				CONNMAN_SERVICE_STATE_READY);

	for (i = 0; eth_input[i]; i++)
		test_managed_rule_exists(AF_INET, "INPUT", "eth0",
					eth_input[i]);

	for (i = 0; eth_output[i]; i++)
		test_managed_rule_exists(AF_INET, "OUTPUT", "eth0",
					eth_output[i]);

	/* Test service 2 cellular */
	test_service2.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	firewall_notifier->service_state_changed(&test_service2,
				CONNMAN_SERVICE_STATE_READY);

	for (i = 0; cellular_input[i]; i++)
		test_managed_rule_exists(AF_INET, "INPUT", "rmnet0",
					cellular_input[i]);

	for (i = 0; cellular_output[i]; i++)
		test_managed_rule_exists(AF_INET, "OUTPUT", "rmnet0",
					cellular_output[i]);

	/* Test service 1 ethernet disconnect*/
	test_service.state = CONNMAN_SERVICE_STATE_DISCONNECT;

	firewall_notifier->service_state_changed(&test_service,
				CONNMAN_SERVICE_STATE_DISCONNECT);

	for (i = 0; eth_input[i]; i++)
		test_managed_rule_not_exists(AF_INET, "INPUT", "eth0",
					eth_input[i]);

	for (i = 0; eth_output[i]; i++)
		test_managed_rule_not_exists(AF_INET, "OUTPUT", "eth0",
					eth_output[i]);
	
	/* Test service 2 cellular disconnect */
	test_service2.state = CONNMAN_SERVICE_STATE_DISCONNECT;

	firewall_notifier->service_state_changed(&test_service2,
				CONNMAN_SERVICE_STATE_DISCONNECT);

	for (i = 0; cellular_input[i]; i++)
		test_managed_rule_not_exists(AF_INET, "INPUT", "rmnet0",
					cellular_input[i]);

	for (i = 0; cellular_output[i]; i++)
		test_managed_rule_not_exists(AF_INET, "OUTPUT", "rmnet0",
					cellular_output[i]);

	__connman_firewall_cleanup();
	__connman_iptables_cleanup();

	/* Check that iptables is clean */
	assert_rule_not_exists(AF_INET, "filter",
				"-A INPUT -j connman-INPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A OUTPUT -j connman-OUTPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A FORWARD -j connman-FORWARD");

	assert_rule_not_exists(AF_INET, "filter",
				":connman-INPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-OUTPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-FORWARD - [0:0]");
}

static void test_firewall_managed_clean(void)
{
	g_assert(clean_firewall_config());
}

static void test_firewall_managed_invalid_prep(void)
{
	g_assert(init_firewall_config(false));
}

static void test_firewall_managed_invalid_rules0(void)
{
	int i;

	__connman_iptables_init();
	__connman_firewall_init();

	for (i = 0; invalid_general_input[i]; i++)
		test_managed_rule_not_exists(AF_INET, "INPUT", NULL,
					invalid_general_input[i]);

	for (i = 0; invalid_general_output[i]; i++)
		test_managed_rule_not_exists(AF_INET, "OUTPUT", NULL,
					invalid_general_output[i]);

	for (i = 0; invalid_general_forward[i]; i++)
		test_managed_rule_not_exists(AF_INET, "FORWARD", NULL,
					invalid_general_forward[i]);

	/* Check that iptables is clean */
	assert_rule_not_exists(AF_INET, "filter",
				"-A INPUT -j connman-INPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A OUTPUT -j connman-OUTPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A FORWARD -j connman-FORWARD");

	assert_rule_not_exists(AF_INET, "filter",
				":connman-INPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-OUTPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-FORWARD - [0:0]");

	__connman_firewall_cleanup();
	__connman_iptables_cleanup();
}

static void test_firewall_managed_invalid_rules1(void)
{
	int i;

	g_assert(init_firewall_config(false));

	__connman_iptables_init();
	__connman_firewall_init();

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	firewall_notifier->service_state_changed(&test_service,
				CONNMAN_SERVICE_STATE_READY);

	for (i = 0; invalid_eth_input[i]; i++)
		test_managed_rule_not_exists(AF_INET, "INPUT", "eth0",
					invalid_eth_input[i]);

	for (i = 0; invalid_eth_output[i]; i++)
		test_managed_rule_not_exists(AF_INET, "OUTPUT", "eth0",
					invalid_eth_output[i]);

	test_service.state = CONNMAN_SERVICE_STATE_DISCONNECT;

	firewall_notifier->service_state_changed(&test_service,
				CONNMAN_SERVICE_STATE_DISCONNECT);

	/* Check that iptables is clean */
	assert_rule_not_exists(AF_INET, "filter",
				"-A INPUT -j connman-INPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A OUTPUT -j connman-OUTPUT");
	assert_rule_not_exists(AF_INET, "filter",
				"-A FORWARD -j connman-FORWARD");

	assert_rule_not_exists(AF_INET, "filter",
				":connman-INPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-OUTPUT - [0:0]");
	assert_rule_not_exists(AF_INET, "filter",
				":connman-FORWARD - [0:0]");

	__connman_firewall_cleanup();
	__connman_iptables_cleanup();
}

static void test_firewall_managed_invalid_clean(void)
{
	g_assert(clean_firewall_config());
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

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	int err;

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

	__connman_iptables_init();
	__connman_firewall_init();
	__connman_nat_init();

	g_test_add_func("/iptables/chain0", test_iptables_chain0);
	g_test_add_func("/iptables/chain1", test_iptables_chain1);
	g_test_add_func("/iptables/chain2", test_iptables_chain2);
	g_test_add_func("/iptables/chain3", test_iptables_chain3);
	g_test_add_func("/iptables/rule0",  test_iptables_rule0);
	g_test_add_func("/iptables/rule1",  test_iptables_rule1);
	g_test_add_func("/iptables/rule2",  test_iptables_rule2);
	g_test_add_func("/iptables/target0", test_iptables_target0);
	g_test_add_func("/ip6tables/chain0", test_ip6tables_chain0);
	g_test_add_func("/ip6tables/chain1", test_ip6tables_chain1);
	g_test_add_func("/ip6tables/chain2", test_ip6tables_chain2);
	g_test_add_func("/ip6tables/chain3", test_ip6tables_chain3);
	g_test_add_func("/ip6tables/rule0",  test_ip6tables_rule0);
	g_test_add_func("/ip6tables/rule1",  test_ip6tables_rule1);
	g_test_add_func("/ip6tables/rule2",  test_ip6tables_rule2);
	g_test_add_func("/ip6tables/target0", test_ip6tables_target0);
	g_test_add_func("/nat/basic0", test_nat_basic0);
	g_test_add_func("/nat/basic1", test_nat_basic1);
	g_test_add_func("/firewall/basic0", test_firewall_basic0);
	g_test_add_func("/firewall/basic1", test_firewall_basic1);
	g_test_add_func("/firewall/basic2", test_firewall_basic2);
	g_test_add_func("/firewall/basic3", test_firewall_basic3);
	g_test_add_func("/firewall6/basic0", test_firewall6_basic0);
	g_test_add_func("/firewall6/basic1", test_firewall6_basic1);
	g_test_add_func("/firewall6/basic2", test_firewall6_basic2);
	g_test_add_func("/firewall6/basic3", test_firewall6_basic3);
	g_test_add_func("/firewall4and6/basic4", test_firewall_4and6_basic0);
	g_test_add_func("/firewallmanaged/prep", test_firewall_managed_prep);
	g_test_add_func("/firewallmanaged/rule0", test_firewall_managed_rules0);
	g_test_add_func("/firewallmanaged/rule1", test_firewall_managed_rules1);
	g_test_add_func("/firewallmanaged/rule2", test_firewall_managed_rules2);
	g_test_add_func("/firewallmanaged/clean", test_firewall_managed_clean);
	g_test_add_func("/firewallmanaged/invalid_prep",
				test_firewall_managed_invalid_prep);
	g_test_add_func("/firewallmanaged/invalid0",
				test_firewall_managed_invalid_rules0);
	g_test_add_func("/firewallmanaged/invalid1",
				test_firewall_managed_invalid_rules1);
	g_test_add_func("/firewallmanaged/invalid_clean",
				test_firewall_managed_invalid_clean);

	err = g_test_run();

	__connman_nat_cleanup();
	//__connman_firewall_cleanup();
	//__connman_iptables_cleanup();

	g_free(option_debug);

	return err;
}
