/*
 *  ConnMan firewall unit tests
 *
 *  Copyright (C) 2018-2019 Jolla Ltd. All rights reserved.
 *  Contact: jussi.laakkonen@jolla.com
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

/* TODO list:
 * 1) check rule ordering, the order of the rules is defined by the files they
 *    are loaded from. All dynamic rules are put on top, their order is
 *    following the same file ordering but the last enabled dynamic rules are
 *    always first. Some rules are included only with the specific IP family.
 * 2) add general rules to the dynamically loaded file and check that they are
 *    added and removed accordingly, and put after the general rules in the
 *    firewall.conf (the main file).
 * 3) Add changing policies to additional dynamically loaded files. Remove and
 *    add them and check for policy changes.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <errno.h>
#include <gdbus.h>
#include <stdio.h>
#include <unistd.h>

#include "src/connman.h"

struct connman_service {
	char *dummy;
	char *name;
	char *identifier;
	char *ifname;
	enum connman_service_type type;
	enum connman_service_state state;
};

struct connman_service test_service = {
	.dummy = "dummy",
	.name = "Ethernet1",
	.identifier = "eth_123",
	.ifname = "eth0",
	.type = CONNMAN_SERVICE_TYPE_ETHERNET,
	.state = CONNMAN_SERVICE_STATE_IDLE,
};

struct connman_service test_service2 = {
	.dummy = "dummy2",
	.name = "cellular1",
	.identifier = "rmnet_123",
	.ifname = "rmnet0",
	.type = CONNMAN_SERVICE_TYPE_CELLULAR,
	.state = CONNMAN_SERVICE_STATE_IDLE,
};

struct connman_service test_service3 = {
	.dummy = "dummy3",
	.name = "Ethernet2",
	.identifier = "eth_456",
	.ifname = "eth1",
	.type = CONNMAN_SERVICE_TYPE_ETHERNET,
	.state = CONNMAN_SERVICE_STATE_IDLE,
};

enum configtype {
	GLOBAL_NOT_SET = 	0x0000,
	CONFIG_OK = 		0x0002,
	CONFIG_INVALID =	0x0004,
	CONFIG_MIXED = 		0x0008,
	CONFIG_DUPLICATES = 	0x0010,
	CONFIG_ALL = 		0x0020,
	CONFIG_MAIN_INVALID = 	0x0040,
	CONFIG_TETHERING = 	0x0080,
	CONFIG_USE_POLICY = 	0x0100,
	ACCESS_FAILURE = 	0x0200,
	DIR_ACCESS_FAILURE =	0x0800,
	CONFIG_ICMP_ONLY =	0x1000,
	CONFIG_OPTIONS_ONLY =	0x2000,
	CONFIG_OPTIONS_ADDR =	0x4000,
};

static enum configtype global_config_type = GLOBAL_NOT_SET;

static const gchar *testfiles[] = {
				"10-firewall.conf",
				"30-firewall.conf",
				"20-firewall.conf",
				"04-firewall.conf",
				"69.conf",
				NULL
};

#define TESTFILES_MAX 5

static gboolean config_files_enabled[TESTFILES_MAX];

static void toggle_config(int index, gboolean enable)
{
	if (index >= TESTFILES_MAX)
		return;

	config_files_enabled[index] = enable;
}

#define FILE_CEL0 0
#define FILE_ETH1 1
#define FILE_CEL2 2
#define FILE_ETH3 3

static gboolean config_enabled(int index)
{
	if (index >= TESTFILES_MAX)
		return FALSE;

	return config_files_enabled[index];
}

static void reset_services() {
	test_service.state = test_service2.state = test_service3.state =
				CONNMAN_SERVICE_STATE_IDLE;
}

static void setup_test_params(enum configtype type)
{
	int i;

	if (type & CONFIG_OK)
		DBG("CONFIG_OK");

	if (type & CONFIG_INVALID)
		DBG("CONFIG_INVALID");

	if (type & CONFIG_MIXED)
		DBG("CONFIG_MIXED");

	if (type & CONFIG_MAIN_INVALID)
		DBG("CONFIG_MAIN_INVALID");

	if (type & CONFIG_TETHERING)
		DBG("CONFIG_TETHERING");

	if (type & CONFIG_USE_POLICY)
		DBG("CONFIG_USE_POLICY");
	
	if (type & ACCESS_FAILURE)
		DBG("ACCESS_FAILURE");
	
	if (type & DIR_ACCESS_FAILURE)
		DBG("DIR_ACCESS_FAILURE");

	if (type & CONFIG_ICMP_ONLY)
		DBG("CONFIG_ICMP_ONLY");

	if (type & CONFIG_OPTIONS_ONLY)
		DBG("CONFIG_OPTIONS_ONLY");

	if (type & CONFIG_OPTIONS_ADDR)
		DBG("CONFIG_OPTIONS_ADDR");

	global_config_type = type;

	DBG("type %d duplicates %d all_configs %d", type,
				type & CONFIG_DUPLICATES ? 1 : 0,
				type & CONFIG_ALL ? 1 : 0);

	for (i = 0; i < TESTFILES_MAX; i++)
		toggle_config(i, TRUE);

	reset_services();
}

// Dummies

// Config dummies

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

// Service dummies 

enum connman_service_type connman_service_get_type(
						struct connman_service *service)
{
	return service->type;
}

const char *__connman_service_get_name(struct connman_service *service)
{
	return service->name;
}

const char *connman_service_get_identifier(struct connman_service *service)
{
	return service->identifier;
}

const char *__connman_service_type2string(enum connman_service_type type)
{
	if (type == CONNMAN_SERVICE_TYPE_ETHERNET)
		return "ethernet";

	if (type == CONNMAN_SERVICE_TYPE_CELLULAR)
		return "cellular";

	if (type == CONNMAN_SERVICE_TYPE_WIFI)
		return "wifi";

	if (type == CONNMAN_SERVICE_TYPE_VPN)
		return "vpn";

	return NULL;
}

enum connman_service_type __connman_service_string2type(const char *str)
{
	if (!g_strcmp0(str, "ethernet"))
		return CONNMAN_SERVICE_TYPE_ETHERNET;

	if (!g_strcmp0(str, "cellular"))
		return CONNMAN_SERVICE_TYPE_CELLULAR;

	if (!g_strcmp0(str, "wifi"))
		return CONNMAN_SERVICE_TYPE_WIFI;

	if (!g_strcmp0(str, "vpn"))
		return CONNMAN_SERVICE_TYPE_VPN;

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

struct connman_service *connman_service_lookup_from_identifier(
						const char* identifier)
{
	if (!g_strcmp0(identifier, "eth_123"))
		return &test_service;

	if (!g_strcmp0(identifier, "rmnet_123"))
		return &test_service2;

	if (!g_strcmp0(identifier, "eth_456"))
		return &test_service3;

	return NULL;
}

int connman_service_iterate_services(connman_service_iterate_cb cb,
							void *user_data)
{
	cb(&test_service, user_data);
	cb(&test_service2, user_data);
	cb(&test_service3, user_data);

	return 0;
}

enum connman_service_state connman_service_get_state(
						struct connman_service *service)
{
	return service->state;
}

char *connman_service_get_interface(struct connman_service *service)
{
	if (service->ifname)
		return g_strdup(service->ifname);

	return g_strdup("unknown0");
}

// Tech / tethering dummies

struct connman_technology {
	char *ident;
	char *bridge;
	enum connman_service_type type;
	bool enabled;
	bool default_rules;
};

struct connman_technology test_technology = {
	.ident = "wifi_123",
	.bridge = "tether",
	.type = CONNMAN_SERVICE_TYPE_WIFI,
	.enabled = false,
	.default_rules = true,
};

const char *__connman_technology_get_tethering_ident(
				struct connman_technology *tech)
{
	if (!tech)
		return NULL;

	return tech->ident;
}

const char *__connman_tethering_get_bridge(void)
{
	if (test_technology.enabled)
		return test_technology.bridge;
	return NULL;
}

enum connman_service_type __connman_technology_get_type(
					struct connman_technology *tech)
{
	if (!tech)
		return 0;

	return tech->type;
}

void connman_technology_tethering_notify(struct connman_technology *technology,
							bool enabled)
{
	return;
}

// Access dummies

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
	if (global_config_type & ACCESS_FAILURE)
		return CONNMAN_ACCESS_DENY;

	return CONNMAN_ACCESS_ALLOW;
}

// DBus dummies

DBusMessage *test_message = NULL;
GDBusMethodFunction reload_call = NULL;

gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy)
{
	int i;

	g_assert(methods);

	for (i = 0; methods[i].name; i++) {
		if (!g_strcmp0(methods[i].name, "Reload"))
			reload_call = methods[i].function;
	}

	g_assert(reload_call);

	return TRUE;
}

gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name)
{
	return TRUE;
}

// Original version from gdbus/object.c
gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message)
{
	g_assert_true(connection == NULL);
	g_assert_true(message != NULL);

	test_message = message;
	return TRUE;
}

// Copied from gdbus/object.c
DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, format);

	reply = g_dbus_create_error_valist(message, name, format, args);

	va_end(args);

	return reply;
}

// Copied from gdbus/object.c
DBusMessage *g_dbus_create_error_valist(DBusMessage *message, const char *name,
					const char *format, va_list args)
{
	char str[1024];

	if (format)
		vsnprintf(str, sizeof(str), format, args);
	else
		str[0] = '\0';

	return dbus_message_new_error(message, name, str);
}

// Copied from gdbus/object.c
gboolean g_dbus_send_reply(DBusConnection *connection,
				DBusMessage *message, int type, ...)
{
	va_list args;
	gboolean result;

	va_start(args, type);

	result = g_dbus_send_reply_valist(connection, message, type, args);

	va_end(args);

	return result;
}

// Copied from gdbus/object.c
gboolean g_dbus_send_reply_valist(DBusConnection *connection,
				DBusMessage *message, int type, va_list args)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return FALSE;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return FALSE;
	}

	return g_dbus_send_message(connection, reply);
}

// Copied from gdbus/object.c
DBusMessage *g_dbus_create_reply_valist(DBusMessage *message,
						int type, va_list args)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return NULL;
	}

	return reply;
}

// Copied from gdbus/object.c
DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, type);

	reply = g_dbus_create_reply_valist(message, type, args);

	va_end(args);

	return reply;
}

// Notifier dummies

static struct connman_notifier *firewall_notifier;
static bool notifier_fail = false;

int connman_notifier_register(struct connman_notifier *notifier)
{
	DBG("");

	g_assert(notifier);

	if (notifier_fail)
		return -EINVAL;

	if (!g_strcmp0(notifier->name, "firewall"))
		firewall_notifier = notifier;

	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
	DBG("");

	g_assert(notifier);

	firewall_notifier = NULL;
}

// Iptables dummies

struct iptables_rule {
	int type;
	gchar *table;
	gchar *chain;
	gchar *rule_spec;
};

static GSList *rules_ipv4 = NULL;
static GSList *chains_ipv4 = NULL;
static gchar *policies_ipv4[3] = { 0 };
static const gchar *tables_ipv4[] = { "nat", "mangle", "filter", "raw",
						"security", NULL};

static GSList *rules_ipv6 = NULL;
static GSList *chains_ipv6 = NULL;
static gchar *policies_ipv6[3] = { 0 };
static const gchar *tables_ipv6[] = { "raw", "mangle", "filter", NULL};

enum iptablestype {
	IPTABLES_NORMAL = 	0x0000,
	IPTABLES_CHAIN_FAIL = 	0x0002,
	IPTABLES_ADD_FAIL =	0x0004,
	IPTABLES_INS_FAIL = 	0x0008,
	IPTABLES_DEL_FAIL = 	0x0010,
	IPTABLES_POLICY_FAIL =	0x0020,
	IPTABLES_COMMIT_FAIL = 	0x0040,
	IPTABLES_ALL_CHAINS  = 	0x0080,
};

static enum iptablestype global_iptables_type = IPTABLES_NORMAL;

static void setup_iptables_params(enum iptablestype type)
{
	if (type & IPTABLES_NORMAL) {
		global_config_type = IPTABLES_NORMAL;
		DBG("IPTABLES_NORMAL");
	}

	if (type & IPTABLES_CHAIN_FAIL)
		DBG("IPTABLES_CHAIN_FAIL");

	if (type & IPTABLES_ADD_FAIL)
		DBG("IPTABLES_ADD_FAIL");

	if (type & IPTABLES_INS_FAIL)
		DBG("IPTABLES_INS_FAIL");

	if (type & IPTABLES_DEL_FAIL)
		DBG("IPTABLES_DEL_FAIL");

	if (type & IPTABLES_POLICY_FAIL)
		DBG("IPTABLES_POLICY_FAIL");

	if (type & IPTABLES_COMMIT_FAIL)
		DBG("IPTABLES_COMMIT_FAIL");
	
	if (type & IPTABLES_ALL_CHAINS)
		DBG("IPTABLES_ALL_CHAINS");

	global_iptables_type = type;
}

static struct iptables_rule *new_rule(int type, const char *table,
			const char *chain, const char *rule_spec)
{
	struct iptables_rule *rule;

	if (!table || !chain || !rule_spec)
		return NULL;

	rule = g_try_new0(struct iptables_rule, 1);

	if (!rule)
		return NULL;

	rule->type = type;
	rule->table = g_strdup(table);
	rule->chain = g_strdup(chain);
	rule->rule_spec = g_strdup(rule_spec);

	return rule;
}

static void delete_rule(struct iptables_rule *rule)
{
	if (!rule)
		return;

	g_free(rule->table);
	g_free(rule->chain);
	g_free(rule->rule_spec);

	g_free(rule);
}

static gboolean table_exists(int type, const char *table_name)
{
	int i;

	switch (type) {
	case AF_INET:
		for (i = 0; tables_ipv4[i]; i++) {
			if (!g_strcmp0(tables_ipv4[i], table_name))
				return true;
		}
		break;
	case AF_INET6:
		for (i = 0; tables_ipv6[i]; i++) {
			if (!g_strcmp0(tables_ipv6[i], table_name))
				return true;
		}
	}

	return false;
}

static gboolean is_builtin(const char *chain)
{
	int i;
	const char *builtin[] = {"INPUT", "FORWARD", "OUTPUT", NULL};

	for (i = 0; builtin[i]; i++) {
		if (!g_strcmp0(chain, builtin[i]))
			return TRUE;
	}
	return FALSE;
}

static gboolean chain_exists(int type, const char *chain)
{
	GSList *list = NULL;
	switch (type) {
	case AF_INET:
		list = chains_ipv4;
		break;
	case AF_INET6:
		list = chains_ipv6;
	}
	
	if (is_builtin(chain))
		return true;

	if (g_slist_find_custom(list, chain, (GCompareFunc)g_strcmp0))
		return true;

	return false;
}

int __connman_iptables_new_chain(int type, 
				const char *table_name,
				const char *chain)
{
	DBG("");

	if (!table_name || !chain)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (chain_exists(type, chain))
		return -EINVAL;
	
	if (global_iptables_type & IPTABLES_CHAIN_FAIL)
		return -EEXIST;

	switch (type) {
	case AF_INET:
		chains_ipv4 = g_slist_prepend(chains_ipv4, g_strdup(chain));
		break;
	case AF_INET6:
		chains_ipv6 = g_slist_prepend(chains_ipv6, g_strdup(chain));
	}

	return 0;
}

int __connman_iptables_delete_chain(int type,
				const char *table_name,
				const char *chain)
{
	DBG("");

	if (!table_name || !chain)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (is_builtin(chain)) // Builtin chains are not to be deleted
		return -EINVAL;

	if (!chain_exists(type, chain))
		return -EINVAL;

	if (global_iptables_type & IPTABLES_CHAIN_FAIL)
		return -EEXIST;

	switch (type) {
	case AF_INET:
		chains_ipv4 = g_slist_remove(chains_ipv4, chain);
		break;
	case AF_INET6:
		chains_ipv6 = g_slist_remove(chains_ipv6, chain);
	}

	return 0;
}

int __connman_iptables_flush_chain(int type,
				const char *table_name,
				const char *chain)
{
	GSList *rules = NULL, *iter, *current, *remove;
	struct iptables_rule *rule;

	DBG("");

	if (!table_name || !chain)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (!chain_exists(type, chain))
		return -EINVAL;
	
	if (global_iptables_type & IPTABLES_CHAIN_FAIL)
		return -EINVAL;

	switch (type) {
	case AF_INET:
		rules = rules_ipv4;
		break;
	case AF_INET6:
		rules = rules_ipv6;
	}

	iter = rules;

	while (iter) {
		rule = iter->data;
		current = iter; // backup current
		iter = iter->next;
		
		if (rule->type == type &&
					g_str_equal(rule->table, table_name) &&
					g_str_equal(rule->chain, chain))
		{
			remove = g_slist_remove_link(rules, current);
			
			g_assert(remove);
			
			delete_rule(remove->data);
			g_slist_free1(remove);
		}
	}

	return 0;
}

static int chain_to_index(const char *chain)
{
	if (g_str_equal("INPUT", chain))
		return 0;

	if (g_str_equal("FORWARD", chain))
		return 1;

	if (g_str_equal("OUTPUT", chain))
		return 2;

	return -EINVAL;
}

static gboolean is_valid_policy(const char *policy)
{
	if (g_str_equal("ACCEPT", policy))
		return true;

	if (g_str_equal("DROP", policy))
		return true;

	return false;
}

int __connman_iptables_change_policy(int type,
				const char *table_name,
				const char *chain,
				const char *policy)
{
	int index;

	DBG("");

	if (!table_name || !chain || !policy)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (!is_valid_policy(policy))
		return -EINVAL;

	if (global_iptables_type & IPTABLES_POLICY_FAIL)
		return -EINVAL;

	DBG("table %s chain %s policy %s", table_name, chain, policy);

	index = chain_to_index(chain);

	if (index < 0)
		return index;

	switch (type) {
	case AF_INET:
		if (policies_ipv4[index])
			g_free(policies_ipv4[index]);

		policies_ipv4[index] = g_strdup(policy);
		break;
	case AF_INET6:
		if (policies_ipv6[index])
			g_free(policies_ipv6[index]);

		policies_ipv6[index] = g_strdup(policy);
	}

	return 0;
}

int __connman_iptables_append(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	struct iptables_rule *rule;

	DBG("");

	if (!table_name || !chain || !rule_spec)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (global_iptables_type & IPTABLES_ADD_FAIL)
		return -EINVAL;

	if (global_iptables_type & IPTABLES_COMMIT_FAIL)
		return 0;

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	rule = new_rule(type, table_name, chain, rule_spec);

	switch (type) {
	case AF_INET:
		rules_ipv4 = g_slist_append(rules_ipv4, rule);
		break;
	case AF_INET6:
		rules_ipv6 = g_slist_append(rules_ipv6, rule);
	}

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	return 0;
}

int __connman_iptables_insert(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	struct iptables_rule *rule;

	DBG("");

	if (!table_name || !chain || !rule_spec)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (global_iptables_type & IPTABLES_INS_FAIL)
		return -EINVAL;

	if (global_iptables_type & IPTABLES_COMMIT_FAIL)
		return 0;

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	rule = new_rule(type, table_name, chain, rule_spec);

	switch (type) {
	case AF_INET:
		rules_ipv4 = g_slist_prepend(rules_ipv4, rule);
		break;
	case AF_INET6:
		rules_ipv6 = g_slist_prepend(rules_ipv6, rule);
	}

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	return 0;
}

int __connman_iptables_delete(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	GSList *iter = NULL;
	struct iptables_rule *rule;

	DBG("");

	if (!table_name || !chain || !rule_spec)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (global_iptables_type & IPTABLES_DEL_FAIL)
		return -EINVAL;

	if (global_iptables_type & IPTABLES_COMMIT_FAIL)
		return 0;

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	switch (type) {
	case AF_INET:
		iter = rules_ipv4;
		break;
	case AF_INET6:
		iter = rules_ipv6;
	}

	while (iter) {
		rule = iter->data;
		
		if (rule->type == type &&
					!g_strcmp0(rule->table, table_name) &&
					!g_strcmp0(rule->chain, chain) &&
					!g_strcmp0(rule->rule_spec, rule_spec)) {
			switch (type) {
				case AF_INET:
					rules_ipv4 = g_slist_remove_link(
								rules_ipv4,
								iter);
					break;
				case AF_INET6:
					rules_ipv6 = g_slist_remove_link(
								rules_ipv6,
								iter);
			}

			delete_rule(rule);
			g_slist_free1(iter);

			break;
		}

		iter = iter->next;
	}

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	return 0;
}

int __connman_iptables_commit(int type, const char *table_name)
{
	DBG("");

	if (!table_name)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;
	
	if (global_iptables_type & IPTABLES_COMMIT_FAIL)
		return -EINVAL;

	return 0;
}

static const char *connman_chains[] = { "connman-INPUT",
					"connman-FORWARD",
					"connman-OUTPUT"
};

int __connman_iptables_iterate_chains(int type, const char *table_name,
				connman_iptables_iterate_chains_cb_t cb,
				void *user_data)
{
	const char *chains[] = {
				"INPUT",
				"OUTPUT",
				"FORWARD",
				connman_chains[0],
				connman_chains[1],
				connman_chains[2],
				NULL
	};
	int i, limit = 3;

	DBG("");
	
	if (global_iptables_type & IPTABLES_ALL_CHAINS)
		limit = 6;
	
	for (i = 0; i < limit; i++)
		cb(chains[i], user_data);

	return 0;
}

int __connman_iptables_init(void)
{
	int i = 0;

	DBG("");

	rules_ipv4 = NULL;
	rules_ipv6 = NULL;
	chains_ipv4 = NULL;
	chains_ipv6 = NULL;

	for (i = 0; i < 3; i++)
		policies_ipv4[i] = policies_ipv6[i] = NULL;

	return 0;
}

static void rule_cleanup(gpointer data)
{
	struct iptables_rule *rule = data;

	delete_rule(rule);
}

void __connman_iptables_cleanup(void)
{
	int i = 0;

	DBG("");

	g_slist_free_full(rules_ipv4, rule_cleanup);
	g_slist_free_full(rules_ipv6, rule_cleanup);
	g_slist_free_full(chains_ipv4, g_free);
	g_slist_free_full(chains_ipv6, g_free);

	for (i = 0; i < 3; i++) {
		g_free(policies_ipv4[i]);
		g_free(policies_ipv6[i]);
		
		policies_ipv4[i] = policies_ipv6[i] = NULL;
	}
}

// GDir dummies 

int file_index = 0;

typedef struct _GDir {
	gboolean value;
} GDir;

GDir *g_dir_open (const gchar *path, guint flags, GError **error)
{
	if (global_config_type & DIR_ACCESS_FAILURE)
		return NULL;

	GDir *dir = g_try_new(GDir, 1);

	g_assert(dir);

	file_index = 0;

	return dir;
}

const gchar *g_dir_read_name (GDir *dir)
{
	g_assert(dir);

	DBG("%d:%s = %s", file_index, testfiles[file_index],
				config_enabled(file_index) ? "on" : "off");

	if (file_index < 5) {
		// Recurse
		if (!config_enabled(file_index)) {
			file_index++;
			return g_dir_read_name(dir);
		}

		return testfiles[file_index++];
	}
	return NULL;
}

void g_dir_close (GDir *dir)
{
	g_assert(dir);

	file_index = 0;

	g_free(dir);
}

gboolean g_file_test(const gchar *filename, GFileTest test)
{
	if (g_str_has_suffix(filename, "firewall.d/")) {

		if (global_config_type & CONFIG_ALL) {
			DBG("dir %s", filename);
			return TRUE;
		} else {
			return FALSE;
		}
	}

	if (g_strstr_len(filename, -1, "firewall.d")) {
		DBG("file in firewall.d/ (%s)", filename);
		return TRUE;
	}

	if (g_str_has_suffix(filename, "/firewall.conf")) {
		DBG("main config");
		return TRUE;
	}
	
	if (g_str_has_suffix(filename, "_tables_names")) {
		DBG("iptables names file");
		return TRUE;
	}

	DBG("invalid");

	return FALSE;
}

gboolean g_file_get_contents(const gchar *filename, gchar **contents,
			gsize *length, GError **error)
{
	if (g_str_has_suffix(filename, "ip_tables_names")) {
		*contents = g_strjoinv("\n", (gchar**)tables_ipv4);
	}
	
	if (g_str_has_suffix(filename, "ip6_tables_names")) {
		*contents = g_strjoinv("\n", (gchar**)tables_ipv6);
	}

	return TRUE;
}

// device dummies

struct connman_device {
	const char *ifname;
	bool managed;
};

static struct connman_device test_device1 = {
	.ifname = "rndis0",
	.managed = false,
};

static struct connman_device test_device2 = {
	.ifname = "usb0",
	.managed = false,
};

static struct connman_device test_device3 = {
	.ifname = NULL,
	.managed = false,
};

const char *connman_device_get_string(struct connman_device *device,
							const char *key)
{
	if (device && !g_strcmp0(key, "Interface"))
		return device->ifname;

	return NULL;
}

void connman_device_set_managed(struct connman_device *device, bool managed)
{
	if (!device)
		return;

	device->managed = managed;
}

bool connman_device_get_managed(struct connman_device *device)
{
	if (!device)
		return true;

	return device->managed;
}

/* TODO implement this properly */
bool connman_device_has_status_changed_to(struct connman_device *device,
					bool new_status)
{
	return true;
}

// End of dummies

#define CHAINS_GEN4 3
#define RULES_GEN4 (CHAINS_GEN4 + 68)
#define CHAINS_GEN6 3
#define RULES_GEN6 (CHAINS_GEN6 + 70)
#define RULES_ETH 17
#define RULES_CEL 4
#define RULES_TETH 7

/* Main config ok */
static const char *general_input[] = {
		/* All protocols with targets that are supported */
		"-p tcp -j ACCEPT",
		"-p udp -j DROP",
		"-p sctp -j LOG",
		"-p icmp -j QUEUE", /* IPv4 only */
		"-p icmpv6 -j REJECT", /* IPv6 only */
		"-p ipv6-icmp -j ACCEPT", /* IPv6 only */
		"-p esp -j DROP",
		"-p ah -j LOG",
		"-p mh -j QUEUE", /* IPv6 only */
		"-p dccp -j REJECT",
		"-p all -j ACCEPT",
		"-p udplite -j DROP",
		"-p gre -j ACCEPT",
		/* Port switches with protocols */
		"-p tcp -m tcp --dport 80 -j ACCEPT",
		"-p udp -m udp --sport 81 -j DROP",
		"-p sctp --destination-port 8088 -j LOG",
		"-p dccp --destination-port 8188 -j QUEUE",
		"-p tcp -m tcp --destination-port 993 --source-port 992 -j LOG",
		"-p udp -m udp --destination-port 997 --sport 996 -j ACCEPT",
		"-p udplite -m udplite --dport 999 --sport 998 -j REJECT",
		"-p sctp --dport 995 --source-port 994 -j DROP",
		/* Port with services and their aliases */
		"-p tcp -m tcp --dport smtp -j ACCEPT",
		"-p tcp -m tcp --dport mail -j ACCEPT",
		/* Port ranges */
		"-p tcp -m multiport --dports 23,33,44 -j ACCEPT",
		"-p tcp -m multiport --dports 33:44 -j ACCEPT",
		"-p tcp -m multiport --dports 23,33:44 -j ACCEPT",
		"-p tcp -m multiport --dports 35,33:44,40 -j ACCEPT",
		"-p tcp -m multiport --dports 35,33:44,40:60 -j ACCEPT",
		"-p tcp -m multiport --dports 23,http:https,100 -j ACCEPT",
		"-p tcp -m multiport --dports ssh,echo:http,9000 -j ACCEPT",
		/* Conntrack */
		"-p all -m conntrack --ctstate RELATED -j ACCEPT",
		"-m conntrack --ctstate NEW,ESTABLISHED,RELATED -j LOG",
		/* ICMP, using also negation */
		"-p icmp -m icmp --icmp-type 8/0 -j DROP",
		"-p ipv6-icmp -m ipv6-icmp --icmpv6-type 128/0 -j DROP",
		/* Protocols with number and text match are allowed */
		"-p 6 -m tcp --dport 9898 -j ACCEPT",
		"-p 132 --dport 6789 -j LOG",
		"-p udp -m udp --sport echo -j QUEUE",
		"-p 47 -j ACCEPT", /* gre */
		/* Negations */
		"! -p tcp -m multiport --dports 67,68,69 -j ACCEPT",
		"-p tcp ! -m multiport --dports 70,71 -j ACCEPT",
		"-p icmpv6 -m icmpv6 ! --icmpv6-type 128/0 -j DROP",
		"! -p udp ! -m udp ! --sport 23 -j ACCEPT",
		/* Interfaces are allowed with general rules */
		"-i eth0 -j ACCEPT",
		"--in-interface rndis0 -j DROP",
		"-i eth0 -o rndis0 -j ACCEPT",
		"--in-interface eth0 --out-interface eth1 -j LOG",
		 /* Treated as whitespace */
		"#-p sctp --dport 69 -j REJECT",
		/* owner match - should work in INPUT with NETFILTER_XT_MATCH_QTAGUID */
		"-m owner --uid-owner 0 -j LOG",
		"-m owner --gid-owner 0-499 -j LOG",
		NULL
};
static const char *general_output[] = {
		/* Identical rules in different chains are allowed */
		"-p tcp -m tcp --dport 80 -j ACCEPT",
		"-p udp -m udp --sport 81 -j DROP",
		"-p sctp --destination-port 8088 -j LOG",
		"-p dccp --source-port 8188 -j QUEUE",
		"-p tcp -m tcp --destination-port 993 --source-port 992 -j LOG",
		"-p udp -m udp --destination-port 997 --sport 996 -j ACCEPT",
		"-p udplite -m udplite --dport 999 --sport 998 -j REJECT",
		"-p sctp --dport 995 --source-port 994 -j DROP",
		"-p icmp -m icmp --icmp-type 8/0 -j DROP", // +1 IPv4
		"-p esp -j DROP",
		"-p ah -j LOG",
		"-p mh -j QUEUE", /* IPv6 only */
		"#-p sctp --sport 123 -j REJECT",
		/* Interfaces going out */
		"-o eth1 -j ACCEPT",
		"-o usb0 -j DROP",
		"--out-interface eth1 -j ACCEPT",
		/* owner match */
		"-m owner --uid-owner 0-499 -j ACCEPT",
		"-m owner --uid-owner 100-100 -j ACCEPT",
		"-m owner --gid-owner 0 -j DROP",
		"-m owner --socket-exists -j LOG",
		NULL
};
static const char *general_forward[] = {
		"-p all -m conntrack --ctstate RELATED,ESTABLISHED,NEW -j DROP",
		"-m ttl --ttl-eq 60 -j LOG", // +1 IPv4
		/* Basic targets */
		"-j ACCEPT",
		"-j DROP",
		"-j QUEUE",
		"-j LOG",
		"-j REJECT",
		NULL
};
static const char *policies_default[] = {"ACCEPT", "ACCEPT", "ACCEPT"};
static const char *general_policies_ok[] = { "DROP", "ACCEPT", "DROP"};
static const char *general_policies_fail[] = {"DENY", "REJECT", "ALLOW"};
static const char *eth_input[] = {
		/* Multiport with switches */
		"-p tcp -m tcp --dport 8080 -j ACCEPT",
		"-p udp -m udp --destination-port 8081 -j DROP",
		"-p tcp -m multiport --dports 22,23 -j ACCEPT",
		"-p tcp -m multiport --dports 8080:10000 -j ACCEPT",
		"-p udp -m multiport --dports 808,100,123,555,12345 -j DROP",
		"-p sctp -m multiport --sports 200:300 -j LOG",
		"-p sctp -m multiport --destination-ports 69:100 -j REJECT",
		"-p tcp -m multiport --source-ports 23,24,45,65 -j LOG",
		"-p tcp -m multiport --port 9999 -j LOG",
		"-p tcp -m multiport --ports 9999,10000 -j QUEUE",
		"-p tcp -m multiport --dport 6789 -j ACCEPT",
		"-p tcp -m multiport --sport 6789 -j DROP",
		"-p tcp -m multiport --destination-port 6789 -j LOG",
		"-p tcp -m multiport --source-port 6789 -j QUEUE",
		NULL
};
static const char *eth_output[] = {
		"-p tcp -m tcp --sport 8080 -j ACCEPT",
		"-p udp -m udp --source-port 8081 -j DROP",
		"-p sctp --sport 123 -j REJECT",
		NULL
};
static const char *cellular_input[] = {
		"-p tcp -m tcp --dport 8082 -j ACCEPT",
		"-p udp -m udp --dport 8083 -j DROP",
		NULL
};
static const char *cellular_output[] = {
		"-p tcp -m tcp --sport 8082 -j ACCEPT",
		"-p udp -m udp --sport 8083 -j DROP",
		NULL
};

/* Tethering for main */
static const char *tethering_input[] = {
		"-p udp -m multiport --dports 53,67 -j ACCEPT",
		"-p tcp -m tcp --dport 53 -j ACCEPT",
		NULL
};

static const char *tethering_forward[] = {
		"-p udp -m multiport --dports 53,67 -j ACCEPT",
		"-p tcp -m multiport --dports 1024:65535 -j ACCEPT",
		"-p tcp -m tcp --dport 22 -j DROP",
		NULL
};

static const char *tethering_output[] = {
		"-p udp -m udp --dport 68 -j ACCEPT",
		"-p tcp -m tcp --dport 53 -j ACCEPT",
		NULL
};

static const char *tethering_input_invalid[] = {
		"-p tcp -m tcp --dport 53 -j ACCEPT", // Double
		"-p tcp -m udp -j LOG", // Invalid rule
		NULL
};

#define RULES_ICMP4 47 // 46 + 1 managed chain
#define RULES_ICMP6 37 // 36 + 1 managed chain

/* ICMP RULES */
static const char *general_icmpv4[] = {
	"-p icmp -m icmp --icmp-type any -j ACCEPT",
	"-p icmp -m icmp --icmp-type echo-reply -j ACCEPT",
	"-p icmp -m icmp --icmp-type destination-unreachable -j ACCEPT",
	"-p icmp -m icmp --icmp-type network-unreachable -j ACCEPT",
	"-p icmp -m icmp --icmp-type host-unreachable -j ACCEPT",
	"-p icmp -m icmp --icmp-type protocol-unreachable -j ACCEPT",
	"-p icmp -m icmp --icmp-type port-unreachable -j ACCEPT",
	"-p icmp -m icmp --icmp-type fragmentation-needed -j ACCEPT",
	"-p icmp -m icmp --icmp-type source-route-failed -j ACCEPT",
	"-p icmp -m icmp --icmp-type network-unknown -j ACCEPT",
	"-p icmp -m icmp --icmp-type host-unknown -j ACCEPT",
	"-p icmp -m icmp --icmp-type network-prohibited -j ACCEPT",
	"-p icmp -m icmp --icmp-type host-prohibited -j ACCEPT",
	"-p icmp -m icmp --icmp-type TOS-network-unreachable -j ACCEPT",
	"-p icmp -m icmp --icmp-type TOS-host-unreachable -j ACCEPT",
	"-p icmp -m icmp --icmp-type communication-prohibited -j ACCEPT",
	"-p icmp -m icmp --icmp-type host-precedence-violation -j ACCEPT",
	"-p icmp -m icmp --icmp-type precedence-cutoff -j ACCEPT",
	"-p icmp -m icmp --icmp-type source-quench -j ACCEPT",
	"-p icmp -m icmp --icmp-type redirect -j ACCEPT",
	"-p icmp -m icmp --icmp-type network-redirect -j ACCEPT",
	"-p icmp -m icmp --icmp-type host-redirect -j ACCEPT",
	"-p icmp -m icmp --icmp-type TOS-network-redirect -j ACCEPT",
	"-p icmp -m icmp --icmp-type TOS-host-redirect -j ACCEPT",
	"-p icmp -m icmp --icmp-type echo-request -j ACCEPT",
	"-p icmp -m icmp --icmp-type router-advertisement -j ACCEPT",
	"-p icmp -m icmp --icmp-type router-solicitation -j ACCEPT",
	"-p icmp -m icmp --icmp-type time-exceeded -j ACCEPT",
	"-p icmp -m icmp --icmp-type ttl-zero-during-transit -j ACCEPT",
	"-p icmp -m icmp --icmp-type ttl-zero-during-reassembly -j ACCEPT",
	"-p icmp -m icmp --icmp-type parameter-problem -j ACCEPT",
	"-p icmp -m icmp --icmp-type ip-header-bad -j ACCEPT",
	"-p icmp -m icmp --icmp-type required-option-missing -j ACCEPT",
	"-p icmp -m icmp --icmp-type timestamp-request -j ACCEPT",
	"-p icmp -m icmp --icmp-type timestamp-reply -j ACCEPT",
	"-p icmp -m icmp --icmp-type address-mask-request -j ACCEPT",
	"-p icmp -m icmp --icmp-type address-mask-reply -j ACCEPT",
	/* Plain codes */
	"-p icmp -m icmp --icmp-type 0 -j ACCEPT",
	"-p icmp -m icmp --icmp-type 8 -j ACCEPT",
	"-p icmp -m icmp --icmp-type 128 -j ACCEPT",
	"-p icmp -m icmp --icmp-type 255 -j ACCEPT", /* 255 is max for type */
	/* Code/type */
	"-p icmp -m icmp --icmp-type 0/0 -j ACCEPT",
	"-p icmp -m icmp --icmp-type 8/1 -j ACCEPT",
	"-p icmp -m icmp --icmp-type 128/128 -j ACCEPT",
	"-p icmp -m icmp --icmp-type 255/255 -j ACCEPT",
	/* proto with number */
	"-p 1 -m icmp --icmp-type echo-reply -j ACCEPT",
	NULL,
};

static const char *general_icmpv6[] = {
	"-p icmpv6 -m icmpv6 --icmpv6-type destination-unreachable -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type no-route -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type communication-prohibited -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type beyond-scope -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type address-unreachable -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type port-unreachable -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type failed-policy -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type reject-route -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type packet-too-big -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type time-exceeded -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type ttl-exceeded -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type ttl-zero-during-transit -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type ttl-zero-during-reassembly -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type parameter-problem -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type bad-header -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type unknown-header-type -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type unknown-option -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type echo-request -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type echo-reply -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type router-solicitation -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type router-advertisement -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT",
	"-p icmpv6 -m icmpv6 --icmpv6-type redirect -j ACCEPT",
	/* Plain codes, mixed protos */
	"-p ipv6-icmp -m icmpv6 --icmpv6-type 0 -j ACCEPT",
	"-p ipv6-icmp -m icmpv6 --icmpv6-type 8 -j ACCEPT",
	"-p icmpv6 -m ipv6-icmp --icmpv6-type 128 -j ACCEPT",
	"-p icmpv6 -m ipv6-icmp --icmpv6-type 255 -j ACCEPT",
	/* Code/type */
	"-p ipv6-icmp -m ipv6-icmp --icmpv6-type 0/0 -j ACCEPT",
	"-p ipv6-icmp -m ipv6-icmp --icmpv6-type 8/1 -j ACCEPT",
	"-p ipv6-icmp -m ipv6-icmp --icmpv6-type 128/128 -j ACCEPT",
	"-p ipv6-icmp -m ipv6-icmp --icmpv6-type 255/255 -j ACCEPT",
	/* proto with number */
	"-p 58 -m ipv6-icmp --icmpv6-type echo-reply -j ACCEPT",
	"-p 58 -m icmpv6 --icmpv6-type echo-reply -j ACCEPT",
	NULL
};

#define RULES_OPTIONS4 65 // +1 for chain
#define RULES_OPTIONS6 62 // +1 for chain

static const char *general_options[] = {
	/* AH and ESP options */
	"-p ah -m ah --ahspi 12 -j ACCEPT",
	"-p ah -m ah --ahspi 12:34 -j ACCEPT",
	"-p 51 -m ah --ahspi 122:334 -j ACCEPT",
	"-p esp -m esp --espspi 14 -j ACCEPT",
	"-p esp -m esp --espspi 14:45 -j ACCEPT",
	"-p 50 -m esp --espspi 14:45 -j ACCEPT",
	/* ECN options */
	"-p tcp -m ecn --ecn-tcp-cwr -j ACCEPT",
	"-p tcp -m ecn --ecn-tcp-ece -j ACCEPT",
	"-p tcp -m ecn --ecn-ip-ect 0 -j ACCEPT",
	"-p 6 -m ecn --ecn-ip-ect 3 -j ACCEPT",
	/* helper options */
	"-p tcp -m helper --helper irc -j ACCEPT",
	"-p udp -m helper --helper echo -j ACCEPT",
	/* limit options */
	"-p tcp -m limit --limit 10/sec -j ACCEPT",
	"-p udp -m limit --limit 5/minute -j ACCEPT",
	"-p sctp -m limit --limit 2/hour -j ACCEPT",
	"-p dccp -m limit --limit 1/day -j ACCEPT",
	"-p tcp -m limit --limit-burst 5 -j DROP",
	"-p tcp -m limit --limit 6/minute --limit-burst 10 -j DROP",
	/* pkttype options */
	"-p tcp -m pkttype --pkt-type unicast -j ACCEPT",
	"-p udp -m pkttype --pkt-type broadcast -j ACCEPT",
	"-p tcp -m pkttype --pkt-type multicast -j ACCEPT",
	/* ttl options, only for IPv4 as of now */
	"-p tcp -m ttl --ttl-eq 10 -j DROP",
	"-p tcp -m ttl --ttl-lt 20 -j DROP",
	"-p tcp -m ttl --ttl-gt 30 -j DROP",
	/* dccp options */
	"-p dccp --dccp-types REQUEST -j ACCEPT",
	"-p dccp --dccp-types REQUEST,RESPONSE,DATA,ACK,DATAACK,CLOSEREQ,CLOSE,"
				"RESET,SYNC,SYNCACK,INVALID -j ACCEPT",
	"-p dccp --dccp-option 12 -j DROP",
	"-p 33 --dccp-types DATA -j ACCEPT",
	/* conntrack options */
	"-m conntrack --ctstate NEW,INVALID,ESTABLISHED,RELATED,UNTRACKED,"
				"SNAT,DNAT -j ACCEPT",
	"-m conntrack --ctproto tcp -j ACCEPT",
	"-m conntrack --ctproto 6 -j ACCEPT",
	"-m conntrack --ctproto all -j ACCEPT",
	"-m conntrack --ctorigsrcport 22 -j ACCEPT",
	"-m conntrack --ctorigsrcport ssh -j ACCEPT",
	"-m conntrack --ctorigdstport 22 -j ACCEPT",
	"-m conntrack --ctorigdstport ssh -j ACCEPT",
	"-m conntrack --ctreplsrcport 2222 -j ACCEPT",
	"-m conntrack --ctreplsrcport ssh -j ACCEPT",
	"-m conntrack --ctrepldstport 22 -j ACCEPT",
	"-m conntrack --ctrepldstport ssh -j ACCEPT",
	"-m conntrack --ctstatus NONE -j ACCEPT",
	"-m conntrack --ctstatus NONE,EXPECTED,SEEN_REPLY,ASSURED,CONFIRMED"
				" -j ACCEPT",
	"-m conntrack --ctexpire 20 -j ACCEPT",
	"-m conntrack --ctexpire 21:33 -j ACCEPT",
	"-m conntrack --ctdir ORIGINAL -j DROP",
	"-m conntrack --ctdir REPLY -j DROP",
	/* mark options */
	"-m mark --mark 1 -j ACCEPT",
	"-m mark --mark 0x01 -j DROP",
	"-m mark --mark 1/2 -j ACCEPT",
	"-m mark --mark 0x01/0x30 -j DROP",
	"-p tcp -m mark --mark 0xffff -j ACCEPT",
	"-p tcp -m mark --mark 0xDEAD -j ACCEPT",
	/* tcp options */
	"-p tcp -m tcp --tcp-flags SYN URG -j DROP",
	"-p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST,URG,PSH,ALL,NONE "
				"SYN,ACK,FIN,RST,URG,PSH,ALL,NONE -j DROP",
	"-p tcp -m tcp --syn -j ACCEPT",
	"-p 6 -m tcp --tcp-option 45 -j DROP",
	/* Long versions of options */
	"--protocol tcp -m tcp --dport 45 -j ACCEPT",
	"--protocol tcp --match tcp --dport 55 -j DROP",
	"-p tcp --match tcp --dport 56 -j LOG",
	"-p tcp -m tcp --dport 66 --jump QUEUE",
	"--protocol tcp --match tcp --dport 5555 --jump DROP",
	"--protocol gre --jump REJECT",
	/* Hostnames */
	"-d host.name.com -j DROP",
	"-s host.name.com,host2.name2.com,host3.name3.com -j DROP",
	NULL
};

#define RULES_OPTIONS_ADDR4 23 // +1 chain
#define RULES_OPTIONS_ADDR6 15 // +1 chain

static const char *general_options_address4[] = {
	/* Address options IPv4 */
	"--source 192.168.1.1 -j DROP",
	"--src 192.168.1.2/32 -j DROP",
	"-s 192.168.1.3/24 -j DROP",
	"--destination 192.168.1.3 -j DROP",
	"--dst 192.168.1.4 -j DROP",
	"-d 192.168.1.5 -j DROP",
	"--source 192.168.1.1 --destination 192.168.2.1 -j DROP",
	"-p tcp ! -s 1.2.3.4 -j DROP",
	"-s 1.2.3.4,5.6.7.8/16,9.8.7.6 -j ACCEPT",
	"-m conntrack --ctorigsrc 1.2.3.4 -j ACCEPT",
	"-m conntrack --ctorigsrc connman.org -j ACCEPT",
	"-m conntrack --ctorigdst 4.3.2.1 -j ACCEPT",
	"-m conntrack --ctorigdst connman.org -j ACCEPT",
	"-m conntrack --ctreplsrc 8.8.8.8 -j ACCEPT",
	"-m conntrack --ctreplsrc connman.org -j ACCEPT",
	"-m conntrack --ctrepldst 10.0.0.1 -j ACCEPT",
	"-m conntrack --ctrepldst connman.org -j ACCEPT",
	/* iprange match */
	"-m iprange --src-range 1.1.1.1 -j LOG",
	"-m iprange --src-range 1.1.1.2-1.1.1.2 -j LOG",
	"-m iprange --src-range 1.2.3.5-1.2.4.4 -j ACCEPT",
	"-m iprange --src-range 2.2.2.2-3.3.3.3 -j ACCEPT",
	"-m iprange --dst-range 4.4.4.4-5.5.5.5 -j ACCEPT",
	NULL
};

static const char *general_options_address6[] = {
	/* Address options IPv6 */
	"--source 2001:db8:3333:4444:5555:6666:7777:8888 -j DROP",
	"--src 2001:db8:: -j DROP",
	"-s ::1234:5678/64 -j DROP",
	"-p tcp ! -s ::1234:5678/64 -j DROP",
	"--destination 2001:db8::1234:5678 -j DROP",
	"--dst 2001:0db8:0001:0000:0000:0ab9:C0A8:0102 -j DROP",
	"-d 2001:db8:3333:4444:5555:6666:1.2.3.4 -j DROP",
	"--source 2001:db8:: --destination ::1234:5678/64 -j DROP",
	"-s 2001:db8::,::1234:5678/64,2001:db8::1234:5678/128 -j DROP",
	/* iprange match */
	"-m iprange --src-range fe80::1 -j LOG",
	"-m iprange --src-range fe80::2-fe80::2 -j LOG",
	"-m iprange --src-range fe80::3:2-fe80::4:1 -j LOG",
	"-m iprange --src-range fe80::2-fe80::10:ff -j ACCEPT",
	"-m iprange --dst-range fe80::11:00-fe80::12:ff -j ACCEPT",
	NULL
};

static const char *invalid_general_options[] = {
	/* AH and ESP options */
	"-p ah -m ah --ahspi 12-34 -j ACCEPT",
	"-p 50 -m ah --ahspi 12:34 -j ACCEPT",
	"-p mh -m ah --ahspi 12 -j ACCEPT",
	"-p ah -m tcp --ahspi 12:34 -j ACCEPT",
	"-p ah -m ah --ahspi -j ACCEPT",
	"-p ah -m ah --ahspi spi -j ACCEPT",
	"-p ah -m ah --ahspi spi:45 -j ACCEPT",
	"-p ah -m ah --ahspi spi:ips -j ACCEPT",
	"-p esp -m esp --espspi 14-45 -j ACCEPT",
	"-p tcp -m esp --espspi 14 -j ACCEPT",
	"-p 51 -m esp --espspi 14 -j ACCEPT",
	"-p esp -m udp --espspi 14:45 -j ACCEPT",
	"-p esp -m esp --espspi -j ACCEPT",
	"-p esp -m esp --espspi spi -j ACCEPT",
	"-p esp -m esp --espspi spi:14 -j ACCEPT",
	"-p esp -m esp --espspi spi:ips -j ACCEPT",
	/* ECN options */
	"-p 17 -m ecn --ecn-tcp-cwr -j ACCEPT",
	"-p udp -m ecn --ecn-tcp-ece -j ACCEPT",
	"-p all -m ecn --ecn-ip-ect 0 -j ACCEPT",
	"-p ecn -m ecn --ecn-ip-ect 3 -j ACCEPT",
	"-p tcp -m ecn --ecn-ip-ect -1 -j ACCEPT",
	"-p tcp -m ecn --ecn-ip-ect 4 -j ACCEPT",
	"-p tcp -m tcp --ecn-ip-ect 1 -j ACCEPT",
	/* helper options */
	"-p tcp -m tcp --helper irc -j ACCEPT",
	/* limit options */
	"-p tcp -m tcp --limit 10/sec -j ACCEPT",
	"-p tcp -m tcp --limit-burst 5 -j DROP",
	"-p tcp -m tcp --limit 6/minute --limit-burst 10 -j DROP",
	"-p tcp -m limit --limit none -j ACCEPT",
	"-p tcp -m limit --limit 10/year -j ACCEPT",
	"-p tcp -m limit --limit ten/sec -j ACCEPT",
	"-p tcp -m limit --limit-burst ten -j ACCEPT",
	/* pkttype options */
	"-p tcp -m tcp --pkt-type unicast -j ACCEPT",
	"-p udp -m tcp --pkt-type broadcast -j ACCEPT",
	"-p tcp -m tcp --pkt-type multicast -j ACCEPT",
	"-p tcp -m pkttype --pkttype singlecast -j ACCEPT",
	/* ttl options, only for IPv4 */
	"-p tcp -m ttl --ttl-eq ten -j DROP",
	"-p tcp -m ttl --ttl-lt ten -j DROP",
	"-p tcp -m ttl --ttl-gt ten -j DROP",
	/* dccp options */
	"-p dccp --dccp-types REQUESTED -j ACCEPT",
	"-p dccp --dccp-types REQUEST,RESPONSE:DATA,ACK,DATAACK,CLOSEREQ,CLOSE,"
				"RESET,SYNC,SYNCACK,INVALID -j ACCEPT",
	"-p dccp --dccp-option DATA -j DROP",
	/* conntrack options */
	"-m conntrack --ctstate NEW;INVALID,ESTABLISHED,RELATED,UNTRACKED,"
				"SNAT,DNAT -j ACCEPT",
	"-m conntrack --ctstate UNVALID -j ACCEPT",
	"-m conntrack --ctstate 12 -j ACCEPT",
	"-m conntrack --ctproto tcplite -j ACCEPT",
	"-m conntrack --ctproto 256 -j ACCEPT",
	"-m conntrack --ctorigsrcport dummy -j ACCEPT",
	"-p tcp -m tcp --ctorigdstport 22 -j ACCEPT",
	"-p tcp -m tcp --ctorigdstport dummy -j ACCEPT",
	"-m conntrack --ctreplsrcport 222222 -j ACCEPT",
	"-m conntrack --ctreplsrcport ssha -j ACCEPT",
	"-m conntrack --ctrepldstport 0 -j ACCEPT",
	"-m conntrack --ctrepldstport sshd -j ACCEPT",
	"-m conntrack --ctorigsrc 1.2.3.4/40 -j ACCEPT",
	"-m conntrack --ctorigsrc connman.org,1.2.3.4/34 -j ACCEPT",
	"-m conntrack --ctorigdst 4.3.2.1/44 -j ACCEPT",
	"-m conntrack --ctreplsrc 8.8.8.8/56 -j ACCEPT",
	"-m conntrack --ctrepldst 10.0.0.1/66 -j ACCEPT",
	"-m conntrack --ctstatus NON -j ACCEPT",
	"-m conntrack --ctstatus NONE:EXPECTED,SEEN_REPLY,ASSURED,CONFIRMED"
				" -j ACCEPT",
	"-m conntrack --ctexpire today -j ACCEPT",
	"-m conntrack --ctexpire today:33 -j ACCEPT",
	"-m conntrack --ctexpire today:tomorrow -j ACCEPT",
	"-m conntrack --ctdir 1 -j DROP",
	"-m conntrack --ctdir REPLYED -j DROP",
	/* mark options */
	"-p tcp -m tcp --mark 1 -j ACCEPT",
	"-m mark --mark one -j ACCEPT",
	"-m mark --mark 0xx01 -j DROP",
	"-m mark --mark one/2 -j ACCEPT",
	"-m mark --mark 2/three -j DROP",
	"-m mark --mark 0xDEADBEEFY -j QUEUE",
	/* tcp options */
	"-p udp -m tcp --tcp-flags SYN URG -j DROP",
	"-p tcp -m sctp --tcp-flags SYN URG -j DROP",
	"-p tcp -m tcp --tcp-flags SYNC URGENT -j DROP",
	"-p tcp -m tcp --tcp-flags SYNC URG -j DROP",
	"-p tcp -m tcp --tcp-flags SYN URGENT -j DROP",
	"-p tcp -m tcp --tcp-flags SYN SYN:ACK,FIN -j DROP",
	"-p tcp -m tcp --tcp-flags SYN:ACK,FIN,RST,URG,PSH,ALL,NONE "
				"SYN;ACK,FIN,RST,URG,PSH,ALL,NONE -j DROP",
	"-m tcp --syn -j ACCEPT",
	"-p tcp -m tcp --tcp-option option45 -j DROP",
	"-p 50 -m tcp --tcp-option 45 -j DROP",
	/* disabled mh options */
	"-p mh -m mh --mh-type 1 -j ACCEPT",
	"-p mobility-header -m mh --mh-type 2 -j ACCEPT",
	"-p 135 -m mh --mh-type 3 -j DROP",
	"-p mh --mh-type 1 -j ACCEPT",
	"-p mobility-header --mh-type 2 -j ACCEPT",
	"-p 135 --mh-type 3 -j DROP",
	/* disabled sctp options */
	"-p sctp -m sctp --chunk-types all SACK -j DROP",
	"-p sctp -m sctp --chunk-types any DATA:Be,INIT -j DROP",
	"-p 132 -m sctp --chunk-types only SHUTDOWN_COMPLETE:T,DATA:Bi -j DROP",
	"-p sctp --chunk-types all SACK -j DROP",
	"-p sctp --chunk-types any DATA:Be,INIT -j DROP",
	"-p 132 --chunk-types only SHUTDOWN_COMPLETE:T,DATA:Bi -j DROP",
	/* port switches defined twice */
	"-p tcp -m tcp --dport 34 --destination-port 44 -j ACCEPT",
	"-p tcp -m tcp --destination-port 44 --dport 34 -j ACCEPT",
	"-p tcp -m tcp --sport 34 --source-port 44 -j ACCEPT",
	"-p tcp -m tcp --source-port 44 --sport 34 -j ACCEPT",
	/* multiport switches */
	"-p tcp -m multiport --dports 22,23 --sports 10:1000 -j ACCEPT",
	"-p sctp -m multiport --dports 6999 --sports 200:300 -j LOG",
	"-p sctp -m multiport --destination-ports 69:100 "
				"--sports 100,200 -j REJECT",
	"-p tcp -m multiport --dports 6060:50000 "
				"--source-ports 23,24,45,65 -j LOG",
	"-p udp -m multiport --destination-ports 1000:3000 "
				"--source-ports 2000:4000 -j DROP",
	"-p tcp -m multiport --dports 34 --destination-port 44 -j ACCEPT",
	"-p tcp -m multiport --dports 34 --destination-ports 44 -j ACCEPT",
	"-p tcp -m multiport --dports 34 --dports 44 -j ACCEPT",
	"-p tcp -m multiport --dports 34 --dport 44 -j ACCEPT",
	"-p tcp -m multiport --dports 34 --ports 44 -j ACCEPT",
	"-p tcp -m multiport --dports 34 --port 44 -j ACCEPT",
	"-p tcp -m multiport --destination-ports 34 --destination-port 44 "
				"-j ACCEPT",
	"-p tcp -m multiport --destination-ports 34 --destination-ports 44 "
				"-j ACCEPT",
	"-p tcp -m multiport --destination-ports 34 --dports 44 -j ACCEPT",
	"-p tcp -m multiport --destination-ports 34 --dport 44 -j ACCEPT",
	"-p tcp -m multiport --destination-ports 34 --ports 44 -j ACCEPT",
	"-p tcp -m multiport --destination-ports 34 --port 44 -j ACCEPT",
	"-p tcp -m multiport --sports 34 --source-port 44 -j ACCEPT",
	"-p tcp -m multiport --sports 34 --source-ports 44 -j ACCEPT",
	"-p tcp -m multiport --sports 34 --sports 44 -j ACCEPT",
	"-p tcp -m multiport --sports 34 --sport 44 -j ACCEPT",
	"-p tcp -m multiport --sports 34 --ports 44 -j ACCEPT",
	"-p tcp -m multiport --sports 34 --port 44 -j ACCEPT",
	"-p tcp -m multiport --source-ports 34 --source-port 44 -j ACCEPT",
	"-p tcp -m multiport --source-ports 34 --source-ports 44 -j ACCEPT",
	"-p tcp -m multiport --source-ports 34 --sports 44 -j ACCEPT",
	"-p tcp -m multiport --source-ports 34 --sport 44 -j ACCEPT",
	"-p tcp -m multiport --source-ports 34 --ports 44 -j ACCEPT",
	"-p tcp -m multiport --source-ports 34 --port 44 -j ACCEPT",
	"-p tcp -m multiport --port 34 --port 44 -j ACCEPT",
	"-p tcp -m multiport --ports 44 --port 34 -j ACCEPT",
	"-p tcp -m multiport --ports 34 --ports 44 -j ACCEPT",
	"-p tcp -m multiport --port 44 --ports 34 -j ACCEPT",
	/* Port ranges not valid for single port switches */
	"-p tcp -m tcp --dport 34,35 -j ACCEPT",
	"-p tcp -m tcp --sport 34:35 -j ACCEPT",
	"-p tcp -m tcp --sport echo:35 -j ACCEPT",
	"-p tcp -m tcp --sport ssh,http -j ACCEPT",
	/* Port ranges */
	"-p tcp -m multiport --dports 44:44 -j ACCEPT",
	"-p tcp -m multiport --dports 44:,56 -j ACCEPT",
	"-p tcp -m multiport --dports ssh:,55 -j ACCEPT",
	"-p tcp -m multiport --dports 22,ssh:,55 -j ACCEPT",
	"-p tcp -m multiport --dports 22,sshd:55 -j ACCEPT",
	"-p tcp -m multiport --dports 22a,ssh:55 -j ACCEPT",
	"-p tcp -m multiport --dports 46:44 -j ACCEPT",
	"-p tcp -m multiport --dports 23:45:80 -j ACCEPT",
	"-p tcp -m multiport --dports 35,44:40,40 -j ACCEPT",
	"-p tcp -m multiport --dports https:http -j ACCEPT",
	"-p tcp -m multiport --dports https:50 -j ACCEPT",
	"-p tcp -m multiport --dports 8000:http -j ACCEPT",
	"-p tcp -m multiport --dports ssh,http:echo,9000 -j ACCEPT",
	"-p tcp -m multiport --dports ssh,http:echo:http,9000 -j ACCEPT",
	/* Invalid protocol for service name */
	"-p tcp -m tcp --dport s1-control -j DROP", // SCTP service
	"-p udp -m udp --sport rxapi -j ACCEPT",  // TCP service
	/* rxapi = TCP, pim-port = TCP/SCTP, iadt-tls = TCP, lcs-ap = SCTP */
	"-p udp -m multiport --dports rxapi,pim-port,iadt-tls:lcs-ap -j DROP",
	/* Matches without options */
	"-p tcp -m multiport -j ACCEPT",
	"-p tcp -m tcp -m multiport -j DROP",
	"-m tcp -j LOG",
	"-m iprange -j LOG",
	/* Interfaces */
	"-i eth0 -i eth1 -j DROP",
	"-i eth0 -o eth1 -i rndis0 -j DROP",
	"-o eth1 -i eth0 -o eth0 -j DROP",
	"--in-interface eth0 --in-interface eth1 -j DROP",
	"--in-interface eth1 -i eth0 -j DROP",
	"--out-interface eth0 --out-interface eth0 -j DROP",
	"--out-interface eth0 -o eth1 -j DROP",
	"-i ! eth1 -j DROP",
	"-i ! eth1 -o ! eth0 -j ACCEPT",
	/* iprange match */
	"-m iprange --src-range '' -j ACCEPT",
	"-m iprange --src-range 1.1.1.1- -j ACCEPT",
	"-m iprange --src-range 3.3.3.3-2.2.2.2 -j ACCEPT",
	"-m iprange --src-range 1.2.4.4-1.2.3.5 -j ACCEPT",
	"-m iprange --src-range 3.3.3.3-2.2.2.2-1.1.1.1 -j ACCEPT",
	"-m iprange --dst-range fe80::12:ff-fe80::11:00 -j ACCEPT",
	"-m iprange --dst-range 1.1.1.1-fe80::11:00 -j ACCEPT",
	"-m iprange --dst-range fe80::12:ff-2.2.2.2 -j ACCEPT",
	NULL
};

/* Main config with invalid rules */
static const char *invalid_general_input[] = {
		/* Match has to have options */
		"-p tcp -m tcp -j ACCEPT",
		"-p udp -m udp -j DROP",
		/* Matches cannot be defined as protocol integers */
		"-p 6 -m 6 --dport https -j LOG",
		/* Only one target */
		"-p tcp -m tcp --dport 80 -j ACCEPT -j DROP",
		/* Protocol omitted */
		"udp -m udp --dport 81 -j DROP",
		/* -m sctp is not supported */
		"-p sctp -m sctp --dport 5678 -j ACCEPT",
		/* -m mh is not supported */
		"-p mh -m mh -j ACCEPT",
		"-p mh -m mh --mh-type binding-refresh-request -j LOG",
		"-p mh -m mh --mh-type cot:be -j DROP",
		/* -m dccp is not supported */
		"-p dccp -m dccp --source-port 8188 -j QUEUE",
		/* One protocol only */
		"-p tcp -p all -m conntrack --ctstate RELATED -j ACCEPT",
		/* State is disabled */
		"-p tcp -m state --state NEW -j ACCEPT",
		/* Comment is disabled, TODO lone --comment must be disabled */
		"-p tcp -m tcp --dport 22 -j ACCEPT -m comment --comment test",
		/* Protocol gre has no options or match support*/
		"-p gre --dport 55 -j ACCEPT",
		"-p gre -m gre -j ACCEPT",
		"-p gre -m gre --dport 56 -j DROP",
		"-p 47 -m gre -j DROP",
		/* ICMP v4*/
		"-p icmp -m icmpv6 --icmp-type 8 -j ACCEPT",
		"-p icmp -m icmp --icmp-type 8/ -j ACCEPT",
		"-p icmp -m icmp --icmp-type 8/a -j ACCEPT",
		"-p icmp -m icmp --icmp-type echo-reguest -j ACCEPT",
		"-p icmp -m icmp --icmp-type 300 -j ACCEPT",
		"-p icmp -m icmp --icmp-type 8/300 -j ACCEPT",
		"-p icmp -m icmp --icmp-type 256/256 -j ACCEPT",
		"-p icmp -m icmp --icmp-type 10000/10000 -j ACCEPT",
		"-p icmp -m icmp --icmp-type -j ACCEPT",
		"-p icmp -m icmp -j ACCEPT",
		/* ICMP v6 */
		"-p icmpv6 -m icmp --icmp-type 8 -j ACCEPT",
		"-p icmpv6 -m icmp --icmpv6-type 8 -j ACCEPT",
		"-p icmpv6 -m icmpv6 --icmp-type 8 -j ACCEPT",
		"-p ipv6-icmp -m icmpv6 --icmp-type tll-exceeded -j ACCEPT",
		"-p ipv6-icmp -m icmpv6 --icmp-type /255 -j ACCEPT",
		/* Source or destination modifiers cannot be used twice */
		"--source 1.2.3.4 --source 4.3.2.1 -j ACCEPT",
		"--src 1.2.3.4 --src 4.3.2.1 -j ACCEPT",
		"-s 1.2.3.4 -s 4.3.2.1 -j ACCEPT",
		"--destination 1.2.3.4 --destination 4.3.2.1 -j ACCEPT",
		"--dst 1.2.3.4 --dst 4.3.2.1 -j ACCEPT",
		"-d 1.2.3.4 -d 4.3.2.1 -j ACCEPT",
		"-d 1.2.3.4 -s 4.3.2.1 -d 9.8.7.6 -j ACCEPT",
		/* Invalid netmask use */
		"-s 1.9.2.6//32 -j DROP",
		"-d 2.3.4.5/33 -j DROP",
		"-s 10.0.0.1/20/24 -j DROP",
		"-d 2.3.4.5/255.255.255.256 -j ACCEPT",
		"-s host.name.com/32 -j ACCEPT",
		"-d host.name.com/255.255.255.0 -j ACCEPT",
		"-s ! 1.2.3.4 -j ACCEPT",
		/* Invalid switches */
		"-4 -p tcp -j ACCEPT",
		"--ipv4 -p tcp -j ACCEPT",
		"-6 -p tcp -j ACCEPT",
		"--ipv6 -p tcp -j ACCEPT",
		"-f -p udp -m udp --dport 45 -j DROP",
		"--fragment -p udp -m udp --dport 45 -j DROP",
		NULL
};
static const char *invalid_general_output[] = {
		/* One target only, max 2 port speficiers */
		/* TODO two same port specifiers should be disabled */
		"-p tcp -m tcp --sport 80 -j ACCEPT -j ACCEPT -j DROP",
		"-p udp -m udp --sport 81 --dport 50 --dport 40 -j DROP",
		/* No target modifier */
		"DROP",
		/* Disabled matches */
		"-m recent --name example --check --seconds 60",
		/* Multiport cannot be used in conjunction of -m protocol */
		/* TODO this is iptables.c limitation, fix it */
		"-p tcp -m tcp -m multiport 45:8000 -j ACCEPT",
		/* Clearly invalid */
		"-p tcp -m",
		"-p  ",
		"!",
		"--portocol tcp -j ACCEPT",
		"-p tcp --motch tcp -j DROP",
		"--p tcp -m tcp -j LOG",
		/* Empty port specifiers for multiport*/
		"-p tcp -m multiport --dport -j ACCEPT",
		"-p tcp -m multiport --sport -j DROP",
		"-p tcp -m multiport --dports -j ACCEPT",
		"-p tcp -m multiport --destination-port -j LOG",
		"-p tcp -m multiport --source-port -j QUEUE",
		"-p tcp -m multiport --dport --sport  -j REJECT",
		/* Incorrect users for owner match */
		"-m owner --uid-owner 100-0 -j LOG",
		"-m owner --uid-owner 4294967295 -j LOG", /* UINT32_MAX-1 */
		"-m owner --uid-owner 17179869184 -j LOG", /* 2^34 */
		"-m owner --uid-owner user-absent -j LOG",
		"-m owner --uid-owner nonexistent -j LOG",
		NULL
};
static const char *invalid_general_forward[] = {
		/* Double target */
		"-j ACCEPT -j DROP",
		/* Invalid multiport range */
		"-p udp -m multiport --dports 11-4000 -j ACCEPT",
		/* No protocol and double match */
		"-m multiport -m tcp --dports 70:111 -j ACCEPT",
		/* Double match */
		"-p tcp -m multiport -m tcp --dports 555:666 -j ACCEPT",
		/* No protocol */
		"-p -j DROP",
		/* Invalid targets */
		"-p tcp -j DORP",
		"-p tcp -j connman-INPUT",
		"-p tcp -j own-table-name",
		NULL
};
static const char *invalid_eth_input[] = {
		"-p tcp -m tcp --dport 80 -j ACCEPT -j DROP",
		"udp -m udp --dport 81 -j DROP",
		"-p tcp -p all -m conntrack --ctstate RELATED -j ACCEPT",
		"-i eth0 -j LOG",
		"--in-interface eth0 -j LOG",
		NULL
};
static const char *invalid_eth_output[] = {
		"-p tcp -m tcp --sport 80 -j ACCEPT -j ACCEPT -j DROP",
		"-p udp -m udp --sport 81 --dport 50 --dport 40 -j DROP",
		"DROP",
		"-o eth1 -j QUEUE",
		"--out-interface eth1 -j QUEUE",
		"-m tcp --dport 8888 -j DROP",
		NULL
};

static gboolean setup_main_config(GKeyFile *config)
{
	g_assert(config);

	if (global_config_type & GLOBAL_NOT_SET){
		DBG("invalid global_config_type");
		return FALSE;
	}

	if (global_config_type & CONFIG_MAIN_INVALID) {
		DBG("invalid main config");
		
		g_key_file_set_string_list(config, "invalid",
					"IPv4.INPUT.RULES", general_input,
					g_strv_length((char**)general_input));

		g_key_file_set_string_list(config, "General",
					"IPv4.OUTPUT.RULE", general_output,
					g_strv_length((char**)general_output));

		g_key_file_set_string_list(config, "General",
					"IPv8.INPUT.RULES", general_input,
					g_strv_length((char**)general_input));

		g_key_file_set_string_list(config, "General",
					"IPv6.OUTGOING.RULES", general_output,
					g_strv_length((char**)general_output));
		return TRUE;
	}

	if (global_config_type & CONFIG_OK ||
				global_config_type & CONFIG_MIXED) {
		DBG("ok or mixed");
		g_key_file_set_string_list(config, "General",
					"IPv4.INPUT.RULES", general_input,
					g_strv_length((char**)general_input));

		g_key_file_set_string_list(config, "General",
					"IPv4.OUTPUT.RULES", general_output,
					g_strv_length((char**)general_output));

		g_key_file_set_string_list(config, "General",
					"IPv4.FORWARD.RULES", general_forward,
					g_strv_length((char**)general_forward));

		g_key_file_set_string_list(config, "ethernet",
					"IPv4.INPUT.RULES", eth_input,
					g_strv_length((char**)eth_input));

		g_key_file_set_string_list(config, "ethernet",
					"IPv4.OUTPUT.RULES", eth_output,
					g_strv_length((char**)eth_output));

		g_key_file_set_string_list(config, "cellular",
					"IPv4.INPUT.RULES", cellular_input,
					g_strv_length((char**)cellular_input));

		g_key_file_set_string_list(config, "cellular",
					"IPv4.OUTPUT.RULES", cellular_output,
					g_strv_length((char**)cellular_output));

		// IPv6
		g_key_file_set_string_list(config, "General",
					"IPv6.INPUT.RULES", general_input,
					g_strv_length((char**)general_input));

		g_key_file_set_string_list(config, "General",
					"IPv6.OUTPUT.RULES", general_output,
					g_strv_length((char**)general_output));

		g_key_file_set_string_list(config, "General",
					"IPv6.FORWARD.RULES", general_forward,
					g_strv_length((char**)general_forward));

		g_key_file_set_string_list(config, "ethernet",
					"IPv6.INPUT.RULES", eth_input,
					g_strv_length((char**)eth_input));

		g_key_file_set_string_list(config, "ethernet",
					"IPv6.OUTPUT.RULES", eth_output,
					g_strv_length((char**)eth_output));

		g_key_file_set_string_list(config, "cellular",
					"IPv6.INPUT.RULES", cellular_input,
					g_strv_length((char**)cellular_input));

		g_key_file_set_string_list(config, "cellular",
					"IPv6.OUTPUT.RULES", cellular_output,
					g_strv_length((char**)cellular_output));
	}

	if (global_config_type & CONFIG_INVALID) {
		DBG("invalid");
		g_key_file_set_string_list(config, "General",
					"IPv4.INPUT.RULES",
					invalid_general_input,
					g_strv_length(
					(char**)invalid_general_input));

		g_key_file_set_string_list(config, "General",
					"IPv4.OUTPUT.RULES",
					invalid_general_output,
					g_strv_length(
					(char**)invalid_general_output));

		g_key_file_set_string_list(config, "General",
					"IPv4.FORWARD.RULES",
					invalid_general_forward,
					g_strv_length(
					(char**)invalid_general_forward));

		g_key_file_set_string_list(config, "ethernet",
					"IPv4.INPUT.RULES",
					invalid_eth_input,
					g_strv_length(
					(char**)invalid_eth_input));

		g_key_file_set_string_list(config, "ethernet",
					"IPv4.OUTPUT.RULES",
					invalid_eth_output,
					g_strv_length(
					(char**)invalid_eth_output));
		
		// IPv6
		g_key_file_set_string_list(config, "General",
					"IPv6.INPUT.RULES",
					invalid_general_input,
					g_strv_length(
					(char**)invalid_general_input));

		g_key_file_set_string_list(config, "General",
					"IPv6.OUTPUT.RULES",
					invalid_general_output,
					g_strv_length(
					(char**)invalid_general_output));

		g_key_file_set_string_list(config, "General",
					"IPv6.FORWARD.RULES",
					invalid_general_forward,
					g_strv_length(
					(char**)invalid_general_forward));

		g_key_file_set_string_list(config, "ethernet",
					"IPv6.INPUT.RULES",
					invalid_eth_input,
					g_strv_length(
					(char**)invalid_eth_input));

		g_key_file_set_string_list(config, "ethernet",
					"IPv6.OUTPUT.RULES",
					invalid_eth_output,
					g_strv_length(
					(char**)invalid_eth_output));
	}

	/*
	 * Group change is required because otherwise groups would be
	 * overwritten
	 */
	if (global_config_type & CONFIG_MIXED) {
		DBG("mixed");
		g_key_file_set_string_list(config, "wifi",
					"IPv4.INPUT.RULES",
					invalid_general_input,
					g_strv_length(
					(char**)invalid_general_input));

		g_key_file_set_string_list(config, "wifi",
					"IPv4.OUTPUT.RULES",
					invalid_general_output,
					g_strv_length(
					(char**)invalid_general_output));

		g_key_file_set_string_list(config, "wifi",
					"IPv4.FORWARD.RULES",
					invalid_general_forward,
					g_strv_length(
					(char**)invalid_general_forward));

		g_key_file_set_string_list(config, "vpn",
					"IPv4.INPUT.RULES",
					invalid_eth_input,
					g_strv_length(
					(char**)invalid_eth_input));

		g_key_file_set_string_list(config, "vpn",
					"IPv4.OUTPUT.RULES",
					invalid_eth_output,
					g_strv_length(
					(char**)invalid_eth_output));
		
		// IPv6
		g_key_file_set_string_list(config, "wifi",
					"IPv6.INPUT.RULES",
					invalid_general_input,
					g_strv_length(
					(char**)invalid_general_input));

		g_key_file_set_string_list(config, "wifi",
					"IPv6.OUTPUT.RULES",
					invalid_general_output,
					g_strv_length(
					(char**)invalid_general_output));

		g_key_file_set_string_list(config, "wifi",
					"IPv6.FORWARD.RULES",
					invalid_general_forward,
					g_strv_length(
					(char**)invalid_general_forward));

		g_key_file_set_string_list(config, "vpn",
					"IPv6.INPUT.RULES",
					invalid_eth_input,
					g_strv_length(
					(char**)invalid_eth_input));

		g_key_file_set_string_list(config, "vpn",
					"IPv6.OUTPUT.RULES",
					invalid_eth_output,
					g_strv_length(
					(char**)invalid_eth_output));
	}

	if (global_config_type & CONFIG_TETHERING) {
		g_key_file_set_string_list(config, "tethering",
					"IPv4.INPUT.RULES",
					tethering_input,
					g_strv_length((char**)tethering_input));
		g_key_file_set_string_list(config, "tethering",
					"IPv4.FORWARD.RULES",
					tethering_forward,
					g_strv_length(
					(char**)tethering_forward));
		g_key_file_set_string_list(config, "tethering",
					"IPv4.OUTPUT.RULES",
					tethering_output,
					g_strv_length(
					(char**)tethering_output));
		g_key_file_set_string_list(config, "tethering",
					"IPv6.INPUT.RULES",
					tethering_input,
					g_strv_length((char**)tethering_input));
		g_key_file_set_string_list(config, "tethering",
					"IPv6.FORWARD.RULES",
					tethering_forward,
					g_strv_length(
					(char**)tethering_forward));
		g_key_file_set_string_list(config, "tethering",
					"IPv6.OUTPUT.RULES",
					tethering_output,
					g_strv_length(
					(char**)tethering_output));
	}

	if (global_config_type & CONFIG_OK &&
				global_config_type & CONFIG_USE_POLICY) {
		g_key_file_set_string(config, "General", "IPv4.INPUT.POLICY",
					general_policies_ok[0]);
		g_key_file_set_string(config, "General", "IPv4.FORWARD.POLICY",
					general_policies_ok[1]);
		g_key_file_set_string(config, "General", "IPv4.OUTPUT.POLICY",
					general_policies_ok[2]);
		g_key_file_set_string(config, "General", "IPv6.INPUT.POLICY",
					general_policies_ok[0]);
		g_key_file_set_string(config, "General", "IPv6.FORWARD.POLICY",
					general_policies_ok[1]);
		g_key_file_set_string(config, "General", "IPv6.OUTPUT.POLICY",
					general_policies_ok[2]);
	}

	if (global_config_type & CONFIG_INVALID &&
				global_config_type & CONFIG_USE_POLICY) {
		g_key_file_set_string(config, "General", "IPv4.INPUT.POLICY",
					general_policies_fail[0]);
		g_key_file_set_string(config, "General", "IPv4.FORWARD.POLICY",
					general_policies_fail[1]);
		g_key_file_set_string(config, "General", "IPv4.OUTPUT.POLICY",
					general_policies_fail[2]);
		g_key_file_set_string(config, "General", "IPv6.INPUT.POLICY",
					general_policies_fail[0]);
		g_key_file_set_string(config, "General", "IPv6.FORWARD.POLICY",
					general_policies_fail[1]);
		g_key_file_set_string(config, "General", "IPv6.OUTPUT.POLICY",
					general_policies_fail[2]);
	}

	if (global_config_type & CONFIG_ICMP_ONLY) {
		g_key_file_set_string_list(config, "General",
					"IPv4.INPUT.RULES",
					general_icmpv4,
					g_strv_length((char**)general_icmpv4));
		g_key_file_set_string_list(config, "General",
					"IPv6.INPUT.RULES",
					general_icmpv6,
					g_strv_length((char**)general_icmpv6));
	}

	if (global_config_type & CONFIG_OPTIONS_ONLY) {
		if (global_config_type & CONFIG_INVALID) {
			g_key_file_set_string_list(config, "General",
					"IPv4.INPUT.RULES",
					invalid_general_options,
					g_strv_length(
					(char**)invalid_general_options));
			g_key_file_set_string_list(config, "General",
					"IPv6.INPUT.RULES",
					invalid_general_options,
					g_strv_length(
					(char**)invalid_general_options));
		} else if (global_config_type & CONFIG_OPTIONS_ADDR) {
			g_key_file_set_string_list(config, "General",
					"IPv4.INPUT.RULES",
					general_options_address4,
					g_strv_length(
					(char**)general_options_address4));
			g_key_file_set_string_list(config, "General",
					"IPv6.INPUT.RULES",
					general_options_address6,
					g_strv_length(
					(char**)general_options_address6));
		} else {
			g_key_file_set_string_list(config, "General",
					"IPv4.INPUT.RULES",
					general_options,
					g_strv_length((char**)general_options));
			g_key_file_set_string_list(config, "General",
					"IPv6.INPUT.RULES",
					general_options,
					g_strv_length((char**)general_options));
		}
	}

	return TRUE;
}

#define RULES_CEL_ADD0 3
#define RULES_ETH_ADD1 2
#define RULES_CEL_ADD2 2
#define RULES_ETH_ADD3 3

// Cellular
static const char *cel_input_add0[] = {
			"-p udp -m udp --dport 12000 -j LOG",
			"-p tcp -m tcp --dport 12001 -j QUEUE",
			"-p dccp --dport 12002 -j REJECT",
			NULL,
};

static const char *input_fail0[] = {
			"-p sctp -m tcp -j ACCEPT",
			"-p udplite -m udp -j DROP",
			"-m state -j DROP",
			NULL,
};

// Ethernet
static const char *eth_input_add1[] = {
			"-m mark --mark 1 -j DROP",
			"-p ah -j ACCEPT",
			NULL,
};

static const char *input_fail1[] = {
			"-o eth1 -p tcp -m tcp --dport -j DROP",
			"-i eth1 -o eth2 -j ACCEPT",
			NULL,
};

// Cellular
static const char *cel_input_add2[] = {
			"-j ACCEPT",
			"-p sctp -j DROP",
			NULL,
};

static const char *input_fail2[] = {
			"-p udp -j",
			"-m -j DROP",
			NULL,
};

// Ethernet
static const char *eth_input_add3[] = {
			"-p dccp --sport 34 --dport 55 -j ACCEPT",
			"-p dccp -m multiport --ports 56:67 -j DROP",
			"-p all -m conntrack --ctstate NEW -j ACCEPT",
			NULL,
};

static const char *input_fail3[] = {
			"-m DROP",
			NULL,
};

static const char **input_ok_rules[4] = {
			cel_input_add0,
			eth_input_add1,
			cel_input_add2,
			eth_input_add3,
};

static const char **input_fail_rules[4] = {
			input_fail0,
			input_fail1,
			input_fail2,
			input_fail3,
};

gboolean setup_config(GKeyFile *config, int config_index)
{
	g_assert(config);
	gchar *config_group;

	DBG("%d", config_index);

	switch (config_index) {
	case 0: // "10-firewall.conf"
		config_group = g_strdup("cellular");
		break;
	case 1: // "30-firewall.conf"
		config_group = g_strdup("ethernet");
		break;
	case 2: // "20-firewall.conf"
		config_group = g_strdup("cellular");
		break;
	case 3: // "01-firewall.conf"
		config_group = g_strdup("ethernet");
		break;
	case 4: // NULL, nothing to add
		return TRUE;
	default:
		return FALSE;
	}

	if (global_config_type & CONFIG_OK ||
				global_config_type & CONFIG_MIXED) {
		DBG("ok or mixed");
		g_key_file_set_string_list(config, config_group,
					"IPv4.INPUT.RULES",
					input_ok_rules[config_index],
					g_strv_length(
					(char**)input_ok_rules[config_index]));
		g_key_file_set_string_list(config, config_group,
					"IPv6.INPUT.RULES",
					input_ok_rules[config_index],
					g_strv_length(
					(char**)input_ok_rules[config_index]));
	}

	if (global_config_type & CONFIG_INVALID ||
				global_config_type & CONFIG_MIXED) {
		/* Add invalid tethering rules */
		if (global_config_type & CONFIG_TETHERING) {
			DBG("invalid tethering rules");
			g_key_file_set_string_list(config, "tethering",
					"IPv4.OUTPUT.RULES",
					tethering_input_invalid,
					g_strv_length(
					(char**)tethering_input_invalid));
			g_key_file_set_string_list(config, "tethering",
					"IPv6.OUTPUT.RULES",
					tethering_input_invalid,
					g_strv_length(
					(char**)tethering_input_invalid));
		} else {
			DBG("invalid or mixed");
			g_key_file_set_string_list(config, config_group,
					"IPv4.OUTPUT.RULES",
					input_fail_rules[config_index],
					g_strv_length(
					(char**)input_fail_rules[config_index]));
			g_key_file_set_string_list(config, config_group,
					"IPv6.OUTPUT.RULES",
					input_fail_rules[config_index],
					g_strv_length(
					(char**)input_fail_rules[config_index]));
		}
	}

	g_free(config_group);

	return TRUE;
}

gboolean g_key_file_load_from_file(GKeyFile *key_file, const gchar *file,
			GKeyFileFlags flags, GError **error)
{
	int i;

	DBG("load %s\n", file);

	if (g_strstr_len(file, -1, "firewall.d")) {
		for (i = 0; testfiles[i]; i++) {
			if (g_str_has_suffix(file, testfiles[i])) {
				DBG("file %s", testfiles[i]);
				
				// Use main config to detect duplicates
				if (global_config_type & CONFIG_DUPLICATES) {
					DBG("return duplicate of main");
					return setup_main_config(key_file);
				} else {
					return setup_config(key_file, i);
				}
			}
		}
		return FALSE;
	} else {
		return setup_main_config(key_file);
	}
}

// End of dummies

static DBusMessage *construct_message_reload()
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".Firewall",
				"/", CONNMAN_SERVICE ".Firewall", "Reload");

	// Close everything off
	dbus_message_set_serial (msg, 1);

	return msg;
}

static void service_state_change(struct connman_service *service,
			enum connman_service_state state)
{
	if (firewall_notifier)
		firewall_notifier->service_state_changed(service, state);

	service->state = state;
}

static void service_remove(struct connman_service *service)
{
	if (firewall_notifier)
		firewall_notifier->service_remove(service);
	
	service->state = CONNMAN_SERVICE_STATE_IDLE;
}

static gboolean is_supported_by_type(int type, const char *rule_spec)
{
	int i = 0;
	const char *not_with_ipv4[] = { "-p icmpv6",
					"-p ipv6-icmp",
					"-p mh",
					NULL
	};
	const char *not_with_ipv6[] = { "-p icmp", "-m ttl", NULL};

	switch (type) {
	case AF_INET:
		for (i = 0; not_with_ipv4[i]; i++) {
			if (g_strstr_len(rule_spec, -1, not_with_ipv4[i]))
				return false;
		}
		return true;
	case AF_INET6:
		for (i = 0; not_with_ipv6[i]; i++) {
			if (g_strstr_len(rule_spec, -1, not_with_ipv6[i]))
				return false;
		}
		return true;
	default:
		return false;
	}
}

static void assert_rule_exists(int type, const char *table, const char *chain,
			const char *rule_spec, const char *device)
{
	GSList *iter = NULL;
	struct iptables_rule *rule;
	char *rule_str;
	char device_type;

	// Rules starting with # are interpreted as empty (commented) rules
	if (rule_spec[0] == '#' || !is_supported_by_type(type, rule_spec))
		return;

	switch (type) {
	case AF_INET:
		iter = rules_ipv4;
		break;
	case AF_INET6:
		iter = rules_ipv6;
	}

	if (device) {
		if (!g_strcmp0(chain, connman_chains[0]))
			device_type = 'i';
		else if (!g_strcmp0(chain, connman_chains[1]))
			device_type = 'o';
		else if (!g_strcmp0(chain, connman_chains[2]))
			device_type = 'o';
		else
			device_type = '?';
		
		g_assert(device_type != '?');
		
		rule_str = g_strdup_printf("-%c %s %s", device_type, device,
					rule_spec);
	} else {
		rule_str = g_strdup(rule_spec);
	}

	while (iter) {
		rule = iter->data;
		
		if (rule->type == type && !g_strcmp0(rule->table, table) &&
					!g_strcmp0(rule->chain, chain) &&
					!g_strcmp0(rule->rule_spec, rule_str))
			goto out;

		iter = iter->next;
	}

	g_assert(FALSE);

out:
	g_free(rule_str);
}

static void assert_rule_not_exists(int type, const char *table,
			const char *chain, const char *rule_spec,
			const char *device)
{
	GSList *iter = NULL;
	struct iptables_rule *rule;
	char *rule_str;
	char device_type;

	// Rules starting with # are interpreted as empty (commented) rules
	if (rule_spec[0] == '#')
		return;

	switch (type) {
	case AF_INET:
		iter = rules_ipv4;
		break;
	case AF_INET6:
		iter = rules_ipv6;
	}

	if (device) {
		if (!g_strcmp0(chain, connman_chains[0]))
			device_type = 'i';
		else if (!g_strcmp0(chain, connman_chains[1]))
			device_type = 'o';
		else if (!g_strcmp0(chain, connman_chains[2]))
			device_type = 'o';
		else
			device_type = '?';
		
		g_assert(device_type != '?');
		
		rule_str = g_strdup_printf("-%c %s %s", device_type, device,
					rule_spec);
	} else {
		rule_str = g_strdup(rule_spec);
	}

	while (iter) {
		rule = iter->data;

		g_assert_false(rule->type == type &&
					!g_strcmp0(rule->table, table) &&
					!g_strcmp0(rule->chain, chain) &&
					!g_strcmp0(rule->rule_spec, rule_str));

		iter = iter->next;
	}

	g_free(rule_str);
}

typedef  void (*assert_cb_t)(int type, const char *table, const char *chain,
			const char *rule_spec, const char *device);

static void check_rules(assert_cb_t cb, int type, const char **rules[],
			const char *ifname)
{
	int i, j;

	for (j = 0; j < 3; j++) {
		if (!rules[j])
			continue;

		for (i = 0; rules[j][i]; i++) {
			if (!type || type == AF_INET)
				cb(AF_INET, "filter", connman_chains[j],
						rules[j][i], ifname);

			if (!type || type == AF_INET6)
				cb(AF_INET6, "filter", connman_chains[j],
						rules[j][i], ifname);
		}
	}
}

static void check_main_config_rules()
{
	const char **general_rules_all[] = {
				general_input,
				general_forward,
				general_output
	};
	const char **eth_rules_all[] = {eth_input, NULL, eth_output};
	const char **cel_rules_all[] = {cellular_input, NULL, cellular_output};

	check_rules(assert_rule_exists, 0, general_rules_all, NULL);
	check_rules(assert_rule_not_exists, 0, eth_rules_all, NULL);
	check_rules(assert_rule_not_exists, 0, cel_rules_all, NULL);
}

static void check_default_policies(const char *policies[])
{
	int i;

	for (i = 0; i < 3; i++) {
		DBG("IPv4 %s - %s", policies_ipv4[i], policies[i]);
		if (policies_ipv4[i] && policies[i])
			g_assert(!g_strcmp0(policies_ipv4[i], policies[i]));

		DBG("IPv6 %s - %s", policies_ipv6[i], policies[i]);
		if (policies_ipv6[i] && policies[i])
			g_assert(!g_strcmp0(policies_ipv6[i], policies[i]));
	}
}

static void firewall_test_basic0()
{
	struct firewall_context *ctx;

	__connman_iptables_init();
	
	g_assert(!__connman_firewall_is_up());
	
	__connman_firewall_init();

	ctx = __connman_firewall_create();

	g_assert(ctx);

	g_assert_cmpint(__connman_firewall_enable(ctx), ==, 0);
	
	g_assert(__connman_firewall_is_up());

	g_assert_cmpint(__connman_firewall_disable(ctx), ==, 0);

	__connman_firewall_destroy(ctx);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();
	__connman_iptables_cleanup();
}

static const char *basic_rules[] = { "-o eth1 -j ACCEPT",
					"-p tcp -m tcp -j DROP",
					"-m conntrack --ctstate NEW -j ACCEPT",
					"-i wlan0 -j REJECT",
					"-m mark --mark 0x01 -j QUEUE",
					NULL
};

static void firewall_test_basic1()
{
	struct firewall_context *ctx;
	int id[5], id6[5], i;
	const char *table = "filter";
	const char *chain = "INPUT";

	__connman_iptables_init();
	__connman_firewall_init();

	ctx = __connman_firewall_create();

	g_assert(ctx);

	g_assert(__connman_firewall_is_up());
	
	for (i = 0; i < 5; i++) {
		id[i] = __connman_firewall_add_rule(ctx, NULL, NULL, table,
					chain, basic_rules[i]);
		
		g_assert(id[i] >= 0);
		
		id6[i] = __connman_firewall_add_ipv6_rule(ctx, NULL, NULL,
					table, chain, basic_rules[i]);
		
		g_assert(id6[i] >= 0);
	}

	g_assert(__connman_firewall_enable(ctx) == 0);
	
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 6);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 6);

	g_assert(__connman_firewall_disable(ctx) == 0);
	__connman_firewall_destroy(ctx);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();
	__connman_iptables_cleanup();
}

static void firewall_test_basic2()
{
	struct firewall_context *ctx;
	int id[5], id6[5], i = 0, res;
	const char *table = "filter";
	const char *chains[] = {"INPUT", "connman-INPUT", "OUTPUT",
				"connman-OUTPUT", "FORWARD" };

	__connman_iptables_init();
	__connman_firewall_init();

	ctx = __connman_firewall_create();

	g_assert(ctx);

	g_assert(__connman_firewall_is_up());
	
	id[0] = __connman_firewall_add_rule(ctx, NULL, NULL, table, chains[0],
				basic_rules[0]);
	g_assert(id[0]);
		
	id6[0] = __connman_firewall_add_ipv6_rule(ctx, NULL, NULL, table,
				chains[0], basic_rules[0]);
	g_assert(id6[0]);
	
	g_assert(__connman_firewall_enable(ctx) == 0);

	for (i = 1; i < 5; i++) {
		id[i] = __connman_firewall_add_rule(ctx, NULL, NULL, table,
					chains[i], basic_rules[i]);

		g_assert(id[i]);
		
		id6[i] = __connman_firewall_add_ipv6_rule(ctx, NULL, NULL,
					table, chains[i], basic_rules[i]);

		g_assert(id6[i]);
	}

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 2); // +1 managed chain
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 2); // +1 managed chain

	g_assert(__connman_firewall_remove_rule(ctx, id[3]) == 0);
	id[3] = 0;

	g_assert(__connman_firewall_remove_ipv6_rule(ctx, id6[2]) == 0);
	id6[2] = 0;

	for (i = 0; i < 5; i++) {
		res = __connman_firewall_enable_rule(ctx, id[i]);

		if (id[i] && i > 0)
			g_assert(res == 0);
		else
			g_assert(res != 0);

		res = __connman_firewall_enable_rule(ctx, id6[i]);

		if (id6[i] && i > 0)
			g_assert(res == 0);
		else
			g_assert(res != 0);
		
	}

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 7); // +3 managed chains
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 6); // +2 managed chains
	
	for (i = 0; i < 5; i++) {
		res = __connman_firewall_disable_rule(ctx, id[i]);

		if (id[i])
			g_assert(res == 0);
		else
			g_assert(res != 0);

		res = __connman_firewall_disable_rule(ctx, id6[i]);

		if (id6[i])
			g_assert(res == 0);
		else
			g_assert(res != 0);
		
	}

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	g_assert(__connman_firewall_disable(ctx) == 0);
	__connman_firewall_destroy(ctx);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();
	__connman_iptables_cleanup();
}

static void firewall_test_main_config_ok0()
{
	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_ok1()
{
	setup_test_params(CONFIG_MIXED);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_ok2()
{
	setup_test_params(CONFIG_OK|CONFIG_USE_POLICY);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();
	check_default_policies(general_policies_ok);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_ok0()
{
	setup_test_params(CONFIG_OK|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_ok1()
{
	setup_test_params(CONFIG_MIXED|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_duplicates0()
{
	setup_test_params(CONFIG_OK|CONFIG_DUPLICATES|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_duplicates1()
{
	setup_test_params(CONFIG_MIXED|CONFIG_DUPLICATES|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_icmp_config_ok0()
{
	const char **icmpv4_rules[] = { general_icmpv4, NULL, NULL};
	const char **icmpv6_rules[] = { general_icmpv6, NULL, NULL};

	setup_test_params(CONFIG_ICMP_ONLY);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_ICMP4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_ICMP6);

	check_rules(assert_rule_exists, AF_INET, icmpv4_rules, NULL);
	check_rules(assert_rule_exists, AF_INET6, icmpv6_rules, NULL);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_options_config_ok0()
{
	const char **opt4_rules[] = { general_options, NULL, NULL};
	const char **opt6_rules[] = { general_options, NULL, NULL};

	setup_test_params(CONFIG_OPTIONS_ONLY);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_OPTIONS4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_OPTIONS6);

	check_rules(assert_rule_exists, AF_INET, opt4_rules, NULL);
	check_rules(assert_rule_exists, AF_INET6, opt6_rules, NULL);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_options_config_ok1()
{
	const char **opt4_rules[] = { general_options_address4, NULL, NULL};
	const char **opt6_rules[] = { general_options_address6, NULL, NULL};

	setup_test_params(CONFIG_OPTIONS_ONLY|CONFIG_OPTIONS_ADDR);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_OPTIONS_ADDR4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_OPTIONS_ADDR6);

	check_rules(assert_rule_exists, AF_INET, opt4_rules, NULL);
	check_rules(assert_rule_exists, AF_INET6, opt6_rules, NULL);
	check_rules(assert_rule_not_exists, AF_INET, opt6_rules, NULL);
	check_rules(assert_rule_not_exists, AF_INET6, opt4_rules, NULL);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_fail0()
{
	setup_test_params(CONFIG_INVALID); // Rules that are invalid

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_fail1()
{
	setup_test_params(CONFIG_INVALID|CONFIG_USE_POLICY);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	check_default_policies(policies_default);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_fail2()
{
	setup_test_params(CONFIG_MAIN_INVALID); // Invalid groups, keys

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_fail0()
{
	setup_test_params(CONFIG_INVALID|CONFIG_DUPLICATES|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_options_config_fail0()
{
	const char **opt4_rules[] = { invalid_general_options, NULL, NULL};
	const char **opt6_rules[] = { invalid_general_options, NULL, NULL};

	setup_test_params(CONFIG_OPTIONS_ONLY|CONFIG_INVALID);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	check_rules(assert_rule_not_exists, AF_INET, opt4_rules, NULL);
	check_rules(assert_rule_not_exists, AF_INET6, opt6_rules, NULL);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	__connman_iptables_cleanup();
}

/* One service to ready, online and off */
static void firewall_test_dynamic_ok0()
{
	char *ifname;

	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);
	// Double on
	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, 0, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_ONLINE);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	check_rules(assert_rule_exists, 0, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Two services on and off and both running at the same time*/
static void firewall_test_dynamic_ok1()
{
	char *ifname, *ifname2;

	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **cel_rules[] = { cellular_input, NULL, cellular_output};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, 0, eth_rules, ifname);

	// Enable cellular test service
	test_service2.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_READY);

	g_assert(g_slist_length(rules_ipv4) ==
				RULES_GEN4 + RULES_ETH + RULES_CEL);
	g_assert(g_slist_length(rules_ipv6) ==
				RULES_GEN6 + RULES_ETH + RULES_CEL);

	ifname2 = connman_service_get_interface(&test_service2);
	check_rules(assert_rule_exists, 0, cel_rules, ifname2);

	// Disable ethernet test service
	test_service.state = test_service2.state =
				CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_CEL);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_CEL);

	check_rules(assert_rule_not_exists, 0, eth_rules, ifname);

	// Disable cellular test service
	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, cel_rules, ifname2);

	g_free(ifname);
	g_free(ifname2);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static const char *tethering_default_input[] = {"-j ACCEPT", NULL};

/* Tethering on twice, off, re-enable and off with default rules */
static void firewall_test_dynamic_ok2()
{
	const char *ifname;
	const char **device_rules[] = { tethering_default_input, NULL, NULL};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Tethering without defined rules
	test_technology.default_rules = true;
	test_technology.enabled = true;
	firewall_notifier->tethering_changed(&test_technology, true);
	// Double notify
	firewall_notifier->tethering_changed(&test_technology, true);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 1);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 1 );

	ifname = __connman_tethering_get_bridge();
	check_rules(assert_rule_exists, 0, device_rules, ifname);

	firewall_notifier->tethering_changed(&test_technology, false);
	test_technology.enabled = false;

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	// Re-enable
	test_technology.enabled = true;
	firewall_notifier->tethering_changed(&test_technology, true);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 1);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 1 );

	ifname = __connman_tethering_get_bridge();
	check_rules(assert_rule_exists, 0, device_rules, ifname);

	firewall_notifier->tethering_changed(&test_technology, false);
	test_technology.enabled = false;

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Tethering with custom rules */
static void firewall_test_dynamic_ok3()
{
	const char *ifname;

	const char **tethering_rules[] = { tethering_input, 
					tethering_forward,
					tethering_output,
	};
	const char **not_exist_rules[] = { tethering_default_input, NULL, NULL};

	setup_test_params(CONFIG_OK|CONFIG_TETHERING);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Tethering with custom rules
	test_technology.default_rules = false;
	test_technology.enabled = true;
	firewall_notifier->tethering_changed(&test_technology, true);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_TETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_TETH);

	ifname = __connman_tethering_get_bridge();
	check_rules(assert_rule_exists, 0, tethering_rules, ifname);
	check_rules(assert_rule_not_exists, 0, not_exist_rules, ifname);

	firewall_notifier->tethering_changed(&test_technology, false);
	test_technology.enabled = false;

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, tethering_rules, ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/*
 * Two services and tethering with custom rules on and off and running
 * simultaneously
 */
static void firewall_test_dynamic_ok4()
{
	const char *iftether;
	char *ifname, *ifname2;

	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **cel_rules[] = { cellular_input, NULL, cellular_output};
	const char **tethering_rules[] = { tethering_input, 
					tethering_forward,
					tethering_output,
	};
	const char **not_exist_rules[] = { tethering_default_input, NULL, NULL};
	const char **eth_add_rules1[] = { eth_input_add1, NULL, NULL };
	const char **eth_add_rules3[] = { eth_input_add3, NULL, NULL };
	const char **cel_add_rules0[] = { cel_input_add0, NULL, NULL };
	const char **cel_add_rules2[] = { cel_input_add2, NULL, NULL };

	setup_test_params(CONFIG_MIXED|CONFIG_TETHERING|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, 0, eth_rules, ifname);
	check_rules(assert_rule_exists, 0, eth_add_rules1, ifname);
	check_rules(assert_rule_exists, 0, eth_add_rules3, ifname);

	// Tethering on
	test_technology.default_rules = false;
	test_technology.enabled = true;
	firewall_notifier->tethering_changed(&test_technology, true);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_TETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_TETH);

	iftether = __connman_tethering_get_bridge();
	check_rules(assert_rule_exists, 0, tethering_rules, iftether);
	check_rules(assert_rule_not_exists, 0, not_exist_rules, iftether);

	// Enable cellular test service
	test_service2.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH  +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_TETH +
				RULES_CEL + RULES_CEL_ADD0 + RULES_CEL_ADD2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH  +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_TETH +
				RULES_CEL + RULES_CEL_ADD0 + RULES_CEL_ADD2);

	ifname2 = connman_service_get_interface(&test_service2);
	check_rules(assert_rule_exists, 0, cel_rules, ifname2);
	check_rules(assert_rule_exists, 0, cel_add_rules0, ifname2);
	check_rules(assert_rule_exists, 0, cel_add_rules2, ifname2);

	// Disable ethernet test service
	test_service.state = test_service2.state = CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_TETH +
				RULES_CEL + RULES_CEL_ADD0 + RULES_CEL_ADD2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_TETH +
				RULES_CEL + RULES_CEL_ADD0 + RULES_CEL_ADD2);

	check_rules(assert_rule_not_exists, 0, eth_rules, ifname);
	check_rules(assert_rule_not_exists, 0, eth_add_rules1, ifname);
	check_rules(assert_rule_not_exists, 0, eth_add_rules3, ifname);

	// Disable cellular test service
	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_TETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_TETH);

	check_rules(assert_rule_not_exists, 0, cel_rules, ifname2);
	check_rules(assert_rule_not_exists, 0, eth_add_rules1, ifname2);
	check_rules(assert_rule_not_exists, 0, eth_add_rules3, ifname2);

	// Disable tethering
	firewall_notifier->tethering_changed(&test_technology, false);
	test_technology.enabled = false;

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, tethering_rules, iftether);

	g_free(ifname);
	g_free(ifname2);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* One service on and off with changing interface */
static void firewall_test_dynamic_ok5()
{
	char *ifname;

	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	test_service3.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service3, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service3);
	check_rules(assert_rule_exists, 0, device_rules, ifname);

	test_service3.state = CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service3, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	g_free(ifname);

	test_service3.ifname = g_strdup("eth2");

	test_service3.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service3, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service3);
	check_rules(assert_rule_exists, 0, device_rules, ifname);

	test_service.state = CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service3, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	g_free(ifname);
	g_free(test_service3.ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/*
 * Two services on and off and both running at the same time with additional
 * files
 */
static void firewall_test_dynamic_ok6()
{
	char *ifname, *ifname2;

	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **cel_rules[] = { cellular_input, NULL, cellular_output };
	const char **eth_add_rules1[] = { eth_input_add1, NULL, NULL };
	const char **eth_add_rules3[] = { eth_input_add3, NULL, NULL };
	const char **cel_add_rules0[] = { cel_input_add0, NULL, NULL };
	const char **cel_add_rules2[] = { cel_input_add2, NULL, NULL };

	setup_test_params(CONFIG_OK|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, 0, eth_rules, ifname);
	check_rules(assert_rule_exists, 0, eth_add_rules1, ifname);
	check_rules(assert_rule_exists, 0, eth_add_rules3, ifname);

	// Enable cellular test service
	test_service2.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_CEL +
				RULES_CEL_ADD0 + RULES_CEL_ADD2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_CEL +
				RULES_CEL_ADD0 + RULES_CEL_ADD2);

	ifname2 = connman_service_get_interface(&test_service2);
	check_rules(assert_rule_exists, 0, cel_rules, ifname2);
	check_rules(assert_rule_exists, 0, cel_add_rules0, ifname2);
	check_rules(assert_rule_exists, 0, cel_add_rules2, ifname2);

	// Disable ethernet test service
	test_service.state = test_service2.state = CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_CEL +
				RULES_CEL_ADD0 + RULES_CEL_ADD2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_CEL +
				RULES_CEL_ADD0 + RULES_CEL_ADD2);

	check_rules(assert_rule_not_exists, 0, eth_rules, ifname);
	check_rules(assert_rule_not_exists, 0, eth_add_rules1, ifname);
	check_rules(assert_rule_not_exists, 0, eth_add_rules3, ifname);

	// Disable cellular test service
	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, cel_rules, ifname2);
	check_rules(assert_rule_not_exists, 0, cel_add_rules0, ifname2);
	check_rules(assert_rule_not_exists, 0, cel_add_rules2, ifname2);

	g_free(ifname);
	g_free(ifname2);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Two services on and off and both running at the same time and other removed*/
static void firewall_test_dynamic_ok7()
{
	char *ifname, *ifname2;

	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **cel_rules[] = { cellular_input, NULL, cellular_output};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, 0, eth_rules, ifname);

	// Enable cellular test service
	test_service2.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_READY);

	g_assert(g_slist_length(rules_ipv4) ==
				RULES_GEN4 + RULES_ETH + RULES_CEL);
	g_assert(g_slist_length(rules_ipv6) ==
				RULES_GEN6 + RULES_ETH + RULES_CEL);

	ifname2 = connman_service_get_interface(&test_service2);
	check_rules(assert_rule_exists, 0, cel_rules, ifname2);

	test_service2.state = CONNMAN_SERVICE_STATE_ONLINE;

	// Remove ethernet test service twice
	service_remove(&test_service);
	service_remove(&test_service);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_CEL);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_CEL);

	check_rules(assert_rule_not_exists, 0, eth_rules, ifname);

	// Disable cellular test service
	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, cel_rules, ifname2);

	// Remove disconnected
	service_remove(&test_service2);

	g_free(ifname);
	g_free(ifname2);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Tethering with invalid rules also added */
static void firewall_test_dynamic_ok8()
{
	const char **tethering_rules[] = { tethering_input, NULL, NULL};
	const char *ifname;

	setup_test_params(CONFIG_TETHERING|CONFIG_INVALID);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	// Tethering with custom rules, the rules are invalid
	test_technology.default_rules = false;
	test_technology.enabled = true;
	firewall_notifier->tethering_changed(&test_technology, true);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, CHAINS_GEN4 +
				RULES_TETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, CHAINS_GEN6 +
				RULES_TETH);

	ifname = __connman_tethering_get_bridge();

	/*
	 * Check only valid rules, the tethering_input_invalid contains a
	 * duplicate rule found in tethering_input.
	 */
	check_rules(assert_rule_exists, 0, tethering_rules, ifname);

	firewall_notifier->tethering_changed(&test_technology, false);
	test_technology.enabled = false;

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();

	__connman_firewall_cleanup();

	__connman_iptables_cleanup();
}

static void firewall_test_device_status0()
{
	const char **device_rules[] = { tethering_default_input, NULL, NULL};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	/* on */
	firewall_notifier->device_status_changed(&test_device1, true);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 2);
	check_rules(assert_rule_exists, 0, device_rules, test_device1.ifname);

	/* off */
	firewall_notifier->device_status_changed(&test_device1, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	check_rules(assert_rule_not_exists, 0, device_rules,
				test_device1.ifname);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Tests with two devices */
static void firewall_test_device_status1()
{
	const char **device_rules[] = { tethering_default_input, NULL, NULL};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	/* device 1 on */
	firewall_notifier->device_status_changed(&test_device1, true);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 2);
	check_rules(assert_rule_exists, 0, device_rules, test_device1.ifname);

	/* device 1 off */
	firewall_notifier->device_status_changed(&test_device1, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	check_rules(assert_rule_not_exists, 0, device_rules,
				test_device1.ifname);

	/* device 1 on */
	firewall_notifier->device_status_changed(&test_device1, true);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 2);
	check_rules(assert_rule_exists, 0, device_rules, test_device1.ifname);

	/* device 2 on */
	firewall_notifier->device_status_changed(&test_device2, true);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 4);
	check_rules(assert_rule_exists, 0, device_rules, test_device2.ifname);

	/* device 1 off */
	firewall_notifier->device_status_changed(&test_device1, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 2);
	check_rules(assert_rule_not_exists, 0, device_rules,
				test_device1.ifname);

	/* device 2 off */
	firewall_notifier->device_status_changed(&test_device2, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	check_rules(assert_rule_not_exists, 0, device_rules,
				test_device2.ifname);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Tests devices with double notifications */
static void firewall_test_device_status2()
{
	const char **device_rules[] = { tethering_default_input, NULL, NULL};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	/* on */
	firewall_notifier->device_status_changed(&test_device1, true);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 2);
	check_rules(assert_rule_exists, 0, device_rules, test_device1.ifname);

	/* on double */
	firewall_notifier->device_status_changed(&test_device1, true);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 2);
	check_rules(assert_rule_exists, 0, device_rules, test_device1.ifname);

	/* off */
	firewall_notifier->device_status_changed(&test_device1, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	check_rules(assert_rule_not_exists, 0, device_rules,
				test_device1.ifname);

	/* off double */
	firewall_notifier->device_status_changed(&test_device1, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	check_rules(assert_rule_not_exists, 0, device_rules,
				test_device1.ifname);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Notify from managed device - no new rules */
static void firewall_test_device_status3()
{
	const char **device_rules[] = { tethering_default_input, NULL, NULL};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	/* on */
	test_device1.managed = true;
	firewall_notifier->device_status_changed(&test_device1, true);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	check_rules(assert_rule_not_exists, 0, device_rules,
				test_device1.ifname);

	/* off */
	firewall_notifier->device_status_changed(&test_device1, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	check_rules(assert_rule_not_exists, 0, device_rules,
				test_device1.ifname);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();

	test_device1.managed = false;
}

/* Only off notify from managed device - nothing done */
static void firewall_test_device_status4()
{
	const char **device_rules[] = { tethering_default_input, NULL, NULL};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	/* Managed device off notification, nothing is done */
	firewall_notifier->device_status_changed(&test_device1, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	check_rules(assert_rule_not_exists, 0, device_rules,
				test_device1.ifname);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload0()
{
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload1()
{
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload2()
{
	char *ifname;
	const char **eth_rules[] = { eth_input, NULL, eth_output };
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, 0, eth_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	check_rules(assert_rule_not_exists, 0, eth_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload3()
{
	char *ifname;
	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **add_rules1[] = { eth_input_add1, NULL, NULL};
	const char **add_rules3[] = { eth_input_add3, NULL, NULL};
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|CONFIG_ALL);
	toggle_config(FILE_ETH1, FALSE);
	toggle_config(FILE_ETH3, FALSE);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, 0, eth_rules, ifname);

	test_service.state = CONNMAN_SERVICE_STATE_ONLINE;

	// Load new configs
	toggle_config(FILE_ETH1, TRUE);
	toggle_config(FILE_ETH3, TRUE);

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);

	check_rules(assert_rule_exists, 0, eth_rules, ifname);
	check_rules(assert_rule_exists, 0, add_rules1, ifname);
	check_rules(assert_rule_exists, 0, add_rules3, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	check_rules(assert_rule_not_exists, 0, eth_rules, ifname);
	check_rules(assert_rule_not_exists, 0, add_rules1, ifname);
	check_rules(assert_rule_not_exists, 0, add_rules3, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/*
 * Remove configs before service is enabled, start service and remove another
 * config.
 */
static void firewall_test_config_reload4()
{
	char *ifname;
	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **add_rules1[] = { eth_input_add1, NULL, NULL};
	const char **add_rules3[] = { eth_input_add3, NULL, NULL};
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|CONFIG_ALL);
	msg = construct_message_reload();

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Disable first and reload
	toggle_config(FILE_ETH1, FALSE);

	reply = reload_call(NULL, msg, NULL);
	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;
	test_service.state = CONNMAN_SERVICE_STATE_READY;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, 0, eth_rules, ifname);
	check_rules(assert_rule_exists, 0, add_rules3, ifname);
	check_rules(assert_rule_not_exists, 0, add_rules1, ifname);

	test_service.state = CONNMAN_SERVICE_STATE_ONLINE;

	// Remove config 3
	toggle_config(FILE_ETH3, FALSE);

	reply = reload_call(NULL, msg, NULL);
	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	check_rules(assert_rule_exists, 0, eth_rules, ifname);
	check_rules(assert_rule_not_exists, 0, add_rules1, ifname);
	check_rules(assert_rule_not_exists, 0, add_rules3, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	check_rules(assert_rule_not_exists, 0, eth_rules, ifname);

	g_free(ifname);
	dbus_message_unref(msg);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Device is null  */
static void firewall_test_device_status_fail0()
{
	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	/* NULL device on */
	firewall_notifier->device_status_changed(NULL, true);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	/* NULL device off */
	firewall_notifier->device_status_changed(NULL, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Interface is null  */
static void firewall_test_device_status_fail1()
{
	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	/* Device with no inteface on */
	firewall_notifier->device_status_changed(&test_device3, true);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	/* Device with no inteface off */
	firewall_notifier->device_status_changed(&test_device3, false);
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload_fail0()
{
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|ACCESS_FAILURE);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload_fail1()
{
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|DIR_ACCESS_FAILURE);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_notifier_fail0()
{
	char *ifname;

	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK|CONFIG_ALL);
	notifier_fail = true; // No dynamic rules

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_ONLINE);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
	
	notifier_fail = false;
}

static void firewall_test_iptables_fail0()
{
	setup_test_params(CONFIG_OK|CONFIG_ALL);
	setup_iptables_params(IPTABLES_COMMIT_FAIL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();
	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
}

static void firewall_test_iptables_fail1()
{
	setup_test_params(CONFIG_OK|CONFIG_ALL|CONFIG_USE_POLICY);
	setup_iptables_params(IPTABLES_POLICY_FAIL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_default_policies(policies_default);

	__connman_firewall_pre_cleanup();

	__connman_firewall_cleanup();
	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
}

static void firewall_test_iptables_fail2()
{
	char *ifname;
	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK|CONFIG_ALL);

	/*
	 * General rules are not added, only the managed chains because
	 * they are added using __connman_iptables_insert()
	 */
	setup_iptables_params(IPTABLES_ADD_FAIL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, CHAINS_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, CHAINS_GEN6);

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, CHAINS_GEN4 +
				RULES_ETH + RULES_ETH_ADD1 + RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, CHAINS_GEN4 +
				RULES_ETH + RULES_ETH_ADD1 + RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, 0, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, CHAINS_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, CHAINS_GEN6);

	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
}

static void firewall_test_iptables_fail3()
{
	char *ifname;
	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK|CONFIG_ALL);

	/*
	 * Managed chains also fail as they are added with
	 * __connman_iptables_insert().
	 */
	setup_iptables_params(IPTABLES_INS_FAIL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	check_rules(assert_rule_not_exists, 0, device_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
}

static void firewall_test_iptables_fail4()
{
	setup_test_params(CONFIG_OK|CONFIG_ALL);
	setup_iptables_params(IPTABLES_NORMAL|IPTABLES_ALL_CHAINS);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	
	setup_iptables_params(IPTABLES_DEL_FAIL|IPTABLES_POLICY_FAIL);

	__connman_firewall_pre_cleanup();

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
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
	int ret;

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
	__connman_iptables_validate_init();

	g_test_add_func("/firewall/test_basic0", firewall_test_basic0);
	g_test_add_func("/firewall/test_basic1", firewall_test_basic1);
	g_test_add_func("/firewall/test_basic2", firewall_test_basic2);
	g_test_add_func("/firewall/test_main_config_ok0",
				firewall_test_main_config_ok0);
	g_test_add_func("/firewall/test_main_config_ok1",
				firewall_test_main_config_ok1);
	g_test_add_func("/firewall/test_main_config_ok2",
				firewall_test_main_config_ok2);
	g_test_add_func("/firewall/test_all_config_ok0",
				firewall_test_all_config_ok0);
	g_test_add_func("/firewall/test_all_config_ok1",
				firewall_test_all_config_ok1);
	g_test_add_func("/firewall/test_all_config_duplicates0",
				firewall_test_all_config_duplicates0);
	g_test_add_func("/firewall/test_all_config_duplicates1",
				firewall_test_all_config_duplicates1);
	g_test_add_func("/firewall/test_icmp_config_ok0",
				firewall_test_icmp_config_ok0);
	g_test_add_func("/firewall/test_options_config_ok0",
				firewall_test_options_config_ok0);
	g_test_add_func("/firewall/test_options_config_ok1",
				firewall_test_options_config_ok1);
	g_test_add_func("/firewall/test_main_config_fail0",
				firewall_test_main_config_fail0);
	g_test_add_func("/firewall/test_main_config_fail1",
				firewall_test_main_config_fail1);
	g_test_add_func("/firewall/test_main_config_fail2",
				firewall_test_main_config_fail2);
	g_test_add_func("/firewall/test_all_config_fail0",
				firewall_test_all_config_fail0);
	g_test_add_func("/firewall/test_options_config_fail0",
				firewall_test_options_config_fail0);
	g_test_add_func("/firewall/test_dynamic_ok0",
				firewall_test_dynamic_ok0);
	g_test_add_func("/firewall/test_dynamic_ok1",
				firewall_test_dynamic_ok1);
	g_test_add_func("/firewall/test_dynamic_ok2",
				firewall_test_dynamic_ok2);
	g_test_add_func("/firewall/test_dynamic_ok3",
				firewall_test_dynamic_ok3);
	g_test_add_func("/firewall/test_dynamic_ok4",
				firewall_test_dynamic_ok4);
	g_test_add_func("/firewall/test_dynamic_ok5",
				firewall_test_dynamic_ok5);
	g_test_add_func("/firewall/test_dynamic_ok6",
				firewall_test_dynamic_ok6);
	g_test_add_func("/firewall/test_dynamic_ok7",
				firewall_test_dynamic_ok7);
	g_test_add_func("/firewall/test_dynamic_ok8",
				firewall_test_dynamic_ok8);
	g_test_add_func("/firewall/test_device_status0",
				firewall_test_device_status0);
	g_test_add_func("/firewall/test_device_status1",
				firewall_test_device_status1);
	g_test_add_func("/firewall/test_device_status2",
				firewall_test_device_status2);
	g_test_add_func("/firewall/test_device_status3",
				firewall_test_device_status3);
	g_test_add_func("/firewall/test_device_status4",
				firewall_test_device_status4);
	g_test_add_func("/firewall/test_config_reload0",
				firewall_test_config_reload0);
	g_test_add_func("/firewall/test_config_reload1",
				firewall_test_config_reload1);
	g_test_add_func("/firewall/test_config_reload2",
				firewall_test_config_reload2);
	g_test_add_func("/firewall/test_config_reload3",
				firewall_test_config_reload3);
	g_test_add_func("/firewall/test_config_reload4",
				firewall_test_config_reload4);
	g_test_add_func("/firewall/test_device_status_fail0",
				firewall_test_device_status_fail0);
	g_test_add_func("/firewall/test_device_status_fail1",
				firewall_test_device_status_fail1);
	g_test_add_func("/firewall/config_reload_fail0",
				firewall_test_config_reload_fail0);
	g_test_add_func("/firewall/config_reload_fail1",
				firewall_test_config_reload_fail1);
	g_test_add_func("/firewall/iptables_notifier_fail0",
				firewall_test_notifier_fail0);
	g_test_add_func("/firewall/iptables_fail0",
				firewall_test_iptables_fail0);
	g_test_add_func("/firewall/iptables_fail1",
				firewall_test_iptables_fail1);
	g_test_add_func("/firewall/iptables_fail2",
				firewall_test_iptables_fail2);
	g_test_add_func("/firewall/iptables_fail3",
				firewall_test_iptables_fail3);
	g_test_add_func("/firewall/iptables_fail4",
				firewall_test_iptables_fail4);

	ret = g_test_run();

	__connman_iptables_validate_cleanup();

	return ret;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
