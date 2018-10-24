/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013,2015  BMW Car IT GmbH.
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

#include <xtables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include "connman.h"

#define CHAIN_PREFIX "connman-"
#define FW_ALL_RULES -1

/*
 * All IPv6 equivalents of the indexes used here have the same values as the
 * IPv4 ones.
 */
static const char *builtin_chains[] = {
	[NF_IP_PRE_ROUTING]	= "PREROUTING",
	[NF_IP_LOCAL_IN]	= "INPUT",
	[NF_IP_FORWARD]		= "FORWARD",
	[NF_IP_LOCAL_OUT]	= "OUTPUT",
	[NF_IP_POST_ROUTING]	= "POSTROUTING",
};

struct connman_managed_table {
	int type;
	char *name;
	unsigned int chains[NF_INET_NUMHOOKS];
};

struct fw_rule {
	int id;
	int type;
	bool enabled;
	char *table;
	char *chain;
	char *rule_spec;
};

struct firewall_context {
	GList *rules;
};

static GSList *managed_tables;

static bool firewall_is_up;
static unsigned int firewall_rule_id;

static int chain_to_index(const char *chain_name)
{
	if (!g_strcmp0(builtin_chains[NF_IP_PRE_ROUTING], chain_name))
		return NF_IP_PRE_ROUTING;
	if (!g_strcmp0(builtin_chains[NF_IP_LOCAL_IN], chain_name))
		return NF_IP_LOCAL_IN;
	if (!g_strcmp0(builtin_chains[NF_IP_FORWARD], chain_name))
		return NF_IP_FORWARD;
	if (!g_strcmp0(builtin_chains[NF_IP_LOCAL_OUT], chain_name))
		return NF_IP_LOCAL_OUT;
	if (!g_strcmp0(builtin_chains[NF_IP_POST_ROUTING], chain_name))
		return NF_IP_POST_ROUTING;

	return -1;
}

static int managed_chain_to_index(const char *chain_name)
{
	if (!g_str_has_prefix(chain_name, CHAIN_PREFIX))
		return -1;

	return chain_to_index(chain_name + strlen(CHAIN_PREFIX));
}

static int insert_managed_chain(int type, const char *table_name, int id)
{
	char *rule, *managed_chain;
	int err;

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX,
					builtin_chains[id]);

	err = __connman_iptables_new_chain(type, table_name, managed_chain);

	if (err < 0)
		goto out;

	rule = g_strdup_printf("-j %s", managed_chain);

	err = __connman_iptables_insert(type, table_name,
					builtin_chains[id], rule);

	g_free(rule);
	if (err < 0) {
		__connman_iptables_delete_chain(type, table_name,
						managed_chain);
		goto out;
	}

out:
	g_free(managed_chain);

	return err;
}

static int delete_managed_chain(int type, const char *table_name, int id)
{
	char *rule, *managed_chain;
	int err;

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX,
					builtin_chains[id]);

	rule = g_strdup_printf("-j %s", managed_chain);
	err = __connman_iptables_delete(type, table_name,
					builtin_chains[id], rule);
	g_free(rule);

	if (err < 0)
		goto out;

	err =  __connman_iptables_delete_chain(type, table_name,
					managed_chain);

out:
	g_free(managed_chain);

	return err;
}

static int insert_managed_rule(int type, const char *table_name,
				const char *chain_name,
				const char *rule_spec)
{
	struct connman_managed_table *mtable = NULL;
	GSList *list;
	char *chain;
	int id, err;

	id = chain_to_index(chain_name);
	if (id < 0) {
		/* This chain is not managed */
		chain = g_strdup(chain_name);
		goto out;
	}

	for (list = managed_tables; list; list = list->next) {
		mtable = list->data;

		if (g_strcmp0(mtable->name, table_name) == 0 &&
				mtable->type == type)
			break;

		mtable = NULL;
	}

	if (!mtable) {
		mtable = g_new0(struct connman_managed_table, 1);
		mtable->name = g_strdup(table_name);
		mtable->type = type;

		managed_tables = g_slist_prepend(managed_tables, mtable);
	}

	if (mtable->chains[id] == 0) {
		DBG("table %s add managed chain for %s",
			table_name, chain_name);

		err = insert_managed_chain(type, table_name, id);
		if (err < 0)
			return err;
	}

	mtable->chains[id]++;
	chain = g_strdup_printf("%s%s", CHAIN_PREFIX, chain_name);

out:
	err = __connman_iptables_append(type, table_name, chain, rule_spec);
	
	if (err < 0)
		DBG("table %s cannot append rule %s", table_name, rule_spec);

	g_free(chain);

	return err;
 }

static int delete_managed_rule(int type, const char *table_name,
				const char *chain_name,
				const char *rule_spec)
 {
	struct connman_managed_table *mtable = NULL;
	GSList *list;
	int id, err;
	char *managed_chain;

	id = chain_to_index(chain_name);
	if (id < 0) {
		/* This chain is not managed */
		return __connman_iptables_delete(type, table_name,
						chain_name, rule_spec);
	}

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX, chain_name);

	err = __connman_iptables_delete(type, table_name, managed_chain,
				rule_spec);
	
	if (err < 0)
		DBG("table %s managed rule %s was not removed from ip%stables",
			table_name, rule_spec, type == AF_INET6 ? "6" : "");

	for (list = managed_tables; list; list = list->next) {
		mtable = list->data;

		if (g_strcmp0(mtable->name, table_name) == 0 &&
				mtable->type == type)
			break;

		mtable = NULL;
	}

	if (!mtable) {
		err = -ENOENT;
		goto out;
	}

	mtable->chains[id]--;
	if (mtable->chains[id] > 0)
		goto out;

	DBG("table %s remove managed chain for %s",
			table_name, chain_name);

	err = delete_managed_chain(type, table_name, id);

 out:
	g_free(managed_chain);

	return err;
}

static void cleanup_managed_table(gpointer user_data)
{
	struct connman_managed_table *table = user_data;

	g_free(table->name);
	g_free(table);
}

static void cleanup_fw_rule(gpointer user_data)
{
	struct fw_rule *rule = user_data;

	g_free(rule->rule_spec);
	g_free(rule->chain);
	g_free(rule->table);
	g_free(rule);
}

struct firewall_context *__connman_firewall_create(void)
{
	struct firewall_context *ctx;

	ctx = g_new0(struct firewall_context, 1);

	return ctx;
}

void __connman_firewall_destroy(struct firewall_context *ctx)
{
	g_list_free_full(ctx->rules, cleanup_fw_rule);
	g_free(ctx);
}

static int firewall_enable_rule(struct fw_rule *rule)
{
	int err;

	if (rule->enabled)
		return -EALREADY;

	DBG("%d %s %s %s", rule->type, rule->table, rule->chain,
			rule->rule_spec);

	err = insert_managed_rule(rule->type, rule->table, rule->chain,
					rule->rule_spec);
	if (err < 0)
		return err;

	err = __connman_iptables_commit(rule->type, rule->table);

	if (err < 0)
		return err;

	rule->enabled = true;

	return 0;
}

static int firewall_disable_rule(struct fw_rule *rule)
{
	int err;

	if (!rule->enabled)
		return -EALREADY;

	err = delete_managed_rule(rule->type, rule->table, rule->chain,
					rule->rule_spec);
	if (err < 0) {
		connman_error("pre-commit: Cannot remove previously installed "
			"iptables rules: %s", strerror(-err));
		return err;
	}

	err = __connman_iptables_commit(rule->type, rule->table);
	
	if (err < 0) {
		connman_error("Cannot remove previously installed "
			"iptables rules: %s", strerror(-err));
		return err;
	}

	rule->enabled = false;

	return 0;
}

int __connman_firewall_add_rule(struct firewall_context *ctx,
				const char *table,
				const char *chain,
				const char *rule_fmt, ...)
{
	va_list args;
	char *rule_spec;
	struct fw_rule *rule;

	va_start(args, rule_fmt);

	rule_spec = g_strdup_vprintf(rule_fmt, args);

	va_end(args);

	rule = g_new0(struct fw_rule, 1);

	rule->id = firewall_rule_id++;
	rule->type = AF_INET;
	rule->enabled = false;
	rule->table = g_strdup(table);
	rule->chain = g_strdup(chain);
	rule->rule_spec = rule_spec;

	ctx->rules = g_list_append(ctx->rules, rule);
	return rule->id;
}

int __connman_firewall_add_ipv6_rule(struct firewall_context *ctx,
				const char *table,
				const char *chain,
				const char *rule_fmt, ...)
{
	va_list args;
	char *rule_spec;
	struct fw_rule *rule;

	va_start(args, rule_fmt);

	rule_spec = g_strdup_vprintf(rule_fmt, args);

	va_end(args);

	rule = g_new0(struct fw_rule, 1);

	rule->id = firewall_rule_id++;
	rule->type = AF_INET6;
	rule->enabled = false;
	rule->table = g_strdup(table);
	rule->chain = g_strdup(chain);
	rule->rule_spec = rule_spec;

	ctx->rules = g_list_append(ctx->rules, rule);
	return rule->id;
}

int __connman_firewall_remove_rule(struct firewall_context *ctx, int id)
{
	struct fw_rule *rule;
	GList *list;
	int err = -ENOENT;

	list = g_list_last(ctx->rules);
	while (list) {
		GList *prev = g_list_previous(list);

		rule = list->data;
		if (rule->id == id || id == FW_ALL_RULES) {
			ctx->rules = g_list_remove(ctx->rules, rule);
			cleanup_fw_rule(rule);
			err = 0;

			if (id != FW_ALL_RULES)
				break;
		}

		list = prev;
	}

	return err;
}

/* For consistency, both IPv4 and IPv6 rules can be removed in similar way. */
int __connman_firewall_remove_ipv6_rule(struct firewall_context *ctx, int id)
{
	return __connman_firewall_remove_rule(ctx, id);
}

int __connman_firewall_enable_rule(struct firewall_context *ctx, int id)
{
	struct fw_rule *rule;
	GList *list;
	int err = -ENOENT;

	for (list = g_list_first(ctx->rules); list; list = g_list_next(list)) {
		rule = list->data;

		if (rule->id == id || id == FW_ALL_RULES) {
			err = firewall_enable_rule(rule);
			if (err < 0)
				break;

			if (id != FW_ALL_RULES)
				break;
		}
	}

	return err;
}

int __connman_firewall_disable_rule(struct firewall_context *ctx, int id)
{
	struct fw_rule *rule;
	GList *list;
	int e;
	int err = -ENOENT;

	for (list = g_list_last(ctx->rules); list;
			list = g_list_previous(list)) {
		rule = list->data;

		if (rule->id == id || id == FW_ALL_RULES) {
			e = firewall_disable_rule(rule);

			/* Report last error back */
			if (e == 0 && err == -ENOENT)
				err = 0;
			else if (e < 0)
				err = e;

			if (id != FW_ALL_RULES)
				break;
		}
	}

	return err;
}

int __connman_firewall_enable(struct firewall_context *ctx)
{
	int err;

	err = __connman_firewall_enable_rule(ctx, FW_ALL_RULES);
	if (err < 0) {
		connman_warn("Failed to install iptables rules: %s",
				strerror(-err));
		__connman_firewall_disable_rule(ctx, FW_ALL_RULES);
		return err;
	}

	firewall_is_up = true;

	return 0;
}

int __connman_firewall_disable(struct firewall_context *ctx)
{
	__connman_firewall_disable_rule(ctx, FW_ALL_RULES);
	return __connman_firewall_remove_rule(ctx, FW_ALL_RULES);
}

bool __connman_firewall_is_up(void)
{
	return firewall_is_up;
}

static void iterate_chains_cb(const char *chain_name, void *user_data)
{
	GSList **chains = user_data;
	int id;

	id = managed_chain_to_index(chain_name);
	if (id < 0)
		return;

	*chains = g_slist_prepend(*chains, GINT_TO_POINTER(id));
}

static void flush_table(int type, const char *table_name)
{
	GSList *chains = NULL, *list;
	char *rule, *managed_chain;
	int id, err;

	err = __connman_iptables_iterate_chains(type, table_name,
					iterate_chains_cb, &chains);
	
	if (err < 0)
		DBG("table %s cannot iterate chains", table_name);

	for (list = chains; list; list = list->next) {
		id = GPOINTER_TO_INT(list->data);

		managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX,
						builtin_chains[id]);

		rule = g_strdup_printf("-j %s", managed_chain);
		
		err = __connman_iptables_delete(type, table_name,
						builtin_chains[id],
						rule);

		if (err < 0) {
			connman_warn("Failed to delete jump rule '%s': %s",
				rule, strerror(-err));
		}
		g_free(rule);

		err = __connman_iptables_flush_chain(type, table_name,
						managed_chain);
		
		if (err < 0) {
			connman_warn("Failed to flush chain '%s': %s",
				managed_chain, strerror(-err));
		}
		
		err = __connman_iptables_delete_chain(type, table_name,
						managed_chain);
		
		if (err < 0) {
			connman_warn("Failed to delete chain '%s': %s",
				managed_chain, strerror(-err));
		}

		g_free(managed_chain);
	}

	err = __connman_iptables_commit(type, table_name);
	if (err < 0) {
		connman_warn("Failed to flush table '%s': %s",
			table_name, strerror(-err));
	}

	g_slist_free(chains);
}

static void flush_all_tables(int type)
{
	/* Flush the tables ConnMan might have modified
	 * But do so if only ConnMan has done something with
	 * iptables */

	if (!g_file_test("/proc/net/ip_tables_names",
			G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		firewall_is_up = false;
		return;
	}

	firewall_is_up = true;

	flush_table(type, "filter");
	flush_table(type, "mangle");
	flush_table(type, "nat");
}

int __connman_firewall_init(void)
{
	DBG("");

	flush_all_tables(AF_INET);
	flush_all_tables(AF_INET6);

	return 0;
}

void __connman_firewall_cleanup(void)
{
	DBG("");

	g_slist_free_full(managed_tables, cleanup_managed_table);
}
