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
#include <netdb.h>

#include <xtables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include <gdbus.h>

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
	char *ifname;
};

struct firewall_context {
	GList *rules;
	bool enabled;
};

static GSList *managed_tables = NULL;

static bool firewall_is_up;
static unsigned int firewall_rule_id;

#define FIREWALLFILE "firewall.conf"
#define FIREWALLCONFIGFILE CONFIGDIR "/" FIREWALLFILE
#define FIREWALLCONFIGDIR CONFIGDIR "/firewall.d/"
#define GROUP_GENERAL "General"
#define GROUP_TETHERING "tethering"
#define GENERAL_FIREWALL_POLICIES 3

struct general_firewall_context {
	char **policies;
	char **policiesv6;
	char **restore_policies;
	char **restore_policiesv6;
	struct firewall_context *ctx;
};

static struct general_firewall_context *general_firewall = NULL;

/* The dynamic rules that are loaded from config */
static struct firewall_context **dynamic_rules = NULL;

/* Tethering rules are a special case */
static struct firewall_context *tethering_firewall = NULL;

/* Configuration files that are read */
static GList *configuration_files = NULL;

static const char *supported_chains[] = {
	[NF_IP_PRE_ROUTING]	= NULL,
	[NF_IP_LOCAL_IN]	= "IPv4.INPUT.RULES",
	[NF_IP_FORWARD]		= "IPv4.FORWARD.RULES",
	[NF_IP_LOCAL_OUT]	= "IPv4.OUTPUT.RULES",
	[NF_IP_POST_ROUTING]	= NULL,
};

static const char *supported_chainsv6[] = {
	[NF_IP_PRE_ROUTING]	= NULL,
	[NF_IP_LOCAL_IN]	= "IPv6.INPUT.RULES",
	[NF_IP_FORWARD]		= "IPv6.FORWARD.RULES",
	[NF_IP_LOCAL_OUT]	= "IPv6.OUTPUT.RULES",
	[NF_IP_POST_ROUTING]	= NULL,
};

static const char *supported_policies[] = {
	[NF_IP_PRE_ROUTING]	= NULL,
	[NF_IP_LOCAL_IN]	= "IPv4.INPUT.POLICY",
	[NF_IP_FORWARD]		= "IPv4.FORWARD.POLICY",
	[NF_IP_LOCAL_OUT]	= "IPv4.OUTPUT.POLICY",
	[NF_IP_POST_ROUTING]	= NULL,
};

static const char *supported_policiesv6[] = {
	[NF_IP_PRE_ROUTING]	= NULL,
	[NF_IP_LOCAL_IN]	= "IPv6.INPUT.POLICY",
	[NF_IP_FORWARD]		= "IPv6.FORWARD.POLICY",
	[NF_IP_LOCAL_OUT]	= "IPv6.OUTPUT.POLICY",
	[NF_IP_POST_ROUTING]	= NULL,
};

/*
 * The dynamic rules that are currently in use. Service name is used as hash
 * value and the struct firewall_context is the data held.
 */
static GHashTable *current_dynamic_rules = NULL;

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

static char *format_new_rule(int chain, const char* ifname, const char* rule)
{
	char *new_rule = NULL;

	if (ifname && *ifname && rule && *rule) {
		switch (chain) {
		case NF_IP_LOCAL_IN:
			new_rule = g_strdup_printf("-i %s %s", ifname, rule);
			break;
		case NF_IP_FORWARD:
		case NF_IP_LOCAL_OUT:
			new_rule = g_strdup_printf("-o %s %s", ifname, rule);
			break;
		default:
			break;
		}
	}

	return new_rule;
}

static int insert_managed_rule(int type,
				const char *table_name,
				const char *chain_name,
				const char *ifname,
				const char *rule_spec)
{
	struct connman_managed_table *mtable = NULL;
	GSList *list;
	char *chain;
	char *full_rule = NULL;
	int id, err;

	id = chain_to_index(chain_name);

	full_rule = format_new_rule(id, ifname, rule_spec);

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
	err = __connman_iptables_append(type, table_name, chain,
				full_rule ? full_rule : rule_spec);
	
	if (err < 0)
		DBG("table %s cannot append rule %s", table_name,
				full_rule ? full_rule : rule_spec);

	g_free(chain);
	g_free(full_rule);

	return err;
 }

static int delete_managed_rule(int type, const char *table_name,
				const char *chain_name,
				const char *ifname,
				const char *rule_spec)
 {
	struct connman_managed_table *mtable = NULL;
	GSList *list;
	int id, err;
	char *managed_chain;
	char *full_rule = NULL;

	id = chain_to_index(chain_name);

	full_rule = format_new_rule(id, ifname, rule_spec);

	if (id < 0) {
		/* This chain is not managed */
		return __connman_iptables_delete(type, table_name,
					chain_name,
					full_rule ? full_rule : rule_spec);
	}

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX, chain_name);

	err = __connman_iptables_delete(type, table_name, managed_chain,
				full_rule ? full_rule : rule_spec);
	
	if (err < 0)
		DBG("table %s managed rule %s was not removed from ip%stables",
			table_name, full_rule ? full_rule : rule_spec,
			type == AF_INET6 ? "6" : "");

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
	g_free(full_rule);

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

	g_free(rule->ifname);
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

	DBG("%d %s %s %s %s", rule->type, rule->table, rule->chain,
					rule->ifname, rule->rule_spec);

	err = insert_managed_rule(rule->type, rule->table, rule->chain,
					rule->ifname, rule->rule_spec);
	if (err < 0) {
		DBG("cannot insert managed rule %d", err);
		return err;
	}

	err = __connman_iptables_commit(rule->type, rule->table);

	if (err < 0) {
		DBG("iptables commit failed %d", err);
		return err;
	}

	rule->enabled = true;

	return 0;
}

static int firewall_disable_rule(struct fw_rule *rule)
{
	int err;

	if (!rule->enabled)
		return -EALREADY;

	err = delete_managed_rule(rule->type, rule->table, rule->chain,
					rule->ifname, rule->rule_spec);
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
	int e;
	int err = -ENOENT;
	int count = 0;

	for (list = g_list_first(ctx->rules); list; list = g_list_next(list)) {
		rule = list->data;

		if (rule->id == id || id == FW_ALL_RULES) {
			e = firewall_enable_rule(rule);

			/* Do not stop if enabling all rules */
			if (e == 0 && err == -ENOENT)
				err = 0;
			else if (e < 0)
				err = e;

			if (id != FW_ALL_RULES)
				break;
		}

		count++;
	}

	if (!err && id == FW_ALL_RULES) {
		DBG("firewall enabled");
		ctx->enabled = true;
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

	if (!err && id == FW_ALL_RULES) {
		DBG("firewall disabled");
		ctx->enabled = false;
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

#define IP_TABLES_NAMES_FILE "/proc/net/ip_tables_names"
#define IP6_TABLES_NAMES_FILE "/proc/net/ip6_tables_names"

static void flush_all_tables(int type)
{
	gchar *content = NULL;
	gsize len = -1;
	GError *error = NULL;
	const char *iptables_file = NULL;
	const char *tables[] = { "filter", "mangle", "nat", NULL };
	char **tokens = NULL;
	int i, j;

	switch (type) {
	case AF_INET:
		iptables_file = IP_TABLES_NAMES_FILE;
		break;
	case AF_INET6:
		iptables_file = IP6_TABLES_NAMES_FILE;
		break;
	default:
		return;
	}

	if (!g_file_test(iptables_file,
			G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		firewall_is_up = false;
		return;
	}

	firewall_is_up = true;

	if (!g_file_get_contents(iptables_file, &content, &len, &error)) {
		DBG("cannot flush tables, file %s read error: %s",
					iptables_file, error->message);
		g_clear_error(&error);
		goto out;
	}

	tokens = g_strsplit(content, "\n", -1);

	if (!tokens || !g_strv_length(tokens))
		goto out;

	/* Flush the tables ConnMan might have modified
	 * But do so if only ConnMan has done something with
	 * iptables */
	for (i = 0; tables[i]; i++) {
		for (j = 0; tokens[j]; j++) {
			if (!g_strcmp0(tables[i], tokens[j])) {
				DBG("flush type %d table %s", type, tables[i]);
				flush_table(type, tables[i]);
			}
		}
	}

out:
	g_free(content);
	g_strfreev(tokens);
}

static bool has_dynamic_rules_set(enum connman_service_type type)
{
	if (!dynamic_rules || !dynamic_rules[type])
		return false;

	if (g_list_length(dynamic_rules[type]->rules) == 0)
		return false;

	return true;
}

static void setup_firewall_rule_interface(gpointer data, gpointer user_data)
{
	struct fw_rule *rule;
	char *ifname;

	rule = data;
	ifname = user_data;

	/* If rule is already enabled interface info is already set */
	if (!rule || !ifname || rule->enabled)
		return;

	if (rule->ifname && g_str_equal(rule->ifname, ifname)) {
		DBG("rule %d ifname %s not changed", rule->id, rule->ifname);
		return;
	}

	g_free(rule->ifname);
	rule->ifname = g_strdup(ifname);

	DBG("rule %d %s %s", rule->id, rule->ifname, rule->rule_spec);
}

static gpointer copy_fw_rule(gconstpointer src, gpointer data)
{
	const struct fw_rule *old;
	struct fw_rule *new;
	char *ifname;
	
	old = src;
	ifname = data;

	if (!old)
		return NULL;

	new = g_try_new0(struct fw_rule, 1);

	if (!new)
		return NULL;

	new->id = firewall_rule_id++;
	new->enabled = false;
	new->type = old->type;
	new->table = g_strdup(old->table);
	new->chain = g_strdup(old->chain);
	new->rule_spec = g_strdup(old->rule_spec);

	setup_firewall_rule_interface(new, ifname);

	return new;
}

static struct firewall_context *clone_firewall_context(
						struct firewall_context *ctx,
						char *ifname)
{
	struct firewall_context *clone;

	if (!ctx || !ifname)
		return NULL;
	
	clone = __connman_firewall_create();
	
	if (!clone)
		return NULL;
	
	clone->rules = g_list_copy_deep(ctx->rules, copy_fw_rule, ifname);
	
	return clone;
}

static int enable_dynamic_rules(struct connman_service *service)
{
	struct firewall_context *ctx;
	enum connman_service_type type;
	const char *identifier;
	char *ifname = NULL;
	char *hash;

	DBG("");

	/* This is not set if the configuration has not been loaded */
	if (!current_dynamic_rules)
		return 0;

	identifier = connman_service_get_identifier(service);

	ctx = g_hash_table_lookup(current_dynamic_rules, identifier);

	/* Not found, check if it has dynamic rules configured */
	if (!ctx) {
		type = connman_service_get_type(service);
		
		/* No rules set for this type */
		if (!has_dynamic_rules_set(type))
			return 0;

		ifname = connman_service_get_interface(service);

		/* Create a clone with interface info from service */
		ctx = clone_firewall_context(dynamic_rules[type], ifname);

		/* Allocation of ctx failed */
		if (!ctx) {
			g_free(ifname);
			return -ENOMEM;
		}

		hash = g_strdup(identifier);

		/*
		 * Add a new into hash table, this condition should not be ever
		 * met. Left for debugging.
		 */
		if (!g_hash_table_replace(current_dynamic_rules, hash, ctx))
			DBG("hash table error, key %s exists", hash);
		else
			DBG("added new firewall rules for service %p %s",
					service, identifier);
	} else {
		if (ctx->enabled)
			return -EALREADY;

		ifname = connman_service_get_interface(service);

		/* Set interface information for each firewall rule */
		g_list_foreach(ctx->rules, setup_firewall_rule_interface,
					ifname);

		DBG("reused firewall for service %p %s", service, identifier);
	}

	g_free(ifname);

	return __connman_firewall_enable(ctx);
}

static int disable_dynamic_rules(struct connman_service *service)
{
	struct firewall_context *ctx;
	const char *identifier;

	DBG("");

	if (!current_dynamic_rules)
		return 0;

	identifier = connman_service_get_identifier(service);

	ctx = g_hash_table_lookup(current_dynamic_rules, identifier);

	/* No rules set, no error */
	if (!ctx)
		return 0;

	if (!ctx->enabled)
		return -EALREADY;

	/* Only disable rules, do not remove them to reduce mem fragmentation */
	return __connman_firewall_disable_rule(ctx, FW_ALL_RULES);
}

static void service_state_changed(struct connman_service *service,
				enum connman_service_state state)
{
	enum connman_service_type type;
	int err;

	type = connman_service_get_type(service);

	DBG("service %p %s type %d state %d", service,
				__connman_service_get_name(service), type,
				state);

	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		break;
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		err = disable_dynamic_rules(service);

		if (err == -EALREADY)
			DBG("dynamic firewall already disabled for service %p",
						service);
		else if (err)
			DBG("cannot disable dynamic rules of service %p "
						"error %d", service, err);

		break;
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		err = enable_dynamic_rules(service);

		if (err == -EALREADY)
			DBG("dynamic firewall already enabled for service %p",
						service);
		else if (err == -ENOMEM)
			DBG("firewall cloning failed for service %p", service);
		else if (err)
			DBG("cannot enable dynamic rules of service %p "
						", error %d", service, err);
	}
}

static void service_remove(struct connman_service *service)
{
	const char *identifier;

	if (!current_dynamic_rules)
		return;

	identifier = connman_service_get_identifier(service);

	if (g_hash_table_remove(current_dynamic_rules, identifier))
		DBG("removed dynamic rules of service %s", identifier);
}

static int add_default_tethering_rules(struct firewall_context *ctx,
								char *ifname)
{
	/* Add more in the future if needed */
	const char *tethering_rules[] = { "-j ACCEPT", NULL };
	int id;
	int i;

	/* Add tethering rules for both IPv4 and IPv6 when using usb */
	for (i = 0; tethering_rules[i]; i++) {
		id = __connman_firewall_add_rule(ctx, "filter", "INPUT",
					tethering_rules[i]);
		if (id < 0)
			DBG("cannot add IPv4 rule %s",
						tethering_rules[i]);

		id = __connman_firewall_add_ipv6_rule(ctx, "filter",
					"INPUT", tethering_rules[i]);
		if (id < 0)
			DBG("cannot add IPv6 rule %s",
						tethering_rules[i]);
	}

	g_list_foreach(ctx->rules, setup_firewall_rule_interface,
					ifname);

	return 0;
}

#define DEFAULT_TETHERING_IDENT "tethering_default"

static void tethering_changed(struct connman_technology *tech, bool on)
{
	struct firewall_context *ctx;
	enum connman_service_type type;
	const char *identifier;
	char *ifname = NULL;
	char *hash;
	int err;
	
	DBG("technology %p %s", tech, on ? "on" : "off");
	
	if (!tech)
		return;
	
	/* This is not set if the configuration has not been loaded */
	if (!current_dynamic_rules)
		return;

	type = __connman_technology_get_type(tech);
	identifier = __connman_technology_get_tethering_ident(tech);
	
	/* This is known to happen with usb tethering, no ident exists */
	if (!identifier)
		identifier = DEFAULT_TETHERING_IDENT;
	
	DBG("tethering ident %s type %s", identifier,
				__connman_service_type2string(type));
	
	ctx = g_hash_table_lookup(current_dynamic_rules, identifier);

	/* Not found, create new. */
	if (!ctx) {
		/* If no rules are set and tethering is disabled, return */
		if (!on)
			return;

		/*
		 * Eventually ifname is duplicated for each rule but bridge is
		 * defined as const in technology.c it is safer to dup the
		 * ifname and free it accordingly.
		 */
		ifname = g_strdup(__connman_tethering_get_bridge());

		/* Clone with specific types only */
		switch (type) {
		case CONNMAN_SERVICE_TYPE_WIFI:
			ctx = clone_firewall_context(tethering_firewall,
						ifname);
			break;
		default:
			break;
		}

		/* No match to type of tethering_firewall is not set */
		if (!ctx) {
			ctx = __connman_firewall_create();

			/* Allocation of ctx failed, disable tethering. */
			if (!ctx) {
				DBG("new firewall cannot be created");
				goto disable;
			}
		}

		/* If list is empty add default rules */
		if (!g_list_length(ctx->rules)) {
			/* Try to add default rules for tethering */
			if (add_default_tethering_rules(ctx, ifname)) {
				DBG("default tethering rules cannot be added.");
				goto disable;
			}
		}

		hash = g_strdup(identifier);

		/*
		 * Add a new into hash table, this condition should not be ever
		 * met. Left for debugging.
		 */
		if (!g_hash_table_replace(current_dynamic_rules, hash, ctx))
			DBG("hash table error, key %s exists", hash);
		else
			DBG("added new tethering firewall rules for %p %s %s",
						tech, identifier, ifname);
	} else {
		/*
		 * If tethering is on and firewall is enabled, return. 
		 * If tethering is off and firewall is disabled, return.
		 */
		if ((on && ctx->enabled) || (!on && !ctx->enabled)) {
			DBG("tethering firewall already %s for %s",
						on ? "enabled" : "disabled",
						identifier);
			return;
		}

		/*
		 * If there is a tethering firewall for this identifier it will
		 * have the rules set up properly. Just to make sure, update the
		 * used interface info.
		 */
		if (on) {
			ifname = g_strdup(__connman_tethering_get_bridge());

			/* Set interface information for each firewall rule */
			g_list_foreach(ctx->rules,
						setup_firewall_rule_interface,
						ifname);

			DBG("reused tethering firewall for %p %s %s",
						tech, identifier, ifname);
		}
	}

	if (on) {
		err = __connman_firewall_enable(ctx);

		if (err && err != -EALREADY) {
			DBG("cannot enable firewall, tethering disabled: "
						"error %d", err);
			goto disable;
		}
	} else {
		err = __connman_firewall_disable_rule(ctx, FW_ALL_RULES);

		if (err && err != -EALREADY)
			DBG("cannot disable firewall: error %d", err);
	}

	g_free(ifname);

	return;

disable:
	connman_error("tethering firewall error, tethering disabled");

	/* This generates notification */
	connman_technology_tethering_notify(tech, FALSE);
	g_free(ifname);
}

enum iptables_switch_type {
	IPTABLES_UNSET    = 0,
	IPTABLES_SWITCH   = 1,
	IPTABLES_MATCH    = 2,
	IPTABLES_TARGET   = 3,
	IPTABLES_PROTO    = 4,
	IPTABLES_PORT     = 5,
};

#define MAX_IPTABLES_SWITCH 6

static bool is_string_digits(const char *str)
{
	int i;

	if (!str || !*str)
		return false;

	for (i = 0; str[i]; i++) {
		if (!g_ascii_isdigit(str[i]))
			return false;
	}
	return true;
}

/* Protocols that iptables supports with -p or --protocol switch */
	const char *supported_protocols[] = { 	"tcp",
						"udp",
						"udplite",
						"icmp",
						"icmpv6",
						"ipv6-icmp",
						"esp",
						"ah",
						"sctp",
						"mh",
						"all",
						NULL
	};

static bool is_supported(int type, enum iptables_switch_type switch_type,
					const char* group, const char *str)
{
	/*
	 * The switches and matches that are not supported.
	 * 
	 * Chain manipulation is not supported, the rules are going to specific
	 * managed chains within connman.
	 *
	 * Setting specific addresses is not supported because the purpose of
	 * these rules is to set the base line of prevention to be used on both
	 * IPv4 and IPv6. In the future rules may be separated to have own for
	 * both of the IP protocols.
	 
	 * Setting specific interfaces is not supported for dynamic rules, these
	 * are added dynamically into the rules when interface comes up. For
	 * General rules setting interfaces is allowed.
	 */
	const char *not_supported_switches[] = { "--source", "--src","-s",
						"--destination", "--dst", "-d",
						"--append", "-A",
						"--delete", "-D",
						"--delete-chain", "-X",
						"--flush", "-F",
						"--insert", "-I",
						"--new-chain", "-N",
						"--policy", "-P",
						"--rename-chain", "-E",
						"--replace", "-R",
						"--zero", "-Z",
						"--to-destination",
						"--from-destination",
						NULL
	};
	const char *not_supported_dynamic_switches[] = { "--in-interface", "-i",
						"--out-interface", "-o",
						NULL
	};

	const char *not_supported_matches_ipv4[] = { "comment",
						"state",
						"iprange",
						"recent",
						"owner",
						NULL
	};
	const char *not_supported_matches_ipv6[] = { "comment",
						"state",
						"iprange",
						"recent",
						"owner",
						"ttl",
						NULL
	};

	/*
	 * Targets that are supported. No targets to custom chains are
	 * allowed
	 */
	const char *supported_targets[] = { "ACCEPT",
						"DROP",
						"REJECT",
						"LOG",
						"QUEUE",
						NULL
	};

	struct protoent *p = NULL;
	bool is_general = false;
	int protonum = 0;
	int i = 0;

	/* Do not care about empty or nonexistent content */
	if (!str || !*str)
		return true;
	
	if (group && !g_strcmp0(group, GROUP_GENERAL))
		is_general = true;

	switch (switch_type) {
	case IPTABLES_SWITCH:
		for (i = 0; not_supported_switches[i]; i++) {
			if (!g_strcmp0(str, not_supported_switches[i]))
				return false;
		}

		/* If the rule is not in Group general */
		if (!is_general) {
			for (i = 0; not_supported_dynamic_switches[i]; i++) {
				if (!g_strcmp0(str,
					not_supported_dynamic_switches[i]))
					return false;
			} 
		}

		return true;
	case IPTABLES_MATCH:
		if (type == AF_INET) {
			for (i = 0 ; not_supported_matches_ipv4[i] ; i++) {
				if(!g_strcmp0(str,
						not_supported_matches_ipv4[i]))
					return false;
			}
		} else if (type == AF_INET6) {
			for (i = 0 ; not_supported_matches_ipv6[i] ; i++) {
				if(!g_strcmp0(str,
						not_supported_matches_ipv6[i]))
					return false;
			}
		} else {
			return false;
		}

		return true;
	case IPTABLES_TARGET:
		for (i = 0 ; supported_targets[i] ; i++) {
			if(!g_strcmp0(str, supported_targets[i]))
				return true;
		}

		return false;
	case IPTABLES_PROTO:
		if (is_string_digits(str))
			protonum = (int) g_ascii_strtoll(str, NULL, 10);

		for (i = 0; supported_protocols[i]; i++) {
			/* Protocols can be also capitalized */
			if (!g_ascii_strcasecmp(str, supported_protocols[i]))
				return true;

			/* Protocols can be defined by their number. */
			if (protonum) {
				p = getprotobyname(supported_protocols[i]);
				if (p && protonum == p->p_proto)
					return true;
			}
		}

		return false;
	default:
		return true;
	}
}

static bool is_port_switch(const char *str, bool multiport)
{
	const char *multiport_switches[] = { "--destination-ports", "--dports",
					"--source-ports", "--sports",
					"--port", "--ports",
					NULL
	};
	const char *port_switches[] = { "--destination-port", "--dport",
					"--source-port", "--sport",
					NULL
	};

	int i;

	if (!str || !*str)
		return true;

	if (multiport) {
		for (i = 0; multiport_switches[i]; i++) {
			if (!g_strcmp0(str, multiport_switches[i]))
				return true;
		}
	}

	/* Normal port switches can be used also with -m multiport */
	for (i = 0; port_switches[i]; i++) {
		if (!g_strcmp0(str, port_switches[i])) {
			return true;
		}
	}

	return false;
}

static bool validate_ports_or_services(const char *str)
{
	gchar **tokens;
	 /* In iptables ports are separated with commas, ranges with colon. */
	const char delimiters[] = ",:";
	struct servent *s;
	bool ret = true;
	int portnum;
	int i;

	if (!str || !*str)
		return false;

	tokens = g_strsplit_set(str, delimiters, 0);

	if (!tokens)
		return false;

	for (i = 0; tokens[i]; i++) {

		/* Plain digits, check if port is valid */
		if (is_string_digits(tokens[i])) {
			portnum = (int) g_ascii_strtoll(tokens[i], NULL, 10);

			/* Valid port number */
			if (portnum && portnum < G_MAXUINT16)
				continue;
		}

		/* Check if service name is valid with any protocol */
		s = getservbyname(tokens[i], NULL);

		if (s) {
			if (!g_strcmp0(tokens[i], s->s_name))
				continue;
		}

		/* If one of the ports/services is invalid, rule is invalid */
		ret = false;
		DBG("invalid port/service %s in %s", tokens[i], str);
		break;
	}

	g_strfreev(tokens);

	return ret;
}

static bool protocol_match_equals(const char *protocol, const char *match)
{
	struct protoent *p = NULL;
	int protonum;
	int i;

	if (!protocol || !match)
		return false;

	if (!g_ascii_strcasecmp(protocol, match))
		return true;

	/* If protocol is integer */
	if (is_string_digits(protocol)) {
		protonum = (int) g_ascii_strtoll(protocol, NULL, 10);

		if (!protonum)
			return false;

		p = getprotobynumber(protonum);
	} else {
		p = getprotobyname(protocol);
	}

	if (!p)
		return false;

	/* Protocol official name equals */
	if (!g_ascii_strcasecmp(p->p_name, match))
		return true;

	/* Check if it is one of the aliases */
	for (i = 0; p->p_aliases && p->p_aliases[i]; i++) {
		/* Protocols can be also capitalized */
		if (!g_ascii_strcasecmp(p->p_aliases[i], match))
			return true;
	}

	return false;
}

static bool validate_iptables_rule(int type, const char *group,
							const char *rule_spec)
{
	gchar **argv = NULL;
	GError *error = NULL;
	bool ret = false;
	int i = 0;
	int argc = 0;
	int protocol_opt_index = 0;
	int protocol_match_index = 0;
	bool multiport_used = false;
	unsigned int switch_types_found[MAX_IPTABLES_SWITCH] = { 0 };
	enum iptables_switch_type switch_type = IPTABLES_UNSET;
	const char *match = NULL;
	const char valid_prefix = '-';

	if (!g_shell_parse_argv(rule_spec, &argc, &argv, &error)) {
		DBG("failed in parsing %s", error ? error->message : "");
		goto out;
	}

	/* -j TARGET is the bare minimum of a rule */
	if (argc < 2 || !argv[0][0]) {
		DBG("parsed content is invalid");
		goto out;
	}

	/* Only '-' prefixed rules are allowed in iptables. */
	if (argv[0][0] != valid_prefix) {
		DBG("invalid rule prefix");
		goto out;
	}

	for (i = 0; i < argc; ) {
		const char *arg = argv[i++];

		if (!is_supported(type, IPTABLES_SWITCH, group, arg)) {
			DBG("switch %s is not supported", arg);
			goto out;
		}

		if (!g_strcmp0(arg, "-m")) {
			switch_type = IPTABLES_MATCH;
			match = argv[i++];

			if (!match) {
				DBG("trailing '-m' in rule \"%s\"", rule_spec);
				goto out;
			}

			/* multiport match has to have valid port switches */
			if (!g_strcmp0(match, "multiport")) {
				multiport_used = true;
				
				/* Cannot use -m multiport with -m protocol */
				if (protocol_match_index) {
					DBG("-m multiport with -m %s",
						argv[protocol_match_index]);
					goto out;
				}
				
				const char *opt = argv[i++];

				if (!opt) {
					DBG("empty %s %s switch", arg, match);
					goto out;
				}

				if (!is_port_switch(opt, true)) {
					DBG("non-supported %s %s switch %s",
						arg, match, opt);
					goto out;
				}

				const char *param = argv[i++];
				if (!param) {
					DBG("empty parameter with %s", opt);
					goto out;
				}

				/* Negated switch must be skipped */
				if (!g_strcmp0(param, "!"))
					param = argv[i++];

				if (!validate_ports_or_services(param)) {
					DBG("invalid ports %s %s", opt, param);
					goto out;
				}
			}
			
			/* If this is one of the supported protocols */
			if (is_supported(type, IPTABLES_PROTO, group, match)) {
				/*
				 * If no protocol is set before, protocol match
				 * cannot be used
				 */
				if (!switch_types_found[IPTABLES_PROTO]) {
					DBG("-m %s without -p protocol", match);
					goto out;
				}

				/* Check if match protocol equals */
				if (!protocol_match_equals(
						argv[protocol_opt_index],
						match)) {
					DBG("-p %s -m %s different protocol",
						argv[protocol_opt_index],
						match);
					goto out;
				}

				if (multiport_used) {
					DBG("-m multiport -m %s not supported",
							match);
					goto out;
				}

				/* Store the match index for multiport */
				protocol_match_index = i-1;
			}
		}

		if (!g_strcmp0(arg, "-j")) {
			switch_type = IPTABLES_TARGET;
			match = argv[i++];

			if (!match) {
				DBG("trailing '-j' in rule \"%s\"", rule_spec);
				goto out;
			}
		}

		if (!g_strcmp0(arg, "-p")) {
			switch_type = IPTABLES_PROTO;
			match = argv[i++];

			if (!match) {
				DBG("trailing '-p' in rule \"%s\"", rule_spec);
				goto out;
			}

			/* Negated switch must be skipped */
			if (!g_strcmp0(match, "!"))
				match = argv[i++];
			
			/* Save the protocol index for -m switch check */
			protocol_opt_index = i-1;
		}

		if (is_port_switch(arg, false)) {
			switch_type = IPTABLES_PORT;
			match = argv[i++];

			if (!match) {
				DBG("trailing '%s' in rule \"%s\"", arg,
					rule_spec);
				goto out;
			}

			/* Negated switch must be skipped */
			if (!g_strcmp0(match, "!"))
				match = argv[i++];

			if (!validate_ports_or_services(match)) {
				DBG("invalid ports %s %s", arg, match);
				goto out;
			}
		}

		if (match && !is_supported(type, switch_type, group, match)) {
			DBG("%s %s is not supported", arg, match);
			goto out;
		}

		/* Record the current switch type */
		switch_types_found[switch_type]++;
		switch_type = IPTABLES_UNSET;
		match = NULL;
	}

	/* There can be 0...2 port switches in rule */
	if (switch_types_found[IPTABLES_PORT] > 2)
		goto out;

	/* There should be 0...2 matches in one rule */
	if (switch_types_found[IPTABLES_MATCH] > 2)
		goto out;

	/* There should be 0...1 protocols defined in rule */
	if (switch_types_found[IPTABLES_PROTO] > 1)
		goto out;

	/* There has to be exactly one target in rule */
	if (switch_types_found[IPTABLES_TARGET] != 1)
		goto out;

	ret = true;

out:
	g_clear_error(&error);
	g_strfreev(argv);

	return ret;
}

typedef int (*add_rules_cb_t)(int type, const char *group, int chain_id,
								char** rules);

static int add_dynamic_rules_cb(int type, const char *group, int chain_id,
								char** rules)
{
	enum connman_service_type service_type;
	char table[] = "filter";
	int count = 0;
	int err = 0;
	int id;
	int i; 

	if (!dynamic_rules || !rules)
		return 0;

	service_type = __connman_service_string2type(group);

	if (!dynamic_rules[service_type])
		dynamic_rules[service_type] = __connman_firewall_create();

	for(i = 0; rules[i] ; i++) {

		DBG("process rule tech %s chain %s rule %s", group,
					builtin_chains[chain_id], rules[i]);

		if (!validate_iptables_rule(type, group, rules[i])) {
			DBG("failed to add rule, rule is invalid");
			continue;
		}

		switch (type) {
		case AF_INET:
			id = __connman_firewall_add_rule(
						dynamic_rules[service_type],
						table, builtin_chains[chain_id],
						rules[i]);
			break;
		case AF_INET6:
			id = __connman_firewall_add_ipv6_rule(
						dynamic_rules[service_type],
						table, builtin_chains[chain_id],
						rules[i]);
			break;
		default:
			id = -1;
			DBG("invalid IP protocol %d", type);
			break;
		}

		if (id < 0) {
			DBG("failed to add rule to firewall");
			err = -EINVAL;
		} else {
			DBG("added with id %d", id);
			count++;
		}
	}

	if (!err)
		return count;

	return err;
}

static int add_general_rules_cb(int type, const char *group, int chain_id,
								char** rules)
{
	char table[] = "filter";
	int count = 0;
	int err = 0;
	int id;
	int i;

	if (!general_firewall)
		return -EINVAL;

	if (!general_firewall->ctx)
		general_firewall->ctx = __connman_firewall_create();

	if (!general_firewall->ctx)
		return -ENOMEM;

	if (!rules)
		return 0;

	for (i = 0; rules[i]; i++) {

		if (!g_utf8_validate(rules[i], -1, NULL)) {
			DBG("skipping rule, not valid UTF8");
			continue;
		}

		DBG("processing type %d group %s rule chain %s rule %s", type,
					GROUP_GENERAL, builtin_chains[chain_id],
					rules[i]);

		if (!validate_iptables_rule(type, group, rules[i])) {
			DBG("invalid general rule");
			continue;
		}

		switch (type) {
		case AF_INET:
			id = __connman_firewall_add_rule(general_firewall->ctx,
					table, builtin_chains[chain_id],
					rules[i]);
			break;
		case AF_INET6:
			id = __connman_firewall_add_ipv6_rule(
					general_firewall->ctx, table,
					builtin_chains[chain_id], rules[i]);
			break;
		default:
			id = -1;
			DBG("invalid IP protocol %d", type);
			break;
		}

		if (id < 0) {
			DBG("failed to add group %s chain_id %d rule %s",
					GROUP_GENERAL, chain_id, rules[i]);
			err = -EINVAL;
		} else {
			DBG("added with id %d", id);
			count++;
		}
	}

	if (!err)
		return count;

	return err;
}

static int add_tethering_rules_cb(int type, const char *group, int chain_id,
								char** rules)
{
	char table[] = "filter";
	int count = 0;
	int err = 0;
	int id;
	int i;

	if (!tethering_firewall)
		tethering_firewall = __connman_firewall_create();

	if (!tethering_firewall)
		return -ENOMEM;

	if (!rules)
		return 0;

	for (i = 0; rules[i]; i++) {

		if (!g_utf8_validate(rules[i], -1, NULL)) {
			DBG("skipping rule, not valid UTF8");
			continue;
		}

		DBG("processing type %d group %s rule chain %s rule %s", type,
					group, builtin_chains[chain_id],
					rules[i]);

		if (!validate_iptables_rule(type, group, rules[i])) {
			DBG("invalid general rule");
			continue;
		}

		switch (type) {
		case AF_INET:
			id = __connman_firewall_add_rule(tethering_firewall,
					table, builtin_chains[chain_id],
					rules[i]);
			break;
		case AF_INET6:
			id = __connman_firewall_add_ipv6_rule(
					tethering_firewall, table,
					builtin_chains[chain_id], rules[i]);
			break;
		default:
			id = -1;
			DBG("invalid IP protocol %d", type);
			break;
		}

		if (id < 0) {
			DBG("failed to add group %s chain_id %d rule %s",
					group, chain_id, rules[i]);
			err = -EINVAL;
		} else {
			DBG("added with id %d", id);
			count++;
		}
	}

	if (!err)
		return count;

	return err;
}

static int add_rules_from_group(GKeyFile *config, const char *group,
							add_rules_cb_t cb)
{
	GError *error = NULL;
	char** rules;
	const char *chain_name = NULL;
	int types[3] = { AF_INET, AF_INET6, 0 };
	int chain;
	int count;
	int err = 0;
	int i;
	gsize len;

	DBG("");

	if (!group || !*group || !cb)
		return 0;

	for (chain = NF_IP_LOCAL_IN; chain < NF_IP_NUMHOOKS - 1; chain++) {
		for (i = 0; types[i] ; i++) {

			/* Setup chain name based on IP type */
			switch (types[i]) {
			case AF_INET:
				chain_name = supported_chains[chain];
				break;
			case AF_INET6:
				chain_name = supported_chainsv6[chain];
				break;
			default:
				chain_name = NULL;
			}

			if (!chain_name)
				continue;

			rules = __connman_config_get_string_list(config, group,
						chain_name, &len, &error);

			if (rules && len) {
				DBG("found %d rules in group %s chain %s", len,
							group, chain_name);

				count = cb(types[i], group, chain, rules);
			
				if (count < 0) {
					DBG("cannot add rules from config");
					err = -EINVAL;
				} else if (count < len) {
					DBG("%d invalid rules were detected,"
						"%d rules were added",
						len - count, count);
				} else {
					DBG("all %d rules were added", count);
				}
			} else if (rules && error) {
					/* A real error has happened */
					DBG("group %s chain %s error: %s",
							group, chain_name,
							error->message);
			}

			g_clear_error(&error);

			g_strfreev(rules);
		}
	}

	return err;
}

static bool check_config_key(const char* group, const char* key)
{
	bool is_general = false;
	int i;

	if (group && !g_strcmp0(group, GROUP_GENERAL))
		is_general = true;

	/*
	 * Allow only NF_IP_LOCAL_IN...NF_IP_LOCAL_OUT chains since filter
	 * table has no PRE/POST_ROUTING chains.
	 *
	 * The chain ids defined by netfilter are:
	 * NF_IP_PRE_ROUTING	0
	 * NF_IP_LOCAL_IN	1
	 * NF_IP_FORWARD	2
	 * NF_IP_LOCAL_OUT	3
	 * NF_IP_POST_ROUTING	4
	 * NF_IP_NUMHOOKS	5
	 */
	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1; i++) {
		if (!g_strcmp0(key, supported_chains[i]))  {
			DBG("match key %s chain %s", key, supported_chains[i]);
			return true;
		}

		if (!g_strcmp0(key, supported_chainsv6[i])) {
			DBG("match key %s chain %s", key,
						supported_chainsv6[i]);
			return true;
		}

		/* No other than General group should have policies set. */
		if (is_general) {
			if (!g_strcmp0(key, supported_policies[i])) {
				DBG("match key %s chain %s", key,
						supported_policies[i]);
				return true;
			}
			
			if (!g_strcmp0(key, supported_policiesv6[i])) {
				DBG("match key %s chain %s", key,
						supported_policiesv6[i]);
				return true;
			}
		}
	}

	DBG("no match for key %s", key);

	return false;
}

static bool check_config_group(const char *group)
{
	const char *type_str;
	enum connman_service_type type;
	
	if (!g_strcmp0(group, GROUP_GENERAL)) {
		DBG("match group %s", group);
		return true;
	}

	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN;
				type < MAX_CONNMAN_SERVICE_TYPES; type++) {
			type_str = __connman_service_type2string(type);

			if (!type_str)
				continue;

			if (!g_strcmp0(group, type_str)) {
				DBG("match group %s type %s", group, type_str);
				return true;
			}
	}

	if (!g_strcmp0(group, GROUP_TETHERING)) {
		DBG("match group %s", group);
		return true;
	}

	DBG("no match for group %s", group);

	return false;
}

static bool check_dynamic_rules(GKeyFile *config)
{
	enum connman_service_type type;
	char **keys;
	int i;
	bool ret = true;
	const char *group;

	if (!config)
		return false;

	keys = g_key_file_get_groups(config, NULL);

	/* Check that there are only valid service types */
	for (i = 0; keys && keys[i]; i++) {
		if (!check_config_group(keys[i])) {
			connman_warn("Unknown group %s in file %s",
						keys[i], FIREWALLFILE);
			ret = false;
		}
	}

	g_strfreev(keys);

	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN;
			type < MAX_CONNMAN_SERVICE_TYPES; type++) {

		group = __connman_service_type2string(type);

		if (!group)
			continue;

		keys = g_key_file_get_keys(config, group, NULL, NULL);

		for (i = 0; keys && keys[i]; i++) {
			if (!check_config_key(group, keys[i])) {
				connman_warn("Unknown group %s option %s in %s",
							group, keys[i],
							FIREWALLFILE);
				ret = false;
			}
		}

		g_strfreev(keys);
	}

	return ret;
}

static GKeyFile *load_dynamic_rules(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ';');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (err->code != G_FILE_ERROR_NOENT) {
			connman_error("Parsing %s failed: %s", file,
						err->message);
		}

		g_error_free(err);
		g_key_file_unref(keyfile);
		return NULL;
	}

	return keyfile;
}

static int enable_general_firewall_policies(int type, char **policies)
{
	char table[] = "filter";
	int err;
	int i;

	if (!policies || !g_strv_length(policies))
		return 0;

	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1 ; i++) {
		if (!policies[i-1])
			continue;

		err = __connman_iptables_change_policy(type, table,
					builtin_chains[i], policies[i-1]);

		if (err)
			DBG("cannot set type %d chain %s policy %s", type,
						builtin_chains[i],
						policies[i-1]);
		else {
			DBG("set type %d chain %s policy %s", type,
						builtin_chains[i],
						policies[i-1]);

			err = __connman_iptables_commit(type, table);

			if (err) {
				DBG("commit failed, type %d table %s", type,
							table);
				return err;
			}
		}
	}

	return 0;
}

static int enable_general_firewall()
{
	int err;

	DBG("");

	if (!general_firewall || !general_firewall->ctx) {
		DBG("no general firewall or firewall context set");
		return -EINVAL;
	}

	if (!g_list_length(general_firewall->ctx->rules)) {
		DBG("no general rules set, policies are not set");

		/* No rules defined, no error */
		return 0;
	}

	DBG("%d general rules", g_list_length(general_firewall->ctx->rules));

	err = __connman_firewall_enable(general_firewall->ctx);

	/*
	 * If there is a problem with general firewall, do not apply policies
	 * since it may result in blocking all incoming traffic and the device
	 * is not accessible.
	 */
	if (err) {
		DBG("cannot enable general firewall, policies are not changed");
		return err;
	}

	err = enable_general_firewall_policies(AF_INET,
				general_firewall->policies);

	if (err)
		DBG("cannot enable IPv4 iptables policies, err %d", err);

	err = enable_general_firewall_policies(AF_INET6,
				general_firewall->policiesv6);

	if (err)
		DBG("cannot enable IPv6 iptables policies, err %d", err);

	return err;

}

static bool is_valid_policy(char *policy)
{
	const char *valid_policies[] = {"ACCEPT", "DROP", NULL};

	if (!policy || !*policy)
		return false;

	if (!g_strcmp0(policy, valid_policies[0]) || 
				!g_strcmp0(policy, valid_policies[1]))
		return true;

	DBG("invalid policy %s", policy);

	return false;
}

static int load_general_firewall_policies(int type, GKeyFile *config,
								char **policies)
{
	GError *error = NULL;
	const char *policy;
	char *load_policy;
	int i;

	if (!policies)
		return -EINVAL;

	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1; i++) {
		switch (type) {
		case AF_INET:
			policy = supported_policies[i];
			break;
		case AF_INET6:
			policy = supported_policiesv6[i];
			break;
		default:
			return -EINVAL;
		}

		if (!policy)
			continue;

		load_policy = __connman_config_get_string(config,
					GROUP_GENERAL, policy, &error);

		if (!load_policy) {
			DBG("no policy set for type %d chain %s", type,
						builtin_chains[i]);
		} else if (!is_valid_policy(load_policy)) {
			g_free(load_policy);
		} else {
			/* When the policy is valid, override existing */
			if (policies[i-1])
				g_free(policies[i-1]);

			policies[i-1] = load_policy;
			DBG("set type %d chain %s policy %s", type,
					builtin_chains[i], policies[i-1]);
		}

		/* If policy is read and error is set is is a proper error.*/
		if (policies[i-1] && error)
			DBG("failed to read %s: %s", policy, error->message);

		g_clear_error(&error);
	}

	return 0;
}

static bool restore_policies_set = false;

static int init_general_firewall_policies(GKeyFile *config)
{
	int err = 0;
	int i;

	DBG("");

	if (!general_firewall || !config)
		return -EINVAL;

	if (!general_firewall->policies)
		general_firewall->policies = g_try_new0(char*,
				sizeof(char*) * GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->policies)
		return -ENOMEM;

	if (!general_firewall->restore_policies)
		general_firewall->restore_policies = g_try_new0(char*,
				sizeof(char*) * GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->restore_policies)
		return -ENOMEM;
	
	if (!general_firewall->policiesv6)
		general_firewall->policiesv6 = g_try_new0(char*,
				sizeof(char*) * GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->policiesv6)
		return -ENOMEM;

	if (!general_firewall->restore_policiesv6)
		general_firewall->restore_policiesv6 = g_try_new0(char*,
				sizeof(char*) * GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->restore_policiesv6)
		return -ENOMEM;

	err = load_general_firewall_policies(AF_INET, config,
				general_firewall->policies);
	if (err)
		DBG("failed to load IPv4 iptables chain policies, err %d", err);

	err = load_general_firewall_policies(AF_INET6, config,
				general_firewall->policiesv6);
	if (err)
		DBG("failed to load IPv6 iptables chain policies, err %d", err);

	if (!restore_policies_set) {
		// TODO add function into iptables.c to get chain policy
		for (i = 0; i < GENERAL_FIREWALL_POLICIES ; i++) {
			general_firewall->restore_policies[i] =
						g_strdup("ACCEPT");
			general_firewall->restore_policiesv6[i] =
						g_strdup("ACCEPT");
		}
		restore_policies_set = true;
	}

	return err;
}

static int init_general_firewall(GKeyFile *config)
{
	int err;

	DBG("");

	if (!config)
		return -EINVAL;

	if (!general_firewall)
		general_firewall = g_try_new0(struct general_firewall_context,
									1);

	if (!general_firewall)
		return -ENOMEM;

	err = init_general_firewall_policies(config);

	if (err)
		DBG("cannot initialize general policies"); // TODO react to this

	err = add_rules_from_group(config, GROUP_GENERAL, add_general_rules_cb);

	if (err)
		DBG("cannot setup general firewall rules");

	return err;
}

static void remove_ctx(gpointer user_data)
{
	struct firewall_context *ctx = user_data;

	if (ctx->enabled)
		__connman_firewall_disable_rule(ctx, FW_ALL_RULES);

	__connman_firewall_destroy(ctx);
}

static int init_dynamic_firewall_rules(const char *file)
{
	GKeyFile *config;
	enum connman_service_type type;
	const char *group;
	int ret = 0;

	DBG("");

	config = load_dynamic_rules(file);

	/* No config is set, no error but dynamic rules are disabled */
	if (!config) {
		DBG("no configuration found, file %s", file);
		goto out;
	}

	/* The firewall config must be correct */
	if (!check_dynamic_rules(config)) {
		connman_error("firewall config %s has errors", file);
		ret = -EINVAL;
		goto out;
	}

	if (init_general_firewall(config))
		DBG("Cannot setup general firewall");

	if (!dynamic_rules)
		dynamic_rules = g_try_new0(struct firewall_context*,
					sizeof(struct firewall_context*) *
					MAX_CONNMAN_SERVICE_TYPES);

	if (!dynamic_rules) {
		ret = -ENOMEM;
		goto out;
	}

	if (!current_dynamic_rules)
		current_dynamic_rules = g_hash_table_new_full(g_str_hash,
					g_str_equal,g_free, remove_ctx);

	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN;
			type < MAX_CONNMAN_SERVICE_TYPES ; type++) {

		group = __connman_service_type2string(type);

		if (!group)
			continue;

		if (add_rules_from_group(config, group, add_dynamic_rules_cb))
			DBG("failed to process rules from group type %d", type);
	}

	if (add_rules_from_group(config, GROUP_TETHERING,
				add_tethering_rules_cb))
		DBG("failed to add tethering rules");

out:
	if (config)
		g_key_file_unref(config);

	return ret;
}

static int init_all_dynamic_firewall_rules(void)
{
	GList *iter;
	GError *error = NULL;
	GDir *dir;
	const char *filename = NULL;
	char *filepath = NULL;
	int err;

	err = init_dynamic_firewall_rules(FIREWALLCONFIGFILE);

	if (g_file_test(FIREWALLCONFIGDIR, G_FILE_TEST_IS_DIR)) {
		dir = g_dir_open(FIREWALLCONFIGDIR, 0, &error);

		if (!dir) {
			if (error) {
				DBG("cannot open dir, error: %s",
							error->message);
				g_clear_error(&error);
			}
			goto out;
		}

		DBG("read configs from %s", FIREWALLCONFIGDIR);

		/*
		 * Ordering of files is not guaranteed with g_dir_open(). Read
		 * the filenames into sorted GList.
		 */
		while ((filename = g_dir_read_name(dir))) {
			/* Read configs that have firewall.conf suffix */
			if (!g_str_has_suffix(filename, FIREWALLFILE))
				continue;

			/*
			 * Prepend read files into list of configuration
			 * files to be used in checks when new configurations
			 * are added to avoid unnecessary reads of already read
			 * configurations. Sort list after all are added.
			 */
			configuration_files = g_list_prepend(
						configuration_files,
						g_strdup(filename));
		}

		configuration_files = g_list_sort(configuration_files,
					(GCompareFunc)g_strcmp0);

		for (iter = configuration_files; iter ; iter = iter->next) {
			filename = iter->data;

			filepath = g_strconcat(FIREWALLCONFIGDIR, filename,
						NULL);
			DBG("reading config %s", filepath);

			/* Allow also symbolic links in configs */
			if (g_file_test(filepath, G_FILE_TEST_IS_REGULAR)) {
				if (init_dynamic_firewall_rules(filepath))
					DBG("invalid firewall config");
			}

			g_free(filepath);
		}

		g_dir_close(dir);
	} else {
		DBG("no config dir %s", FIREWALLCONFIGDIR);
	}

	/* Error loading main configuration */
	if (err)
		return err;

out:
	err = enable_general_firewall();

	return err;
}

static int restore_policies(int type, char **policies, char **restore_policies)
{
	char table[] = "filter";
	int commit_err = 0;
	int err = 0;
	int i;

	if (!policies && !restore_policies)
		return -EINVAL;

	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1; i++) {
		/* Policy is changed only if it has been set */
		if (policies[i-1]) {

			g_free(policies[i-1]);

			if (!restore_policies[i-1])
				continue;

			/* Commit errors are not recoverable */
			if (!commit_err) {
				err = __connman_iptables_change_policy(type,
							table,
							builtin_chains[i],
							restore_policies[i-1]);

				if (err) {
					/* Ignore this and continue with next */
					DBG("cannot restore chain %s policy %s",
							builtin_chains[i],
							restore_policies[i-1]);
				} else {
					commit_err = __connman_iptables_commit(
								type, table);

					if (commit_err) {
						DBG("cannot commit policy "
							"restore on chain %s "
							"policy %s",
							builtin_chains[i],
							restore_policies[i-1]);
					}
				}
			}
		}

		g_free(restore_policies[i-1]);
	}

	return commit_err;
}

static void cleanup_general_firewall()
{
	int err;

	DBG("");

	if (!general_firewall)
		return;

	if (!general_firewall->ctx)
		return;

	if (general_firewall->ctx->enabled) {
		err = __connman_firewall_disable_rule(general_firewall->ctx,
				FW_ALL_RULES);

		if (err)
			DBG("Cannot disable generic firewall rules");
	}
	__connman_firewall_destroy(general_firewall->ctx);
	general_firewall->ctx = NULL;

	g_free(general_firewall);
	general_firewall = NULL;
}

static void cleanup_dynamic_firewall_rules()
{
	enum connman_service_type type;

	DBG("");

	if (current_dynamic_rules)
		g_hash_table_destroy(current_dynamic_rules);

	current_dynamic_rules = NULL;

	if (!dynamic_rules)
		return;

	/* These rules are never enabled directly */
	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN + 1;
			type < MAX_CONNMAN_SERVICE_TYPES ; type++) {

		if (!dynamic_rules[type])
			continue;

		__connman_firewall_destroy(dynamic_rules[type]);
		dynamic_rules[type] = NULL;
	}

	if (tethering_firewall) {
		if (tethering_firewall->enabled)
			__connman_firewall_disable_rule(tethering_firewall,
						FW_ALL_RULES);

		__connman_firewall_destroy(tethering_firewall);
		tethering_firewall = NULL;
	}

	cleanup_general_firewall();

	g_free(dynamic_rules);
	dynamic_rules = NULL;
}

static void firewall_failsafe(const char *chain_name, void *user_data)
{
	int err;
	int type;
	const char *data = user_data;

	if (!data)
		return;

	if (!g_strcmp0(data, "AF_INET"))
		type = AF_INET;
	else if (!g_strcmp0(data, "AF_INET6"))
		type = AF_INET6;
	else
		return;

	err = __connman_iptables_change_policy(type, "filter", chain_name,
				"ACCEPT");

	if (err) {
		DBG("cannot set table filter chain %s policy ACCEPT, error %d",
					chain_name, err);
		return;
	}

	err = __connman_iptables_commit(type, "filter");

	if (err)
		DBG("cannot commit table filter chain %s policy, error %d",
					chain_name, err);
}

static int copy_new_dynamic_rules(struct firewall_context *dyn_ctx,
			struct firewall_context *srv_ctx, char* ifname)
{
	GList *srv_list;
	GList *dyn_list;
	struct fw_rule *dyn_rule;
	struct fw_rule *srv_rule;
	struct fw_rule *new_rule;
	int err;

	/* Go over dynamic rules for this type */
	for (dyn_list = dyn_ctx->rules; dyn_list; dyn_list = dyn_list->next) {
		dyn_rule = dyn_list->data;
		bool found = false;

		for (srv_list = srv_ctx->rules; srv_list;
					srv_list = srv_list->next) {

			srv_rule = srv_list->data;
			
			/*
			 * If rule_spec is identical the do not add dynamic
			 * rule into this service firewall, it is already added.
			 */
			if (!g_strcmp0(dyn_rule->rule_spec,
						srv_rule->rule_spec)) {
				found = true;
				break;
			}
		}

		if (found)
			continue;

		new_rule = copy_fw_rule(dyn_rule, ifname);
		
		srv_ctx->rules = g_list_append(srv_ctx->rules, new_rule);

		if (srv_ctx->enabled) {
			err = firewall_enable_rule(new_rule);

			if (err)
				DBG("new rule not enabled %d", err);
		}
	}
	
	return 0;
}

static int firewall_reload_configurations()
{
	GError *error = NULL;
	GDir *dir;
	GHashTableIter iter;
	gpointer key, value;
	struct connman_service *service;
	enum connman_service_type type;
	struct firewall_context *ctx;
	const char *filename;
	char *ifname;
	char *filepath;
	bool new_configuration_files = false;
	int err = 0;

	/* Nothing to read */
	if (!g_file_test(FIREWALLCONFIGDIR, G_FILE_TEST_IS_DIR))
		return 0;

	dir = g_dir_open(FIREWALLCONFIGDIR, 0, &error);

	if (!dir) {
		if (error) {
			DBG("cannot open dir, error: %s", error->message);
			g_clear_error(&error);
		}

		/* Ignore dir open error in reload */
		return 0;
	}

	DBG("read configs from %s", FIREWALLCONFIGDIR);

	while ((filename = g_dir_read_name(dir))) {
		/* Read configs that have firewall.conf suffix */
		if (!g_str_has_suffix(filename, FIREWALLFILE))
			continue;

		/* If config file is already read */
		if (g_list_find_custom(configuration_files, filename,
					(GCompareFunc)g_strcmp0))
			continue;

		filepath = g_strconcat(FIREWALLCONFIGDIR, filename, NULL);

		if (g_file_test(filepath, G_FILE_TEST_IS_REGULAR)) {

			err = init_dynamic_firewall_rules(filepath);

			if (!err) {
				DBG("new configuration %s loaded", filepath);

				configuration_files = g_list_insert_sorted(
						configuration_files,
						g_strdup(filename),
						(GCompareFunc)g_strcmp0);

				new_configuration_files = true;
			}
		}

		g_free(filepath);
	}

	g_dir_close(dir);

	if (!new_configuration_files) {
		DBG("no new configuration was found");
		return 0;
	}

	/* Apply general firewall rules that were added */
	__connman_firewall_enable_rule(general_firewall->ctx, FW_ALL_RULES);

	g_hash_table_iter_init(&iter, current_dynamic_rules);

	/*
	 * Go through all service specific firewalls and add new rules
	 * for each.
	 */
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		service = connman_service_lookup_from_identifier(key);

		if (!service)
			continue;

		type = connman_service_get_type(service);
		ifname = connman_service_get_interface(service);

		if (!has_dynamic_rules_set(type))
			continue;

		ctx = value;

		copy_new_dynamic_rules(dynamic_rules[type], ctx, ifname);

		g_free(ifname);
	}

	return 0;
}

static struct connman_access_firewall_policy *firewall_access_policy = NULL;

static struct connman_access_firewall_policy *get_firewall_access_policy()
{
	if (!firewall_access_policy) {
		/* Use the default policy */
		firewall_access_policy =
				__connman_access_firewall_policy_create(NULL);
	}
	return firewall_access_policy;
}

static DBusMessage *reload(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	int err;

	DBG("conn %p", conn);

	if (__connman_access_firewall_manage(get_firewall_access_policy(),
				"Reload", dbus_message_get_sender(msg),
				CONNMAN_ACCESS_ALLOW) != CONNMAN_ACCESS_ALLOW) {
		DBG("%s is not allowed to reload firewall configurations",
				dbus_message_get_sender(msg));
		return __connman_error_permission_denied(msg);
	}

	err = firewall_reload_configurations();

	/* TODO proper error reporting if necessary/sensible */
	if (err)
		return __connman_error_failed(msg, err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusConnection *connection = NULL;

static const GDBusMethodTable firewall_methods[] = {
	{ GDBUS_ASYNC_METHOD("Reload", NULL, NULL, reload) },
	{ },
};

static struct connman_notifier firewall_notifier = {
	.name			= "firewall",
	.service_state_changed	= service_state_changed,
	.service_remove		= service_remove,
	.tethering_changed	= tethering_changed,
};

int __connman_firewall_init(void)
{
	int err;

	DBG("");

	flush_all_tables(AF_INET);
	flush_all_tables(AF_INET6);

	err = init_all_dynamic_firewall_rules();

	if (!err) { 
		err = connman_notifier_register(&firewall_notifier);
		if (err < 0) {
			DBG("cannot register notifier, dynamic rules disabled");
			cleanup_dynamic_firewall_rules();
		}

		connection = connman_dbus_get_connection();

		if (!g_dbus_register_interface(connection,
					CONNMAN_FIREWALL_PATH,
					CONNMAN_FIREWALL_INTERFACE,
					firewall_methods, NULL, NULL, NULL,
					NULL)) {
			DBG("cannot register dbus, new firewall configuration "
						"cannot be installed runtime");

			dbus_connection_unref(connection);
			connection = NULL;
		}
	} else {
		DBG("dynamic rules disabled, policy ACCEPT set for all chains");
		connman_error("firewall initialization error, reset iptables");
		__connman_iptables_cleanup();
		__connman_iptables_init();
		__connman_iptables_iterate_chains(AF_INET, "filter",
					firewall_failsafe, "AF_INET");
		__connman_iptables_iterate_chains(AF_INET6, "filter",
					firewall_failsafe, "AF_INET6");
	}

	return 0;
}

void __connman_firewall_pre_cleanup(void)
{
	int err;

	if (!general_firewall)
		return;

	err = restore_policies(AF_INET, general_firewall->policies,
				general_firewall->restore_policies);

	if (err)
		DBG("failed to restore IPv4 iptables policies, err %d", err);

	err = restore_policies(AF_INET6, general_firewall->policiesv6,
				general_firewall->restore_policiesv6);

	if (err)
		DBG("failed to restore IPv6 iptables policies, err %d", err);

	g_free(general_firewall->policies);
	general_firewall->policies = NULL;

	g_free(general_firewall->restore_policies);
	general_firewall->restore_policies = NULL;

	g_free(general_firewall->policiesv6);
	general_firewall->policiesv6 = NULL;

	g_free(general_firewall->restore_policiesv6);
	general_firewall->restore_policiesv6 = NULL;
}

void __connman_firewall_cleanup(void)
{
	DBG("");

	if (connection) {
		if (!g_dbus_unregister_interface(connection,
					CONNMAN_FIREWALL_PATH,
					CONNMAN_FIREWALL_INTERFACE))
			DBG("dbus unregister failed");

		dbus_connection_unref(connection);
	}

	__connman_access_firewall_policy_free(firewall_access_policy);
	firewall_access_policy = NULL;

	cleanup_dynamic_firewall_rules();

	g_list_free_full(configuration_files, g_free);
	configuration_files = NULL;

	g_slist_free_full(managed_tables, cleanup_managed_table);
	managed_tables = NULL;
}
