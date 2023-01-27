/*
 *  Connection Manager
 *
 *  Copyright (C) 2023 Jolla Ltd. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include <connman/ipconfig.h>
#include <connman/inet.h>
#include <connman/log.h>
#include <connman/network.h>
#include <connman/plugin.h>
#include <connman/service.h>
#include <connman/task.h>
#include <connman/dbus.h>
#include "../include/nat.h"
#include <connman/notifier.h>
#include <connman/rtnl.h>
#include <connman/setting.h>

#include <gweb/gresolv.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE

#define WKN_ADDRESS "ipv4only.arpa"

enum clat_state {
	CLAT_STATE_IDLE = 0,
	CLAT_STATE_PREFIX_QUERY,
	CLAT_STATE_PRE_CONFIGURE,
	CLAT_STATE_RUNNING,
	CLAT_STATE_POST_CONFIGURE,
	CLAT_STATE_STOPPED, // TODO: killed?
	CLAT_STATE_FAILURE,
	CLAT_STATE_RESTART,
};

struct clat_data {
	struct connman_service *service;
	struct connman_task *task;
	enum clat_state state;
	char *isp_64gateway;

	char *config_path;
	char *clat_prefix;
	char *address;
	char *ipv6address;
	unsigned char clat_prefixlen;
	unsigned char addr_prefixlen;
	unsigned char ipv6_prefixlen;
	int ifindex;

	GResolv *resolv;
	guint resolv_query_id;
	guint remove_resolv_id;

	guint dad_id;
	guint prefix_query_id;

	int out_ch_id;
	int err_ch_id;
	GIOChannel *out_ch;
	GIOChannel *err_ch;

	bool tethering_on;
};

#define DEFAULT_TAYGA_BIN		"/usr/local/bin/tayga"
#define TAYGA_CLAT_DEVICE		"clat"
#define TAYGA_CONF			"tayga.conf"
#define TAYGA_IPv4ADDR			"192.0.0.2"	/* from RFC 7335 */
#define CLAT_IPv4ADDR			"192.0.0.1"	/* from RFC 7335 */
#define IPv4ADDR_NETMASK		29		/* from RFC 7335 */
#define CLAT_INADDR_ANY		"0.0.0.0"
#define CLAT_IPv4_METRIC		2049		/* Set as value -1 */
#define CLAT_IPv4_ROUTE_MTU		1260		/* from clatd */
#define CLAT_IPv6_METRIC		1024
#define CLAT_SUFFIX			"c1a7"

#define PREFIX_QUERY_TIMEOUT		600000		/* 10 seconds */
#define DAD_TIMEOUT			600000		/* 10 minutes */

static const char GLOBAL_PREFIX[] = "64:ff9b::";
static const unsigned char GLOBAL_PREFIXLEN = 96;

static struct {
	char *tayga_bin;
	bool dad_enabled;
	bool resolv_always_succeeds;
	bool clat_device_use_netmask;
	bool tayga_use_ipv6_conf;
	bool tayga_use_strict_frag_hdr;
} clat_settings = {
	.tayga_bin = NULL,

	/* Use DAD for protecting the address, in android this is done */
	.dad_enabled = true,

	/* Resolv result always sets global prefix if fails */
	.resolv_always_succeeds = false,

	/* Add netmask to the CLAT device IPv4 address */
	.clat_device_use_netmask = false,

	/* Write IPv6 address of the interface used to the tayga config */
	.tayga_use_ipv6_conf = false,

	/* Value for strict-frag-hdr, defaults on */
	.tayga_use_strict_frag_hdr = true,
};

#define CLATCONFIGFILE			CONFIGDIR "/clat.conf"
#define CONF_TAYGA_BIN			"Tayga"
#define CONF_DAD_ENABLED		"EnableDAD"
#define CONF_RESOLV_ALWAYS_SUCCEEDS	"ResolvAlwaysSucceeds"
#define CONF_CLAT_USE_NETMASK		"ClatDeviceUseNetmask"
#define CONF_TAYGA_USE_IPV6_CONF	"TaygaRequiresIPv6Address"
#define CONF_TAYGA_USE_STRICT_FRAG_HDR	"TaygaStrictFragHdr"

struct clat_data *__data = NULL;

static GKeyFile *load_clat_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (err->code != G_FILE_ERROR_NOENT) {
			connman_error("Parsing %s failed: %s", file,
								err->message);
		}

		g_error_free(err);
		g_key_file_unref(keyfile);
		return NULL;
	}

	DBG("load config %s", file);

	return keyfile;
}

static void parse_clat_config(GKeyFile *config)
{
	GError *error = NULL;
	bool boolean;
	char *str;
	const char *group = "CLAT";

	if (!config) {
		DBG("No CLAT config was found, nothing to parse");
		return;
	}

	DBG("parsing config %p", config);

	str = g_key_file_get_string(config, group, CONF_TAYGA_BIN, &error);
	if (!error)
		clat_settings.tayga_bin = g_strdup(str);
	else
		clat_settings.tayga_bin = g_strdup(DEFAULT_TAYGA_BIN);

	boolean = g_key_file_get_boolean(config, group, CONF_DAD_ENABLED,
						&error);
	if (!error)
		clat_settings.dad_enabled = boolean;

	g_clear_error(&error);

	boolean = g_key_file_get_boolean(config, group,
						CONF_RESOLV_ALWAYS_SUCCEEDS,
						&error);
	if (!error)
		clat_settings.resolv_always_succeeds = boolean;

	g_clear_error(&error);

	boolean = g_key_file_get_boolean(config, group,
						CONF_CLAT_USE_NETMASK,
						&error);
	if (!error)
		clat_settings.clat_device_use_netmask = boolean;

	g_clear_error(&error);

	boolean = g_key_file_get_boolean(config, group,
						CONF_TAYGA_USE_IPV6_CONF,
						&error);
	if (!error)
		clat_settings.tayga_use_ipv6_conf = boolean;

	g_clear_error(&error);

	boolean = g_key_file_get_boolean(config, group,
						CONF_TAYGA_USE_STRICT_FRAG_HDR,
						&error);
	if (!error)
		clat_settings.tayga_use_strict_frag_hdr = boolean;

	g_clear_error(&error);
}

static void clear_clat_config(void)
{
	g_free(clat_settings.tayga_bin);
}

static bool is_running(enum clat_state state)
{
	switch (state) {
	case CLAT_STATE_IDLE:
	case CLAT_STATE_STOPPED:
	case CLAT_STATE_FAILURE:
		return false;
	case CLAT_STATE_PREFIX_QUERY:
	case CLAT_STATE_PRE_CONFIGURE:
	case CLAT_STATE_RUNNING:
	case CLAT_STATE_POST_CONFIGURE:
	case CLAT_STATE_RESTART:
		return true;
	}

	return false;
}

static const char* state2string(enum clat_state state)
{
	switch (state) {
	case CLAT_STATE_IDLE:
		return "idle";
	case CLAT_STATE_STOPPED:
		return "stopped";
	case CLAT_STATE_FAILURE:
		return "failure";
	case CLAT_STATE_PREFIX_QUERY:
		return "prefix query";
	case CLAT_STATE_PRE_CONFIGURE:
		return "pre configure";
	case CLAT_STATE_RUNNING:
		return "running";
	case CLAT_STATE_POST_CONFIGURE:
		return "post configure";
	case CLAT_STATE_RESTART:
		return "restart";
	}

	return "invalid state";
}

static void close_io_channel(struct clat_data *data, GIOChannel *channel)
{
	if (!data || !channel)
		return;

	if (data->out_ch == channel) {
		DBG("closing task %p STDOUT", data->task);

		if (data->out_ch_id) {
			g_source_remove(data->out_ch_id);
			data->out_ch_id = 0;
		}

		g_io_channel_shutdown(data->out_ch, FALSE, NULL);
		g_io_channel_unref(data->out_ch);

		data->out_ch = NULL;
		return;
	}

	if (data->err_ch == channel) {
		DBG("closing task %p STDERR", data->task);

		if (data->err_ch_id) {
			g_source_remove(data->err_ch_id);
			data->err_ch_id = 0;
		}

		g_io_channel_shutdown(data->err_ch, FALSE, NULL);
		g_io_channel_unref(data->err_ch);

		data->err_ch = NULL;
		return;
	}
}

static gboolean io_channel_cb(GIOChannel *source, GIOCondition condition,
			gpointer user_data)
{
	struct clat_data *data = user_data;
	char *str;
	const char *type = (source == data->out_ch ? "STDOUT" :
				(source == data->err_ch ? "STDERR" : "NaN"));

	if ((condition & G_IO_IN) &&
		g_io_channel_read_line(source, &str, NULL, NULL, NULL) ==
							G_IO_STATUS_NORMAL) {
		str[strlen(str) - 1] = '\0';

		connman_error("CLAT %s: %s", clat_settings.tayga_bin, str);

		g_free(str);
	} else if (condition & (G_IO_ERR | G_IO_HUP)) {
		DBG("%s Channel termination", type);
		close_io_channel(data, source);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int create_task(struct clat_data *data)
{
	if (!data)
		return -ENOENT;

	data->task = connman_task_create(clat_settings.tayga_bin, NULL, data);
	if (!data->task)
		return -ENOMEM;

	DBG("task %p", data->task);

	return 0;
}

static int destroy_task(struct clat_data *data)
{
	int err;

	if (!data || !data->task)
		return -ENOENT;

	DBG("task %p", data->task);

	err = connman_task_stop(data->task);
	if (err) {
		connman_error("CLAT failed to stop current task");
		return err;
	}

	connman_task_destroy(data->task);
	data->task = NULL;
	return 0;
}

static struct clat_data *get_data()
{
	return __data;
}

static void clat_data_clear(struct clat_data *data)
{
	if (!data)
		return;

	DBG("data %p", data);

	g_free(data->isp_64gateway);
	data->isp_64gateway = NULL;

	g_free(data->config_path);
	data->config_path = NULL;

	g_free(data->clat_prefix);
	data->clat_prefix = NULL;

	g_free(data->address);
	data->address = NULL;

	g_free(data->ipv6address);
	data->ipv6address = NULL;

	data->clat_prefixlen = 0;
	data->addr_prefixlen = 0;
	data->ipv6_prefixlen = 0;
	data->ifindex = -1;

	data->state = CLAT_STATE_IDLE;
}

static void clat_data_free(struct clat_data *data)
{
	DBG("");

	clat_data_clear(data);
	g_free(data);
}

static struct clat_data *clat_data_init()
{
	struct clat_data *data;

	DBG("");

	data = g_new0(struct clat_data, 1);
	if (!data)
		return NULL;

	data->ifindex = -1;

	return data;
}

static int clat_create_tayga_config(struct clat_data *data)
{
	GError *error = NULL;
	GString *str;
	char *buf;
	int err = 0;

	g_free(data->config_path);
	data->config_path = g_build_filename(RUNSTATEDIR, "connman",
						TAYGA_CONF, NULL);

	DBG("config %s", data->config_path);

	str = g_string_new("");

	g_string_append_printf(str, "tun-device %s\n", TAYGA_CLAT_DEVICE);
	g_string_append_printf(str, "ipv4-addr %s\n", TAYGA_IPv4ADDR);

	/* IPv6 address is required only when global prefix is in use */
	if (clat_settings.tayga_use_ipv6_conf)
		g_string_append_printf(str, "ipv6-addr %s\n",
							data->ipv6address);

	g_string_append_printf(str, "prefix %s/%u\n", data->clat_prefix,
						data->clat_prefixlen);

	/*
	 * Man pages state that:
	 * Creates  a static mapping between RFC 7577 compliant hosts or
	 * subnets ipv4_address[/length] and ipv6_address[/length] to be used
	 * when translating IPv4 packets to IPv6 or IPv6 packets to IPv4. If
	 * /length is not present, the /length after ipv4_address is treated
	 * as "/32" and that of ipv6_address as "/128".
	 *
	 * BUT IT DOES NOT WORK.
	 */
	g_string_append_printf(str, "map %s %s\n", CLAT_IPv4ADDR,
						data->address);

	/* ippool.c apparently defaults to 24 subnet */
	g_string_append_printf(str, "dynamic-pool %s/%u\n",
				connman_setting_get_string(
					"TetheringSubnetBlock"),
				24);

	g_string_append_printf(str, "strict-frag-hdr %s\n",
				clat_settings.tayga_use_strict_frag_hdr ?
					"on" : "off");

	buf = g_string_free(str, FALSE);

	g_file_set_contents(data->config_path, buf, -1, &error);
	if (error) {
		connman_error("Error creating conf: %s\n", error->message);
		g_error_free(error);
		err = -EIO;
	}

	g_free(buf);

	return err;
}

static int clat_run_task(struct clat_data *data);

static gboolean remove_resolv(gpointer user_data)
{
	struct clat_data *data = user_data;

	DBG("");

	if (data->remove_resolv_id)
		g_source_remove(data->remove_resolv_id);

	if (data->resolv && data->resolv_query_id) {
		DBG("cancel resolv lookup");
		g_resolv_cancel_lookup(data->resolv, data->resolv_query_id);
	}

	data->resolv_query_id = 0;
	data->remove_resolv_id = 0;

	g_resolv_unref(data->resolv);
	data->resolv = NULL;

	return G_SOURCE_REMOVE;
}

struct prefix_entry {
	char *prefix;
	unsigned char prefixlen;
};

static void free_prefix_entry(gpointer user_data)
{
	struct prefix_entry *entry = user_data;

	DBG("entry %p", entry);

	if (!entry)
		return;

	g_free(entry->prefix);
	g_free(entry);
}

static struct prefix_entry *new_prefix_entry(const char *address)
{
	struct prefix_entry *entry;
	gchar **tokens;

	DBG("address %s", address);

	if (!address)
		return NULL;

	tokens = g_strsplit(address, "/", 2);
	entry = g_new0(struct prefix_entry, 1);
	if (!entry)
		return NULL;

	DBG("entry %p", entry);

	/* Result has a global prefix */
	if (g_str_has_prefix(address, GLOBAL_PREFIX)) {
		entry->prefix = g_strdup(GLOBAL_PREFIX);
		entry->prefixlen = GLOBAL_PREFIXLEN;
	/* Result had address and prefix length. */
	} else if (tokens && g_strv_length(tokens) == 2) {
		entry->prefix = g_strdup(tokens[0]);
		entry->prefixlen = (unsigned char)g_ascii_strtoull(tokens[1],
								NULL, 10);
	} else {
		DBG("address does not contain a valid prefix");
		free_prefix_entry(entry);
		return NULL;
	}
	/*
	 * TODO: Check the prefixlenght from other than ones with GLOBAL_PREFIX
	 * utilizing XOR of the A record result. Use /96 prefix for all as
	 * android does.
	 */

	g_strfreev(tokens);

	if (entry->prefixlen > 128 || entry->prefixlen < 16) {
		DBG("Invalid prefixlen %u", entry->prefixlen);
		g_free(entry);
		return NULL;
	}

	DBG("prefix %s/%u", entry->prefix, entry->prefixlen);

	return entry;
}

static gint prefix_comp(gconstpointer a, gconstpointer b)
{
	const struct prefix_entry *entry_a = a;
	const struct prefix_entry *entry_b = b;

	/* Largest on top */
	if (entry_a->prefixlen > entry_b->prefixlen)
		return -1;

	if (entry_a->prefixlen < entry_b->prefixlen)
		return 1;

	return 0;
}

static int assign_clat_prefix(struct clat_data *data, char **results)
{
	GList *prefixes = NULL;
	GList *first;
	struct prefix_entry *entry;
	int err = 0;
	int len;
	int i;

	if (!results) {
		DBG("no results");
		return -ENOENT;
	}

	len = g_strv_length(results);
	DBG("got %d results", len);

	for (i = 0; i < len; i++) {
		entry = new_prefix_entry(results[i]);
		if (!entry)
			continue;

		prefixes = g_list_insert_sorted(prefixes, entry, prefix_comp);
	}

	first = g_list_first(prefixes);
	if (first) {
		entry = first->data;
	} else {
		DBG("no prefixes found, fallback using global %s/%u",
							GLOBAL_PREFIX,
							GLOBAL_PREFIXLEN);
		entry = new_prefix_entry(GLOBAL_PREFIX);
		prefixes = g_list_insert_sorted(prefixes, entry, prefix_comp);
	}

	if (!entry) {
		DBG("no entry is set");
		g_list_free_full(prefixes, free_prefix_entry);
		return -ENOENT;
	}

	/* A prefix exists already */
	if (data->clat_prefix) {
		if (g_strcmp0(data->clat_prefix, entry->prefix) &&
				data->clat_prefixlen != entry->prefixlen) {
			DBG("changing existing prefix %s/%u -> %s/%u",
						data->clat_prefix,
						data->clat_prefixlen,
						entry->prefix,
						entry->prefixlen);
			err = -ERESTART;
		}

		if (!g_strcmp0(data->clat_prefix, entry->prefix) &&
				data->clat_prefixlen == entry->prefixlen) {
			DBG("no change to existing prefix %s/%u",
						data->clat_prefix,
						data->clat_prefixlen);
			err = -EALREADY;
		}
	}


	g_free(data->clat_prefix);
	data->clat_prefix = g_strdup(entry->prefix);
	data->clat_prefixlen = entry->prefixlen;

	g_list_free_full(prefixes, free_prefix_entry);

	return err;
}

static void prefix_query_cb(GResolvResultStatus status,
					char **results, gpointer user_data)
{
	struct clat_data *data = user_data;
	enum clat_state new_state = data->state;
	int err;

	DBG("state %d/%s status %d GResolv %p", data->state,
						state2string(data->state),
						status, data->resolv);

	if (!data->resolv && !data->resolv_query_id) {
		DBG("resolv was already cleared, running state: %s",
					is_running(data->state) ? "yes" : "no");
		return;
	}

	/*
	 * We cannot unref the resolver here as resolv struct is manipulated
	 * by gresolv.c after we return from this callback.
	 */
	data->remove_resolv_id = g_timeout_add(0, remove_resolv, data);
	data->resolv_query_id = 0;

	if (status != G_RESOLV_RESULT_STATUS_SUCCESS) {
		if (clat_settings.resolv_always_succeeds) {
			DBG("ignore resolv result %d", status);
			gchar **override = g_new0(char*, 1);
			override[0] = g_strdup("64:ff9b::/96");
			err = assign_clat_prefix(data, override);
			g_strfreev(override);
		} else {
			err = -EHOSTDOWN;
		}
	} else {
		DBG("resolv of %s success, parse prefix", WKN_ADDRESS);
		err = assign_clat_prefix(data, results);
	}

	switch (err) {
	case 0:
		DBG("new prefix %s/%u", data->clat_prefix,
						data->clat_prefixlen);
		break;
	case -EALREADY:
		/* No state change with same prefix */
		DBG("no change in prefix");
		return;
	case -ERESTART:
		DBG("prefix changed to %s/%u, do restart",
						data->clat_prefix,
						data->clat_prefixlen);
		new_state = CLAT_STATE_RESTART;
		break;
	case -EHOSTDOWN:
		DBG("failed to resolv %s, CLAT is not started", WKN_ADDRESS);
		new_state = CLAT_STATE_STOPPED;
		break;
	default:
		DBG("failed to assign prefix, error %d", err);
		new_state = CLAT_STATE_FAILURE;
		break;
	}

	if (data->state == CLAT_STATE_FAILURE) {
		DBG("CLAT already in failure state, not transitioning state");
		return;
	}

	/*
	 * Do state transition only when doing initial query or when changing
	 * state.
	 */
	if (data->state == CLAT_STATE_PREFIX_QUERY ||
						data->state != new_state) {
		DBG("State progress or state change");
		data->state = new_state;

		err = clat_run_task(data);
		if (err && err != -EALREADY)
			connman_error("failed to run CLAT, error %d", err);
	}
}

static int clat_task_do_prefix_query(struct clat_data *data)
{
	DBG("");

	/*
	 * TODO handle this
	 if (connman_inet_check_ipaddress(data->isp_64gateway) > 0) {
		
		return -EINVAL;
	}*/

	if (data->resolv_query_id > 0) {
		DBG("previous query was running, abort it");
		remove_resolv(data);
	}

	data->resolv = g_resolv_new(0);
	if (!data->resolv) {
		connman_error("CLAT cannot create resolv, stopping");
		return -ENOMEM;
	}

	DBG("Trying to resolv %s gateway %s", WKN_ADDRESS, data->isp_64gateway);

	g_resolv_set_address_family(data->resolv, AF_INET6);
	data->resolv_query_id = g_resolv_lookup_hostname(data->resolv,
					WKN_ADDRESS, prefix_query_cb, data);
	if (data->resolv_query_id <= 0) {
		DBG("failed to start hostname lookup for %s", WKN_ADDRESS);
		return -ENOENT;
	}

	return 0;
}

static gboolean run_prefix_query(gpointer user_data)
{
	struct clat_data *data = user_data;

	DBG("");

	if (!data)
		return G_SOURCE_REMOVE;

	if (clat_task_do_prefix_query(data)) {
		DBG("failed to run prefix query");
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int clat_task_start_periodic_query(struct clat_data *data)
{
	DBG("");

	if (data->prefix_query_id > 0) {
		DBG("Already running");
		return -EALREADY;
	}

	data->prefix_query_id = g_timeout_add(PREFIX_QUERY_TIMEOUT,
							run_prefix_query, data);
	if (data->prefix_query_id <= 0) {
		connman_error("CLAT failed to start periodic prefix query");
		return -EINVAL;
	}

	return 0;
}

static void clat_task_stop_periodic_query(struct clat_data *data)
{
	DBG("");

	if (data->prefix_query_id)
		g_source_remove(data->prefix_query_id);

	data->prefix_query_id = 0;

	/* Cancel also ongoing resolv */
	if (data->resolv_query_id)
		remove_resolv(data);
}

static gboolean do_online_check(gpointer user_data)
{
	return G_SOURCE_REMOVE;
}

static int clat_task_start_online_check(struct clat_data *data)
{
	// TODO run this via wispr ?
	do_online_check(data);
	return 0;
}

static void clat_task_stop_online_check(struct clat_data *data)
{
	return;
}


static int derive_ipv6_address(struct clat_data *data, const char *ipv6_addr,
						unsigned char ipv6_prefixlen)
{
	char** tokens;
	char ipv6prefix[135] = { 0 };
	int left;
	int pos;
	int i;

	DBG("data %p IPv6 address %s/%u", data, ipv6_addr, ipv6_prefixlen);

	if (!data || !ipv6_addr)
		return -EINVAL;

	tokens = g_strsplit(ipv6_addr, ":", 8);
	if (!tokens) {
		connman_error("CLAT failed to tokenize IPv6 address");
		return -EINVAL;
	}

	left = 8 - (128 - (int)ipv6_prefixlen) / 16;
	pos = 0;

	for (i = 0; tokens[i] && i < left; i++) {
		strncpy(&ipv6prefix[pos], tokens[i], 4);
		pos += strlen(tokens[i]) + 1; // + ':'

		if (i + 1 < left)
			ipv6prefix[pos-1] = ':';
	}

	g_strfreev(tokens);

	/*
	 * TODO clat daemon made in perl does this a bit more intelligently,
	 * https://github.com/toreanderson/clatd/blob/master/clatd#L442
	 * 
	 */
	data->address = g_strconcat(ipv6prefix, "::", CLAT_SUFFIX, NULL);
	data->addr_prefixlen = 128;

	return 0;
}

static int clat_task_pre_configure(struct clat_data *data)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	const char *address;
	unsigned char prefixlen;
	int err;

	DBG("");

	ipconfig = connman_service_get_ipconfig(data->service, AF_INET6);
	if (!ipconfig) {
		DBG("No IPv6 ipconfig");
		return -ENOENT;
	}

	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	if (!ipaddress) {
		DBG("No IPv6 ipaddress in ipconfig %p", ipconfig);
		return -ENOENT;
	}

	err = connman_ipaddress_get_ip(ipaddress, &address, &prefixlen);
	if (err || !address) {
		DBG("No IPv6 address set in ipaddress %p", ipaddress);
		return -ENOENT;
	}

	DBG("IPv6 %s prefixlen %u", address, prefixlen);
	data->ipv6address = g_strdup(address);
	data->ipv6_prefixlen = prefixlen;

	err = derive_ipv6_address(data, address, prefixlen);
	if (err) {
		connman_error("CLAT failed to derive IPv6 address from %s",
						address);
		return err;
	}

	DBG("Address IPv6 %s/%u -> CLAT address %s", data->ipv6address,
					data->ipv6_prefixlen, data->address);

	clat_create_tayga_config(data);

	if (create_task(data))
		return -ENOMEM;

	connman_task_add_argument(data->task, "--config", data->config_path);
	connman_task_add_argument(data->task, "--mktun", NULL);

	return 0;
}

/*
5) set up routing and start TAYGA

$ tayga --mktun
$ ip link set dev clat up
$ ip route add 2a00:e18:8000:6cd::c1a7 dev clat
$ ip address add 192.0.0.4 dev clat
$ ip -4 route add default dev clat
$ tayga
*/

/* TODO add this to ipaddress.c as plugins/vpn.c uses this */
static char *cidr_to_str(unsigned char cidr_netmask)
{
	struct in_addr netmask_in;
	in_addr_t addr;
	char netmask[INET_ADDRSTRLEN] = { 0 };
	unsigned char prefix_len = 32;

	if (cidr_netmask && cidr_netmask <= prefix_len)
		prefix_len = cidr_netmask;

	addr = 0xffffffff << (32 - prefix_len);
	netmask_in.s_addr = htonl(addr);

	if (!inet_ntop(AF_INET, &netmask_in, netmask, INET_ADDRSTRLEN)) {
		connman_error("failed to convert CIDR %u", cidr_netmask);
		return NULL;
	}

	DBG("CIDR %u to netmask %s", cidr_netmask, netmask);

	return g_strdup(netmask);
}

static int clat_task_start_tayga(struct clat_data *data)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	char *netmask = NULL;
	int err;
	int index;
	//$ ip link set dev clat up
	// TODO wait for rtnl notify?
	index = connman_inet_ifindex(TAYGA_CLAT_DEVICE);
	if (index < 0) {
		connman_warn("CLAT tayga not up yet?");
		return -ENODEV;
	}

	DBG("");

	err = connman_inet_ifup(index);
	if (err && err != -EALREADY) {
		connman_error("CLAT failed to bring interface %s up",
							TAYGA_CLAT_DEVICE);
		return err;
	}

	ipconfig = connman_service_get_ipconfig(data->service, AF_INET6);
	if (!ipconfig) {
		DBG("No IPv6 ipconfig");
		return -ENOENT;
	}

	err = connman_nat6_prepare(ipconfig, data->address,
						data->addr_prefixlen,
						TAYGA_CLAT_DEVICE, true);
	if (err) {
		connman_warn("CLAT failed to prepare nat and firewall %d", err);
		return err;
	}

	//$ ip route add 2a00:e18:8000:6cd::c1a7 dev clat
	// TODO default route or...?
	connman_inet_add_ipv6_network_route_with_metric(index, data->address,
						NULL, data->addr_prefixlen,
						CLAT_IPv6_METRIC);
	//$ ip address add 192.0.0.2 dev clat
	if (clat_settings.clat_device_use_netmask)
		netmask = cidr_to_str(IPv4ADDR_NETMASK);

	ipaddress = connman_ipaddress_alloc(AF_INET);
	connman_ipaddress_set_ipv4(ipaddress, CLAT_IPv4ADDR, netmask, NULL);
	connman_inet_set_address(index, ipaddress);

	//$ ip -4 route add default dev clat
	/* Set no address, all traffic should be forwarded to the device */
	connman_inet_add_network_route_with_metric(index, CLAT_INADDR_ANY,
							CLAT_INADDR_ANY,
							CLAT_INADDR_ANY,
							CLAT_IPv4_METRIC,
							CLAT_IPv4_ROUTE_MTU);
	connman_ipaddress_free(ipaddress);
	g_free(netmask);

	if (create_task(data))
		return -ENOMEM;

	connman_task_add_argument(data->task, "--config", data->config_path);
	connman_task_add_argument(data->task, "--nodetach", NULL);
	connman_task_add_argument(data->task, "-d", NULL);

	return 0;
}

void clat_dad_cb(struct nd_neighbor_advert *reply, unsigned int length,
					struct in6_addr *addr,
					void *user_data)
{
	char ipv6_addr[INET6_ADDRSTRLEN];

	// This reply can be ignored
	DBG("got reply %p length %u", reply, length);

	if (addr && inet_ntop(AF_INET6, addr, ipv6_addr, INET6_ADDRSTRLEN))
		DBG("IPv6 address %s", ipv6_addr);

	return;
}

static gboolean clat_task_run_dad(gpointer user_data)
{
	struct clat_data *data = user_data;
	unsigned char addr[sizeof(struct in6_addr)];
	int err = 0;

	DBG("");

	if (inet_pton(AF_INET6, data->address, addr) != 1) {
		connman_error("failed to pton address %s", data->address);
		return G_SOURCE_REMOVE;
	}

	err = connman_inet_ipv6_do_dad(data->ifindex, 100,
						(struct in6_addr *)addr,
						clat_dad_cb, data);
	if (err) {
		connman_error("CLAT failed to send dad: %d", err);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int clat_task_start_dad(struct clat_data *data)
{
	DBG("");

	if (!clat_settings.dad_enabled) {
		DBG("DAD disabled by config");
		return 0;
	}

	data->dad_id = g_timeout_add(DAD_TIMEOUT, clat_task_run_dad, data);

	if (data->dad_id <= 0) {
		connman_error("CLAT failed to start DAD timeout");
		return -EINVAL;
	}

	return 0;
}

static int clat_task_stop_dad(struct clat_data *data)
{
	DBG("");

	if (data->dad_id)
		g_source_remove(data->dad_id);

	data->dad_id = 0;

	return 0;
}

static int clat_task_post_configure(struct clat_data *data)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	char *netmask = NULL;
	int index;

	//$ ip link set dev clat up
	// TODO wait for rtnl notify?

	ipconfig = connman_service_get_ipconfig(data->service, AF_INET6);
	if (ipconfig)
		connman_nat6_restore(ipconfig, data->address,
							data->addr_prefixlen);

	DBG("ipconfig %p", ipconfig);

	index = connman_inet_ifindex(TAYGA_CLAT_DEVICE);
	if (index >= 0) {
		ipaddress = connman_ipaddress_alloc(AF_INET);
		connman_inet_del_network_route_with_metric(index, CLAT_IPv4ADDR,
							CLAT_IPv4_METRIC);

		if (clat_settings.clat_device_use_netmask)
			netmask = cidr_to_str(IPv4ADDR_NETMASK);

		connman_ipaddress_set_ipv4(ipaddress, CLAT_IPv4ADDR, netmask,
							NULL);
		g_free(netmask);

		connman_inet_clear_address(index, ipaddress);
		connman_inet_del_ipv6_network_route_with_metric(index,
							data->address,
							data->addr_prefixlen,
							CLAT_IPv6_METRIC);
		connman_inet_ifdown(index);
		connman_ipaddress_free(ipaddress);
	} else {
		DBG("CLAT tayga interface not up, nothing to do");
	}

	if (create_task(data))
		return -ENOMEM;

	connman_task_add_argument(data->task, "--config", data->config_path);
	connman_task_add_argument(data->task, "--rmtun", NULL);

	return 0;
}

static void clat_task_exit(struct connman_task *task, int exit_code,
								void *user_data)
{
	struct clat_data *data = user_data;
	int err;

	if (!data) {
		DBG("data gone, exit code %d after CLAT exit", exit_code);

		if (task) {
			DBG("destroying task %p", task);
			connman_task_destroy(task);
		}

		return;
	}

	DBG("state %d/%s", data->state, state2string(data->state));

	if (exit_code)
		connman_warn("CLAT task failed with code %d", exit_code);

	if (task != data->task) {
		connman_warn("CLAT task differs, nothing done");
		return;
	}

	destroy_task(data);

	switch (data->state) {
	case CLAT_STATE_IDLE:
	case CLAT_STATE_STOPPED:
	case CLAT_STATE_FAILURE:
		DBG("CLAT task exited in state %d/%s", data->state,
						state2string(data->state));
		break;
	case CLAT_STATE_PREFIX_QUERY:
	case CLAT_STATE_PRE_CONFIGURE:
	case CLAT_STATE_RUNNING:
		if (exit_code)
			data->state = CLAT_STATE_FAILURE;
		else
			DBG("run next state %d/%s", data->state + 1,
						state2string(data->state + 1));

		err = clat_run_task(data);
		if (err && err != -EALREADY)
			connman_error("failed to run CLAT, error %d", err);
		return;
	case CLAT_STATE_POST_CONFIGURE:
		DBG("CLAT process ended");
		data->state = CLAT_STATE_STOPPED;
		break;
	case CLAT_STATE_RESTART:
		DBG("CLAT task return when restarting");
		return;
	}

	/*
	 * Not continuing with running task or handling restart, clear all data
	 * in case of terminating failure or when stopping clat.
	 */
	clat_data_clear(data);
}

static void setup_double_nat(struct clat_data *data)
{
	int err;

	if (!data)
		return;

	if (data->tethering_on && data->state == CLAT_STATE_RUNNING) {
		DBG("tethering enabled when CLAT is running, override nat");

		err = connman_nat_enable_double_nat_override(TAYGA_CLAT_DEVICE,
						"192.0.0.0", IPv4ADDR_NETMASK);
		if (err && err != -EINPROGRESS)
			connman_error("Failed to setup double nat for tether");
	} else {
		DBG("Remove nat override");
		connman_nat_disable_double_nat_override(TAYGA_CLAT_DEVICE);
	}
}

static void stop_running(struct clat_data *data)
{
	if (!data)
		return;

	clat_task_stop_periodic_query(data);
	clat_task_stop_dad(data);
	clat_task_stop_online_check(data);

	data->tethering_on = false;
	setup_double_nat(data);
}

static int clat_run_task(struct clat_data *data)
{
	int fd_out;
	int fd_err;
	int err = 0;

	DBG("state %d/%s", data->state, state2string(data->state));

	switch (data->state) {
	case CLAT_STATE_IDLE:
		data->state = CLAT_STATE_PREFIX_QUERY;
		/* Get the prefix from the ISP NAT service */
		err = clat_task_do_prefix_query(data);
		if (err && err != -EALREADY) {
			connman_error("CLAT failed to start prefix query");
			break;
		}

		return 0;

	case CLAT_STATE_PREFIX_QUERY:
		err = clat_task_pre_configure(data);
		if (err) {
			connman_error("CLAT failed to create pre-configure "
								"task");
			break;
		}

		data->state = CLAT_STATE_PRE_CONFIGURE;
		break;
	case CLAT_STATE_PRE_CONFIGURE:
		err = clat_task_start_tayga(data);
		if (err) {
			connman_error("CLAT failed to create run task");
			break;
		}

		data->state = CLAT_STATE_RUNNING;

		err = clat_task_start_periodic_query(data);
		if (err && err != -EALREADY)
			connman_warn("CLAT failed to start periodic prefix "
								"query");

		err = clat_task_start_dad(data);
		if (err && err != -EALREADY)
			connman_warn("CLAT failed to start periodic DAD");

		break;
	/* If either running or stopped state and run is called do cleanup */
	case CLAT_STATE_RUNNING:
	case CLAT_STATE_STOPPED:
		stop_running(data);

		err = clat_task_post_configure(data);
		if (err) {
			connman_error("CLAT failed to create post-configure "
								"task");
			break;
		}
		data->state = CLAT_STATE_POST_CONFIGURE;

		break;
	case CLAT_STATE_POST_CONFIGURE:
		connman_warn("CLAT run task called in post-configure state");
		data->state = CLAT_STATE_STOPPED;
		return 0;
	case CLAT_STATE_FAILURE:
		DBG("CLAT entered failure state, stop all that is running");

		destroy_task(data);

		/* Do post configure if the interface is up */
		err = clat_task_post_configure(data);
		if (err && err != -ENODEV)
			connman_error("CLAT failed to create post-configure "
						"task in failure state");

		stop_running(data);

		/* Remain in failure state, can be started via clat_start(). */
		data->state = CLAT_STATE_FAILURE;

		if (err)
			return err;

		break;
	case CLAT_STATE_RESTART:
		destroy_task(data);

		/* Run as stopped -> does cleanup */
		data->state = CLAT_STATE_STOPPED;
		err = clat_run_task(data);
		if (err && err != -EALREADY) {
			connman_error("CLAT failed to start cleanup task");
			data->state = CLAT_STATE_FAILURE;
		}

		/*
		 * RESTART comes after prefix query has been done, go directly
		 * to PRE_CONFIGURE state.
		 */
		data->state = CLAT_STATE_PRE_CONFIGURE;
		break;
	}

	if (!err) {
		DBG("CLAT run task %p", data->task);
		err = connman_task_run(data->task, clat_task_exit, data, NULL,
							&fd_out, &fd_err);
	}

	if (err) {
		connman_error("CLAT task failed to run, error %d/%s",
							err, strerror(-err));
		data->state = CLAT_STATE_FAILURE;
		destroy_task(data);
	} else {
		if (data->out_ch)
			close_io_channel(data, data->out_ch);

		data->out_ch = g_io_channel_unix_new(fd_out);
		g_io_channel_set_close_on_unref(data->out_ch, TRUE);

		data->out_ch_id = g_io_add_watch(data->out_ch,
						G_IO_IN | G_IO_ERR | G_IO_HUP,
						io_channel_cb, data);

		if (data->err_ch)
			close_io_channel(data, data->err_ch);

		data->err_ch = g_io_channel_unix_new(fd_err);
		g_io_channel_set_close_on_unref(data->err_ch, TRUE);

		data->err_ch_id = g_io_add_watch(data->err_ch,
						G_IO_IN | G_IO_ERR | G_IO_HUP,
						io_channel_cb, data);

		setup_double_nat(data);
	}

	DBG("in state %d/%s", data->state, state2string(data->state));

	return err;
}

static int clat_start(struct clat_data *data)
{
	DBG("state %d/%s", data->state, state2string(data->state));

	if (!data)
		return -EINVAL;

	if (is_running(data->state))
		return -EALREADY;

	data->state = CLAT_STATE_IDLE;
	clat_run_task(data);

	return 0;
}

static int clat_stop(struct clat_data *data)
{
	int err;

	if (!data)
		return -EINVAL;

	DBG("state %d/%s", data->state, state2string(data->state));

	destroy_task(data);

	/* Run as stopped -> does cleanup */
	data->state = CLAT_STATE_STOPPED;
	err = clat_run_task(data);
	if (err && err != -EALREADY) {
		connman_error("CLAT failed to start cleanup task");
		data->state = CLAT_STATE_FAILURE;
	}

	/* Sets as idle */
	clat_data_clear(data);

	return err;
}

static int clat_failure(struct clat_data *data)
{
	return 0;
}

static void clat_new_rtnl_gateway(int index, const char *dst,
						const char *gateway, int metric,
						unsigned char rtm_protocol)
{
	struct clat_data *data = get_data();

	DBG("%d dst %s gateway %s metric %d", index, dst, gateway, metric);

	/* Not the cellular device we are monitoring. */
	if (index != data->ifindex)
		return;

	if (rtm_protocol != RTPROT_RA && rtm_protocol != RTPROT_DHCP) {
		DBG("rtm_protocol not RA|DHCP");
		return;
	}

	/*if (!connman_inet_is_any_addr(dst, AF_INET6)) {
		DBG("dst %s != IPv6 ANY: %s", dst, IPV6_ANY);
		return;
	}*/

	g_free(data->isp_64gateway);
	data->isp_64gateway = g_strdup(gateway);

	// TODO: perhaps store also dst and metric?
}

static void clat_del_rtnl_gateway(int index, const char *dst,
						const char *gateway, int metric,
						unsigned char rtm_protocol)
{
	struct clat_data *data = get_data();
	
	DBG("%d dst %s gateway %s metric %d", index, dst, gateway, metric);

	if (index != data->ifindex)
		return;

	if (rtm_protocol != RTPROT_RA && rtm_protocol != RTPROT_DHCP) {
		DBG("rtm_protocol not RA|DHCP");
		return;
	}

	/* We lost our gateway, shut down clat */
	if (!g_strcmp0(data->isp_64gateway, gateway)) {
		DBG("CLAT gateway %s gone", data->isp_64gateway);
		clat_stop(data);
	}
}

static struct connman_rtnl clat_rtnl = {
	.name			= "clat",
	.newgateway6		= clat_new_rtnl_gateway,
	.delgateway6		= clat_del_rtnl_gateway,
};

static void clat_ipconfig_changed(struct connman_service *service,
					struct connman_ipconfig *ipconfig)
{
	struct connman_network *network;
	struct clat_data *data = get_data();
	enum connman_service_state state;
	int err;

	if (service || !data->service)
		return;

	DBG("service %p ipconfig %p", service, ipconfig);

	if (service != data->service || connman_service_get_type(service) !=
						CONNMAN_SERVICE_TYPE_CELLULAR) {
		DBG("Not tracking service %p/%s or not cellular", service,
				connman_service_get_identifier(service));
		return;
	}

	if (connman_ipconfig_get_config_type(ipconfig) ==
						CONNMAN_IPCONFIG_TYPE_IPV4) {
		DBG("cellular %p has IPv4 config, stop CLAT", service);
		clat_stop(data);
		return;
	}

	if (service != connman_service_get_default()) {
		DBG("cellular service %p is not default, stop CLAT", service);
		clat_stop(data);
		return;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected, stop CLAT", network);
		clat_stop(data);
		return;
	}

	state = connman_service_get_state(service);

	if (state == CONNMAN_SERVICE_STATE_READY ||
				state == CONNMAN_SERVICE_STATE_ONLINE) {
		DBG("service %p ready|online, start CLAT", service);
		err = clat_start(data);
		if (err && err != -EALREADY)
			connman_error("CLAT failed to start, error %d", err);
	}
}

static bool has_ipv4_address(struct connman_service *service)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	enum connman_ipconfig_method method;
	const char *address;
	unsigned char prefixlen;
	int err;

	ipconfig = connman_service_get_ipconfig(service, AF_INET);
	DBG("IPv4 ipconfig %p", ipconfig);

	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	DBG("IPv4 ipaddress %p", ipaddress);

	err = connman_ipaddress_get_ip(ipaddress, &address, &prefixlen);
	if (err) {
		DBG("IPv4 is not configured on cellular service %p", service);
		return false;
	}

	if (!address) {
		DBG("no IPv4 address on cellular service %p", service);
		return false;
	}

	method = connman_service_get_ipconfig_method(service,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		DBG("IPv4 method unknown/off, address is old");
		return false;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		break;
	}

	DBG("IPv4 address %s set for service %p", address, service);
	return true;
}

static void clat_default_changed(struct connman_service *service)
{
	struct connman_network *network;
	struct clat_data *data = get_data();

	if (!service || !data->service)
		return;

	DBG("service %p", service);

	if (!is_running(data->state)) {
		DBG("CLAT not running, default change not affected");
		return;
	}

	if (data->service && data->service != service) {
		DBG("Tracked cellular service %p is not default, stop CLAT",
							data->service);
		clat_stop(data);
		return;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected, stop CLAT", network);
		clat_stop(data);
		return;
	}

	if (connman_network_is_configured(network,
					CONNMAN_IPCONFIG_TYPE_IPV4) &&
					has_ipv4_address(data->service)) {
		DBG("IPv4 is configured on cellular network %p, stop CLAT",
							network);
		clat_stop(data);
		return;
	}
}

static void clat_service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	struct connman_network *network;
	struct clat_data *data = get_data();
	char *ifname;
	int err;

	if (!service || connman_service_get_type(service) !=
						CONNMAN_SERVICE_TYPE_CELLULAR)
		return;

	DBG("cellular service %p", service);

	switch (state) {
	/* Not connected */
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		/* Stop clat if the service goes offline */
		if (service == data->service) {
			DBG("offline state, stop CLAT");
			clat_stop(data);
			data->service = NULL;
		}
		return;
	/* Connecting does not need yet clat as there is no network.*/
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		DBG("association|configuration, assign service %p", service);
		data->service = service;
		return;
	/* Connected, start clat. */
	case CONNMAN_SERVICE_STATE_READY:
		if (service != data->service)
			return;

		if (connman_service_get_default() != data->service) {
			DBG("CLAT service is not default service");
			return;
		}

		if (is_running(data->state)) {
			DBG("CLAT is already running in state %d/%s",
						data->state,
						state2string(data->state));
			return;
		}

		DBG("ready, initialize CLAT");
		break;
	case CONNMAN_SERVICE_STATE_ONLINE:
		if (service != data->service)
			return;

		if (connman_service_get_default() != data->service) {
			DBG("CLAT service is not default service");
			return;
		}

		if (!is_running(data->state)) {
			DBG("online, CLAT is not running yet, start it first");
			break;
		}

		goto onlinecheck;
	}

	network = connman_service_get_network(service);
	if (!network) {
		DBG("No network yet, not starting clat");
		return;
	}

	if (data->ifindex < 0) {
		DBG("ifindex not set, get it from network");
		data->ifindex = connman_network_get_index(network);
	}

	if (data->ifindex < 0) {
		DBG("Interface not up, not starting clat");
		return;
	}

	ifname = connman_inet_ifname(data->ifindex);
	if (!ifname) {
		DBG("Interface %d not up, not starting clat", data->ifindex);
		return;
	}

	g_free(ifname);

	/* Network may have DHCP/AUTO set without address */
	if (connman_network_is_configured(network,
					CONNMAN_IPCONFIG_TYPE_IPV4) &&
					has_ipv4_address(data->service)) {
		DBG("Service %p has IPv4 address on interface %d, not "
						"starting CLAT", data->service,
						data->ifindex);
		return;
	}

	err = clat_start(data);
	if (err && err != -EALREADY)
		connman_error("failed to start CLAT, error %d", err);

onlinecheck:
	if (state == CONNMAN_SERVICE_STATE_ONLINE &&
					data->state == CLAT_STATE_RUNNING) {
		DBG("online, CLAT is running, do online check");

		err = clat_task_start_online_check(data);
		if (err && err != -EALREADY)
			connman_error("CLAT failed to do online check");
	}
}

static void clat_tethering_changed(struct connman_technology *tech, bool on)
{
	struct clat_data *data = get_data();

	/* We just need to know if tethering is enabled or not */
	data->tethering_on = on;

	setup_double_nat(data);
}

static struct connman_notifier clat_notifier = {
	.name			= "clat",
	.ipconfig_changed	= clat_ipconfig_changed,
	.default_changed	= clat_default_changed,
	.service_state_changed	= clat_service_state_changed,
	.tethering_changed	= clat_tethering_changed,
};

static int clat_init(void)
{
	GKeyFile *config;
	int err;

	DBG("");

	config = load_clat_config(CLATCONFIGFILE);
	if (config) {
		parse_clat_config(config);
		g_key_file_free(config);
	}

	__data = clat_data_init();
	if (!__data) {
		connman_error("CLAT: cannot initialize data");
		return -ENOMEM;
	}

	err = connman_notifier_register(&clat_notifier);
	if (err) {
		connman_error("CLAT: notifier register failed");
		return err;
	}

	err = connman_rtnl_register(&clat_rtnl);
	if (err) {
		connman_error("CLAT: rtnl notifier register failed");
		return err;
	}

	connman_rtnl_handle_rtprot_ra(true);

	return 0;
}

static void clat_exit(void)
{
	DBG("");

	if (is_running(__data->state))
		clat_stop(__data);

	connman_notifier_unregister(&clat_notifier);
	connman_rtnl_handle_rtprot_ra(false);
	connman_rtnl_unregister(&clat_rtnl);

	clat_data_free(__data);
	clear_clat_config();
}

CONNMAN_PLUGIN_DEFINE(clat, "CLAT plugin", VERSION,
			CONNMAN_PLUGIN_PRIORITY_DEFAULT, clat_init, clat_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
