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
#include <connman/nat.h>
#include <connman/notifier.h>
#include <connman/rtnl.h>
#include <connman/setting.h>
#include <connman/wakeup_timer.h>
#include <connman/provider.h>

#include <gweb/gresolv.h>

#include <linux/if_tun.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE

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

enum tethering_state {
	TETHERING_UNSET = 0,
	TETHERING_ON,
	TETHERING_OFF,
};

struct clat_data {
	struct connman_service *service;
	struct connman_ipconfig *ipv6config;
	struct connman_task *task;
	struct connman_service *vpn_service;
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
	guint resolv_timeouts;
	guint resolv_errors;

	guint dad_id;
	guint prefix_query_id;

	guint out_ch_id;
	guint err_ch_id;
	GIOChannel *out_ch;
	GIOChannel *err_ch;

	enum tethering_state tethering;
	bool do_restart;
	bool task_is_stopping;
	bool ipv4_default_route_on;
	bool vpn_mode_on;
};

#define WKN_ADDRESS "ipv4only.arpa"
#define DEFAULT_TAYGA_BIN		"/usr/sbin/tayga"
#define TAYGA_CLAT_DEVICE		"clat"
#define TAYGA_CONF			"tayga.conf"
#define TAYGA_IPv4ADDR			"192.0.0.2"	/* from RFC 7335 */

#define CLAT_IPv4ADDR			"192.0.0.1"	/* from RFC 7335 */
#define CLAT_IPv4ADDR_NETWORK		"192.0.0.0"	/* from RFC 7335 */
#define CLAT_IPv4ADDR_NETMASK		29		/* from RFC 7335 */
#define CLAT_IPv4_INADDR_ANY		"0.0.0.0"
#define CLAT_IPv4_METRIC		2049		/* Set as value -1 */
#define CLAT_IPv4_ROUTE_MTU		1260		/* from clatd */
#define CLAT_IPv6_METRIC		1024		/* from clatd */
#define CLAT_IPv6_SUFFIX		"c1a7"

#define PREFIX_QUERY_TIMEOUT		600000		/* 10 minutes */
#define PREFIX_QUERY_RETRY_TIMEOUT	2000		/* Retry in 2 seconds */
#define PREFIX_QUERY_MAX_RETRY_TIMEOUT	6		/* Try 6 times if TO */
#define DAD_TIMEOUT			600000		/* 10 minutes */

/* Globally defined and assigned prefix */
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

	/* Use DAD for protecting the address, default to being on. */
	.dad_enabled = true,

	/* Resolv result always sets global prefix if fails, default off */
	.resolv_always_succeeds = false,

	/* Add netmask to the CLAT device IPv4 address, default on */
	.clat_device_use_netmask = true,

	/* Write IPv6 address of the interface to tayga config, default off */
	.tayga_use_ipv6_conf = false,

	/* Value for strict-frag-hdr, default on */
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

	g_clear_error(&error);

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

static bool is_running_state(enum clat_state state)
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
	} else if (data->err_ch == channel) {
		DBG("closing task %p STDERR", data->task);

		if (data->err_ch_id) {
			g_source_remove(data->err_ch_id);
			data->err_ch_id = 0;
		}

		g_io_channel_shutdown(data->err_ch, FALSE, NULL);
		g_io_channel_unref(data->err_ch);

		data->err_ch = NULL;
	}
}

static int force_rmtun(const char *ifname)
{
	int index;
	int err;

	index = connman_inet_ifindex(ifname);
	if (index < 0) {
		connman_error("Cannot force-remove %s, no such interface",
									ifname);
		return -ENODEV;
	}

	err = connman_inet_ifdown(index);
	if (err && err != -EALREADY)
		connman_error("Cannot put %s down, trying to remove anyway",
									ifname);

	/* tayga in tayga.c sets IFF_TUN as only flag for the interface */
	err = connman_inet_rmtun(TAYGA_CLAT_DEVICE, IFF_TUN);
	if (err) {
		connman_error("Failed to remove tun device %s",	ifname);
		return err;
	}

	DBG("Forcefully removed persistent tun device %s", ifname);

	return 0;
}

static int clat_run_task(struct clat_data *data);
static int clat_stop(struct clat_data *data);
static int stop_task(struct clat_data *data);

static gboolean io_channel_cb(GIOChannel *source, GIOCondition condition,
			gpointer user_data)
{
	struct clat_data *data = user_data;
	const char dev_busy_suffix[] = "aborting: Device or resource busy";
	const char dev_invalid[] = "aborting: Invalid argument";
	const char bad_state_suffix[] = "File descriptor in bad state";
	char *str;
	unsigned int *id;
	int err;

	id = source == data->out_ch ? &data->out_ch_id : &data->err_ch_id;

	if (condition & (G_IO_IN | G_IO_PRI)) {
		GIOStatus status;
		bool restart = false;
		gsize len;

		status = g_io_channel_read_line(source, &str, &len, NULL, NULL);
		if (status != G_IO_STATUS_NORMAL && status != G_IO_STATUS_EOF) {
			DBG("cannot read line, status %d", status);
			return G_SOURCE_CONTINUE;
		}

		if (!str || !len) {
			DBG("Empty or 0 length read");
			return G_SOURCE_CONTINUE;
		}

		str[len - 1] = '\0';

		if (source == data->out_ch) {
			connman_info("CLAT %s: %s", clat_settings.tayga_bin,
									str);
		} else {
			connman_error("CLAT %s: %s", clat_settings.tayga_bin,
									str);
		}

		/* This requires real hard removal of the device */
		if (g_str_has_suffix(str, dev_busy_suffix) ||
					g_str_has_suffix(str, dev_invalid)) {
			switch (data->state) {
			case CLAT_STATE_IDLE:
			case CLAT_STATE_PREFIX_QUERY:
			case CLAT_STATE_RUNNING:
			case CLAT_STATE_RESTART:
				connman_warn("State machine invalid, not"
							"reacting to error");
				break;
			/*
			 * Force remove the device and restart. Restart will
			 * set the device first to POST_CONFIGURE state and
			 * fails to remove the nonexistent device resulting in
			 * stopping this task and returning to state that
			 * preceeds PRE_CONFIGURE. After running the new task
			 * when current task exits it starts with old config.
			 */
			case CLAT_STATE_PRE_CONFIGURE:
				err = force_rmtun(TAYGA_CLAT_DEVICE);
				if (!err)
					restart = true;

				break;
			/* It may be possible to read the message late */
			case CLAT_STATE_STOPPED:
			case CLAT_STATE_FAILURE:
			case CLAT_STATE_POST_CONFIGURE:
				err = force_rmtun(TAYGA_CLAT_DEVICE);
				if (err)
					connman_error("Lingering tun device %s",
							TAYGA_CLAT_DEVICE);

				break;
			}
		/*
		 * Process needs restart, without interface post configure
		 * only removes the nat6 rules.
		 */
		} else if (g_str_has_suffix(str, bad_state_suffix)) {
			restart = true;
		}

		g_free(str);

		if (restart) {
			data->state = CLAT_STATE_RESTART;

			/*
			 * When task is running stop it and do restart in exit
			 * function.
			 */
			if (data->state == CLAT_STATE_RUNNING)
				err = stop_task(data);
			else
				err = clat_run_task(data);

			if (err && err != -EALREADY) {
				connman_error("Interface lost and failed to do "
						"CLAT restart %d. Stop CLAT",
						err);
				err = clat_stop(data);
				if (err && err != -EALREADY)
					connman_error("Stopping CLAT failed %d",
								err);
			}

			*id = 0;
			return G_SOURCE_REMOVE;
		}
	} else if (condition & (G_IO_ERR | G_IO_HUP)) {
		DBG("%s Channel termination", source == data->out_ch ?
						"STDOUT" : "STDERR");
		*id = 0;
		close_io_channel(data, source);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int create_task(struct clat_data *data)
{
	if (!data)
		return -ENOENT;

	data->task = connman_task_create(clat_settings.tayga_bin, NULL, NULL);
	if (!data->task)
		return -ENOMEM;

	DBG("task %p", data->task);

	return 0;
}

static int stop_task(struct clat_data *data)
{
	int err;

	if (!data || !data->task)
		return -ENOENT;

	DBG("task %p", data->task);

	/* Task should be called to stop only once */
	if (data->task_is_stopping) {
		DBG("already stopping");
		return -EALREADY;
	}

	err = connman_task_stop(data->task);
	if (err)
		connman_error("CLAT failed to stop current task");
	else
		data->task_is_stopping = true;

	return err;
}

static int destroy_task(struct clat_data *data)
{
	int err;

	if (!data || !data->task)
		return -ENOENT;

	DBG("task %p", data->task);

	err = stop_task(data);
	if (err && err != -EALREADY)
		connman_error("CLAT task stopping failed, continuing anyway");

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

	data->resolv_timeouts = 0;
	data->resolv_errors = 0;
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

	/* ippool.c apparently defaults to 24 subnet for tethering */
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

	entry = g_new0(struct prefix_entry, 1);
	if (!entry)
		return NULL;

	DBG("entry %p", entry);

	tokens = g_strsplit(address, "/", 2);

	/* Result has a global prefix */
	if (g_str_has_prefix(address, GLOBAL_PREFIX)) {
		entry->prefix = g_strdup(GLOBAL_PREFIX);
		entry->prefixlen = GLOBAL_PREFIXLEN;
	/* Result had address and prefix length. */
	} else if (tokens && g_strv_length(tokens) == 2) {
		entry->prefix = g_strdup(tokens[0]);
		entry->prefixlen = (unsigned char)g_ascii_strtoull(tokens[1],
								NULL, 10);
	/* TODO create proper parser for addresses without prefix */
	} else {
		DBG("address does not contain a valid prefix");
		free_prefix_entry(entry);
		entry = NULL;
	}
	/*
	 * TODO: Check the prefixlenght from other than ones with GLOBAL_PREFIX
	 * utilizing XOR of the A record result. Use /96 prefix for all as
	 * android does.
	 */

	g_strfreev(tokens);

	if (!entry)
		return NULL;

	/*
	 * Addresses with < 16 prefixlen should not be possible, also ignore
	 * single address prefixes as there is no room for additional address.
	 */
	if (entry->prefixlen > 120 || entry->prefixlen < 16) {
		DBG("Invalid prefixlen %u", entry->prefixlen);
		free_prefix_entry(entry);
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
		if (g_strcmp0(data->clat_prefix, entry->prefix) ||
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

static int clat_task_start_periodic_query(struct clat_data *data);
static int clat_task_restart_periodic_query(struct clat_data *data);
static int stop_task(struct clat_data *data);

static bool clat_is_running(struct clat_data *data)
{
	if (!data)
		return false;

	return is_running_state(data->state);
}

static void prefix_query_cb(GResolvResultStatus status,
					char **results, gpointer user_data)
{
	struct clat_data *data = user_data;
	enum clat_state new_state = data->state;
	int err = 0;

	DBG("state %d/%s status %d GResolv %p", data->state,
						state2string(data->state),
						status, data->resolv);

	if (!data->resolv && !data->resolv_query_id) {
		DBG("resolv was already cleared, running state: %s",
					clat_is_running(data) ? "yes" : "no");
		return;
	}

	/*
	 * We cannot unref the resolver here as resolv struct is manipulated
	 * by gresolv.c after we return from this callback.
	 */
	data->remove_resolv_id = g_timeout_add(0, remove_resolv, data);
	data->resolv_query_id = 0;

	switch (status) {
	case G_RESOLV_RESULT_STATUS_SUCCESS:
		DBG("resolv of %s success, parse prefix", WKN_ADDRESS);
		err = assign_clat_prefix(data, results);
		data->resolv_timeouts = 0;
		data->resolv_errors = 0;
		break;
	/* request timeouts not an error, try again */
	case G_RESOLV_RESULT_STATUS_NO_RESPONSE:
		err = -ETIMEDOUT;
		data->resolv_timeouts++;
		break;
	/* server had an issue, try again */
	case G_RESOLV_RESULT_STATUS_SERVER_FAILURE:
		err = -EHOSTDOWN;
		break;
	/* Consider these as non-continuable errors */
	case G_RESOLV_RESULT_STATUS_ERROR:
	case G_RESOLV_RESULT_STATUS_FORMAT_ERROR:
	case G_RESOLV_RESULT_STATUS_NAME_ERROR:
	case G_RESOLV_RESULT_STATUS_NOT_IMPLEMENTED:
		err = -EINVAL;
		break;
	case G_RESOLV_RESULT_STATUS_REFUSED:
		err = -ECONNREFUSED;
		break;
	case G_RESOLV_RESULT_STATUS_NO_ANSWER:
		err = -ENOENT;
		data->resolv_errors++;
		break;
	}

	if (status != G_RESOLV_RESULT_STATUS_SUCCESS &&
					clat_settings.resolv_always_succeeds) {
		gchar **override = g_new0(char*, 2);

		DBG("ignore resolv result %d", status);

		override[0] = g_strdup("64:ff9b::/96");
		override[1] = NULL;
		err = assign_clat_prefix(data, override);
		g_strfreev(override);
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
		if (clat_is_running(data)) {
			DBG("failed to resolv %s, CLAT is stopped",
								WKN_ADDRESS);
			stop_task(data);
			return;
		}

		DBG("failed to resolv %s, set failure state", WKN_ADDRESS);
		new_state = CLAT_STATE_FAILURE;

		break;
	case -ETIMEDOUT:
	case -ENOENT:
		DBG("timeouts %d errors %d", data->resolv_timeouts,
							data->resolv_errors);

		if (data->resolv_timeouts > PREFIX_QUERY_MAX_RETRY_TIMEOUT) {
			DBG("resolv timeout limit reached, CLAT is stopped");
			clat_stop(data);
			return;
		}

		if (data->resolv_errors > PREFIX_QUERY_MAX_RETRY_TIMEOUT) {
			DBG("resolv error limit reached, CLAT is stopped");
			clat_stop(data);
			return;
		}

		/* Start periodic query if this is the initial query */
		if (data->state == CLAT_STATE_PREFIX_QUERY) {
			DBG("failed to resolv %s during initial query, "
						"continue periodic query",
						WKN_ADDRESS);
			clat_task_start_periodic_query(data);
			return;
		}

		/*
		 * If timeout or possibly lost response happens when CLAT is
		 * running repeat the query up to the
		 * PREFIX_QUERY_MAX_RETRY_TIMEOUT limit.
		 */
		if (clat_is_running(data)) {
			DBG("query timeouted/lost, retry after %d seconds",
					PREFIX_QUERY_RETRY_TIMEOUT/1000);
			clat_task_restart_periodic_query(data);
			return;
		}

		new_state = CLAT_STATE_FAILURE;
		break;
	default:
		DBG("failed to assign prefix/resolv host, error %d", err);
		new_state = CLAT_STATE_FAILURE;
		break;
	}

	if (data->state == CLAT_STATE_FAILURE) {
		DBG("CLAT already in failure state, not transitioning state");
		return;
	}

	/*
	 * In case state changes to failure while the task is running let it
	 * die first to get the cleanup done properly.
	 */
	if (data->state == CLAT_STATE_RUNNING) {
		DBG("Stop running CLAT to change state to %d", new_state);

		stop_task(data);
		data->state = new_state;

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
		if (err && err != -EALREADY) {
			connman_error("failed to run CLAT, error %d", err);
			clat_data_clear(data);
		}
	}
}

static guint get_pq_timeout(struct clat_data *data)
{
	if (!data)
		return 0;

	if (data->state == CLAT_STATE_IDLE)
		return PREFIX_QUERY_RETRY_TIMEOUT / 10; /* every second */

	if (data->state == CLAT_STATE_PREFIX_QUERY)
		return PREFIX_QUERY_RETRY_TIMEOUT;

	return PREFIX_QUERY_TIMEOUT;
}

static int clat_task_start_periodic_query(struct clat_data *data);

static bool has_nameservers_set(struct connman_service *service)
{
	char **nss;
	bool ret;

	if (!service)
		return false;

	nss = connman_service_get_nameservers(service);
	if (!nss)
		return false;

	ret = g_strv_length(nss) > 0 ? true : false;
	g_strfreev(nss);

	return ret;
}

static int clat_task_do_prefix_query(struct clat_data *data)
{
	int err;

	DBG("");

	if (data->resolv_query_id > 0) {
		DBG("previous query was running, abort it");
		remove_resolv(data);
	}

	data->resolv_query_id = 0;

	/* When getting the initial resolv and no nameservers are set, wait */
	if (data->state == CLAT_STATE_PREFIX_QUERY &&
					!has_nameservers_set(data->service)) {
		DBG("service %p has no nameservers set yet, try again in 1s",
								data->service);

		err = clat_task_start_periodic_query(data);
		if (err)
			return err;

		return -EINPROGRESS;
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
	int err;

	DBG("");

	if (!data)
		return G_SOURCE_REMOVE;

	data->prefix_query_id = 0;

	err = clat_task_do_prefix_query(data);
	if (err) {
		DBG("failed to run prefix query: %d", err);
		return G_SOURCE_REMOVE;
	}

	data->prefix_query_id = connman_wakeup_timer_add(get_pq_timeout(data),
							run_prefix_query, data);
	if (!data->prefix_query_id)
		connman_error("CLAT failed to continue periodic prefix query");

	return G_SOURCE_REMOVE;
}

static int clat_task_restart_periodic_query(struct clat_data *data)
{
	DBG("");

	if (data->prefix_query_id > 0) {
		DBG("Already running, stop old");
		g_source_remove(data->prefix_query_id);
	}

	data->prefix_query_id = connman_wakeup_timer_add(
						PREFIX_QUERY_RETRY_TIMEOUT,
						run_prefix_query, data);
	if (!data->prefix_query_id) {
		connman_error("CLAT failed to re-start periodic prefix query");
		return -EINVAL;
	}

	return 0;
}

static int clat_task_start_periodic_query(struct clat_data *data)
{
	DBG("");

	if (data->prefix_query_id > 0) {
		DBG("Already running");
		return -EALREADY;
	}

	/*
	 * TODO: make this do the queries with AAAA DNS TTL - 10s, i.e., 10s
	 * before the record expires as stated by RFC.
	 */
	data->prefix_query_id = connman_wakeup_timer_add(get_pq_timeout(data),
							run_prefix_query, data);
	if (!data->prefix_query_id) {
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
	g_free(data->address);
	data->address = g_strconcat(ipv6prefix, "::", CLAT_IPv6_SUFFIX, NULL);
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

	g_free(data->ipv6address);
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

static int setup_ipv4_default_route(struct clat_data *data, bool enable)
{
	int index;
	int err;

	index = connman_inet_ifindex(TAYGA_CLAT_DEVICE);
	if (index < 0) {
		DBG("index %d name %s", index, TAYGA_CLAT_DEVICE);
		return -ENODEV;
	}

	if (data->ipv4_default_route_on == enable)
		return -EALREADY;

	if (enable) {
		err = connman_inet_add_network_route_with_metric(index,
							CLAT_IPv4_INADDR_ANY,
							CLAT_IPv4_INADDR_ANY,
							CLAT_IPv4_INADDR_ANY,
							CLAT_IPv4_METRIC,
							CLAT_IPv4_ROUTE_MTU);
	} else {
		err = connman_inet_del_network_route_with_metric(index,
							CLAT_IPv4_INADDR_ANY,
							CLAT_IPv4_METRIC);
	}

	if (err)
		return err;

	data->ipv4_default_route_on = enable;
	return 0;
}

static int clat_task_configure(struct clat_data *data)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	enum connman_service_state new_state;
	char *netmask = NULL;
	int err;
	int index;

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

	/* Call to nat6 prepare increases the ipconfig reference for itself*/
	err = connman_nat6_prepare(ipconfig, data->address,
						data->addr_prefixlen,
						TAYGA_CLAT_DEVICE, true);
	if (err) {
		connman_warn("CLAT failed to prepare nat and firewall %d", err);
		return err;
	}

	/*
	 * We keep this because the service can reset the pointer to its
	 * ipconfig before tayga process has properly terminated and ipconfig
	 * is needed for nat6 restore. As the struct itself is kept by nat.c
	 * as an added reference we can safely use this between nat6 prepare
	 * and restore.
	 */
	data->ipv6config = ipconfig;

	connman_inet_add_ipv6_network_route_with_metric(index, data->address,
						NULL, data->addr_prefixlen,
						CLAT_IPv6_METRIC);

	if (clat_settings.clat_device_use_netmask)
		netmask = cidr_to_str(CLAT_IPv4ADDR_NETMASK);

	err = connman_service_reset_ipconfig_to_address(data->service,
						&new_state,
						CONNMAN_IPCONFIG_TYPE_IPV4,
						CONNMAN_IPCONFIG_METHOD_MANUAL,
						index,
						CLAT_IPv4ADDR,
						netmask,
						NULL,
						0);

	if (err) {
		connman_error("Failed to set CLAT IPv4 address for service %p",
								data->service);
		return err;
	}

	DBG("Set service %p to new state %d using CLAT IPv4 address %s",
				data->service, new_state, CLAT_IPv4ADDR);

	ipconfig = connman_service_get_ipconfig(data->service, AF_INET);
	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	if (ipaddress) {
		connman_inet_set_address(index, ipaddress);
		g_free(netmask);
	}

	if (!ipaddress) {
		connman_error("No IPv4config on service %p cannot setup CLAT",
								data->service);
		return -ENOENT;
	}

	err = setup_ipv4_default_route(data, true);
	if (err && err != -EALREADY) {
		connman_error("CLAT failed to enable IPv4 default route: %d",
									err);
		return -EINVAL;
	}

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
	char ipv6_addr[INET6_ADDRSTRLEN] = { 0 };

	DBG("reply %p length %u", reply, length);

	if (addr) {
		/* This should not probably happen */
		if (!inet_ntop(AF_INET6, addr, ipv6_addr, INET6_ADDRSTRLEN)) {
			DBG("Invalid IPv6 address in DAD reply");
		}
	}

	/* No reply with zero lenght means success according to dhcpv6.c */
	if (!reply && !length) {
		DBG("DAD succeeded for %s", ipv6_addr);
		return;
	}

	/* TODO select another address if cannot be DAD'd and restart process */
	DBG("DAD failed for %s", ipv6_addr);
}

static gboolean clat_task_run_dad(gpointer user_data)
{
	struct clat_data *data = user_data;
	struct in6_addr addr = { 0 };
	int err;

	DBG("data %p", data);

	data->dad_id = 0;

	if (inet_pton(AF_INET6, data->address, &addr) != 1) {
		connman_error("failed to pton address %s", data->address);
		return G_SOURCE_REMOVE;
	}

	err = connman_inet_ipv6_do_dad(data->ifindex, 1000, &addr, clat_dad_cb,
									data);
	if (err < 0) {
		/*
		 * If the sending of DAD fails consecutive calls will as well,
		 * stop DAD in such case
		 */
		connman_error("CLAT failed to send DAD: %d, stoppped", err);
		return G_SOURCE_REMOVE;
	}

	data->dad_id = connman_wakeup_timer_add(DAD_TIMEOUT, clat_task_run_dad,
									data);
	if (!data->dad_id)
		connman_error("CLAT failed to start DAD timeout");

	return G_SOURCE_REMOVE;
}

static int clat_task_start_dad(struct clat_data *data)
{
	DBG("");

	if (!clat_settings.dad_enabled) {
		DBG("DAD disabled by config");
		return 0;
	}

	/* Do DAD initially right away and then with DAD_TIMEOUT interval */
	data->dad_id = connman_wakeup_timer_add(0, clat_task_run_dad, data);
	if (!data->dad_id) {
		connman_error("CLAT failed to start DAD timeout");
		return -EINVAL;
	}

	return 0;
}

static int clat_task_stop_dad(struct clat_data *data)
{
	DBG("");

	if (data->dad_id > 0)
		g_source_remove(data->dad_id);

	data->dad_id = 0;

	return 0;
}

static int clat_task_post_configure(struct clat_data *data)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	enum connman_service_state new_state;
	int index;
	int err;

	DBG("ipconfig %p", data->ipv6config);

	if (data->ipv6config) {
		/* Restore releases the reference to ipconfig, set it to NULL */
		connman_nat6_restore(data->ipv6config);
		data->ipv6config = NULL;
	}

	index = connman_inet_ifindex(TAYGA_CLAT_DEVICE);
	if (index < 0) {
		DBG("CLAT tayga interface not up, nothing to do");
		return -ENODEV;
	}

	err = setup_ipv4_default_route(data, false);
	if (err && err != -EALREADY) {
		connman_error("CLAT failed to delete IPv4 default route: %d",
									err);
	}

	ipconfig = connman_service_get_ipconfig(data->service, AF_INET);
	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	if (ipaddress) {
		connman_inet_clear_address(index, ipaddress);
		connman_ipaddress_clear(ipaddress);
	} else {
		connman_warn("Cannot clear CLAT IPv4 address in interface %d",
									index);
	}

	err = connman_service_reset_ipconfig_to_address(data->service,
						&new_state,
						CONNMAN_IPCONFIG_TYPE_IPV4,
						CONNMAN_IPCONFIG_METHOD_OFF,
						index, NULL, NULL, NULL, 0);
	if (err)
		connman_error("CLAT cannot reset service %p IPv4config, err %d",
							data->service, err);

	connman_inet_del_ipv6_network_route_with_metric(index,
						data->address,
						data->addr_prefixlen,
						CLAT_IPv6_METRIC);
	connman_inet_ifdown(index);

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

	DBG("task %p state %d/%s", task, data->state, state2string(data->state));

	if (exit_code)
		connman_warn("CLAT task failed with code %d", exit_code);

	if (task != data->task) {
		connman_warn("CLAT task differs, nothing done");
		return;
	}

	destroy_task(data);

	/* Reset task stopping after destroy to avoid 2nd call */
	data->task_is_stopping = false;

	switch (data->state) {
	case CLAT_STATE_IDLE:
	case CLAT_STATE_STOPPED:
		DBG("CLAT task exited in state %d/%s", data->state,
						state2string(data->state));
		break;
	/* If the state has been set to failure cleanup is required */
	case CLAT_STATE_FAILURE:
		DBG("CLAT task exited, state set to failure, do post config");

		data->state = CLAT_STATE_POST_CONFIGURE;

		err = clat_run_task(data);
		if (err && err != -EALREADY)
			connman_error("failed to run CLAT post conf, error %d",
									err);
		return;
	case CLAT_STATE_PREFIX_QUERY:
	case CLAT_STATE_PRE_CONFIGURE:
	case CLAT_STATE_RUNNING:
		if (exit_code) {
			/*
			 * If the process segfaults when clat should be running
			 * do restart.
			 */
			if (data->state == CLAT_STATE_RUNNING)
				data->state = CLAT_STATE_RESTART;
			else
				data->state = CLAT_STATE_FAILURE;
		} else {
			DBG("run next state %d/%s", data->state + 1,
						state2string(data->state + 1));
		}

		err = clat_run_task(data);
		if (err && err != -EALREADY) {
			connman_error("failed to run CLAT, error %d", err);
			break;
		}

		return;
	case CLAT_STATE_POST_CONFIGURE:
		if (data->do_restart) {
			/*
			 * RESTART comes after prefix query has been done or
			 * when the process segfaults, go directly to
			 * PRE_CONFIGURE state.
			 */
			DBG("CLAT process restarting");
			data->state = CLAT_STATE_PREFIX_QUERY;
			data->do_restart = false;

			err = clat_run_task(data);
			if (err && err != -EALREADY) {
				connman_error("failed to run CLAT restart, "
							"error %d", err);
				break;
			}

			return;
		}

		DBG("CLAT process ended");
		data->state = CLAT_STATE_STOPPED;
		break;
	case CLAT_STATE_RESTART:
		DBG("CLAT task return when restarting");

		err = clat_run_task(data);
		if (err && err != -EALREADY)
			connman_error("failed to start CLAT in restart state, "
							"error %d", err);
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

	/* In VPN mode double nat is not set */
	if (!data->ipv4_default_route_on)
		return;

	if (data->tethering == TETHERING_ON &&
					data->state == CLAT_STATE_RUNNING) {
		DBG("tethering enabled when CLAT is running, override nat");

		err = connman_nat_enable_double_nat_override(TAYGA_CLAT_DEVICE,
						CLAT_IPv4ADDR_NETWORK,
						CLAT_IPv4ADDR_NETMASK);
		if (err && err != -EINPROGRESS)
			connman_error("Failed to setup double nat for tether");
	} else if (data->tethering == TETHERING_OFF) {
		DBG("Remove nat override");
		connman_nat_disable_double_nat_override(TAYGA_CLAT_DEVICE);
	}
}

static void stop_running(struct clat_data *data)
{
	enum tethering_state tethering;

	if (!data)
		return;

	clat_task_stop_periodic_query(data);
	clat_task_stop_dad(data);
	clat_task_stop_online_check(data);

	/* When stopping disable double nat but backup tethering state */
	if (data->tethering == TETHERING_ON) {
		tethering = data->tethering;
		data->tethering = TETHERING_OFF;
		setup_double_nat(data);
		data->tethering = tethering;
	}
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
		if (err && err != -EALREADY && err != -EINPROGRESS) {
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
		err = clat_task_configure(data);
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
	case CLAT_STATE_RESTART:
		data->do_restart = true;
		/* fall through */
	/* If either running or stopped state and run is called do cleanup */
	case CLAT_STATE_RUNNING:
	case CLAT_STATE_STOPPED:
		stop_running(data);

		err = clat_task_post_configure(data);
		if (!err) {
			data->state = CLAT_STATE_POST_CONFIGURE;
			break;
		}

		/* If restarting CLAT the device may be gone already */
		if (err == -ENODEV && data->do_restart) {
			DBG("Device %s gone and restart required ignore ENODEV",
							TAYGA_CLAT_DEVICE);
			/*
			 * Reset back to state to run pre configure and stop
			 * the task to it call exit function. This will make
			 * tayga use existing settings.
			 */
			data->do_restart = false;
			data->state = CLAT_STATE_PREFIX_QUERY;

			/*
			 * This will make sure that the task will stop. If post
			 * configure reports -ENODEV it has not set up the task
			 * yet. We can ignore the error.
			 */
			err = stop_task(data);
			if (err == -ENOENT) {
				/*
				 * When there was no task to stop the process
				 * needs to be started.
				 */
				DBG("Restart CLAT into pre configure state");

				err = clat_run_task(data);
				if (err)
					connman_error("Failed to restart CLAT");

				return err;
			} else if (err) {
				connman_error("Failed to stop task %p, error "
							"%d/%s, continue",
							data->task, err,
							strerror(-err));
			} else {
				/* Task exit will do the state transition */
				return 0;
			}
		} else {
			connman_error("CLAT failed to create post-configure "
							"task, error %d/%s",
							err, strerror(-err));
			return err;
		}

		break;
	case CLAT_STATE_POST_CONFIGURE:
		connman_warn("CLAT run task called in post-configure state");
		data->state = CLAT_STATE_STOPPED;
		return 0;
	case CLAT_STATE_FAILURE:
		DBG("CLAT entered failure state, stop all that is running");

		stop_running(data);

		/* Do post configure if the interface is up */
		err = clat_task_post_configure(data);
		if (err && err != -ENODEV) {
			connman_error("CLAT failed to create post-configure "
						"task in failure state");
			break;
		}

		data->state = CLAT_STATE_POST_CONFIGURE;

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

	if (clat_is_running(data))
		return -EALREADY;

	data->state = CLAT_STATE_IDLE;
	clat_run_task(data);

	return 0;
}

static void set_vpn_service(struct clat_data *data,
					struct connman_service *vpn_service)
{
	struct connman_provider *provider;

	DBG("VPN service %p", vpn_service);

	if (!data)
		return;

	if (vpn_service && data->vpn_service == vpn_service) {
		DBG("No change in VPN service");
		return;
	}

	/* The VPN is only set if it is a IPv4 VPN using the tracked service */
	if (!vpn_service && data->state == CLAT_STATE_RUNNING) {
		provider = connman_service_get_vpn_provider(data->vpn_service);
		if (provider) {
			DBG("Disconnecting VPN %p provider %p ",
						data->vpn_service, provider);
			connman_provider_disconnect(provider);
		}
	}

	if (data->vpn_service)
		connman_service_unref(data->vpn_service);

	if (!vpn_service)
		data->vpn_service = NULL;
	else
		data->vpn_service = connman_service_ref(vpn_service);
}

static int clat_stop(struct clat_data *data)
{
	if (!data)
		return -EINVAL;

	DBG("state %d/%s", data->state, state2string(data->state));

	/* Do not leave the VPN hanging */
	set_vpn_service(data, NULL);
	data->vpn_mode_on = false;

	if (!clat_is_running(data)) {
		DBG("already stopping/stopped");
		return -EALREADY;
	}

	if (data->state == CLAT_STATE_PREFIX_QUERY)
		clat_task_stop_periodic_query(data);

	if (data->task)
		return stop_task(data);

	data->state = CLAT_STATE_STOPPED;

	return 0;
}

/*static int clat_failure(struct clat_data *data)
{
	return 0;
}*/

static void clat_new_rtnl_gateway(int index, const char *dst,
						const char *gateway, int metric,
						unsigned char rtm_protocol)
{
	struct clat_data *data = get_data();

	DBG("%d dst %s gateway %s metric %d", index, dst, gateway, metric);

	/* Not the device we are monitoring. */
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
		//clat_stop(data);
	}
}

static struct connman_rtnl clat_rtnl = {
	.name			= "clat",
	.newgateway6		= clat_new_rtnl_gateway,
	.delgateway6		= clat_del_rtnl_gateway,
};

enum clat_service_type {
	CLAT_SERVICE_IGNORE = 0,
	CLAT_SERVICE_ACCEPT,
	CLAT_SERVICE_VPNMODE,
};

static bool has_ip_address(struct connman_service *service,
						enum connman_ipconfig_type type)
{
	struct connman_ipconfig *ipconfig;
	char v;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		ipconfig = connman_service_get_ipconfig(service, AF_INET);
		v = '4';
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		ipconfig = connman_service_get_ipconfig(service, AF_INET6);
		v = '6';
		break;
	case CONNMAN_IPCONFIG_TYPE_ALL:
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		return false;
	}

	DBG("IPv%c ipconfig %p", v, ipconfig);

	return connman_ipconfig_has_ipaddress_set(ipconfig);
}

static bool check_vpn_transport(struct connman_service *service,
					struct connman_service *vpn_service)
{
	struct connman_service *transport;
	const char *identifier;

	DBG("service %p VPN service %p", service, vpn_service);

	if (!service || !vpn_service)
		return false;

	if (connman_service_get_type(vpn_service) != CONNMAN_SERVICE_TYPE_VPN) {
		DBG("not a VPN service %p", vpn_service);
		return false;
	}

	identifier = connman_service_get_vpn_transport_identifier(vpn_service);
	if (!identifier) {
		DBG("No transport set for VPN %p", vpn_service);
		return false;
	}

	transport = connman_service_lookup_from_identifier(identifier);
	if (transport != service) {
		DBG("Different VPN transport %s", identifier);
		return false;
	}

	return true;
}

static enum clat_service_type check_service_type(struct clat_data *data,
						struct connman_service *service)
{
	struct connman_service *default_service;
	enum connman_service_type type;

	DBG("data %p service %p", data, service);

	if (!data || !service)
		return CLAT_SERVICE_IGNORE;

	default_service = connman_service_get_default();
	DBG("default service %p", default_service);

	type = connman_service_get_type(service);
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		/*
		 * When VPN is the default with an IPv4 address and CLAT is
		 * running it means that VPN is going over CLAT and specific
		 * mode is being required. 
		 */
		if (default_service == service &&
					has_ip_address(service,
						CONNMAN_IPCONFIG_TYPE_IPV4) &&
					check_vpn_transport(data->service,
						service)) {
			DBG("Enabling CLAT VPN mode, VPN service %p", service);

			return CLAT_SERVICE_VPNMODE;
		} else {
			DBG("VPN service %p is not default", service);
		}

		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		// TODO make this work
		return CLAT_SERVICE_IGNORE;
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		/*
		 * Check of VPN is running as a default service with IPv4
		 * address and using the cellular service as transport.
		 */
		if (service != default_service &&
					check_vpn_transport(service,
						default_service) &&
					has_ip_address(default_service,
						CONNMAN_IPCONFIG_TYPE_IPV4)) {
			DBG("VPN mode active, tracked service %p is used as "
						"transport for IPv4 VPN %p",
						data->service, default_service);
			
			if (data->vpn_service)
				connman_service_unref(data->vpn_service);
			data->vpn_service = connman_service_ref(
						default_service);

			return CLAT_SERVICE_VPNMODE;
		}

		/* Cellular, do default checks elsewhere */
		DBG("Accept cellular service %p", service);

		return CLAT_SERVICE_ACCEPT;
	}

	return CLAT_SERVICE_IGNORE;
}

static bool is_valid_start_state(enum connman_service_state state)
{
	return state == CONNMAN_SERVICE_STATE_READY ||
				state == CONNMAN_SERVICE_STATE_ONLINE;
}

static int try_clat_start(struct clat_data *data)
{
	struct connman_network *network;
	char *ifname;

	if (!data || !data->service)
		return -EINVAL;

	if (!is_valid_start_state(connman_service_get_state(data->service))) {
		DBG("not ready|online, not starting clat");
		return -EINVAL;
	}

	network = connman_service_get_network(data->service);
	if (!network) {
		DBG("No network yet, not starting clat");
		return -ENONET;
	}

	if (!connman_network_get_connected(network)) {
		DBG("Network not connected yet, not starting clat");
		return -ENONET;
	}

	if (data->ifindex < 0) {
		DBG("ifindex not set, get it from network");
		data->ifindex = connman_network_get_index(network);
	}

	if (data->ifindex < 0) {
		DBG("Interface not up (index %d), not starting clat",
						data->ifindex);
		return -ENODEV;
	}

	ifname = connman_inet_ifname(data->ifindex);
	if (!ifname) {
		DBG("Interface %d not up, not starting clat", data->ifindex);
		return -ENODEV;
	}

	g_free(ifname);

	/* Network may have DHCP/AUTO set without address */
	if (connman_network_is_configured(network,
					CONNMAN_IPCONFIG_TYPE_IPV4) &&
					has_ip_address(data->service,
						CONNMAN_IPCONFIG_TYPE_IPV4)) {
		DBG("Service %p has IPv4 address on interface %d, not "
						"starting CLAT", data->service,
						data->ifindex);
		return 0;
	}

	return clat_start(data);
}

static bool has_ipv4_config(struct clat_data *data,
					struct connman_service *service,
					struct connman_ipconfig *ipconfig)
{
	int ipconfig_index;
	int clat_index;

	if (clat_is_running(data)) {
		clat_index = connman_inet_ifindex(TAYGA_CLAT_DEVICE);
		ipconfig_index = connman_ipconfig_get_index(ipconfig);

		if (clat_index >= 0 && ipconfig_index >= 0 &&
					clat_index == ipconfig_index) {
			DBG("Ignoring IPv4 ipconfig, set by CLAT");
			return false;
		}

		DBG("Not CLAT IPv4config change");
	}

	return has_ip_address(service, CONNMAN_IPCONFIG_TYPE_IPV4);
}

static void clat_ipconfig_changed(struct connman_service *service,
					struct connman_ipconfig *ipconfig)
{
	struct connman_network *network;
	struct clat_data *data = get_data();
	enum clat_service_type type;

	DBG("service %p ipconfig %p", service, ipconfig);

	if (!service || !data->service)
		return;

	/* TODO Support VPN as well */
	type = check_service_type(data, service);
	if (service != data->service || type == CLAT_SERVICE_IGNORE) {
		DBG("Not tracking service %p/%s or not supported", service,
				connman_service_get_identifier(service));
		return;
	}

	if (connman_ipconfig_get_config_type(ipconfig) ==
					CONNMAN_IPCONFIG_TYPE_IPV4) {
		if (has_ipv4_config(data, service, ipconfig)) {
			DBG("IPv4 config set, stop CLAT");
			clat_stop(data);
			return;
		}
	}

	/*
	 * When service loses its IPv6 address we need to stop. When service
	 * goes offline ipconfig may have been removed.
	 */
	if ((connman_ipconfig_get_config_type(ipconfig) ==
					CONNMAN_IPCONFIG_TYPE_IPV6) &&
					!has_ip_address(service,
						CONNMAN_IPCONFIG_TYPE_IPV6)) {
		DBG("cellular %p has lost IPv6 config, stop CLAT", service);
		clat_stop(data);
		return;
	}

	network = connman_service_get_network(data->service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected, stop CLAT", network);
		clat_stop(data);
		return;
	}
}

static int set_clat_service(struct clat_data *data,
						struct connman_service *service)
{
	bool restart = false;
	int err;

	DBG("data %p service %p", data, service);

	if (!data || !service)
		return -EINVAL;

	if (data->service == service)
		return -EALREADY;

	if (data->service && data->state == CLAT_STATE_RUNNING) {
		DBG("Service changed from %p/%s to %p/%s, do restart",
				data->service,
				connman_service_get_identifier(data->service),
				service,
				connman_service_get_identifier(service));
		restart = true;
	}

	data->service = service;

	if (restart) {
		data->state = CLAT_STATE_RESTART;
		err = clat_run_task(data);
		if (err) {
			connman_error("Changing tracked service and failed to "
						"run CLAT restart %d", err);
			return err;
		}
	}

	return 0;
}

static void clat_default_changed(struct connman_service *service)
{
	struct connman_network *network;
	struct connman_ipconfig *ipconfig;
	struct clat_data *data;
	enum connman_service_state state;
	int err;

	DBG("service %p", service);

	data = get_data();

	if (!service) {
		/*
		 * If we get a NULL service when tracked service is online/ready
		 * it is most likely because of re-arranging the default
		 * service list. In such case simply ignore the NULL and rely
		 * on the state change or a proper service as default to stop
		 * CLAT.
		 */
		if (clat_is_running(data)) {
			state = connman_service_get_state(data->service);
			if (state == CONNMAN_SERVICE_STATE_ONLINE ||
					state == CONNMAN_SERVICE_STATE_READY) {
				DBG("Ignore NULL service, tracked %p is "
							"ONLINE/READY",
							data->service);
				return;
			}

			DBG("CLAT stop with NULL default service");
			clat_stop(data);
		}

		return;
	}

	if (data->service != service) {
		switch (check_service_type(data, service)) {
		case CLAT_SERVICE_ACCEPT:
			DBG("Set service %p/%s as tracked service", service,
					connman_service_get_identifier(service));

			err = set_clat_service(data, service);
			if (err && err != -EALREADY) {
				connman_error("Failed to change service, stop "
									"CLAT");

				err = clat_stop(data);
				if (err && err != -EALREADY) {
					connman_error("Failed to stop CLAT");
				}

				clat_data_clear(data);
			}

			if (data->vpn_mode_on) {
				DBG("VPN mode on -> off");
				set_vpn_service(data, NULL);
				data->vpn_mode_on = false;
			}

			break;
		/*
		 * If clat is running and VPN is getting set as default
		 * and it uses IPv4 we need to disable default route from
		 * CLAT interface.
		 */
		case CLAT_SERVICE_VPNMODE:
			if (data->state != CLAT_STATE_RUNNING) {
				DBG("CLAT not in running state with VPN on");
				set_vpn_service(data, NULL);
				return;
			}

			set_vpn_service(data, service);

			if (data->tethering == TETHERING_ON) {
				/* Disable double nat if VPN is default */
				connman_nat_disable_double_nat_override(
							TAYGA_CLAT_DEVICE);
				DBG("Disabled double NAT for VPN %p", service);
			}

			err = setup_ipv4_default_route(data, false);
			if (err && err != -EALREADY) {
				connman_error("CLAT failed to remove IPv4 "
						"default route for VPN %p: %d",
						service, err);
			} else {
				DBG("Dropped IPv4 default route for VPN");
			}

			DBG("VPN mode on");
			data->vpn_mode_on = true;

			return;
		case CLAT_SERVICE_IGNORE:
			if (data->vpn_mode_on) {
				DBG("VPN mode on -> off");

				set_vpn_service(data, NULL);
				data->vpn_mode_on = false;
			}

			DBG("Tracked service %p is not default or valid, "
								"stop CLAT",
								data->service);
			clat_stop(data);
			return;
		}
	}

	state = connman_service_get_state(data->service);

	/* Tracked service is the default service but is not running -> start */
	if (!clat_is_running(data) && is_valid_start_state(state)) {
		DBG("Tracked service is default, start CLAT");

		err = try_clat_start(data);
		if (err && err != -EALREADY)
			connman_error("failed to start CLAT %d", err);

		return;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected, stop CLAT", network);
		clat_stop(data);
		return;
	}

	if (connman_network_is_configured(network,
						CONNMAN_IPCONFIG_TYPE_IPV4)) {
		ipconfig = connman_service_get_ipconfig(data->service, AF_INET);

		if (has_ipv4_config(data, service, ipconfig)) {
			DBG("IPv4 is configured on network %p, stop CLAT",
								network);
			clat_stop(data);
			return;
		}
	}

	/* VPN disconnected case, turn default route for IPv4 on */
	if (data->state == CLAT_STATE_RUNNING && is_valid_start_state(state) &&
						!data->ipv4_default_route_on) {

		if (data->vpn_mode_on) {
			DBG("VPN mode on -> off");
			set_vpn_service(data, NULL);
			data->vpn_mode_on = false;
		}

		err = setup_ipv4_default_route(data, true);
		if (err && err != -EALREADY) {
			connman_error("Failed to enable IPv4 default route: %d "
						"Stop clat", err);
			clat_stop(data);
			return;
		}

		DBG("Re-enabled IPv4 default route for CLAT");

		if (data->tethering == TETHERING_ON) {
			setup_double_nat(data);
			DBG("Re-enabled IPv4 double NAT for CLAT");
		}
	}
}

static void clat_service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	struct clat_data *data;
	enum clat_service_type type;
	int err;

	data = get_data();

	/*
	 * State changes are monitored only on the accepted type service or
	 * when in VPN mode
	 */
	type = check_service_type(data, service);
	switch (type) {
	case CLAT_SERVICE_ACCEPT:
		DBG("cellular service %p", service);
		break;
	case CLAT_SERVICE_VPNMODE:
		DBG("cellular service %p as VPN transport", service);
		break;
	case CLAT_SERVICE_IGNORE:
		if (connman_service_get_type(service) ==
						CONNMAN_SERVICE_TYPE_VPN &&
						data->vpn_service == service) {
			DBG("Ignoring a VPN service -> unset it");
			set_vpn_service(data, NULL);
		}
		return;
	};

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

		if (clat_is_running(data)) {
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

		if (!clat_is_running(data)) {
			DBG("online, CLAT is not running yet, start it first");
			break;
		}

		goto onlinecheck;
	}

	err = try_clat_start(data);
	if (err && err != -EALREADY) {
		connman_error("CLAT failed to start");
	}

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
	data->tethering = on ? TETHERING_ON : TETHERING_OFF;

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
	} else {
		clat_settings.tayga_bin = g_strdup(DEFAULT_TAYGA_BIN);
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
