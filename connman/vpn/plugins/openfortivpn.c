/*
 *
 * ConnMan VPN daemon
 *
 * Copyright (C) 2019-2021  Jolla Ltd.
 * Copyright (C) 2019-2020  Open Mobile Platform LLC.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

/* This plugin is based on existing L2TP and OpenConnect VPN plugins. */

#include <dbus/dbus.h>
#include <errno.h>
#include <glib.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <sys/socket.h>

#include <connman/log.h>	// Connman logging functions
#include <connman/plugin.h>	// Connman plugin registration
#include <connman/task.h>	// Connman binary execution

#include <connman/dbus.h>
#include <connman/vpn-dbus.h> // VPN_AGENT_INTERFACE

#include <connman/agent.h>
#include <connman/ipaddress.h>
#include <connman/setting.h>

#include <pppd/pathnames.h> // _PATH_PEERFILES

#include "../vpn-provider.h"
#include "../vpn-agent.h"

#include "vpn.h"
#include "../vpn.h"

#define PLUGIN_NAME "openfortivpn"
static DBusConnection *connection;

/* From openconnect.c */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

enum opt_type {
	OPT_STRING	= 0,
	OPT_BOOL	= 1,
};

struct {
	const char	*cm_opt;
	const char	*ofv_opt;
	bool		has_value;
	bool		enabled;
	enum opt_type	type;
} ofv_options[] = {
	{ "openfortivpn.AllowSelfSignedCert", "--trust-all-certs", 0, 1,
								OPT_BOOL},
	{ "openfortivpn.TrustedCert", "--trusted-cert", 1, 1, OPT_STRING},
	{ "openfortivpn.Port", NULL, 1, 0, OPT_STRING},
	{ "PPPD.NoIPv6", "--pppd-noipv6", 0, 1, OPT_BOOL },
};

#define ROUTE_NETWORK_KEY_PREFIX "route_network_"
#define ROUTE_NETMASK_KEY_PREFIX "route_netmask_"
#define ROUTE_GATEWAY_KEY_PREFIX "route_gateway_"

struct ofv_private_data {
	struct vpn_provider *provider;
	struct connman_task *task;
	char *if_name;
	vpn_provider_connect_cb_t cb;
	void *user_data;
};

static void ofv_connect_done(struct ofv_private_data *data, int err)
{
	vpn_provider_connect_cb_t cb;
	void *user_data;

	if (!data || !data->cb)
		return;

	/* Ensure that callback is called only once */
	cb = data->cb;
	user_data = data->user_data;
	data->cb = NULL;
	data->user_data = NULL;
	cb(data->provider, user_data, err);
}

static void free_private_data(struct ofv_private_data *data)
{
	if (vpn_provider_get_plugin_data(data->provider) == data)
		vpn_provider_set_plugin_data(data->provider, NULL);

	ofv_connect_done(data, EIO);
	vpn_provider_unref(data->provider);
	g_free(data->if_name);
	g_free(data);
}


static DBusMessage *ofv_get_sec(struct connman_task *task, DBusMessage *msg,
							void *user_data)
{
	const char *user;
	const char *passwd;
	struct vpn_provider *provider = user_data;

	if (dbus_message_get_no_reply(msg))
		return NULL;

	DBusMessage *reply;

	user = vpn_provider_get_string(provider, "openfortivpn.User");
	passwd = vpn_provider_get_string(provider, "openfortivpn.Password");

	if (!user || !*user || !passwd || !*passwd)
		return NULL;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &user,
				DBUS_TYPE_STRING, &passwd, DBUS_TYPE_INVALID);

	return reply;
}

static void ofv_died(struct connman_task *task, int exit_code, void *user_data)
{
	struct ofv_private_data *data = user_data;

	DBG("task %p, code %d, data %p", task, exit_code, user_data);
	vpn_died(task, exit_code, user_data);
	free_private_data(data);
}

struct request_input_reply {
	struct vpn_provider *provider;
	vpn_provider_password_cb_t callback;
	void *user_data;
};

static void request_input_reply(DBusMessage *reply, void *user_data)
{
	struct request_input_reply *ofv_reply = user_data;
	struct ofv_private_data *data = NULL;
	const char *error = NULL;
	char *username = NULL;
	char *password = NULL;
	char *key;
	DBusMessageIter iter;
	DBusMessageIter dict;
	int err;

	DBG("provider %p", ofv_reply->provider);

	if (!reply)
		goto done;

	data = ofv_reply->user_data;

	err = vpn_agent_check_and_process_reply_error(
				reply, ofv_reply->provider, data->task,
				data->cb, data->user_data);
	if (err) {
		/* Ensure cb is called only once */
		data->cb = NULL;
		data->user_data = NULL;
		error = dbus_message_get_error_name(reply);
		goto done;
	}

	if (!vpn_agent_check_reply_has_dict(reply))
		goto done;

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *str;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "Username")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry) !=
						DBUS_TYPE_VARIANT)
				break;

			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value) !=
						DBUS_TYPE_STRING)
				break;

			dbus_message_iter_get_basic(&value, &str);
			username = g_strdup(str);
		}

		if (g_str_equal(key, "Password")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry) !=
						DBUS_TYPE_VARIANT)
				break;

			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value) !=
						DBUS_TYPE_STRING)
				break;

			dbus_message_iter_get_basic(&value, &str);
			password = g_strdup(str);
		}

		dbus_message_iter_next(&dict);
	}

done:
	ofv_reply->callback(ofv_reply->provider, username, password, error,
				ofv_reply->user_data);

	g_free(username);
	g_free(password);

	g_free(ofv_reply);
}

typedef void (*request_cb_t)(struct vpn_provider *provider,
			const char *username, const char *password,
			const char *error, void *user_data);

static int request_input(struct vpn_provider *provider, request_cb_t callback,
			 const char *dbus_sender, void *user_data)
{
	DBusMessage *message;
	const char *path;
	const char *agent_sender;
	const char *agent_path;
	DBusMessageIter iter;
	DBusMessageIter dict;
	struct request_input_reply *ofv_reply;
	int err;
	void *agent;

	agent = connman_agent_get_info(dbus_sender, &agent_sender, &agent_path);
	if (!provider || !agent || !agent_path || !callback)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
				VPN_AGENT_INTERFACE, "RequestInput");
	if (!message)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = vpn_provider_get_path(provider);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	connman_dbus_dict_open(&iter, &dict);

	if (vpn_provider_get_authentication_errors(provider))
		vpn_agent_append_auth_failure(&dict, provider, NULL);

	vpn_agent_append_user_info(&dict, provider, "openfortivpn.User");

	vpn_agent_append_host_and_name(&dict, provider);

	connman_dbus_dict_close(&iter, &dict);

	ofv_reply = g_new0(struct request_input_reply, 1);
	ofv_reply->provider = provider;
	ofv_reply->callback = callback;
	ofv_reply->user_data = user_data;

	err = connman_agent_queue_message(provider, message,
				connman_timeout_input_request(),
				request_input_reply, ofv_reply, agent);
	dbus_message_unref(message);

	if (err < 0 && err != -EBUSY) {
		DBG("error %d sending agent request", err);
		g_free(ofv_reply);
		return err;
	}

	return -EINPROGRESS;
}

/* From openconnect.c */
static int task_append_config_data(struct vpn_provider *provider,
					struct connman_task *task)
{
	const char *value = NULL;
	bool no_ipv6 = false;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(ofv_options); i++) {
		if (!ofv_options[i].ofv_opt || !ofv_options[i].enabled)
			continue;

		if (ofv_options[i].has_value) {
			char *opt;

			value = vpn_provider_get_string(provider,
						ofv_options[i].cm_opt);
			if (!value)
				continue;
				
			opt = g_strconcat(ofv_options[i].ofv_opt, "=", value,
						NULL);

			connman_task_add_argument(task, opt, NULL);
			g_free(opt);
		}

		/* Add boolean type values only if set as true. */
		if (ofv_options[i].type == OPT_BOOL) {
			if (!vpn_provider_get_boolean(provider,
						ofv_options[i].cm_opt, false))
				continue;

			if (!g_strcmp0(ofv_options[i].cm_opt, "PPPD.NoIPv6"))
				no_ipv6 = true;
			else
				connman_task_add_argument(task,
							ofv_options[i].ofv_opt,
							NULL);
		}
	}

	vpn_provider_set_supported_ip_networks(provider, true, !no_ipv6);

	return 0;
}

static int run_connect(struct ofv_private_data *data, const char *username,
							const char *password)
{
	struct vpn_provider *provider = data->provider;
	struct connman_task *task = data->task;
	const char *host;
	const char *port;
	char *gateway;
	char *initial_args = NULL;
	char *peer_file;
	char *esc_user;
	char *esc_pass;
	char *plugin;
	int err;

	if (!username || !*username || !password || !*password) {
		DBG("Cannot connect username %s password %p", username,
					password);
		err = -EINVAL;
		goto done;
	}

	DBG("username %s password %p", username, password);

	peer_file = g_strconcat(_PATH_PEERFILES, PLUGIN_NAME, NULL);
	if (g_file_test(peer_file, G_FILE_TEST_EXISTS) &&
			g_file_test(peer_file, G_FILE_TEST_IS_REGULAR)) {
		initial_args = g_strdup_printf("--pppd-call=%s", PLUGIN_NAME);
		connman_task_add_argument(task, initial_args, NULL);
	}

	connman_task_add_argument(task, "-vvv", NULL);

	task_append_config_data(provider, task);

	esc_user = g_strdup_printf("--username=%s", username);
	connman_task_add_argument(task, esc_user, NULL);

	esc_pass = g_strdup_printf("--password=%s", password);
	connman_task_add_argument(task, esc_pass, NULL);

	host = vpn_provider_get_string(provider, "Host");
	port = vpn_provider_get_string(provider, "openfortivpn.Port");
	DBG("host %s port %p", host, port);

	if (!port || !*port) {
		/* openfortivpn defaults to using 10443 if port is omitted */
		gateway = g_strdup(host);
	} else {
		gateway = g_strconcat(host, ":", port, NULL);
	}

	DBG("gateway %s", gateway);

	connman_task_add_argument(task, gateway, NULL);

	plugin = g_strconcat("--pppd-plugin=", SCRIPTDIR, "/libppp-plugin.so",
				NULL);
	connman_task_add_argument(task, plugin, NULL);

	g_free(peer_file);
	g_free(initial_args);
	g_free(gateway);
	g_free(esc_user);
	g_free(esc_pass);
	g_free(plugin);

	err = connman_task_run(task, ofv_died, data, NULL, NULL, NULL);
	if (err < 0) {
		connman_error("ofv failed to start");
		err = -EIO;
	}

done:
	if (err)
		ofv_connect_done(data, -err);

	return err;
}

static void request_input_cb(struct vpn_provider *provider,
			const char *username, const char *password,
			const char *error, void *user_data)
{
	struct ofv_private_data *data = user_data;

	if (!username || !*username || !password || !*password)
		DBG("Requesting username %s or password failed, error %s",
					username, error);
	else if (error)
		DBG("error %s", error);

	vpn_provider_set_string(provider, "openfortivpn.User", username);
	vpn_provider_set_string_hide_value(provider, "openfortivpn.Password",
				password);

	run_connect(data, username, password);
}

static int ofv_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *reason;
	const char *key;
	const char *value;
	char *addressv4 = NULL;
	char *netmask = NULL;
	char *gateway = NULL;
	char *ifname = NULL;
	char *nameservers = NULL;
	struct connman_ipaddress *ipaddress = NULL;
	struct ofv_private_data *data;

	DBG("provider %p", provider);

	data = vpn_provider_get_plugin_data(provider);

	vpn_provider_set_string(provider, "DefaultRoute", "false");

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

	if (strcmp(reason, "auth failed") == 0) {
		DBG("authentication failure");

		vpn_provider_set_string(provider, "openfortivpn.User", NULL);
		vpn_provider_set_string_hide_value(provider,
					"openfortivpn.Password", NULL);

		ofv_connect_done(data, EACCES);
		return VPN_STATE_AUTH_FAILURE;
	}

	if (strcmp(reason, "connect")) {
		ofv_connect_done(data, EIO);

		/*
		 * Stop the task to avoid potential looping of this state when
		 * authentication fails.
		 */
		if (data && data->task)
			connman_task_stop(data->task);

		return VPN_STATE_DISCONNECT;
	}

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("%s = %s", key, value);

		if (!strcmp(key, "INTERNAL_IP4_ADDRESS"))
			addressv4 = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_NETMASK"))
			netmask = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_DNS"))
			nameservers = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IFNAME"))
			ifname = g_strdup(value);

		dbus_message_iter_next(&dict);
	}

	if (vpn_set_ifname(provider, ifname) < 0) {
		g_free(ifname);
		g_free(addressv4);
		g_free(netmask);
		g_free(nameservers);
		return VPN_STATE_FAILURE;
	}

	if (addressv4)
		ipaddress = connman_ipaddress_alloc(AF_INET);

	g_free(ifname);

	if (!ipaddress) {
		connman_error("No IP address for provider");
		g_free(addressv4);
		g_free(netmask);
		g_free(nameservers);
		return VPN_STATE_FAILURE;
	}

	value = vpn_provider_get_string(provider, "HostIP");
	if (value) {
		vpn_provider_set_string(provider, "Gateway", value);
		gateway = g_strdup(value);
	}

	if (addressv4)
		connman_ipaddress_set_ipv4(ipaddress, addressv4, netmask,
					gateway);

	connman_ipaddress_set_p2p(ipaddress, true);
	vpn_provider_set_ipaddress(provider, ipaddress);
	vpn_provider_set_nameservers(provider, nameservers);

	g_free(addressv4);
	g_free(netmask);
	g_free(gateway);
	g_free(nameservers);
	connman_ipaddress_free(ipaddress);

	ofv_connect_done(data, 0);
	return VPN_STATE_CONNECT;
}

static int ofv_connect(struct vpn_provider *provider, struct connman_task *task,
			const char *if_name, vpn_provider_connect_cb_t cb,
			const char *dbus_sender, void *user_data)
{
	struct ofv_private_data *data;
	const char *username;
	const char *password;
	int err = -ENETUNREACH;

	DBG("provider %p", provider);

	data = g_try_new0(struct ofv_private_data, 1);
	data->provider = vpn_provider_ref(provider);
	data->task = task;
	data->if_name = g_strdup(if_name);
	data->cb = cb;
	data->user_data = user_data;
	vpn_provider_set_plugin_data(provider, data);

	if (connman_task_set_notify(task, "getsec", ofv_get_sec, provider)
				!= 0) {
		err = -ENOMEM;
		goto error;
	}

	username = vpn_provider_get_string(provider, "openfortivpn.User");
	password = vpn_provider_get_string(provider, "openfortivpn.Password");

	if (!username || !*username || !password || !*password) {
		err = request_input(provider, request_input_cb, dbus_sender,
					data);
		if (err != -EINPROGRESS)
			goto error;

		return err;
	}

	return run_connect(data, username, password);

error:
	ofv_connect_done(data, -err);
	free_private_data(data);

	return err;
}

static void ofv_disconnect(struct vpn_provider *provider)
{
	DBG("provider %p", provider);

	if (!provider)
		return;

	/*
	 * Cancelling the agent request
	 * to avoid having multiple ones visible in case of timeout.
	 */
	connman_agent_cancel(provider);

	vpn_provider_set_string_hide_value(provider, "openfortivpn.Password",
				NULL);
}

static int ofv_error_code(struct vpn_provider *provider, int exit_code)
{
	DBG("provider %p exit %d", provider, exit_code);

	return exit_code;
}

static int ofv_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *save_group;
	const char *option;
	int i;

	DBG("provider %p", provider);

	save_group = vpn_provider_get_save_group(provider);

	for (i = 0; i < (int)ARRAY_SIZE(ofv_options); i++) {
			option = vpn_provider_get_string(provider,
							ofv_options[i].cm_opt);
			if (!option)
				continue;

			g_key_file_set_string(keyfile, save_group,
					ofv_options[i].cm_opt, option);
	}

	return 0;
}

static int ofv_device_flags(struct vpn_provider *provider)
{
	DBG("provider %p", provider);
	return IFF_TUN;
}

static int ofv_route_env_parse(struct vpn_provider *provider, const char *key,
			int *family, unsigned long *idx,
			enum vpn_provider_route_type *type)
{
	char *end = NULL;
	const char *start;

	DBG("provider %p", provider);

	if (g_str_has_prefix(key, ROUTE_NETWORK_KEY_PREFIX)) {
		start = key + strlen(ROUTE_NETWORK_KEY_PREFIX);
		*type = VPN_PROVIDER_ROUTE_TYPE_ADDR;
	} else if (g_str_has_prefix(key, ROUTE_NETMASK_KEY_PREFIX)) {
		start = key + strlen(ROUTE_NETMASK_KEY_PREFIX);
		*type = VPN_PROVIDER_ROUTE_TYPE_MASK;
	} else if (g_str_has_prefix(key, ROUTE_GATEWAY_KEY_PREFIX)) {
		start = key + strlen(ROUTE_GATEWAY_KEY_PREFIX);
		*type = VPN_PROVIDER_ROUTE_TYPE_GW;
	} else
		return -EINVAL;

	*family = AF_INET;
	*idx = g_ascii_strtoull(start, &end, 10);
	if (!end) {
		return errno;
	}

	return 0;
}

static const struct vpn_driver vpn_driver = {
	.notify = ofv_notify,
	.connect = ofv_connect,
	.disconnect = ofv_disconnect,
	.error_code = ofv_error_code,
	.save = ofv_save,
	.device_flags = ofv_device_flags,
	.route_env_parse = ofv_route_env_parse,
};

static int openfortivpn_init(void)
{
	connection = connman_dbus_get_connection();
	return vpn_register(PLUGIN_NAME, &vpn_driver, OPENFORTIVPN);
}

static void openfortivpn_exit(void)
{
	vpn_unregister(PLUGIN_NAME);
	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(openfortivpn, "VPN plugin openfortivpn", CONNMAN_VERSION,
			CONNMAN_PLUGIN_PRIORITY_DEFAULT, openfortivpn_init,
			openfortivpn_exit)
