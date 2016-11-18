/*
 *
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2010-2014  BMW Car IT GmbH.
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/dbus.h>
#include <connman/ipconfig.h>
#include <connman/agent.h>
#include <connman/setting.h>
#include <connman/vpn-dbus.h>

#include "../vpn-provider.h"
#include "../vpn-agent.h"

#include "vpn.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static DBusConnection *connection;

struct {
	const char *cm_opt;
	const char *ov_opt;
	char       has_value;
} ov_options[] = {
	{ "Host", "--remote", 1 },
	{ "OpenVPN.CACert", "--ca", 1 },
	{ "OpenVPN.Cert", "--cert", 1 },
	{ "OpenVPN.Key", "--key", 1 },
	{ "OpenVPN.MTU", "--tun-mtu", 1 },
	{ "OpenVPN.NSCertType", "--ns-cert-type", 1 },
	{ "OpenVPN.Proto", "--proto", 1 },
	{ "OpenVPN.Port", "--port", 1 },
	{ "OpenVPN.AuthUserPass", "--auth-user-pass", 1 },
	{ "OpenVPN.AskPass", "--askpass", 1 },
	{ "OpenVPN.AuthNoCache", "--auth-nocache", 0 },
	{ "OpenVPN.TLSRemote", "--tls-remote", 1 },
	{ "OpenVPN.TLSAuth", NULL, 1 },
	{ "OpenVPN.TLSAuthDir", NULL, 1 },
	{ "OpenVPN.Cipher", "--cipher", 1 },
	{ "OpenVPN.Auth", "--auth", 1 },
	{ "OpenVPN.CompLZO", "--comp-lzo", 0 },
	{ "OpenVPN.RemoteCertTls", "--remote-cert-tls", 1 },
	{ "OpenVPN.ConfigFile", "--config", 1 },
	{ "OpenVPN.DeviceType", NULL, 1 },
	{ "OpenVPN.Verb", "--verb", 1 },
};

struct ov_private_data {
	struct vpn_provider *provider;
	struct connman_task *task;
	char *if_name;
	vpn_provider_connect_cb_t cb;
	void *user_data;
};

static void free_private_data(struct ov_private_data *data)
{
	g_free(data->if_name);
	g_free(data);
}

struct nameserver_entry {
	int id;
	char *nameserver;
};

static struct nameserver_entry *ov_append_dns_entries(const char *key,
						const char *value)
{
	struct nameserver_entry *entry = NULL;
	gchar **options;

	if (!g_str_has_prefix(key, "foreign_option_"))
		return NULL;

	options = g_strsplit(value, " ", 3);
	if (options[0] &&
		!strcmp(options[0], "dhcp-option") &&
			options[1] &&
			!strcmp(options[1], "DNS") &&
				options[2]) {

		entry = g_try_new(struct nameserver_entry, 1);
		if (!entry)
			return NULL;

		entry->nameserver = g_strdup(options[2]);
		entry->id = atoi(key + 15); /* foreign_option_XXX */
	}

	g_strfreev(options);

	return entry;
}

static char *ov_get_domain_name(const char *key, const char *value)
{
	gchar **options;
	char *domain = NULL;

	if (!g_str_has_prefix(key, "foreign_option_"))
		return NULL;

	options = g_strsplit(value, " ", 3);
	if (options[0] &&
		!strcmp(options[0], "dhcp-option") &&
			options[1] &&
			!strcmp(options[1], "DOMAIN") &&
				options[2]) {

		domain = g_strdup(options[2]);
	}

	g_strfreev(options);

	return domain;
}

static gint cmp_ns(gconstpointer a, gconstpointer b)
{
	struct nameserver_entry *entry_a = (struct nameserver_entry *)a;
	struct nameserver_entry *entry_b = (struct nameserver_entry *)b;

	if (entry_a->id < entry_b->id)
		return -1;

	if (entry_a->id > entry_b->id)
		return 1;

	return 0;
}

static void free_ns_entry(gpointer data)
{
	struct nameserver_entry *entry = data;

	g_free(entry->nameserver);
	g_free(entry);
}

static int ov_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	DBusMessageIter iter, dict;
	const char *reason, *key, *value;
	char *address = NULL, *gateway = NULL, *peer = NULL, *netmask = NULL;
	struct connman_ipaddress *ipaddress;
	GSList *nameserver_list = NULL;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

	if (strcmp(reason, "up"))
		return VPN_STATE_DISCONNECT;

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		struct nameserver_entry *ns_entry = NULL;
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("%s = %s", key, value);

		if (!strcmp(key, "trusted_ip"))
			gateway = g_strdup(value);

		if (!strcmp(key, "ifconfig_local"))
			address = g_strdup(value);

		if (!strcmp(key, "ifconfig_netmask"))
			netmask = g_strdup(value);

		if (!strcmp(key, "ifconfig_remote"))
			peer = g_strdup(value);

		if (g_str_has_prefix(key, "route_"))
			vpn_provider_append_route(provider, key, value);

		if ((ns_entry = ov_append_dns_entries(key, value)))
			nameserver_list = g_slist_prepend(nameserver_list,
							ns_entry);
		else {
			char *domain = ov_get_domain_name(key, value);
			if (domain) {
				vpn_provider_set_domain(provider, domain);
				g_free(domain);
			}
		}

		dbus_message_iter_next(&dict);
	}

	ipaddress = connman_ipaddress_alloc(AF_INET);
	if (!ipaddress) {
		g_slist_free_full(nameserver_list, free_ns_entry);
		g_free(address);
		g_free(gateway);
		g_free(peer);
		g_free(netmask);

		return VPN_STATE_FAILURE;
	}

	connman_ipaddress_set_ipv4(ipaddress, address, netmask, gateway);
	connman_ipaddress_set_peer(ipaddress, peer);
	vpn_provider_set_ipaddress(provider, ipaddress);

	if (nameserver_list) {
		char *nameservers = NULL;
		GSList *tmp;

		nameserver_list = g_slist_sort(nameserver_list, cmp_ns);
		for (tmp = nameserver_list; tmp;
						tmp = g_slist_next(tmp)) {
			struct nameserver_entry *ns = tmp->data;

			if (!nameservers) {
				nameservers = g_strdup(ns->nameserver);
			} else {
				char *str;
				str = g_strjoin(" ", nameservers,
						ns->nameserver, NULL);
				g_free(nameservers);
				nameservers = str;
			}
		}

		g_slist_free_full(nameserver_list, free_ns_entry);

		vpn_provider_set_nameservers(provider, nameservers);

		g_free(nameservers);
	}

	g_free(address);
	g_free(gateway);
	g_free(peer);
	g_free(netmask);
	connman_ipaddress_free(ipaddress);

	return VPN_STATE_CONNECT;
}

static int ov_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(ov_options); i++) {
		if (strncmp(ov_options[i].cm_opt, "OpenVPN.", 8) == 0) {
			option = vpn_provider_get_string(provider,
							ov_options[i].cm_opt);
			if (!option)
				continue;

			g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					ov_options[i].cm_opt, option);
		}
	}
	return 0;
}

static int task_append_config_data(struct vpn_provider *provider,
					struct connman_task *task)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(ov_options); i++) {
		if (!ov_options[i].ov_opt)
			continue;

		option = vpn_provider_get_string(provider,
					ov_options[i].cm_opt);
		if (!option)
			continue;

                /* If the AuthUserPass option is "-", provide the input via stdin */
                if (!strcmp(ov_options[i].cm_opt, "OpenVPN.AuthUserPass") && !strcmp(option, "-"))
                        option = NULL;

		if (connman_task_add_argument(task,
				ov_options[i].ov_opt,
				ov_options[i].has_value ? option : NULL) < 0) {
			return -EIO;
		}
	}

	return 0;
}

static int run_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb, void *user_data)
{
	const char *option;
	const char *credentials[2] = { NULL, NULL };
	int stdin_fd, fd;
	int err = 0, i, len;

	option = vpn_provider_get_string(provider, "OpenVPN.AuthUserPass");
	if (option && !strcmp(option, "-")) {
                credentials[0] = vpn_provider_get_string(provider, "OpenVPN.Username");
                credentials[1] = vpn_provider_get_string(provider, "OpenVPN.Password");
        }

	option = vpn_provider_get_string(provider, "OpenVPN.ConfigFile");
	if (!option) {
		/*
		 * Set some default options if user has no config file.
		 */
		option = vpn_provider_get_string(provider, "OpenVPN.TLSAuth");
		if (option) {
			connman_task_add_argument(task, "--tls-auth", option);
			option = vpn_provider_get_string(provider,
							"OpenVPN.TLSAuthDir");
			if (option)
				connman_task_add_argument(task, option, NULL);
		}

		connman_task_add_argument(task, "--nobind", NULL);
		connman_task_add_argument(task, "--persist-key", NULL);
		connman_task_add_argument(task, "--client", NULL);
	}

	connman_task_add_argument(task, "--syslog", NULL);

	connman_task_add_argument(task, "--script-security", "2");

	connman_task_add_argument(task, "--up",
					SCRIPTDIR "/openvpn-script");
	connman_task_add_argument(task, "--up-restart", NULL);

	connman_task_add_argument(task, "--setenv", NULL);
	connman_task_add_argument(task, "CONNMAN_BUSNAME",
					dbus_bus_get_unique_name(connection));

	connman_task_add_argument(task, "--setenv", NULL);
	connman_task_add_argument(task, "CONNMAN_INTERFACE",
					CONNMAN_TASK_INTERFACE);

	connman_task_add_argument(task, "--setenv", NULL);
	connman_task_add_argument(task, "CONNMAN_PATH",
					connman_task_get_path(task));

	connman_task_add_argument(task, "--dev", if_name);
	option = vpn_provider_get_string(provider, "OpenVPN.DeviceType");
	if (option) {
		connman_task_add_argument(task, "--dev-type", option);
	} else {
		/*
		 * Default to tun for backwards compatibility.
		 */
		connman_task_add_argument(task, "--dev-type", "tun");
	}

	connman_task_add_argument(task, "--persist-tun", NULL);

	connman_task_add_argument(task, "--route-noexec", NULL);
	connman_task_add_argument(task, "--ifconfig-noexec", NULL);

	/*
	 * Disable client restarts because we can't handle this at the
	 * moment. The problem is that when OpenVPN decides to switch
	 * from CONNECTED state to RECONNECTING and then to RESOLVE,
	 * it is not possible to do a DNS lookup. The DNS server is
	 * not accessable through the tunnel anymore and so we end up
	 * trying to resolve the OpenVPN servers address.
	 */
	connman_task_add_argument(task, "--ping-restart", "0");

	fd = fileno(stderr);
	err = connman_task_run(task, vpn_died, provider,
			&stdin_fd, &fd, &fd);
	if (err < 0) {
		connman_error("openvpn failed to start");
		err = -EIO;
		goto done;
        }

        if (credentials[0] && credentials[1]) {
                for (i = 0; i < 2; ++i) {
                        len = strlen(credentials[i]);
                        if (write(stdin_fd, credentials[i], len) != (ssize_t)len ||
                                write(stdin_fd, "\n", 1) != 1) {
                                connman_error("openvpn failed to take credentials on stdin");
                                err = -EIO;
                                goto done;
                        }
                }
        }

        close(stdin_fd);

done:
	if (cb)
		cb(provider, user_data, err);

	return err;
}

static void request_input_append_mandatory(DBusMessageIter *iter,
		void *user_data)
{
	char *str = "string";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
}

static void request_input_append_password(DBusMessageIter *iter,
		void *user_data)
{
	char *str = "password";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
}

static void request_input_credentials_reply(DBusMessage *reply, void *user_data)
{
	struct ov_private_data *data = user_data;
	char *password = NULL, *username = NULL;
	char *key;
	DBusMessageIter iter, dict;

	DBG("provider %p", data->provider);

	if (!reply || dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto err;

	if (!vpn_agent_check_reply_has_dict(reply))
		goto err;

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "OpenVPN.Password")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &password);
			vpn_provider_set_string_hide_value(data->provider,
					key, password);

		} else if (g_str_equal(key, "OpenVPN.Username")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &username);
			vpn_provider_set_string_hide_value(data->provider,
					key, username);
		}

		dbus_message_iter_next(&dict);
	}

	if (!password || !username)
		goto err;

	run_connect(data->provider, data->task, data->if_name, data->cb,
		data->user_data);

	free_private_data(data);

	return;

err:
	vpn_provider_indicate_error(data->provider,
			VPN_PROVIDER_ERROR_AUTH_FAILED);

	free_private_data(data);
}

static int request_credentials_input(struct vpn_provider *provider,
				struct ov_private_data *data,
				const char *dbus_sender)
{
	DBusMessage *message;
	const char *path, *agent_sender, *agent_path;
	DBusMessageIter iter;
	DBusMessageIter dict;
	int err;
	void *agent;

	agent = connman_agent_get_info(dbus_sender, &agent_sender,
							&agent_path);
	if (!provider || !agent || !agent_path)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					VPN_AGENT_INTERFACE,
					"RequestInput");
	if (!message)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = vpn_provider_get_path(provider);
	dbus_message_iter_append_basic(&iter,
				DBUS_TYPE_OBJECT_PATH, &path);

	connman_dbus_dict_open(&iter, &dict);

        /* Request temporary properties to pass on to openvpn */
	connman_dbus_dict_append_dict(&dict, "OpenVPN.Username",
			request_input_append_mandatory, NULL);

	connman_dbus_dict_append_dict(&dict, "OpenVPN.Password",
			request_input_append_password, NULL);

	vpn_agent_append_host_and_name(&dict, provider);

	connman_dbus_dict_close(&iter, &dict);

	err = connman_agent_queue_message(provider, message,
			connman_timeout_input_request(),
			request_input_credentials_reply, data, agent);

	if (err < 0 && err != -EBUSY) {
		DBG("error %d sending agent request", err);
		dbus_message_unref(message);

		return err;
	}

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static int ov_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb, const char *dbus_sender,
			void *user_data)
{
	const char *option;
	int err = 0;

	option = vpn_provider_get_string(provider, "Host");
	if (!option) {
		connman_error("Host not set; cannot enable VPN");
		return -EINVAL;
	}

	task_append_config_data(provider, task);

	option = vpn_provider_get_string(provider, "OpenVPN.AuthUserPass");
	if (option && !strcmp(option, "-")) {
                /* Ask user for auth information before proceeding */
		struct ov_private_data *data;

		data = g_try_new0(struct ov_private_data, 1);
		if (!data)
			return -ENOMEM;

		data->provider = provider;
		data->task = task;
		data->if_name = g_strdup(if_name);
		data->cb = cb;
		data->user_data = user_data;

		err = request_credentials_input(provider, data, dbus_sender);
		if (err != -EINPROGRESS) {
			vpn_provider_indicate_error(data->provider,
					VPN_PROVIDER_ERROR_LOGIN_FAILED);
			free_private_data(data);
		}
		return err;
	}

	return run_connect(provider, task, if_name, cb, user_data);
}

static int ov_device_flags(struct vpn_provider *provider)
{
	const char *option;

	option = vpn_provider_get_string(provider, "OpenVPN.DeviceType");
	if (!option) {
		return IFF_TUN;
	}

	if (g_str_equal(option, "tap")) {
		return IFF_TAP;
	}

	if (!g_str_equal(option, "tun")) {
		connman_warn("bad OpenVPN.DeviceType value, falling back to tun");
	}

	return IFF_TUN;
}

static struct vpn_driver vpn_driver = {
	.notify	= ov_notify,
	.connect	= ov_connect,
	.save		= ov_save,
	.device_flags = ov_device_flags,
};

static int openvpn_init(void)
{
	connection = connman_dbus_get_connection();

	return vpn_register("openvpn", &vpn_driver, OPENVPN);
}

static void openvpn_exit(void)
{
	vpn_unregister("openvpn");

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(openvpn, "OpenVPN plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, openvpn_init, openvpn_exit)
