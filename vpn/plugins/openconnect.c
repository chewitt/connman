/*
 *
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2019  Jolla Ltd. All rights reserved.
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
#include <net/if.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/ipconfig.h>
#include <connman/dbus.h>
#include <connman/agent.h>
#include <connman/setting.h>
#include <connman/vpn-dbus.h>

#include <openconnect.h>

#include "../vpn-provider.h"
#include "../vpn-agent.h"

#include "vpn.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define OC_MAX_READBUF_LEN 128

enum opt_type {
	OPT_STRING	= 0,
	OPT_BOOL	= 1,
};

struct {
	const char	*cm_opt;
	const char	*oc_opt;
	bool		has_value;
	bool		enabled; // Use as task parameter
	enum opt_type	type;
} oc_options[] = {
	{ "OpenConnect.AllowSelfSignedCert", NULL, 1, 0, OPT_BOOL},
	{ "OpenConnect.AuthType", NULL, 1, 0, OPT_STRING},
	{ "OpenConnect.CACert", "--cafile", 1, 1, OPT_STRING},
	{ "OpenConnect.ClientCert", NULL, 1, 0, OPT_STRING},
	{ "OpenConnect.DisableIPv6", "--disable-ipv6", 1, 1, OPT_BOOL},
	{ "OpenConnect.PKCSClientCert", NULL, 1, 0, OPT_STRING},
	{ "OpenConnect.Protocol", "--protocol", 1, 1, OPT_STRING},
	/* --no-cert-check is disabled in openconnect 8.02 */
	{ "OpenConnect.NoCertCheck", "--no-cert-check", 0, 0, OPT_BOOL},
	{ "OpenConnect.NoHTTPKeepalive", "--no-http-keepalive", 1, 1, OPT_BOOL},
	{ "OpenConnect.NoDTLS", "--no-dtls", 1, 1, OPT_BOOL},
	{ "OpenConnect.ServerCert", "--servercert", 1, 1, OPT_STRING},
	{ "OpenConnect.Usergroup", "--usergroup", 1, 1, OPT_STRING},
	{ "OpenConnect.UserPrivateKey", NULL, 1, 0, OPT_STRING},
	{ "VPN.MTU", "--base-mtu", 1, 1, OPT_STRING},
};

enum oc_connect_type {
	OC_CONNECT_COOKIE = 0,
	OC_CONNECT_COOKIE_WITH_USERPASS,
	OC_CONNECT_USERPASS,
	OC_CONNECT_PUBLICKEY,
	OC_CONNECT_PKCS,
};

static const char *connect_types[] = {"cookie", "cookie_with_userpass",
			"userpass", "publickey", "pkcs", NULL};

struct oc_private_data {
	struct vpn_provider *provider;
	struct connman_task *task;
	char *if_name;
	char *dbus_sender;
	vpn_provider_connect_cb_t cb;
	void *user_data;

	GThread *cookie_thread;
	struct openconnect_info *vpninfo;
	int fd_cmd;
	int err;

	int fd_in;
	int err_ch_id;
	GIOChannel *err_ch;
	enum oc_connect_type connect_type;
	bool tried_passphrase;
	bool group_set;
};

typedef void (*request_input_reply_cb_t) (DBusMessage *reply,
					void *user_data);

static int run_connect(struct oc_private_data *data, const char *cookie);
static int request_input_credentials_full(
			struct oc_private_data *data,
			request_input_reply_cb_t cb,
			void *user_data);

static bool is_valid_protocol(const char* protocol)
{
	int num_protocols;
	int i;
	struct oc_vpn_proto *protos;

	if (!protocol || !*protocol)
		return false;

	num_protocols = openconnect_get_supported_protocols(&protos);

	for (i = 0; i < num_protocols; i++)
		if (!strcmp(protos[i].name, protocol))
			break;

	openconnect_free_supported_protocols(protos);

	return i < num_protocols;
}

static void oc_connect_done(struct oc_private_data *data, int err)
{
	connman_info("data %p err %d/%s", data, err, strerror(err));

	if (data && data->cb) {
		vpn_provider_connect_cb_t cb = data->cb;
		void *user_data = data->user_data;

		/* Make sure we don't invoke this callback twice */
		data->cb = NULL;
		data->user_data = NULL;
		cb(data->provider, user_data, err);
	}
}

static void close_io_channel(struct oc_private_data *data, GIOChannel *channel)
{
	int id = 0;

	connman_info("data %p channel %p", data, channel);

	if (!data || !channel)
		return;

	if (data->err_ch == channel) {
		id = data->err_ch_id;
		data->err_ch = NULL;
		data->err_ch_id = 0;
	} else {
		return;
	}

	if (id)
		g_source_remove(id);

	g_io_channel_shutdown(channel, FALSE, NULL);
	g_io_channel_unref(channel);
}

static void free_private_data(struct oc_private_data *data)
{
	connman_info("data %p", data);

	if (!data || !data->provider)
		return;

	connman_info("provider %p", data->provider);

	if (data->vpninfo)
		openconnect_vpninfo_free(data->vpninfo);

	if (vpn_provider_get_plugin_data(data->provider) == data)
		vpn_provider_set_plugin_data(data->provider, NULL);

	vpn_provider_unref(data->provider);

	if (data->fd_in > 0)
		close(data->fd_in);
	data->fd_in = -1;
	close_io_channel(data, data->err_ch);

	g_free(data->dbus_sender);
	g_free(data->if_name);
	g_free(data);
}

static int task_append_config_data(struct vpn_provider *provider,
					struct connman_task *task)
{
	const char *option = NULL;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(oc_options); i++) {
		if (!oc_options[i].oc_opt || !oc_options[i].enabled)
			continue;

		if (oc_options[i].has_value) {
			option = vpn_provider_get_string(provider,
						oc_options[i].cm_opt);
			if (!option)
				continue;

			/* Add boolean type values only if set as true. */
			if (oc_options[i].type == OPT_BOOL) {
				if (!vpn_provider_get_boolean(provider,
							oc_options[i].cm_opt,
							false))
					continue;

				/* No option is set for boolean type values. */
				option = NULL;
			}

			/* Skip protocol if it is invalid. */
			if (!g_strcmp0(oc_options[i].cm_opt,
						"OpenConnect.Protocol")) {
				if (!is_valid_protocol(option))
					continue;
			}
		}

		/*
		 * Add server certificate fingerprint only when self signed
		 * certificates are explicitly allowed. Using --servercert as
		 * parameter will accept any server with matching fingerprint,
		 * which would disregard the setting of AllowSelfSignedCert.
		 */
		if (!g_strcmp0(oc_options[i].cm_opt,
					"OpenConnect.ServerCert")) {
			if (!vpn_provider_get_boolean(provider,
					"OpenConnect.AllowSelfSignedCert",
					false))
				continue;
		}

		if (connman_task_add_argument(task,
				oc_options[i].oc_opt,
				oc_options[i].has_value ? option : NULL) < 0)
			return -EIO;
	}

	return 0;
}

static int oc_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	DBusMessageIter iter, dict;
	const char *reason, *key, *value;
	char *domain = NULL;
	char *addressv4 = NULL, *addressv6 = NULL;
	char *netmask = NULL, *gateway = NULL;
	unsigned char prefix_len = 0;
	struct connman_ipaddress *ipaddress;
	struct oc_private_data *data;

	connman_info("provider %p", provider);

	data = vpn_provider_get_plugin_data(provider);

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		oc_connect_done(data, ENOENT);
		return VPN_STATE_FAILURE;
	}

	if (strcmp(reason, "connect"))
		return VPN_STATE_DISCONNECT;

	domain = g_strdup(vpn_provider_get_string(provider, "VPN.Domain"));

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		if (strcmp(key, "CISCO_CSTP_OPTIONS"))
			DBG("%s = %s", key, value);

		if (!strcmp(key, "VPNGATEWAY"))
			gateway = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_ADDRESS"))
			addressv4 = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP6_ADDRESS")) {
			addressv6 = g_strdup(value);
			prefix_len = 128;
		}

		if (!strcmp(key, "INTERNAL_IP4_NETMASK"))
			netmask = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP6_NETMASK")) {
			char *sep;

			/* The netmask contains the address and the prefix */
			sep = strchr(value, '/');
			if (sep) {
				unsigned char ip_len = sep - value;

				addressv6 = g_strndup(value, ip_len);
				prefix_len = (unsigned char)
						strtol(sep + 1, NULL, 10);
			}
		}

		if (!strcmp(key, "INTERNAL_IP4_DNS") ||
				!strcmp(key, "INTERNAL_IP6_DNS"))
			vpn_provider_set_nameservers(provider, value);

		if (!strcmp(key, "CISCO_PROXY_PAC"))
			vpn_provider_set_pac(provider, value);

		if (!domain && !strcmp(key, "CISCO_DEF_DOMAIN")) {
			g_free(domain);
			domain = g_strdup(value);
		}

		if (g_str_has_prefix(key, "CISCO_SPLIT_INC") ||
			g_str_has_prefix(key, "CISCO_IPV6_SPLIT_INC"))
			vpn_provider_append_route(provider, key, value);

		dbus_message_iter_next(&dict);
	}

	DBG("%p %p", addressv4, addressv6);

	if (addressv4)
		ipaddress = connman_ipaddress_alloc(AF_INET);
	else if (addressv6)
		ipaddress = connman_ipaddress_alloc(AF_INET6);
	else
		ipaddress = NULL;

	if (!ipaddress) {
		g_free(addressv4);
		g_free(addressv6);
		g_free(netmask);
		g_free(gateway);
		g_free(domain);

		return VPN_STATE_FAILURE;
	}

	if (addressv4)
		connman_ipaddress_set_ipv4(ipaddress, addressv4,
						netmask, gateway);
	else
		connman_ipaddress_set_ipv6(ipaddress, addressv6,
						prefix_len, gateway);

	connman_ipaddress_set_p2p(ipaddress, true);
	vpn_provider_set_ipaddress(provider, ipaddress);
	vpn_provider_set_domain(provider, domain);

	g_free(addressv4);
	g_free(addressv6);
	g_free(netmask);
	g_free(gateway);
	g_free(domain);
	connman_ipaddress_free(ipaddress);

	oc_connect_done(data, 0);
	return VPN_STATE_CONNECT;
}

static ssize_t full_write(int fd, const char *buf, size_t len)
{
	ssize_t byte_write;

	while (len) {
		byte_write = write(fd, buf, len);
		if (byte_write < 0) {
			connman_error("failed to write config to openconnect: "
					" %s\n", strerror(errno));
			return byte_write;
		}
		len -= byte_write;
		buf += byte_write;
	}

	return len;
}

static ssize_t write_data(int fd, const char *data)
{
	gchar *buf;
	ssize_t len;

	if (!data || !*data)
		return -1;

	buf = g_strdup_printf("%s\n", data);

	len = full_write(fd, buf, strlen(buf));

	g_free(buf);

	return len;
}

static void oc_died(struct connman_task *task, int exit_code, void *user_data)
{
	struct oc_private_data *data = user_data;

	connman_info("task %p data %p exit_code %d user_data %p", task, data,
				exit_code, user_data);

	if (!data)
		return;

	if (data->provider) {
		connman_agent_cancel(data->provider);

		if (task)
			vpn_died(task, exit_code, data->provider);
	}

	free_private_data(data);
}

static bool strv_contains_prefix(const char *strv[], const char *str)
{
	int i;

	if (!strv || !str || !*str)
		return false;

	for (i = 0; strv[i]; i++) {
		if (g_str_has_prefix(str, strv[i]))
			return true;
	}

	return false;
}

static void clear_provider_credentials(struct vpn_provider *provider,
						bool clear_pkcs_pass)
{
	const char *keys[] = { "OpenConnect.PKCSPassword",
				"OpenConnect.Username",
				"OpenConnect.Password",
				"OpenConnect.SecondPassword",
				"OpenConnect.Cookie",
				NULL
	};
	size_t i;

	connman_info("provider %p", provider);

	for (i = !clear_pkcs_pass; keys[i]; i++) {
		if (!vpn_provider_get_string_immutable(provider, keys[i]))
			vpn_provider_set_string_hide_value(provider, keys[i],
						"-");
	}
}

static void __attribute__ ((format(printf, 3, 4))) oc_progress(void *user_data,
		int level, const char *fmt, ...)
{
	va_list ap;
	char *msg;

	va_start(ap, fmt);
	msg = g_strdup_vprintf(fmt, ap);

	connman_debug("%s", msg);
	g_free(msg);

	va_end(ap);
}

/*
 * There is no enum / defines for these in openconnect.h, but these values
 * are based on the comment for openconnect_validate_peer_cert_vfn.
 */
enum oc_cert_status {
	OC_CERT_ACCEPT = 0,
	OC_CERT_REJECT = 1
};

struct validate_cert_data {
	GMutex mutex;
	GCond cond;
	const char *reason;
	struct oc_private_data *data;
	bool processed;
	enum oc_cert_status status;
};

static gboolean validate_cert(void *user_data)
{
	struct validate_cert_data *cert_data = user_data;
	struct oc_private_data *data;
	const char *server_cert;
	bool allow_self_signed;

	DBG("");

	g_mutex_lock(&cert_data->mutex);

	data = cert_data->data;
	server_cert = vpn_provider_get_string(data->provider,
						"OpenConnect.ServerCert");
	allow_self_signed = vpn_provider_get_boolean(data->provider,
					"OpenConnect.AllowSelfSignedCert",
					false);

	if (!allow_self_signed) {
		cert_data->status = OC_CERT_REJECT;
	} else if (server_cert) {
		/*
		 * Check peer cert hash may return negative values on errors,
		 * but anything non-zero is acceptable.
		 */
		cert_data->status = openconnect_check_peer_cert_hash(
								data->vpninfo,
								server_cert);
	} else {
		/*
		 * We could verify this from the agent at this point, and
		 * release the thread upon reply.
		 */
		DBG("Server cert hash: %s",
				openconnect_get_peer_cert_hash(data->vpninfo));
		vpn_provider_set_string(data->provider,
				"OpenConnect.ServerCert",
				openconnect_get_peer_cert_hash(data->vpninfo));
		cert_data->status = OC_CERT_ACCEPT;
	}

	cert_data->processed = true;
	g_cond_signal(&cert_data->cond);
	g_mutex_unlock(&cert_data->mutex);

	return G_SOURCE_REMOVE;
}

static int oc_validate_peer_cert(void *user_data, const char *reason)
{
	struct validate_cert_data data = { .reason = reason,
						.data = user_data,
						.processed = false };

	g_cond_init(&data.cond);
	g_mutex_init(&data.mutex);

	g_mutex_lock(&data.mutex);

	g_idle_add(validate_cert, &data);

	while (!data.processed)
		g_cond_wait(&data.cond, &data.mutex);

	g_mutex_unlock(&data.mutex);

	g_mutex_clear(&data.mutex);
	g_cond_clear(&data.cond);

	return data.status;
}

struct process_form_data {
	GMutex mutex;
	GCond cond;
	struct oc_auth_form *form;
	struct oc_private_data *data;
	bool processed;
	int status;
};

static void request_input_pkcs_reply(DBusMessage *reply, void *user_data)
{
	struct process_form_data *form_data = user_data;
	struct oc_private_data *data = form_data->data;
	struct oc_form_opt *opt;
	const char *key;
	const char *password = NULL;
	DBusMessageIter iter, dict;

	connman_info("provider %p", data->provider);

	if (!reply) {
		data->err = ENOENT;
		goto err;
	}

	if ((data->err = vpn_agent_check_and_process_reply_error(reply,
							data->provider,
							data->task,
							data->cb,
							data->user_data))) {
		data->cb = NULL;
		data->user_data = NULL;
		goto err;
	}

	if (!vpn_agent_check_reply_has_dict(reply)) {
		data->err = ENOENT;
		goto err;
	}

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "OpenConnect.PKCSPassword")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &password);
			vpn_provider_set_string_hide_value(data->provider, key,
						password);
		}

		dbus_message_iter_next(&dict);
	}

	if (!password)
		goto err;

	for (opt = form_data->form->opts; opt; opt = opt->next) {
		if (opt->flags & OC_FORM_OPT_IGNORE)
			continue;

		if (opt->type == OC_FORM_OPT_PASSWORD &&
				g_str_has_prefix(opt->name,
					"openconnect_pkcs")) {
			opt->_value = strdup(password);
			form_data->status = OC_FORM_RESULT_OK;
			data->tried_passphrase = true;
			break;
		}
	}

	goto out;

err:
	form_data->status = OC_FORM_RESULT_ERR;

out:
	form_data->processed = true;
	g_cond_signal(&form_data->cond);
	g_mutex_unlock(&form_data->mutex);
}

static gboolean io_channel_err_cb(GIOChannel *source, GIOCondition condition,
							gpointer user_data)
{
	struct oc_private_data *data;
	const char *auth_failures[] = {
				/* Cookie not valid */
				"Got inappropriate HTTP CONNECT response: "
						"HTTP/1.1 401 Unauthorized",
				/* Invalid cookie */
				"VPN service unavailable",
				NULL
	};
	const char *conn_failures[] = {
				"Failed to connect to",
				"Failed to open HTTPS connection to",
				NULL
	};
	const char *server_key_hash = "    --servercert ";
	char *str;
	int err = 0;

	data = user_data;

	if (!data)
		return G_SOURCE_REMOVE;

	if (source && data->err_ch != source)
		return G_SOURCE_REMOVE;

	if ((condition & G_IO_IN)) {
		gsize len;

		if (g_io_channel_read_line(source, &str, &len, NULL,
					NULL) != G_IO_STATUS_NORMAL)
			err = EIO;
		else
			g_strchomp(str);

		connman_info("openconnect: %s", str);

		if (err || !str || !*str) {
			connman_info("error reading from openconnect");
		} else if (g_str_has_prefix(str, server_key_hash)) {
			const char *fingerprint;
			int position;
			bool allow_self_signed;

			allow_self_signed = vpn_provider_get_boolean(
					data->provider,
					"OpenConnect.AllowSelfSignedCert",
					false);

			if (allow_self_signed) {
				position = strlen(server_key_hash) + 1;
				fingerprint = g_strstrip(str + position);

				connman_info("Set server key hash: \"%s\"",
							fingerprint);

				vpn_provider_set_string(data->provider,
						"OpenConnect.ServerCert",
						str + strlen(server_key_hash));
			} else {
				connman_warn("Self signed certificate is not "
							"allowed");
				err = ECONNREFUSED;
			}
		} else if (strv_contains_prefix(auth_failures, str)) {
			connman_warn("authentication failed: %s", str);
			err = EACCES;
		} else if (strv_contains_prefix(conn_failures, str)) {
			connman_warn("connection failed: %s", str);
			err = ECONNREFUSED;
		}

		g_free(str);
	} else if (condition & (G_IO_ERR | G_IO_HUP)) {
		connman_info("Err channel termination");
		close_io_channel(data, source);
		return G_SOURCE_REMOVE;
	}

	if (err) {
		switch (err) {
		case EACCES:
			clear_provider_credentials(data->provider, true);
			break;
		case ECONNREFUSED:
			/*
			 * This will trigger VPN_PROVIDER_ERROR_CONNECT_FAILED
			 * in vpn-provider.c:connect_cb().
			 */
		default:
			break;
		}

		oc_connect_done(data, err);
	}

	return G_SOURCE_CONTINUE;
}

static gboolean process_auth_form(void *user_data)
{
	struct process_form_data *form_data = user_data;
	struct oc_private_data *data = form_data->data;
	struct oc_form_opt_select *authgroup_opt;
	struct oc_form_opt *opt;
	const char *password;
	const char *group;
	int i;

	g_mutex_lock(&form_data->mutex);

	DBG("");

	/*
	 * Special handling for "GROUP:" field, if present.
	 * Different group selections can make other fields disappear/appear
	 */
	if (form_data->form->authgroup_opt) {
		group = vpn_provider_get_string(data->provider, "OpenConnect.Group");
		authgroup_opt = form_data->form->authgroup_opt;

		if (group && !data->group_set) {
			for (i = 0; i < authgroup_opt->nr_choices; i++) {
				struct oc_choice *choice = authgroup_opt->choices[i];

				if (!strcmp(group, choice->label)) {
					DBG("Switching to auth group: %s", group);
					openconnect_set_option_value(&authgroup_opt->form,
									choice->name);
					data->group_set = true;
					form_data->status = OC_FORM_RESULT_NEWGROUP;
					goto out;
				}
			}

			connman_warn("Group choice %s not present", group);
			data->err = -EACCES;
			clear_provider_credentials(data->provider, true);
			form_data->status = OC_FORM_RESULT_ERR;
			goto out;
		}
	}

	switch (data->connect_type) {
	case OC_CONNECT_USERPASS:
	case OC_CONNECT_COOKIE_WITH_USERPASS:
		break;

	case OC_CONNECT_PKCS:
		password = vpn_provider_get_string(data->provider,
					"OpenConnect.PKCSPassword");

		for (opt = form_data->form->opts; opt; opt = opt->next) {
			if (opt->flags & OC_FORM_OPT_IGNORE)
				continue;

			if (opt->type == OC_FORM_OPT_PASSWORD &&
					g_str_has_prefix(opt->name,
							"openconnect_pkcs"))
				break;
		}

		if (opt) {
			if (password && g_strcmp0(password, "-")) {
				opt->_value = strdup(password);
				data->tried_passphrase = true;
				form_data->status = OC_FORM_RESULT_OK;
				goto out;
			} else {
				if (data->tried_passphrase) {
					vpn_provider_add_error(data->provider,
					       VPN_PROVIDER_ERROR_AUTH_FAILED);
					clear_provider_credentials(
								data->provider,
								true);
				}
				request_input_credentials_full(data,
						request_input_pkcs_reply,
						form_data);
				return G_SOURCE_REMOVE;
			}
		}

		/* fall-through */

	/*
	 * In case of public key, reaching here means that the
	 * passphrase previously provided was incorrect.
	 */
	case OC_CONNECT_PUBLICKEY:
		data->err = -EACCES;
		clear_provider_credentials(data->provider, true);

		/* fall-through */
	default:
		form_data->status = OC_FORM_RESULT_ERR;
		goto out;
	}

	/*
	 * Form values are released with free(), so always use strdup()
	 * instead of g_strdup()
	 */
	for (opt = form_data->form->opts; opt; opt = opt->next) {
		if (opt->flags & OC_FORM_OPT_IGNORE)
			continue;

		if (opt->type == OC_FORM_OPT_TEXT &&
				g_str_has_prefix(opt->name, "user")) {
			const char *user = vpn_provider_get_string(
						data->provider,
						"OpenConnect.Username");
			if (user)
				opt->_value = strdup(user);
		} else if (opt->type == OC_FORM_OPT_PASSWORD &&
				g_str_has_prefix(opt->name, "password")) {

			const char *pass = vpn_provider_get_string(
						data->provider,
						"OpenConnect.Password");
			if (pass)
				opt->_value = strdup(pass);
		} else if (opt->type == OC_FORM_OPT_PASSWORD &&
				g_str_has_prefix(opt->name, "secondary_password")) {
			const char *pass = vpn_provider_get_string(
						data->provider,
						"OpenConnect.SecondPassword");
			if (pass)
				opt->_value = strdup(pass);
		}
	}

	form_data->status = OC_FORM_RESULT_OK;

out:
	form_data->processed = true;
	g_cond_signal(&form_data->cond);
	g_mutex_unlock(&form_data->mutex);

	return G_SOURCE_REMOVE;
}

static int oc_process_auth_form(void *user_data, struct oc_auth_form *form)
{
	struct process_form_data data = { .form = form,
						.data = user_data,
						.processed = false };

	DBG("");

	g_cond_init(&data.cond);
	g_mutex_init(&data.mutex);

	g_mutex_lock(&data.mutex);
	g_idle_add(process_auth_form, &data);

	while (!data.processed)
		g_cond_wait(&data.cond, &data.mutex);

	g_mutex_unlock(&data.mutex);

	g_mutex_clear(&data.mutex);
	g_cond_clear(&data.cond);

	return data.status;
}

static gboolean authenticated(void *user_data)
{
	struct oc_private_data *data = user_data;
	int rv = GPOINTER_TO_INT(g_thread_join(data->cookie_thread));

	DBG("");

	data->cookie_thread = NULL;

	if (rv == 0)
		rv = run_connect(data, openconnect_get_cookie(data->vpninfo));
	else if (rv < 0)
		clear_provider_credentials(data->provider, true);

	openconnect_vpninfo_free(data->vpninfo);
	data->vpninfo = NULL;

	if (rv != -EINPROGRESS) {
		oc_connect_done(data, data->err ? data->err : rv);
		free_private_data(data);
	}

	return G_SOURCE_REMOVE;
}

static void *obtain_cookie_thread(void *user_data)
{
	struct oc_private_data *data = user_data;
	int ret;

	DBG("%p", data->vpninfo);

	ret = openconnect_obtain_cookie(data->vpninfo);

	g_idle_add(authenticated, data);

	return GINT_TO_POINTER(ret);
}

static int authenticate(struct oc_private_data *data)
{
	const char *cert = NULL;
	const char *key = NULL;
	const char *urlpath;
	const char *vpnhost;

	DBG("");

	switch (data->connect_type) {
	case OC_CONNECT_PKCS:
		cert = vpn_provider_get_string(data->provider,
					"OpenConnect.PKCSClientCert");
		break;
	case OC_CONNECT_PUBLICKEY:
		cert = vpn_provider_get_string(data->provider,
					"OpenConnect.ClientCert");
		key = vpn_provider_get_string(data->provider,
					"OpenConnect.UserPrivateKey");
		break;

	case OC_CONNECT_USERPASS:
	case OC_CONNECT_COOKIE_WITH_USERPASS:
		break;

	default:
		return -EINVAL;
	}

	openconnect_init_ssl();
	data->vpninfo = openconnect_vpninfo_new("ConnMan VPN Agent",
			oc_validate_peer_cert,
			NULL,
			oc_process_auth_form,
			oc_progress,
			data);

	/* Replicating how openconnect's --usergroup argument works */
	urlpath = vpn_provider_get_string(data->provider,
						"OpenConnect.Usergroup");
	if (urlpath)
		openconnect_set_urlpath(data->vpninfo, urlpath);

	if (vpn_provider_get_boolean(data->provider,
					"OpenConnect.DisableIPv6", false))
		openconnect_disable_ipv6(data->vpninfo);

	vpnhost = vpn_provider_get_string(data->provider,
						"OpenConnect.VPNHost");
	if (!vpnhost || !*vpnhost)
		vpnhost = vpn_provider_get_string(data->provider, "Host");

	openconnect_set_hostname(data->vpninfo, vpnhost);

	if (cert)
		openconnect_set_client_cert(data->vpninfo, cert, key);

	data->fd_cmd = openconnect_setup_cmd_pipe(data->vpninfo);

	/*
	 * openconnect_obtain_cookie blocks, so run it in background thread
	 * instead
	 */
	data->cookie_thread = g_thread_try_new("obtain_cookie",
							obtain_cookie_thread,
							data, NULL);

	if (!data->cookie_thread)
		return -EIO;

	return -EINPROGRESS;
}

static int run_connect(struct oc_private_data *data, const char *cookie)
{
	struct vpn_provider *provider;
	struct connman_task *task;
	const char *vpnhost;
	int fd_err;
	int err = 0;
	bool allow_self_signed;
	const char *server_cert;

	if (!data || !cookie)
		return -EINVAL;

	provider = data->provider;
	task = data->task;

	server_cert = vpn_provider_get_string(provider,
						"OpenConnect.ServerCert");
	allow_self_signed = vpn_provider_get_boolean(provider,
					"OpenConnect.AllowSelfSignedCert",
					false);

	DBG("provider %p task %p", provider, task);

	connman_task_add_argument(task, "--cookie-on-stdin", NULL);

	vpnhost = vpn_provider_get_string(provider, "OpenConnect.VPNHost");
	if (!vpnhost || !*vpnhost)
		vpnhost = vpn_provider_get_string(provider, "Host");

	task_append_config_data(provider, task);

	connman_task_add_argument(task, "--script", SCRIPTDIR "/vpn-script");

	connman_task_add_argument(task, "--interface", data->if_name);

	connman_task_add_argument(task, (char *)vpnhost, NULL);

	err = connman_task_run(task, oc_died, data, &data->fd_in,
				NULL, &fd_err);
	if (err < 0) {
		err = -EIO;
		goto done;
	}

	if (write_data(data->fd_in, cookie) != 0) {
		connman_error("openconnect failed to take cookie on "
				"stdin");
		err = -EIO;
	}

	if (!server_cert || !allow_self_signed) {
		if (write_data(data->fd_in,
					(allow_self_signed ? "yes" : "no"))) {
			connman_error("openconnect failed to take certificate "
					"acknowledgement on stdin");
			err = -EIO;
		}
	}

	if (err) {
		if (fd_err >= 0)
			close(fd_err);

		goto done;
	}

	err = -EINPROGRESS;

	data->err_ch = g_io_channel_unix_new(fd_err);

	/* Use ASCII encoding only */
	if (g_io_channel_set_encoding(data->err_ch, NULL, NULL) !=
				G_IO_STATUS_NORMAL) {
		close_io_channel(data, data->err_ch);
		err = -EIO;
	} else {
		data->err_ch_id = g_io_add_watch(data->err_ch,
					G_IO_IN | G_IO_ERR | G_IO_HUP,
					(GIOFunc)io_channel_err_cb, data);
	}

done:
	clear_provider_credentials(data->provider, err != -EINPROGRESS);

	return err;
}

static void request_input_append(DBusMessageIter *iter,
		const char *str_type, const char *str, void *user_data)
{
	const char *string;

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str_type);
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);

	if (!user_data)
		return;

	string = user_data;
	connman_dbus_dict_append_basic(iter, "Value", DBUS_TYPE_STRING,
				&string);
}

static void request_input_append_informational(DBusMessageIter *iter,
		void *user_data)
{
	request_input_append(iter, "string", "informational", user_data);
}

static void request_input_append_mandatory(DBusMessageIter *iter,
		void *user_data)
{
	request_input_append(iter, "string", "mandatory", user_data);
}

static void request_input_append_optional(DBusMessageIter *iter,
		void *user_data)
{
	request_input_append(iter, "string", "optional", user_data);
}

static void request_input_append_password(DBusMessageIter *iter,
		void *user_data)
{
	request_input_append(iter, "password", "mandatory", user_data);
}

static void request_input_append_to_dict(struct vpn_provider *provider,
			DBusMessageIter *dict,
			connman_dbus_append_cb_t function_cb, const char *key)
{
	const char *str;
	bool immutable = false;

	if (!provider || !dict || !function_cb || !key)
		return;

	str = vpn_provider_get_string(provider, key);
	/* Ignore empty informational content */
	if (!str && function_cb == request_input_append_informational)
		return;

	/* If value is "-", it is cleared by VPN agent */
	if (!g_strcmp0(str, "-"))
		str = NULL;

	if (str)
		immutable = vpn_provider_get_string_immutable(provider, key);

	if (immutable) {
		/* Hide immutable password types */
		if (function_cb == request_input_append_password)
			str = "********";

		/* Send immutable as informational */
		function_cb = request_input_append_informational;
	}

	connman_dbus_dict_append_dict(dict, key, function_cb,
				str ? (void *)str : NULL);
}

static void request_input_credentials_reply(DBusMessage *reply, void *user_data)
{
	struct oc_private_data *data = user_data;
	const char *cookie = NULL;
	const char *servercert = NULL;
	const char *vpnhost = NULL;
	const char *username = NULL;
	const char *password = NULL;
	const char *second_password = NULL;
	const char *pkcspassword = NULL;
	const char *key;
	DBusMessageIter iter, dict;
	int err;

	connman_info("provider %p", data->provider);

	if (!reply) {
		err = ENOENT;
		goto err;
	}

	err = vpn_agent_check_and_process_reply_error(reply, data->provider,
				data->task, data->cb, data->user_data);
	if (err) {
		/* Ensure cb is called only once */
		data->cb = NULL;
		data->user_data = NULL;
		goto out;
	}

	if (!vpn_agent_check_reply_has_dict(reply)) {
		err = ENOENT;
		goto err;
	}

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "OpenConnect.Cookie")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &cookie);
			vpn_provider_set_string_hide_value(data->provider,
					key, cookie);
		} else if (g_str_equal(key, "OpenConnect.ServerCert")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &servercert);
			vpn_provider_set_string(data->provider, key,
					servercert);

		} else if (g_str_equal(key, "OpenConnect.VPNHost")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &vpnhost);
			vpn_provider_set_string(data->provider, key, vpnhost);
		} else if (g_str_equal(key, "Username")) {
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
					"OpenConnect.Username", username);
		} else if (g_str_equal(key, "Password")) {
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
					"OpenConnect.Password", password);
		} else if (g_str_equal(key, "OpenConnect.SecondPassword")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &second_password);
			vpn_provider_set_string_hide_value(data->provider,
					"OpenConnect.SecondPassword",
					second_password);
		} else if (g_str_equal(key, "OpenConnect.PKCSPassword")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &pkcspassword);
			vpn_provider_set_string_hide_value(data->provider, key,
						pkcspassword);
		}

		dbus_message_iter_next(&dict);
	}

	switch (data->connect_type) {
	case OC_CONNECT_COOKIE:
		if (!cookie) {
			err = EACCES;
			goto err;
		}

		break;
	case OC_CONNECT_USERPASS:
		/* fall through */
	case OC_CONNECT_COOKIE_WITH_USERPASS:
		if (!username || !password) {
			err = EACCES;
			goto err;
		}

		break;
	case OC_CONNECT_PUBLICKEY:
		break; // This should not be reached.
	case OC_CONNECT_PKCS:
		if (!pkcspassword) {
			err = EACCES;
			goto err;
		}

		break;
	}

	if (cookie)
		err = run_connect(data, cookie);
	else
		err = authenticate(data);

	if (err != -EINPROGRESS)
		goto err;

	return;

err:
	oc_connect_done(data, err);

out:
	free_private_data(data);
}

static int request_input_credentials_full(
			struct oc_private_data *data,
			request_input_reply_cb_t cb,
			void *user_data)
{
	DBusMessage *message;
	const char *path;
	const char *agent_sender;
	const char *agent_path;
	const char *username;
	DBusMessageIter iter;
	DBusMessageIter dict;
	int err;
	void *agent;
	bool use_second_password = false;

	if (!data || !cb)
		return -ESRCH;

	connman_info("provider %p", data->provider);

	agent = connman_agent_get_info(data->dbus_sender,
				&agent_sender, &agent_path);
	if (!data->provider || !agent || !agent_path)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					VPN_AGENT_INTERFACE,
					"RequestInput");
	if (!message)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = vpn_provider_get_path(data->provider);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	connman_dbus_dict_open(&iter, &dict);

	request_input_append_to_dict(data->provider, &dict,
				request_input_append_informational,
				"OpenConnect.CACert");

	/*
	 * For backwards compatibility add OpenConnect.ServerCert and
	 * OpenConnect.VPNHost as mandatory only in the default authentication
	 * mode. Otherwise. add the fields as informational. These should be
	 * set in provider settings and not to be queried with every connection
	 * attempt.
	 */
	request_input_append_to_dict(data->provider, &dict,
				data->connect_type == OC_CONNECT_COOKIE ?
				request_input_append_optional :
				request_input_append_informational,
				"OpenConnect.ServerCert");

	request_input_append_to_dict(data->provider, &dict,
				data->connect_type == OC_CONNECT_COOKIE ?
				request_input_append_optional :
				request_input_append_informational,
				"OpenConnect.VPNHost");

	if (vpn_provider_get_authentication_errors(data->provider))
		vpn_agent_append_auth_failure(&dict, data->provider, NULL);

	switch (data->connect_type) {
	case OC_CONNECT_COOKIE:
		request_input_append_to_dict(data->provider, &dict,
					request_input_append_mandatory,
					"OpenConnect.Cookie");
		break;
	/*
	 * The authentication is done with username and password to get the
	 * cookie for connection.
	 */
	case OC_CONNECT_COOKIE_WITH_USERPASS:
		/* fallthrough */
	case OC_CONNECT_USERPASS:
		username = vpn_provider_get_string(data->provider,
					"OpenConnect.Username");
		vpn_agent_append_user_info(&dict, data->provider, username);

		use_second_password = vpn_provider_get_boolean(data->provider,
					"OpenConnect.UseSecondPassword",
					false);

		if (use_second_password)
			request_input_append_to_dict(data->provider, &dict,
					request_input_append_password,
					"OpenConnect.SecondPassword");

		break;
	case OC_CONNECT_PUBLICKEY:
		return -EINVAL;
	case OC_CONNECT_PKCS:
		request_input_append_to_dict(data->provider, &dict,
				request_input_append_informational,
				"OpenConnect.PKCSClientCert");

		/* Do not allow to store or retrieve the encrypted PKCS pass */
		vpn_agent_append_allow_credential_storage(&dict, false);
		vpn_agent_append_allow_credential_retrieval(&dict, false);

		/*
		 * Indicate to keep credentials, the PKCS password should not
		 * affect the credential storing.
		 */
		vpn_agent_append_keep_credentials(&dict, true);

		request_input_append_to_dict(data->provider, &dict,
					request_input_append_password,
					"OpenConnect.PKCSPassword");
		break;
	}

	vpn_agent_append_host_and_name(&dict, data->provider);

	connman_dbus_dict_close(&iter, &dict);

	err = connman_agent_queue_message(data->provider, message,
			connman_timeout_input_request(), cb, user_data, agent);

	dbus_message_unref(message);

	if (err < 0 && err != -EBUSY) {
		connman_error("cannot send agent request, error: %d", err);
		return err;
	}

	return -EINPROGRESS;
}

static int request_input_credentials(struct oc_private_data *data,
			request_input_reply_cb_t cb)
{
	return request_input_credentials_full(data, cb, data);
}

static enum oc_connect_type get_authentication_type(
			struct vpn_provider *provider)
{
	const char *auth;
	enum oc_connect_type type;

	auth = vpn_provider_get_string(provider, "OpenConnect.AuthType");
	if (!auth)
		goto out;

	for (type = 0; connect_types[type]; type++) {
		if (!g_strcmp0(auth, connect_types[type])) {
			connman_info("auth type %d/%s", type,
						connect_types[type]);
			return type;
		}
	}

out:
	/* Default to cookie */
	return OC_CONNECT_COOKIE;
}

static int oc_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb,
			const char *dbus_sender, void *user_data)
{
	struct oc_private_data *data;
	const char *vpncookie = NULL;
	const char *certificate;
	const char *username;
	const char *password;
	const char *second_password = NULL;
	const char *private_key;
	int err;
	bool use_second_password = false;

	connman_info("provider %p task %p", provider, task);

	data = g_try_new0(struct oc_private_data, 1);
	if (!data)
		return -ENOMEM;

	vpn_provider_set_plugin_data(provider, data);
	data->provider = vpn_provider_ref(provider);
	data->task = task;
	data->if_name = g_strdup(if_name);
	data->dbus_sender = g_strdup(dbus_sender);
	data->cb = cb;
	data->user_data = user_data;
	data->connect_type = get_authentication_type(provider);

	switch (data->connect_type) {
	case OC_CONNECT_COOKIE:
		vpncookie = vpn_provider_get_string(provider,
					"OpenConnect.Cookie");
		if (!vpncookie || !g_strcmp0(vpncookie, "-"))
			goto request_input;

		break;
	case OC_CONNECT_USERPASS:
		username = vpn_provider_get_string(provider,
					"OpenConnect.Username");
		password = vpn_provider_get_string(provider,
					"OpenConnect.Password");

		use_second_password = vpn_provider_get_boolean(provider,
					"OpenConnect.UseSecondPassword",
					false);

		if (use_second_password)
			second_password = vpn_provider_get_string(provider,
					"OpenConnect.SecondPassword");

		if (!username || !password || !g_strcmp0(username, "-") ||
					!g_strcmp0(password, "-") ||
					(use_second_password && !second_password))
			goto request_input;

		break;
	case OC_CONNECT_COOKIE_WITH_USERPASS:
		vpncookie = vpn_provider_get_string(provider,
					"OpenConnect.Cookie");
		/* Username and password must be set if cookie is missing */
		if (!vpncookie) {
			username = vpn_provider_get_string(provider,
						"OpenConnect.Username");
			password = vpn_provider_get_string(provider,
						"OpenConnect.Password");

			if (!username || !password ||
						!g_strcmp0(username, "-") ||
						!g_strcmp0(password, "-"))
				goto request_input;
		} else if (!g_strcmp0(vpncookie, "-")) {
			goto request_input;
		}

		break;
	case OC_CONNECT_PUBLICKEY:
		certificate = vpn_provider_get_string(provider,
				"OpenConnect.ClientCert");
		private_key = vpn_provider_get_string(provider,
				"OpenConnect.UserPrivateKey");

		if (!certificate || !private_key) {
			connman_warn("missing certificate and/or private key");
			oc_connect_done(data, EACCES);
			free_private_data(data);
			return -EACCES;
		}

		break;
	case OC_CONNECT_PKCS:
		certificate = vpn_provider_get_string(provider,
					"OpenConnect.PKCSClientCert");
		if (!certificate) {
			connman_warn("missing PKCS certificate");
			oc_connect_done(data, EACCES);
			free_private_data(data);
			return -EACCES;
		}

		break;
	}

	if (vpncookie && g_strcmp0(vpncookie, "-"))
		return run_connect(data, vpncookie);
	return authenticate(data);

request_input:
	err = request_input_credentials(data, request_input_credentials_reply);
	if (err != -EINPROGRESS) {
		oc_connect_done(data, err);
		vpn_provider_indicate_error(data->provider,
					VPN_PROVIDER_ERROR_LOGIN_FAILED);
		free_private_data(data);
	}

	return err;
}

static void oc_disconnect(struct vpn_provider *provider)
{
	struct oc_private_data *data;

	connman_info("provider %p", provider);

	if (!provider)
		return;

	/*
	* OpenConnect may be disconnect by timeout in connmand before running
	* the openconnect process. In such case it is important to cancel the
	* agent request to avoid having multiple ones visible.
	*/
	connman_agent_cancel(provider);

	data = vpn_provider_get_plugin_data(provider);

	if (!data)
		return;

	if (data->cookie_thread) {
		char cmd = OC_CMD_CANCEL;
		int w = write(data->fd_cmd, &cmd, 1);
		if (w != 1)
			DBG("Write failed, might be leaking a thread");
	}

}

static int oc_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *save_group;
	const char *option;
	int i;

	save_group = vpn_provider_get_save_group(provider);

	for (i = 0; i < (int)ARRAY_SIZE(oc_options); i++) {
		if (strncmp(oc_options[i].cm_opt, "OpenConnect.", 12) == 0) {
			option = vpn_provider_get_string(provider,
							oc_options[i].cm_opt);
			if (!option)
				continue;

			g_key_file_set_string(keyfile, save_group,
					oc_options[i].cm_opt, option);
		}
	}

	return 0;
}

static int oc_error_code(struct vpn_provider *provider, int exit_code)
{
	connman_info("%d", exit_code);

	/* OpenConnect process return values are ambiguous in definition
	 * https://github.com/openconnect/openconnect/blob/master/main.c#L1693
	 * and it is safer not to rely on them. Login error cannot be
	 * differentiated from connection errors, e.g., when self signed
	 * certificate is rejected by user setting.
	 */

	switch (exit_code) {
	case 2:
		/* Cookie has failed */
		clear_provider_credentials(provider, false);
		return VPN_PROVIDER_ERROR_LOGIN_FAILED;
	case 1:
		/* fall through */
	default:
		return VPN_PROVIDER_ERROR_UNKNOWN;
	}
}

static int oc_route_env_parse(struct vpn_provider *provider, const char *key,
		int *family, unsigned long *idx,
		enum vpn_provider_route_type *type)
{
	char *end;
	const char *start;

	if (g_str_has_prefix(key, "CISCO_SPLIT_INC_")) {
		*family = AF_INET;
		start = key + strlen("CISCO_SPLIT_INC_");
	} else if (g_str_has_prefix(key, "CISCO_IPV6_SPLIT_INC_")) {
		*family = AF_INET6;
		start = key + strlen("CISCO_IPV6_SPLIT_INC_");
	} else
		return -EINVAL;

	*idx = g_ascii_strtoull(start, &end, 10);

	if (strncmp(end, "_ADDR", 5) == 0)
		*type = VPN_PROVIDER_ROUTE_TYPE_ADDR;
	else if (strncmp(end, "_MASK", 5) == 0)
		*type = VPN_PROVIDER_ROUTE_TYPE_MASK;
	else if (strncmp(end, "_MASKLEN", 8) == 0 && *family == AF_INET6)
		*type = VPN_PROVIDER_ROUTE_TYPE_MASK;
	else
		return -EINVAL;

	return 0;
}

static struct vpn_driver vpn_driver = {
	.notify         = oc_notify,
	.connect	= oc_connect,
	.disconnect	= oc_disconnect,
	.error_code	= oc_error_code,
	.save		= oc_save,
	.route_env_parse = oc_route_env_parse,
};

static int openconnect_init(void)
{
	return vpn_register("openconnect", &vpn_driver, OPENCONNECT);
}

static void openconnect_exit(void)
{
	vpn_unregister("openconnect");
}

CONNMAN_PLUGIN_DEFINE(openconnect, "OpenConnect VPN plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, openconnect_init, openconnect_exit)
