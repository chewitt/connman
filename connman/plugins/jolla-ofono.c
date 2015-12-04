/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2015 Jolla Ltd. All rights reserved.
 *  Contact: Slava Monich <slava.monich@jolla.com>
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

#include <gofono_manager.h>
#include <gofono_modem.h>
#include <gofono_netreg.h>
#include <gofono_simmgr.h>
#include <gofono_connmgr.h>
#include <gofono_connctx.h>
#include <gofono_util.h>
#include <gofonoext_mm.h>
#include <gutil_log.h>

#include <errno.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/network.h>
#include <connman/inet.h>
#include <connman/dbus.h>
#include <connman/log.h>
#include <connman/technology.h>

enum mm_handler_id {
	MM_HANDLER_VALID,
	MM_HANDLER_DATA_MODEM,
	MM_HANDLER_COUNT
};

enum manager_handler_id {
	MANAGER_HANDLER_VALID,
	MANAGER_HANDLER_MODEM_ADDED,
	MANAGER_HANDLER_MODEM_REMOVED,
	MANAGER_HANDLER_COUNT
};

enum modem_handler_id {
	MODEM_HANDLER_VALID,
	MODEM_HANDLER_POWERED,
	MODEM_HANDLER_ONLINE,
	MODEM_HANDLER_COUNT
};

enum netreg_handler_id {
	NETREG_HANDLER_VALID,
	NETREG_HANDLER_STATUS,
	NETREG_HANDLER_MCC,
	NETREG_HANDLER_MNC,
	NETREG_HANDLER_STRENGTH,
	NETREG_HANDLER_NAME,
	NETREG_HANDLER_COUNT
};

enum simmgr_handler_id {
	SIMMGR_HANDLER_VALID,
	SIMMGR_HANDLER_IMSI,
	SIMMGR_HANDLER_COUNT
};

enum connmgr_handler_id {
	CONNMGR_HANDLER_VALID,
	CONNMGR_HANDLER_ATTACHED,
	CONNMGR_HANDLER_CONTEXT_ADDED,
	CONNMGR_HANDLER_CONTEXT_REMOVED,
	CONNMGR_HANDLER_COUNT
};

enum connctx_handler_id {
	CONNCTX_HANDLER_VALID,
	CONNCTX_HANDLER_ACTIVE,
	CONNCTX_HANDLER_FAILED,
	CONNCTX_HANDLER_SETTINGS,
	CONNCTX_HANDLER_IPV6_SETTINGS,
	CONNCTX_HANDLER_COUNT
};

struct modem_data {
	OfonoModem *modem;
	OfonoNetReg *netreg;
	OfonoSimMgr *simmgr;
	OfonoConnMgr *connmgr;
	OfonoConnCtx *connctx;
	OfonoExtModemManager* mm;
	gulong modem_handler_id[MODEM_HANDLER_COUNT];
	gulong netreg_handler_id[NETREG_HANDLER_COUNT];
	gulong simmgr_handler_id[SIMMGR_HANDLER_COUNT];
	gulong connmgr_handler_id[CONNMGR_HANDLER_COUNT];
	gulong connctx_handler_id[CONNCTX_HANDLER_COUNT];
	struct connman_device *device;
	struct connman_network *network;
	const char *country;
	gboolean roaming;
	guint strength;
	char *name;
	char *imsi;
};

struct plugin_data {
	OfonoExtModemManager* mm;
	OfonoManager* manager;
	GHashTable *modems;
	gulong mm_handler_id[MM_HANDLER_COUNT];
	gulong manager_handler_id[MANAGER_HANDLER_COUNT];
};

static void connctx_update_active(struct modem_data *data);

static void connctx_cancel_activate_failed_handler(struct modem_data *data)
{
	if (data->connctx_handler_id[CONNCTX_HANDLER_FAILED]) {
		ofono_connctx_remove_handler(data->connctx,
			data->connctx_handler_id[CONNCTX_HANDLER_FAILED]);
		data->connctx_handler_id[CONNCTX_HANDLER_FAILED] = 0;
	}
}

static void connctx_activate_failed(OfonoConnCtx* ctx, const GError* err,
								void* arg)
{
	struct modem_data *data = arg;
	GASSERT(data->connctx_handler_id[CONNCTX_HANDLER_FAILED]);
	connctx_cancel_activate_failed_handler(data);
	if (data->network) {
		connman_network_set_error(data->network,
				CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);
	}
}

static int ofono_network_probe(struct connman_network *network)
{
	struct modem_data *data = connman_network_get_data(network);
	DBG("%s network %p", ofono_modem_path(data->modem), network);
	return 0;
}

static void ofono_network_remove(struct connman_network *network)
{
	struct modem_data *data = connman_network_get_data(network);
	DBG("%s network %p", ofono_modem_path(data->modem), network);
}

static int ofono_network_connect(struct connman_network *network)
{
	struct modem_data *data = connman_network_get_data(network);
	DBG("%s network %p", ofono_modem_path(data->modem), network);
	connctx_cancel_activate_failed_handler(data);
	if (data->connctx) {
		ofono_connctx_activate(data->connctx);
		if (data->connctx->active) {
			return 0;
		} else {
			data->connctx_handler_id[CONNCTX_HANDLER_FAILED] =
				ofono_connctx_add_activate_failed_handler(
					data->connctx, connctx_activate_failed,
					data);
			return (-EINPROGRESS);
		}
	} else {
		return (-ENOSYS);
	}
}

static int ofono_network_disconnect(struct connman_network *network)
{
	struct modem_data *data = connman_network_get_data(network);
	DBG("%s network %p", ofono_modem_path(data->modem), network);
	if (data->connctx) {
		ofono_connctx_deactivate(data->connctx);
		return data->connctx->active ? (-EINPROGRESS) : 0;
	} else {
		return -ENOSYS;
	}
}

static struct connman_network_driver ofono_network_driver = {
	.name           = "cellular",
	.type           = CONNMAN_NETWORK_TYPE_CELLULAR,
	.probe          = ofono_network_probe,
	.remove         = ofono_network_remove,
	.connect        = ofono_network_connect,
	.disconnect     = ofono_network_disconnect,
};

static int ofono_device_probe(struct connman_device *device)
{
	struct modem_data *data = connman_device_get_data(device);
	DBG("%s device %p", ofono_modem_path(data->modem), device);
	return 0;
}

static void ofono_device_remove(struct connman_device *device)
{
	struct modem_data *data = connman_device_get_data(device);
	DBG("%s device %p", ofono_modem_path(data->modem), device);
}

static int ofono_device_enable(struct connman_device *device)
{
	struct modem_data *data = connman_device_get_data(device);
	DBG("%s device %p", ofono_modem_path(data->modem), device);
	ofono_modem_set_online(data->modem, TRUE);
	return 0;
}

static int ofono_device_disable(struct connman_device *device)
{
	struct modem_data *data = connman_device_get_data(device);
	DBG("%s device %p", ofono_modem_path(data->modem), device);
	ofono_modem_set_online(data->modem, FALSE);
	return 0;
}

static struct connman_device_driver ofono_device_driver = {
	.name           = "modem",
	.type           = CONNMAN_DEVICE_TYPE_CELLULAR,
	.probe          = ofono_device_probe,
	.remove         = ofono_device_remove,
	.enable         = ofono_device_enable,
	.disable        = ofono_device_disable,
};

static int ofono_tech_probe(struct connman_technology *technology)
{
	DBG("");
	return 0;
}

static void ofono_tech_remove(struct connman_technology *technology)
{
	DBG("");
}

static struct connman_technology_driver ofono_tech_driver = {
	.name           = "cellular",
	.type           = CONNMAN_SERVICE_TYPE_CELLULAR,
	.probe          = ofono_tech_probe,
	.remove         = ofono_tech_remove,
};

static const char *modem_ident(struct modem_data *data)
{
	const char *path = ofono_connctx_path(data->connctx);
	if (path && path[0] == '/') {
		const char *slash = strrchr(path, '/');
		if (slash) {
			return slash + 1;
		}
	}
	return NULL;
}

static void modem_create_device(struct modem_data *data)
{
	const char *path = ofono_modem_path(data->modem);
	const char *ident;
	char *tmp;

	GASSERT(!data->device);
	if (connman_dbus_validate_ident(data->imsi)) {
		tmp = NULL;
		ident = data->imsi;
	} else {
		tmp = connman_dbus_encode_string(data->imsi);
		ident = tmp;
	}

	data->device = connman_device_create("ofono",
						CONNMAN_DEVICE_TYPE_CELLULAR);

	DBG("%s device %p ident %s", path, data->device, ident);
	connman_device_set_ident(data->device, ident);
	connman_device_set_string(data->device, "Path", path);
	connman_device_set_data(data->device, data);
	connman_device_set_powered(data->device, data->modem->online);
	if (connman_device_register(data->device)) {
		connman_error("Failed to register cellular device");
		connman_device_unref(data->device);
		ofono_modem_set_online(data->modem, FALSE);
		data->device = NULL;
	} else {
		gboolean offline = connman_technology_load_offlinemode();
		ofono_modem_set_online(data->modem, !offline);
	}
	g_free(tmp);
}

static void modem_create_network(struct modem_data *data)
{
	const char *path = ofono_modem_path(data->modem);

	DBG("%s", path);
	GASSERT(data->device);
	GASSERT(!data->network);

	data->network = connman_network_create(path,
					CONNMAN_NETWORK_TYPE_CELLULAR);
	DBG("network %p", data->network);

	connman_network_set_data(data->network, data);
	connman_network_set_name(data->network, data->name ? data->name : "");
	connman_network_set_group(data->network, modem_ident(data));
	connman_network_set_strength(data->network, data->strength);
	connman_network_set_bool(data->network, "Roaming", data->roaming);
	connman_network_set_string(data->network, "Path", path);

	if (connman_device_add_network(data->device, data->network) == 0) {
		connctx_update_active(data);
	} else {
		connman_network_unref(data->network);
		data->network = NULL;
	}
}

static void modem_destroy_network(struct modem_data *data)
{
	if (data->network) {
		connman_device_remove_network(data->device, data->network);
		connman_network_unref(data->network);
		data->network = NULL;
	}
}

static void modem_destroy_device(struct modem_data *data)
{
	if (data->device) {
		DBG("%s", ofono_modem_path(data->modem));
		connman_device_set_powered(data->device, false);
		modem_destroy_network(data);
		connman_device_unregister(data->device);
		connman_device_unref(data->device);
		data->device = NULL;
	}
}

static gboolean modem_can_create_device(struct modem_data *data)
{
	return ofono_modem_valid(data->modem) && data->modem->powered &&
		ofono_simmgr_valid(data->simmgr) && data->imsi &&
		ofono_connmgr_valid(data->connmgr) && data->mm->valid &&
		ofono_modem_equal(data->mm->data_modem, data->modem);
}

static gboolean modem_can_create_network(struct modem_data *data)
{
	return data->device && data->connmgr->attached;
}

static void modem_update_device(struct modem_data *data)
{
	if (modem_can_create_device(data)) {
		if (data->device) {
			connman_device_set_powered(data->device,
							data->modem->online);
		} else {
			modem_create_device(data);
		}
	} else {
		modem_destroy_device(data);
	}
}

static void modem_update_network(struct modem_data *data)
{
	modem_update_device(data);
	if (modem_can_create_network(data)) {
		if (!data->network) {
			modem_create_network(data);
		}
	} else {
		modem_destroy_network(data);
	}
}

static GString *modem_append_strv(GString *str, char* const* strv)
{
	if (strv) {
		while (*strv) {
			const char *s = *strv;
			if (s[0]) {
				if (!str) {
					str = g_string_new(NULL);
				} else if (str->len > 0) {
					g_string_append_c(str, ' ');
				}
				g_string_append(str, s);
			}
			strv++;
		}
	}
	return str;
}

static GString *modem_configure_ipv4(struct connman_network *network,
	const struct ofono_connctx_settings *config, GString *nameservers)
{
	if (config->method == OFONO_CONNCTX_METHOD_STATIC && config->address) {
		struct connman_ipaddress *ipaddr =
			connman_ipaddress_alloc(CONNMAN_IPCONFIG_TYPE_IPV4);
		connman_ipaddress_set_ipv4(ipaddr, config->address,
					config->netmask, config->gateway);
		connman_network_set_ipv4_method(network,
					CONNMAN_IPCONFIG_METHOD_FIXED);
		connman_network_set_ipaddress(network, ipaddr);
		connman_ipaddress_free(ipaddr);
	} else {
		connman_network_set_ipv4_method(network,
					CONNMAN_IPCONFIG_METHOD_DHCP);
	}
	return modem_append_strv(nameservers, config->dns);
}

static GString *modem_configure_ipv6(struct connman_network *network,
	const struct ofono_connctx_settings *config, GString *nameservers)
{
	if (config->method == OFONO_CONNCTX_METHOD_DHCP) {
		connman_network_set_ipv6_method(network,
					CONNMAN_IPCONFIG_METHOD_DHCP);
	} else if (config->address) {
		struct connman_ipaddress *ipaddr =
			connman_ipaddress_alloc(CONNMAN_IPCONFIG_TYPE_IPV6);
		connman_ipaddress_set_ipv6(ipaddr, config->address,
					config->prefix, config->gateway);
		connman_network_set_ipv6_method(network,
					CONNMAN_IPCONFIG_METHOD_FIXED);
		connman_network_set_ipaddress(network, ipaddr);
		connman_ipaddress_free(ipaddr);
	} else {
		connman_network_set_ipv6_method(network,
					CONNMAN_IPCONFIG_METHOD_AUTO);
	}
	return modem_append_strv(nameservers, config->dns);
}

static int modem_configure(struct modem_data *data)
{
	const int index = connman_inet_ifindex(data->connctx->ifname);
	struct connman_service *service =
		connman_service_lookup_from_network(data->network);

	if (index >= 0 && service) {
		GString *nameservers = NULL;

		DBG("%s %d", ofono_modem_path(data->modem), index);

		if (data->connctx->settings) {
			connman_service_create_ip4config(service, index);
			nameservers = modem_configure_ipv4(data->network,
					data->connctx->settings, nameservers);
		} else {
			connman_network_set_ipv4_method(data->network,
					CONNMAN_IPCONFIG_METHOD_DHCP);
		}

		if (data->connctx->ipv6_settings) {
			connman_service_create_ip6config(service, index);
			nameservers = modem_configure_ipv6(data->network,
				data->connctx->ipv6_settings, nameservers);
		} else {
			connman_network_set_ipv6_method(data->network,
					CONNMAN_IPCONFIG_METHOD_AUTO);
		}

		if (nameservers) {
			connman_network_set_nameservers(data->network,
							nameservers->str);
			g_string_free(nameservers, TRUE);
		}
	}

	return index;
}

static void modem_connected(struct modem_data *data)
{
	const int index = modem_configure(data);

	if (index >= 0) {
		connman_network_set_index(data->network, index);
		connman_network_set_connected(data->network, TRUE);
	}
}

static void simmgr_changed(OfonoSimMgr* simmgr, void* arg)
{
	struct modem_data *data = arg;
	GASSERT(data->simmgr == simmgr);
	if (ofono_simmgr_valid(simmgr)) {
		DBG("%s %s", ofono_modem_path(data->modem), simmgr->imsi);
		if (g_strcmp0(simmgr->imsi, data->imsi)) {
			modem_destroy_device(data);
			g_free(data->imsi);
			data->imsi = g_strdup(simmgr->imsi);
		}
	} else {
		DBG("%s invalid", ofono_modem_path(data->modem));
		g_free(data->imsi);
		data->imsi = NULL;
	}
	modem_update_network(data);
}

static void modem_update_roaming(struct modem_data *data)
{
	const gboolean roaming = data->roaming;
	data->roaming = (ofono_netreg_valid(data->netreg) &&
			data->netreg->status == OFONO_NETREG_STATUS_ROAMING);
	if (data->network && data->roaming != roaming) {
		DBG("%d", data->roaming);
		connman_network_set_bool(data->network, "Roaming",
								data->roaming);
		connman_network_update(data->network);
	}
}

static void modem_update_strength(struct modem_data *data)
{
	const guint strength = data->strength;
	data->strength = (ofono_netreg_valid(data->netreg) ?
						data->netreg->strength : 0);
	if (data->network && data->strength != strength) {
		DBG("%u", data->strength);
		connman_network_set_strength(data->network, data->strength);
		connman_network_update(data->network);
	}
}

static void modem_update_name(struct modem_data *data)
{
	const char *name = ofono_netreg_valid(data->netreg) ?
						data->netreg->name : "";
	if (g_strcmp0(data->name, name)) {
		DBG("%s", name);
		g_free(data->name);
		data->name = g_strdup(name);
		if (data->network) {
			connman_network_set_name(data->network, data->name);
		}
	}
}

static void modem_update_country(struct modem_data *data)
{
	const char *country = data->country;
	data->country = ofono_netreg_country(data->netreg);
	if (data->country && g_strcmp0(data->country, country)) {
		DBG("%s", data->country);
		connman_technology_set_regdom(data->country);
	}
}

static void object_valid_changed(OfonoObject* object, void* arg)
{
	modem_update_network(arg);
}

static void modem_valid_changed(OfonoModem* modem, void* arg)
{
	DBG("%s %d", ofono_modem_path(modem), ofono_modem_valid(modem));
	if (ofono_modem_valid(modem)) {
		DBG("%s powered %d online %d", ofono_modem_path(modem),
					modem->powered, modem->online);
		ofono_modem_set_powered(modem, TRUE);
	}
	modem_update_network(arg);
}

static void connctx_update_active(struct modem_data *data)
{
	GASSERT(data->connctx);
	if (ofono_connctx_valid(data->connctx) && data->connctx->active) {
		connctx_cancel_activate_failed_handler(data);
		if (data->network &&
			!connman_network_get_connected(data->network)) {
			modem_connected(data);
		}
	} else if (data->network) {
		connman_network_set_connected(data->network, FALSE);
	}
}

static void connctx_active_changed(OfonoConnCtx* connctx, void* arg)
{
	connctx_update_active(arg);
}

static void connctx_settings_changed(OfonoConnCtx* connctx, void* arg)
{
	modem_configure(arg);
}

static void modem_update_context(struct modem_data *data)
{
	OfonoConnCtx* ctx = ofono_connmgr_get_context_for_type(data->connmgr,
						OFONO_CONNCTX_TYPE_INTERNET);
	const char* old_path = ofono_connctx_path(data->connctx);
	const char* new_path = ofono_connctx_path(ctx);
	if (g_strcmp0(old_path, new_path)) {
		if (data->connctx) {
			modem_destroy_network(data);
			ofono_connctx_remove_handlers(data->connctx,
						data->connctx_handler_id,
						CONNCTX_HANDLER_COUNT);
			ofono_connctx_unref(data->connctx);
		}
		data->connctx = ofono_connctx_ref(ctx);
		if (data->connctx) {
			DBG("%s", ofono_connctx_path(data->connctx));
			data->connctx_handler_id[CONNCTX_HANDLER_VALID] =
				ofono_object_add_valid_changed_handler(
					ofono_connctx_object(data->connctx),
					object_valid_changed, data);
			data->connctx_handler_id[CONNCTX_HANDLER_ACTIVE] =
				ofono_connctx_add_active_changed_handler(
					data->connctx, connctx_active_changed,
					data);
			data->connctx_handler_id[CONNCTX_HANDLER_SETTINGS] =
				ofono_connctx_add_active_changed_handler(
					data->connctx, connctx_settings_changed,
					data);
			data->connctx_handler_id[CONNCTX_HANDLER_IPV6_SETTINGS] =
				ofono_connctx_add_active_changed_handler(
					data->connctx, connctx_settings_changed,
					data);
			connctx_update_active(data);
		} else {
			DBG("no internet context");
		}
	}
	modem_update_network(data);
}

static void connmgr_contexts_changed(OfonoConnMgr* onnmgr,
					OfonoConnCtx* context, void* arg)
{
	modem_update_context(arg);
}

static void modem_changed(OfonoModem* modem, void* arg)
{
	DBG("%s powered %d online %d", ofono_modem_path(modem),
					modem->powered, modem->online);
	modem_update_network(arg);
}

static void netreg_status_changed(OfonoNetReg* netreg, void* arg)
{
	modem_update_roaming(arg);
}

static void netreg_strength_changed(OfonoNetReg* netreg, void* arg)
{
	modem_update_strength(arg);
}

static void netreg_name_changed(OfonoNetReg* netreg, void* arg)
{
	modem_update_name(arg);
}

static void netreg_network_changed(OfonoNetReg* netreg, void* arg)
{
	modem_update_country(arg);
}

static void connmgr_attached_changed(OfonoConnMgr* connmgr, void* arg)
{
	modem_update_network(arg);
}

static void modem_create(struct plugin_data *plugin, OfonoModem *modem)
{
	const char* path = ofono_modem_path(modem);
	struct modem_data *data = g_new0(struct modem_data, 1);

	data->mm = ofonoext_mm_ref(plugin->mm);
	data->modem = ofono_modem_ref(modem);
	data->modem_handler_id[MODEM_HANDLER_VALID] =
		ofono_modem_add_valid_changed_handler(data->modem,
					modem_valid_changed, data);
	data->modem_handler_id[MODEM_HANDLER_POWERED] =
		ofono_modem_add_powered_changed_handler(data->modem,
					modem_changed, data);
	data->modem_handler_id[MODEM_HANDLER_ONLINE] =
		ofono_modem_add_online_changed_handler(data->modem,
					modem_changed, data);

	data->netreg = ofono_netreg_new(path);
	data->netreg_handler_id[NETREG_HANDLER_VALID] =
		ofono_netreg_add_valid_changed_handler(data->netreg,
					netreg_status_changed, data);
	data->netreg_handler_id[NETREG_HANDLER_STATUS] =
		ofono_netreg_add_status_changed_handler(data->netreg,
					netreg_status_changed, data);
	data->netreg_handler_id[NETREG_HANDLER_MCC] =
		ofono_netreg_add_mcc_changed_handler(data->netreg,
					netreg_network_changed, data);
	data->netreg_handler_id[NETREG_HANDLER_MNC] =
		ofono_netreg_add_mnc_changed_handler(data->netreg,
					netreg_network_changed, data);
	data->netreg_handler_id[NETREG_HANDLER_STRENGTH] =
		ofono_netreg_add_strength_changed_handler(data->netreg,
					netreg_strength_changed, data);
	data->netreg_handler_id[NETREG_HANDLER_NAME] =
		ofono_netreg_add_strength_changed_handler(data->netreg,
					netreg_name_changed, data);

	data->simmgr = ofono_simmgr_new(path);
	data->simmgr_handler_id[SIMMGR_HANDLER_VALID] =
		ofono_simmgr_add_valid_changed_handler(data->simmgr,
					simmgr_changed, data);
	data->simmgr_handler_id[SIMMGR_HANDLER_IMSI] =
		ofono_simmgr_add_imsi_changed_handler(data->simmgr,
					simmgr_changed, data);

	data->connmgr = ofono_connmgr_new(path);
	data->connmgr_handler_id[CONNMGR_HANDLER_VALID] =
		ofono_object_add_valid_changed_handler(
			ofono_connmgr_object(data->connmgr),
			object_valid_changed, data);
	data->connmgr_handler_id[CONNMGR_HANDLER_ATTACHED] =
		ofono_connmgr_add_attached_changed_handler(data->connmgr,
					connmgr_attached_changed, data);
	data->connmgr_handler_id[CONNMGR_HANDLER_CONTEXT_ADDED] =
		ofono_connmgr_add_context_added_handler(data->connmgr,
					connmgr_contexts_changed, data);
	data->connmgr_handler_id[CONNMGR_HANDLER_CONTEXT_REMOVED] =
		ofono_connmgr_add_context_removed_handler(data->connmgr,
					connmgr_contexts_changed, data);

	data->imsi = g_strdup(data->simmgr->imsi);
	g_hash_table_replace(plugin->modems, g_strdup(path), data);

	if (ofono_modem_valid(modem)) {
		ofono_modem_set_powered(modem, TRUE);
	}
	modem_update_network(data);
	modem_update_roaming(data);
	modem_update_strength(data);
	modem_update_name(data);
	modem_update_country(data);
}

static void modem_delete(gpointer value)
{
	struct modem_data *data = value;

	DBG("%s", ofono_modem_path(data->modem));
	modem_destroy_device(data);
	ofonoext_mm_unref(data->mm);

	ofono_modem_remove_handlers(data->modem,
			data->modem_handler_id, MODEM_HANDLER_COUNT);
	ofono_modem_unref(data->modem);

	ofono_netreg_remove_handlers(data->netreg,
			data->netreg_handler_id, NETREG_HANDLER_COUNT);
	ofono_netreg_unref(data->netreg);

	ofono_simmgr_remove_handlers(data->simmgr,
			data->simmgr_handler_id, SIMMGR_HANDLER_COUNT);
	ofono_simmgr_unref(data->simmgr);

	ofono_connmgr_remove_handlers(data->connmgr,
			data->connmgr_handler_id, CONNMGR_HANDLER_COUNT);
	ofono_connmgr_unref(data->connmgr);

	if (data->connctx) {
		ofono_connctx_deactivate(data->connctx);
		ofono_connctx_remove_handlers(data->connctx,
			data->connctx_handler_id, CONNCTX_HANDLER_COUNT);
		ofono_connctx_unref(data->connctx);
	}

	g_free(data->name);
	g_free(data->imsi);
	g_free(data);
}

static void manager_valid(struct plugin_data *plugin)
{
	GPtrArray *modems = ofono_manager_get_modems(plugin->manager);
	guint i;

	GASSERT(plugin->manager->object.valid);
	GASSERT(!g_hash_table_size(plugin->modems));

	for (i=0; i<modems->len; i++) {
		OfonoModem *modem = modems->pdata[i];
		DBG("modem %s", modem->object.path);
		modem_create(plugin, modem);
	}

	g_ptr_array_unref(modems);
}

static void manager_valid_changed(OfonoManager *manager, void *arg)
{
	struct plugin_data *plugin = arg;
	DBG("%d", manager->valid);
	GASSERT(plugin->manager == manager);
	if (manager->valid) {
		manager_valid(plugin);
	} else {
		g_hash_table_remove_all(plugin->modems);
	}
}

static void modem_added(OfonoManager *manager, OfonoModem *modem, void *arg)
{
	struct plugin_data *plugin = arg;
	DBG("%s", ofono_modem_path(modem));
	modem_create(plugin, modem);
}

static void modem_removed(OfonoManager *manager, const char *path, void *arg)
{
	struct plugin_data *plugin = arg;
	DBG("%s", path);
	g_hash_table_remove(plugin->modems, path);
}

static void mm_changed(OfonoExtModemManager* mm, void* arg)
{
	GHashTableIter it;
	gpointer value;
	struct plugin_data *plugin = arg;

	DBG("valid %d path %s", plugin->mm->valid,
				ofono_modem_path(plugin->mm->data_modem));

	/* Unregister stale devices first */
	g_hash_table_iter_init(&it, plugin->modems);
	while (g_hash_table_iter_next(&it, NULL, &value)) {
		struct modem_data *data = value;
		if (!modem_can_create_device(data)) {
			modem_destroy_device(data);
		}
	}

	/* Then create new ones if necessary */
	g_hash_table_iter_init(&it, plugin->modems);
	while (g_hash_table_iter_next(&it, NULL, &value)) {
 		modem_update_network(value);
	}
}

static struct plugin_data *ofono_plugin_new(void)
{
	struct plugin_data *plugin = g_new0(struct plugin_data, 1);

	plugin->modems = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, modem_delete);

	plugin->mm = ofonoext_mm_new();
	plugin->mm_handler_id[MM_HANDLER_VALID] =
		ofonoext_mm_add_valid_changed_handler(plugin->mm,
					mm_changed, plugin);
	plugin->mm_handler_id[MM_HANDLER_DATA_MODEM] =
		ofonoext_mm_add_data_modem_changed_handler(plugin->mm,
					mm_changed, plugin);

	plugin->manager = ofono_manager_new();
	plugin->manager_handler_id[MANAGER_HANDLER_VALID] =
		ofono_manager_add_valid_changed_handler(plugin->manager,
					manager_valid_changed, plugin);
	plugin->manager_handler_id[MANAGER_HANDLER_MODEM_ADDED] =
		ofono_manager_add_modem_added_handler(plugin->manager,
					modem_added, plugin);
	plugin->manager_handler_id[MANAGER_HANDLER_MODEM_REMOVED] =
		ofono_manager_add_modem_removed_handler(plugin->manager,
					modem_removed, plugin);

	if (plugin->manager->valid) {
		manager_valid(plugin);
	}
	return plugin;
}

static void ofono_plugin_delete(struct plugin_data *plugin)
{
	if (plugin) {
		g_hash_table_destroy(plugin->modems);
		ofonoext_mm_remove_handlers(plugin->mm,
			plugin->mm_handler_id, MM_HANDLER_COUNT); 
		ofonoext_mm_unref(plugin->mm);
		ofono_manager_remove_handlers(plugin->manager,
			plugin->manager_handler_id, MANAGER_HANDLER_COUNT);
		ofono_manager_unref(plugin->manager);
		g_free(plugin);
	}
 }

static void ofono_plugin_log_notify(struct connman_debug_desc *desc)
{
	if (desc->flags & CONNMAN_DEBUG_FLAG_PRINT) {
		gofono_log.level = gofono_log.max_level;
	} else {
		gofono_log.level = gutil_log_default.level;
	}
	DBG("%s log level %d", gofono_log.name, gofono_log.level);
}

static struct plugin_data* ofono_plugin;

static int jolla_ofono_init(void)
{
	int err;
	static struct connman_debug_desc ofono_debug_desc CONNMAN_DEBUG_ATTR = {
		.name = "libgofono",
		.file = __FILE__,
		.flags = CONNMAN_DEBUG_FLAG_DEFAULT,
		.notify = ofono_plugin_log_notify
	};

	if (ofono_debug_desc.flags & CONNMAN_DEBUG_FLAG_PRINT) {
		gofono_log.level = GLOG_LEVEL_VERBOSE;
	}

	err = connman_network_driver_register(&ofono_network_driver);
	if (!err) {
		err = connman_device_driver_register(&ofono_device_driver);
		if (!err) {
			err = connman_technology_driver_register(
							&ofono_tech_driver);
			if (!err) {
				GASSERT(!ofono_plugin);
				ofono_plugin = ofono_plugin_new();
				DBG("ok");
				return 0;
			}
			connman_device_driver_unregister(&ofono_device_driver);
		}
		connman_network_driver_unregister(&ofono_network_driver);
	}

	DBG("error %d", err);
	return err;
}

static void jolla_ofono_exit(void)
{
	DBG("");
	GASSERT(ofono_plugin);
	ofono_plugin_delete(ofono_plugin);
	ofono_plugin = NULL;

	connman_technology_driver_unregister(&ofono_tech_driver);
	connman_device_driver_unregister(&ofono_device_driver);
	connman_network_driver_unregister(&ofono_network_driver);
}

CONNMAN_PLUGIN_DEFINE(jolla_ofono, "Jolla oFono plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, jolla_ofono_init, jolla_ofono_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
