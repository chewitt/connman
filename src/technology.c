/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2014-2020  Jolla Ltd. All rights reserved.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
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
#include <string.h>

#include <gdbus.h>

#include "connman.h"

#define DELAYED_TIMEOUT 300

static DBusConnection *connection;

static GSList *technology_list = NULL;

/*
 * List of devices with no technology associated with them either because of
 * no compiled in support or the driver is not yet loaded.
*/
static GSList *techless_device_list = NULL;
static GHashTable *rfkill_list;

static bool global_offlinemode;
static unsigned int global_offlinemode_override; /* Technology bitmask */
struct connman_access_tech_policy *tech_access_policy;
static unsigned int enable_delayed_ids[MAX_CONNMAN_SERVICE_TYPES] = { 0 };

static char *global_regdom = NULL;

struct connman_rfkill {
	unsigned int index;
	enum connman_service_type type;
	bool softblock;
	bool hardblock;
};

struct connman_technology {
	int refcount;
	enum connman_service_type type;
	char *path;
	GSList *device_list;
	bool enabled;
	char *regdom;
	bool connected;

	bool tethering;
	bool tethering_persistent; /* Tells the save status, needed
					      * as offline mode might set
					      * tethering OFF.
					      */
	char *tethering_ident;
	char *tethering_passphrase;

	bool enable_persistent; /* Save the tech state */

	GSList *driver_list;

	DBusMessage *pending_reply;
	guint pending_timeout;

	GSList *scan_pending;

	bool rfkill_driven;
	bool softblocked;
	bool hardblocked;
	bool dbus_registered;
};

static GSList *driver_list = NULL;

static int technology_enabled(struct connman_technology *technology);
static int technology_disabled(struct connman_technology *technology);

static struct connman_access_tech_policy *get_tech_access_policy()
{
	/* We can't initialize this variable in __connman_technology_init
	 * because __connman_technology_init runs before sailfish access
	 * plugin (or any other plugin) is loaded */
	if (!tech_access_policy) {
		/* Use the default policy */
		tech_access_policy = __connman_access_tech_policy_create(NULL);
	}
	return tech_access_policy;
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_technology_driver *driver1 = a;
	const struct connman_technology_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

static void rfkill_check(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_rfkill *rfkill = value;
	enum connman_service_type type = GPOINTER_TO_INT(user_data);

	/* Calling _technology_add_rfkill will update the tech. */
	if (rfkill->type == type)
		__connman_technology_add_rfkill(rfkill->index, type,
				rfkill->softblock, rfkill->hardblock);
}

bool
connman_technology_is_tethering_allowed(enum connman_service_type type)
{
	static char *allowed_default[] = { "wifi", "bluetooth", "gadget",
					   NULL };
	const char *type_str = __connman_service_type2string(type);
	char **allowed;
	int i;

	if (!type_str)
		return false;

	allowed = connman_setting_get_string_list("TetheringTechnologies");
	if (!allowed)
		allowed = allowed_default;

	for (i = 0; allowed[i]; i++) {
		if (g_strcmp0(allowed[i], type_str) == 0)
			return true;
	}

	return false;
}

static const char *get_name(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_VPN:
		break;
	case CONNMAN_SERVICE_TYPE_GADGET:
		return "Gadget";
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "Wired";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "WiFi";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "Bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "Cellular";
	case CONNMAN_SERVICE_TYPE_GPS:
		return "Gps";
	case CONNMAN_SERVICE_TYPE_P2P:
		return "P2P";
	}

	return NULL;
}

static void technology_save(struct connman_technology *technology)
{
	GKeyFile *keyfile;
	gchar *identifier;
	const char *name = get_name(technology->type);

	DBG("technology %p type %d name %s", technology, technology->type,
									name);
	if (!name)
		return;

	keyfile = __connman_storage_load_global();
	if (!keyfile)
		keyfile = g_key_file_new();

	identifier = g_strdup_printf("%s", name);
	if (!identifier)
		goto done;

	g_key_file_set_boolean(keyfile, identifier, "Enable",
				technology->enable_persistent);

	g_key_file_set_boolean(keyfile, identifier, "Tethering",
				technology->tethering_persistent);

	if (technology->tethering_ident)
		g_key_file_set_string(keyfile, identifier,
					"Tethering.Identifier",
					technology->tethering_ident);

	if (technology->tethering_passphrase)
		g_key_file_set_string(keyfile, identifier,
					"Tethering.Passphrase",
					technology->tethering_passphrase);

done:
	g_free(identifier);

	__connman_storage_save_global(keyfile);

	g_key_file_unref(keyfile);

	return;
}

static void tethering_changed(struct connman_technology *technology)
{
	dbus_bool_t tethering = technology->tethering;

	connman_dbus_property_changed_basic(technology->path,
				CONNMAN_TECHNOLOGY_INTERFACE, "Tethering",
						DBUS_TYPE_BOOLEAN, &tethering);

	technology_save(technology);
}

int connman_technology_tethering_notify(struct connman_technology *technology,
							bool enabled)
{
	int err;

	DBG("technology %p enabled %u", technology, enabled);

	if (technology->tethering == enabled)
		return -EALREADY;

	if (enabled) {
		err = __connman_tethering_set_enabled();
		if (err < 0)
			return err;
	} else
		__connman_tethering_set_disabled();

	technology->tethering = enabled;
	tethering_changed(technology);

	/*
	 * Notify about tethering having been turned off after it's actually
	 * been turned off.
	 */
	if (!enabled)
		__connman_notifier_tethering_changed(technology, FALSE);

	return 0;
}

static int set_tethering(struct connman_technology *technology,
				bool enabled)
{
	int result = -EOPNOTSUPP;
	int err;
	const char *ident, *passphrase, *bridge;
	GSList *tech_drivers;

	ident = technology->tethering_ident;
	passphrase = technology->tethering_passphrase;

	__sync_synchronize();
	if (!technology->enabled)
		return -EACCES;

	bridge = __connman_tethering_get_bridge();
	if (!bridge)
		return -EOPNOTSUPP;

	if (technology->type == CONNMAN_SERVICE_TYPE_WIFI &&
	    (!ident || !passphrase))
		return -EINVAL;

	/*
	 * Notify about tethering being turned on before it actually gets
	 * turned on.
	 */
	if (enabled)
		__connman_notifier_tethering_changed(technology, TRUE);

	for (tech_drivers = technology->driver_list; tech_drivers;
	     tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver || !driver->set_tethering)
			continue;

		err = driver->set_tethering(technology, ident, passphrase,
				bridge, enabled);

		if (result == -EINPROGRESS)
			continue;

		if (err == -EINPROGRESS || err == 0)
			result = err;
	}

	/*
	 * Let notificants know that we have failed to turn tethering on.
	 * Note that we won't be able to do that in case if the driver
	 * returns -EINPROGRESS and then silently fails to actually turn
	 * tethering on. There's no API in connman for reporting this kind
	 * of postponed failures. Oh well..
	 */
	if (enabled && result < 0 && result != -EINPROGRESS)
		__connman_notifier_tethering_changed(technology, FALSE);

	return result;
}

void connman_technology_regdom_notify(struct connman_technology *technology,
							const char *alpha2)
{
	DBG("");

	if (!alpha2)
		connman_error("Failed to set regulatory domain");
	else
		DBG("Regulatory domain set to %s", alpha2);

	g_free(technology->regdom);
	technology->regdom = g_strdup(alpha2);
}

static int set_regdom_by_device(struct connman_technology *technology,
							const char *alpha2)
{
	GSList *list;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (connman_device_set_regdom(device, alpha2) != 0)
			return -ENOTSUP;
	}

	return 0;
}

int connman_technology_set_regdom(const char *alpha2)
{
	GSList *list, *tech_drivers;

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (set_regdom_by_device(technology, alpha2) != 0) {

			for (tech_drivers = technology->driver_list;
			     tech_drivers;
			     tech_drivers = g_slist_next(tech_drivers)) {

				struct connman_technology_driver *driver =
					tech_drivers->data;

				if (driver->set_regdom)
					driver->set_regdom(technology, alpha2);
			}
		}

		/* Save regdom for this technology */
		connman_technology_regdom_notify(technology, alpha2);
	}

	g_free(global_regdom);
	global_regdom = g_strdup(alpha2);

	return 0;
}

static struct connman_technology *technology_find(enum connman_service_type type)
{
	GSList *list;

	DBG("type %d", type);

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (technology->type == type)
			return technology;
	}

	return NULL;
}

const char *__connman_technology_get_regdom(enum connman_service_type type)
{
	struct connman_technology *technology;

	DBG("type %d/%s", type, get_name(type));

	technology = technology_find(type);
	if (!technology)
		return NULL;

	if (technology->regdom)
		return technology->regdom;

	return global_regdom;
}

enum connman_service_type connman_technology_get_type
				(struct connman_technology *technology)
{
	if (!technology)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	return technology->type;
}

bool connman_technology_get_wifi_tethering(const char **ssid,
							const char **psk)
{
	struct connman_technology *technology;

	if (!ssid || !psk)
		return false;

	*ssid = *psk = NULL;

	technology = technology_find(CONNMAN_SERVICE_TYPE_WIFI);
	if (!technology)
		return false;

	if (!technology->tethering)
		return false;

	*ssid = technology->tethering_ident;
	*psk = technology->tethering_passphrase;

	return true;
}

static void free_rfkill(gpointer data)
{
	struct connman_rfkill *rfkill = data;

	g_free(rfkill);
}

static int technology_load_values(struct connman_technology *technology,
							GKeyFile *keyfile)
{
	GError *error = NULL;
	const char *identifier;
	bool enable;
	bool need_saving = false;

	if (!technology || !keyfile)
		return -EINVAL;

	identifier = get_name(technology->type);
	if (!identifier)
		return -ENOENT;

	enable = g_key_file_get_boolean(keyfile, identifier, "Enable", &error);
	if (!error) {
		technology->enable_persistent = enable;
	} else {
		if (technology->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			technology->enable_persistent = true;
		else
			technology->enable_persistent = false;

		need_saving = true;
		g_clear_error(&error);
	}

	enable = g_key_file_get_boolean(keyfile, identifier,
					"Tethering", &error);
	if (!error) {
		technology->tethering_persistent = enable;
	} else {
		need_saving = true;
		g_clear_error(&error);
	}

	technology->tethering_ident = g_key_file_get_string(keyfile,
				identifier, "Tethering.Identifier", NULL);

	technology->tethering_passphrase = g_key_file_get_string(keyfile,
				identifier, "Tethering.Passphrase", NULL);

	if (need_saving)
		technology_save(technology);

	return 0;
}

static void technology_load(struct connman_technology *technology)
{
	GKeyFile *keyfile;

	DBG("technology %p", technology);

	keyfile = __connman_storage_load_global();
	/* Fallback on disabling technology if file not found. */
	if (!keyfile) {
		if (technology->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			/* We enable ethernet by default */
			technology->enable_persistent = true;
		else
			technology->enable_persistent = false;
		return;
	}

	if (technology_load_values(technology, keyfile))
		DBG("Cannot load technology %p/%s keyfile %p", technology,
					get_name(technology->type), keyfile);

	g_key_file_unref(keyfile);

	/* Currently, Sailfish OS assumes that cellular technology is
	 * always enabled. We don't have any UI to enable it meaning
	 * that if it ever gets disabled, it stays like that forever.
	 * Let's make sure it's enabled.
	 *
	 * Note that the technology won't actually get enabled if the
	 * device is in the offline mode.
	 */
	if (technology->type == CONNMAN_SERVICE_TYPE_CELLULAR)
		technology->enable_persistent = true;

	return;
}

bool __connman_technology_get_offlinemode(void)
{
	return global_offlinemode;
}

const char *__connman_technology_get_tethering_ident(
						struct connman_technology *tech)
{
	if (!tech)
		return NULL;
	
	return tech->tethering_ident;
}

enum connman_service_type __connman_technology_get_type(
						struct connman_technology *tech)
{
	if (!tech)
		return CONNMAN_SERVICE_TYPE_UNKNOWN; /* 0 */

	return tech->type;
}

static void connman_technology_save_offlinemode(void)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	bool offlinemode;

	keyfile = __connman_storage_load_global();

	if (!keyfile) {
		keyfile = g_key_file_new();
		g_key_file_set_boolean(keyfile, "global",
					"OfflineMode", global_offlinemode);

		__connman_storage_save_global(keyfile);
	}
	else {
		offlinemode = g_key_file_get_boolean(keyfile, "global",
						"OfflineMode", &error);

		if (error || offlinemode != global_offlinemode) {
			g_key_file_set_boolean(keyfile, "global",
					"OfflineMode", global_offlinemode);
			if (error)
				g_clear_error(&error);

			__connman_storage_save_global(keyfile);
		}
	}

	g_key_file_unref(keyfile);

	return;
}

bool connman_technology_load_offlinemode(void)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	bool offlinemode;

	/* If there is a error, we enable offlinemode */
	keyfile = __connman_storage_load_global();
	if (!keyfile)
		return false;

	offlinemode = g_key_file_get_boolean(keyfile, "global",
						"OfflineMode", &error);
	if (error) {
		offlinemode = false;
		g_clear_error(&error);
	}

	g_key_file_unref(keyfile);

	return offlinemode;
}

static void append_properties(DBusMessageIter *iter,
		struct connman_technology *technology)
{
	DBusMessageIter dict;
	dbus_bool_t val;
	const char *str;

	connman_dbus_dict_open(iter, &dict);

	str = get_name(technology->type);
	if (str)
		connman_dbus_dict_append_basic(&dict, "Name",
						DBUS_TYPE_STRING, &str);

	str = __connman_service_type2string(technology->type);
	if (str)
		connman_dbus_dict_append_basic(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	__sync_synchronize();
	val = technology->enabled;
	connman_dbus_dict_append_basic(&dict, "Powered",
					DBUS_TYPE_BOOLEAN,
					&val);

	val = technology->connected;
	connman_dbus_dict_append_basic(&dict, "Connected",
					DBUS_TYPE_BOOLEAN,
					&val);

	val = technology->tethering;
	connman_dbus_dict_append_basic(&dict, "Tethering",
					DBUS_TYPE_BOOLEAN,
					&val);

	if (technology->tethering_ident)
		connman_dbus_dict_append_basic(&dict, "TetheringIdentifier",
					DBUS_TYPE_STRING,
					&technology->tethering_ident);

	if (technology->tethering_passphrase)
		connman_dbus_dict_append_basic(&dict, "TetheringPassphrase",
					DBUS_TYPE_STRING,
					&technology->tethering_passphrase);

	connman_dbus_dict_close(iter, &dict);
}

static void technology_added_signal(struct connman_technology *technology)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "TechnologyAdded");
	if (!signal)
		return;

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&technology->path);
	append_properties(&iter, technology);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}

static void technology_removed_signal(struct connman_technology *technology)
{
	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "TechnologyRemoved",
			DBUS_TYPE_OBJECT_PATH, &technology->path,
			DBUS_TYPE_INVALID);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *message, void *user_data)
{
	struct connman_technology *technology = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	append_properties(&iter, technology);

	return reply;
}

void __connman_technology_list_struct(DBusMessageIter *array)
{
	GSList *list;
	DBusMessageIter entry;

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (!technology->path ||
				(technology->rfkill_driven &&
				 technology->hardblocked))
			continue;

		dbus_message_iter_open_container(array, DBUS_TYPE_STRUCT,
				NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
				&technology->path);
		append_properties(&entry, technology);
		dbus_message_iter_close_container(array, &entry);
	}
}

static gboolean technology_pending_reply(gpointer user_data)
{
	struct connman_technology *technology = user_data;
	DBusMessage *reply;

	/* Power request timed out, send ETIMEDOUT. */
	if (technology->pending_reply) {
		reply = __connman_error_failed(technology->pending_reply, ETIMEDOUT);
		if (reply)
			g_dbus_send_message(connection, reply);

		dbus_message_unref(technology->pending_reply);
		technology->pending_reply = NULL;
		technology->pending_timeout = 0;
	}

	return FALSE;
}

static int technology_send_pending_reply(
					struct connman_technology *technology,
					int error)
{
	DBusMessage *reply;
	int err = -ECOMM;

	if (!technology->pending_reply)
		return -ENOENT;

	if (!error) {
		err = g_dbus_send_reply(connection, technology->pending_reply,
					DBUS_TYPE_INVALID) ? 0 : -ECOMM;
		goto out;
	}

	reply = __connman_error_failed(technology->pending_reply, error);
	if (reply)
		err = g_dbus_send_message(connection, reply) ? 0 : -ECOMM;

out:
	dbus_message_unref(technology->pending_reply);
	technology->pending_reply = NULL;

	if (technology->pending_timeout != 0) {
		g_source_remove(technology->pending_timeout);
		technology->pending_timeout = 0;
	}

	return err;
}

static int technology_affect_devices(struct connman_technology *technology,
						bool enable_device)
{
	int err = 0, err_dev;
	GSList *list;

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
		if (enable_device)
			__connman_technology_enabled(technology->type);
		else
			__connman_technology_disabled(technology->type);
		return 0;
	}

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (enable_device)
			err_dev = __connman_device_enable(device);
		else
			err_dev = __connman_device_disable(device);

		if (err_dev < 0 && err_dev != -EALREADY)
			err = err_dev;
	}

	return err;
}

static void powered_changed(struct connman_technology *technology)
{
	dbus_bool_t enabled;

	if (!technology->dbus_registered)
		return;

	if (technology_send_pending_reply(technology, 0) == -ECOMM)
		connman_warn("could not reply to pending request");

	__sync_synchronize();
	enabled = technology->enabled;
	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE, "Powered",
			DBUS_TYPE_BOOLEAN, &enabled);
}

static void enable_tethering(struct connman_technology *technology)
{
	int ret;

	if (!connman_setting_get_bool("PersistentTetheringMode"))
		return;

	ret = set_tethering(technology, true);
	if (ret < 0 && ret != -EALREADY)
		DBG("Cannot enable tethering yet for %s (%d/%s)",
			get_name(technology->type),
			-ret, strerror(-ret));
}

static int technology_enabled(struct connman_technology *technology)
{
	__sync_synchronize();
	if (technology->enabled)
		return -EALREADY;

	technology->enabled = true;

	if (technology->type == CONNMAN_SERVICE_TYPE_WIFI) {
		struct connman_technology *p2p;

		p2p = technology_find(CONNMAN_SERVICE_TYPE_P2P);
		if (p2p && !p2p->enabled && p2p->enable_persistent)
			technology_enabled(p2p);
	}

	if (technology->tethering_persistent)
		enable_tethering(technology);

	powered_changed(technology);

	return 0;
}

static int technology_enable(struct connman_technology *technology)
{
	int err = 0;
	int err_dev;

	DBG("technology %p enable", technology);

	if (global_offlinemode && technology->type < MAX_CONNMAN_SERVICE_TYPES) {
		DBG("Overriding offlinemode for type %d", technology->type);
		global_offlinemode_override |= (1 << technology->type);
	}

	__sync_synchronize();

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
		struct connman_technology *wifi;

		wifi = technology_find(CONNMAN_SERVICE_TYPE_WIFI);
		if (wifi && wifi->enabled)
			return technology_enabled(technology);
		return 0;
	}

	if (technology->enabled)
		return -EALREADY;

	if (technology->pending_reply)
		return -EBUSY;

	if (connman_setting_get_bool("PersistentTetheringMode")	&&
					technology->tethering)
		set_tethering(technology, true);

	if (technology->rfkill_driven) {
		err = __connman_rfkill_block(technology->type, false);
		DBG("rfkill err %d/%s", -err, strerror(-err));
	}

	err_dev = technology_affect_devices(technology, true);

	if (!technology->rfkill_driven)
		err = err_dev;

	return err;
}

static int technology_disabled(struct connman_technology *technology)
{
	__sync_synchronize();
	if (!technology->enabled)
		return -EALREADY;

	technology->enabled = false;

	powered_changed(technology);

	return 0;
}

static int technology_disable(struct connman_technology *technology)
{
	int err;

	DBG("technology %p disable", technology);

	if (global_offlinemode && technology->type < MAX_CONNMAN_SERVICE_TYPES) {
		DBG("Clearing offlinemode override for type %d",
			technology->type);
		global_offlinemode_override &= ~(1 << technology->type);
	}

	__sync_synchronize();

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
		technology->enable_persistent = false;
		__connman_device_stop_scan(CONNMAN_SERVICE_TYPE_P2P);
		__connman_peer_disconnect_all();
		return technology_disabled(technology);
	} else if (technology->type == CONNMAN_SERVICE_TYPE_WIFI) {
		struct connman_technology *p2p;

		p2p = technology_find(CONNMAN_SERVICE_TYPE_P2P);
		if (p2p && p2p->enabled) {
			p2p->enable_persistent = true;
			technology_disabled(p2p);
		}
	}

	if (!technology->enabled)
		return -EALREADY;

	if (technology->pending_reply)
		return -EBUSY;

	if (technology->tethering)
		set_tethering(technology, false);

	err = technology_affect_devices(technology, false);

	if (technology->rfkill_driven)
		err = __connman_rfkill_block(technology->type, true);

	return err;
}

/*
 * This function supports notifying about power change for both rfkill and
 * non-rfkill technologies.
 */
static int technology_changed_state(struct connman_technology *technology,
								bool on)
{
	if (on) {
		if (technology->rfkill_driven) {
			if (technology->tethering_persistent)
				enable_tethering(technology);
		}

		return technology_enabled(technology);
	} else {
		if (!technology->rfkill_driven) {
			GSList *list;

			for (list = technology->device_list; list;
						list = list->next) {
				struct connman_device *device = list->data;

				if (connman_device_get_powered(device))
					return 0;
			}
		}

		return technology_disabled(technology);
	}
}

static gboolean enable_delayed(gpointer user_data)
{
	struct connman_technology *technology = user_data;
	int err;

	DBG("");

	if (!technology || technology->enabled)
		goto out;

	err = technology_enable(technology);
	switch (err) {
	case -EBUSY:
		/* Make sure the pending reply does not block and continue */
		if (technology_send_pending_reply(technology, -ECANCELED) ==
					-ECOMM)
			connman_warn("could not reply to pending request");

		return G_SOURCE_CONTINUE;
	case -EINPROGRESS:
		/* Keep in loop until enabled */
		return G_SOURCE_CONTINUE;
	case -EALREADY:
		/*
		 * Already enabled, nothing to do and the notify is already
		 * sent prior to this, as enabled is toggled by
		 * technology_enabled()/technology_disabled().
		 */
		break;
	case 0:
		if (technology_changed_state(technology, true))
			connman_warn("technology %p state not notified",
						technology);

		break;
	default:
		break;
	}

out:
	enable_delayed_ids[technology->type] = 0;
	return G_SOURCE_REMOVE;
}

static int technology_init_enable_delayed(
					struct connman_technology *technology)
{
	DBG("");

	if (!technology)
		return -EINVAL;

	if (enable_delayed_ids[technology->type]) {
		DBG("already in progress for type %d", technology->type);
		return -EALREADY;
	}

	enable_delayed_ids[technology->type] = g_timeout_add(DELAYED_TIMEOUT,
				enable_delayed, technology);

	return 0;
}

static DBusMessage *set_powered(struct connman_technology *technology,
				DBusMessage *msg, bool powered)
{
	DBusMessage *reply = NULL;
	int err = 0;

	if (technology->rfkill_driven && technology->hardblocked) {
		err = -EACCES;
		goto make_reply;
	}

	if (powered)
		err = technology_enable(technology);
	else
		err = technology_disable(technology);

	if (err != -EBUSY) {
		technology->enable_persistent = powered;
		technology_save(technology);
	} else if (powered && err == -EBUSY) {
		technology_init_enable_delayed(technology);
		err = -EINPROGRESS;
	}

make_reply:
	if (err == -EINPROGRESS) {
		technology->pending_reply = dbus_message_ref(msg);
		technology->pending_timeout = g_timeout_add_seconds(10,
					technology_pending_reply, technology);
	} else if (err == -EALREADY) {
		if (powered)
			reply = __connman_error_already_enabled(msg);
		else
			reply = __connman_error_already_disabled(msg);
	} else if (err < 0)
		reply = __connman_error_failed(msg, -err);
	else
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_technology *technology = data;
	DBusMessageIter iter, value;
	const char *name;
	int type, err;

	DBG("conn %p", conn);

	if (!dbus_message_iter_init(msg, &iter))
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	if (__connman_access_tech_set_property(get_tech_access_policy(),
		name, dbus_message_get_sender(msg), CONNMAN_ACCESS_ALLOW) !=
						CONNMAN_ACCESS_ALLOW) {
		DBG("%s is not allowed to set %s",
				dbus_message_get_sender(msg), name);
		return __connman_error_permission_denied(msg);
	}

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	DBG("property %s", name);

	if (g_str_equal(name, "Tethering")) {
		dbus_bool_t tethering;
		int err;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		if (!connman_technology_is_tethering_allowed(technology->type)) {
			DBG("%s tethering not allowed by config file",
				__connman_service_type2string(technology->type));
			return __connman_error_not_supported(msg);
		}

		dbus_message_iter_get_basic(&value, &tethering);

		if (technology->tethering == tethering) {
			if (!tethering)
				return __connman_error_already_disabled(msg);
			else
				return __connman_error_already_enabled(msg);
		}

		err = set_tethering(technology, tethering);
		if (err < 0)
			return __connman_error_failed(msg, -err);

		technology->tethering_persistent = tethering;

		technology_save(technology);

	} else if (g_str_equal(name, "TetheringIdentifier")) {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);

		if (technology->type != CONNMAN_SERVICE_TYPE_WIFI)
			return __connman_error_not_supported(msg);

		if (strlen(str) < 1 || strlen(str) > 32)
			return __connman_error_invalid_arguments(msg);

		if (g_strcmp0(technology->tethering_ident, str) != 0) {
			g_free(technology->tethering_ident);
			technology->tethering_ident = g_strdup(str);
			technology_save(technology);

			connman_dbus_property_changed_basic(technology->path,
						CONNMAN_TECHNOLOGY_INTERFACE,
						"TetheringIdentifier",
						DBUS_TYPE_STRING,
						&technology->tethering_ident);
		}
	} else if (g_str_equal(name, "TetheringPassphrase")) {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);

		if (technology->type != CONNMAN_SERVICE_TYPE_WIFI)
			return __connman_error_not_supported(msg);

		err = __connman_service_check_passphrase(CONNMAN_SERVICE_SECURITY_PSK,
							str);
		if (err < 0)
			return __connman_error_passphrase_required(msg);

		if (g_strcmp0(technology->tethering_passphrase, str) != 0) {
			g_free(technology->tethering_passphrase);
			technology->tethering_passphrase = g_strdup(str);
			technology_save(technology);

			connman_dbus_property_changed_basic(technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					"TetheringPassphrase",
					DBUS_TYPE_STRING,
					&technology->tethering_passphrase);
		}
	} else if (g_str_equal(name, "Powered")) {
		dbus_bool_t enable;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &enable);

		return set_powered(technology, msg, enable);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void reply_scan_pending(struct connman_technology *technology, int err)
{
	DBusMessage *reply;

	DBG("technology %p err %d", technology, err);

	while (technology->scan_pending) {
		DBusMessage *msg = technology->scan_pending->data;

		DBG("reply to %s", dbus_message_get_sender(msg));

		if (err == 0)
			reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
		else
			reply = __connman_error_failed(msg, -err);
		g_dbus_send_message(connection, reply);
		dbus_message_unref(msg);

		technology->scan_pending =
			g_slist_delete_link(technology->scan_pending,
					technology->scan_pending);
	}
}

void __connman_technology_scan_started(struct connman_device *device)
{
	DBG("device %p", device);
}

void __connman_technology_scan_stopped(struct connman_device *device,
					enum connman_service_type type)
{
	int count = 0;
	struct connman_technology *technology;
	GSList *list;

	technology = technology_find(type);

	DBG("technology %p device %p", technology, device);

	if (!technology)
		return;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *other_device = list->data;

		if (device == other_device)
			continue;

		if (connman_device_get_scanning(other_device, type))
			count += 1;
	}

	if (count == 0)
		reply_scan_pending(technology, 0);
}

void __connman_technology_notify_regdom_by_device(struct connman_device *device,
						int result, const char *alpha2)
{
	bool regdom_set = false;
	struct connman_technology *technology;
	enum connman_service_type type;
	GSList *tech_drivers;

	type = __connman_device_get_service_type(device);
	technology = technology_find(type);

	if (!technology)
		return;

	if (result < 0) {

		for (tech_drivers = technology->driver_list;
		     tech_drivers;
		     tech_drivers = g_slist_next(tech_drivers)) {
			struct connman_technology_driver *driver =
				tech_drivers->data;

			if (driver->set_regdom) {
				driver->set_regdom(technology, alpha2);
				regdom_set = true;
			}

		}

		if (!regdom_set)
			alpha2 = NULL;
	}

	connman_technology_regdom_notify(technology, alpha2);
}

static DBusMessage *scan(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct connman_technology *technology = data;
	int err;

	DBG("technology %p request from %s", technology,
			dbus_message_get_sender(msg));

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P &&
				!technology->enabled)
		return __connman_error_permission_denied(msg);

	dbus_message_ref(msg);
	technology->scan_pending =
		g_slist_prepend(technology->scan_pending, msg);

	err = __connman_device_request_scan_full(technology->type);
	if (err < 0)
		reply_scan_pending(technology, err);

	return NULL;
}

static const GDBusMethodTable technology_methods[] = {
	{ GDBUS_DEPRECATED_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_ASYNC_METHOD("Scan", NULL, NULL, scan) },
	{ },
};

static const GDBusSignalTable technology_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ },
};

static bool technology_dbus_register(struct connman_technology *technology)
{
	if (technology->dbus_registered ||
				(technology->rfkill_driven &&
				 technology->hardblocked))
		return true;

	if (!g_dbus_register_interface(connection, technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					technology_methods, technology_signals,
					NULL, technology, NULL)) {
		connman_error("Failed to register %s", technology->path);
		return false;
	}

	technology_added_signal(technology);
	technology->dbus_registered = true;

	return true;
}

static void technology_dbus_unregister(struct connman_technology *technology)
{
	if (!technology->dbus_registered)
		return;

	technology_removed_signal(technology);
	g_dbus_unregister_interface(connection, technology->path,
		CONNMAN_TECHNOLOGY_INTERFACE);

	technology->dbus_registered = false;
}

static void technology_put(struct connman_technology *technology)
{
	DBG("technology %p", technology);

	if (__sync_sub_and_fetch(&technology->refcount, 1) > 0)
		return;

	reply_scan_pending(technology, -EINTR);

	while (technology->driver_list) {
		struct connman_technology_driver *driver;

		driver = technology->driver_list->data;

		if (driver->remove)
			driver->remove(technology);

		technology->driver_list =
			g_slist_delete_link(technology->driver_list,
					technology->driver_list);
	}

	technology_list = g_slist_remove(technology_list, technology);

	technology_dbus_unregister(technology);

	g_slist_free(technology->device_list);

	if (technology_send_pending_reply(technology, -ECANCELED) == -ECOMM)
		connman_warn("could not reply to pending request");

	g_free(technology->path);
	g_free(technology->regdom);
	g_free(technology->tethering_ident);
	g_free(technology->tethering_passphrase);
	g_free(technology);
}

static struct connman_technology *technology_get(enum connman_service_type type)
{
	GSList *tech_drivers = NULL;
	struct connman_technology_driver *driver;
	struct connman_technology *technology;
	const char *str;
	GSList *list;

	DBG("type %d", type);

	str = __connman_service_type2string(type);
	if (!str)
		return NULL;

	technology = technology_find(type);
	if (technology) {
		if (type != CONNMAN_SERVICE_TYPE_P2P)
			__sync_fetch_and_add(&technology->refcount, 1);
		return technology;
	}

	/* First check if we have a driver for this technology type */
	for (list = driver_list; list; list = list->next) {
		driver = list->data;

		if (driver->type == type) {
			DBG("technology %p driver %p", technology, driver);
			tech_drivers = g_slist_append(tech_drivers, driver);
		}
	}

	if (!tech_drivers) {
		DBG("No matching drivers found for %s.",
				__connman_service_type2string(type));
		return NULL;
	}

	technology = g_try_new0(struct connman_technology, 1);
	if (!technology)
		return NULL;

	technology->refcount = 1;
	technology->type = type;
	technology->path = g_strdup_printf("%s/technology/%s",
							CONNMAN_PATH, str);

	technology_load(technology);
	technology_list = g_slist_prepend(technology_list, technology);
	technology->driver_list = tech_drivers;
	technology->regdom = g_strdup(global_regdom);

	for (list = tech_drivers; list; list = list->next) {
		driver = list->data;

		if (driver->probe && driver->probe(technology) < 0)
			DBG("Driver probe failed for technology %p",
					technology);
	}

	if (!technology_dbus_register(technology)) {
		technology_put(technology);
		return NULL;
	}

	if (type == CONNMAN_SERVICE_TYPE_P2P) {
		struct connman_technology *wifi;
		bool enable;

		enable = technology->enable_persistent;

		wifi = technology_find(CONNMAN_SERVICE_TYPE_WIFI);
		if (enable && wifi)
			enable = wifi->enabled;

		technology_affect_devices(technology, enable);
	}

	DBG("technology %p %s", technology, get_name(technology->type));

	return technology;
}

int connman_technology_driver_register(struct connman_technology_driver *driver)
{
	GSList *list;
	struct connman_device *device;
	enum connman_service_type type;

	for (list = driver_list; list; list = list->next) {
		if (list->data == driver)
			goto exist;
	}

	DBG("Registering %s driver", driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	/*
	 * Check for technology less devices if this driver
	 * can service any of them.
	*/
	for (list = techless_device_list; list; list = list->next) {
		device = list->data;

		type = __connman_device_get_service_type(device);
		if (type != driver->type)
			continue;

		techless_device_list = g_slist_remove(techless_device_list,
								device);

		__connman_technology_add_device(device);
	}

	/* Check for orphaned rfkill switches. */
	g_hash_table_foreach(rfkill_list, rfkill_check,
					GINT_TO_POINTER(driver->type));

exist:
	if (driver->type == CONNMAN_SERVICE_TYPE_P2P) {
		if (!technology_get(CONNMAN_SERVICE_TYPE_P2P))
			return -ENOMEM;
	}

	return 0;
}

void connman_technology_driver_unregister(struct connman_technology_driver *driver)
{
	GSList *list, *tech_drivers;
	struct connman_technology *technology;
	struct connman_technology_driver *current;

	DBG("Unregistering driver %p name %s", driver, driver->name);

	for (list = technology_list; list; list = list->next) {
		technology = list->data;

		for (tech_drivers = technology->driver_list; tech_drivers;
				tech_drivers = g_slist_next(tech_drivers)) {
			current = tech_drivers->data;
			if (driver != current)
				continue;

			if (driver->remove)
				driver->remove(technology);

			technology->driver_list =
				g_slist_remove(technology->driver_list,
								driver);
			break;
		}
	}

	driver_list = g_slist_remove(driver_list, driver);

	if (driver->type == CONNMAN_SERVICE_TYPE_P2P) {
		technology = technology_find(CONNMAN_SERVICE_TYPE_P2P);
		if (technology)
			technology_put(technology);
	}
}

void __connman_technology_add_interface(enum connman_service_type type,
				int index, const char *ident)
{
	struct connman_technology *technology;
	GSList *tech_drivers;
	struct connman_technology_driver *driver;
	char *name;

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	}

	name = connman_inet_ifname(index);
	DBG("Adding interface %s [ %s ]", name,
				__connman_service_type2string(type));

	technology = technology_find(type);

	if (!technology)
		goto out;

	for (tech_drivers = technology->driver_list; tech_drivers;
	     tech_drivers = g_slist_next(tech_drivers)) {
		driver = tech_drivers->data;

		if (driver->add_interface)
			driver->add_interface(technology, index, name, ident);
	}

	/*
	 * At this point we can try to enable tethering automatically as
	 * now the interfaces are set properly.
	 */
	if (technology->tethering_persistent)
		enable_tethering(technology);

out:
	g_free(name);
}

void __connman_technology_remove_interface(enum connman_service_type type,
				int index, const char *ident)
{
	struct connman_technology *technology;
	GSList *tech_drivers;
	struct connman_technology_driver *driver;
	char *name;

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	}

	name = connman_inet_ifname(index);
	DBG("Remove interface %s [ %s ]", name,
				__connman_service_type2string(type));
	g_free(name);

	technology = technology_find(type);

	if (!technology)
		return;

	for (tech_drivers = technology->driver_list; tech_drivers;
	     tech_drivers = g_slist_next(tech_drivers)) {
		driver = tech_drivers->data;

		if (driver->remove_interface)
			driver->remove_interface(technology, index);
	}
}

int __connman_technology_add_device(struct connman_device *device)
{
	struct connman_technology *technology;
	enum connman_service_type type;

	type = __connman_device_get_service_type(device);

	DBG("device %p type %s", device, get_name(type));

	technology = technology_get(type);
	if (!technology) {
		/*
		 * Since no driver can be found for this device at the moment we
		 * add it to the techless device list.
		*/
		techless_device_list = g_slist_prepend(techless_device_list,
								device);

		return -ENXIO;
	}

	__sync_synchronize();
	if (technology->rfkill_driven) {
		if (technology->enabled)
			__connman_device_enable(device);
		else
			__connman_device_disable(device);

		goto done;
	}

	if (technology->enable_persistent &&
					!global_offlinemode) {
		int err = __connman_device_enable(device);
		/*
		 * connman_technology_add_device() calls __connman_device_enable()
		 * but since the device is already enabled, the call does not
		 * propagate through to connman_technology_enabled via
		 * connman_device_set_powered.
		 */
		if (err == -EALREADY)
			__connman_technology_enabled(type);
	}
	/* if technology persistent state is offline */
	if (!technology->enable_persistent)
		__connman_device_disable(device);

done:
	technology->device_list = g_slist_prepend(technology->device_list,
								device);

	return 0;
}

int __connman_technology_remove_device(struct connman_device *device)
{
	struct connman_technology *technology;
	enum connman_service_type type;

	DBG("device %p", device);

	type = __connman_device_get_service_type(device);

	technology = technology_find(type);
	if (!technology) {
		techless_device_list = g_slist_remove(techless_device_list,
								device);
		return -ENXIO;
	}

	technology->device_list = g_slist_remove(technology->device_list,
								device);

	if (technology->tethering)
		set_tethering(technology, false);

	technology_put(technology);

	return 0;
}

int __connman_technology_enabled(enum connman_service_type type)
{
	struct connman_technology *technology;

	technology = technology_find(type);
	if (!technology)
		return -ENXIO;

	DBG("technology %p type %s rfkill %d enabled %d", technology,
		get_name(type), technology->rfkill_driven,
		technology->enabled);

	if (technology->rfkill_driven) {
		if (technology->tethering_persistent)
			enable_tethering(technology);
		return 0;
	}

	return technology_enabled(technology);
}

int __connman_technology_disabled(enum connman_service_type type)
{
	struct connman_technology *technology;
	GSList *list;

	technology = technology_find(type);
	if (!technology)
		return -ENXIO;

	if (technology->rfkill_driven)
		return 0;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (connman_device_get_powered(device))
			return 0;
	}

	return technology_disabled(technology);
}

int __connman_technology_set_offlinemode(bool offlinemode)
{
	GSList *list;
	int err = -EINVAL, enabled_tech_count = 0;

	if (global_offlinemode == offlinemode)
		return 0;

	DBG("offlinemode %s", offlinemode ? "On" : "Off");

	/*
	 * This is a bit tricky. When you set offlinemode, there is no
	 * way to differentiate between attempting offline mode and
	 * resuming offlinemode from last saved profile. We need that
	 * information in rfkill_update, otherwise it falls back on the
	 * technology's persistent state. Hence we set the offline mode here
	 * but save it & call the notifier only if it is successful.
	 */

	global_offlinemode = offlinemode;

	/* Notify technology drivers that global_offlinemode has changed */
	for (list = driver_list; list; list = list->next) {
		struct connman_technology_driver *driver = list->data;

		if (driver->set_offline) {
			driver->set_offline(offlinemode);
		}
	}

	/* Traverse technology list, enable/disable each technology. */
	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (offlinemode) {
			err = technology_disable(technology);
			continue;
		}

		if (technology->hardblocked)
			continue;

		if (!offlinemode && (technology->enable_persistent ||
					technology->type ==
					CONNMAN_SERVICE_TYPE_CELLULAR)) {
			err = technology_enable(technology);
			switch (err) {
			case -EINPROGRESS:
			case -EALREADY:
			case 0:
				enabled_tech_count++;
				break;
			case -EBUSY:
				technology_init_enable_delayed(technology);
				break;
			default:
				break;
			}
		}
	}

	switch (err) {
	case -EINVAL:
		if (enabled_tech_count > 0)
			break;

	case -EINPROGRESS:
		/* fall through */
	case -EALREADY:
		/* fall through */
	case 0:
		connman_technology_save_offlinemode();
		__connman_notifier_offlinemode(offlinemode);
		break;
	default:
		global_offlinemode = connman_technology_load_offlinemode();
	}

	DBG("Clearing offlinemode override bitmask.");
	global_offlinemode_override = 0;

	return err;
}

void __connman_technology_set_connected(enum connman_service_type type,
		bool connected)
{
	struct connman_technology *technology;
	dbus_bool_t val;

	technology = technology_find(type);
	if (!technology)
		return;

	DBG("technology %p connected %d", technology, connected);

	technology->connected = connected;

	val = connected;
	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE, "Connected",
			DBUS_TYPE_BOOLEAN, &val);
}

bool __connman_technology_disable_all(void)
{
	GSList *list;
	GSList *devlist;
	int err;
	bool ret = true;

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (!technology->enabled)
			continue;

		DBG("disabling enabled technology %p/%s", technology,
					get_name(technology->type));

		for (devlist = technology->device_list; devlist;
					devlist = devlist->next) {
			struct connman_device *device = devlist->data;

			if (!connman_device_get_scanning(device,
							technology->type))
				continue;

			err = connman_device_set_scanning(device,
						technology->type, false);
			if (err)
				DBG("failed to stop scan: %s",
							strerror(-err));
		}

		/* To make sure that all scan requests are replied */
		reply_scan_pending(technology, -EINTR);

		/* Make sure there is no pending reply awaiting */
		if (technology_send_pending_reply(technology, -ECANCELED) ==
					-ECOMM)
			connman_warn("could not reply to pending request");

		err = technology_disable(technology);
		if (!err) {
			if (technology_changed_state(technology, false))
				connman_warn("technology %p state change not "
							"notified",
							technology);
		} else {
			ret = false;
		}

		if (err != -EBUSY)
			technology->enable_persistent = false;

		/*
		 * technology_disable() will disable tethering, clean
		 * ident and passphrase here.
		 */
		g_free(technology->tethering_ident);
		technology->tethering_ident = NULL;

		g_free(technology->tethering_passphrase);
		technology->tethering_passphrase = NULL;

		DBG("result %s", err ? strerror(-err) : "ok");
	}

	return ret;
}

static void initialize_offline_mode(void)
{
	global_offlinemode = connman_technology_load_offlinemode();
	global_offlinemode_override = 0;

	/* This will create settings file if it is missing */
	connman_technology_save_offlinemode();
}

bool __connman_technology_enable_from_config()
{
	GSList *list;
	GKeyFile *keyfile;
	GError *error = NULL;
	bool offlinemode = false;
	int err;

	keyfile = __connman_storage_load_global();
	if (!keyfile) {
		/*
		 * When the settings file does not exist create it similarly to
		 * technology is initialization. This concerns new users only.
		 */
		initialize_offline_mode();

		DBG("No global settings found, all techs are off.");
		return false;
	}

	offlinemode = g_key_file_get_boolean(keyfile, "global",
				"OfflineMode", &error);
	if (error) {
		offlinemode = false;
		g_clear_error(&error);
	}

	DBG("offlinemode %s", offlinemode ? "true" : "false");

	/*
	 * If new mode is online but in offline mode, set new mode to
	 * avoid setting offline override without actual need when a
	 * technology is enabled.
	 */
	if (!offlinemode && global_offlinemode) {
		DBG("in offline mode, set to online");
		__connman_technology_set_offlinemode(offlinemode);
	}

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (technology_load_values(technology, keyfile)) {
			DBG("Cannot load technology %p/%s keyfile %p",
						technology,
						get_name(technology->type),
						keyfile);
			continue;
		}

		if (technology->rfkill_driven && technology->hardblocked) {
			DBG("technology %p/%s hardblocked, not set as %s",
						technology,
						get_name(technology->type),
						technology->enable_persistent ?
						"enabled" : "disabled");
			technology_save(technology);
			continue;
		}

		DBG("technology %p/%s set as %s", technology,
					get_name(technology->type),
					technology->enable_persistent ?
					"enabled" : "disabled");

		if (!technology->enable_persistent) {
			if (!technology->enabled) {
				DBG("tech %p/%s already disabled", technology,
						get_name(technology->type));
				continue;
			}

			err = technology_disable(technology);
			if (!err) {
				if (technology_changed_state(technology,
							false))
					connman_warn("technology %p state"
							"change not notified",
							technology);
			}

			DBG("tech %p/%s enabled set as disabled, result %s",
						technology,
						get_name(technology->type),
						err ? strerror(-err) : "ok");
		} else {
			/*
			 * Don't enable in offline mode but set
			 * enable_persistent to make sure tech is enabled
			 * when leaving offline mode.
			*/
			if (offlinemode) {
				DBG("tech %p/%s not enabled in offlinemode",
						technology,
						get_name(technology->type));
				continue;
			}

			if (technology->enabled) {
				DBG("tech %p/%s already enabled", technology,
						get_name(technology->type));
				continue;
			}

			/*
			 * In user change enabling of rfkill devices must be
			 * delayed to avoid inconsistent state.
			 */
			if (technology->rfkill_driven) {
				err = technology_init_enable_delayed(
							technology);
			} else {
				err = technology_enable(technology);
				if (!err) {
					if (technology_changed_state(
							technology, true))
						connman_warn("tech %p state"
							"change notify fail",
							technology);
				} else if (err == -EBUSY) {
					technology_init_enable_delayed(
								technology);
				}
			}

			DBG("tech %p/%s disabled set as enabled, result %s",
						technology,
						get_name(technology->type),
						err ? strerror(-err) : "ok");
		}

		technology_save(technology);
	}

	DBG("setting offline mode %s", offlinemode ? "true" : "false");
	__connman_technology_set_offlinemode(offlinemode);

	g_key_file_unref(keyfile);

	return true;
}

static bool technology_apply_rfkill_change(struct connman_technology *technology,
						bool softblock,
						bool hardblock,
						bool new_rfkill)
{
	bool hardblock_changed = false;
	bool apply = true;
	GList *start, *list;

	DBG("technology %p --> %d/%d vs %d/%d",
			technology, softblock, hardblock,
			technology->softblocked, technology->hardblocked);

	if (technology->hardblocked == hardblock)
		goto softblock_change;

	if (!(new_rfkill && !hardblock)) {
		start = g_hash_table_get_values(rfkill_list);

		for (list = start; list; list = list->next) {
			struct connman_rfkill *rfkill = list->data;

			if (rfkill->type != technology->type)
				continue;

			if (rfkill->hardblock != hardblock)
				apply = false;
		}

		g_list_free(start);
	}

	if (!apply)
		goto softblock_change;

	technology->hardblocked = hardblock;
	hardblock_changed = true;

softblock_change:
	if (!apply && technology->softblocked != softblock)
		apply = true;

	if (!apply)
		return technology->hardblocked;

	technology->softblocked = softblock;

	if (technology->hardblocked ||
					technology->softblocked) {
		if (technology_disabled(technology) != -EALREADY)
			technology_affect_devices(technology, false);
	} else if (!technology->hardblocked &&
					!technology->softblocked) {
		if (technology_enabled(technology) != -EALREADY)
			technology_affect_devices(technology, true);
	}

	if (hardblock_changed) {
		if (technology->hardblocked) {
			DBG("%s is switched off.", get_name(technology->type));
			technology_dbus_unregister(technology);
		} else {
			DBG("%s is switched on.", get_name(technology->type));
			technology_dbus_register(technology);

			if (global_offlinemode)
				__connman_rfkill_block(technology->type, true);
		}
	}

	return technology->hardblocked;
}

int __connman_technology_add_rfkill(unsigned int index,
					enum connman_service_type type,
						bool softblock,
						bool hardblock)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;

	DBG("index %u type %d soft %u hard %u", index, type,
							softblock, hardblock);

	rfkill = g_hash_table_lookup(rfkill_list, GINT_TO_POINTER(index));
	if (rfkill)
		goto done;

	rfkill = g_try_new0(struct connman_rfkill, 1);
	if (!rfkill)
		return -ENOMEM;

	rfkill->index = index;
	rfkill->type = type;
	rfkill->softblock = softblock;
	rfkill->hardblock = hardblock;

	g_hash_table_insert(rfkill_list, GINT_TO_POINTER(index), rfkill);

done:
	technology = technology_get(type);
	/* If there is no driver for this type, ignore it. */
	if (!technology)
		return -ENXIO;

	technology->rfkill_driven = true;

	/* If hardblocked, there is no need to handle softblocked state */
	if (technology_apply_rfkill_change(technology,
				softblock, hardblock, true))
		return 0;

	/*
	 * Depending on softblocked state we unblock/block according to
	 * offlinemode and persistente state.
	 */
	if (technology->softblocked &&
				!global_offlinemode &&
				technology->enable_persistent)
		return __connman_rfkill_block(type, false);
	else if (!technology->softblocked &&
		(global_offlinemode ||
				!technology->enable_persistent)) {
		/* Don't block for technologies which have been enabled
		   since offlinemode was turned on */
		if (global_offlinemode_override & (1 << type))
			DBG("Overriding offlinemode for type %d", type);
		else
			return __connman_rfkill_block(type, true);
	}

	return 0;
}

int __connman_technology_update_rfkill(unsigned int index,
					enum connman_service_type type,
						bool softblock,
						bool hardblock)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;

	DBG("index %u soft %u hard %u", index, softblock, hardblock);

	rfkill = g_hash_table_lookup(rfkill_list, GINT_TO_POINTER(index));
	if (!rfkill)
		return -ENXIO;

	if (rfkill->softblock == softblock &&
				rfkill->hardblock == hardblock)
		return 0;

	rfkill->softblock = softblock;
	rfkill->hardblock = hardblock;

	technology = technology_find(type);
	/* If there is no driver for this type, ignore it. */
	if (!technology)
		return -ENXIO;

	technology_apply_rfkill_change(technology, softblock, hardblock,
								false);

	if (technology->hardblocked)
		DBG("%s hardblocked", get_name(technology->type));
	else
		DBG("%s is%s softblocked", get_name(technology->type),
			technology->softblocked ? "" : " not");

	return 0;
}

int __connman_technology_remove_rfkill(unsigned int index,
					enum connman_service_type type)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;

	DBG("index %u", index);

	rfkill = g_hash_table_lookup(rfkill_list, GINT_TO_POINTER(index));
	if (!rfkill)
		return -ENXIO;

	g_hash_table_remove(rfkill_list, GINT_TO_POINTER(index));

	technology = technology_find(type);
	if (!technology)
		return -ENXIO;

	technology_apply_rfkill_change(technology,
		technology->softblocked, !technology->hardblocked, false);

	technology_put(technology);

	return 0;
}

int __connman_technology_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	rfkill_list = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_rfkill);

	initialize_offline_mode();

	return 0;
}

void __connman_technology_cleanup(void)
{
	int i;

	DBG("");

	while (technology_list) {
		struct connman_technology *technology = technology_list->data;
		technology_list = g_slist_remove(technology_list, technology);
		technology_put(technology);
	}

	g_hash_table_destroy(rfkill_list);

	for (i = 0; i < MAX_CONNMAN_SERVICE_TYPES; i++) {
		if (enable_delayed_ids[i])
			g_source_remove(enable_delayed_ids[i]);
	}

	dbus_connection_unref(connection);

	__connman_access_tech_policy_free(tech_access_policy);
	tech_access_policy = NULL;

	g_free(global_regdom);
}
