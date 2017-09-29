/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
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
#include <ctype.h>

#include <gdbus.h>

#include <connman/agent.h>

#include "connman.h"

#include <gsupplicant_util.h>
#include <gutil_misc.h>

#define SET_OFFLINE_MODE_ACCESS     CONNMAN_ACCESS_ALLOW
#define CREATE_SERVICE_ACCESS       CONNMAN_ACCESS_ALLOW

static bool connman_state_idle;
static dbus_bool_t sessionmode;
struct connman_access_manager_policy *manager_access_policy;

static struct connman_access_manager_policy *get_manager_access_policy()
{
	/* We can't initialize this variable in __connman_manager_init
	 * because __connman_manager_init runs before sailfish access
	 * plugin (or any other plugin) is loaded */
	if (!manager_access_policy) {
		/* Use the default policy */
		manager_access_policy =
			__connman_access_manager_policy_create(NULL);
	}
	return manager_access_policy;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter array, dict;
	dbus_bool_t offlinemode;
	dbus_uint32_t uint32_value;
	const char *str;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);

	str = __connman_notifier_get_state();
	connman_dbus_dict_append_basic(&dict, "State",
						DBUS_TYPE_STRING, &str);

	offlinemode = __connman_technology_get_offlinemode();
	connman_dbus_dict_append_basic(&dict, "OfflineMode",
					DBUS_TYPE_BOOLEAN, &offlinemode);

	connman_dbus_dict_append_basic(&dict, "SessionMode",
					DBUS_TYPE_BOOLEAN,
					&sessionmode);

	uint32_value = connman_timeout_input_request();
	connman_dbus_dict_append_basic(&dict, "InputRequestTimeout",
					DBUS_TYPE_UINT32,
					&uint32_value);

	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("conn %p", conn);

	if (!dbus_message_iter_init(msg, &iter))
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "OfflineMode")) {
		const char *sender = dbus_message_get_sender(msg);
		dbus_bool_t offlinemode;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		if (__connman_access_manager_policy_check(
				get_manager_access_policy(),
				CONNMAN_ACCESS_MANAGER_SET_PROPERTY,
				name, sender, SET_OFFLINE_MODE_ACCESS) !=
						CONNMAN_ACCESS_ALLOW) {
			DBG("access denied for %s", sender);
			return __connman_error_permission_denied(msg);
		}

		dbus_message_iter_get_basic(&value, &offlinemode);

		__connman_technology_set_offlinemode(offlinemode);
	} else if (g_str_equal(name, "SessionMode")) {

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &sessionmode);

	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void append_technology_structs(DBusMessageIter *iter, void *user_data)
{
	__connman_technology_list_struct(iter);
}

static DBusMessage *get_technologies(DBusConnection *conn,
		DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	DBG("");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	__connman_dbus_append_objpath_dict_array(reply,
			append_technology_structs, NULL);

	return reply;
}

static DBusMessage *remove_provider(DBusConnection *conn,
				    DBusMessage *msg, void *data)
{
	const char *path;
	int err;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __connman_provider_remove_by_path(path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusConnection *connection = NULL;

static void idle_state(bool idle)
{

	DBG("idle %d", idle);

	connman_state_idle = idle;

	if (!connman_state_idle)
		return;
}

static struct connman_notifier technology_notifier = {
	.name		= "manager",
	.priority	= CONNMAN_NOTIFIER_PRIORITY_HIGH,
	.idle_state	= idle_state,
};

static void append_service_structs(DBusMessageIter *iter, void *user_data)
{
	__connman_service_list_struct(iter);
}

static DBusMessage *get_services(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	__connman_dbus_append_objpath_dict_array(reply,
			append_service_structs, NULL);

	return reply;
}

static void append_peer_structs(DBusMessageIter *iter, void *user_data)
{
	__connman_peer_list_struct(iter);
}

static DBusMessage *get_peers(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	__connman_dbus_append_objpath_dict_array(reply,
					append_peer_structs, NULL);
	return reply;
}

static DBusMessage *connect_provider(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	int err;

	DBG("conn %p", conn);

	err = __connman_provider_create_and_connect(msg);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return NULL;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = connman_agent_register(sender, path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = connman_agent_unregister(sender, path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *register_counter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	unsigned int accuracy, period;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_UINT32, &accuracy,
						DBUS_TYPE_UINT32, &period,
							DBUS_TYPE_INVALID);

	/* FIXME: add handling of accuracy parameter */

	err = __connman_counter_register(sender, path, period);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_counter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __connman_counter_unregister(sender, path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *reset_counters(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *type = NULL;

	DBG("conn %p", conn);
	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &type,
							DBUS_TYPE_INVALID);

	__connman_service_counter_reset_all(type);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

/* This key is checked only if the first CreateService argument is empty */
#define SERVICE_KEY_TYPE       "Type"

/* These should match the ones defined in service.c */
#define SERVICE_KEY_NAME       "Name"
#define SERVICE_KEY_SSID       "SSID"
#define SERVICE_KEY_SECURITY   "Security"

static DBusMessage *create_service(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array, entry;
	enum connman_service_type service_type;
	GKeyFile *settings;
	const char *sender = dbus_message_get_sender(msg);
	const char *device_ident, *network_ident, *type = NULL, *name = NULL;
	char *ident, *p, *tmp_name = NULL;

	/* N.B. The caller has checked the signature */
	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &type);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &device_ident);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &network_ident);
	dbus_message_iter_next(&iter);

	/* If service type is missing, pull it from the settings */
	if (!type || !type[0]) {
		dbus_message_iter_recurse(&iter, &array);
		while (dbus_message_iter_get_arg_type(&array) ==
							DBUS_TYPE_STRUCT) {
			const char *key = NULL;

			dbus_message_iter_recurse(&array, &entry);
			dbus_message_iter_get_basic(&entry, &key);
			dbus_message_iter_next(&entry);

			if (!g_strcmp0(key, SERVICE_KEY_TYPE)) {
				dbus_message_iter_get_basic(&entry, &type);
				break;
			}

			dbus_message_iter_next(&array);
		}
	}

	if (type && type[0]) {
		/* Check the service type (only wifi is supported for now) */
		service_type = __connman_service_string2type(type);
		if (service_type == CONNMAN_SERVICE_TYPE_UNKNOWN) {
			DBG("unknown device type %s", type);
			return __connman_error_invalid_arguments(msg);
		} else if (service_type != CONNMAN_SERVICE_TYPE_WIFI) {
			DBG("unsupported device type %s", type);
			return __connman_error_not_supported(msg);
		}
	} else {
		/* No device type given, assume wifi */
		service_type = CONNMAN_SERVICE_TYPE_WIFI;
		type = __connman_service_type2string(service_type);
	}

	/* Check access */
	if (__connman_access_manager_policy_check(get_manager_access_policy(),
			CONNMAN_ACCESS_MANAGER_CREATE_SERVICE, type, sender,
			CREATE_SERVICE_ACCESS) != CONNMAN_ACCESS_ALLOW) {
		DBG("access denied for %s", sender);
		return __connman_error_permission_denied(msg);
	}

	/*
	 * If no device identifier is given, assume the first device
	 * of this type.
	 */
	if (!device_ident || !device_ident[0]) {
		struct connman_device *device =
			__connman_device_find_device(service_type);

		if (!device) {
			DBG("no devices of type %s", type);
			return __connman_error_invalid_arguments(msg);
		}
		device_ident = connman_device_get_ident(device);
	}

	/*
	 * If no network identifier is provided, deduce one from ssid
	 * and security (we have to assume wifi here)
	 */
	if (network_ident && network_ident[0]) {
		ident = g_strconcat(type, "_", device_ident, "_",
							network_ident, NULL);
	} else {
		const char *ssid = NULL, *security = NULL, *ptr;

		dbus_message_iter_recurse(&iter, &array);
		while (dbus_message_iter_get_arg_type(&array) ==
				DBUS_TYPE_STRUCT && !(ssid && security)) {
			const char *key = NULL;

			dbus_message_iter_recurse(&array, &entry);
			dbus_message_iter_get_basic(&entry, &key);
			dbus_message_iter_next(&entry);

			if (!g_strcmp0(key, SERVICE_KEY_SSID)) {
				dbus_message_iter_get_basic(&entry, &ssid);
			} else if (!g_strcmp0(key, SERVICE_KEY_SECURITY)) {
				dbus_message_iter_get_basic(&entry, &security);
			}

			dbus_message_iter_next(&array);
		}

		if (!ssid || !security) {
			DBG("missing security and/or ssid");
			return __connman_error_invalid_arguments(msg);
		}

		if (__connman_service_string2security(security) ==
					CONNMAN_SERVICE_SECURITY_UNKNOWN) {
			DBG("invalid security %s", security);
			return __connman_error_invalid_arguments(msg);
		}

		for (ptr = ssid; *ptr; ptr++) {
			if (!isxdigit(*ptr)) {
				DBG("invalid ssid %s", ssid);
				return __connman_error_invalid_arguments(msg);
			}
		}

		if ((ptr - ssid) & 1) {
			DBG("invalid ssid length");
			return __connman_error_invalid_arguments(msg);
		}

		ident = g_strconcat(type, "_", device_ident, "_",
					ssid, "_managed_", security, NULL);
	}

	/* Lowercase the identifier */
	p = g_utf8_strdown(ident, -1);
	if (p) {
		g_free(ident);
		ident = p;
	}

	/* Decode settings */
	settings = g_key_file_new();
	dbus_message_iter_recurse(&iter, &array);
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		const char *key, *value;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);
		g_key_file_set_string(settings, ident, key, value);
		dbus_message_iter_next(&array);

		/* Find the name in the process of filling the keyfile */
		if (!g_strcmp0(key, SERVICE_KEY_NAME)) {
			name = value;
		}
	}

	/* If there's no name, generate one (again, this is wifi specific) */
	if (!name) {
		char *str = g_key_file_get_string(settings, ident,
						SERVICE_KEY_SSID, NULL);
		GBytes* ssid = gutil_hex2bytes(str, -1);
		if (ssid) {
			name = tmp_name = gsupplicant_utf8_from_bytes(ssid);
			g_bytes_unref(ssid);
		}
		g_free(str);
	}

	if (name) {
		const char *path;

		/* Actually create the service (or update the existing one) */
		DBG("%s \"%s\"", ident, name);
		path = __connman_service_create(service_type, ident, settings);
		if (path) {
			DBG("%s", path);
			reply = g_dbus_create_reply(msg,
					DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID);
		} else {
			/* Passing zero to get the generic Failed error */
			reply = __connman_error_failed(msg, 0);
		}
	} else {
		DBG("can't generate service name");
		reply = __connman_error_invalid_arguments(msg);
	}

	g_key_file_unref(settings);
	g_free(ident);
	return reply;
}

static DBusMessage *create_session(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	int err;

	DBG("conn %p", conn);

	err = __connman_session_create(msg);
	if (err < 0) {
		if (err == -EINPROGRESS)
			return NULL;

		return __connman_error_failed(msg, -err);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *destroy_session(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	int err;

	DBG("conn %p", conn);

	err = __connman_session_destroy(msg);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *request_private_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender;
	int  err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	err = __connman_private_network_request(msg, sender);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return NULL;
}

static DBusMessage *release_private_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path;
	int err;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __connman_private_network_release(path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static int parse_peers_service_specs(DBusMessageIter *array,
			const unsigned char **spec, int *spec_len,
			const unsigned char **query, int *query_len,
			int *version)
{
	*spec = *query = NULL;
	*spec_len = *query_len = *version = 0;

	while (dbus_message_iter_get_arg_type(array) ==
							DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, inter, value;
		const char *key;

		dbus_message_iter_recurse(array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &inter);

		if  (!g_strcmp0(key, "BonjourResponse")) {
			dbus_message_iter_recurse(&inter, &value);
			dbus_message_iter_get_fixed_array(&value,
							spec, spec_len);
		} else if (!g_strcmp0(key, "BonjourQuery")) {
			dbus_message_iter_recurse(&inter, &value);
			dbus_message_iter_get_fixed_array(&value,
							query, query_len);
		} else if (!g_strcmp0(key, "UpnpService")) {
			dbus_message_iter_get_basic(&inter, spec);
			*spec_len = strlen((const char *)*spec)+1;
		} else if (!g_strcmp0(key, "UpnpVersion")) {
			dbus_message_iter_get_basic(&inter, version);
		} else if (!g_strcmp0(key, "WiFiDisplayIEs")) {
			if (*spec || *query)
				return -EINVAL;

			dbus_message_iter_recurse(&inter, &value);
			dbus_message_iter_get_fixed_array(&value,
							spec, spec_len);
		} else
			return -EINVAL;

		dbus_message_iter_next(array);
	}

	if ((*query && !*spec && !*version) ||
				(!*spec && !*query) || (!*spec && *version))
		return -EINVAL;

	return 0;
}

static DBusMessage *register_peer_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const unsigned char *spec, *query;
	DBusMessageIter iter, array;
	int spec_len, query_len;
	dbus_bool_t master;
	const char *owner;
	int version;
	int ret;

	DBG("");

	owner = dbus_message_get_sender(msg);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	ret = parse_peers_service_specs(&array, &spec, &spec_len,
						&query, &query_len, &version);
	if (ret)
		goto error;

	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &master);

	ret = __connman_peer_service_register(owner, msg, spec, spec_len,
					query, query_len, version,master);
	if (!ret)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	if (ret == -EINPROGRESS)
		return NULL;
error:
	return __connman_error_failed(msg, -ret);
}

static DBusMessage *unregister_peer_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const unsigned char *spec, *query;
	DBusMessageIter iter, array;
	int spec_len, query_len;
	const char *owner;
	int version;
	int ret;

	DBG("");

	owner = dbus_message_get_sender(msg);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	ret = parse_peers_service_specs(&array, &spec, &spec_len,
						&query, &query_len, &version);
	if (ret)
		goto error;

	ret = __connman_peer_service_unregister(owner, spec, spec_len,
						query, query_len, version);
	if (!ret)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
error:
	return __connman_error_failed(msg, -ret);

}

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_METHOD("GetTechnologies",
			NULL, GDBUS_ARGS({ "technologies", "a(oa{sv})" }),
			get_technologies) },
	{ GDBUS_DEPRECATED_METHOD("RemoveProvider",
			GDBUS_ARGS({ "provider", "o" }), NULL,
			remove_provider) },
	{ GDBUS_METHOD("GetServices",
			NULL, GDBUS_ARGS({ "services", "a(oa{sv})" }),
			get_services) },
	{ GDBUS_METHOD("GetPeers",
			NULL, GDBUS_ARGS({ "peers", "a(oa{sv})" }),
			get_peers) },
	{ GDBUS_DEPRECATED_ASYNC_METHOD("ConnectProvider",
			      GDBUS_ARGS({ "provider", "a{sv}" }),
			      GDBUS_ARGS({ "path", "o" }),
			      connect_provider) },
	{ GDBUS_METHOD("RegisterAgent",
			GDBUS_ARGS({ "path", "o" }), NULL,
			register_agent) },
	{ GDBUS_METHOD("UnregisterAgent",
			GDBUS_ARGS({ "path", "o" }), NULL,
			unregister_agent) },
	{ GDBUS_METHOD("RegisterCounter",
			GDBUS_ARGS({ "path", "o" }, { "accuracy", "u" },
					{ "period", "u" }),
			NULL, register_counter) },
	{ GDBUS_METHOD("UnregisterCounter",
			GDBUS_ARGS({ "path", "o" }), NULL,
			unregister_counter) },
	{ GDBUS_METHOD("ResetCounters",
			GDBUS_ARGS({ "type", "s" }), NULL,
			reset_counters) },
	{ GDBUS_METHOD("CreateService",
			GDBUS_ARGS({ "service_type", "s" },
					{ "device_ident", "s" },
					{ "network_ident", "s" },
					{ "settings", "a(ss)" }),
			GDBUS_ARGS({ "service", "o" }),
			create_service) },
	{ GDBUS_ASYNC_METHOD("CreateSession",
			GDBUS_ARGS({ "settings", "a{sv}" },
						{ "notifier", "o" }),
			GDBUS_ARGS({ "session", "o" }),
			create_session) },
	{ GDBUS_METHOD("DestroySession",
			GDBUS_ARGS({ "session", "o" }), NULL,
			destroy_session) },
	{ GDBUS_ASYNC_METHOD("RequestPrivateNetwork",
			      NULL, GDBUS_ARGS({ "path", "o" },
					       { "settings", "a{sv}" },
					       { "socket", "h" }),
			      request_private_network) },
	{ GDBUS_METHOD("ReleasePrivateNetwork",
			GDBUS_ARGS({ "path", "o" }), NULL,
			release_private_network) },
	{ GDBUS_ASYNC_METHOD("RegisterPeerService",
			GDBUS_ARGS({ "specification", "a{sv}" },
				   { "master", "b" }), NULL,
			register_peer_service) },
	{ GDBUS_METHOD("UnregisterPeerService",
			GDBUS_ARGS({ "specification", "a{sv}" }), NULL,
			unregister_peer_service) },
	{ },
};

static const GDBusSignalTable manager_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ GDBUS_SIGNAL("TechnologyAdded",
			GDBUS_ARGS({ "path", "o" },
				   { "properties", "a{sv}" })) },
	{ GDBUS_SIGNAL("TechnologyRemoved",
			GDBUS_ARGS({ "path", "o" })) },
	{ GDBUS_SIGNAL("ServicesChanged",
			GDBUS_ARGS({ "changed", "a(oa{sv})" },
					{ "removed", "ao" })) },
	{ GDBUS_SIGNAL("PeersChanged",
			GDBUS_ARGS({ "changed", "a(oa{sv})" },
					{ "removed", "ao" })) },
	{ },
};

int __connman_manager_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (!connection)
		return -1;

	if (connman_notifier_register(&technology_notifier) < 0)
		connman_error("Failed to register technology notifier");

	g_dbus_register_interface(connection, CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					manager_methods,
					manager_signals, NULL, NULL, NULL);

	connman_state_idle = true;

	return 0;
}

void __connman_manager_cleanup(void)
{
	DBG("");

	if (!connection)
		return;

	connman_notifier_unregister(&technology_notifier);

	g_dbus_unregister_interface(connection, CONNMAN_MANAGER_PATH,
						CONNMAN_MANAGER_INTERFACE);

	dbus_connection_unref(connection);

	__connman_access_manager_policy_free(manager_access_policy);
	manager_access_policy = NULL;
}
