/*
 *  ConnMan storage unit tests
 *
 *  Copyright (C) 2020  Jolla Ltd.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
 *  Contact: jussi.laakkonen@jolla.com
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <glib/gstdio.h>
#include <unistd.h>
#include <errno.h>
#include <gdbus.h>
#include <dbus/dbus.h>
#include "dbus.h"

#include "src/connman.h"

#define TEST_PREFIX "/storage"
#define TEST_PATH_PREFIX "connman_test"
#define PROPER_SENDER ":1.1"
#define IMPROPER_SENDER ":1.2"

static gboolean dbus_on = FALSE;
static gboolean dbus_register_on = FALSE;
static int ptr = 0x12345678;
static int ptr2 = 0x12341234;
static GDBusMethodFunction connmand_method = NULL;
static void *connmand_data = NULL;
static GDBusMethodFunction vpnd_method = NULL;
static void *vpnd_data = NULL;
static GHashTable *technology_methods = NULL;
static const char *test_user_dir = ".local/share";

struct technology_dbus_item {
	GDBusMethodFunction function;
	void *data;
};

static struct technology_dbus_item *new_technology_dbus_item(
			GDBusMethodFunction function, void *data)
{
	struct technology_dbus_item *item;

	item = g_new0(struct technology_dbus_item, 1);
	g_assert(item);

	item->function = function;
	item->data = data;

	return item;
}

static void free_technology_dbus_item(void *data)
{
	struct technology_dbus_item *item = data;
	g_free(item);
}

/* dummies */
DBusConnection *connman_dbus_get_connection(void)
{
	/* Return something non NULL */
	if (dbus_on)
		return (DBusConnection*)&ptr;

	return NULL;
}

dbus_bool_t connman_dbus_property_changed_basic(const char *path,
				const char *interface, const char *key,
							int type, void *val)
{
	return TRUE;
}

/* Copy from dbus.c */
void connman_dbus_property_append_basic(DBusMessageIter *iter,
					const char *key, int type, void *val)
{
	DBusMessageIter value;
	const char *signature;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);

	switch (type) {
	case DBUS_TYPE_BOOLEAN:
		signature = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DBUS_TYPE_STRING:
		signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		signature = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_UINT16:
		signature = DBUS_TYPE_UINT16_AS_STRING;
		break;
	case DBUS_TYPE_INT16:
		signature = DBUS_TYPE_INT16_AS_STRING;
		break;
	case DBUS_TYPE_UINT32:
		signature = DBUS_TYPE_UINT32_AS_STRING;
		break;
	case DBUS_TYPE_INT32:
		signature = DBUS_TYPE_INT32_AS_STRING;
		break;
	case DBUS_TYPE_UINT64:
		signature = DBUS_TYPE_UINT64_AS_STRING;
		break;
	case DBUS_TYPE_INT64:
		signature = DBUS_TYPE_INT64_AS_STRING;
		break;
	case DBUS_TYPE_OBJECT_PATH:
		signature = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	default:
		signature = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
							signature, &value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(iter, &value);
}

void dbus_connection_unref(DBusConnection *connection)
{
	return;
}

dbus_bool_t dbus_connection_send(DBusConnection *connection,
				DBusMessage *message, dbus_uint32_t *serial)
{
	return dbus_on;
}

enum dbus_mode_t {
	DBUS_MODE_USER_CHANGE_TO_CONNMAND,
	DBUS_MODE_USER_CHANGE_TO_VPND,
	DBUS_MODE_USER_CHANGE_TO_CALLER,
	DBUS_MODE_NONE
};

static enum dbus_mode_t dbus_mode = DBUS_MODE_NONE;
static DBusMessage* last_message = NULL;
static DBusMessage* last_reply = NULL;
static DBusMessage* last_reply_error = NULL;
static DBusPendingCall* last_pending_call = NULL;
static DBusPendingCallNotifyFunction last_pending_function = NULL;
static void* last_pending_function_data = NULL;
static dbus_uint32_t message_serial = 0;

dbus_bool_t dbus_connection_send_with_reply(DBusConnection *connection,
					DBusMessage *message,
					DBusPendingCall **pending_return,
					int timeout_milliseconds)
{
	DBG("connection %p message %p call %p", connection, message,
				pending_return);
	g_assert(connection);
	g_assert(message);

	switch (dbus_mode) {
	case DBUS_MODE_NONE:
		return false;

	case DBUS_MODE_USER_CHANGE_TO_CONNMAND:
		if (!connmand_method)
			return false;

		DBG("message %p to connmand", message);

		dbus_message_set_serial(message, ++message_serial);
		last_message = dbus_message_ref(message);

		if (pending_return) {
			last_pending_call = (DBusPendingCall*)&ptr2;
			*pending_return = last_pending_call;
		}

		dbus_mode = DBUS_MODE_USER_CHANGE_TO_VPND;

		return true;

	case DBUS_MODE_USER_CHANGE_TO_VPND:
		if (!vpnd_method)
			return false;

		if (last_message)
			dbus_message_unref(last_message);

		DBG("message %p to vpnd", message);

		if (pending_return) {
			last_pending_call = (DBusPendingCall*)&ptr2;
			*pending_return = last_pending_call;
		}

		dbus_message_set_serial(message, ++message_serial);
		dbus_message_set_sender(message, PROPER_SENDER);
		last_message = dbus_message_ref(message);

		dbus_mode = DBUS_MODE_USER_CHANGE_TO_CALLER;

		return true;
	case DBUS_MODE_USER_CHANGE_TO_CALLER:
		if (last_message)
			dbus_message_unref(last_message);

		DBG("message %p back to caller", message);

		dbus_message_set_serial(message, ++message_serial);
		last_message = dbus_message_ref(message);

		return true;
	default:
		return false;
	}
}

dbus_bool_t dbus_pending_call_set_notify(DBusPendingCall *pending,
			DBusPendingCallNotifyFunction function,
			void *user_data, DBusFreeFunction free_user_data)
{
	g_assert(pending);
	g_assert(function);
	g_assert(user_data);

	DBG("pending %p function %p user_data %p", pending, function,
				user_data);

	if (!dbus_on)
		return FALSE;

	g_assert(pending == last_pending_call);

	last_pending_function = function;
	last_pending_function_data = user_data;

	return TRUE;
}

bool steal_reply_error = false;

DBusMessage* dbus_pending_call_steal_reply(DBusPendingCall *pending)
{
	g_assert(pending);
	g_assert(pending == last_pending_call);

	DBG("pending %p", pending);

	if (steal_reply_error) {
		DBG("error reply %p", last_reply_error);
		return last_reply_error;
	}

	DBG("reply %p", last_reply);
	return last_reply;
}

DBusMessage *g_dbus_create_error_valist(DBusMessage *message, const char *name,
					const char *format, va_list args)
{
	char str[1024];

	if (format)
		vsnprintf(str, sizeof(str), format, args);
	else
		str[0] = '\0';

	return dbus_message_new_error(message, name, str);
}

DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...)
{
	va_list args;
	DBusMessage *reply;

	g_assert(message);

	DBG("message %p serial %u name %s format %s", message,
				dbus_message_get_serial(message),
				name, format);

	va_start(args, format);

	reply = g_dbus_create_error_valist(message, name, format, args);

	va_end(args);

	DBG("created error %p", reply);

	return reply;
}

DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...)
{
	g_assert(message);

	DBG("message %p", message);

	return dbus_message_new_method_return(message);
}

/* Error reply to method call */
gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message)
{
	g_assert(connection);
	g_assert(message);

	DBG("connection %p message %p", connection, message);

	if (last_reply_error)
		dbus_message_unref(last_reply_error);

	if (!dbus_on)
		return FALSE;

	last_reply_error = dbus_message_ref(message);

	return TRUE;
}

gboolean g_dbus_send_message_with_reply(DBusConnection *connection,
					DBusMessage *message,
					DBusPendingCall **call, int timeout)
{
	return dbus_connection_send_with_reply(connection, message, call,
				timeout);
}

/* OK reply to method call */
gboolean g_dbus_send_reply(DBusConnection *connection,
				DBusMessage *message, int type, ...)
{
	g_assert(connection);
	g_assert(message);

	DBG("connection %p message %p", connection, message);

	if (last_reply)
		dbus_message_unref(last_reply);

	if (!dbus_on)
		return FALSE;

	last_reply = g_dbus_create_reply(message, type);
	dbus_message_unref(message);

	return TRUE;
}

gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy)
{
	g_assert(connection);
	g_assert(path);
	g_assert(methods);

	if (!dbus_register_on)
		return dbus_register_on;

	if (g_str_equal(methods[0].name, "ChangeUser")) {
		if (!g_strcmp0(name, "net.connman.vpn.Storage")) {
			DBG("VPN method register");
			vpnd_method = methods[0].function;
			vpnd_data = user_data;
		} else if (!g_strcmp0(name, "net.connman.Storage")) {
			DBG("main method register");
			connmand_method = methods[0].function;
			connmand_data = user_data;
		} else {
			DBG("invalid interface name \"%s\"", name);
			g_assert(false);
		}
	} else if (g_str_has_prefix(name, "net.connman.Technology")) {

		if (g_str_equal(methods[1].name, "SetProperty")) {
			if (!technology_methods)
				technology_methods = g_hash_table_new_full(
						g_str_hash,
						g_str_equal,
						g_free,
						free_technology_dbus_item);

			DBG("technology SetProperty register on path %s",
						path);
			struct technology_dbus_item *item =
						new_technology_dbus_item(
						methods[1].function,user_data);
			g_hash_table_replace(technology_methods,
						g_strdup(path), item);
		}
	}

	return dbus_register_on;
}

gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name)
{
	g_assert(connection);
	g_assert(path);

	if (!g_strcmp0(name, "net.connman.vpn.Storage")) {
		DBG("VPN method unregister");
		g_assert(vpnd_method);
		vpnd_method = NULL;
		vpnd_data = NULL;
	} else if (!g_strcmp0(name, "net.connman.Storage")) {
		DBG("main method unregister");
		g_assert(connmand_method);
		connmand_method = NULL;
		connmand_data = NULL;
	} else if (!g_strcmp0(name, "net.connman.Technology")) {
		DBG("technology method unregister");

		if (!technology_methods)
			return dbus_register_on;

		g_assert_true(g_hash_table_contains(technology_methods, path));
		g_assert_true(g_hash_table_remove(technology_methods, path));

		if (!g_hash_table_size(technology_methods)) {
			g_hash_table_destroy(technology_methods);
			technology_methods = NULL;
		}
	} else {
		DBG("invalid interface name \"%s\"", name);
		g_assert(false);
	}

	return dbus_register_on;
}

gboolean g_dbus_emit_signal(DBusConnection *connection,
				const char *path, const char *interface,
				const char *name, int type, ...)
{
	return TRUE;
}

static guint watch_id = 123654798;
static GDBusWatchFunction connect_watch = NULL;
static GDBusWatchFunction disconnect_watch = NULL;

guint g_dbus_add_service_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction connect,
				GDBusWatchFunction disconnect,
				void *user_data, GDBusDestroyFunction destroy)
{
	g_assert(name);
	g_assert(connect);
	g_assert(disconnect);

	g_assert_cmpstr(name, ==, "net.connman.vpn");

	connect_watch = connect;
	disconnect_watch = disconnect;

	return watch_id;
}

gboolean g_dbus_remove_watch(DBusConnection *connection, guint id)
{
	return id == watch_id;
}

const char *__connman_service_type2string(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return "system";
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "cellular";
	case CONNMAN_SERVICE_TYPE_GPS:
		return "gps";
	case CONNMAN_SERVICE_TYPE_VPN:
		return "vpn";
	case CONNMAN_SERVICE_TYPE_GADGET:
		return "gadget";
	case CONNMAN_SERVICE_TYPE_P2P:
		return "p2p";
	}

	return NULL;
}

struct connman_device {
	int index;
	enum connman_device_type type;
	const char *ident;
	const char *ifname;
	bool powered;
	bool enabled;
	bool scanning;
};

static struct connman_device test_device1 = {
	.index = 100,
	.type = CONNMAN_DEVICE_TYPE_CELLULAR,
	.ident = "cellular123",
	.ifname = "rndis0",
	.powered = false,
	.enabled = false,
	.scanning = false,
};

static struct connman_technology_driver test_device1_driver = {
	.name = "cellular_test",
	.type = CONNMAN_SERVICE_TYPE_CELLULAR,
};

static struct connman_device test_device2 = {
	.index = 101,
	.type = CONNMAN_DEVICE_TYPE_WIFI,
	.ident = "wifi456",
	.ifname = "wifi0",
	.powered = false,
	.enabled = false,
	.scanning = false,
};

static struct connman_technology_driver test_device2_driver = {
	.name = "wifi_test",
	.type = CONNMAN_SERVICE_TYPE_WIFI,
};

static struct connman_device test_device3 = {
	.index = 102,
	.type = CONNMAN_DEVICE_TYPE_UNKNOWN,
	.ident = "xxx789",
	.ifname = "rndis0",
	.powered = false,
	.enabled = false,
	.scanning = false,
};

int __connman_device_request_scan(enum connman_service_type type)
{
	return 0;
}

int __connman_device_request_scan_full(enum connman_service_type type)
{
	return 0;
}


int connman_device_set_scanning(struct connman_device *device,
				enum connman_service_type type, bool scanning)
{
	return 0;
}

int connman_device_set_regdom(struct connman_device *device,
						const char *alpha2)
{
	return device ? 0 : -EINVAL;
}

enum connman_service_type __connman_device_get_service_type(
				struct connman_device *device)
{
	switch (device->type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
		break;
	case CONNMAN_DEVICE_TYPE_GPS:
		return CONNMAN_SERVICE_TYPE_GPS;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	case CONNMAN_DEVICE_TYPE_WIFI:
		return CONNMAN_SERVICE_TYPE_WIFI;
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	case CONNMAN_DEVICE_TYPE_CELLULAR:
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	case CONNMAN_DEVICE_TYPE_GADGET:
		return CONNMAN_SERVICE_TYPE_GADGET;

	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

int __connman_service_check_passphrase(enum connman_service_security security,
		const char *passphrase)
{
	return 0;
}

bool connman_device_get_powered(struct connman_device *device)
{
	return device ? device->powered : false;
}

int __connman_device_enable(struct connman_device *device)
{
	DBG("device %p:%s", device, device->ident);

	if (!device)
		return -EINVAL;

	if (device->enabled)
		return -EALREADY;

	device->enabled = true;

	return 0;
}

int __connman_device_disable(struct connman_device *device)
{
	DBG("device %p:%s", device, device->ident);

	if (!device)
		return -EINVAL;

	if (!device->enabled)
		return -EALREADY;

	device->enabled = false;

	return 0;
}

bool connman_device_get_scanning(struct connman_device *device,
						enum connman_service_type type)
{
	return device->scanning;
}

struct connman_device *connman_device_find_by_index(int index)
{
	switch (index) {
	case 100:
		return &test_device1;
	case 101:
		return &test_device2;
	case 102:
		return &test_device3;
	default:
		return NULL;
	}
}

void __connman_device_stop_scan(enum connman_service_type type)
{
	return;
}

char *connman_inet_ifname(int index)
{
	struct connman_device *dev;

	dev = connman_device_find_by_index(index);

	if (!dev)
		return NULL;

	return g_strdup(dev->ifname);
}

bool connman_setting_get_bool(const char *key)
{
	return true;
}

char **connman_setting_get_string_list(const char *key)
{
	return NULL;
}

const char *__connman_tethering_get_bridge(void)
{
	return "bridge";
}

int __connman_tethering_set_enabled(void)
{
	return 0;
}

void __connman_tethering_set_disabled(void)
{
	return;
}

void __connman_notifier_tethering_changed(struct connman_technology* tech,
								bool on)
{
	return;
}

void __connman_notifier_offlinemode(bool enabled)
{
	return;
}

int __connman_rfkill_block(enum connman_service_type type, bool block)
{
	return 0;
}

struct connman_access_tech_policy {
	int unused;
};

struct connman_access_tech_policy *__connman_access_tech_policy_create
							(const char *spec)
{
	return g_new0(struct connman_access_tech_policy, 1);
}

void __connman_access_tech_policy_free(struct connman_access_tech_policy *p)
{
	g_free(p);
}

enum connman_access __connman_access_tech_set_property
		(const struct connman_access_tech_policy *p, const char *name,
			const char *sender, enum connman_access default_access)
{
	return CONNMAN_ACCESS_ALLOW;
}

void __connman_peer_disconnect_all(void)
{
	return;
}

struct passwd {
	char   *pw_name;       /* username */
	char   *pw_passwd;     /* user password */
	uid_t   pw_uid;        /* user ID */
	gid_t   pw_gid;        /* group ID */
	char   *pw_gecos;      /* user information */
	char   *pw_dir;        /* home directory */
	char   *pw_shell;      /* shell program */
};

#define UID_ROOT	0
#define UID_USER	1000
#define UID_USER2	1001
#define UID_INVALID	9999
#define UID_HTTP	2

static struct passwd passwd_list[] = {
	{
		.pw_name = "root",
		.pw_uid = UID_ROOT,
		.pw_shell = "/bin/bash",
		.pw_dir = NULL,
	},
	{
		.pw_name = "user",
		.pw_uid = UID_USER,
		.pw_shell = "/bin/sh",
		.pw_dir = NULL,
	},
	{
		.pw_name = "user2",
		.pw_uid = UID_USER2,
		.pw_shell = "/usr/bin/sh",
		.pw_dir = NULL,
	},
	{
		.pw_name = "invalid",
		.pw_uid = UID_INVALID,
		.pw_shell = "/usr/bin/nologin",
		.pw_dir = NULL,
	},
	{
		.pw_name = "http",
		.pw_uid = UID_HTTP,
		.pw_shell = "/bin/false",
		.pw_dir = NULL,
	}
};

static const char* user_pw_dir_root = NULL;

static void set_user_pw_dir_root(const char *user_root)
{
	user_pw_dir_root = user_root;
}

struct passwd *getpwuid(uid_t uid)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS(passwd_list); i++) {
		if (passwd_list[i].pw_uid == uid) {
			if (user_pw_dir_root) {
				if (passwd_list[i].pw_dir)
					g_free(passwd_list[i].pw_dir);

				passwd_list[i].pw_dir =
					g_build_filename(user_pw_dir_root,
					passwd_list[i].pw_name, NULL);
			}

			return &passwd_list[i];
		}
	}

	return NULL;
}

static void clean_pwd()
{
	int i;

	for (i = 0; i < G_N_ELEMENTS(passwd_list); i++) {
		if (passwd_list[i].pw_dir) {
			g_free(passwd_list[i].pw_dir);
			passwd_list[i].pw_dir = NULL;
		}
	}
}

uid_t geteuid(void)
{
	return 0;
}

static char *user_shells[] = { "/bin/sh", "/bin/bash", "/usr/bin/sh",
			"/usr/bin/bash", NULL };

static int shell_counter = 0;

void setusershell(void)
{
	shell_counter = 0;
}

char *getusershell(void)
{
	/* EOF returns NULL, this simulates that behavior */
	if (!user_shells[shell_counter])
		return user_shells[shell_counter];

	return user_shells[shell_counter++];
}

void endusershell(void)
{
	shell_counter = 0;
}


/* EOF dummies */

static void init_dbus(gboolean register_on)
{
	dbus_on = TRUE;
	dbus_register_on = register_on;
	dbus_mode = DBUS_MODE_USER_CHANGE_TO_CONNMAND;
}

static void clean_dbus(void)
{
	dbus_on = FALSE;
	dbus_register_on = FALSE;
	dbus_mode = DBUS_MODE_NONE;

	if (last_message)
		dbus_message_unref(last_message);

	if (last_reply)
		dbus_message_unref(last_reply);

	if (last_reply_error)
		dbus_message_unref(last_reply_error);

	last_message = NULL;
	last_reply = NULL;
	last_reply_error = NULL;
	last_pending_call = NULL;
	last_pending_function = NULL;
	last_pending_function_data = NULL;
	steal_reply_error = false;

	clean_pwd();
}

static void set_reply_error(DBusMessage *reply_error)
{
	if (last_reply_error)
		dbus_message_unref(last_reply_error);

	last_reply_error = dbus_message_ref(reply_error);
	steal_reply_error = true;
}

static void set_reply(DBusMessage *reply)
{
	if (last_reply)
		dbus_message_unref(last_reply);

	last_reply = dbus_message_ref(reply);
	steal_reply_error = false;
}

static gchar* setup_test_directory()
{
	gchar *test_path = NULL;

	test_path = g_strdup_printf("%s/%s.XXXXXX", g_get_tmp_dir(),
				TEST_PATH_PREFIX);
	g_assert(test_path);

	test_path = g_mkdtemp_full(test_path, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
	g_assert(test_path);

	DBG("setup test dir %s", test_path);

	g_assert_true(g_file_test(test_path, G_FILE_TEST_EXISTS));
	g_assert_true(g_file_test(test_path, G_FILE_TEST_IS_DIR));
	g_assert_cmpint(g_access(test_path, R_OK), ==, 0);
	g_assert_cmpint(g_access(test_path, W_OK), ==, 0);
	g_assert_cmpint(g_access(test_path, X_OK), ==, 0);
	g_assert_cmpint(g_access(test_path, R_OK|W_OK|X_OK), ==, 0);

	return test_path;
}

static int rmdir_r(const gchar* path)
{
	DIR *d = opendir(path);

	if (d) {
		const struct dirent *p;
		int r = 0;

		while (!r && (p = readdir(d))) {
			char *buf;
			struct stat st;

			if (!strcmp(p->d_name, ".") ||
						!strcmp(p->d_name, "..")) {
				continue;
			}

			buf = g_strdup_printf("%s/%s", path, p->d_name);
			if (!stat(buf, &st)) {
				r =  S_ISDIR(st.st_mode) ? rmdir_r(buf) :
								unlink(buf);
			}
			g_free(buf);
		}
		closedir(d);
		return r ? r : rmdir(path);
	} else {
		return -1;
	}
}

static void cleanup_test_directory(gchar *test_path)
{
	gint access_mode = R_OK|W_OK|X_OK;

	if (g_file_test(test_path, G_FILE_TEST_IS_DIR)) {
		g_assert(!access(test_path, access_mode));
		rmdir_r(test_path);
	}
}

static gchar* format_content(gchar **content_in)
{
	const gchar separator[] = "\n";
	gchar *content_out;

	if (!content_in || g_strv_length(content_in) == 0)
		content_out = g_strdup("");
	else
		content_out = g_strjoinv(separator, content_in);

	return content_out;
}

static void verify_content(const char *file, gchar *content)
{
	gchar *content_verify = NULL;
	gsize content_verify_len = 0;

	g_assert(g_file_get_contents(file, &content_verify,
				&content_verify_len, NULL));
	g_assert_cmpint(g_ascii_strcasecmp(content, content_verify), ==, 0);

	g_free(content_verify);
}

static void set_and_verify_content(const gchar *file, gchar **content_in)
{
	gchar *content;

	g_assert(file);

	content = format_content(content_in);
	DBG("set file %s content:%s", file, content);

	g_assert_true(g_file_set_contents(file, content, -1, NULL));
	verify_content(file, content);

	g_free(content);
}

static void storage_test_basic1()
{
	gchar *connman_path;
	gchar *vpn_path;
	mode_t m_dir = 0;
	mode_t m_file = 0;

	g_assert_cmpint(__connman_storage_init(NULL, NULL, m_dir, m_file),
						==, -EINVAL);
	g_assert_cmpint(__connman_storage_init(NULL, test_user_dir, m_dir,
						m_file), ==, -EINVAL);
	g_assert_cmpint(__connman_storage_init(DEFAULT_STORAGE_ROOT,
						DEFAULT_USER_STORAGE, m_dir,
						m_file), ==, 0);
	connman_path = g_build_filename(DEFAULT_STORAGE_ROOT, "connman", NULL);
	vpn_path = g_build_filename(DEFAULT_STORAGE_ROOT, "connman-vpn", NULL);
	g_assert(!g_strcmp0(STORAGEDIR, connman_path));
	g_assert(!g_strcmp0(VPN_STORAGEDIR, vpn_path));
	g_assert(STORAGE_DIR_MODE == m_dir);
	g_assert(STORAGE_FILE_MODE == m_file);
	g_assert_cmpint(__connman_storage_create_dir(NULL, m_dir), ==,
								-EINVAL);
	__connman_storage_cleanup();

	cleanup_test_directory(connman_path);
	cleanup_test_directory(vpn_path);

	g_free(connman_path);
	g_free(vpn_path);
}

static void storage_test_basic2()
{
	gchar *test_path;
	gchar *connman_path;
	gchar *vpn_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	connman_path = g_build_filename(test_path, "connman", NULL);
	vpn_path = g_build_filename(test_path, "connman-vpn", NULL);

	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert(!g_strcmp0(STORAGEDIR, connman_path));
	g_assert(!g_strcmp0(VPN_STORAGEDIR, vpn_path));
	g_assert(__connman_storage_dir_mode() == m_dir);
	g_assert(__connman_storage_file_mode() == m_file);

	/* No D-Bus available, register fails */
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, -ENOTCONN);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, -ENOTCONN);

	init_dbus(FALSE);

	/* STATE or USER types are not valid */
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_STATE, NULL), ==, -EINVAL);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_USER, NULL), ==, -EINVAL);

	/* Register fails */
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, -ENOENT);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, -ENOENT);

	init_dbus(TRUE);

	/* connmand register succeeds */
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, 0);
	__connman_storage_cleanup();

	/* vpnd register succeeds */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, 0);
	__connman_storage_cleanup();

	/* Register succeeds but unregister will return false */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, 0);
	clean_dbus(); 
	__connman_storage_cleanup();

	cleanup_test_directory(test_path);

	g_free(connman_path);
	g_free(vpn_path);
	g_free(test_path);
}

static void storage_test_basic3()
{
	gchar *test_path;
	gchar *connman_path;
	gchar *vpn_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	GKeyFile *keyfile;

	test_path = setup_test_directory();
	connman_path = g_build_filename(test_path, "connman", NULL);
	vpn_path = g_build_filename(test_path, "connman-vpn", NULL);

	init_dbus(TRUE);

	/* Main */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_true(g_file_test(STORAGEDIR, G_FILE_TEST_IS_DIR));

	/* Should return 0 as the dir exists */
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	__connman_inotify_init();

	g_assert_null(__connman_storage_load_config(NULL));
	g_assert_null(__connman_storage_load_config(""));
	g_assert_null(__connman_storage_load_config("wifi1conf"));
	g_assert_null(__connman_storage_load_provider_config(NULL));
	g_assert_null(__connman_storage_load_provider_config(""));
	g_assert_null(__connman_storage_load_provider_config("provider1conf"));

	g_assert_null(connman_storage_load_service(NULL));
	g_assert_null(connman_storage_load_service(""));
	g_assert_null(connman_storage_load_service("wifi1"));
	g_assert_cmpint(__connman_storage_save_service(NULL, NULL), !=, 0);
	g_assert_cmpint(__connman_storage_save_service(NULL, ""), !=, 0);
	g_assert_cmpint(__connman_storage_save_service(NULL, "wifi1"), !=, 0);
	g_assert_false(__connman_storage_remove_service(NULL));
	g_assert_false(__connman_storage_remove_service(""));
	g_assert_false(__connman_storage_remove_service("wifi1"));
	g_assert_null(connman_storage_get_services());

	/*
	 * Create a service from a new keyfile, save it before cleanup to
	 * be able to fool storage to load it as inotify is not running in
	 * tests.
	 */
	keyfile = g_key_file_new();
	g_key_file_set_value(keyfile, "wifi_1_managed_psk", "Name", "wifi1");
	g_key_file_set_value(keyfile, "wifi_1_managed_psk", "SSID",
				"444e412d4d6f6b6b756c612d35472d444");
	g_key_file_set_value(keyfile, "wifi_1_managed_psk", "Frequency",
				"2417");
	g_assert_cmpint(__connman_storage_save_service(keyfile,
				"wifi_1_managed_psk"), ==, 0);
	g_key_file_unref(keyfile);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	/* VPNd */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(VPN_STORAGEDIR, m_dir),
									==, 0);
	g_assert_true(g_file_test(VPN_STORAGEDIR, G_FILE_TEST_IS_DIR));
	__connman_inotify_init();

	g_assert_null(__connman_storage_load_provider(NULL));
	g_assert_null(__connman_storage_load_provider("provider1"));

	/* No return value, just run these */
	__connman_storage_save_provider(NULL, NULL);
	__connman_storage_save_provider(NULL, "provider1");

	g_assert_false(__connman_storage_remove_provider(NULL));
	g_assert_false(__connman_storage_remove_provider("provider1"));
	g_assert_null(__connman_storage_get_providers());

	/* And provider for VPN */
	keyfile = g_key_file_new();
	g_key_file_set_value(keyfile, "provider_123", "Name", "VPN1");
	g_key_file_set_value(keyfile, "provider_123", "Type", "openvpn");
	g_key_file_set_value(keyfile, "provider_123", "Host", "1.1.1.1");
	__connman_storage_save_provider(keyfile, "123");
	g_key_file_unref(keyfile);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	/* Init main */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_true(g_file_test(STORAGEDIR, G_FILE_TEST_IS_DIR));

	/* Should return 0 as the dir exists */
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	__connman_inotify_init();

	/* Load the service */
	keyfile = connman_storage_load_service("wifi_1_managed_psk");
	g_assert(keyfile);
	g_assert_true(g_key_file_has_group(keyfile, "wifi_1_managed_psk"));
	g_key_file_unref(keyfile);

	gchar **services = connman_storage_get_services();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 1);
	g_assert_cmpstr(services[0], ==, "wifi_1_managed_psk");
	g_strfreev(services);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	/* VPNd */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(VPN_STORAGEDIR, m_dir),
									==, 0);
	g_assert_true(g_file_test(VPN_STORAGEDIR, G_FILE_TEST_IS_DIR));
	__connman_inotify_init();

	keyfile = __connman_storage_load_provider("123");
	g_assert(keyfile);
	g_assert_true(g_key_file_has_group(keyfile, "provider_123"));
	g_key_file_unref(keyfile);

	gchar **providers = __connman_storage_get_providers();
	g_assert(providers);
	g_assert_cmpint(g_strv_length(providers), ==, 1);
	g_assert_cmpstr(providers[0], ==, "provider_123");
	g_strfreev(providers);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	clean_dbus();

	cleanup_test_directory(test_path);

	g_free(connman_path);
	g_free(vpn_path);
	g_free(test_path);
}

static void storage_test_global1()
{
	gchar *test_path;
	gchar *connman_path;
	gchar *settings_file;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	GKeyFile *keyfile;

	test_path = setup_test_directory();
	connman_path = g_build_filename(test_path, "connman", NULL);

	init_dbus(TRUE);

	/* Main */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_true(g_file_test(STORAGEDIR, G_FILE_TEST_IS_DIR));

	/* Should return 0 as the dir exists */
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	__connman_inotify_init();

	/* No settings */
	g_assert_null(__connman_storage_load_global());
	g_assert_cmpint(__connman_storage_save_global(NULL), !=, 0);

	/* Create empty settings file */
	settings_file = g_build_filename(connman_path, "settings", NULL);
	set_and_verify_content(settings_file, NULL);

	g_assert((keyfile = __connman_storage_load_global()));
	g_assert_cmpint(__connman_storage_save_global(keyfile), ==, 0);

	__connman_storage_delete_global();
	g_assert_false(g_file_test(settings_file, G_FILE_TEST_EXISTS));

	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	clean_dbus();

	g_remove(settings_file);
	cleanup_test_directory(test_path);

	g_free(connman_path);
	g_free(test_path);
	g_free(settings_file);
}

static void storage_test_global2()
{
	gchar *test_path;
	gchar *connman_path;
	gchar *settings_file;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	GKeyFile *keyfile;
	GKeyFile *keyfile2;
	gchar *content[] = {
				"[global]",
				"OfflineMode=false",
				"",
				"[WiFi]",
				"Enable=true",
				"",
				"[Cellular]",
				"Enable=false",
				"",
				NULL,
	};

	test_path = setup_test_directory();
	connman_path = g_build_filename(test_path, "connman", NULL);

	init_dbus(TRUE);

	/* Main */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_true(g_file_test(STORAGEDIR, G_FILE_TEST_IS_DIR));

	/* Create settings file */
	settings_file = g_build_filename(connman_path, "settings", NULL);
	set_and_verify_content(settings_file, content);

	/* Should return 0 as the dir exists */
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	__connman_inotify_init();

	g_assert((keyfile = __connman_storage_load_global()));

	/* Second load should return from cache */
	g_assert((keyfile2 = __connman_storage_load_global()));
	g_assert(keyfile == keyfile2);

	g_assert_true(g_key_file_has_key(keyfile, "global", "OfflineMode",
				NULL));
	g_assert_false(g_key_file_get_boolean(keyfile, "global", "OfflineMode",
				NULL));

	g_assert_true(g_key_file_has_key(keyfile, "WiFi", "Enable", NULL));
	g_assert_true(g_key_file_get_boolean(keyfile, "WiFi", "Enable", NULL));

	g_assert_true(g_key_file_has_key(keyfile, "Cellular", "Enable", NULL));
	g_assert_false(g_key_file_get_boolean(keyfile, "Cellular", "Enable",
				NULL));

	/* Save and verify content */
	g_assert_cmpint(__connman_storage_save_global(keyfile), ==, 0);
	g_key_file_unref(keyfile);

	gchar *content_formatted = format_content(content);
	verify_content(settings_file, content_formatted);
	g_free(content_formatted);

	__connman_storage_delete_global();
	g_assert_false(g_file_test(settings_file, G_FILE_TEST_EXISTS));

	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	clean_dbus();

	g_remove(settings_file);
	cleanup_test_directory(test_path);

	g_free(settings_file);
	g_free(connman_path);
	g_free(test_path);
}

enum cb_functions {
	PRE_CB =		0,
	UNLOAD_CB =		1,
	LOAD_CB =		2,
	POST_CB =		3,
	FINALIZE_CB =		4,
	TOTAL_CB_COUNT = 	5,
};

int cb_counts[TOTAL_CB_COUNT] = { 0 };

static void clean_cb_counts()
{
	int i;

	for (i = 0; i < TOTAL_CB_COUNT; i++)
		cb_counts[i] = 0;
}

enum user_change_mode {
	USER_CHANGE_SUCCESS = 		0x0001,
	USER_CHANGE_INVALID_USER =	0x0002,
	USER_CHANGE_ERROR_REPLY =	0x0004,
	USER_CHANGE_ACCESS_DENIED =	0x0008,
	USER_CHANGE_ALREADY_SET =	0x0010,
	USER_CHANGE_VPN_CRASH =		0x0020,
	USER_CHANGE_VPN_ACCESS_DENIED =	0x0040,
};

static DBusMessage *create_dbus_error(DBusMessage *reply_to,
			const char *error_name)
{
	g_assert(reply_to);
	g_assert(error_name);

	return dbus_message_new_error(reply_to, error_name, NULL);
}

static const char *get_connman_error(const char *error_name)
{
	if (g_str_has_suffix(error_name, ".Timeout") ||
				g_str_has_suffix(error_name, "TimedOut"))
		return "net.connman.Error.OperationTimeout";


	if (g_str_has_suffix(error_name, ".NoReply"))
		return "net.connman.Error.NotFound";

	return NULL;
}

static uid_t current_uid = 0;

static void user_change_process(uid_t uid, enum user_change_mode mode,
			const char *error_name, bool fake_error,
			int *cb_checklist, int *vpn_cb_checklist)
{
	DBusMessage *change_user_msg;
	DBusMessage *change_user_reply;
	DBusConnection *connection;
	DBusError error;
	dbus_uint32_t user_id;
	int i;

	user_id = (dbus_uint32_t)uid;
	current_uid = UID_ROOT;

	connection = connman_dbus_get_connection();
	dbus_error_init(&error);

	/* Create user change message and "send" it */
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_UINT32, &user_id,
				DBUS_TYPE_INVALID));

	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));

	/* Process message in connmand */
	DBG("call connmand change_user()");
	g_assert(connmand_method);

	if (mode & USER_CHANGE_INVALID_USER ||
				mode & USER_CHANGE_ACCESS_DENIED ||
				mode & USER_CHANGE_ALREADY_SET) {
		DBusMessage *initial_reply;

		initial_reply = connmand_method(connection, last_message,
					connmand_data);

		g_assert_true(dbus_set_error_from_message(&error,
					initial_reply));

		g_assert_cmpstr(error.name, ==, error_name);
		dbus_error_free(&error);
		dbus_message_unref(initial_reply);
		dbus_message_unref(change_user_msg);

		return;
	}

	g_assert_null(connmand_method(connection, last_message,
					connmand_data));

	if (mode & USER_CHANGE_VPN_CRASH) {
		g_assert(disconnect_watch);
		g_assert(connect_watch);

		disconnect_watch(connection, NULL);
		connect_watch(connection, NULL);
	}


	if (fake_error) {
		DBG("fake error \"%s\" for user change", error_name);
		change_user_reply = create_dbus_error(last_message,
					error_name);
	} else {
		/* Call vpnd method and get return */
		DBG("call vpnd change user()");
		g_assert(vpnd_method);
		change_user_reply = vpnd_method(connection, last_message,
					vpnd_data);
	}

	g_assert(change_user_reply);

	if (mode & USER_CHANGE_SUCCESS) {
		g_assert_false(dbus_set_error_from_message(&error,
					change_user_reply));
		set_reply(change_user_reply);
	} else if (mode & USER_CHANGE_ERROR_REPLY) {
		g_assert_true(dbus_set_error_from_message(&error,
					change_user_reply));

		g_assert_cmpstr(error.name, ==, error_name);
		dbus_error_free(&error);

		set_reply_error(change_user_reply);

		dbus_error_init(&error);
	} else if (mode & USER_CHANGE_VPN_ACCESS_DENIED) {
		g_assert_true(dbus_set_error_from_message(&error,
					change_user_reply));

		g_assert_cmpstr(error.name, ==, error_name);
		dbus_error_free(&error);

		set_reply_error(change_user_reply);

		dbus_error_init(&error);
	} else {
		DBG("Invalid mode");
		g_assert(false);
	}

	if (vpn_cb_checklist) {
		DBG("verify vpn callback count");
		for (i = 0; i < TOTAL_CB_COUNT; i++) {
			g_assert_cmpint(cb_counts[i], ==, vpn_cb_checklist[i]);
			cb_counts[i] = 0;
		}
	}

	/* Call the pending callback */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	if (mode & USER_CHANGE_SUCCESS) {
		g_assert(last_reply);
		g_assert_null(last_reply_error);
	} else if (mode & USER_CHANGE_ERROR_REPLY) {
		const char* connman_error_name = NULL;

		g_assert_null(last_reply);
		g_assert(last_reply_error);
		g_assert(last_reply_error != change_user_reply);

		g_assert_true(dbus_set_error_from_message(&error,
					last_reply_error));

		/*
		 * If error is faked the error returned to user is a connman
		 * error, not the requested freedesktop error.
		 */
		if (fake_error && g_str_has_prefix(error_name,
					"org.freedesktop.DBus.Error"))
			connman_error_name = get_connman_error(error_name);
		else
			connman_error_name = error_name;

		g_assert_cmpstr(error.name, ==, connman_error_name);

		dbus_error_free(&error);
		dbus_message_unref(last_reply_error);
	}

	if (fake_error)
		dbus_message_unref(change_user_reply);

	dbus_message_unref(change_user_msg);

	if (cb_checklist) {
		DBG("verify callback count");
		for (i = 0; i < TOTAL_CB_COUNT; i++) {
			g_assert_cmpint(cb_counts[i], ==, cb_checklist[i]);
			cb_counts[i] = 0;
		}
	}
}

/* No user change, user is root, no callbacks */
static void storage_test_user_change1()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, 0);

	user_change_process(UID_ROOT, USER_CHANGE_ALREADY_SET,
				"net.connman.Error.AlreadyEnabled", false,
				NULL, NULL);

	__connman_storage_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Change to regular user, no callbacks*/
static void storage_test_user_change2()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, 0);

	user_change_process(UID_USER, USER_CHANGE_SUCCESS, NULL, false, NULL,
				NULL);

	__connman_storage_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Change to regular user and back to root, no callbacks*/
static void storage_test_user_change3()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, 0);

	user_change_process(UID_USER, USER_CHANGE_SUCCESS, NULL, false, NULL,
				NULL);

	clean_dbus();
	init_dbus(TRUE);

	user_change_process(UID_ROOT, USER_CHANGE_SUCCESS, NULL, false, NULL,
				NULL);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Do multiple user changes, no callbacks. */
static void storage_test_user_change4()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	const uid_t users[6] = { UID_USER, UID_USER2, UID_ROOT, UID_USER,
				UID_USER2, UID_ROOT };
	int i = 0;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, 0);

	while (i < 6) {
		user_change_process(users[i], USER_CHANGE_SUCCESS, NULL, false,
					NULL, NULL);
		clean_dbus();
		init_dbus(TRUE);
		i++;
	}

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static bool pre_cb(void)
{
	DBG("");
	cb_counts[PRE_CB]++;
	return true;
}

static int unload_items = 0;

static void unload_cb(char **items, int len)
{
	int i;

	DBG("items %p length %d", items, len);
	for (i = 0; i < len; i++) {
		DBG("%d: %s", i, items[i]);

		if (g_str_has_prefix(items[i], "provider_"))
			__connman_storage_remove_provider(items[i]);
		else
			__connman_storage_remove_service(items[i]);
	}

	cb_counts[UNLOAD_CB]++;

	unload_items = len;
}

static void load_cb(void)
{
	DBG("");
	cb_counts[LOAD_CB]++;
}

static bool post_cb(void)
{
	DBG("");
	cb_counts[POST_CB]++;
	return true;
}

static void finalize_cb(uid_t uid, void *user_data)
{
	DBG("");
	cb_counts[FINALIZE_CB]++;
}

static void uid_changed_cb(uid_t uid)
{
	DBG("cb called with uid %u", uid);
	current_uid = uid;
}

static struct connman_storage_callbacks callbacks = {
	.pre = pre_cb,
	.unload = unload_cb,
	.load = load_cb,
	.post = post_cb,
	.finalize = finalize_cb,
	.uid_changed = uid_changed_cb,
};

/* No user change, user is root, with callbacks */
static void storage_test_user_change5()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	int i;

	test_path = setup_test_directory();
	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);
	current_uid = 0;

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &callbacks), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &callbacks), ==, 0);

	user_change_process(UID_ROOT, USER_CHANGE_ALREADY_SET,
				"net.connman.Error.AlreadyEnabled", false,
				NULL, NULL);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	for (i = 0; i < TOTAL_CB_COUNT; i++)
		g_assert_cmpint(cb_counts[i], ==, 0);

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Change to regular user, with callbacks*/
static void storage_test_user_change6()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	int cb_checklist[TOTAL_CB_COUNT] = {2, 0, 1, 1, 1};
	int vpn_cb_checklist[TOTAL_CB_COUNT] = {1, 0, 1, 1, 1};

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);
	current_uid = 0;

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &callbacks), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &callbacks), ==, 0);

	user_change_process(UID_USER, USER_CHANGE_SUCCESS, NULL, false,
				cb_checklist, vpn_cb_checklist);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	clean_dbus();
	clean_cb_counts();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static void create_settings_file(const gchar *root_path, const gchar *name,
			gchar **content)
{
	gchar *settings_path;
	gchar *settings_file;
	int dir_mode = S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH;

	g_assert(root_path);
	g_assert(name);
	g_assert(content);

	settings_path = g_build_filename(root_path, name, NULL);
	g_assert(settings_path);
	DBG("create %s/%s/settings -> %s", root_path, name, settings_path);
	g_assert_cmpint(g_mkdir_with_parents(settings_path, dir_mode), ==, 0);

	g_assert_true(g_file_test(settings_path, G_FILE_TEST_EXISTS));
	g_assert_true(g_file_test(settings_path, G_FILE_TEST_IS_DIR));
	g_assert_cmpint(g_access(settings_path, F_OK), ==, 0);
	g_assert_cmpint(g_access(settings_path, R_OK|X_OK|W_OK), ==, 0);
	g_free(settings_path);

	settings_file = g_build_filename(root_path, name, "settings", NULL);
	g_assert(settings_file);
	set_and_verify_content(settings_file, content);
	g_free(settings_file);
}

static gboolean check_settings_file(const gchar *root_path, const gchar *name)
{
	gchar *settings_path;
	gchar *settings_file;
	gboolean path_exists;
	gboolean file_exists;
	gboolean is_vpn;
	gboolean rval = true;

	g_assert(root_path);
	g_assert(name);

	is_vpn = g_str_has_prefix(name, "provider_");

	settings_path = g_build_filename(root_path, name, NULL);
	path_exists = g_file_test(settings_path, G_FILE_TEST_EXISTS) &&
				g_file_test(settings_path, G_FILE_TEST_IS_DIR);
	g_free(settings_path);

	settings_file = g_build_filename(root_path, name, "settings", NULL);
	file_exists = g_file_test(settings_file, G_FILE_TEST_EXISTS) &&
				g_file_test(settings_file,
				G_FILE_TEST_IS_REGULAR);
	g_free(settings_file);

	if (is_vpn) {
		gchar **name_set = g_strsplit(name, "_", 2);
		g_assert(name_set);
		g_assert_cmpint(g_strv_length(name_set), ==, 2);

		/* Check that vpn_ prefix dir also exists */
		gchar *vpn_id = g_strdup_printf("vpn_%s", name_set[1]);

		rval = check_settings_file(root_path, vpn_id);

		g_free(vpn_id);
		g_strfreev(name_set);
	}

	return rval && path_exists && file_exists;
}

/* Change to regular user, with callbacks and files set.*/
static void storage_test_user_change7()
{
	DBusMessage *change_user_msg;
	DBusMessage *change_user_reply;
	DBusConnection *connection;
	DBusError error;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	/* Unload does not happen because vpnd uses same storage impl here. */
	int cb_checklist[TOTAL_CB_COUNT] = {2, 0, 1, 1, 1};
	/* Unload is called for the second user change */
	int user2_cb_checklist[TOTAL_CB_COUNT] = {2, 2, 1, 1, 1};
	int vpn_cb_checklist[TOTAL_CB_COUNT] = {1, 1, 1, 1, 1};
	int user2_vpn_cb_checklist[TOTAL_CB_COUNT] = {2, 0, 1, 1, 1};
	int i;

	/* Root service and provider files */
	gchar *root_wifi1[] = {
		"[wifi_1_managed_psk]",
		"Name=wifi1",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3447",
		"Frequency=2417",
		NULL
	};
	gchar *root_wifi2[] = {
		"[wifi_2_managed_psk]",
		"Name=wifi2",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3446",
		"Frequency=2416",
		NULL
	};
	gchar *root_vpn1[] = {
		"[1_2_3_4_root_org_1]",
		"Name=RootVPN1",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=root.org.1",
		NULL
	};
	gchar *root_vpn1_vpn[] = {
		"[vpn_1_2_3_4_root_org_1]",
		"Name=RootVPN1",
		NULL
	};
	gchar *root_vpn2[] = {
		"[1_2_3_4_root_org_2]",
		"Name=RootVPN2",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=root.org.2",
		NULL
	};
	gchar *root_vpn2_vpn[] = {
		"[vpn_1_2_3_4_root_org_2]",
		"Name=RootVPN2",
		NULL
	};

	/* user1 service and provider files */
	gchar *user_wifi1[] = {
		"[wifi_1_user1_managed_psk]",
		"Name=wifi1user1",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3447",
		"Frequency=2417",
		NULL
	};
	gchar *user_cellular1[] = {
		"[cellular_1_user_context1]",
		"Name=cellular1user",
		NULL
	};
	gchar *user_vpn1[] = {
		"[1_2_3_4_user_org_1]",
		"Name=UserVPN1",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=user.org.1",
		NULL
	};
	gchar *user_vpn1_vpn[] = {
		"[vpn_1_2_3_4_user_org_1]",
		"Name=UserVPN1",
		NULL
	};
	gchar *user_vpn2[] = {
		"[1_2_3_4_user_org_2]",
		"Name=UserVPN2",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=user.org.2",
		NULL
	};
	gchar *user_vpn2_vpn[] = {
		"[vpn_1_2_3_4_user_org_2]",
		"Name=UserVPN2",
		NULL
	};
	gchar *user_vpn3[] = {
		"[1_2_3_4_user_org_3]",
		"Name=UserVPN3",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=user.org.3",
		NULL
	};
	gchar *user_vpn3_vpn[] = {
		"[vpn_1_2_3_4_user_org_3]",
		"Name=UserVPN3",
		NULL
	};

	/* user2 service and provider files */
	gchar *user2_wifi1[] = {
		"[wifi_1_user2_managed_psk]",
		"Name=wifi1user2",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3447",
		"Frequency=2417",
		NULL
	};
	gchar *user2_wifi2[] = {
		"[wifi_2_user2_managed_psk]",
		"Name=wifi2user2",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3443",
		"Frequency=2415",
		NULL
	};
	gchar *user2_vpn1[] = {
		"[1_2_3_4_user2_org_1]",
		"Name=User2VPN1",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=user2.org.1",
		NULL
	};
	gchar *user2_vpn1_vpn[] = {
		"[vpn_1_2_3_4_user2_org_1]",
		"Name=User2VPN1",
		NULL
	};
	dbus_uint32_t user_id;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	current_uid = 0;

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(VPN_STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);

	/* Create root test files */
	create_settings_file(STORAGEDIR, "wifi_1_managed_psk", root_wifi1);
	create_settings_file(STORAGEDIR, "wifi_2_managed_psk", root_wifi2);
	create_settings_file(VPN_STORAGEDIR, "provider_1_2_3_4_root_org_1",
				root_vpn1);
	create_settings_file(VPN_STORAGEDIR, "provider_1_2_3_4_root_org_2",
				root_vpn2);
	create_settings_file(VPN_STORAGEDIR, "vpn_1_2_3_4_root_org_1",
				root_vpn1_vpn);
	create_settings_file(VPN_STORAGEDIR, "vpn_1_2_3_4_root_org_2",
				root_vpn2_vpn);

	/* Create a non-service dir without settings */
	char *non_service = g_build_filename(STORAGEDIR, "iptables", NULL);
	g_assert_cmpint(g_mkdir_with_parents(non_service,
				S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH), ==, 0);
	g_free(non_service);

	/* Verify that services are loaded */
	gchar **services = connman_storage_get_services();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 2);
	g_assert_true(g_strv_contains((const gchar**)services,
				"wifi_1_managed_psk"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"wifi_2_managed_psk"));
	g_strfreev(services);

	services = __connman_storage_get_providers();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 2);
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_root_org_1"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_root_org_2"));
	g_strfreev(services);

	init_dbus(TRUE);

	/* Register both connmand and vpnd D-Bus with callbacks */
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &callbacks), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &callbacks), ==, 0);

	connection = connman_dbus_get_connection();
	dbus_error_init(&error);

	/*
	 * CHANGE USER TO USER1:
	 * Create user change message and "send" it
	 */
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	user_id = UID_USER;
	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_UINT32, &user_id,
				DBUS_TYPE_INVALID));

	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));

	/* Process message in connmand */
	DBG("call connmand change_user()");
	g_assert(connmand_method);
	g_assert_null(connmand_method(connection, last_message,
					connmand_data));

	/* Call vpnd method and get return */
	DBG("call vpnd change user()");
	g_assert(vpnd_method);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);

	g_assert_false(dbus_set_error_from_message(&error,
					change_user_reply));
	set_reply(change_user_reply);

	DBG("verify vpn callback count");
	for (i = 0; i < TOTAL_CB_COUNT; i++) {
		g_assert_cmpint(cb_counts[i], ==, vpn_cb_checklist[i]);
		cb_counts[i] = 0;
	}

	/*
	 * Create user1 VPN services - these can be created only after the
	 * user change is done because USER_VPN_STORAGEDIR and
	 * USER_STORAGEDIR are set only after the change.
	 */
	create_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user_org_1", user_vpn1);
	create_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user_org_2", user_vpn2);
	create_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user_org_3", user_vpn3);
	create_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user_org_1",
				user_vpn1_vpn);
	create_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user_org_2",
				user_vpn2_vpn);
	create_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user_org_3",
				user_vpn3_vpn);

	/* Check that the services are loaded after user change */
	services = __connman_storage_get_providers();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 3);
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_user_org_1"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_user_org_2"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_user_org_3"));

	/* Check the provider files and test removal */
	for (i = 0; i < 3; i++) {
		g_assert_true(check_settings_file(USER_VPN_STORAGEDIR,
					services[i]));

		g_assert_false(__connman_storage_remove_provider(services[i]));

		/* VPN handles providers without provider_ prefix */
		gchar **provider_set = g_strsplit(services[i], "_", 2);
		g_assert(provider_set);
		g_assert_cmpint(g_strv_length(provider_set), ==, 2);
		g_assert_true(__connman_storage_remove_provider(
					provider_set[1]));
		g_strfreev(provider_set);

		/* Provider should not be present anymore */
		g_assert_false(check_settings_file(USER_VPN_STORAGEDIR,
					services[i]));
	}

	g_strfreev(services);

	/* Call the pending callback to finish change in connmand*/
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	/* Proper reply should be received */
	g_assert(last_reply);
	g_assert_null(last_reply_error);

	dbus_message_unref(change_user_msg);

	DBG("verify callback count");
	for (i = 0; i < TOTAL_CB_COUNT; i++) {
		g_assert_cmpint(cb_counts[i], ==, cb_checklist[i]);
		cb_counts[i] = 0;
	}

	g_assert_cmpint(current_uid, ==, UID_USER);

	/* Create user1 service and test that it is loaded after user change.*/
	create_settings_file(USER_STORAGEDIR, "wifi_1_user1_managed_psk",
				user_wifi1);

	/* Try to load and save the wifi service */
	GKeyFile *wifi1_keyfile = connman_storage_load_service(
				"wifi_1_user1_managed_psk");
	g_assert(wifi1_keyfile);
	g_assert_cmpint(__connman_storage_save_service(wifi1_keyfile,
				"wifi_1_user1_managed_psk"), ==, 0);
	g_key_file_unref(wifi1_keyfile);

	/* This is not attempted to be watched and is ignored. */
	create_settings_file(USER_STORAGEDIR, "cellular_1_user_context1",
				user_cellular1);

	services = connman_storage_get_services();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 1);
	g_assert_cmpstr(services[0], ==, "wifi_1_user1_managed_psk");

	/* Invalid service names */
	g_assert_false(__connman_storage_remove_service(
				"wifi_user2_managed_psk"));
	g_assert_false(__connman_storage_remove_service(
				"wifi2_managed_psk"));

	/* Remove service and check success */
	g_assert_true(check_settings_file(USER_STORAGEDIR, services[0]));
	g_assert_true(__connman_storage_remove_service(services[0]));
	g_assert_false(check_settings_file(USER_STORAGEDIR, services[0]));
	g_assert_false(check_settings_file(STORAGEDIR, services[0]));

	g_strfreev(services);
	clean_dbus();
	init_dbus(TRUE);

	/*
	 * CHANGE USER TO USER2:
	 * Create user2 change message and "send" it
	 */
	user_id = UID_USER2;
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_UINT32, &user_id,
				DBUS_TYPE_INVALID));

	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));

	/* Process message in connmand */
	DBG("call connmand change_user()");
	g_assert(connmand_method);
	g_assert_null(connmand_method(connection, last_message,
					connmand_data));

	/* Call vpnd method and get return */
	DBG("call vpnd change user()");
	g_assert(vpnd_method);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);

	g_assert_false(dbus_set_error_from_message(&error,
					change_user_reply));
	set_reply(change_user_reply);

	DBG("verify vpn callback count");
	for (i = 0; i < TOTAL_CB_COUNT; i++) {
		g_assert_cmpint(cb_counts[i], ==, user2_vpn_cb_checklist[i]);
		cb_counts[i] = 0;
	}

	/*
	 * Create user2 VPN files. Can be created only after the change
	 * as the USER dirs are not set until user change is completed.
	 */
	create_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user2_org_1", user2_vpn1);
	create_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user2_org_1",
				user2_vpn1_vpn);

	/* Check that the provider is loaded */
	services = __connman_storage_get_providers();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 1);
	g_assert_cmpstr(services[0], ==, "provider_1_2_3_4_user2_org_1");

	g_assert_true(check_settings_file(USER_VPN_STORAGEDIR, services[0]));
	g_assert_false(__connman_storage_remove_provider(services[0]));

	/* VPN handles providers without provider_ prefix */
	gchar **provider_set = g_strsplit(services[0], "_", 2);
	g_assert(provider_set);
	g_assert_cmpint(g_strv_length(provider_set), ==, 2);
	g_assert_true(__connman_storage_remove_provider(provider_set[1]));
	g_strfreev(provider_set);

	g_assert_false(check_settings_file(USER_VPN_STORAGEDIR,
				services[0]));
	g_strfreev(services);

	/* Call the pending callback */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	/* No error should be sent back */
	g_assert(last_reply);
	g_assert_null(last_reply_error);

	dbus_message_unref(change_user_msg);

	DBG("verify callback count");
	for (i = 0; i < TOTAL_CB_COUNT; i++) {
		g_assert_cmpint(cb_counts[i], ==, user2_cb_checklist[i]);
		cb_counts[i] = 0;
	}

	g_assert_cmpint(current_uid, ==, UID_USER2);

	/* Create user Wifi files */
	create_settings_file(USER_STORAGEDIR, "wifi_1_user2_managed_psk",
				user2_wifi1);
	create_settings_file(USER_STORAGEDIR, "wifi_2_user2_managed_psk",
				user2_wifi2);

	/* Check that both user2 services are loaded */
	services = connman_storage_get_services();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 2);
	g_assert_true(g_strv_contains((const gchar**)services,
				"wifi_1_user2_managed_psk"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"wifi_2_user2_managed_psk"));

	/* Remove all services */
	for (i = 0; i < 2; i++) {
		g_assert_true(check_settings_file(USER_STORAGEDIR,
					services[i]));
		g_assert_true(__connman_storage_remove_service(services[i]));
		g_assert_false(check_settings_file(USER_STORAGEDIR,
					services[i]));
	}

	g_strfreev(services);
	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Change to regular user, with callbacks and files not removed after load */
static void storage_test_user_change8()
{
	DBusMessage *change_user_msg;
	DBusMessage *change_user_reply;
	DBusConnection *connection;
	DBusError error;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	/* Unload does not happen because vpnd uses same storage impl here. */
	int cb_checklist[TOTAL_CB_COUNT] = {2, 0, 1, 1, 1};
	/* Unload is called for the second user change */
	int user2_cb_checklist[TOTAL_CB_COUNT] = {2, 1, 1, 1, 1};
	int vpn_cb_checklist[TOTAL_CB_COUNT] = {1, 1, 1, 1, 1};
	int user2_vpn_cb_checklist[TOTAL_CB_COUNT] = {2, 0, 1, 1, 1};
	int i;

	/* Root service and provider files */
	gchar *root_wifi1[] = {
		"[wifi_1_managed_psk]",
		"Name=wifi1",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3447",
		"Frequency=2417",
		NULL
	};
	gchar *root_wifi2[] = {
		"[wifi_2_managed_psk]",
		"Name=wifi2",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3446",
		"Frequency=2416",
		NULL
	};
	gchar *root_vpn1[] = {
		"[1_2_3_4_root_org_1]",
		"Name=RootVPN1",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=root.org.1",
		NULL
	};
	gchar *root_vpn1_vpn[] = {
		"[vpn_1_2_3_4_root_org_1]",
		"Name=RootVPN1",
		NULL
	};
	gchar *root_vpn2[] = {
		"[1_2_3_4_root_org_2]",
		"Name=RootVPN2",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=root.org.2",
		NULL
	};
	gchar *root_vpn2_vpn[] = {
		"[vpn_1_2_3_4_root_org_2]",
		"Name=RootVPN2",
		NULL
	};

	/* user1 service and provider files */
	gchar *user_wifi1[] = {
		"[wifi_1_user1_managed_psk]",
		"Name=wifi1user1",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3447",
		"Frequency=2417",
		NULL
	};
	gchar *user_vpn1[] = {
		"[1_2_3_4_user_org_1]",
		"Name=UserVPN1",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=user.org.1",
		NULL
	};
	gchar *user_vpn1_vpn[] = {
		"[vpn_1_2_3_4_user_org_1]",
		"Name=UserVPN1",
		NULL
	};
	gchar *user_vpn2[] = {
		"[1_2_3_4_user_org_2]",
		"Name=UserVPN2",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=user.org.2",
		NULL
	};
	gchar *user_vpn2_vpn[] = {
		"[vpn_1_2_3_4_user_org_2]",
		"Name=UserVPN2",
		NULL
	};
	gchar *user_vpn3[] = {
		"[1_2_3_4_user_org_3]",
		"Name=UserVPN3",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=user.org.3",
		NULL
	};
	gchar *user_vpn3_vpn[] = {
		"[vpn_1_2_3_4_user_org_3]",
		"Name=UserVPN3",
		NULL
	};

	/* user2 service and provider files */
	gchar *user2_wifi1[] = {
		"[wifi_1_user2_managed_psk]",
		"Name=wifi1user2",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3447",
		"Frequency=2417",
		NULL
	};
	gchar *user2_wifi2[] = {
		"[wifi_2_user2_managed_psk]",
		"Name=wifi2user2",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3443",
		"Frequency=2415",
		NULL
	};
	gchar *user2_vpn1[] = {
		"[1_2_3_4_user2_org_1]",
		"Name=User2VPN1",
		"Type=openconnect",
		"Host=1.2.3.4",
		"VPN.Domain=user2.org.1",
		NULL
	};
	gchar *user2_vpn1_vpn[] = {
		"[vpn_1_2_3_4_user2_org_1]",
		"Name=User2VPN1",
		NULL
	};
	uid_t user_id;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	current_uid = 0;

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(VPN_STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);

	/* Create root test files */
	create_settings_file(STORAGEDIR, "wifi_1_managed_psk", root_wifi1);
	create_settings_file(STORAGEDIR, "wifi_2_managed_psk", root_wifi2);
	create_settings_file(VPN_STORAGEDIR, "provider_1_2_3_4_root_org_1",
				root_vpn1);
	create_settings_file(VPN_STORAGEDIR, "provider_1_2_3_4_root_org_2",
				root_vpn2);
	create_settings_file(VPN_STORAGEDIR, "vpn_1_2_3_4_root_org_1",
				root_vpn1_vpn);
	create_settings_file(VPN_STORAGEDIR, "vpn_1_2_3_4_root_org_2",
				root_vpn2_vpn);

	/* Verify that services are loaded */
	gchar **services = connman_storage_get_services();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 2);
	g_assert_true(g_strv_contains((const gchar**)services,
				"wifi_1_managed_psk"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"wifi_2_managed_psk"));
	g_strfreev(services);

	services = __connman_storage_get_providers();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 2);
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_root_org_1"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_root_org_2"));
	g_strfreev(services);

	init_dbus(TRUE);

	/* Register both connmand and vpnd D-Bus with callbacks */
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &callbacks), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &callbacks), ==, 0);

	connection = connman_dbus_get_connection();
	dbus_error_init(&error);

	/*
	 * CHANGE USER TO USER1:
	 * Create user change message and "send" it
	 */
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	user_id = UID_USER;
	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_UINT32, &user_id,
				DBUS_TYPE_INVALID));

	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));

	/* Process message in connmand */
	DBG("call connmand change_user() for user");
	g_assert(connmand_method);
	g_assert_null(connmand_method(connection, last_message,
					connmand_data));

	/* Call vpnd method and get return */
	DBG("call vpnd change user() for user");
	g_assert(vpnd_method);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);

	g_assert_false(dbus_set_error_from_message(&error,
					change_user_reply));
	set_reply(change_user_reply);

	DBG("verify vpn callback count for user");
	for (i = 0; i < TOTAL_CB_COUNT; i++) {
		g_assert_cmpint(cb_counts[i], ==, vpn_cb_checklist[i]);
		cb_counts[i] = 0;
	}

	/* Root has 2 VPNs */
	g_assert_cmpint(unload_items, ==, 2);

	/*
	 * Create user1 VPN services - these can be created only after the
	 * user change is done because USER_VPN_STORAGEDIR and
	 * USER_STORAGEDIR are set only after the change.
	 */
	create_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user_org_1", user_vpn1);
	create_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user_org_2", user_vpn2);
	create_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user_org_3", user_vpn3);
	create_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user_org_1",
				user_vpn1_vpn);
	create_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user_org_2",
				user_vpn2_vpn);
	create_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user_org_3",
				user_vpn3_vpn);

	/* Check that the services are loaded after user change */
	services = __connman_storage_get_providers();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 3);
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_user_org_1"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_user_org_2"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"provider_1_2_3_4_user_org_3"));

	/* Check the provider files */
	for (i = 0; i < 3; i++)
		g_assert_true(check_settings_file(USER_VPN_STORAGEDIR,
					services[i]));
	g_strfreev(services);

	/* Call the pending callback to finish change in connmand*/
	DBG("call connmand pending call notify for user");
	last_pending_function(last_pending_call, last_pending_function_data);

	/* Proper reply should be received */
	g_assert(last_reply);
	g_assert_null(last_reply_error);

	dbus_message_unref(change_user_msg);

	DBG("verify callback count for user");
	for (i = 0; i < TOTAL_CB_COUNT; i++) {
		g_assert_cmpint(cb_counts[i], ==, cb_checklist[i]);
		cb_counts[i] = 0;
	}

	/* Root has 2 services */
	g_assert_cmpint(unload_items, ==, 2);

	g_assert_cmpint(current_uid, ==, UID_USER);

	/* Create user1 service and test that it is loaded after change */
	create_settings_file(USER_STORAGEDIR, "wifi_1_user1_managed_psk",
				user_wifi1);

	services = connman_storage_get_services();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 1);
	g_assert_cmpstr(services[0], ==, "wifi_1_user1_managed_psk");

	g_assert_true(check_settings_file(USER_STORAGEDIR, services[0]));

	g_strfreev(services);
	clean_dbus();
	init_dbus(TRUE);

	/* Check that system service and provider files are kept */
	check_settings_file(STORAGEDIR, "wifi_1_managed_psk");
	check_settings_file(STORAGEDIR, "wifi_2_managed_psk");
	check_settings_file(VPN_STORAGEDIR, "provider_1_2_3_4_root_org_1");
	check_settings_file(VPN_STORAGEDIR, "provider_1_2_3_4_root_org_2");
	check_settings_file(VPN_STORAGEDIR, "vpn_1_2_3_4_root_org_1");
	check_settings_file(VPN_STORAGEDIR, "vpn_1_2_3_4_root_org_2");

	/*
	 * CHANGE USER TO USER2:
	 * Create user2 change message and "send" it
	 */
	user_id = UID_USER2;
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_UINT32, &user_id,
				DBUS_TYPE_INVALID));

	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));
	dbus_message_unref(change_user_msg);

	/* Process message in connmand */
	DBG("call connmand change_user() for user2");
	g_assert(connmand_method);
	g_assert_null(connmand_method(connection, last_message,
					connmand_data));

	/* Call vpnd method and get return */
	DBG("call vpnd change user() for user2");
	g_assert(vpnd_method);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);

	g_assert_false(dbus_set_error_from_message(&error,
					change_user_reply));
	set_reply(change_user_reply);

	DBG("verify vpn callback count for user2");
	for (i = 0; i < TOTAL_CB_COUNT; i++) {
		g_assert_cmpint(cb_counts[i], ==, user2_vpn_cb_checklist[i]);
		cb_counts[i] = 0;
	}

	g_assert_cmpint(unload_items, ==, 2);

	/*
	 * Create user2 VPN files. Can be created only after the change
	 * as the USER dirs are not set until user change is completed.
	 */
	create_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user2_org_1", user2_vpn1);
	create_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user2_org_1",
				user2_vpn1_vpn);

	/* Check that the provider is loaded */
	services = __connman_storage_get_providers();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 1);
	g_assert_cmpstr(services[0], ==, "provider_1_2_3_4_user2_org_1");
	g_assert_true(check_settings_file(USER_VPN_STORAGEDIR,
				services[0]));

	/* And neither does the vpn_ prefixed connmand service */
	gchar **provider_set = g_strsplit(services[0], "_", 2);
	g_assert(provider_set);
	g_assert_cmpint(g_strv_length(provider_set), ==, 2);

	/* Check that vpn_ prefix dir also exists */
	gchar *vpn_id = g_strdup_printf("vpn_%s", provider_set[1]);
	g_assert_true(check_settings_file(USER_VPN_STORAGEDIR, vpn_id));
	g_free(vpn_id);
	g_strfreev(provider_set);
	g_strfreev(services);

	/* Call the pending callback */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	/* No error should be sent back */
	g_assert(last_reply);
	g_assert_null(last_reply_error);

	DBG("verify callback count for user2");
	for (i = 0; i < TOTAL_CB_COUNT; i++) {
		g_assert_cmpint(cb_counts[i], ==, user2_cb_checklist[i]);
		cb_counts[i] = 0;
	}

	g_assert_cmpint(unload_items, ==, 2);

	g_assert_cmpint(current_uid, ==, UID_USER2);

	/* Create user Wifi files */
	create_settings_file(USER_STORAGEDIR, "wifi_1_user2_managed_psk",
				user2_wifi1);
	create_settings_file(USER_STORAGEDIR, "wifi_2_user2_managed_psk",
				user2_wifi2);

	/* Check that both user2 services are loaded */
	services = connman_storage_get_services();
	g_assert(services);
	g_assert_cmpint(g_strv_length(services), ==, 2);
	g_assert_true(g_strv_contains((const gchar**)services,
				"wifi_1_user2_managed_psk"));
	g_assert_true(g_strv_contains((const gchar**)services,
				"wifi_2_user2_managed_psk"));

	for (i = 0; i < 2; i++)
		g_assert_true(check_settings_file(USER_STORAGEDIR,
					services[i]));

	g_strfreev(services);

	/* Check that user services and providers are kept */
	check_settings_file(USER_STORAGEDIR, "wifi_1_user1_managed_psk");
	check_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user_org_1");
	check_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user_org_2");
	check_settings_file(USER_VPN_STORAGEDIR,
				"provider_1_2_3_4_user_org_3");
	check_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user_org_1");
	check_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user_org_2");
	check_settings_file(USER_VPN_STORAGEDIR, "vpn_1_2_3_4_user_org_3");

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

struct connman_access_storage_policy {
	int unused;
};

static struct connman_access_storage_policy* policy_create(const char *spec)
{
	return g_new0(struct connman_access_storage_policy, 1);
}

static enum connman_access allow_change_user(
				const struct connman_access_storage_policy *p,
				const char *user, const char *sender,
				enum connman_access default_access)
{
	return CONNMAN_ACCESS_ALLOW;
}

static void policy_free(struct connman_access_storage_policy *p)
{
	g_free(p);
}

static bool allow_vpn_change_user(const char *sender, const char *arg,
				bool default_access)
{
	return true;
}

static struct connman_storage_callbacks access_success_callbacks = {
	.pre = pre_cb,
	.unload = unload_cb,
	.load = load_cb,
	.post = post_cb,
	.finalize = finalize_cb,
	.uid_changed = uid_changed_cb,
	.access_policy_create = policy_create,
	.access_change_user = allow_change_user,
	.access_policy_free = policy_free,
	.vpn_access_change_user = allow_vpn_change_user,
};

/* Change to regular user, with callbacks*/
static void storage_test_user_change9()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	int cb_checklist[TOTAL_CB_COUNT] = {2, 0, 1, 1, 1};
	int vpn_cb_checklist[TOTAL_CB_COUNT] = {1, 0, 1, 1, 1};

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	current_uid = 0;

	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN,
				&access_success_callbacks), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN,
				&access_success_callbacks), ==, 0);

	user_change_process(UID_USER, USER_CHANGE_SUCCESS, NULL, false,
				cb_checklist, vpn_cb_checklist);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	clean_dbus();
	clean_cb_counts();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

struct user_cb_data_t {
	uid_t uids[2];
	int errs[2];
	unsigned int call_count;
	unsigned int expected_call_count;
};

static void internal_user_change_process(uid_t uid,
			connman_storage_change_user_result_cb_t cb,
			void *user_cb_data, bool prepare_only,
			int expected_return, const char *error_name,
			enum dbus_mode_t mode)
{
	DBusConnection *connection;
	DBusMessage *change_user_reply;
	DBusError error;
	struct user_cb_data_t *cb_data = user_cb_data;
	int call_count = prepare_only ? 2 : 1;

	DBG("uid %u", uid);
	current_uid = 0;

	connection = connman_dbus_get_connection();
	dbus_error_init(&error);

	if (cb_data)
		cb_data->expected_call_count = call_count;

	dbus_mode = mode;

	g_assert_cmpint(__connman_storage_change_user(uid, cb, cb_data,
				prepare_only), ==, expected_return);

	switch (expected_return) {
	case -EINPROGRESS:
	case 0:
		break;
	default:
		return;
	}

	/* Call vpnd method and get return */
	DBG("call vpnd change user()");
	g_assert(vpnd_method);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);

	/*
	 * Because both, connmand and vpnd are tested within one process and
	 * the first setting of user dirs in "connmand" side when preparing
	 * will have an equal value in the user VPN storage dir -> vpnd will
	 * report this as already set - which in real use does not exist.
	 */
	if (prepare_only || error_name) {
		g_assert_true(dbus_set_error_from_message(&error,
					change_user_reply));
		g_assert_cmpstr(error.name, ==, error_name);
		dbus_error_free(&error);
	} else {
		g_assert_false(dbus_set_error_from_message(&error,
					change_user_reply));
	}

	set_reply(change_user_reply);

	/* Call the pending callback */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	/* No error should be sent back */
	g_assert(last_reply);
	g_assert_null(last_reply_error);

	if (cb_data)
		g_assert_cmpint(cb_data->call_count, ==, call_count);
}

/*
 * Test user change in preparing mode - this cannot be properly tested without
 * forking/threading and will return already enabled because connmand sets the
 * same storage.c value as vpnd uses to check. In real use this is not
 * happening.
 */
static void storage_test_user_change10()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, 0);

	internal_user_change_process(UID_USER, NULL, NULL, true, -EINPROGRESS,
				"net.connman.Error.AlreadyEnabled",
				DBUS_MODE_USER_CHANGE_TO_VPND);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static struct connman_storage_callbacks uid_callback = {
	.uid_changed = uid_changed_cb,
};

/* Test user change without result callback in normal mode */
static void storage_test_user_change11()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &uid_callback), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	internal_user_change_process(UID_USER, NULL, NULL, false, -EINPROGRESS,
				NULL, dbus_mode);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static void result_cb(uid_t uid, int err, void *user_data)
{
	struct user_cb_data_t *data = user_data;

	g_assert(data);

	DBG("call %d uid %d err %d", data->call_count + 1, uid, err);

	g_assert_cmpint(data->uids[data->call_count], ==, uid);
	g_assert_cmpint(data->errs[data->call_count], ==, err);

	data->call_count++;

	g_assert_cmpint(data->call_count, <=, data->expected_call_count);
}

/*
 * Change to user in prepare mode which causes already enabled error to be
 * received as the preparing mode is impossible to test without
 * forking/threads. One user change in prepare mode sets the current_uid in
 * storage and vpnd cannot change that but reports already enabled.
 */
static void storage_test_user_change12()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	struct user_cb_data_t data = {
				.uids = { UID_USER, UID_USER },
				.errs = { -EINPROGRESS, -EALREADY },
				};

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &uid_callback), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	internal_user_change_process(UID_USER, result_cb, &data, true,
				-EINPROGRESS,
				"net.connman.Error.AlreadyEnabled",
				DBUS_MODE_USER_CHANGE_TO_VPND);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Change to user without preparation expecting a single reply */
static void storage_test_user_change13()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	struct user_cb_data_t data = {
				.uids = { UID_USER, 0 },
				.errs = { 0, 0 },
				};

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &uid_callback), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	internal_user_change_process(UID_USER, result_cb, &data, false,
				-EINPROGRESS, NULL, dbus_mode);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static int finalize_cb1_call_count = 0;

static void finalize_cb1(uid_t uid, void *user_data)
{
	DBG("uid %u data %p", uid, user_data);

	finalize_cb1_call_count++;
	g_assert_null(user_data);
}

static int finalize_cb2_call_count = 0;
static void *finalize_cb2_data = (void*)0x987123;

static void finalize_cb2(uid_t uid, void *user_data)
{
	DBG("uid %u data %p", uid, user_data);

	finalize_cb2_call_count++;
	g_assert(user_data == finalize_cb2_data);
}

struct connman_storage_callbacks finalize_callback = {
	.uid_changed		= uid_changed_cb,
	.finalize		= finalize_cb1,
	.finalize_user_data	= NULL,
};

/*
 * Normal change to user, then next call is already enabled and change to
 * another user2 and then return back to user. Change the finalize function
 * and last to NULL so it is dropped.
 */
static void storage_test_user_change14()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	struct connman_storage_callbacks *callbacks;
	struct user_cb_data_t data = {
				.uids = { UID_USER, 0 },
				.errs = { 0, 0 },
				};
	struct user_cb_data_t data2 = {
				.uids = { UID_USER2, 0 },
				.errs = { 0, 0 },
				};

	/* connman_storage_update_finalize_cb modifies the contents of the *
	 * registered callbacks list. To make the test idempotent, we copy *
	 * the finalize_callback struct to a new address.                  */
	callbacks = g_memdup2(&finalize_callback,
				sizeof(struct connman_storage_callbacks));
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, callbacks),
				==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, callbacks),
				==, 0);

	internal_user_change_process(UID_USER, result_cb, &data, false,
				-EINPROGRESS, NULL, dbus_mode);

	/* Both connmand and vpnd call the callbacks. */
	g_assert_cmpint(finalize_cb1_call_count, ==, 2);

	g_assert_cmpint(current_uid, ==, UID_USER);

	/* Another call results in EALREADY */
	clean_dbus();
	init_dbus(TRUE);

	data.call_count = 0;
	data.errs[0] = -EALREADY;
	internal_user_change_process(UID_USER, result_cb, &data, false,
				-EALREADY,
				"net.connman.Error.AlreadyEnabled", dbus_mode);

	/* Change to user2 */
	clean_dbus();
	init_dbus(TRUE);

	connman_storage_update_finalize_cb(finalize_cb2, finalize_cb2_data);

	internal_user_change_process(UID_USER2, result_cb, &data2, false,
				-EINPROGRESS, NULL, dbus_mode);

	/* Both connmand and vpnd call the callbacks. */
	g_assert_cmpint(finalize_cb2_call_count, ==, 2);

	g_assert_cmpint(current_uid, ==, UID_USER2);

	/* Change back to user */
	clean_dbus();
	init_dbus(TRUE);

	data.call_count = 0;
	data.errs[0] = 0;
	connman_storage_update_finalize_cb(NULL, NULL);

	internal_user_change_process(UID_USER, result_cb, &data, false,
				-EINPROGRESS, NULL, dbus_mode);

	/* Set to NULL, these are not called */
	g_assert_cmpint(finalize_cb1_call_count, ==, 2);
	g_assert_cmpint(finalize_cb2_call_count, ==, 2);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
	g_free(callbacks);
	finalize_cb1_call_count = 0;
	finalize_cb2_call_count = 0;
}

/* Total wait of 0.120s */
#define MAIN_LOOP_ITERATIONS_DEFAULT 6000
#define MAIN_LOOP_SLEEP_USEC 20

static unsigned int iterate_main_context(GMainContext *context,
			gboolean may_block, unsigned int max_events)
{
	unsigned int counter = 0;
	unsigned int events = 0;
	bool event_recorded = false;

	g_assert(context);
	g_assert_true(g_main_context_acquire(context));

	DBG("");

	while (counter < MAIN_LOOP_ITERATIONS_DEFAULT && events < max_events) {

		/*
		 * This main loop iteration simulation is for re-sending user
		 * change messages to vpnd.
		 */
		dbus_mode = DBUS_MODE_USER_CHANGE_TO_VPND;

		if (g_main_context_pending(context)) {
			events++;
			DBG("event #%u @ iteration %u", events, counter);

			/*
			 * Main context iteration is not set to wait, dispatch
			 * here.
			 */
			if (!may_block)
				g_main_context_dispatch(context);

			event_recorded = true;
		}

		/* If iteration fails to dispatch do that manually. */
		if (!g_main_context_iteration(context, may_block)) {
			g_main_context_dispatch(context);
		/*
		 * If the g_main_context_pending() already recorded an event
		 * skip it here to avoid double.
		 */
		} else if (!event_recorded) {
			events++;
			DBG("event #%u @ iteration %u", events, counter);
		}

		usleep(MAIN_LOOP_SLEEP_USEC);

		counter++;
		event_recorded = false;
	}

	g_main_context_release(context);

	DBG("ended with %u events", events);

	return events;
}

/*
 * Change to regular user and back to root, use vpnd notify to disconnect and
 * connect it again to trigger message resending. Simulate vpnd action. No
 * callbacks in use.
 */
static void storage_test_vpn_crash1()
{
	GMainLoop *mainloop;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	DBusConnection *connection;
	DBusMessage *reply;
	DBusError error;

	mainloop = g_main_loop_new(NULL, FALSE);
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	dbus_error_init(&error);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(STORAGE_DIR_TYPE_MAIN,
				&uid_callback), ==, 0);
	g_assert(connect_watch);
	g_assert(disconnect_watch);

	connection = connman_dbus_get_connection();
	connect_watch(connection, NULL); // does nothing

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	user_change_process(UID_USER, USER_CHANGE_SUCCESS, NULL, false, NULL,
				NULL);

	g_assert_cmpint(current_uid, ==, UID_USER);

	/* No events in main loop either */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	clean_dbus();
	init_dbus(TRUE);

	/* vpnd crashed */
	disconnect_watch(connection, NULL);

	/* vpnd started, send_change_user_msg() is used */
	connect_watch(connection, NULL);

	/* Process the user notify */
	DBG("call vpnd change user()");
	g_assert(vpnd_method);
	reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(reply);

	/* Because storage.c is shared by both, EALREADY error is sent */
	g_assert_true(dbus_set_error_from_message(&error, reply));
	g_assert_cmpstr(error.name, ==, "net.connman.Error.AlreadyEnabled");
	dbus_error_free(&error);
	set_reply_error(reply);

	/* Call the pending callback */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	g_assert_cmpint(current_uid, ==, UID_USER);

	/* No events in main loop either */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	g_assert(last_reply_error);
	g_assert_null(last_reply);

	clean_dbus();
	init_dbus(TRUE);

	DBG("change back to root");
	user_change_process(UID_ROOT, USER_CHANGE_SUCCESS, NULL, false, NULL,
				NULL);

	disconnect_watch(connection, NULL);
	connect_watch(connection, NULL); // Does nothing, uid = root

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

struct vpn_error_data {
	const char *errorname;
	uid_t uid;
	int events;
};

/*
 * Send user change, then crash vpnd. Check with different errors that the
 * user is not changed in wrong cases back to root. Also test that all actions
 * will result in a delayed user change, which will get a faked OK reply.
 */
static void storage_test_vpn_crash2()
{
	struct vpn_error_data vpn_data[] = {
			/* These 4 will initiate delayed user change */
			{"net.connman.Error.Timeout", UID_USER, 1},
			{"net.connman.Error.NotConnected", UID_USER, 1},
			{"net.connman.Error.NoReply", UID_USER, 1},
			{"net.connman.Error.UnknownMethod", UID_USER, 1},
			/* No new call is to be made */
			{"net.connman.Error.AlreadyEnabled",UID_USER, 0},
			/* An "other" error, caused by fs access error etc. */
			{"net.connman.Error.Failed", UID_ROOT, 0},
	};
	GMainLoop *mainloop;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	DBusConnection *connection;
	DBusMessage *reply;
	DBusError error;
	unsigned int i;

	mainloop = g_main_loop_new(NULL, FALSE);
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	dbus_error_init(&error);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(STORAGE_DIR_TYPE_MAIN,
				&uid_callback), ==, 0);
	g_assert(connect_watch);
	g_assert(disconnect_watch);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);
	connection = connman_dbus_get_connection();

	user_change_process(UID_USER, USER_CHANGE_SUCCESS, NULL, false, NULL,
				NULL);

	g_assert_cmpint(current_uid, ==, UID_USER);

	/* No events in main loop either */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	clean_dbus();
	init_dbus(TRUE);

	for (i = 0; i < G_N_ELEMENTS(vpn_data); i++) {
		DBG("iterate %d", i);

		/* vpnd crashed */
		disconnect_watch(connection, NULL);

		/* vpnd started, send_change_user_msg() is used */
		connect_watch(connection, NULL);

		/* Fake error as reply */
		reply = create_dbus_error(last_message, vpn_data[i].errorname);
		g_assert(reply);
		set_reply_error(reply);

		/* Call the pending callback */
		DBG("call connmand pending call notify");
		last_pending_function(last_pending_call,
						last_pending_function_data);

		/* User is reset to root in case the error is unknown */
		g_assert_cmpint(current_uid, ==, vpn_data[i].uid);

		/* Different errors result in different amount of events */
		g_assert_cmpint(iterate_main_context(
					g_main_loop_get_context(mainloop),
					FALSE, 1), ==, vpn_data[i].events);

		g_assert(last_reply_error);
		g_assert_null(last_reply);

		if (vpn_data[i].events) {
			/* Fake reply */
			reply = g_dbus_create_reply(last_message,
							DBUS_TYPE_INVALID);
			g_assert(reply);
			set_reply(reply);

			/* Call the pending callback to handle event */
			DBG("call connmand pending call notify");
			last_pending_function(last_pending_call,
						last_pending_function_data);
		}

		clean_dbus();
		init_dbus(TRUE);
	}

	/* vpnd crashed for second time */
	disconnect_watch(connection, NULL);

	/* vpnd started, send_change_user_msg() is used, which fails*/
	dbus_mode = DBUS_MODE_NONE;
	connect_watch(connection, NULL);
	connect_watch(connection, NULL); // Does nothing

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/*
 * Send user change, simulate vpnd slow response by doing a crash vpnd while
 * doing the request then crash vpnd but errors are reported back
 */
static void storage_test_vpn_crash3()
{
	GMainLoop *mainloop;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	mainloop = g_main_loop_new(NULL, FALSE);
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(STORAGE_DIR_TYPE_MAIN,
				&uid_callback), ==, 0);
	g_assert(connect_watch);
	g_assert(disconnect_watch);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	user_change_process(UID_USER,
				USER_CHANGE_SUCCESS|USER_CHANGE_VPN_CRASH,
				NULL, false, NULL, NULL);

	g_assert_cmpint(current_uid, ==, UID_USER);

	/* No events in main loop either */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	clean_dbus();

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	g_main_loop_unref(mainloop);
	cleanup_test_directory(test_path);
	g_free(test_path);
}

/*
 * Send user change, then crash vpnd, user change comes during it and call is
 * delayed.
 */
static void storage_test_vpn_crash4()
{
	GMainLoop *mainloop;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	DBusConnection *connection;
	DBusMessage *change_user_msg;
	DBusMessage *change_user_reply = NULL;
	DBusError error;
	dbus_uint32_t user_id;
	enum dbus_mode_t mode;

	mainloop = g_main_loop_new(NULL, FALSE);
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	dbus_error_init(&error);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(STORAGE_DIR_TYPE_MAIN,
				&uid_callback), ==, 0);
	g_assert(connect_watch);
	g_assert(disconnect_watch);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);
	connection = connman_dbus_get_connection();

	user_change_process(UID_USER, USER_CHANGE_SUCCESS, NULL, false, NULL,
				NULL);

	g_assert_cmpint(current_uid, ==, UID_USER);

	clean_dbus();
	init_dbus(TRUE);

	/* vpnd crashed */
	disconnect_watch(connection, NULL);

	/* Disable dbus */
	dbus_on = false;
	mode = dbus_mode;
	dbus_mode = DBUS_MODE_NONE;

	/* Cannot send message when detected again */
	connect_watch(connection, NULL);

	/*No delayed user change event exists */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	/* Enable dbus */
	dbus_on = true;
	dbus_mode = mode;

	/* vpnd crashed */
	disconnect_watch(connection, NULL);

	/* Block with pending call that vpnd watch delays user change */
	user_id = (dbus_uint32_t)UID_USER2;

	/* Create user change message and "send" it */
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_UINT32, &user_id,
				DBUS_TYPE_INVALID));

	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));

	/* Process message in connmand */
	DBG("call connmand change_user()");
	g_assert(connmand_method);
	g_assert_null(connmand_method(connection, last_message,
				connmand_data));

	/* vpnd started, send_change_user_msg() but pending call is ongoing */
	connect_watch(connection, NULL);

	/* User is not changed */
	g_assert_cmpint(current_uid, ==, UID_USER);

	/* Trigger first event and result is still EBUSY */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 1);

	/* Fake reply from vpnd */
	change_user_reply = create_dbus_error(last_message,
					"net.connman.error.Failed");
	g_assert(change_user_reply);
	set_reply_error(change_user_reply);

	/* Call the pending callback to process fake call */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);
	dbus_message_unref(last_reply_error);

	/* User is not changed */
	g_assert_cmpint(current_uid, ==, UID_USER);

	dbus_on = false;

	/*A delayed user change event is added */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 1);

	dbus_on = true;

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	dbus_message_unref(change_user_msg);
	g_main_loop_unref(mainloop);
	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Send user change with internal process, then crash vpnd */
static void storage_test_vpn_crash5()
{
	GMainLoop *mainloop;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	DBusConnection *connection;
	DBusMessage *reply;
	DBusError error;
	struct user_cb_data_t data = { 0 };

	mainloop = g_main_loop_new(NULL, FALSE);
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	dbus_error_init(&error);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(STORAGE_DIR_TYPE_MAIN,
				&uid_callback), ==, 0);
	g_assert(connect_watch);
	g_assert(disconnect_watch);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);
	connection = connman_dbus_get_connection();

	data.uids[0] = UID_USER;
	internal_user_change_process(UID_USER, result_cb, &data, false,
				-EINPROGRESS, NULL, dbus_mode);

	g_assert_cmpint(current_uid, ==, UID_USER);

	/* No events in main loop either */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	clean_dbus();
	init_dbus(TRUE);

	/* vpnd crashed */
	disconnect_watch(connection, NULL);

	/* vpnd started, send_change_user_msg() is used */
	connect_watch(connection, NULL);

	/* Fake error as reply, failed can result from any of mkdir errors. */
	reply = create_dbus_error(last_message, "net.connman.Error.Failed");
	g_assert(reply);
	set_reply_error(reply);

	/* Call the pending callback */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	/* User is reset to root in case the error is unknown */
	g_assert_cmpint(current_uid, ==, UID_ROOT);

	/* No events in main loop either */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	g_assert(last_reply_error);
	g_assert_null(last_reply);

	clean_dbus();
	init_dbus(TRUE);

	/* vpnd crashed for second time */
	disconnect_watch(connection, NULL);

	/* vpnd started, send_change_user_msg() is used, which fails*/
	dbus_mode = DBUS_MODE_NONE;
	connect_watch(connection, NULL);
	connect_watch(connection, NULL); // Does nothing

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Call with internal change process that fails */
static void storage_test_vpn_crash6()
{
	GMainLoop *mainloop;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	DBusConnection *connection;
	DBusMessage *change_user_reply = NULL;
	DBusError error;
	struct user_cb_data_t data = { 0 };
	enum dbus_mode_t mode;

	mainloop = g_main_loop_new(NULL, FALSE);
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	dbus_error_init(&error);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(STORAGE_DIR_TYPE_MAIN,
				&uid_callback), ==, 0);
	g_assert(connect_watch);
	g_assert(disconnect_watch);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);
	connection = connman_dbus_get_connection();

	data.uids[0] = UID_USER;
	internal_user_change_process(UID_USER, result_cb, &data, false,
				-EINPROGRESS, NULL, dbus_mode);

	g_assert_cmpint(current_uid, ==, UID_USER);

	clean_dbus();
	init_dbus(TRUE);

	/* vpnd crashed */
	disconnect_watch(connection, NULL);

	/* Disable dbus */
	dbus_on = false;
	mode = dbus_mode;
	dbus_mode = DBUS_MODE_NONE;

	/* Cannot send message when detected again */
	connect_watch(connection, NULL);

	/*No delayed user change event exists */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	/* Enable dbus */
	dbus_on = true;
	dbus_mode = mode;

	/* vpnd crashed */
	disconnect_watch(connection, NULL);

	data.call_count = 0;
	data.uids[0] = UID_USER2;
	data.errs[0] = -ENOENT;

	/* Block with pending call that vpnd watch delays user change */
	g_assert_cmpint(__connman_storage_change_user(UID_USER2, result_cb,
				&data, false), ==, -EINPROGRESS);

	/* This will result in failure, just reuse the last message */
	DBG("call connmand change_user()");
	g_assert(connmand_method);
	change_user_reply = connmand_method(connection, last_message,
				connmand_data);
	g_assert(change_user_reply);
	dbus_error_init(&error);
	g_assert_true(dbus_set_error_from_message(&error, change_user_reply));
	g_assert_cmpstr(error.name, ==, "net.connman.Error.Failed");
	dbus_error_free(&error);

	/* vpnd started, send_change_user_msg() but pending call is ongoing */
	connect_watch(connection, NULL);

	/* User is not changed */
	g_assert_cmpint(current_uid, ==, UID_USER);

	/* Trigger first event and result is still EBUSY */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 1);

	/* Fake reply from vpnd */
	change_user_reply = create_dbus_error(last_message,
					"net.connman.error.Failed");
	g_assert(change_user_reply);
	set_reply_error(change_user_reply);

	/* Call the pending callback to process fake call */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	/* User is not changed */
	g_assert_cmpint(current_uid, ==, UID_USER);

	dbus_on = false;

	/*A delayed user change event is added */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 1);

	dbus_on = true;

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	g_main_loop_unref(mainloop);
	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Change to invalid user */
static void storage_test_invalid_user_change1()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	uid_t users[4] = { 1002, UID_INVALID, 9, 10 };
	int i;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, 0);

	for (i = 0; i < 4; init_dbus(TRUE), i++) {
		user_change_process(users[i], USER_CHANGE_INVALID_USER,
					"net.connman.Error.InvalidArguments",
					false, NULL, NULL);
		g_assert_cmpint(current_uid, ==, UID_ROOT);
		clean_dbus();
	}

	__connman_storage_cleanup();
	clean_dbus();
	cleanup_test_directory(test_path);

	g_free(test_path);
}

static enum connman_access deny_change_user(
				const struct connman_access_storage_policy *p,
				const char *user, const char *sender,
				enum connman_access default_access)
{
	return CONNMAN_ACCESS_DENY;
}

static bool deny_vpn_change_user(const char *sender, const char *arg,
				bool default_access)
{
	return false;
}

static struct connman_storage_callbacks access_deny_callbacks = {
	.uid_changed = uid_changed_cb,
	.access_policy_create = policy_create,
	.access_change_user = deny_change_user,
	.access_policy_free = policy_free,
	.vpn_access_change_user = deny_vpn_change_user,
};

/* Change to valid user but access is denied */
static void storage_test_invalid_user_change2()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &access_deny_callbacks),
				==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &access_deny_callbacks),
				==, 0);

	user_change_process(UID_USER, USER_CHANGE_ACCESS_DENIED,
					"net.connman.Error.PermissionDenied",
					false, NULL, NULL);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	__connman_storage_cleanup();
	clean_dbus();
	cleanup_test_directory(test_path);

	g_free(test_path);
}

static struct connman_storage_callbacks access_allow_main_deny_vpn_callbacks = {
	.access_policy_create = policy_create,
	.access_change_user = allow_change_user,
	.access_policy_free = policy_free,
	.vpn_access_change_user = deny_vpn_change_user,
};

/* Change to valid user but access to vpn is denied */
static void storage_test_invalid_user_change3()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN,
				&access_allow_main_deny_vpn_callbacks),
				==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN,
				&access_allow_main_deny_vpn_callbacks),
				==, 0);

	user_change_process(UID_USER, USER_CHANGE_ERROR_REPLY,
					"net.connman.Error.PermissionDenied",
					false, NULL, NULL);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	__connman_storage_cleanup();
	clean_dbus();
	cleanup_test_directory(test_path);

	g_free(test_path);
}

/* Test invalid users with internal process */
static void storage_test_invalid_user_change4()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	uid_t users[3] = { 1002, UID_INVALID, 9000 };
	struct user_cb_data_t data = { 0 };
	int i;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, NULL), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, NULL), ==, 0);

	for (i = 0; i < 3; init_dbus(TRUE), i++) {
		internal_user_change_process(users[i], result_cb, &data, false,
				-EINVAL, NULL, dbus_mode);
		g_assert_cmpint(data.call_count, ==, 0);
		g_assert_cmpint(current_uid, ==, UID_ROOT);
		clean_dbus();
	}

	__connman_storage_cleanup();
	clean_dbus();
	cleanup_test_directory(test_path);

	g_free(test_path);
}

static const char* get_proper_dbus_name()
{
	return PROPER_SENDER;
}

static struct connman_storage_callbacks sender_success_callbacks = {
	.uid_changed = uid_changed_cb,
	.get_peer_dbus_name = get_proper_dbus_name,
};

/* Successful user change with normal dbus process */
static void storage_test_dbus_security_user_change1()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	current_uid = 0;

	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN,
				&sender_success_callbacks), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN,
				&sender_success_callbacks), ==, 0);

	user_change_process(UID_USER, USER_CHANGE_SUCCESS, NULL, false, NULL,
									NULL);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	clean_dbus();
	clean_cb_counts();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Successful user change with internal process in non-preparing mode */
static void storage_test_dbus_security_user_change2()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
			STORAGE_DIR_TYPE_MAIN, &sender_success_callbacks),
									==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
			STORAGE_DIR_TYPE_VPN, &sender_success_callbacks),
									==, 0);

	internal_user_change_process(UID_USER, NULL, NULL, false, -EINPROGRESS,
				NULL, DBUS_MODE_USER_CHANGE_TO_VPND);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/*
 * Successful user change with internal process in preparing mode.
 * Like in storage_test_user_change10, we are expecting already enabled.
 */
static void storage_test_dbus_security_user_change3()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
			STORAGE_DIR_TYPE_MAIN, &sender_success_callbacks),
									==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
			STORAGE_DIR_TYPE_VPN, &sender_success_callbacks),
			==, 0);

	internal_user_change_process(UID_USER, NULL, NULL, true, -EINPROGRESS,
					"net.connman.Error.AlreadyEnabled",
					DBUS_MODE_USER_CHANGE_TO_VPND);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static const char* get_improper_dbus_name()
{
	return IMPROPER_SENDER;
}

static struct connman_storage_callbacks sender_failure_callbacks = {
	.uid_changed = uid_changed_cb,
	.get_peer_dbus_name = get_improper_dbus_name,
};

/* Failed user change with normal dbus process */
static void storage_test_dbus_security_user_change4()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN,
				&sender_failure_callbacks),
				==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN,
				&sender_failure_callbacks),
				==, 0);

	user_change_process(UID_USER, USER_CHANGE_VPN_ACCESS_DENIED,
					"net.connman.Error.PermissionDenied",
					false, NULL, NULL);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	__connman_storage_cleanup();
	clean_dbus();
	cleanup_test_directory(test_path);

	g_free(test_path);
}

/* Failed user change with internal process in non-preparing mode */
static void storage_test_dbus_security_user_change5()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN,
				&sender_failure_callbacks),
				==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN,
				&sender_failure_callbacks),
				==, 0);

	internal_user_change_process(UID_USER, NULL, NULL, false, -EINPROGRESS,
					"net.connman.Error.PermissionDenied",
						DBUS_MODE_USER_CHANGE_TO_VPND);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Failed user change with internal process in preparing mode */
static void storage_test_dbus_security_user_change6()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN,
				&sender_failure_callbacks),
				==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN,
				&sender_failure_callbacks),
				==, 0);

	internal_user_change_process(UID_USER, NULL, NULL, true, -EINPROGRESS,
					"net.connman.Error.PermissionDenied",
						DBUS_MODE_USER_CHANGE_TO_VPND);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static bool delay_peer;

/*
 * This function allows to artificially provide a delay response to the
 * storage.c functions that makes them think that vpnd has not managed to
 * acquire the peering connection to connmand, and thus returns NULL.
 * The global var delay_peer provides control over the call behaviour.
 */
static const char* get_delayed_dbus_name()
{
	if (delay_peer)
		return NULL;
	else
		return PROPER_SENDER;
}

static struct connman_storage_callbacks delayed_success_callbacks = {
	.uid_changed = uid_changed_cb,
	.get_peer_dbus_name = get_delayed_dbus_name,
};

/* User change with normal dbus process while vpnd is not connected */
static void storage_test_dbus_security_user_change7()
{
	GMainLoop *mainloop;
	DBusConnection *connection;
	DBusMessage *change_user_reply;
	DBusError error;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	delay_peer = true;

	mainloop = g_main_loop_new(NULL, FALSE);
	connection = connman_dbus_get_connection();
	dbus_error_init(&error);
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN,
				&delayed_success_callbacks),
				==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN,
				&delayed_success_callbacks),
				==, 0);

	user_change_process(UID_USER, USER_CHANGE_VPN_ACCESS_DENIED,
					"net.connman.Error.NotConnected",
					false, NULL, NULL);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	/*
	 * Finish up. It is not possible to conclude the test like this,
	 * because there's 2 static variables in storage.c that can't be reset
	 * from here - delayed_user_change and vpn_change_call, so we might as
	 * well draw the pending user change to a conclusion.
	 */
	delay_peer = false;

	/*
	 * Main loop should contain the re-attempted user change message
	 * to send to vpnd.
	 */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 1);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);
	g_assert_false(dbus_set_error_from_message(&error, change_user_reply));
	set_reply(change_user_reply);
	last_pending_function(last_pending_call, last_pending_function_data);

	g_assert_cmpint(current_uid, ==, UID_USER);
	/* Main loop should now be empty. */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	__connman_storage_cleanup();
	clean_dbus();
	cleanup_test_directory(test_path);
	g_main_loop_unref(mainloop);

	g_free(test_path);
}

/* User change with internal process in non-preparing mode while vpnd *
 * is not connected.                                                  */
static void storage_test_dbus_security_user_change8()
{
	GMainLoop *mainloop;
	DBusConnection *connection;
	DBusMessage *change_user_reply;
	DBusError error;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	delay_peer = true;

	mainloop = g_main_loop_new(NULL, FALSE);
	connection = connman_dbus_get_connection();
	dbus_error_init(&error);
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN,
				&delayed_success_callbacks),
				==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN,
				&delayed_success_callbacks),
				==, 0);

	user_change_process(UID_USER, USER_CHANGE_VPN_ACCESS_DENIED,
					"net.connman.Error.NotConnected",
					false, NULL, NULL);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	/*
	 * Finish up. It is not possible to conclude the test like this,
	 * because there's 2 static variables in storage.c that can't be reset
	 * from here - delayed_user_change and vpn_change_call, so we might as
	 * well draw the pending user change to a conclusion.
	 */
	delay_peer = false;

	/*
	 * Main loop should contain the re-attempted user change message
	 * to send to vpnd.
	 */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 1);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);
	g_assert_false(dbus_set_error_from_message(&error, change_user_reply));
	set_reply(change_user_reply);
	last_pending_function(last_pending_call, last_pending_function_data);

	g_assert_cmpint(current_uid, ==, UID_USER);
	/* Main loop should now be empty. */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	__connman_storage_cleanup();
	clean_dbus();
	cleanup_test_directory(test_path);
	g_main_loop_unref(mainloop);

	g_free(test_path);
}

/*
 * User change with internal process in preparing mode while vpnd is
 * not connected.
 */
static void storage_test_dbus_security_user_change9()
{
	GMainLoop *mainloop;
	DBusConnection *connection;
	DBusMessage *change_user_reply;
	DBusError error;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	delay_peer = true;

	mainloop = g_main_loop_new(NULL, FALSE);
	connection = connman_dbus_get_connection();
	dbus_error_init(&error);
	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
			STORAGE_DIR_TYPE_MAIN, &delayed_success_callbacks),
									==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
			STORAGE_DIR_TYPE_VPN, &delayed_success_callbacks),
									==, 0);

	internal_user_change_process(UID_USER, NULL, NULL, true, -EINPROGRESS,
						"net.connman.Error.NotConnected",
						DBUS_MODE_USER_CHANGE_TO_VPND);

	g_assert_cmpint(current_uid, ==, UID_USER);

	/*
	 * Finish up. It is not possible to conclude the test like this,
	 * because there's 2 static variables in storage.c that can't be reset
	 * from here - delayed_user_change and vpn_change_call, so we might as
	 * well draw the pending user change to a conclusion.
	 */
	delay_peer = false;

	/*
	 * Main loop should contain the re-attempted user change message
	 * to send to vpnd.
	 */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 1);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);

	/*
	 * Due to this being the preparing mode, we are expecting vpnd to
	 * report that it was already set.
	 */
	g_assert_true(dbus_set_error_from_message(&error, change_user_reply));
	g_assert_cmpstr(error.name, ==, "net.connman.Error.AlreadyEnabled");
	dbus_error_free(&error);
	set_reply(change_user_reply);
	last_pending_function(last_pending_call, last_pending_function_data);

	g_assert_cmpint(current_uid, ==, UID_USER);
	/* Main loop should now be empty. */
	g_assert_cmpint(iterate_main_context(g_main_loop_get_context(mainloop),
				FALSE, 1), ==, 0);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static void dbus_error_user_change_process(uid_t uid,
			enum user_change_mode mode, const char *error_name,
			bool fake_error)
{
	GMainLoop *mainloop;
	GMainContext *context;
	DBusMessage *change_user_msg;
	DBusMessage *change_user_reply = NULL;
	DBusConnection *connection;
	DBusError error;
	dbus_uint32_t user_id;

	user_id = (dbus_uint32_t)uid;
	current_uid = UID_ROOT;

	mainloop = g_main_loop_new(NULL, FALSE);
	g_assert(mainloop);

	connection = connman_dbus_get_connection();
	dbus_error_init(&error);

	/* Create user change message and "send" it */
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_UINT32, &user_id,
				DBUS_TYPE_INVALID));

	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));

	/* Process message in connmand */
	DBG("call connmand change_user()");
	g_assert(connmand_method);
	g_assert_null(connmand_method(connection, last_message,
				connmand_data));

	DBG("fake error \"%s\" for user change", error_name);
	change_user_reply = create_dbus_error(last_message, error_name);
	set_reply_error(change_user_reply);

	/* Call the pending callback which will trigger timeout init */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	/* Iterate mainloop to trigger timeout function to message vpnd */
	context = g_main_loop_get_context(mainloop);
	g_assert(context);
	g_assert_cmpint(iterate_main_context(context, TRUE, 1), ==, 1);

	/* Call vpnd method and get return */
	DBG("call vpnd change user()");
	g_assert(vpnd_method);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);
	g_assert_false(dbus_set_error_from_message(&error, change_user_reply));
	set_reply(change_user_reply);

	/* Call the pending callback again which now has correct answer */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	g_assert(last_reply);
	g_assert(last_reply_error);

	dbus_message_unref(change_user_msg);
	g_main_loop_unref(mainloop);
}

/* Invalid arguments in the D-Bus message */
static void storage_test_dbus_error1()
{
	DBusMessage *change_user_msg;
	DBusMessage *change_user_reply;
	DBusConnection *connection;
	DBusError error;
	gchar *user_id;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &uid_callback), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	user_id = g_strdup_printf("%u", UID_USER);
	g_assert(user_id);

	current_uid = UID_ROOT;

	connection = connman_dbus_get_connection();

	/* Create user change message and "send" it */
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_STRING, &user_id,
				DBUS_TYPE_INVALID));

	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));

	/* Process message in connmand */
	DBG("call connmand change_user()");
	g_assert(connmand_method);
	change_user_reply = connmand_method(connection, last_message,
				connmand_data);
	g_assert(change_user_reply);

	dbus_error_init(&error);
	g_assert_true(dbus_set_error_from_message(&error, change_user_reply));
	g_assert_cmpstr(error.name, ==, "net.connman.Error.InvalidArguments");
	dbus_error_free(&error);
	dbus_message_unref(change_user_reply);

	/*
	 * "Send" directly to vpnd - note that this shouldn't work when vpnd is
	 * restricted to accept user change from connmand only.
	 */
	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));
	DBG("call vpnd change_user_vpnd()");
	g_assert(vpnd_method);
	change_user_reply = vpnd_method(connection, last_message, vpnd_data);
	g_assert(change_user_reply);

	dbus_error_init(&error);
	g_assert_true(dbus_set_error_from_message(&error, change_user_reply));
	g_assert_cmpstr(error.name, ==, "net.connman.Error.InvalidArguments");
	dbus_error_free(&error);
	dbus_message_unref(change_user_reply);

	__connman_storage_cleanup();
	clean_dbus();
	cleanup_test_directory(test_path);

	dbus_message_unref(change_user_msg);
	g_free(test_path);
	g_free(user_id);
}

static void storage_test_dbus_error2()
{
	DBusMessage *change_user_msg;
	DBusMessage *change_user_reply;
	DBusConnection *connection;
	DBusError error;
	dbus_uint32_t user_id;
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &uid_callback), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	user_id = (dbus_uint32_t)UID_USER;
	g_assert(user_id);

	current_uid = UID_ROOT;

	connection = connman_dbus_get_connection();

	/* Create user change message and "send" it */
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_UINT32, &user_id,
				DBUS_TYPE_INVALID));

	g_assert_true(dbus_connection_send_with_reply(connection,
				change_user_msg, NULL, 0));

	/* Process message in connmand when dbus reports error */
	dbus_on = false;

	DBG("call connmand change_user()");
	g_assert(connmand_method);
	change_user_reply = connmand_method(connection, last_message,
				connmand_data);
	g_assert(change_user_reply);
	dbus_on = true;

	dbus_error_init(&error);
	g_assert_true(dbus_set_error_from_message(&error, change_user_reply));
	g_assert_cmpstr(error.name, ==, "net.connman.Error.Failed");
	dbus_error_free(&error);

	__connman_storage_cleanup();
	clean_dbus();
	cleanup_test_directory(test_path);

	dbus_message_unref(change_user_msg);
	dbus_message_unref(change_user_reply);
	g_free(test_path);
}

/*
 * Change to regular users UID_USER and UID_USER2, no callbacks with timeout,
 * noreply, limits exceeded and unknown method errors.
 */
static void storage_test_error_user_change1()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &uid_callback), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	/* One timeout then change is a success with main loop timeout func */
	dbus_error_user_change_process(UID_USER, USER_CHANGE_ERROR_REPLY,
				"org.freedesktop.DBus.Error.TimedOut", true);

	g_assert_cmpint(current_uid, ==, UID_USER);

	clean_dbus();
	init_dbus(TRUE);

	/* One timeout then change is a success with main loop timeout func */
	dbus_error_user_change_process(UID_USER2, USER_CHANGE_ERROR_REPLY,
				"org.freedesktop.DBus.Error.Timeout", true);

	g_assert_cmpint(current_uid, ==, UID_USER2);

	clean_dbus();
	init_dbus(TRUE);

	dbus_error_user_change_process(UID_USER, USER_CHANGE_ERROR_REPLY,
				"org.freedesktop.DBus.Error.NoReply", true);

	g_assert_cmpint(current_uid, ==, UID_USER);

	clean_dbus();
	init_dbus(TRUE);

	dbus_error_user_change_process(UID_USER2, USER_CHANGE_ERROR_REPLY,
				"org.freedesktop.DBus.Error.LimitsExceeded",
				true);

	g_assert_cmpint(current_uid, ==, UID_USER2);

	clean_dbus();
	init_dbus(TRUE);

	dbus_error_user_change_process(UID_USER, USER_CHANGE_ERROR_REPLY,
				"org.freedesktop.DBus.Error.UnknownMethod",
				true);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static void internal_error_user_change_process(uid_t uid,
			connman_storage_change_user_result_cb_t cb,
			void *user_cb_data, bool prepare_only,
			int expected_return, const char *error_name,
			enum dbus_mode_t mode, int limit,
			const char *final_error_name)
{
	GMainLoop *mainloop;
	GMainContext *context;
	DBusMessage *change_user_error;
	struct user_cb_data_t *cb_data = user_cb_data;
	int call_count = prepare_only ? 2 : 1;
	int i;

	DBG("uid %u", uid);

	if (cb_data)
		cb_data->expected_call_count = call_count;

	dbus_mode = mode;
	current_uid = UID_ROOT;

	mainloop = g_main_loop_new(NULL, FALSE);
	g_assert(mainloop);

	g_assert_cmpint(__connman_storage_change_user(uid, cb, cb_data,
				prepare_only), ==, expected_return);

	/* Error in the message sending, don't process messages */
	if (expected_return != -EINPROGRESS)
		return;

	for (i = 0; i < limit; i++) {
		/* Fake error as reply */
		change_user_error = create_dbus_error(last_message,
					error_name);
		g_assert(change_user_error);
		set_reply_error(change_user_error);

		/* Call the pending callback */
		DBG("call connmand pending call notify");
		last_pending_function(last_pending_call,
					last_pending_function_data);

		/* Iterate mainloop to trigger timeout function */
		context = g_main_loop_get_context(mainloop);
		g_assert(context);
		g_assert_cmpint(iterate_main_context(context, TRUE, 1), ==, 1);
	}

	if (final_error_name) {
		/* Fake error as final reply */
		change_user_error = create_dbus_error(last_message,
					final_error_name);
		g_assert(change_user_error);
		set_reply_error(change_user_error);
	} else {
		dbus_message_unref(last_reply_error);
		last_reply_error = NULL;
		set_reply(g_dbus_create_reply(last_message,
					DBUS_TYPE_INVALID));
	}

	/* Call the pending callback */
	DBG("call connmand pending call notify");
	last_pending_function(last_pending_call, last_pending_function_data);

	if (cb_data)
		g_assert_cmpint(cb_data->call_count, ==, call_count);

	g_main_loop_unref(mainloop);
}

/*
 * Test initial user change with D-Bus timeout or noreply errors which will
 * eventually succeed.
 */
static void storage_test_error_user_change2()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	struct user_cb_data_t data = {
				.uids = { UID_USER, UID_USER },
				.errs = { -EINPROGRESS, 0 },
				};

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &uid_callback), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	internal_error_user_change_process(UID_USER, result_cb, &data, true,
				-EINPROGRESS,
				"org.freedesktop.DBus.Error.TimedOut",
				DBUS_MODE_USER_CHANGE_TO_VPND, 3, NULL);

	clean_dbus();
	init_dbus(TRUE);

	data.call_count = 0;
	data.uids[0] = UID_USER2;
	data.uids[1] = 0;
	data.errs[1] = -ENOENT;
	internal_error_user_change_process(UID_USER2, result_cb, &data, true,
				-EINPROGRESS,
				"org.freedesktop.DBus.Error.Timeout",
				DBUS_MODE_USER_CHANGE_TO_VPND, 3,
				"org.freedesktop.DBus.Error.Failed");

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	clean_dbus();
	init_dbus(TRUE);

	data.call_count = 0;
	data.uids[0] = data.uids[1] = UID_USER;
	data.errs[1] = 0;
	internal_error_user_change_process(UID_USER, result_cb, &data, true,
				-EINPROGRESS,
				"org.freedesktop.DBus.Error.NoReply",
				DBUS_MODE_USER_CHANGE_TO_VPND, 1, NULL);

	g_assert_cmpint(current_uid, ==, UID_USER);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/*
 * Test normal user change with D-Bus timeout or noreply errors, which will
 * eventually succeed.
 */
static void storage_test_error_user_change3()
{
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	struct user_cb_data_t data = {
				.uids = { UID_USER, 0 },
				.errs = { 0, 0 },
				};

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &uid_callback), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	internal_error_user_change_process(UID_USER, result_cb, &data, false,
				-EINPROGRESS,
				"org.freedesktop.DBus.Error.TimedOut",
				dbus_mode, 3, NULL);

	g_assert_cmpint(current_uid, ==, UID_USER);

	clean_dbus();
	init_dbus(TRUE);

	data.call_count = 0;
	data.uids[0] = UID_USER2;
	data.errs[0] = -ENOENT;
	internal_error_user_change_process(UID_USER2, result_cb, &data, false,
				-EINPROGRESS,
				"org.freedesktop.DBus.Error.Timeout",
				dbus_mode, 3,
				"org.freedesktop.DBus.Error.NoMemory");

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	clean_dbus();
	init_dbus(TRUE);

	data.call_count = 0;
	data.uids[0] = UID_USER2;
	data.errs[0] = 0;
	internal_error_user_change_process(UID_USER2, result_cb, &data, false,
				-EINPROGRESS,
				"org.freedesktop.DBus.Error.NoReply",
				dbus_mode, 2, NULL);

	g_assert_cmpint(current_uid, ==, UID_USER2);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

/* Test the error handling in the send_change_user_msg() */
static void storage_test_error_user_change4()
{
	enum dbus_mode_t mode = DBUS_MODE_NONE; // send fails
	gchar *test_path;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	struct user_cb_data_t data = {
				.uids = { 0, 0 },
				.errs = { -ECOMM, 0 },
				};

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);

	init_dbus(TRUE);

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &uid_callback), ==, 0);
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_VPN, &uid_callback), ==, 0);

	internal_error_user_change_process(UID_USER, result_cb, &data, true,
				-ECOMM, NULL, mode, 1, NULL);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	clean_dbus();
	init_dbus(TRUE);

	data.call_count = 0;
	internal_error_user_change_process(UID_USER, result_cb, &data, false,
				-ECOMM, NULL, mode, 1, NULL);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	clean_dbus();
	init_dbus(TRUE);
	mode = dbus_mode;
	clean_dbus(); // To cause error to happen in set notify cb

	data.call_count = 0;
	data.errs[0] = -ENOMEM;
	internal_error_user_change_process(UID_USER, result_cb, &data, false,
				-ENOMEM, NULL, mode, 1, NULL);

	g_assert_cmpint(current_uid, ==, UID_ROOT);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	clean_dbus();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static void set_technology_powered(enum connman_service_type type,
			 dbus_bool_t powered, const char *errormsg)
{
	struct technology_dbus_item *item;
	DBusConnection *connection;
	DBusMessage *change_powered;
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter iter;
	gchar *dbus_path;
	const char *setpowered = "Powered";

	connection = connman_dbus_get_connection();

	/* Set techs to enabled with powered D-Bus message */
	dbus_path = g_strdup_printf("%s/technology/%s", CONNMAN_PATH,
				__connman_service_type2string(type));

	change_powered = dbus_message_new_method_call("net.connman", dbus_path,
				"net.connman.Technology", "SetProperty");
	g_assert(change_powered);

	dbus_message_iter_init_append(change_powered, &iter);
	connman_dbus_property_append_basic(&iter, setpowered,
				DBUS_TYPE_BOOLEAN, &powered);
	dbus_message_set_serial(change_powered, ++message_serial);

	/* Find the method for this path */
	g_assert(technology_methods);
	item = g_hash_table_lookup(technology_methods, dbus_path);
	g_assert(item);

	DBG("call set powered for path %s", dbus_path);
	reply = item->function(connection, change_powered, item->data);
	g_assert(reply);

	dbus_error_init(&error);

	if (!errormsg) {
		g_assert_false(dbus_set_error_from_message(&error, reply));
	} else {
		g_assert_true(dbus_set_error_from_message(&error, reply));
		g_assert_cmpstr(error.name, ==, errormsg);
		dbus_error_free(&error);
	}

	dbus_message_unref(change_powered);
	dbus_message_unref(reply);
	g_free(dbus_path);
}

static void storage_test_technology_callbacks1()
{
	gchar *test_path;
	gchar *settings_file;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	gchar *content[] = {
				"[global]",
				"OfflineMode=false",
				"",
				"[WiFi]",
				"Enable=false",
				"",
				"[Cellular]",
				"Enable=true",
				"",
				NULL,
	};

	test_path = setup_test_directory();

	init_dbus(TRUE);

	/* Main */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);

	__connman_inotify_init();

	/* technology init will create empty settings file */
	g_assert_true(__connman_technology_disable_all());
	g_assert_false(__connman_technology_enable_from_config());

	/* Create settings file */
	settings_file = g_build_filename(STORAGEDIR, "settings", NULL);
	set_and_verify_content(settings_file, content);

	__connman_technology_init();

	DBG("register drivers");
	/*
	 * Device register sets devices to enabled but does not enable tech.
	 * cellular (device1) is always on
	 */
	g_assert_cmpint(connman_technology_driver_register(
				&test_device1_driver), ==, 0);
	g_assert_cmpint(connman_technology_driver_register(
				&test_device2_driver), ==, 0);


	DBG("adding devices");
	g_assert_cmpint(__connman_technology_add_device(&test_device1), ==, 0);
	g_assert_true(test_device1.enabled);

	g_assert_cmpint(__connman_technology_add_device(&test_device2), ==, 0);
	g_assert_false(test_device2.enabled);

	/* Set all powered and enabled */
	set_technology_powered(CONNMAN_SERVICE_TYPE_CELLULAR, true, NULL);
	g_assert_cmpint(__connman_technology_enabled(
				CONNMAN_SERVICE_TYPE_CELLULAR), ==, 0);
	g_assert_true(test_device1.enabled);

	/* Another power on call causes AlreadyEnabled error */
	set_technology_powered(CONNMAN_SERVICE_TYPE_CELLULAR, true,
				"net.connman.Error.AlreadyEnabled");

	set_technology_powered(CONNMAN_SERVICE_TYPE_WIFI, true, NULL);
	g_assert_cmpint(__connman_technology_enabled(
				CONNMAN_SERVICE_TYPE_WIFI), ==, 0);
	g_assert_true(test_device2.enabled);

	g_assert_false(__connman_technology_get_offlinemode());

	DBG("disable all tech");
	g_assert_true(__connman_technology_disable_all());
	g_assert_false(test_device1.enabled);
	g_assert_false(test_device2.enabled);

	DBG("re-enable crom config");
	g_assert_true(__connman_technology_enable_from_config());
	g_assert_true(test_device1.enabled);
	g_assert_true(test_device2.enabled);

	DBG("remove devices and drivers");
	set_technology_powered(CONNMAN_SERVICE_TYPE_CELLULAR, false, NULL);
	g_assert_cmpint(__connman_technology_remove_device(&test_device1), ==,
				0);
	connman_technology_driver_unregister(&test_device1_driver);

	set_technology_powered(CONNMAN_SERVICE_TYPE_WIFI, false, NULL);
	g_assert_cmpint(__connman_technology_remove_device(&test_device2), ==,
				0);
	connman_technology_driver_unregister(&test_device2_driver);

	__connman_technology_cleanup();
	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	clean_dbus();
	cleanup_test_directory(test_path);

	g_free(settings_file);
	g_free(test_path);
}

static void change_user_connmand_only(uid_t uid)
{
	DBusConnection *connection;
	DBusMessage *change_user_msg;
	DBusMessage *change_user_reply;

	connection = connman_dbus_get_connection();

	/* Create user change message and "send" it */
	change_user_msg = dbus_message_new_method_call("net.connman",
				"/", "net.connman.Storage", "ChangeUser");
	g_assert(change_user_msg);

	g_assert_true(dbus_message_append_args(change_user_msg,
				DBUS_TYPE_UINT32, &uid,
				DBUS_TYPE_INVALID));

	/* Process message in connmand */
	DBG("call connmand change_user() for uid:%d", uid);
	g_assert(connmand_method);
	g_assert_null(connmand_method(connection, change_user_msg,
					connmand_data));

	/* Create reply as if vpnd replied ok to user change */
	DBG("fake vpnd change user() for uid:%d", uid);
	dbus_message_set_serial(change_user_msg, ++message_serial);
	change_user_reply = g_dbus_create_reply(change_user_msg,
				DBUS_TYPE_INVALID);
	g_assert(change_user_reply);
	set_reply(change_user_reply);

	/* Call the pending callback to finish change in connmand*/
	DBG("call connmand pending call notify for uid:%d", uid);
	last_pending_function(last_pending_call, last_pending_function_data);

	/* Proper reply should be received */
	g_assert(last_reply);
	g_assert_null(last_reply_error);
	dbus_message_unref(change_user_msg);
}

static struct connman_storage_callbacks technology_callbacks = {
	.pre = __connman_technology_disable_all,
	.post = __connman_technology_enable_from_config,
};

/* User change using technology callbacks when user has no settings file */
static void storage_test_technology_callbacks2()
{
	gchar *test_path;
	gchar *settings_file;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	gchar *content_root[] = {
				"[global]",
				"OfflineMode=false",
				"",
				"[WiFi]",
				"Enable=false",
				"",
				"[Cellular]",
				"Enable=true",
				"",
				NULL,
	};

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);

	init_dbus(TRUE);

	/* Main */
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);

	__connman_inotify_init();

	/* Create root settings file */
	settings_file = g_build_filename(STORAGEDIR, "settings", NULL);
	set_and_verify_content(settings_file, content_root);

	__connman_technology_init();

	DBG("register drivers");
	/*
	 * Device register sets devices to enabled but does not enable tech.
	 * cellular (device1) is always on
	 */
	g_assert_cmpint(connman_technology_driver_register(
				&test_device1_driver), ==, 0);
	g_assert_cmpint(connman_technology_driver_register(
				&test_device2_driver), ==, 0);

	DBG("adding devices");
	g_assert_cmpint(__connman_technology_add_device(&test_device1), ==, 0);
	g_assert_true(test_device1.enabled);

	g_assert_cmpint(__connman_technology_add_device(&test_device2), ==, 0);
	g_assert_false(test_device2.enabled);

	/* Set all powered and enabled */
	set_technology_powered(CONNMAN_SERVICE_TYPE_CELLULAR, true, NULL);
	g_assert_cmpint(__connman_technology_enabled(
				CONNMAN_SERVICE_TYPE_CELLULAR), ==, 0);
	g_assert_true(test_device1.enabled);

	set_technology_powered(CONNMAN_SERVICE_TYPE_WIFI, true, NULL);
	g_assert_cmpint(__connman_technology_enabled(
				CONNMAN_SERVICE_TYPE_WIFI), ==, 0);
	g_assert_true(test_device2.enabled);

	g_assert_false(__connman_technology_get_offlinemode());

	/*
	 * Call connmand user change only, which triggers callbacks. Register
	 * only connmand with callbacks, and fake vpnd return.
	 */
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &technology_callbacks),
				==, 0);
	change_user_connmand_only(UID_USER);

	/* No settings files, devices are disabled */
	g_assert_false(test_device1.enabled);
	g_assert_false(test_device2.enabled);
	g_assert_false(__connman_technology_get_offlinemode());

	/*
	 * Since devices and techs are disabled, no power off is required.
	 * If tech is powered off, AlreadyDisabled is received as error.
	 */
	DBG("remove devices and drivers");
	set_technology_powered(CONNMAN_SERVICE_TYPE_CELLULAR, false,
				"net.connman.Error.AlreadyDisabled");
	g_assert_cmpint(__connman_technology_remove_device(&test_device1), ==,
				0);
	connman_technology_driver_unregister(&test_device1_driver);

	set_technology_powered(CONNMAN_SERVICE_TYPE_WIFI, false,
				"net.connman.Error.AlreadyDisabled");
	g_assert_cmpint(__connman_technology_remove_device(&test_device2), ==,
				0);
	connman_technology_driver_unregister(&test_device2_driver);

	__connman_technology_cleanup();
	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	clean_dbus();
	cleanup_test_directory(test_path);

	g_free(settings_file);
	g_free(test_path);
}

/*
 * User change using technology callbacks when user has a settings file,
 * then change to another user with offline mode enabled.
 */
static void storage_test_technology_callbacks3()
{
	gchar *test_path;
	gchar *settings_file;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	gchar *content_root[] = {
				"[global]",
				"OfflineMode=false",
				"",
				"[WiFi]",
				"Enable=true",
				"",
				"[Cellular]",
				"Enable=true",
				"",
				NULL,
	};
	gchar *content_user[] = {
				"[global]",
				"OfflineMode=false",
				"",
				"[WiFi]",
				"Enable=false",
				"",
				"[Cellular]",
				"Enable=true",
				"",
				NULL,
	};
	gchar *content_user2[] = {
				"[global]",
				"OfflineMode=true",
				"",
				"[WiFi]",
				"Enable=false",
				"",
				"[Cellular]",
				"Enable=true",
				"",
				NULL,
	};
	const char *user_storage_dir = ".local/share/system/privileged";

	test_path = setup_test_directory();
	set_user_pw_dir_root(test_path);

	init_dbus(TRUE);

	/* Main */
	g_assert_cmpint(__connman_storage_init(test_path, user_storage_dir,
							m_dir, m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
				__connman_storage_dir_mode()), ==, 0);

	__connman_inotify_init();

	/* Create settings file */
	settings_file = g_build_filename(STORAGEDIR, "settings", NULL);
	set_and_verify_content(settings_file, content_root);
	g_free(settings_file);

	/* Create user settings file */
	settings_file = g_build_filename("user", user_storage_dir, "connman",
									NULL);
	create_settings_file(test_path, settings_file, content_user);
	g_free(settings_file);

	/* Create user2 settings file */
	settings_file = g_build_filename("user2", user_storage_dir, "connman",
									NULL);
	create_settings_file(test_path, settings_file, content_user2);
	g_free(settings_file);

	__connman_technology_init();

	DBG("register drivers");
	/*
	 * Device register sets devices to enabled but does not enable tech.
	 * cellular (device1) is always on
	 */
	g_assert_cmpint(connman_technology_driver_register(
				&test_device1_driver), ==, 0);
	g_assert_cmpint(connman_technology_driver_register(
				&test_device2_driver), ==, 0);

	DBG("adding devices");
	g_assert_cmpint(__connman_technology_add_device(&test_device1), ==, 0);
	g_assert_true(test_device1.enabled);

	g_assert_cmpint(__connman_technology_add_device(&test_device2), ==, 0);
	g_assert_true(test_device2.enabled);

	/* Set all powered and enabled */
	set_technology_powered(CONNMAN_SERVICE_TYPE_CELLULAR, true, NULL);
	g_assert_cmpint(__connman_technology_enabled(
				CONNMAN_SERVICE_TYPE_CELLULAR), ==, 0);
	g_assert_true(test_device1.enabled);

	set_technology_powered(CONNMAN_SERVICE_TYPE_WIFI, true, NULL);
	g_assert_cmpint(__connman_technology_enabled(
				CONNMAN_SERVICE_TYPE_WIFI), ==, 0);
	g_assert_true(test_device2.enabled);

	g_assert_false(__connman_technology_get_offlinemode());

	/*
	 * Call connmand user change only, which triggers callbacks. Register
	 * only connmand with callbacks
	 */
	g_assert_cmpint(__connman_storage_register_dbus(
				STORAGE_DIR_TYPE_MAIN, &technology_callbacks),
				==, 0);
	change_user_connmand_only(UID_USER);

	g_assert_true(test_device1.enabled);
	g_assert_false(test_device2.enabled); /* Wifi for user gets disabled */
	g_assert_false(__connman_technology_get_offlinemode());

	clean_dbus();
	init_dbus(TRUE);

	/* user2 has offline mode enabled */
	change_user_connmand_only(UID_USER2);
	g_assert_false(test_device1.enabled);
	g_assert_false(test_device2.enabled);
	g_assert_true(__connman_technology_get_offlinemode());

	DBG("remove devices and drivers");
	set_technology_powered(CONNMAN_SERVICE_TYPE_CELLULAR, false,
				"net.connman.Error.AlreadyDisabled");
	g_assert_cmpint(__connman_technology_remove_device(&test_device1), ==,
				0);
	connman_technology_driver_unregister(&test_device1_driver);
	g_assert_cmpint(__connman_technology_remove_device(&test_device1), ==,
				-ENXIO);

	set_technology_powered(CONNMAN_SERVICE_TYPE_WIFI, false,
				"net.connman.Error.AlreadyDisabled");
	g_assert_cmpint(__connman_technology_remove_device(&test_device2), ==,
				0);
	connman_technology_driver_unregister(&test_device2_driver);
	g_assert_cmpint(__connman_technology_remove_device(&test_device2), ==,
				-ENXIO);

	__connman_technology_cleanup();
	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	clean_dbus();
	cleanup_test_directory(test_path);

	g_free(test_path);
}

static void storage_test_path_validation_error1()
{
	GKeyFile *keyfile;
	char *test_path;
	char *target;
	char *linkpath;
	char *realpath;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;

	gchar *wifi1[] = {
		"[wifi_1_managed_psk]",
		"Name=wifi1",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3447",
		"Frequency=2417",
		NULL
	};

	test_path = setup_test_directory();

	target = g_build_filename(test_path, "real", NULL);
	linkpath = g_build_filename(test_path, "symlink", NULL);
	realpath = g_build_filename(target, "connman", NULL);

	DBG("target %s realpath %s linkpath %s test_path %s", target, realpath,
							linkpath, test_path);

	__connman_inotify_init();

	/* Init storage with symlink as STORAGEDIR */
	g_assert_cmpint(symlink(target, linkpath), ==, 0);
	g_assert_cmpint(__connman_storage_init(linkpath, test_user_dir, m_dir,
								m_file), ==, 0);

	/* Create the target/connman dir and add files there. */
	g_assert_cmpint(__connman_storage_create_dir(realpath,
				__connman_storage_dir_mode()), ==, 0);
	create_settings_file(realpath, "wifi_1_managed_psk", wifi1);

	/* STORAGEDIR points to symlink, cannot be loaded */
	g_assert_null(connman_storage_load_service("wifi_1_managed_psk"));

	/* Nor saved */
	keyfile = g_key_file_new();
	g_assert_cmpint(__connman_storage_save_service(keyfile,
						"wifi_1_managed_psk"), !=, 0);
	g_key_file_unref(keyfile);

	g_assert_cmpint(unlink(linkpath), ==, 0);
	g_free(target);
	g_free(linkpath);
	g_free(realpath);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static void storage_test_path_validation_error2()
{
	GKeyFile *keyfile;
	const char *test_dirs[] = { "wifi_1_managed_psk", "wifi_X_managed_psk",
									NULL };
	char *test_path;
	char *target;
	char *linkpath;
	char *newlink;
	mode_t m_dir = 0700;
	mode_t m_file = 0600;
	int i = 0;

	gchar *wifi1[] = {
		"[wifi_1_managed_psk]",
		"Name=wifi1",
		"SSID=444e412d4d6f6b6b756c612d35472d444a3335726e5f322e3447",
		"Frequency=2417",
		NULL
	};

	test_path = setup_test_directory();

	__connman_inotify_init();
	g_assert_cmpint(__connman_storage_init(test_path, test_user_dir, m_dir,
								m_file), ==, 0);
	g_assert_cmpint(__connman_storage_create_dir(STORAGEDIR,
					__connman_storage_dir_mode()), ==, 0);

	create_settings_file(STORAGEDIR, "wifi_1_managed_psk", wifi1);

	newlink = "wifi_3_managed_psk";

	/* Test with existing (wifi_1) and broken link (wifi_X) */
	for (i = 0; test_dirs[i]; i++) {
		target = g_build_filename(STORAGEDIR, test_dirs[i], NULL);
		linkpath = g_build_filename(STORAGEDIR, newlink, NULL);
		DBG("target %s linkpath %s", target, linkpath);
		g_assert_cmpint(symlink(target, linkpath), ==, 0);
		g_assert_null(connman_storage_load_service(newlink));

		keyfile = g_key_file_new();
		g_assert_cmpint(__connman_storage_save_service(keyfile,
							newlink), !=, 0);
		g_key_file_unref(keyfile);

		g_assert_cmpint(unlink(linkpath), ==, 0);
		g_free(target);
		g_free(linkpath);
	}

	newlink = "wifi_4_managed_psk";
	linkpath = g_build_filename(STORAGEDIR, newlink, NULL);
	g_assert_cmpint(__connman_storage_create_dir(linkpath, m_dir), ==, 0);
	g_free(linkpath);

	/* Symlink settings file */
	target = g_build_filename(STORAGEDIR, "wifi_1_managed_psk", "settings",
							NULL);
	linkpath = g_build_filename(STORAGEDIR, newlink, "settings", NULL);
	DBG("target %s linkpath %s", target, linkpath);
	g_assert_cmpint(symlink(target, linkpath), ==, 0);
	g_assert_null(connman_storage_load_service(newlink));

	keyfile = g_key_file_new();
	g_assert_cmpint(__connman_storage_save_service(keyfile, newlink), !=,
									0);

	g_assert_cmpint(unlink(linkpath), ==, 0);
	g_free(target);
	g_free(linkpath);

	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	cleanup_test_directory(test_path);
	g_free(test_path);
}

static gchar *option_debug = NULL;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return true;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ NULL },
};

int main(int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	int err;

	g_test_init(&argc, &argv, NULL);

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else {
			g_printerr("An unknown error occurred\n");
		}

		return 1;
	}

	g_option_context_free(context);

	__connman_log_init(argv[0], option_debug, false, false,
			"Unit Tests Connection Manager", VERSION);

	g_test_add_func(TEST_PREFIX "/test_basic1",
				storage_test_basic1);
	g_test_add_func(TEST_PREFIX "/test_basic2",
				storage_test_basic2);
	g_test_add_func(TEST_PREFIX "/test_basic3",
				storage_test_basic3);
	g_test_add_func(TEST_PREFIX "/test_global1",
				storage_test_global1);
	g_test_add_func(TEST_PREFIX "/test_global2",
				storage_test_global2);
	g_test_add_func(TEST_PREFIX "/test_user_change1",
				storage_test_user_change1);
	g_test_add_func(TEST_PREFIX "/test_user_change2",
				storage_test_user_change2);
	g_test_add_func(TEST_PREFIX "/test_user_change3",
				storage_test_user_change3);
	g_test_add_func(TEST_PREFIX "/test_user_change4",
				storage_test_user_change4);
	g_test_add_func(TEST_PREFIX "/test_user_change5",
				storage_test_user_change5);
	g_test_add_func(TEST_PREFIX "/test_user_change6",
				storage_test_user_change6);
	g_test_add_func(TEST_PREFIX "/test_user_change7",
				storage_test_user_change7);
	g_test_add_func(TEST_PREFIX "/test_user_change8",
				storage_test_user_change8);
	g_test_add_func(TEST_PREFIX "/test_user_change9",
				storage_test_user_change9);
	g_test_add_func(TEST_PREFIX "/test_user_change10",
				storage_test_user_change10);
	g_test_add_func(TEST_PREFIX "/test_user_change11",
				storage_test_user_change11);
	g_test_add_func(TEST_PREFIX "/test_user_change12",
				storage_test_user_change12);
	g_test_add_func(TEST_PREFIX "/test_user_change13",
				storage_test_user_change13);
	g_test_add_func(TEST_PREFIX "/test_user_change14",
				storage_test_user_change14);
	g_test_add_func(TEST_PREFIX "/test_user_vpn_crash1",
				storage_test_vpn_crash1);
	g_test_add_func(TEST_PREFIX "/test_user_vpn_crash2",
				storage_test_vpn_crash2);
	g_test_add_func(TEST_PREFIX "/test_user_vpn_crash3",
				storage_test_vpn_crash3);
	g_test_add_func(TEST_PREFIX "/test_user_vpn_crash4",
				storage_test_vpn_crash4);
	g_test_add_func(TEST_PREFIX "/test_user_vpn_crash5",
				storage_test_vpn_crash5);
	g_test_add_func(TEST_PREFIX "/test_user_vpn_crash6",
				storage_test_vpn_crash6);
	g_test_add_func(TEST_PREFIX "/test_invalid_user_change1",
				storage_test_invalid_user_change1);
	g_test_add_func(TEST_PREFIX "/test_invalid_user_change2",
				storage_test_invalid_user_change2);
	g_test_add_func(TEST_PREFIX "/test_invalid_user_change3",
				storage_test_invalid_user_change3);
	g_test_add_func(TEST_PREFIX "/test_invalid_user_change4",
				storage_test_invalid_user_change4);
	g_test_add_func(TEST_PREFIX "/test_dbus_security_user_change1",
				storage_test_dbus_security_user_change1);
	g_test_add_func(TEST_PREFIX "/test_dbus_security_user_change2",
				storage_test_dbus_security_user_change2);
	g_test_add_func(TEST_PREFIX "/test_dbus_security_user_change3",
				storage_test_dbus_security_user_change3);
	g_test_add_func(TEST_PREFIX "/test_dbus_security_user_change4",
				storage_test_dbus_security_user_change4);
	g_test_add_func(TEST_PREFIX "/test_dbus_security_user_change5",
				storage_test_dbus_security_user_change5);
	g_test_add_func(TEST_PREFIX "/test_dbus_security_user_change6",
				storage_test_dbus_security_user_change6);
	g_test_add_func(TEST_PREFIX "/test_dbus_security_user_change7",
				storage_test_dbus_security_user_change7);
	g_test_add_func(TEST_PREFIX "/test_dbus_security_user_change8",
				storage_test_dbus_security_user_change8);
	g_test_add_func(TEST_PREFIX "/test_dbus_security_user_change9",
				storage_test_dbus_security_user_change9);
	g_test_add_func(TEST_PREFIX "/test_dbus_error1",
				storage_test_dbus_error1);
	g_test_add_func(TEST_PREFIX "/test_dbus_error2",
				storage_test_dbus_error2);
	g_test_add_func(TEST_PREFIX "/test_error_user_change1",
				storage_test_error_user_change1);
	g_test_add_func(TEST_PREFIX "/test_error_user_change2",
				storage_test_error_user_change2);
	g_test_add_func(TEST_PREFIX "/test_error_user_change3",
				storage_test_error_user_change3);
	g_test_add_func(TEST_PREFIX "/test_error_user_change4",
				storage_test_error_user_change4);
	g_test_add_func(TEST_PREFIX "/test_technology_callbacks1",
				storage_test_technology_callbacks1);
	g_test_add_func(TEST_PREFIX "/test_technology_callbacks2",
				storage_test_technology_callbacks2);
	g_test_add_func(TEST_PREFIX "/test_technology_callbacks3",
				storage_test_technology_callbacks3);
	g_test_add_func(TEST_PREFIX "/test_path_validation_error1",
				storage_test_path_validation_error1);
	g_test_add_func(TEST_PREFIX "/test_path_validation_error2",
				storage_test_path_validation_error2);

	err = g_test_run();

	__connman_log_cleanup(false);

	return err;
}
